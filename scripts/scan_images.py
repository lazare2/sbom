#!/usr/bin/env python3
"""
Pull a set of container images, scan each with Syft, and upload the SBOMs.

Edit the IMAGES dictionary below. Each entry maps an application name on the SBOM
platform to the image reference to scan:

    IMAGES = {
        "checkout-web": "registry.example.com/checkout/web:1.4.2",
    }

The value may be a bare reference as above, or the whole command as you would type
it -- `docker pull registry.example.com/checkout/web:1.4.2`. Both are accepted, so
a list pasted from a runbook works unedited. Any flags survive and are passed to
the pull (`docker pull --platform linux/amd64 nginx:1.27` does what it says); the
image reference itself must be the last word.

Then:

    set SBOM_INGEST_TOKEN=<token from Admin -> Ingest tokens>
    set SBOM_API_URL=https://sbom.example.com
    python scripts/scan_images.py

Each entry is pulled with `docker pull`, scanned with `syft`, and posted to
`POST /api/v1/scans` as the application named by the key -- the same endpoint a CI
pipeline uses, so the results are ordinary scans: current-build components,
diffs against the previous run, vulnerability findings, and the dashboard.

Two things worth knowing before the first run:

  * A key that matches no existing application does not fail. The platform
    auto-creates one with status `pending_confirmation`, which appears in
    Admin -> Pending as "Unconfirmed" until someone confirms or merges it. That is
    the intended way to onboard, but it does mean a typo in a key creates a second
    application rather than erroring -- worth a look at that queue after a first run.
  * Names match case-insensitively, so `Checkout-Web` and `checkout-web` are one
    application, not two.

Re-running is safe and is the point: each run adds a build to the application's
history, and the platform diffs it against the previous one. The CI endpoint
accepts a byte-identical SBOM without complaint, so an image that has not changed
simply records another build rather than failing.

No third-party packages -- standard library only, so it runs on a locked-down
machine with no pip access. Needs Python 3.8+, `docker`, and `syft` on PATH.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# What to scan
# ---------------------------------------------------------------------------
# key   = application name on the SBOM platform (created on first upload)
# value = the image to pull and scan, either as a bare reference or as the full
#         `docker pull ...` command -- see parse_target() for what is accepted
#
# Prefer an explicit tag or a digest over `:latest`. The platform records this
# reference on the scan, and a moving tag makes a build's provenance unreproducible
# -- "we scanned nginx:latest" does not say what was actually scanned.
IMAGES: Dict[str, str] = {
    "example-api": "nginx:1.27-alpine",
    "example-worker": "docker pull redis:7.4-alpine",
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# The token is read from the environment and never stored here: this file is meant
# to be edited and committed, and an ingest token in version control is a
# credential leak that outlives whoever noticed.
API_URL = os.environ.get("SBOM_API_URL", "http://localhost:3000").rstrip("/")
INGEST_TOKEN = os.environ.get("SBOM_INGEST_TOKEN", "")

DOCKER_BIN = os.environ.get("DOCKER_BIN", "docker")
SYFT_BIN = os.environ.get("SYFT_BIN", "syft")

# Pulling a large image over a slow link legitimately takes minutes, and so does
# cataloguing one with many layers. These are guards against a hung process, not
# performance targets.
PULL_TIMEOUT_SECONDS = int(os.environ.get("SBOM_PULL_TIMEOUT", "1800"))
SCAN_TIMEOUT_SECONDS = int(os.environ.get("SBOM_SCAN_TIMEOUT", "1800"))
UPLOAD_TIMEOUT_SECONDS = 300


class StepError(Exception):
    """A step failed for one image. Reported and skipped; the run continues."""


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------


def run(cmd: List[str], timeout: int, capture_stdout: bool) -> bytes:
    """
    Run a command, returning stdout when asked for it.

    stderr is always captured separately rather than merged: Syft writes its
    progress bar there while the SBOM goes to stdout, so merging the two would
    corrupt every SBOM this script produces.
    """
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture_stdout else None,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        raise StepError("%s is not on PATH" % cmd[0])
    except subprocess.TimeoutExpired:
        raise StepError("%s timed out after %ss" % (cmd[0], timeout))

    if proc.returncode != 0:
        detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
        # Only the tail: docker and syft both emit long progress output before the
        # line that actually explains the failure.
        tail = detail.splitlines()[-4:] if detail else ["exit code %d" % proc.returncode]
        raise StepError("%s failed: %s" % (cmd[0], " | ".join(tail)))

    return proc.stdout or b""


def parse_target(value: str) -> Tuple[str, List[str]]:
    """
    Split a dictionary value into the image reference and any pull flags.

    Both of these mean the same thing:

        "nginx:1.27-alpine"
        "docker pull nginx:1.27-alpine"

    Accepting the command form is not a convenience for its own sake. Image lists
    arrive pasted from runbooks, tickets and chat messages, where they are written
    as the command someone ran; requiring each line to be stripped back to a bare
    reference is an editing pass over forty entries that will occasionally take a
    character with it.

    Flags are preserved and handed to the pull, so `docker pull --platform
    linux/amd64 nginx:1.27` does what it reads as. Only the bare reference is used
    for the scan and recorded on the upload, because `--platform` describes how the
    image was fetched, not which image it is.

    The reference is taken to be the LAST word, which is where docker requires the
    positional argument to sit anyway.
    """
    try:
        tokens = shlex.split(value.strip())
    except ValueError as err:
        # Unbalanced quotes. Left to the caller to report against the entry.
        raise StepError("cannot parse %r: %s" % (value, err))

    if not tokens:
        raise StepError("empty image reference")

    # Strip a leading `docker pull` / `docker image pull`, however docker was spelled.
    if tokens[0].lower().replace(".exe", "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1] == "docker":
        tokens = tokens[1:]
        if tokens[:1] == ["image"]:
            tokens = tokens[1:]
        if tokens[:1] == ["pull"]:
            tokens = tokens[1:]
        else:
            raise StepError("expected `docker pull ...` in %r" % value)

    if not tokens:
        raise StepError("no image reference in %r" % value)

    image = tokens[-1]
    if image.startswith("-"):
        # Otherwise a trailing flag would be pulled as though it were an image, and
        # the error would come back from docker naming something the user never typed.
        raise StepError("the image reference must come last in %r" % value)

    return image, tokens[:-1]


def pull(image: str, flags: List[str]) -> None:
    run([DOCKER_BIN, "pull"] + flags + [image], PULL_TIMEOUT_SECONDS, capture_stdout=True)


def resolve_digest(image: str) -> Optional[str]:
    """
    The pulled image's repo digest, for the log only.

    Best-effort: an image built locally and never pushed has no repo digest, which
    is normal and not a failure. Logging it makes a run reproducible after the fact
    even when the tag has since moved.
    """
    try:
        out = run(
            [DOCKER_BIN, "image", "inspect", "--format", "{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}", image],
            60,
            capture_stdout=True,
        )
    except StepError:
        return None
    return out.decode("utf-8", "replace").strip() or None


def scan(image: str) -> bytes:
    """
    Produce a CycloneDX JSON SBOM for an already-pulled image.

    `syft scan` rather than the bare `syft <image>` form, which is deprecated in
    Syft 1.x. If your Syft predates the subcommand, set SYFT_SUBCOMMAND="" in the
    environment to fall back.
    """
    subcommand = os.environ.get("SYFT_SUBCOMMAND", "scan")
    cmd = [SYFT_BIN]
    if subcommand:
        cmd.append(subcommand)
    cmd += [image, "-o", "cyclonedx-json"]

    sbom = run(cmd, SCAN_TIMEOUT_SECONDS, capture_stdout=True)
    if not sbom.strip():
        raise StepError("syft produced an empty SBOM")
    return sbom


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------


def build_multipart(fields: Dict[str, str], sbom: bytes) -> Tuple[bytes, str]:
    """
    Encode the `multipart/form-data` body the ingest endpoint expects.

    Hand-rolled because the standard library has no multipart encoder and the
    alternative is a dependency this script exists to avoid. The boundary is
    random per request, so it cannot collide with SBOM contents.
    """
    boundary = "----sbom-upload-" + uuid.uuid4().hex
    parts: List[bytes] = []

    for name, value in fields.items():
        parts.append(
            (
                "--%s\r\n"
                'Content-Disposition: form-data; name="%s"\r\n\r\n'
                "%s\r\n" % (boundary, name, value)
            ).encode("utf-8")
        )

    parts.append(
        (
            "--%s\r\n"
            'Content-Disposition: form-data; name="sbom"; filename="sbom.cdx.json"\r\n'
            "Content-Type: application/json\r\n\r\n" % boundary
        ).encode("utf-8")
    )
    parts.append(sbom)
    parts.append(("\r\n--%s--\r\n" % boundary).encode("utf-8"))

    return b"".join(parts), "multipart/form-data; boundary=%s" % boundary


def upload(app_name: str, image: str, sbom: bytes, extra: Dict[str, str]) -> dict:
    """
    POST one SBOM to the ingest endpoint, retrying only what is worth retrying.

    The endpoint's status codes are its contract: 4xx means the request itself is
    wrong and will be wrong again, so retrying it just delays the error. Only 5xx
    and transport failures are retried.
    """
    fields = {"app_name": app_name, "image_ref": image}
    fields.update({k: v for k, v in extra.items() if v})
    body, content_type = build_multipart(fields, sbom)

    attempts = 3
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            "%s/api/v1/scans" % API_URL,
            data=body,
            method="POST",
            headers={
                "Authorization": "Bearer %s" % INGEST_TOKEN,
                "Content-Type": content_type,
                "Content-Length": str(len(body)),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=UPLOAD_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            detail = describe_http_error(err)
            if err.code >= 500 and attempt < attempts:
                print("      %s -- retrying (%d/%d)" % (detail, attempt, attempts))
                time.sleep(2 * attempt)
                continue
            raise StepError(detail)
        except urllib.error.URLError as err:
            if attempt < attempts:
                print("      cannot reach %s: %s -- retrying (%d/%d)" % (API_URL, err.reason, attempt, attempts))
                time.sleep(2 * attempt)
                continue
            raise StepError("cannot reach %s: %s" % (API_URL, err.reason))

    raise StepError("upload failed after %d attempts" % attempts)


def describe_http_error(err: urllib.error.HTTPError) -> str:
    """
    Turn an error response into one readable line.

    The API answers with a JSON envelope carrying a code and a message written for
    a human, so surfacing that beats printing a bare status. The few codes with a
    specific cause get a hint, because the fix is not obvious from the status alone.
    """
    try:
        payload = json.loads(err.read().decode("utf-8"))
        message = payload.get("error", {}).get("message") or str(payload)
    except Exception:
        message = err.reason or "no response body"

    hints = {
        401: "check SBOM_INGEST_TOKEN -- it may be wrong or revoked",
        413: "the SBOM is larger than the server's INGEST_MAX_SBOM_BYTES",
        415: "the request was not multipart/form-data (a proxy may have rewritten it)",
        422: "the file syft produced was not accepted as CycloneDX",
    }
    hint = hints.get(err.code)
    return "HTTP %d: %s%s" % (err.code, message, " (%s)" % hint if hint else "")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def preflight(skip_pull: bool) -> List[str]:
    """Everything that would fail identically for all 40 images, checked once."""
    problems = []
    if not INGEST_TOKEN:
        problems.append("SBOM_INGEST_TOKEN is not set (Admin -> Ingest tokens on the platform)")
    if not skip_pull and shutil.which(DOCKER_BIN) is None:
        problems.append("%s is not on PATH" % DOCKER_BIN)
    if shutil.which(SYFT_BIN) is None:
        problems.append("%s is not on PATH" % SYFT_BIN)
    if not IMAGES:
        problems.append("the IMAGES dictionary is empty -- add entries at the top of this file")

    for name, value in IMAGES.items():
        # Checked here rather than left to a 400 from the server, because a blank
        # or control-character name is nearly always a copy-paste artefact and the
        # server's rejection arrives after a pull and a scan have already run.
        if not name.strip():
            problems.append("an entry has a blank application name")
        elif any(ord(ch) < 32 for ch in name):
            problems.append("application name %r contains control characters" % name)

        # Same reasoning applied to the value: an unparseable entry halfway down the
        # dictionary should be reported now, not after thirty images have been
        # pulled and scanned.
        try:
            parse_target(value)
        except StepError as err:
            problems.append("%s: %s" % (name, err))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Pull, scan and upload container SBOMs.")
    parser.add_argument("--only", action="append", metavar="NAME",
                        help="process just this application (repeatable)")
    parser.add_argument("--no-pull", action="store_true",
                        help="scan the local copy without pulling first")
    parser.add_argument("--dry-run", action="store_true",
                        help="pull and scan, but do not upload")
    parser.add_argument("--branch", help="record a branch on every scan")
    parser.add_argument("--build-number", help="record a build number on every scan")
    args = parser.parse_args()

    problems = preflight(args.no_pull)
    if problems:
        print("Cannot start:")
        for problem in problems:
            print("  - %s" % problem)
        return 2

    targets = dict(IMAGES)
    if args.only:
        wanted = {n.lower() for n in args.only}
        targets = {k: v for k, v in IMAGES.items() if k.lower() in wanted}
        missing = wanted - {k.lower() for k in IMAGES}
        if missing:
            print("Not in IMAGES: %s" % ", ".join(sorted(missing)))
            return 2

    extra = {"branch": args.branch or "", "build_number": args.build_number or ""}

    print("%s -> %d image(s)%s\n" % (API_URL, len(targets), "  [dry run]" if args.dry_run else ""))

    succeeded: List[str] = []
    failed: List[Tuple[str, str]] = []
    created: List[str] = []

    for index, (app_name, value) in enumerate(targets.items(), start=1):
        print("[%d/%d] %s  <-  %s" % (index, len(targets), app_name, value))
        try:
            # Both `nginx:1.27` and `docker pull nginx:1.27` are accepted, so the
            # reference is extracted here rather than assumed to be the raw value.
            image, pull_flags = parse_target(value)
            if args.no_pull:
                print("      skipping pull")
            else:
                print("      pulling %s" % image)
                pull(image, pull_flags)
                digest = resolve_digest(image)
                if digest:
                    print("      digest %s" % digest)

            print("      scanning")
            sbom = scan(image)
            print("      %s SBOM" % human_bytes(len(sbom)))

            if args.dry_run:
                print("      not uploading (dry run)")
                succeeded.append(app_name)
                continue

            result = upload(app_name, image, sbom, extra)
            note = ""
            if result.get("applicationCreated"):
                created.append(result.get("applicationName", app_name))
                note = "  [new application, awaiting confirmation]"
            elif result.get("redirectedFrom"):
                # A merge-always alias sent this somewhere else. Silence here would
                # leave the key in this file looking like it worked as written.
                note = "  [alias redirected from %s]" % result["redirectedFrom"]

            skipped = result.get("skippedComponents") or 0
            print("      uploaded: %d components%s%s" % (
                result.get("componentCount", 0),
                ", %d skipped" % skipped if skipped else "",
                note,
            ))
            succeeded.append(app_name)

        except StepError as err:
            # One bad image must not cost the other thirty-nine their scan.
            print("      FAILED: %s" % err)
            failed.append((app_name, str(err)))

        print("")

    print("-" * 60)
    print("%d succeeded, %d failed" % (len(succeeded), len(failed)))
    if created:
        print("\nNew applications, awaiting confirmation in Admin -> Pending:")
        for name in created:
            print("  - %s" % name)
    if failed:
        print("\nFailed:")
        for name, reason in failed:
            print("  - %s: %s" % (name, reason))

    # Non-zero when anything failed, so a scheduled run is visibly broken rather
    # than quietly half-done.
    return 1 if failed else 0


def human_bytes(count: int) -> str:
    size = float(count)
    for unit in ("B", "KB", "MB"):
        if size < 1024 or unit == "MB":
            return "%.0f %s" % (size, unit) if unit == "B" else "%.1f %s" % (size, unit)
        size /= 1024
    return "%d B" % count


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
