"""
Sets one attribute to one value across a list of applications.

    set SBOM_API_URL=https://sbom.example.com    (default http://localhost:8080)
    set SBOM_API_TOKEN=sbp_...
    python scripts/set_project_attribute.py --attribute team_owner --value Payments
    python scripts/set_project_attribute.py --attribute team_owner --value Payments --apply

Reads application names from a file, one per line, and PATCHes the named attribute on each.
Nothing is written without `--apply`: the default is a dry run that reports exactly what would
change, because this touches every application in the file in one pass and the way back is by
hand.

No third-party packages -- standard library only, so it runs on a locked-down machine with no
pip access.

## Three things this is careful about, each because the obvious version gets them wrong

**The status filter is a trap.** Omitting `status` from the applications query defaults to
active *plus* pending_confirmation. Passing `status=active&status=inactive` is therefore
NARROWER than passing nothing, and it hides every unconfirmed application -- which is most of
them, since CI auto-creates an application as unconfirmed and it stays that way until somebody
confirms it. A script that filters that way reports "not found" for the whole estate while the
request returns 200. This sends no status filter at all.

**"Not found" and "the request failed" are different answers.** A single `None` for both means
an expired token reports every application as missing. They are distinguished here, and a
transport or authentication failure stops the run rather than being counted as 199 skips.

**The attribute has to exist first.** Values are validated against the definition, so an
undefined key is a 400 per application. That is checked once, up front, before anything is
written.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# --- configuration ---------------------------------------------------------

# The platform's address. The default is the offline bundle's own; set SBOM_API_URL for any
# other installation.
BASE_URL = os.environ.get("SBOM_API_URL", "http://localhost:8080").rstrip("/")

# Read from the environment and never written into this file: a token with write access is a
# credential, and a script in version control is not a place to keep one.
API_TOKEN = os.environ.get("SBOM_API_TOKEN", "")

# Certificate verification is on unless SBOM_VERIFY_TLS=0. Turn it off only for an installation
# whose certificate this machine cannot check (a private CA not in its trust store): anything
# able to sit in the path of these requests can then read the bearer token they carry, so the
# token this runs with should be scoped no wider than the job needs.
VERIFY_SSL = os.environ.get("SBOM_VERIFY_TLS", "1").strip().lower() not in ("0", "false", "no")

# Which estate to act on. Without it the API falls back to the OLDEST environment the token can
# reach, which is Production on an upgraded deployment -- correct today and wrong the moment a
# second estate exists, silently and in the dangerous direction.
ENVIRONMENT = os.environ.get("SBOM_ENVIRONMENT", "Production")

# The applications query caps at 200 per page. Names are searched one at a time, so this is a
# ceiling on how many near-matches one name may have before the exact one could be missed.
PAGE_SIZE = 200

TIMEOUT = 30


class ApiError(RuntimeError):
    """A request that did not succeed. Distinct from 'the application does not exist'."""

    def __init__(self, status: int, body: str, url: str) -> None:
        super().__init__(f"HTTP {status} from {url}: {body[:400]}")
        self.status = status
        self.body = body


def _context() -> ssl.SSLContext | None:
    if VERIFY_SSL:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request(method: str, path: str, *, params: dict[str, Any] | None = None,
            body: dict[str, Any] | None = None) -> Any:
    """
    One HTTP call. Raises ApiError on any non-2xx, so a caller cannot mistake a refusal for
    an empty result.
    """
    url = f"{BASE_URL}/api/v1{path}"
    if params:
        # doseq so a list becomes repeated parameters rather than one bracketed string.
        url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"

    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {API_TOKEN}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_context()) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as exc:
        raise ApiError(exc.code, exc.read().decode("utf-8", "replace"), url) from exc
    except urllib.error.URLError as exc:
        raise ApiError(0, f"could not reach the platform: {exc.reason}", url) from exc


# --- preflight -------------------------------------------------------------

def check_token() -> dict[str, Any]:
    """
    Who the token is, and whether it can write.

    Run before anything else so a bad credential is one clear message rather than one per
    application. An expired token on the old script reported the whole estate as missing.
    """
    me = request("GET", "/auth/me")["user"]
    if me["role"] != "admin":
        sys.exit(
            f"The token belongs to '{me['email']}', which is not an administrator.\n"
            "Changing application attributes needs an admin account."
        )
    return me


def check_attribute(key: str, value: str) -> None:
    """
    That the attribute is defined, and that the value is one it will accept.

    Checked once. Without this the first sign of an undefined key is a 400 per application,
    after the run has already started.
    """
    definitions = request("GET", "/attribute-definitions")["definitions"]
    match = next((d for d in definitions if d["key"] == key), None)
    if match is None:
        keys = ", ".join(sorted(d["key"] for d in definitions)) or "(none defined)"
        sys.exit(
            f"No attribute named '{key}' is defined. Defined keys are: {keys}\n\n"
            "Define it once with:\n"
            f"  curl -X POST -H \"Authorization: Bearer $SBOM_API_TOKEN\" \\\n"
            f"    -H 'Content-Type: application/json' \\\n"
            f"    -d '{{\"key\":\"{key}\",\"label\":\"{key}\",\"type\":\"string\"}}' \\\n"
            f"    {BASE_URL}/api/v1/admin/attribute-definitions"
        )
    if not match.get("isActive", True):
        sys.exit(f"The attribute '{key}' exists but is not active, so values cannot be set.")

    # A select attribute rejects anything outside its options, and the message it returns is
    # per-application. Caught here instead.
    options = match.get("options")
    if match["type"] == "select" and options and value not in options:
        sys.exit(
            f"'{key}' is a select attribute and '{value}' is not one of its options.\n"
            f"Permitted: {', '.join(options)}"
        )


def load_names(path: str) -> list[str]:
    if not os.path.isfile(path):
        sys.exit(f"File '{path}' was not found.")

    names: list[str] = []
    seen: set[str] = set()
    # utf-8-sig, not utf-8: a file saved from Notepad carries a byte-order mark, which would
    # otherwise become part of the first name and make that one application unfindable.
    with open(path, "r", encoding="utf-8-sig") as handle:
        for line in handle:
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            # Names match case-insensitively on the platform, so two spellings of one name are
            # one application -- de-duplicated here so the summary counts it once.
            key = cleaned.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(cleaned)
    return names


# --- the work --------------------------------------------------------------

def find_application(name: str) -> dict[str, Any] | None:
    """
    One application by exact name, or None if the estate has no such application.

    Raises on a failed request rather than returning None -- see the note at the top of the
    file. No `status` filter is sent: the default already covers active and unconfirmed
    applications, and naming statuses explicitly is how the whole estate gets hidden.
    """
    page = request("GET", "/applications", params={
        "search": name,
        "environment": ENVIRONMENT,
        "pageSize": PAGE_SIZE,
    })

    items = page.get("items", [])
    total = int(page.get("total", len(items)))
    if total > len(items):
        # `search` is a substring match, so a short name can match more than one page. Said
        # out loud, because the alternative is reporting an application as absent when it was
        # merely on page two.
        print(
            f"  [WARN] '{name}' matched {total} applications; only the first {len(items)} "
            "were examined. Use a more specific name.",
            file=sys.stderr,
        )

    needle = name.strip().lower()
    for app in items:
        if str(app.get("name", "")).strip().lower() == needle:
            return app
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Set one attribute to one value across a list of applications.",
    )
    parser.add_argument("--file", default="projects.txt", help="one application name per line")
    parser.add_argument("--attribute", required=True, help="the attribute key, e.g. team_owner")
    parser.add_argument("--value", required=True, help="the value to set")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually write. Without it this reports what would change and writes nothing.",
    )
    args = parser.parse_args()

    if not API_TOKEN:
        sys.exit("SBOM_API_TOKEN is not set. Mint one on the API access page (write scope).")

    me = check_token()
    check_attribute(args.attribute, args.value)
    names = load_names(args.file)
    if not names:
        print(f"No application names in '{args.file}'. Nothing to do.")
        return 0

    mode = "APPLYING" if args.apply else "DRY RUN -- nothing will be written"
    print(f"{mode}")
    print(f"  platform    {BASE_URL}  (estate: {ENVIRONMENT})")
    print(f"  as          {me['email']}")
    print(f"  setting     {args.attribute} = {args.value!r}")
    print(f"  across      {len(names)} application(s) from {args.file}\n")

    changed: list[str] = []
    already: list[str] = []
    missing: list[str] = []
    failed: list[tuple[str, str]] = []

    for name in names:
        try:
            app = find_application(name)
        except ApiError as exc:
            # A transport or credential failure is not a per-application problem, and
            # continuing would turn one broken token into a report of an empty estate.
            print(f"\nStopped: {exc}", file=sys.stderr)
            print(
                "This is a request failure, not a missing application. "
                "Nothing further was attempted.",
                file=sys.stderr,
            )
            return 2

        if app is None:
            missing.append(name)
            print(f"  [MISSING]   {name}")
            continue

        current = (app.get("attributes") or {}).get(args.attribute)
        if current == args.value:
            # Skipped rather than rewritten: an identical write still produces an audit row,
            # and a trail full of changes that changed nothing is a trail nobody reads.
            already.append(name)
            print(f"  [UNCHANGED] {name}  (already {args.value!r})")
            continue

        was = "unset" if current is None else repr(current)
        if not args.apply:
            changed.append(name)
            print(f"  [WOULD SET] {name}  ({was} -> {args.value!r})")
            continue

        try:
            # Attributes merge, so this leaves every other attribute on the application alone.
            request("PATCH", f"/admin/applications/{app['id']}",
                    body={"attributes": {args.attribute: args.value}})
            changed.append(name)
            print(f"  [SET]       {name}  ({was} -> {args.value!r})")
        except ApiError as exc:
            if exc.status == 403 and "token_read_only" in exc.body:
                sys.exit(
                    "\nThe token is read-only. Mint one with write access on the API access "
                    "page; nothing was changed."
                )
            failed.append((name, f"HTTP {exc.status}: {exc.body[:200]}"))
            print(f"  [FAILED]    {name}  HTTP {exc.status}", file=sys.stderr)

    print(
        f"\n{'would change' if not args.apply else 'changed'}: {len(changed)}   "
        f"already correct: {len(already)}   not found: {len(missing)}   failed: {len(failed)}"
    )
    if missing:
        print("\nnot found (check the spelling, or the estate):")
        for name in missing:
            print(f"  {name}")
    if failed:
        print("\nfailed:", file=sys.stderr)
        for name, why in failed:
            print(f"  {name}: {why}", file=sys.stderr)
    if not args.apply and changed:
        print("\nRe-run with --apply to write these.")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
