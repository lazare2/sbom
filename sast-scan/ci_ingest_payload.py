#!/usr/bin/env python3
"""Build the JSON body for ``POST /api/v1/sast`` from a sast-scan JSON report.

Usage::

    python3 ci_ingest_payload.py <findings.json> <app_name> [commit_sha] [branch] [environment]

Reads the array produced by ``python3 -m sast ... --format json`` and wraps it
into ``{app_name, commit_sha, branch, findings, [environment]}``, matching
``ingestSastRequestSchema`` in ``packages/shared``. Writes the result to
stdout.

A separate script rather than a one-liner inlined in each CI template: the
same transform is needed by both the GitLab and Jenkins templates, and Python
is indentation-sensitive in a way that does not survive being embedded in a
YAML block scalar or a shell heredoc without care — a script file sidesteps
that entirely, and is testable on its own (see
``tests/test_ci_ingest_payload.py``).

Standard library only, so it runs anywhere sast-scan itself does.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def build_payload(
    findings: list[dict[str, Any]],
    app_name: str,
    commit_sha: str = "",
    branch: str = "",
    environment: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "app_name": app_name,
        "commit_sha": commit_sha,
        "branch": branch,
        "findings": findings,
    }
    # Omitted rather than sent empty: the platform's schema treats a present
    # but blank `environment` as an error (a name that trims to nothing is
    # never valid), not as "unset" -- so a project that never set
    # SAST_ENVIRONMENT must not have the field appear at all.
    if environment:
        payload["environment"] = environment
    return payload


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(
            "usage: ci_ingest_payload.py <findings.json> <app_name> [commit_sha] [branch] [environment]",
            file=sys.stderr,
        )
        return 2

    findings_path, app_name, *rest = argv
    commit_sha = rest[0] if len(rest) > 0 else ""
    branch = rest[1] if len(rest) > 1 else ""
    environment = rest[2] if len(rest) > 2 else ""

    with open(findings_path, encoding="utf-8") as fh:
        findings = json.load(fh)

    payload = build_payload(findings, app_name, commit_sha, branch, environment)
    json.dump(payload, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
