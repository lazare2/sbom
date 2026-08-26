"""Output formatting: colorized console report, JSON, and SARIF 2.1.0."""

from __future__ import annotations

import json
import textwrap
from typing import Iterable

from sast.models import Finding, Severity, severity_rank

_COLOR: dict[Severity, str] = {
    Severity.LOW: "\033[36m",  # cyan
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.HIGH: "\033[31m",  # red
    Severity.CRITICAL: "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


def _group_by_file(findings: Iterable[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.file, []).append(finding)
    for items in grouped.values():
        items.sort(key=lambda f: (f.line, f.col))
    return grouped


def format_console(
    findings: list[Finding], use_color: bool = True, show_remediation: bool = False
) -> str:
    """Render findings grouped by file, color-coded by severity.

    ``show_remediation`` prints each rule's fix guidance under the finding. Off
    by default because the usual caller is a CI log, where the same paragraph
    repeated once per finding buries the list it is annotating. A developer
    reading the output by hand passes ``--explain`` and wants exactly that.
    """
    if not findings:
        return "No findings."

    lines: list[str] = []
    grouped = _group_by_file(findings)
    for file in sorted(grouped):
        lines.append(f"\n{file}")
        for finding in grouped[file]:
            color = _COLOR[finding.severity] if use_color else ""
            reset = _RESET if use_color else ""
            lines.append(
                f"  {color}[{finding.severity.value}]{reset} {finding.rule_id} "
                f"line {finding.line}:{finding.col} (CWE-{finding.cwe}) - {finding.message}"
            )
            if show_remediation and finding.remediation:
                dim = "\033[2m" if use_color else ""
                wrapped = textwrap.wrap(finding.remediation, width=72)
                for i, chunk in enumerate(wrapped):
                    label = "fix: " if i == 0 else "     "
                    lines.append(f"      {dim}{label}{chunk}{reset}")

    total = len(findings)
    by_severity = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    summary = ", ".join(f"{by_severity[s]} {s.value}" for s in Severity if by_severity[s])
    lines.append(f"\n{total} finding(s): {summary}")
    return "\n".join(lines)


def format_json(findings: list[Finding]) -> str:
    """Render findings as a plain JSON array."""
    return json.dumps(
        [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "cwe": f.cwe,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "col": f.col,
                "category": f.category.value,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        indent=2,
    )


_SARIF_LEVEL: dict[Severity, str] = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def format_sarif(
    findings: list[Finding], tool_name: str = "sast-tool", tool_version: str = "0.1.0"
) -> str:
    """Render findings as a SARIF 2.1.0 log."""
    rule_ids = sorted({f.rule_id for f in findings})
    rules_meta = []
    for rule_id in rule_ids:
        sample = next(f for f in findings if f.rule_id == rule_id)
        rules_meta.append(
            {
                "id": rule_id,
                "shortDescription": {"text": sample.message},
                # SARIF's conventional home for "what do I do about it" -- GitHub
                # code scanning and VS Code both surface `help` beside the result.
                **({"help": {"text": sample.remediation}} if sample.remediation else {}),
                "properties": {
                    "cwe": f"CWE-{sample.cwe}",
                    "security-severity": sample.severity.value,
                    "category": sample.category.value,
                },
            }
        )

    results = [
        {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line, "startColumn": f.col},
                    }
                }
            ],
            "properties": {"severity": f.severity.value, "cwe": f"CWE-{f.cwe}"},
        }
        for f in findings
    ]

    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/example/sast-tool",
                        "rules": rules_meta,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def has_blocking_findings(findings: Iterable[Finding]) -> bool:
    """True if any finding is HIGH or CRITICAL severity (used for CI exit codes)."""
    return any(severity_rank(f.severity) >= severity_rank(Severity.HIGH) for f in findings)
