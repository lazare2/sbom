"""Regex-based secret scanning (line-oriented, independent of the AST engine)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sast.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class SecretPattern:
    id: str
    regex: re.Pattern[str]
    severity: Severity
    cwe: int
    message: str


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        id="SECRET-AWS-ACCESS-KEY",
        regex=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity=Severity.CRITICAL,
        cwe=798,
        message="Hardcoded AWS access key ID detected.",
    ),
    SecretPattern(
        id="SECRET-PRIVATE-KEY",
        regex=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        cwe=321,
        message="Hardcoded private key material detected in source.",
    ),
    SecretPattern(
        id="SECRET-HARDCODED-PASSWORD",
        regex=re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"']{3,})[\"']"),
        severity=Severity.HIGH,
        cwe=798,
        message="Hardcoded password detected in source code.",
    ),
    SecretPattern(
        id="SECRET-GENERIC-API-KEY",
        regex=re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|token)"
            r"\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']"
        ),
        severity=Severity.MEDIUM,
        cwe=798,
        message="Hardcoded API key or token detected in source code.",
    ),
)


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file line-by-line for hardcoded secrets."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern in SECRET_PATTERNS:
            match = pattern.regex.search(line)
            if match:
                findings.append(
                    Finding(
                        rule_id=pattern.id,
                        severity=pattern.severity,
                        cwe=pattern.cwe,
                        message=pattern.message,
                        file=str(path),
                        line=lineno,
                        col=match.start() + 1,
                    )
                )
    return findings
