"""Shared data model: findings and severity levels."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def severity_rank(severity: Severity) -> int:
    """Return an integer rank for comparing/sorting severities (higher = worse)."""
    return _RANK[severity]


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security finding produced by any scanner/analyzer in this tool."""

    rule_id: str
    severity: Severity
    cwe: int
    message: str
    file: str
    line: int
    col: int
