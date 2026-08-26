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


class Category(str, Enum):
    """Which of the three detection methods produced a finding.

    Carried explicitly rather than inferred from the rule id prefix at the
    point of display: a custom rules file may use any id it likes, and someone
    filtering for "just the hardcoded secrets" should not have to know this
    tool's naming convention to do it.
    """

    SECRETS = "secrets"
    AST = "ast"
    TAINT = "taint"


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
    category: Category = Category.AST
    #: What to actually do about it. Empty when a custom rules file omits it,
    #: so every consumer treats it as optional rather than assuming the
    #: bundled rules are the only ones in play.
    remediation: str = ""
