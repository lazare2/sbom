from __future__ import annotations

import json

from sast.models import Finding, Severity
from sast.report import format_console, format_json, format_sarif, has_blocking_findings

SAMPLE_FINDINGS = [
    Finding(
        rule_id="PY-EVAL-001",
        severity=Severity.HIGH,
        cwe=95,
        message="Use of eval() is dangerous.",
        file="a.py",
        line=3,
        col=5,
    ),
    Finding(
        rule_id="PY-WEAK-RANDOM-001",
        severity=Severity.LOW,
        cwe=330,
        message="random is not cryptographically secure.",
        file="a.py",
        line=10,
        col=1,
    ),
    Finding(
        rule_id="SECRET-AWS-ACCESS-KEY",
        severity=Severity.CRITICAL,
        cwe=798,
        message="Hardcoded AWS access key.",
        file="b.py",
        line=1,
        col=1,
    ),
]


def test_format_console_empty() -> None:
    assert format_console([]) == "No findings."


def test_format_console_groups_by_file_and_includes_details() -> None:
    output = format_console(SAMPLE_FINDINGS, use_color=False)
    assert "a.py" in output
    assert "b.py" in output
    assert "PY-EVAL-001" in output
    assert "CWE-95" in output
    assert "line 3:5" in output
    assert "3 finding(s)" in output


def test_format_json_round_trips() -> None:
    output = format_json(SAMPLE_FINDINGS)
    data = json.loads(output)
    assert len(data) == 3
    assert data[0]["rule_id"] == "PY-EVAL-001"
    assert data[0]["severity"] == "HIGH"
    assert data[0]["cwe"] == 95


def test_format_sarif_is_valid_structure() -> None:
    output = format_sarif(SAMPLE_FINDINGS)
    data = json.loads(output)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "sast-tool"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"PY-EVAL-001", "PY-WEAK-RANDOM-001", "SECRET-AWS-ACCESS-KEY"}
    assert len(run["results"]) == 3
    result = run["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] > 0


def test_has_blocking_findings_true_for_high_or_critical() -> None:
    assert has_blocking_findings(SAMPLE_FINDINGS) is True


def test_has_blocking_findings_false_when_only_low_medium() -> None:
    low_only = [f for f in SAMPLE_FINDINGS if f.severity == Severity.LOW]
    assert has_blocking_findings(low_only) is False


def test_has_blocking_findings_false_for_empty() -> None:
    assert has_blocking_findings([]) is False


def test_json_includes_category_and_remediation() -> None:
    from sast.models import Category

    findings = [
        Finding(
            rule_id="PY-EVAL-001",
            severity=Severity.HIGH,
            cwe=95,
            message="eval is dangerous",
            file="a.py",
            line=1,
            col=1,
            category=Category.AST,
            remediation="Use ast.literal_eval().",
        )
    ]
    entry = json.loads(format_json(findings))[0]
    assert entry["category"] == "ast"
    assert entry["remediation"] == "Use ast.literal_eval()."


def test_console_hides_remediation_by_default_and_shows_it_with_flag() -> None:
    from sast.models import Category

    findings = [
        Finding(
            rule_id="PY-EVAL-001",
            severity=Severity.HIGH,
            cwe=95,
            message="eval is dangerous",
            file="a.py",
            line=1,
            col=1,
            category=Category.AST,
            remediation="Use ast dot literal underscore eval instead.",
        )
    ]
    default = format_console(findings, use_color=False)
    assert "fix:" not in default

    explained = format_console(findings, use_color=False, show_remediation=True)
    assert "fix:" in explained
    assert "literal" in explained


def test_sarif_puts_remediation_in_rule_help() -> None:
    from sast.models import Category

    findings = [
        Finding(
            rule_id="PY-EVAL-001",
            severity=Severity.HIGH,
            cwe=95,
            message="eval is dangerous",
            file="a.py",
            line=1,
            col=1,
            category=Category.AST,
            remediation="Use ast.literal_eval().",
        )
    ]
    rule = json.loads(format_sarif(findings))["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["help"]["text"] == "Use ast.literal_eval()."
    assert rule["properties"]["category"] == "ast"
