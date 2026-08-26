from __future__ import annotations

from pathlib import Path

import pytest

from sast.analyzer import analyze_file

# rule_id -> (vulnerable sample filename, safe sample filename)
AST_RULE_CASES = [
    ("PY-EVAL-001", "eval_exec.py", "eval_exec_safe.py"),
    ("PY-EXEC-001", "eval_exec.py", "eval_exec_safe.py"),
    ("PY-PICKLE-UNSAFE-DESERIALIZATION-001", "pickle_unsafe.py", "pickle_safe.py"),
    ("PY-SUBPROCESS-SHELL-TRUE-001", "subprocess_shell.py", "subprocess_no_shell_safe.py"),
    ("PY-YAML-UNSAFE-LOAD-001", "yaml_unsafe_load.py", "yaml_safe_load.py"),
    ("PY-WEAK-HASH-MD5-001", "weak_hash.py", "weak_hash_safe.py"),
    ("PY-WEAK-HASH-SHA1-001", "weak_hash.py", "weak_hash_safe.py"),
    ("PY-WEAK-RANDOM-001", "weak_random.py", "weak_random_safe.py"),
    ("PY-ASSERT-SECURITY-CHECK-001", "assert_security.py", "assert_safe.py"),
]


@pytest.mark.parametrize("rule_id,vuln_file,safe_file", AST_RULE_CASES)
def test_rule_triggers_on_vulnerable_sample(
    rule_id, vuln_file, safe_file, vulnerable_dir, safe_dir, rules, taint_cfg
) -> None:
    findings = analyze_file(vulnerable_dir / vuln_file, rules, taint_cfg)
    ids = [f.rule_id for f in findings]
    assert rule_id in ids, f"expected {rule_id} in {ids} for {vuln_file}"


@pytest.mark.parametrize("rule_id,vuln_file,safe_file", AST_RULE_CASES)
def test_rule_silent_on_safe_sample(
    rule_id, vuln_file, safe_file, vulnerable_dir, safe_dir, rules, taint_cfg
) -> None:
    findings = analyze_file(safe_dir / safe_file, rules, taint_cfg)
    ids = [f.rule_id for f in findings]
    assert rule_id not in ids, f"did not expect {rule_id} in {ids} for {safe_file}"


# rule_id -> (vulnerable sample filename, safe sample filename, expected cwe)
TAINT_CASES = [
    ("TAINT-OS-SYSTEM", "taint_command_injection.py", "taint_command_injection_safe.py", 78),
    ("TAINT-EXECUTE", "taint_sql_injection.py", "taint_sql_injection_safe.py", 89),
    ("TAINT-EVAL", "taint_eval_injection.py", "taint_eval_injection_safe.py", 95),
]


@pytest.mark.parametrize("rule_id,vuln_file,safe_file,cwe", TAINT_CASES)
def test_taint_triggers_on_vulnerable_sample(
    rule_id, vuln_file, safe_file, cwe, vulnerable_dir, safe_dir, rules, taint_cfg
) -> None:
    findings = analyze_file(vulnerable_dir / vuln_file, rules, taint_cfg)
    matches = [f for f in findings if f.rule_id == rule_id]
    assert matches, f"expected {rule_id} in {[f.rule_id for f in findings]} for {vuln_file}"
    assert matches[0].severity.value == "HIGH"
    assert matches[0].cwe == cwe


@pytest.mark.parametrize("rule_id,vuln_file,safe_file,cwe", TAINT_CASES)
def test_taint_silent_on_safe_sample(
    rule_id, vuln_file, safe_file, cwe, vulnerable_dir, safe_dir, rules, taint_cfg
) -> None:
    findings = analyze_file(safe_dir / safe_file, rules, taint_cfg)
    ids = [f.rule_id for f in findings]
    assert rule_id not in ids, f"did not expect {rule_id} in {ids} for {safe_file}"


def test_subprocess_shell_true_reports_cwe_78(vulnerable_dir: Path, rules, taint_cfg) -> None:
    findings = analyze_file(vulnerable_dir / "subprocess_shell.py", rules, taint_cfg)
    matches = [f for f in findings if f.rule_id == "PY-SUBPROCESS-SHELL-TRUE-001"]
    assert len(matches) == 2
    assert all(f.cwe == 78 and f.severity.value == "HIGH" for f in matches)


def test_syntax_error_file_returns_no_findings(tmp_path: Path, rules, taint_cfg) -> None:
    bad = tmp_path / "broken.py"
    bad.write_text("def f(:\n    pass\n", encoding="utf-8")
    assert analyze_file(bad, rules, taint_cfg) == []


def test_taint_not_triggered_without_source(tmp_path: Path, rules, taint_cfg) -> None:
    sample = tmp_path / "clean.py"
    sample.write_text(
        "import os\n\n"
        "def run() -> None:\n"
        "    cmd = 'ls -la'\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )
    findings = analyze_file(sample, rules, taint_cfg)
    assert not any(f.rule_id.startswith("TAINT-") for f in findings)


def test_taint_propagates_through_fstring(tmp_path: Path, rules, taint_cfg) -> None:
    sample = tmp_path / "fstring.py"
    sample.write_text(
        "import os\n\n"
        "def run() -> None:\n"
        "    host = input('host: ')\n"
        "    os.system(f'ping {host}')\n",
        encoding="utf-8",
    )
    findings = analyze_file(sample, rules, taint_cfg)
    assert any(f.rule_id == "TAINT-OS-SYSTEM" for f in findings)


def test_findings_carry_category_and_remediation(vulnerable_dir, rules, taint_cfg) -> None:
    """Every bundled rule ships fix guidance, and labels which method found it."""
    ast_findings = analyze_file(vulnerable_dir / "eval_exec.py", rules, taint_cfg)
    assert ast_findings
    for f in ast_findings:
        assert f.category.value == "ast"
        assert f.remediation, f"{f.rule_id} has no remediation"

    taint_findings = [
        f
        for f in analyze_file(vulnerable_dir / "taint_command_injection.py", rules, taint_cfg)
        if f.rule_id.startswith("TAINT-")
    ]
    assert taint_findings
    for f in taint_findings:
        assert f.category.value == "taint"
        assert f.remediation, f"{f.rule_id} has no remediation"
