from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sast.cli import run

PROJECT_ROOT = Path(__file__).parent.parent


def test_run_exits_zero_on_safe_samples(safe_dir: Path, capsys) -> None:
    exit_code = run([str(safe_dir)])
    captured = capsys.readouterr()
    assert exit_code == 0, captured.out
    assert captured.out.strip() == "No findings."


def test_run_exits_one_on_vulnerable_samples(vulnerable_dir: Path, capsys) -> None:
    exit_code = run([str(vulnerable_dir)])
    assert exit_code == 1


def test_run_json_format_reports_many_findings(vulnerable_dir: Path, capsys) -> None:
    exit_code = run([str(vulnerable_dir), "--format", "json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 1
    assert len(data) >= 20  # secrets + AST rules + taint findings across all samples
    rule_ids = {item["rule_id"] for item in data}
    assert "PY-EVAL-001" in rule_ids
    assert "SECRET-AWS-ACCESS-KEY" in rule_ids
    assert "TAINT-OS-SYSTEM" in rule_ids


def test_run_sarif_format_is_valid_json(vulnerable_dir: Path, capsys) -> None:
    run([str(vulnerable_dir), "--format", "sarif"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) >= 20


def test_run_severity_threshold_filters_findings(vulnerable_dir: Path, capsys) -> None:
    run([str(vulnerable_dir), "--format", "json", "--severity-threshold", "CRITICAL"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert all(item["severity"] == "CRITICAL" for item in data)
    assert len(data) < 20


def test_run_exclude_flag_skips_directory(tmp_path: Path, capsys) -> None:
    excluded = tmp_path / "thirdparty"
    excluded.mkdir()
    (excluded / "bad.py").write_text("eval('1')\n", encoding="utf-8")

    exit_code = run([str(tmp_path), "--format", "json", "--exclude", "thirdparty"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    assert data == []


def test_run_custom_rules_file(tmp_path: Path, capsys) -> None:
    target = tmp_path / "sample.py"
    target.write_text("dangerous_call(1)\n", encoding="utf-8")

    custom_rules = tmp_path / "custom.yaml"
    custom_rules.write_text(
        "rules:\n"
        "  - id: CUSTOM-DANGEROUS-CALL\n"
        "    severity: HIGH\n"
        "    cwe: 1\n"
        "    message: custom dangerous call\n"
        "    pattern:\n"
        "      node: call\n"
        "      call_names: [dangerous_call]\n",
        encoding="utf-8",
    )

    exit_code = run([str(target), "--format", "json", "--rules", str(custom_rules)])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 1
    assert data[0]["rule_id"] == "CUSTOM-DANGEROUS-CALL"


def test_end_to_end_subprocess_against_vulnerable_samples() -> None:
    """Full end-to-end: invoke `python -m sast` as a real subprocess."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sast",
            "tests/vulnerable_samples",
            "--format",
            "json",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 1, result.stderr
    data = json.loads(result.stdout)
    assert len(data) >= 20
    assert any(item["rule_id"] == "PY-SUBPROCESS-SHELL-TRUE-001" for item in data)


def test_end_to_end_subprocess_against_safe_samples() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "sast", "tests/safe_samples", "--format", "json"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert data == []
