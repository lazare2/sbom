from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

CI_SCRIPT = Path(__file__).parent.parent / "ci_ingest_payload.py"


def test_build_payload_omits_blank_environment() -> None:
    sys.path.insert(0, str(CI_SCRIPT.parent))
    import ci_ingest_payload as mod

    payload = mod.build_payload([], "my-app", "abc123", "main", "")
    assert "environment" not in payload
    assert payload == {"app_name": "my-app", "commit_sha": "abc123", "branch": "main", "findings": []}


def test_build_payload_includes_environment_when_set() -> None:
    sys.path.insert(0, str(CI_SCRIPT.parent))
    import ci_ingest_payload as mod

    payload = mod.build_payload([], "my-app", environment="production")
    assert payload["environment"] == "production"


def test_cli_end_to_end(tmp_path: Path) -> None:
    findings = [
        {
            "rule_id": "PY-EVAL-001",
            "severity": "HIGH",
            "cwe": 95,
            "message": "eval() is dangerous",
            "file": "app.py",
            "line": 3,
            "col": 5,
        }
    ]
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(findings), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(CI_SCRIPT), str(findings_file), "my-app", "abc123", "main"],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["app_name"] == "my-app"
    assert payload["commit_sha"] == "abc123"
    assert payload["branch"] == "main"
    assert payload["findings"] == findings
    assert "environment" not in payload


def test_cli_missing_args_exits_nonzero() -> None:
    result = subprocess.run(
        [sys.executable, str(CI_SCRIPT)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
