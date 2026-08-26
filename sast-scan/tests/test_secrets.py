from __future__ import annotations

from pathlib import Path

from sast.secrets import scan_file


def test_aws_key_detected(vulnerable_dir: Path) -> None:
    findings = scan_file(vulnerable_dir / "secrets_aws.py")
    assert any(f.rule_id == "SECRET-AWS-ACCESS-KEY" for f in findings)


def test_aws_key_safe_sample_clean(safe_dir: Path) -> None:
    findings = scan_file(safe_dir / "secrets_aws_safe.py")
    assert not any(f.rule_id == "SECRET-AWS-ACCESS-KEY" for f in findings)


def test_hardcoded_password_detected(vulnerable_dir: Path) -> None:
    findings = scan_file(vulnerable_dir / "secrets_password.py")
    ids = [f.rule_id for f in findings]
    assert ids.count("SECRET-HARDCODED-PASSWORD") >= 2


def test_hardcoded_password_safe_sample_clean(safe_dir: Path) -> None:
    findings = scan_file(safe_dir / "secrets_password_safe.py")
    assert not any(f.rule_id == "SECRET-HARDCODED-PASSWORD" for f in findings)


def test_generic_api_key_detected(vulnerable_dir: Path) -> None:
    findings = scan_file(vulnerable_dir / "secrets_api_key.py")
    ids = [f.rule_id for f in findings]
    assert ids.count("SECRET-GENERIC-API-KEY") >= 2


def test_generic_api_key_safe_sample_clean(safe_dir: Path) -> None:
    findings = scan_file(safe_dir / "secrets_api_key_safe.py")
    assert not any(f.rule_id == "SECRET-GENERIC-API-KEY" for f in findings)


def test_private_key_detected(vulnerable_dir: Path) -> None:
    findings = scan_file(vulnerable_dir / "secrets_private_key.py")
    assert any(f.rule_id == "SECRET-PRIVATE-KEY" for f in findings)


def test_private_key_safe_sample_clean(safe_dir: Path) -> None:
    findings = scan_file(safe_dir / "secrets_private_key_safe.py")
    assert not any(f.rule_id == "SECRET-PRIVATE-KEY" for f in findings)


def test_findings_have_correct_location(tmp_path: Path) -> None:
    sample = tmp_path / "s.py"
    sample.write_text('x = 1\npassword = "hunter22"\n', encoding="utf-8")
    findings = scan_file(sample)
    assert len(findings) == 1
    assert findings[0].line == 2
    assert findings[0].file == str(sample)


def test_secret_findings_carry_category_and_remediation(vulnerable_dir: Path) -> None:
    findings = scan_file(vulnerable_dir / "secrets_aws.py")
    assert findings
    for f in findings:
        assert f.category.value == "secrets"
        assert f.remediation, f"{f.rule_id} has no remediation"
