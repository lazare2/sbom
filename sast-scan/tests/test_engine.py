from __future__ import annotations

from pathlib import Path

import pytest

from sast.engine import DEFAULT_RULES_PATH, Rule, load_rules, load_taint_config
from sast.models import Severity


def test_default_rules_file_exists() -> None:
    assert DEFAULT_RULES_PATH.exists()


def test_load_rules_returns_rule_objects() -> None:
    rules = load_rules(DEFAULT_RULES_PATH)
    assert len(rules) >= 9
    assert all(isinstance(r, Rule) for r in rules)
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"


def test_load_taint_config_has_sources_sinks_sanitizers() -> None:
    cfg = load_taint_config(DEFAULT_RULES_PATH)
    assert {s.name for s in cfg.sources} >= {"input", "sys.argv", "os.environ"}
    assert {s.name for s in cfg.sinks} >= {"os.system", "eval", "exec", "execute"}
    assert "shlex.quote" in cfg.sanitizers
    assert "int" in cfg.sanitizers


def test_custom_rules_file_is_isolated(tmp_path: Path) -> None:
    custom = tmp_path / "custom.yaml"
    custom.write_text(
        "rules:\n"
        "  - id: CUSTOM-001\n"
        "    severity: HIGH\n"
        "    cwe: 1\n"
        "    message: custom rule\n"
        "    pattern:\n"
        "      node: call\n"
        "      call_names: [dangerous_call]\n",
        encoding="utf-8",
    )
    rules = load_rules(custom)
    assert len(rules) == 1
    assert rules[0].id == "CUSTOM-001"
    assert rules[0].severity == Severity.HIGH


def test_load_rules_rejects_non_mapping_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules(bad)
