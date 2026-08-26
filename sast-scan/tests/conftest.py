from __future__ import annotations

from pathlib import Path

import pytest

from sast.engine import DEFAULT_RULES_PATH, load_rules, load_taint_config

TESTS_DIR = Path(__file__).parent
VULNERABLE_DIR = TESTS_DIR / "vulnerable_samples"
SAFE_DIR = TESTS_DIR / "safe_samples"


@pytest.fixture(scope="session")
def rules():
    return load_rules(DEFAULT_RULES_PATH)


@pytest.fixture(scope="session")
def taint_cfg():
    return load_taint_config(DEFAULT_RULES_PATH)


@pytest.fixture(scope="session")
def vulnerable_dir() -> Path:
    return VULNERABLE_DIR


@pytest.fixture(scope="session")
def safe_dir() -> Path:
    return SAFE_DIR
