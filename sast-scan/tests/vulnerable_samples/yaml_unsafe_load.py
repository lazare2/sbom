"""Vulnerable: yaml.load without a SafeLoader."""

import yaml


def load_config(raw: str) -> object:
    return yaml.load(raw)


def load_config_unsafe_loader(raw: str) -> object:
    return yaml.load(raw, Loader=yaml.UnsafeLoader)
