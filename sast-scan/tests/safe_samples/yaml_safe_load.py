"""Safe: yaml.load with an explicit SafeLoader, or yaml.safe_load."""

import yaml


def load_config(raw: str) -> object:
    return yaml.load(raw, Loader=yaml.SafeLoader)


def load_config_alt(raw: str) -> object:
    return yaml.safe_load(raw)
