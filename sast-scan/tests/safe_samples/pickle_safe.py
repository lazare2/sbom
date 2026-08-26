"""Safe: pickle.loads called on a fixed literal, and json used for external data."""

import json
import pickle


def deserialize_literal() -> object:
    # A hardcoded literal payload is not attacker-controlled.
    return pickle.loads(b"\x80\x04N.")


def deserialize_external(raw: str) -> object:
    return json.loads(raw)
