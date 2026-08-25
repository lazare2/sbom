"""Vulnerable: pickle.loads on non-literal (externally-sourced) data."""

import pickle


def deserialize(raw: bytes) -> object:
    return pickle.loads(raw)


def deserialize_from_file(path: str) -> object:
    with open(path, "rb") as fh:
        return pickle.load(fh)
