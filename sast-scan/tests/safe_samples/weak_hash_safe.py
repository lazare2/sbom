"""Safe: strong hash algorithm (SHA-256)."""

import hashlib


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
