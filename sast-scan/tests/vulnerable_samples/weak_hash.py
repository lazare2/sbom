"""Vulnerable: weak/broken hash algorithms used for security purposes."""

import hashlib


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()
