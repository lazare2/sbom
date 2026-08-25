"""Vulnerable: the random module used to generate a security-sensitive token."""

import random
import string


def generate_token(length: int = 16) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(length))
