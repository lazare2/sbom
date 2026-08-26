"""Safe: the secrets module used for a security-sensitive token."""

import secrets
import string


def generate_token(length: int = 16) -> str:
    return "".join(secrets.choice(string.ascii_letters) for _ in range(length))
