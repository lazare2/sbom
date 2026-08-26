"""Vulnerable: hardcoded password."""

password = "SuperSecret123!"


def connect() -> None:
    passwd = "AnotherSecret456"
    print(passwd)
