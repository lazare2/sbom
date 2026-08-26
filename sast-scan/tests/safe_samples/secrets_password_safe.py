"""Safe: password loaded from the environment, never hardcoded."""

import os

password = os.environ.get("DB_PASSWORD")


def connect() -> None:
    passwd = os.environ.get("OTHER_PASSWORD")
    print(passwd)
