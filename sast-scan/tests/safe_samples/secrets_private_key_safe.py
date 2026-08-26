"""Safe: private key loaded from a file/secret store path, never hardcoded."""

import os

PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "/etc/secrets/id_rsa")

with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as key_file:
    PRIVATE_KEY = key_file.read()
