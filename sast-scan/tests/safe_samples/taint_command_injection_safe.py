"""Safe: user input is sanitized before it reaches a command sink."""

import os
import shlex


def ping_host() -> None:
    host = input("Enter host to ping: ")
    safe_host = shlex.quote(host)
    command = "ping -c 1 " + safe_host
    os.system(command)


def ping_count() -> None:
    raw_count = input("Enter ping count: ")
    count = int(raw_count)  # int() sanitizer: non-numeric input raises instead
    os.system(f"ping -c {count} localhost")
