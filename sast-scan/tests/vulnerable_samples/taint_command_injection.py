"""Vulnerable: user input flows unsanitized into a shell command (CWE-78)."""

import os


def ping_host() -> None:
    host = input("Enter host to ping: ")
    command = "ping -c 1 " + host
    os.system(command)
