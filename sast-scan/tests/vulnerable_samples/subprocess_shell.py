"""Vulnerable: subprocess invoked with shell=True."""

import subprocess


def list_dir(path: str) -> str:
    return subprocess.check_output(f"ls {path}", shell=True).decode()


def run(cmd: str) -> None:
    subprocess.run(cmd, shell=True)
