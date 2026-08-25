"""Safe: subprocess invoked as an argument list, without shell=True."""

import subprocess


def list_dir(path: str) -> str:
    return subprocess.check_output(["ls", path]).decode()


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, shell=False)
