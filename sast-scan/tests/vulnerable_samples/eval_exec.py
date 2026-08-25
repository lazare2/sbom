"""Vulnerable: eval()/exec() on arbitrary input."""


def run_expression(expr: str) -> object:
    return eval(expr)


def run_code(code: str) -> None:
    exec(code)
