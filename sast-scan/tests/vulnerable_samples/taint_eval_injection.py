"""Vulnerable: user input flows unsanitized into eval() (CWE-95)."""


def calculate() -> object:
    expr = input("Enter an expression: ")
    return eval(expr)
