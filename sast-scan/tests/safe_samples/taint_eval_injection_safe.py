"""Safe: user input is parsed with ast.literal_eval instead of eval()."""

import ast


def calculate() -> object:
    expr = input("Enter an expression: ")
    return ast.literal_eval(expr)
