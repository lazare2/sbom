"""Safe: no eval()/exec() -- use ast.literal_eval for safe expression evaluation."""

import ast


def run_expression(expr: str) -> object:
    return ast.literal_eval(expr)
