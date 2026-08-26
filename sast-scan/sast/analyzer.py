"""AST-based analysis: YAML-rule-driven checks plus basic intra-procedural taint tracking.

Two independent passes run over every file's AST:

1. Generic rule matching (see ``engine.py``): every ``Rule`` loaded from YAML is
   tested against every ``Call``/``Assert`` node. No rule logic is hardcoded here.
2. Taint analysis: within each function, track which local variables are
   "tainted" by an untrusted source (``input()``, ``sys.argv``, ``os.environ``,
   ``request.args``/``request.form``), propagate that taint through simple
   assignments, string concatenation and f-strings, clear it when a value
   passes through a sanitizer (``shlex.quote``, ``int``), and flag it if a
   tainted value reaches a dangerous sink (``os.system``, ``subprocess.*``,
   ``eval``/``exec``, ``cursor.execute``). Sources/sinks/sanitizers are also
   data-driven, loaded from the same YAML file via ``TaintConfig``.
"""

from __future__ import annotations

import ast
from pathlib import Path

from sast.engine import (
    Rule,
    TaintConfig,
    TaintSink,
    build_alias_map,
    call_attr_name,
    call_dotted_name,
    matches,
)
from sast.models import Category, Finding


def analyze_file(path: Path, rules: list[Rule], taint_cfg: TaintConfig) -> list[Finding]:
    """Run the YAML rule engine and taint analysis over a single Python file."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    alias_map = build_alias_map(tree)
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.Call, ast.Assert)):
            for rule in rules:
                if matches(node, rule, alias_map):
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            cwe=rule.cwe,
                            message=rule.message,
                            file=str(path),
                            line=node.lineno,
                            col=node.col_offset + 1,
                            category=rule.category,
                            remediation=rule.remediation,
                        )
                    )

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_analyze_function_taint(node, taint_cfg, alias_map, path))

    return findings


# ---------------------------------------------------------------------------
# Taint analysis
# ---------------------------------------------------------------------------


def _dotted(node: ast.AST | None, alias_map: dict[str, str]) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Subscript):
        return _dotted(node.value, alias_map)
    if isinstance(node, ast.Name):
        return alias_map.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value, alias_map)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _matches_dotted(dotted: str | None, name: str) -> bool:
    return dotted is not None and (dotted == name or dotted.startswith(name + "."))


def _is_source_call(dotted: str | None, taint_cfg: TaintConfig) -> bool:
    for src in taint_cfg.sources:
        if src.match_type == "call" and dotted == src.name:
            return True
        if src.match_type == "attr" and _matches_dotted(dotted, src.name):
            return True
    return False


def _is_source_expr(dotted: str | None, taint_cfg: TaintConfig) -> bool:
    return any(
        src.match_type == "attr" and _matches_dotted(dotted, src.name)
        for src in taint_cfg.sources
    )


def _find_sink(call: ast.Call, alias_map: dict[str, str], taint_cfg: TaintConfig) -> TaintSink | None:
    dotted = call_dotted_name(call, alias_map)
    attr = call_attr_name(call)
    for sink in taint_cfg.sinks:
        if sink.match_type == "qualified" and dotted == sink.name:
            return sink
        if sink.match_type == "prefix" and dotted is not None and dotted.startswith(sink.name):
            return sink
        if sink.match_type == "attr" and attr == sink.name:
            return sink
    return None


def _is_tainted(
    node: ast.AST | None,
    tainted: set[str],
    alias_map: dict[str, str],
    taint_cfg: TaintConfig,
) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):  # f-strings
        return any(_is_tainted(v, tainted, alias_map, taint_cfg) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _is_tainted(node.value, tainted, alias_map, taint_cfg)
    if isinstance(node, ast.BinOp):  # string concatenation ("a" + b)
        return _is_tainted(node.left, tainted, alias_map, taint_cfg) or _is_tainted(
            node.right, tainted, alias_map, taint_cfg
        )
    if isinstance(node, ast.Call):
        dotted = call_dotted_name(node, alias_map)
        if dotted in taint_cfg.sanitizers:
            return False  # sanitizer neutralizes taint regardless of its arguments
        if _is_source_call(dotted, taint_cfg):
            return True
        return any(_is_tainted(a, tainted, alias_map, taint_cfg) for a in node.args) or any(
            _is_tainted(kw.value, tainted, alias_map, taint_cfg) for kw in node.keywords
        )
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        if _is_source_expr(_dotted(node, alias_map), taint_cfg):
            return True
        if isinstance(node, ast.Subscript) and _is_tainted(node.slice, tainted, alias_map, taint_cfg):
            return True
        return _is_tainted(node.value, tainted, alias_map, taint_cfg)
    # Generic fallback: taint propagates through any other expression (tuples,
    # lists, calls' unhandled node kinds, etc.) that references a tainted name.
    return any(
        _is_tainted(child, tainted, alias_map, taint_cfg) for child in ast.iter_child_nodes(node)
    )


def _scan_expr_for_sinks(
    node: ast.AST | None,
    tainted: set[str],
    alias_map: dict[str, str],
    taint_cfg: TaintConfig,
    path: Path,
) -> list[Finding]:
    if node is None:
        return []
    findings: list[Finding] = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        sink = _find_sink(sub, alias_map, taint_cfg)
        if sink is None:
            continue
        if sink.check_args == "first":
            candidates = sub.args[:1]
            tainted_arg = any(_is_tainted(a, tainted, alias_map, taint_cfg) for a in candidates)
        else:
            tainted_arg = any(
                _is_tainted(a, tainted, alias_map, taint_cfg) for a in sub.args
            ) or any(_is_tainted(kw.value, tainted, alias_map, taint_cfg) for kw in sub.keywords)
        if tainted_arg:
            findings.append(
                Finding(
                    rule_id=f"TAINT-{sink.name.upper().rstrip('.').replace('.', '-')}",
                    severity=sink.severity,
                    cwe=sink.cwe,
                    message=sink.message,
                    file=str(path),
                    line=sub.lineno,
                    col=sub.col_offset + 1,
                    category=Category.TAINT,
                    remediation=sink.remediation,
                )
            )
    return findings


def _assign_taint(
    target: ast.expr,
    value_tainted: bool,
    tainted: set[str],
) -> None:
    if isinstance(target, ast.Name):
        if value_tainted:
            tainted.add(target.id)
        else:
            tainted.discard(target.id)


def _visit_stmts(
    stmts: list[ast.stmt],
    tainted: set[str],
    alias_map: dict[str, str],
    taint_cfg: TaintConfig,
    path: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    for stmt in stmts:
        if isinstance(stmt, ast.Assign):
            findings.extend(_scan_expr_for_sinks(stmt.value, tainted, alias_map, taint_cfg, path))
            value_tainted = _is_tainted(stmt.value, tainted, alias_map, taint_cfg)
            for target in stmt.targets:
                _assign_taint(target, value_tainted, tainted)
        elif isinstance(stmt, ast.AugAssign):
            findings.extend(_scan_expr_for_sinks(stmt.value, tainted, alias_map, taint_cfg, path))
            value_tainted = _is_tainted(stmt.value, tainted, alias_map, taint_cfg)
            if isinstance(stmt.target, ast.Name) and value_tainted:
                tainted.add(stmt.target.id)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                findings.extend(
                    _scan_expr_for_sinks(stmt.value, tainted, alias_map, taint_cfg, path)
                )
                value_tainted = _is_tainted(stmt.value, tainted, alias_map, taint_cfg)
                _assign_taint(stmt.target, value_tainted, tainted)
        elif isinstance(stmt, ast.Expr):
            findings.extend(_scan_expr_for_sinks(stmt.value, tainted, alias_map, taint_cfg, path))
        elif isinstance(stmt, ast.Return):
            findings.extend(_scan_expr_for_sinks(stmt.value, tainted, alias_map, taint_cfg, path))
        elif isinstance(stmt, ast.If):
            findings.extend(_scan_expr_for_sinks(stmt.test, tainted, alias_map, taint_cfg, path))
            findings.extend(_visit_stmts(stmt.body, tainted, alias_map, taint_cfg, path))
            findings.extend(_visit_stmts(stmt.orelse, tainted, alias_map, taint_cfg, path))
        elif isinstance(stmt, ast.While):
            findings.extend(_scan_expr_for_sinks(stmt.test, tainted, alias_map, taint_cfg, path))
            findings.extend(_visit_stmts(stmt.body, tainted, alias_map, taint_cfg, path))
            findings.extend(_visit_stmts(stmt.orelse, tainted, alias_map, taint_cfg, path))
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            findings.extend(_visit_stmts(stmt.body, tainted, alias_map, taint_cfg, path))
            findings.extend(_visit_stmts(stmt.orelse, tainted, alias_map, taint_cfg, path))
        elif isinstance(stmt, ast.Try):
            findings.extend(_visit_stmts(stmt.body, tainted, alias_map, taint_cfg, path))
            for handler in stmt.handlers:
                findings.extend(_visit_stmts(handler.body, tainted, alias_map, taint_cfg, path))
            findings.extend(_visit_stmts(stmt.orelse, tainted, alias_map, taint_cfg, path))
            findings.extend(_visit_stmts(stmt.finalbody, tainted, alias_map, taint_cfg, path))
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            findings.extend(_visit_stmts(stmt.body, tainted, alias_map, taint_cfg, path))
        # Nested function/class definitions are analyzed independently (the
        # top-level ast.walk in analyze_file visits them as their own scope).
    return findings


def _analyze_function_taint(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    taint_cfg: TaintConfig,
    alias_map: dict[str, str],
    path: Path,
) -> list[Finding]:
    tainted: set[str] = set()
    return _visit_stmts(func.body, tainted, alias_map, taint_cfg, path)
