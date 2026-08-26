"""Generic, YAML-driven rule engine for AST-based static analysis.

Rules (and the taint source/sink/sanitizer configuration) live entirely in data
(see ``rules/python.yaml``). This module knows how to load that data and how to
match a small, generic vocabulary of AST patterns against it. Adding a new rule
never requires touching this file or ``analyzer.py`` -- only the YAML.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from sast.models import Severity

DEFAULT_RULES_PATH: Path = Path(__file__).parent / "rules" / "python.yaml"


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    severity: Severity
    cwe: int
    message: str
    pattern: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TaintSource:
    name: str
    match_type: str  # "call" (e.g. input()) | "attr" (e.g. sys.argv, os.environ)


@dataclass(frozen=True, slots=True)
class TaintSink:
    name: str
    match_type: str  # "qualified" | "prefix" | "attr"
    cwe: int
    message: str
    severity: Severity = Severity.HIGH
    check_args: str = "all"  # "all" | "first" (e.g. cursor.execute(query, params))


@dataclass(frozen=True, slots=True)
class TaintConfig:
    sources: tuple[TaintSource, ...]
    sinks: tuple[TaintSink, ...]
    sanitizers: tuple[str, ...]


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Rules file {path} must contain a mapping at the top level")
    return data


def load_rules(path: Path = DEFAULT_RULES_PATH) -> list[Rule]:
    data = _load_yaml(path)
    return [
        Rule(
            id=raw["id"],
            severity=Severity(raw["severity"]),
            cwe=int(raw["cwe"]),
            message=raw["message"],
            pattern=raw.get("pattern", {}) or {},
        )
        for raw in data.get("rules", []) or []
    ]


def load_taint_config(path: Path = DEFAULT_RULES_PATH) -> TaintConfig:
    data = _load_yaml(path)
    taint = data.get("taint", {}) or {}

    sources = tuple(
        TaintSource(name=s["name"], match_type=s.get("match_type", "attr"))
        for s in taint.get("sources", []) or []
    )
    sinks = tuple(
        TaintSink(
            name=s["name"],
            match_type=s.get("match_type", "qualified"),
            cwe=int(s["cwe"]),
            message=s["message"],
            severity=Severity(s.get("severity", "HIGH")),
            check_args=s.get("check_args", "all"),
        )
        for s in taint.get("sinks", []) or []
    )
    sanitizers = tuple(taint.get("sanitizers", []) or [])
    return TaintConfig(sources=sources, sinks=sinks, sanitizers=sanitizers)


# ---------------------------------------------------------------------------
# Alias resolution -- maps local names to fully-qualified dotted paths so
# patterns can match regardless of how something was imported.
# ---------------------------------------------------------------------------


def build_alias_map(tree: ast.AST) -> dict[str, str]:
    """Map local names to fully-qualified dotted names based on import statements."""
    alias_map: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                alias_map[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                alias_map[local] = f"{node.module}.{alias.name}"
    return alias_map


def dotted_path(node: ast.AST | None, alias_map: dict[str, str]) -> str | None:
    """Best-effort fully-qualified dotted path for a Name/Attribute/Subscript chain."""
    if node is None:
        return None
    if isinstance(node, ast.Subscript):
        return dotted_path(node.value, alias_map)
    if isinstance(node, ast.Name):
        return alias_map.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = dotted_path(node.value, alias_map)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def call_dotted_name(call: ast.Call, alias_map: dict[str, str]) -> str | None:
    return dotted_path(call.func, alias_map)


def call_attr_name(call: ast.Call) -> str | None:
    """The final attribute/name of a call's callee, ignoring its base object."""
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return None


# ---------------------------------------------------------------------------
# Generic pattern matching
# ---------------------------------------------------------------------------


def _get_keyword(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _check_keywords(call: ast.Call, conditions: list[dict[str, Any]]) -> bool:
    """All listed keyword conditions must be present and equal to their literal."""
    for cond in conditions:
        value_node = _get_keyword(call, cond["name"])
        if not isinstance(value_node, ast.Constant) or value_node.value != cond["equals"]:
            return False
    return True


def _check_keyword_unsafe(call: ast.Call, cond: dict[str, Any]) -> bool:
    """True if the given keyword (or positional slot) is missing or not a safe value."""
    name = cond["name"]
    safe_values = set(cond.get("safe_values", []))
    positional_index = cond.get("positional_index")

    value_node = _get_keyword(call, name)
    if value_node is None and positional_index is not None and len(call.args) > positional_index:
        value_node = call.args[positional_index]
    if value_node is None:
        return True  # missing entirely -> treat as unsafe

    if isinstance(value_node, ast.Attribute):
        resolved: str | None = value_node.attr
    elif isinstance(value_node, ast.Name):
        resolved = value_node.id
    else:
        resolved = None
    return resolved not in safe_values


def _check_non_literal(call: ast.Call, indices: list[int]) -> bool:
    """True (flag it) unless every listed positional argument is a literal constant."""
    for idx in indices:
        if idx < len(call.args) and isinstance(call.args[idx], ast.Constant):
            return False
    return True


def _matches_assert(node: ast.Assert, pattern: dict[str, Any]) -> bool:
    contains_any = pattern.get("contains_any")
    if not contains_any:
        return True
    try:
        src = ast.unparse(node.test).lower()
    except Exception:
        return False
    return any(keyword.lower() in src for keyword in contains_any)


def matches(node: ast.AST, rule: Rule, alias_map: dict[str, str]) -> bool:
    """Apply a single rule's pattern to a single AST node."""
    pattern = rule.pattern
    node_type = pattern.get("node", "call")

    if node_type == "assert":
        return isinstance(node, ast.Assert) and _matches_assert(node, pattern)

    if node_type != "call" or not isinstance(node, ast.Call):
        return False

    dotted = call_dotted_name(node, alias_map)
    attr = call_attr_name(node)

    if "call_names" in pattern:
        if dotted not in pattern["call_names"] and attr not in pattern["call_names"]:
            return False
    elif "qualified_names" in pattern:
        if dotted not in pattern["qualified_names"]:
            return False
    elif "module_wildcard" in pattern:
        base = pattern["module_wildcard"]
        if dotted is None or not (dotted == base or dotted.startswith(base + ".")):
            return False

    if "keywords" in pattern and not _check_keywords(node, pattern["keywords"]):
        return False

    if "keyword_unsafe" in pattern and not _check_keyword_unsafe(node, pattern["keyword_unsafe"]):
        return False

    if "non_literal_positional" in pattern and not _check_non_literal(
        node, pattern["non_literal_positional"]
    ):
        return False

    return True
