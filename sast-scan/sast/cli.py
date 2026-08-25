"""Command-line entry point: ``python -m sast <path>``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sast.analyzer import analyze_file
from sast.engine import DEFAULT_RULES_PATH, load_rules, load_taint_config
from sast.models import Finding, Severity, severity_rank
from sast.report import format_console, format_json, format_sarif, has_blocking_findings
from sast.scanner import DEFAULT_EXCLUDES, walk_python_files
from sast.secrets import scan_file as scan_secrets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sast", description="Static Application Security Testing tool for Python."
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--format",
        choices=["console", "sarif", "json"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=[s.value for s in Severity],
        default=Severity.LOW.value,
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="DIR",
        help="Additional directory name to exclude from the scan (repeatable)",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES_PATH,
        help="Path to a custom YAML rules file (default: bundled rules/python.yaml)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored console output"
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    root = Path(args.path)
    excludes = DEFAULT_EXCLUDES | frozenset(args.exclude)

    rules = load_rules(args.rules)
    taint_cfg = load_taint_config(args.rules)

    findings: list[Finding] = []
    for file_path in walk_python_files(root, excludes):
        findings.extend(scan_secrets(file_path))
        findings.extend(analyze_file(file_path, rules, taint_cfg))

    threshold = Severity(args.severity_threshold)
    filtered = [f for f in findings if severity_rank(f.severity) >= severity_rank(threshold)]
    filtered.sort(key=lambda f: (f.file, f.line, f.col))

    if args.format == "console":
        print(format_console(filtered, use_color=not args.no_color))
    elif args.format == "json":
        print(format_json(filtered))
    elif args.format == "sarif":
        print(format_sarif(filtered))

    return 1 if has_blocking_findings(filtered) else 0


def main(argv: list[str] | None = None) -> None:
    sys.exit(run(argv))


if __name__ == "__main__":
    main()
