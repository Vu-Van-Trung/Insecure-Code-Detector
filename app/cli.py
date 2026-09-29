"""Command line interface: ``python main.py scan <target>`` / ``python main.py rules``."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from app import __version__
from app.analyzer.engine import AnalyzerEngine
from app.config.loader import ConfigError
from app.logging_config import setup_logging
from app.models.finding import ScanResult, Severity
from app.rules.registry import RuleRegistry, load_builtin_rules

# Exit codes (useful in CI/CD pipelines).
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE_ERROR = 2

OUTPUT_FORMATS = ("text", "json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Secure Code Analyzer - static security analysis for Python source code.",
    )
    parser.add_argument("--version", action="version", version=f"Secure Code Analyzer v{__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a Python file or directory")
    scan.add_argument("target", help="Python file or directory to scan")
    scan.add_argument("--format", choices=OUTPUT_FORMATS, default="text", help="output format")
    scan.add_argument("--output", "-o", help="write the report to this file instead of stdout")

    subparsers.add_parser("rules", help="list available security rules")
    return parser


def format_text_report(result: ScanResult) -> str:
    counts = result.severity_counts()
    lines = [
        f"Secure Code Analyzer v{__version__}",
        "",
        f"Scanning: {result.target}",
        "",
        f"Files scanned: {result.files_scanned}",
        f"Lines scanned: {result.lines_scanned}",
        "",
    ]
    lines += [f"{severity.value + ':':<10}{counts[severity.value]}" for severity in Severity]
    lines += ["", f"Total findings: {len(result.findings)}"]

    if result.findings:
        lines += ["", "Findings:"]
        for finding in result.findings:
            lines.append(
                f"  [{finding.severity.value}] {finding.rule_id} {finding.file}:{finding.line}:{finding.column}"
                f" - {finding.message} ({finding.cwe}, confidence {finding.confidence:.0%})"
            )
            if finding.code:
                lines.append(f"      {finding.code}")
            if finding.source:
                lines.append(f"      Source: {finding.source}  Sink: {finding.sink}")
            if finding.taint_path:
                lines.append(f"      Taint path: {' -> '.join(finding.taint_path)}")

    if result.errors:
        lines += ["", f"Errors ({len(result.errors)}):"]
        for error in result.errors:
            where = f"{error.file}:{error.line}" if error.line else error.file
            lines.append(f"  {where} - {error.error_type}: {error.reason}")
    return "\n".join(lines) + "\n"


def format_rules(registry: RuleRegistry) -> str:
    if len(registry) == 0:
        return "No rules registered.\n"
    lines = [f"{'ID':<7}{'SEVERITY':<10}{'CWE':<9}NAME"]
    for rule_cls in registry:
        lines.append(f"{rule_cls.id:<7}{rule_cls.severity.value:<10}{rule_cls.cwe:<9}{rule_cls.name}")
    return "\n".join(lines) + "\n"


def _write_output(content: str, output: str | None, stdout: TextIO) -> None:
    if output:
        Path(output).write_text(content, encoding="utf-8")
        stdout.write(f"Report written to {output}\n")
    else:
        stdout.write(content)


def run_scan(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    try:
        engine = AnalyzerEngine()
    except ConfigError as exc:
        stderr.write(f"Error: invalid configuration: {exc}\n")
        return EXIT_USAGE_ERROR
    try:
        result = engine.scan_path(args.target)
    except FileNotFoundError as exc:
        stderr.write(f"Error: {exc}\n")
        return EXIT_USAGE_ERROR

    if args.format == "json":
        content = json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"
    else:
        content = format_text_report(result)
    try:
        _write_output(content, args.output, stdout)
    except OSError as exc:
        stderr.write(f"Error: cannot write report: {exc}\n")
        return EXIT_USAGE_ERROR
    return EXIT_FINDINGS if result.findings else EXIT_OK


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    setup_logging()

    if args.command == "scan":
        return run_scan(args, stdout, stderr)
    if args.command == "rules":
        stdout.write(format_rules(load_builtin_rules()))
        return EXIT_OK
    return EXIT_USAGE_ERROR
