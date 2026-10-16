"""Giao diện dòng lệnh (CLI).

    python main.py scan <file_hoặc_thư_mục> [--format text|json|csv|html] [-o FILE]
    python main.py rules
    python main.py web [--host 127.0.0.1] [--port 8000]
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from app import __version__
from app.analyzer.engine import AnalyzerEngine
from app.analyzer.languages import DISPLAY_NAMES
from app.config.loader import ConfigError
from app.config.settings import DEFAULT_BLACKLIST, AnalyzerSettings
from app.logging_config import setup_logging
from app.models.finding import ScanResult, Severity
from app.reports import REPORT_FORMATS, render_report
from app.rules.registry import RuleRegistry, load_builtin_rules

# Exit code (hữu ích trong pipeline CI/CD: code 1 làm job thất bại khi có lỗ hổng).
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE_ERROR = 2

# "text" (in ra màn hình) + mọi định dạng report (json, csv, html).
OUTPUT_FORMATS = ("text", *REPORT_FORMATS)
SEVERITY_NAMES = [severity.value for severity in Severity]


def build_parser() -> argparse.ArgumentParser:
    """Khai báo các lệnh con (scan, rules, web) và tùy chọn của chúng."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Secure Code Analyzer - static security analysis for Python, Java, C# and PHP source code.",
    )
    parser.add_argument("--version", action="version", version=f"Secure Code Analyzer v{__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a Python file or directory")
    scan.add_argument("target", help="source file (.py, .java, .cs, .php) or directory to scan")
    scan.add_argument("--format", choices=OUTPUT_FORMATS, default="text", help="output format (default: text)")
    scan.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    scan.add_argument("--whitelist", help="whitelist JSON file (default: ./whitelist.json if it exists)")
    scan.add_argument("--no-whitelist", action="store_true", help="ignore whitelist.json")
    scan.add_argument("--blacklist", help=f"blacklist JSON file (default: {DEFAULT_BLACKLIST.name} of the tool)")
    scan.add_argument("--disable", default="", help="comma-separated rule ids to disable, e.g. PY009,PY013")
    # type=str.upper: cho phép gõ "--min-severity high" (chữ thường).
    scan.add_argument("--min-severity", type=str.upper, choices=SEVERITY_NAMES, help="hide findings below this severity")
    scan.add_argument("--min-confidence", type=float, help="hide findings below this confidence (0.0-1.0)")
    scan.add_argument("--fail-on", type=str.upper, choices=SEVERITY_NAMES, default="INFO",
                      help="exit with code 1 only if a finding has at least this severity (default: INFO)")

    subparsers.add_parser("rules", help="list available security rules")

    web = subparsers.add_parser("web", help="start the web interface")
    # Mặc định chỉ nghe trên 127.0.0.1: Web UI không có đăng nhập nên không nên mở ra mạng.
    web.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1, local only)")
    web.add_argument("--port", type=int, default=8000, help="port (default: 8000)")
    return parser


# ---------------------------------------------------------------- xuất dạng văn bản


def format_text_report(result: ScanResult) -> str:
    """Report dạng văn bản để in ra terminal: tổng quan, danh sách finding, lỗi."""
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
    # Mỗi mức severity một dòng, căn trái 10 ký tự: "CRITICAL: 2".
    lines += [f"{severity.value + ':':<10}{counts[severity.value]}" for severity in Severity]
    lines += ["", f"Total findings: {len(result.findings)}"]
    if result.suppressed:
        lines.append(f"Suppressed:     {len(result.suppressed)} (whitelist / analyzer-ignore; not verified safe)")
    if result.filtered_count:
        lines.append(f"Filtered:       {result.filtered_count} (below --min-severity / --min-confidence)")
    if result.skipped_files:
        lines.append(f"Skipped files:  {len(result.skipped_files)} (whitelist)")

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
    """Bảng danh sách rule cho lệnh ``python main.py rules``."""
    if len(registry) == 0:
        return "No rules registered.\n"
    lines = [f"{'ID':<7}{'LANG':<8}{'SEVERITY':<10}{'CWE':<9}NAME"]
    for rule_cls in registry:
        language = DISPLAY_NAMES.get(rule_cls.language, rule_cls.language)
        lines.append(f"{rule_cls.id:<7}{language:<8}{rule_cls.severity.value:<10}{rule_cls.cwe:<9}{rule_cls.name}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- các lệnh


def build_settings(args: argparse.Namespace) -> AnalyzerSettings:
    """Kết hợp các file cấu hình với tùy chọn dòng lệnh (tùy chọn dòng lệnh được ưu tiên)."""
    # Whitelist: file chỉ định bằng --whitelist, nếu không thì ./whitelist.json (nếu có),
    # trừ khi người dùng tắt bằng --no-whitelist.
    whitelist_path: Path | None = None
    if args.whitelist:
        whitelist_path = Path(args.whitelist)
    elif not args.no_whitelist and Path("whitelist.json").is_file():
        whitelist_path = Path("whitelist.json")
    blacklist_path = Path(args.blacklist) if args.blacklist else DEFAULT_BLACKLIST

    settings = AnalyzerSettings.load(whitelist_path=whitelist_path, blacklist_path=blacklist_path)
    # Gom các thay đổi rồi tạo bản sao mới (AnalyzerSettings là bất biến).
    changes: dict[str, object] = {}
    disabled = {rule.strip().upper() for rule in args.disable.split(",") if rule.strip()}
    if disabled:
        changes["disabled_rules"] = settings.disabled_rules | disabled
    if args.min_severity:
        changes["min_severity"] = Severity.parse(args.min_severity)
    if args.min_confidence is not None:
        if not 0.0 <= args.min_confidence <= 1.0:
            raise ConfigError("--min-confidence must be between 0.0 and 1.0")
        changes["min_confidence"] = args.min_confidence
    return settings.with_changes(**changes) if changes else settings


def _write_output(content: str, output: str | None, stdout: TextIO) -> None:
    """Ghi report ra file (nếu có -o) hoặc in ra màn hình."""
    if output:
        Path(output).write_text(content, encoding="utf-8")
        stdout.write(f"Report written to {output}\n")
    else:
        stdout.write(content)


def run_scan(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    """Lệnh ``scan``: chạy analyzer, xuất report và trả exit code theo --fail-on."""
    try:
        engine = AnalyzerEngine(settings=build_settings(args))
    except ConfigError as exc:
        stderr.write(f"Error: invalid configuration: {exc}\n")
        return EXIT_USAGE_ERROR
    try:
        result = engine.scan_path(args.target)
    except FileNotFoundError as exc:
        stderr.write(f"Error: {exc}\n")
        return EXIT_USAGE_ERROR

    content = format_text_report(result) if args.format == "text" else render_report(result, args.format)
    try:
        _write_output(content, args.output, stdout)
    except OSError as exc:
        stderr.write(f"Error: cannot write report: {exc}\n")
        return EXIT_USAGE_ERROR

    # Exit code 1 chỉ khi có finding nặng ít nhất bằng --fail-on (vd --fail-on HIGH bỏ qua MEDIUM/LOW).
    if result.errors:
        return EXIT_USAGE_ERROR
    threshold = Severity.parse(args.fail_on)
    highest = result.highest_severity()
    return EXIT_FINDINGS if highest is not None and highest.rank >= threshold.rank else EXIT_OK


def run_web(args: argparse.Namespace, stderr: TextIO) -> int:
    """Lệnh ``web``: khởi động web server (FastAPI qua uvicorn)."""
    try:
        import uvicorn  # import lazy: phần scan của CLI chạy được mà không cần thư viện web
    except ImportError:
        stderr.write("Error: web dependencies missing. Run: pip install -r requirements.txt\n")
        return EXIT_USAGE_ERROR
    uvicorn.run("app.main:app", host=args.host, port=args.port)
    return EXIT_OK


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    """Điểm vào của CLI; trả về exit code.

    ``argv``/``stdout``/``stderr`` truyền vào được để test kiểm tra output mà không cần chạy tiến trình con.
    """
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    setup_logging()

    if args.command == "scan":
        return run_scan(args, stdout, stderr)
    if args.command == "rules":
        stdout.write(format_rules(load_builtin_rules()))
        return EXIT_OK
    if args.command == "web":
        return run_web(args, stderr)
    return EXIT_USAGE_ERROR
