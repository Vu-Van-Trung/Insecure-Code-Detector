"""Analyzer core: turns files, directories or raw source into a ScanResult.

This module has no dependency on the CLI or the web layer, so it can be reused
from either of them (or from a CI/CD job).

Supported languages: Python (``ast``), Java and C# (tree-sitter). The language
of a file is chosen from its extension (.py, .java, .cs).

Pipeline for each file::

    parse -> rules (syntax tree + taint) -> drop generic duplicates
          -> severity overrides -> inline/whitelist suppression -> thresholds
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from app import __version__
from app.analyzer.context import AnalysisContext
from app.analyzer.languages import DISPLAY_NAMES, EXTENSIONS, PYTHON, language_of, supported_extensions_text
from app.analyzer.parser import ParsedSource, SourceError, decode_text, parse_bytes, parse_source, read_source_file
from app.analyzer.suppression import Ignores, ignores_from_comments, is_suppressed, parse_inline_ignores
from app.analyzer.visitor import SecurityVisitor
from app.config.settings import AnalyzerSettings
from app.models.finding import FileSummary, Finding, ScanError, ScanResult
from app.rules.base import SecurityRule
from app.rules.registry import RuleRegistry, load_builtin_rules

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = frozenset(EXTENSIONS)


class AnalyzerEngine:
    """Runs the registered security rules over Python, Java and C# source code."""

    def __init__(self, registry: RuleRegistry | None = None, settings: AnalyzerSettings | None = None) -> None:
        """Raises ConfigError if the default configuration files are invalid."""
        self.settings = settings if settings is not None else AnalyzerSettings.load()
        self.registry = registry if registry is not None else load_builtin_rules()
        self.rules: list[SecurityRule] = self.registry.create_rules(self.settings.all_disabled_rules())
        for rule in self.rules:
            rule.configure(self.settings)
        self.rules_by_language: dict[str, list[SecurityRule]] = {}
        for rule in self.rules:
            self.rules_by_language.setdefault(rule.language, []).append(rule)
        self._generic_rules = {rule.id for rule in self.rules if rule.generic}

    # ------------------------------------------------------------------ public API

    def scan_path(self, target: str | Path) -> ScanResult:
        """Scan a single source file or every supported file under a directory.

        Raises FileNotFoundError if the target does not exist; per-file problems
        (syntax errors, bad encoding, ...) are recorded in ``result.errors``.
        """
        target_path = Path(target)
        if not target_path.exists():
            raise FileNotFoundError(f"Scan target not found: {target}")

        result, started = self._start(str(target))
        if target_path.is_file():
            if language_of(target_path.name) is None:
                reason = (f"Unsupported file type '{target_path.suffix}', "
                          f"supported: {supported_extensions_text()}")
                self._record_error(result, target_path.as_posix(), SourceError("UnsupportedFile", reason))
                return self._finish(result, started)
            files = [target_path]
        else:
            files = self.discover_files(target_path)
        for file_path in files:
            display_name = file_path.as_posix()
            if self.settings.whitelist.is_file_ignored(display_name):
                result.skipped_files.append(display_name)
                logger.info("File skipped by whitelist: %s", display_name)
                continue
            try:
                data = read_source_file(file_path, self.settings.max_file_size)
            except SourceError as exc:
                self._record_error(result, display_name, exc)
                continue
            self._analyze_into(display_name, data, result)
        return self._finish(result, started)

    def scan_source(self, source: str, filename: str = "<input>") -> ScanResult:
        """Scan source text without touching disk; the language comes from ``filename`` (default Python)."""
        result, started = self._start(filename)
        if (language_of(filename) or PYTHON) == PYTHON:
            try:
                parsed = parse_source(source, filename)
            except SourceError as exc:
                self._record_error(result, filename, exc)
            else:
                self._collect(parsed.filename, PYTHON, self.analyze(parsed),
                              parse_inline_ignores(parsed.source), parsed.line_count, result)
        else:
            self._analyze_into(filename, source.encode("utf-8"), result)
        return self._finish(result, started)

    def scan_sources(self, sources: Iterable[tuple[str, bytes]], target: str = "upload") -> ScanResult:
        """Scan several in-memory files (web uploads). Nothing is written to disk."""
        result, started = self._start(target)
        for filename, data in sources:
            if len(data) > self.settings.max_file_size:
                reason = f"File is {len(data)} bytes, limit is {self.settings.max_file_size} bytes"
                self._record_error(result, filename, SourceError("FileTooLarge", reason))
                continue
            self._analyze_into(filename, data, result)
        return self._finish(result, started)

    def analyze(self, parsed: ParsedSource) -> list[Finding]:
        """Run all enabled Python rules on a parsed source (before suppression/thresholds)."""
        context = AnalysisContext.from_parsed(parsed, self.settings.taint)
        visitor = SecurityVisitor(self.rules_by_language.get(PYTHON, []), context)
        visitor.visit(parsed.tree)
        findings = self._drop_generic_duplicates(visitor.findings)
        self._apply_overrides(findings)
        return findings

    def analyze_tree_sitter(self, filename: str, source: str, language: str) -> tuple[list[Finding], Ignores, int]:
        """Parse and analyze a Java/C# source. Raises SourceError on syntax errors."""
        from app.analyzer.ts.adapters import LanguageUnavailable, get_adapter
        from app.analyzer.ts.context import TSContext
        from app.analyzer.ts.taint import TSTaintConfig, analyze_ts_taint

        try:
            adapter = get_adapter(language)
        except LanguageUnavailable as exc:
            raise SourceError("LanguageUnavailable", str(exc)) from exc
        tree = adapter.parse(source.encode("utf-8"))
        root = tree.root_node
        if root.has_error:
            line = _first_error_line(root)
            raise SourceError("SyntaxError", f"{DISPLAY_NAMES[language]} syntax error", line)

        ctx = TSContext.build(filename, source, root, adapter)
        taint_config = self.settings.language_taint.get(language) or TSTaintConfig()
        ctx.taint = analyze_ts_taint(ctx, taint_config)
        findings: list[Finding] = []
        for rule in self.rules_by_language.get(language, []):
            try:
                findings.extend(rule.check_file(ctx))  # type: ignore[attr-defined]
            except Exception:
                # A bug in one rule must not abort the scan of the whole file.
                logger.exception("Rule %s crashed on %s", rule.id, filename)
        for finding in findings:
            logger.info("Rule triggered: %s at %s:%d", finding.rule_id, finding.file, finding.line)
        self._apply_overrides(findings)
        return findings, ignores_from_comments(adapter.comments(root)), len(ctx.source_lines)

    def discover_files(self, root: Path) -> list[Path]:
        """List supported source files under ``root``, skipping vendored/generated dirs.

        SECURITY: symlinks are not followed, so a scan can never escape the
        requested directory.
        """
        excluded = self.settings.excluded_dirs
        found: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in excluded)
            for filename in sorted(filenames):
                path = Path(dirpath) / filename
                if path.suffix.lower() in SUPPORTED_EXTENSIONS and not path.is_symlink():
                    found.append(path)
        return found

    # ------------------------------------------------------------------ internals

    def _analyze_into(self, filename: str, data: bytes, result: ScanResult) -> None:
        language = language_of(filename) or PYTHON
        try:
            if language == PYTHON:
                parsed = parse_bytes(data, filename)
                findings, ignores, lines = self.analyze(parsed), parse_inline_ignores(parsed.source), parsed.line_count
            else:
                findings, ignores, lines = self.analyze_tree_sitter(filename, decode_text(data), language)
        except SourceError as exc:
            self._record_error(result, filename, exc)
            return
        self._collect(filename, language, findings, ignores, lines, result)

    def _collect(self, filename: str, language: str, findings: list[Finding], ignores: Ignores,
                 line_count: int, result: ScanResult) -> None:
        kept = 0
        for finding in findings:
            finding.language = language
            if self.settings.honor_inline_ignores and is_suppressed(finding.rule_id, finding.line, ignores):
                # Suppression hides the warning; it does not make the code safe.
                result.suppressed.append(finding)
                logger.info("Finding suppressed (inline): %s at %s:%d", finding.rule_id, finding.file, finding.line)
            elif (finding.confidence < self.settings.min_confidence
                  or finding.severity.rank < self.settings.min_severity.rank):
                result.filtered_count += 1
            else:
                result.findings.append(finding)
                kept += 1
        result.files_scanned += 1
        result.lines_scanned += line_count
        result.files.append(FileSummary(filename, line_count, kept, language))
        logger.info("File scanned: %s [%s] (%d findings)", filename, language, kept)

    def _apply_overrides(self, findings: list[Finding]) -> None:
        for finding in findings:
            override = self.settings.severity_overrides.get(finding.rule_id)
            if override is not None:
                finding.severity = override

    def _drop_generic_duplicates(self, findings: list[Finding]) -> list[Finding]:
        """Generic blacklist findings are dropped where a specific rule already reported."""
        specific = {(f.line, f.column) for f in findings if f.rule_id not in self._generic_rules}
        return [
            f for f in findings
            if f.rule_id not in self._generic_rules or (f.line, f.column) not in specific
        ]

    @staticmethod
    def _start(target: str) -> tuple[ScanResult, float]:
        logger.info("Scan started: %s", target)
        result = ScanResult(
            target=target,
            tool_version=__version__,
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        return result, time.perf_counter()

    @staticmethod
    def _record_error(result: ScanResult, filename: str, exc: SourceError) -> None:
        result.errors.append(ScanError(filename, exc.error_type, exc.reason, exc.line))
        logger.warning("Error scanning %s: %s (%s)", filename, exc.error_type, exc.reason)

    @staticmethod
    def _finish(result: ScanResult, started: float) -> ScanResult:
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        result.sort_findings()
        logger.info(
            "Scan completed: %s files=%d lines=%d findings=%d suppressed=%d errors=%d",
            result.target, result.files_scanned, result.lines_scanned,
            len(result.findings), len(result.suppressed), len(result.errors),
        )
        return result


def _first_error_line(root) -> int | None:  # type: ignore[no-untyped-def]
    """1-based line of the first ERROR / MISSING node of a tree-sitter tree."""
    best = None
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            row = node.start_point[0]
            best = row if best is None else min(best, row)
            continue
        if node.has_error:
            stack.extend(node.children)
    return best + 1 if best is not None else None
