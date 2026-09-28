"""Analyzer core: turns files, directories or raw source into a ScanResult.

This module has no dependency on the CLI or the web layer, so it can be reused
from either of them (or from a CI/CD job).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from app.analyzer.context import AnalysisContext
from app.analyzer.parser import DEFAULT_MAX_FILE_SIZE, ParsedSource, SourceError, parse_file, parse_source
from app.analyzer.visitor import SecurityVisitor
from app.models.finding import Finding, ScanError, ScanResult
from app.rules.base import SecurityRule
from app.rules.registry import RuleRegistry, load_builtin_rules

logger = logging.getLogger(__name__)

PYTHON_EXTENSIONS = {".py"}

# Directories that contain third-party or generated code, not project sources.
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env",
    "node_modules", "site-packages", "build", "dist", ".tox", ".mypy_cache", ".pytest_cache",
}


class AnalyzerEngine:
    """Runs the registered security rules over Python source code."""

    def __init__(
        self,
        registry: RuleRegistry | None = None,
        disabled_rules: set[str] | None = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ) -> None:
        self.registry = registry if registry is not None else load_builtin_rules()
        self.rules: list[SecurityRule] = self.registry.create_rules(disabled_rules or set())
        self.max_file_size = max_file_size

    # ------------------------------------------------------------------ public API

    def scan_path(self, target: str | Path) -> ScanResult:
        """Scan a single .py file or every .py file under a directory.

        Raises FileNotFoundError if the target does not exist; per-file problems
        (syntax errors, bad encoding, ...) are recorded in ``result.errors``.
        """
        target_path = Path(target)
        if not target_path.exists():
            raise FileNotFoundError(f"Scan target not found: {target}")

        result = ScanResult(target=str(target))
        logger.info("Scan started: %s", target)
        if target_path.is_file():
            if target_path.suffix.lower() not in PYTHON_EXTENSIONS:
                reason = f"Unsupported file type '{target_path.suffix}', only .py is supported"
                self._record_error(result, target_path.as_posix(), SourceError("UnsupportedFile", reason))
                return self._finish(result)
            files = [target_path]
        else:
            files = list(self.discover_files(target_path))
        for file_path in files:
            self._scan_file_into(file_path, result)
        return self._finish(result)

    def scan_source(self, source: str, filename: str = "<input>") -> ScanResult:
        """Scan source text (e.g. pasted in the web UI) without touching disk."""
        result = ScanResult(target=filename)
        logger.info("Scan started: %s", filename)
        try:
            parsed = parse_source(source, filename)
        except SourceError as exc:
            self._record_error(result, filename, exc)
        else:
            self._analyze_into(parsed, result)
        return self._finish(result)

    def analyze(self, parsed: ParsedSource) -> list[Finding]:
        """Run all enabled rules on an already parsed source."""
        context = AnalysisContext.from_parsed(parsed)
        visitor = SecurityVisitor(self.rules, context)
        visitor.visit(parsed.tree)
        return visitor.findings

    @staticmethod
    def discover_files(root: Path) -> list[Path]:
        """List Python files under ``root``, skipping vendored/generated dirs.

        SECURITY: symlinks are not followed, so a scan can never escape the
        requested directory.
        """
        found: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
            for filename in sorted(filenames):
                path = Path(dirpath) / filename
                if path.suffix.lower() in PYTHON_EXTENSIONS and not path.is_symlink():
                    found.append(path)
        return found

    # ------------------------------------------------------------------ internals

    def _scan_file_into(self, file_path: Path, result: ScanResult) -> None:
        display_name = file_path.as_posix()
        try:
            parsed = parse_file(file_path, display_name, self.max_file_size)
        except SourceError as exc:
            self._record_error(result, display_name, exc)
            return
        self._analyze_into(parsed, result)

    def _analyze_into(self, parsed: ParsedSource, result: ScanResult) -> None:
        findings = self.analyze(parsed)
        result.files_scanned += 1
        result.lines_scanned += parsed.line_count
        result.findings.extend(findings)
        logger.info("File scanned: %s (%d findings)", parsed.filename, len(findings))

    @staticmethod
    def _record_error(result: ScanResult, filename: str, exc: SourceError) -> None:
        result.errors.append(ScanError(filename, exc.error_type, exc.reason, exc.line))
        logger.warning("Error scanning %s: %s (%s)", filename, exc.error_type, exc.reason)

    @staticmethod
    def _finish(result: ScanResult) -> ScanResult:
        result.sort_findings()
        logger.info(
            "Scan completed: %s files=%d lines=%d findings=%d errors=%d",
            result.target, result.files_scanned, result.lines_scanned,
            len(result.findings), len(result.errors),
        )
        return result
