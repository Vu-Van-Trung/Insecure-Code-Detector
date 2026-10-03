"""Lõi analyzer: biến file, thư mục hoặc mã nguồn thô thành một ScanResult.

Module này không phụ thuộc vào CLI hay tầng web, nên dùng lại được từ cả hai
(hoặc từ một job CI/CD).

Ngôn ngữ hỗ trợ: Python (``ast``), Java và C# (tree-sitter). Ngôn ngữ của file
được chọn theo extension (.py, .java, .cs).

Quy trình xử lý mỗi file::

    parse -> chạy rule (cây cú pháp + taint) -> bỏ finding chung bị trùng
          -> ghi đè severity -> ẩn theo comment/whitelist -> lọc theo ngưỡng
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
    """Chạy các security rule đã đăng ký trên mã nguồn Python, Java và C#.

    Tạo engine một lần rồi dùng cho nhiều lần scan: rule và cấu hình chỉ nạp một lần.
    """

    def __init__(self, registry: RuleRegistry | None = None, settings: AnalyzerSettings | None = None) -> None:
        """Ném ConfigError nếu các file cấu hình mặc định không hợp lệ.

        ``registry``/``settings`` cho phép test truyền bộ rule hoặc cấu hình riêng.
        """
        self.settings = settings if settings is not None else AnalyzerSettings.load()
        self.registry = registry if registry is not None else load_builtin_rules()
        # Chỉ tạo đối tượng cho rule đang bật (bỏ rule bị tắt trong cấu hình/whitelist).
        self.rules: list[SecurityRule] = self.registry.create_rules(self.settings.all_disabled_rules())
        for rule in self.rules:
            rule.configure(self.settings)
        # Nhóm rule theo ngôn ngữ để file .java chỉ chạy rule Java, v.v.
        self.rules_by_language: dict[str, list[SecurityRule]] = {}
        for rule in self.rules:
            self.rules_by_language.setdefault(rule.language, []).append(rule)
        # Rule "chung" (blacklist PY012/PY013) nhường chỗ cho rule chuyên biệt khi trùng vị trí.
        self._generic_rules = {rule.id for rule in self.rules if rule.generic}

    # ------------------------------------------------------------------ API công khai

    def scan_path(self, target: str | Path) -> ScanResult:
        """Scan một file nguồn, hoặc mọi file được hỗ trợ trong một thư mục.

        Ném FileNotFoundError nếu đích không tồn tại; lỗi của từng file (sai cú
        pháp, sai encoding...) được ghi vào ``result.errors`` và scan vẫn tiếp tục.
        """
        target_path = Path(target)
        if not target_path.exists():
            raise FileNotFoundError(f"Scan target not found: {target}")

        result, started = self._start(str(target))
        if target_path.is_file():
            # Người dùng chỉ định trực tiếp một file không hỗ trợ: báo lỗi rõ ràng.
            if language_of(target_path.name) is None:
                reason = (f"Unsupported file type '{target_path.suffix}', "
                          f"supported: {supported_extensions_text()}")
                self._record_error(result, target_path.as_posix(), SourceError("UnsupportedFile", reason))
                return self._finish(result, started)
            files = [target_path]
        else:
            files = self.discover_files(target_path)
        for file_path in files:
            # Đường dẫn dạng posix (dấu /) để report giống nhau trên Windows và Linux.
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
        """Scan văn bản mã nguồn mà không đụng tới đĩa; ngôn ngữ suy ra từ ``filename`` (mặc định Python).

        Dùng cho chức năng "paste code" của Web UI và trong test.
        """
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
        """Scan nhiều file nằm trong bộ nhớ (file upload qua web). Không ghi gì xuống đĩa."""
        result, started = self._start(target)
        for filename, data in sources:
            # Kiểm tra kích thước lần nữa ở đây vì dữ liệu upload không đi qua read_source_file.
            if len(data) > self.settings.max_file_size:
                reason = f"File is {len(data)} bytes, limit is {self.settings.max_file_size} bytes"
                self._record_error(result, filename, SourceError("FileTooLarge", reason))
                continue
            self._analyze_into(filename, data, result)
        return self._finish(result, started)

    def analyze(self, parsed: ParsedSource) -> list[Finding]:
        """Chạy mọi rule Python đang bật trên một file đã parse (trước bước ẩn/lọc ngưỡng)."""
        # Context chứa mọi thông tin rule cần: import, cây cha-con, kết quả taint...
        context = AnalysisContext.from_parsed(parsed, self.settings.taint)
        visitor = SecurityVisitor(self.rules_by_language.get(PYTHON, []), context)
        visitor.visit(parsed.tree)
        findings = self._drop_generic_duplicates(visitor.findings)
        self._apply_overrides(findings)
        return findings

    def analyze_tree_sitter(self, filename: str, source: str, language: str) -> tuple[list[Finding], Ignores, int]:
        """Parse và phân tích mã nguồn Java/C#. Ném SourceError khi có lỗi cú pháp.

        Trả về (danh sách finding, bảng comment bỏ qua, số dòng).
        """
        # Import ở đây (lazy) để engine vẫn chạy được với Python khi chưa cài tree-sitter.
        from app.analyzer.ts.adapters import LanguageUnavailable, get_adapter
        from app.analyzer.ts.context import TSContext
        from app.analyzer.ts.taint import TSTaintConfig, analyze_ts_taint

        try:
            adapter = get_adapter(language)
        except LanguageUnavailable as exc:
            raise SourceError("LanguageUnavailable", str(exc)) from exc
        tree = adapter.parse(source.encode("utf-8"))
        root = tree.root_node
        # tree-sitter vẫn tạo cây khi code sai cú pháp (có node ERROR); khi đó phân tích
        # sẽ không đáng tin, nên báo lỗi cú pháp như với Python.
        if root.has_error:
            line = _first_error_line(root)
            raise SourceError("SyntaxError", f"{DISPLAY_NAMES[language]} syntax error", line)

        ctx = TSContext.build(filename, source, root, adapter)
        taint_config = self.settings.language_taint.get(language) or TSTaintConfig()
        ctx.taint = analyze_ts_taint(ctx, taint_config)
        findings: list[Finding] = []
        # Rule Java/C# xét cả file một lần (check_file), không theo từng node như Python.
        for rule in self.rules_by_language.get(language, []):
            try:
                findings.extend(rule.check_file(ctx))  # type: ignore[attr-defined]
            except Exception:
                # Lỗi trong một rule không được làm hỏng việc scan cả file.
                logger.exception("Rule %s crashed on %s", rule.id, filename)
        for finding in findings:
            logger.info("Rule triggered: %s at %s:%d", finding.rule_id, finding.file, finding.line)
        self._apply_overrides(findings)
        return findings, ignores_from_comments(adapter.comments(root)), len(ctx.source_lines)

    def discover_files(self, root: Path) -> list[Path]:
        """Liệt kê các file nguồn được hỗ trợ trong ``root``, bỏ qua thư mục thư viện/sinh tự động.

        BẢO MẬT: không đi theo symlink, nên việc scan không bao giờ thoát ra
        ngoài thư mục được yêu cầu (vd một symlink trỏ tới / hoặc C:\\).
        """
        excluded = self.settings.excluded_dirs
        found: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Gán lại dirnames tại chỗ ([:]) là cách os.walk cho phép bỏ qua thư mục con;
            # sắp xếp để thứ tự file (và report) ổn định giữa các lần chạy.
            dirnames[:] = sorted(d for d in dirnames if d not in excluded)
            for filename in sorted(filenames):
                path = Path(dirpath) / filename
                if path.suffix.lower() in SUPPORTED_EXTENSIONS and not path.is_symlink():
                    found.append(path)
        return found

    # ------------------------------------------------------------------ nội bộ

    def _analyze_into(self, filename: str, data: bytes, result: ScanResult) -> None:
        """Phân tích bytes của một file theo đúng ngôn ngữ, rồi đưa finding vào ``result``."""
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
        """Phân loại từng finding: bị ẩn (suppressed), bị lọc (dưới ngưỡng) hoặc giữ lại."""
        kept = 0
        for finding in findings:
            finding.language = language
            if self.settings.honor_inline_ignores and is_suppressed(finding.rule_id, finding.line, ignores):
                # Suppression chỉ ẩn cảnh báo, không làm code an toàn - vẫn lưu lại để report liệt kê.
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
        """Áp dụng severity ghi đè từ severity.json (vd hạ PY009 xuống LOW cho dự án này)."""
        for finding in findings:
            override = self.settings.severity_overrides.get(finding.rule_id)
            if override is not None:
                finding.severity = override

    def _drop_generic_duplicates(self, findings: list[Finding]) -> list[Finding]:
        """Bỏ finding blacklist chung tại vị trí mà một rule chuyên biệt đã báo.

        Vd ``eval(x)`` vừa khớp PY001 vừa khớp blacklist (PY012): chỉ giữ PY001
        (thông tin chi tiết hơn). Nếu PY001 bị tắt, PY012 vẫn đảm bảo eval được báo.
        """
        specific = {(f.line, f.column) for f in findings if f.rule_id not in self._generic_rules}
        return [
            f for f in findings
            if f.rule_id not in self._generic_rules or (f.line, f.column) not in specific
        ]

    @staticmethod
    def _start(target: str) -> tuple[ScanResult, float]:
        """Tạo ScanResult rỗng và mốc thời gian bắt đầu (để đo thời gian scan)."""
        logger.info("Scan started: %s", target)
        result = ScanResult(
            target=target,
            tool_version=__version__,
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        # perf_counter: đồng hồ chính xác cao, không bị ảnh hưởng khi đổi giờ hệ thống.
        return result, time.perf_counter()

    @staticmethod
    def _record_error(result: ScanResult, filename: str, exc: SourceError) -> None:
        """Ghi một file lỗi vào kết quả (không dừng cả lần scan)."""
        result.errors.append(ScanError(filename, exc.error_type, exc.reason, exc.line))
        logger.warning("Error scanning %s: %s (%s)", filename, exc.error_type, exc.reason)

    @staticmethod
    def _finish(result: ScanResult, started: float) -> ScanResult:
        """Hoàn tất: tính thời gian, sắp xếp finding và ghi log tổng kết."""
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        result.sort_findings()
        logger.info(
            "Scan completed: %s files=%d lines=%d findings=%d suppressed=%d errors=%d",
            result.target, result.files_scanned, result.lines_scanned,
            len(result.findings), len(result.suppressed), len(result.errors),
        )
        return result


def _first_error_line(root) -> int | None:  # type: ignore[no-untyped-def]
    """Dòng (tính từ 1) của node ERROR / MISSING đầu tiên trong cây tree-sitter."""
    best = None
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            row = node.start_point[0]
            best = row if best is None else min(best, row)
            continue
        # Chỉ đi xuống nhánh nào có chứa lỗi (has_error) để không duyệt cả cây.
        if node.has_error:
            stack.extend(node.children)
    return best + 1 if best is not None else None
