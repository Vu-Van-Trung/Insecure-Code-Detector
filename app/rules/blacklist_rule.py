"""PY012 / PY013 - Hàm và module được liệt kê trong blacklist.json.

Các rule "chung" (generic) này cho phép người dùng đánh dấu thêm API nguy hiểm
mà không cần viết code. Khi một rule chuyên biệt (vd PY001 cho eval) đã báo
cùng vị trí, engine bỏ bản trùng của rule chung.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from typing import TYPE_CHECKING

from app.analyzer.context import AnalysisContext
from app.config.settings import BlacklistEntry
from app.models.finding import Finding, Severity
from app.rules.base import CallRule, SecurityRule
from app.rules.registry import register_rule

if TYPE_CHECKING:
    from app.config.settings import AnalyzerSettings


@register_rule
class BlacklistedFunctionRule(CallRule):
    """PY012: lời gọi tới hàm có trong blacklist; severity/CWE lấy từ mục blacklist."""

    id = "PY012"
    name = "Call to blacklisted function"
    description = "The called function is listed in blacklist.json as dangerous for this project."
    severity = Severity.MEDIUM
    cwe = "CWE-676"
    category = "Dangerous Function"
    recommendation = "Review whether this call is necessary and replace it with a safer alternative."
    generic = True

    def __init__(self) -> None:
        self.entries: dict[str, BlacklistEntry] = {}

    def configure(self, settings: AnalyzerSettings) -> None:
        # Danh sách hàm nạp từ blacklist.json (qua AnalyzerSettings).
        self.entries = settings.blacklist.functions

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        entry = self.entries.get(name) if name else None
        if entry is None or context.is_shadowed_builtin(name):
            return
        yield self.create_finding(
            node, context, f"Call to blacklisted function {name}(): {entry.reason}.",
            severity=entry.severity, confidence=0.6, cwe=entry.cwe,
        )


@register_rule
class BlacklistedModuleRule(SecurityRule):
    """PY013: import module có trong blacklist (mặc định INFO - chỉ nhắc review)."""

    id = "PY013"
    name = "Import of blacklisted module"
    description = (
        "The imported module is listed in blacklist.json. Importing it is not a "
        "vulnerability by itself, but every use of it deserves a review."
    )
    severity = Severity.INFO
    cwe = "CWE-676"
    category = "Dangerous Module"
    recommendation = "Check how the module is used; prefer the safer alternative named in the blacklist reason."
    node_types = (ast.Import, ast.ImportFrom)
    generic = True

    def __init__(self) -> None:
        self.entries: dict[str, BlacklistEntry] = {}

    def configure(self, settings: AnalyzerSettings) -> None:
        self.entries = settings.blacklist.modules

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not self.entries:
            return
        if isinstance(node, ast.Import):
            # import a, b.c  -> ["a", "b.c"]
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            # from x.y import z -> ["x.y"]; import tương đối (from . import) bị bỏ qua.
            modules = [node.module]
        else:
            return
        for module in modules:
            entry = self._match(module)
            if entry is not None:
                yield self.create_finding(
                    node, context, f"Import of blacklisted module '{module}': {entry.reason}.",
                    severity=entry.severity, confidence=0.5, cwe=entry.cwe,
                )

    def _match(self, module: str) -> BlacklistEntry | None:
        """'xml.etree' khớp với mục 'xml' cũng như mục 'xml.etree' (ưu tiên mục cụ thể nhất)."""
        parts = module.split(".")
        for i in range(len(parts), 0, -1):
            entry = self.entries.get(".".join(parts[:i]))
            if entry is not None:
                return entry
        return None
