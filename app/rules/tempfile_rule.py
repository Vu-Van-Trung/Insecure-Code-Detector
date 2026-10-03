"""PY017 - Tên file tạm không an toàn (tempfile.mktemp)."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.models.finding import Finding, Severity
from app.rules.base import CallRule
from app.rules.registry import register_rule

# Hàm chỉ trả về một tên file còn trống mà KHÔNG tạo file.
_NAME_ONLY_FUNCTIONS = frozenset({"tempfile.mktemp", "os.tempnam", "os.tmpnam"})


@register_rule
class InsecureTempFileRule(CallRule):
    """PY017: lỗi race condition kiểu TOCTOU (time-of-check to time-of-use).

    Giữa lúc lấy tên và lúc tạo file, kẻ tấn công có thể tạo trước một symlink
    cùng tên trỏ tới file quan trọng. ``tempfile.mkstemp()`` tạo file ngay
    (nguyên tử) nên không có khoảng hở này.
    """

    id = "PY017"
    name = "Insecure temporary file"
    description = (
        "The function only returns a file name that does not exist yet; the file is created "
        "later. In between, another local user or process can create a file or symlink with "
        "that name (race condition), making the program write to or read from a file the "
        "attacker controls."
    )
    severity = Severity.MEDIUM
    cwe = "CWE-377"
    category = "Insecure Temporary File"
    recommendation = (
        "Create the file atomically: tempfile.NamedTemporaryFile(), tempfile.mkstemp() or "
        "tempfile.TemporaryDirectory()."
    )

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        # Luôn báo, không phụ thuộc argument: bản thân hàm đã không an toàn.
        if name in _NAME_ONLY_FUNCTIONS:
            yield self.create_finding(
                node, context, f"{name}() returns a temporary file name without creating the file (race condition).",
                confidence=0.9,
            )
