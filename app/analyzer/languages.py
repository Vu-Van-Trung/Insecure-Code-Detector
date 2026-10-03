"""Các ngôn ngữ được hỗ trợ và phần mở rộng (extension) file tương ứng."""

from __future__ import annotations

from pathlib import PurePath

# Mã định danh nội bộ của từng ngôn ngữ (dùng làm khóa trong cấu hình, rule.language...).
PYTHON, JAVA, CSHARP = "python", "java", "csharp"

# Extension file -> ngôn ngữ. Engine dựa vào bảng này để chọn parser cho từng file.
EXTENSIONS: dict[str, str] = {".py": PYTHON, ".java": JAVA, ".cs": CSHARP}
# Tên hiển thị cho người dùng (report, Web UI).
DISPLAY_NAMES: dict[str, str] = {PYTHON: "Python", JAVA: "Java", CSHARP: "C#"}
# Tiền tố mã rule của từng ngôn ngữ (PY001, JV001, CS001).
RULE_PREFIXES: dict[str, str] = {PYTHON: "PY", JAVA: "JV", CSHARP: "CS"}


def language_of(filename: str) -> str | None:
    """Xác định ngôn ngữ của file theo extension; trả None nếu không hỗ trợ.

    So sánh không phân biệt hoa thường, nên ``App.PY`` vẫn được nhận là Python.
    """
    return EXTENSIONS.get(PurePath(filename).suffix.lower())


def extension_of(language: str) -> str:
    """Extension chuẩn của một ngôn ngữ, vd ``"java"`` -> ``".java"`` (dùng khi đặt tên file code được paste)."""
    return next(ext for ext, lang in EXTENSIONS.items() if lang == language)


def supported_extensions_text() -> str:
    """Danh sách extension để hiển thị trong thông báo lỗi, vd ``".py, .java, .cs"``."""
    return ", ".join(EXTENSIONS)
