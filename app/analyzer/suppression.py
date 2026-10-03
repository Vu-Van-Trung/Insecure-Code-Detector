"""Comment bỏ qua cảnh báo ngay trong code (inline suppression).

    # analyzer-ignore: PY001, PY003        (Python)
    // analyzer-ignore: JV001              (Java, C#)
    /* analyzer-ignore: CS002 */

Comment ẩn các rule được liệt kê trên chính dòng của nó, hoặc trên dòng KẾ TIẾP
nếu comment nằm riêng một dòng. Không ghi mã rule (``analyzer-ignore``) thì mọi
rule trên dòng đó đều bị ẩn.

Comment được lấy từ tokenizer/parser của ngôn ngữ (``tokenize`` cho Python, node
comment của tree-sitter cho Java/C#), nên một chuỗi trông giống marker nhưng nằm
trong string literal (vd ``"# analyzer-ignore"``) không có tác dụng.

QUAN TRỌNG: suppression chỉ ẩn cảnh báo, không làm code trở nên an toàn.
"""

from __future__ import annotations

import io
import re
import tokenize
from collections.abc import Iterable

# Giá trị đặc biệt nghĩa là "ẩn mọi rule".
ALL_RULES = "ALL"
# Khớp "# analyzer-ignore", "// analyzer-ignore: PY001, PY002", "/* analyzer-ignore: CS002 */"...
# Nhóm "ids" (tùy chọn) là danh sách mã rule sau dấu ":".
_MARKER = re.compile(r"(?:#|//|/\*)\s*analyzer-ignore\b(?:\s*:\s*(?P<ids>[A-Za-z0-9_,\s]*))?", re.IGNORECASE)

# Số dòng -> tập mã rule bị ẩn trên dòng đó.
Ignores = dict[int, frozenset[str]]


def ignores_from_comments(comments: Iterable[tuple[int, str, bool]]) -> Ignores:
    """Tạo bảng bỏ qua từ các bộ ``(dòng, nội dung comment, comment có đứng riêng một dòng không)``.

    Hàm dùng chung cho mọi ngôn ngữ; mỗi ngôn ngữ chỉ cần cung cấp danh sách comment.
    """
    ignores: dict[int, set[str]] = {}
    for line, text, standalone in comments:
        match = _MARKER.match(text.strip())
        if not match:
            continue
        ids = {part.strip().upper() for part in (match.group("ids") or "").split(",") if part.strip()}
        # Comment đứng riêng một dòng áp dụng cho dòng code ngay bên dưới.
        target = line + 1 if standalone else line
        ignores.setdefault(target, set()).update(ids or {ALL_RULES})
    return {line: frozenset(ids) for line, ids in ignores.items()}


def parse_inline_ignores(source: str) -> Ignores:
    """Bảng bỏ qua của mã nguồn Python (comment được tìm bằng module ``tokenize``)."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, SyntaxError):
        # Code không tokenize được thì coi như không có comment bỏ qua nào.
        return {}
    return ignores_from_comments(
        # Comment "đứng riêng" nếu dòng chứa nó bắt đầu bằng "#" (không có code phía trước).
        (token.start[0], token.string, token.line.strip().startswith("#"))
        for token in tokens if token.type == tokenize.COMMENT
    )


def is_suppressed(rule_id: str, line: int, ignores: Ignores) -> bool:
    """True nếu rule ``rule_id`` bị ẩn trên dòng ``line`` (do ghi rõ mã rule hoặc ẩn tất cả)."""
    ids = ignores.get(line)
    return bool(ids) and (ALL_RULES in ids or rule_id.upper() in ids)
