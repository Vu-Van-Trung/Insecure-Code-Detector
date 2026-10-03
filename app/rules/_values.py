"""Hàm tiện ích xem một argument chuỗi được tạo ra như thế nào (dùng chung cho PY015 và PY018)."""

from __future__ import annotations

import ast

from app.analyzer.context import AnalysisContext


def assigned_values(node: ast.AST, context: AnalysisContext) -> list[ast.AST]:
    """Các biểu thức có thể đã cho ``node`` giá trị của nó.

    Với một biến: các phép gán trước đó trong cùng scope (``x = ...``, ``x += ...``);
    với mọi thứ khác: chính biểu thức đó.

    Vd ``url = f"https://api/{id}"`` rồi ``requests.get(url)`` -> trả về [f"https://api/{id}"],
    để rule xét được cách URL được tạo dù nó được truyền qua biến.
    """
    if isinstance(node, ast.Name):
        values = [stmt.value for stmt in context.assignments_before(node.id, node)]
        if values:
            return values
    return [node]


def is_string_building(node: ast.AST) -> bool:
    """f-string có placeholder, ghép bằng ``+`` / ``%``, ``.format()`` hoặc ``.join()``."""
    if isinstance(node, ast.JoinedStr):
        # f"text" không có {..} là hằng số, không phải "ghép chuỗi".
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, (ast.Add, ast.Mod))
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"format", "join"}
    )


def leading_literal(node: ast.AST) -> str | None:
    """Phần chữ cố định mà biểu thức chuỗi bắt đầu, vd ``"https://api/"`` trong
    ``f"https://api/{x}"``, ``"https://api/" + x`` hoặc ``"https://api/{}".format(x)``.

    Trả None nếu không bắt đầu bằng chữ cố định (vd ``host + "/api"``).
    """
    # Đi dần về phía TRÁI của biểu thức cho tới khi gặp chuỗi hằng.
    while True:
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.JoinedStr):
            first = node.values[0] if node.values else None
            return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            node = node.left
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            node = node.func.value
        else:
            return None
