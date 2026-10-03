"""Các hàm tiện ích về AST dùng chung cho analyzer và các rule."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator


# Các node mở ra một phạm vi biến (scope) mới: biến khai báo bên trong không thấy được từ bên ngoài.
SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def walk_scope(scope: ast.AST) -> Iterator[ast.AST]:
    """Giống ``ast.walk`` nhưng không đi vào hàm hay class lồng bên trong.

    Dùng khi chỉ cần các câu lệnh của đúng một hàm, vd tìm phép gán biến
    ``query`` trong hàm hiện tại mà không lẫn với biến cùng tên ở hàm con.
    """
    # Duyệt bằng stack (không đệ quy) để code lồng rất sâu không gây RecursionError.
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (*SCOPE_NODES, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))


def collect_imports(tree: ast.AST) -> dict[str, str]:
    """Ánh xạ mọi tên được import trong file sang tên đầy đủ (fully qualified name).

    Ví dụ::

        import os                      -> {"os": "os"}
        import subprocess as sp        -> {"sp": "subprocess"}
        import os.path                 -> {"os": "os"}
        from os import system          -> {"system": "os.system"}
        from os import system as run   -> {"run": "os.system"}

    Nhờ đó rule nhận ra ``sp.run(...)`` chính là ``subprocess.run(...)``, nên kẻ
    viết code không thể dùng alias để "giấu" một lời gọi nguy hiểm.
    """
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imports[alias.asname] = alias.name
                else:
                    # "import os.path" chỉ tạo tên "os" trong file.
                    top_level = alias.name.split(".", 1)[0]
                    imports[top_level] = top_level
        elif isinstance(node, ast.ImportFrom):
            # Import tương đối (from . import x) trỏ tới code của chính dự án, không phải thư viện.
            if node.level or not node.module:
                continue
            for alias in node.names:
                # "from x import *" không cho biết tên nào được import nên bỏ qua.
                if alias.name == "*":
                    continue
                imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return imports


def get_dotted_name(node: ast.AST) -> str | None:
    """Tên dạng chấm (chưa giải alias) của một chuỗi Name/Attribute, vd ``os.path.join``.

    Trả None với mọi thứ không phải chuỗi tên thuần, vd ``get_module().system``
    hay ``obj[0].run``.
    """
    # Attribute lồng nhau từ phải sang trái: os.path.join = Attribute(Attribute(Name(os), path), join)
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def resolve_name(node: ast.AST, imports: dict[str, str]) -> str | None:
    """Giống :func:`get_dotted_name` nhưng đã thay alias import bằng tên đầy đủ.

    Vd với ``import subprocess as sp``: ``sp.run`` -> ``subprocess.run``.
    """
    dotted = get_dotted_name(node)
    if dotted is None:
        return None
    # Chỉ phần đầu (trước dấu chấm đầu tiên) có thể là alias import.
    head, _, rest = dotted.partition(".")
    qualified_head = imports.get(head, head)
    return f"{qualified_head}.{rest}" if rest else qualified_head


def get_keyword(call: ast.Call, name: str) -> ast.keyword | None:
    """Keyword argument ``name`` của lời gọi hàm (vd ``shell=True``), hoặc None nếu không có."""
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword
    return None


def is_constant(node: ast.AST | None, value: object) -> bool:
    """True nếu node là hằng số bằng ``value`` VÀ cùng kiểu.

    So sánh cả kiểu vì trong Python ``0 == False`` và ``1 == True``.
    """
    return (
        isinstance(node, ast.Constant)
        and type(node.value) is type(value)
        and node.value == value
    )


def is_literal_string(node: ast.AST | None) -> bool:
    """True nếu node là chuỗi hằng thuần (không có phần nội suy như f-string)."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_static_value(node: ast.AST | None) -> bool:
    """True nếu giá trị hoàn toàn cố định trong mã nguồn.

    Giá trị tĩnh không thể chứa dữ liệu do kẻ tấn công kiểm soát, vd ``"ls -l"``,
    ``"a" + "b"``, ``f"text"`` (không có placeholder) hay ``["ls", "-l"]``.
    Bất cứ thứ gì có biến, lời gọi hàm hay placeholder của f-string đều là động.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        # Phần chữ của f-string là Constant; phần {placeholder} là FormattedValue.
        return all(isinstance(value, ast.Constant) for value in node.values)
    if isinstance(node, ast.BinOp):
        return is_static_value(node.left) and is_static_value(node.right)
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(is_static_value(element) for element in node.elts)
    return False


def split_identifier(name: str) -> list[str]:
    """Tách tên biến thành các từ viết thường (hỗ trợ cả snake_case và camelCase).

    ``API_KEY`` -> ["api", "key"], ``apiKey`` -> ["api", "key"],
    ``dbPassword2`` -> ["db", "password"].
    """
    # Hoặc một cụm chữ HOA không theo sau bởi chữ thường (API, KEY),
    # hoặc một từ có thể bắt đầu bằng chữ hoa rồi tới chữ thường (Password).
    words = re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+", name)
    return [word.lower() for word in words]


def string_parts(node: ast.AST) -> list[str]:
    """Các mảnh chuỗi hằng trong một biểu thức chuỗi (nối +, f-string, %, .format).

    Vd ``"SELECT * FROM t WHERE id=" + uid`` -> ["SELECT * FROM t WHERE id="].
    """
    parts: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            parts.append(child.value)
    return parts


def get_argument(call: ast.Call, position: int, keyword: str | None = None) -> ast.AST | None:
    """Argument của lời gọi hàm, dù được truyền theo vị trí hay theo tên (keyword).

    Vd ``get_argument(call, 0, "args")`` tìm được cả ``run(cmd)`` lẫn ``run(args=cmd)``.
    Trả None nếu không có argument đó hoặc nó bị ẩn sau ``*args`` (không biết vị trí thật).
    """
    positional = call.args[:position + 1]
    if any(isinstance(arg, ast.Starred) for arg in positional):
        return None
    if len(call.args) > position:
        return call.args[position]
    if keyword is not None:
        found = get_keyword(call, keyword)
        if found is not None:
            return found.value
    return None
