"""PY014 - Path traversal: dữ liệu không tin cậy được dùng làm đường dẫn file."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument
from app.models.finding import Severity
from app.rules.base import TaintedSinkRule
from app.rules.registry import register_rule

# Hàm thao tác file -> các argument là đường dẫn, dạng (vị trí, tên keyword).
# Hàm có 2 đường dẫn (copy, move, rename) thì kiểm tra cả nguồn lẫn đích.
_PATH_FUNCTIONS: dict[str, tuple[tuple[int, str | None], ...]] = {
    "open": ((0, "file"),),
    "io.open": ((0, "file"),),
    "codecs.open": ((0, "filename"),),
    "os.open": ((0, "path"),),
    "os.remove": ((0, "path"),),
    "os.unlink": ((0, "path"),),
    "os.rmdir": ((0, "path"),),
    "os.removedirs": ((0, "name"),),
    "os.listdir": ((0, "path"),),
    "os.scandir": ((0, "path"),),
    "os.rename": ((0, "src"), (1, "dst")),
    "os.replace": ((0, "src"), (1, "dst")),
    "shutil.rmtree": ((0, "path"),),
    "shutil.copy": ((0, "src"), (1, "dst")),
    "shutil.copy2": ((0, "src"), (1, "dst")),
    "shutil.copyfile": ((0, "src"), (1, "dst")),
    "shutil.copytree": ((0, "src"), (1, "dst")),
    "shutil.move": ((0, "src"), (1, "dst")),
    "flask.send_file": ((0, "path_or_file"),),
    "fastapi.responses.FileResponse": ((0, "path"),),
    "starlette.responses.FileResponse": ((0, "path"),),
}
# Method của pathlib đọc, ghi hoặc xóa file mà Path trỏ tới.
_PATHLIB_METHODS = frozenset({
    "open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir", "touch", "mkdir",
})
_PATHLIB_CLASSES = frozenset({
    "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath",
})


@register_rule
class PathTraversalRule(TaintedSinkRule):
    """PY014: chỉ báo khi chứng minh được đường dẫn đến từ request/input (xem TaintedSinkRule).

    ``secure_filename()`` / ``os.path.basename()`` là sanitizer của loại sink
    "path" (taint.json) nên đường dẫn đi qua chúng không bị báo.
    ``send_from_directory`` của Flask tự kiểm tra đường dẫn nên không có trong danh sách sink.
    """

    id = "PY014"
    name = "Path traversal"
    description = (
        "A file system path is built from untrusted input. Sequences such as ../ or an "
        "absolute path let an attacker read, overwrite or delete files outside the "
        "intended directory (e.g. ../../etc/passwd or the application's config)."
    )
    severity = Severity.HIGH
    cwe = "CWE-22"
    category = "Path Traversal"
    recommendation = (
        "Keep only the file name with werkzeug.utils.secure_filename() or os.path.basename(), "
        "or resolve the path and check it stays inside the base directory "
        "(Path(base, name).resolve().is_relative_to(base)). In Flask, prefer send_from_directory()."
    )
    sanitizer_category = "path"

    def sink_arguments(
        self, node: ast.Call, name: str | None, context: AnalysisContext,
    ) -> Iterator[tuple[ast.AST, str]]:
        # 1) Hàm trong bảng _PATH_FUNCTIONS (bỏ qua nếu "open" bị file định nghĩa lại).
        if name in _PATH_FUNCTIONS and not context.is_shadowed_builtin(name):
            for position, keyword in _PATH_FUNCTIONS[name]:
                argument = get_argument(node, position, keyword)
                if argument is not None:
                    yield argument, f"{name}()"
            return
        if not isinstance(node.func, ast.Attribute):
            return
        receiver, method = node.func.value, node.func.attr
        # 2) Method của pathlib: đường dẫn nằm ở đối tượng nhận, không phải argument.
        if method in _PATHLIB_METHODS and self._is_path_object(receiver, context):
            # Path(user_input).read_text(), (BASE / user_input).unlink()
            yield receiver, f"Path.{method}()"
        # 3) Lưu file upload: .save(path) chỉ được xét khi đối tượng nhận là file upload,
        # vì "save" là tên method rất phổ biến (model.save(), image.save()...).
        elif method == "save" and node.args:
            # Upload của Flask/Werkzeug: request.files["f"].save(os.path.join(DIR, f.filename))
            info = context.taint.lookup(receiver)
            if info is not None and info.source == "request.files":
                yield node.args[0], "FileStorage.save()"

    @staticmethod
    def _is_path_object(node: ast.AST, context: AnalysisContext) -> bool:
        """True nếu biểu thức chắc chắn là một đối tượng pathlib."""
        if isinstance(node, ast.Call):
            return context.call_name(node) in _PATHLIB_CLASSES
        # Chuỗi không hỗ trợ toán tử "/", nên BASE / name là một đường dẫn pathlib.
        return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
