"""Minh họa AST và Taint Analysis trên Mẫu 2 (chỉ dùng thư viện chuẩn `ast`).

Đây là phiên bản RÚT GỌN để giải thích nguyên lý trên lớp; công cụ Insecure-Code-Detector
làm việc này đầy đủ hơn (nhiều source/sink, sanitizer, đi qua hàm, ...).

Chạy:
    python demo_ast_taint.py                     # phân tích vulnerable/app.py
    python demo_ast_taint.py fixed/app.py        # so sánh với bản đã sửa
    python demo_ast_taint.py --dump view_file    # in cây AST của một hàm
"""
import ast
import os
import sys

SOURCES = {"request.args", "request.form"}                     # dữ liệu không tin cậy đi vào
SANITIZERS = {"secure_filename", "os.path.basename"}            # cắt đứt taint
SINKS = {                                                       # nơi nguy hiểm nếu nhận taint
    "open": "Path Traversal (CWE-22)",
    "send_file": "Path Traversal (CWE-22)",
    "subprocess.run": "Command Injection (CWE-78)",
    "os.system": "Command Injection (CWE-78)",
}


def dotted_name(node):
    """request.args.get -> 'request.args.get'"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


class TaintTracker(ast.NodeVisitor):
    """Duyệt các câu lệnh của một hàm theo thứ tự, ghi nhớ biến nào đang bị 'nhiễm'."""

    def __init__(self, function_name):
        self.function_name = function_name
        self.tainted = {}           # tên biến -> chuỗi lan truyền, vd ['request.args', 'name']

    def taint_of(self, expr):
        """Trả về đường đi taint nếu biểu thức chứa dữ liệu nhiễm, ngược lại None."""
        if isinstance(expr, ast.Call):
            callee = dotted_name(expr.func) or ""
            if callee in SANITIZERS or callee.split(".")[-1] in SANITIZERS:
                return None                                          # sanitizer: taint bị cắt
            if any(callee.startswith(src) for src in SOURCES):
                return [callee.rsplit(".", 1)[0]]                    # request.args.get(...) là SOURCE
        if isinstance(expr, ast.Name) and expr.id in self.tainted:
            return self.tainted[expr.id]
        for child in ast.iter_child_nodes(expr):                     # lan truyền qua +, f-string, join(...)
            path = self.taint_of(child)
            if path:
                return path
        return None

    def visit_Assign(self, node):
        path = self.taint_of(node.value)
        for target in node.targets:
            names = [t.id for t in ast.walk(target) if isinstance(t, ast.Name)]
            for name in names:
                if path:
                    self.tainted[name] = path + [name]
                    print(f"  dòng {node.lineno:>3}: PROPAGATION  {' -> '.join(path)} -> {name}")
                else:
                    self.tainted.pop(name, None)
        self.generic_visit(node)

    def visit_Call(self, node):
        callee = dotted_name(node.func) or ""
        sink = SINKS.get(callee)
        if sink:
            for arg in node.args:
                path = self.taint_of(arg)
                if path:
                    print(f"  dòng {node.lineno:>3}: SINK {callee}()  <==  {' -> '.join(path)}")
                    print(f"            >>> CẢNH BÁO: {sink}")
                    break
            else:
                print(f"  dòng {node.lineno:>3}: sink {callee}() nhận dữ liệu sạch - an toàn")
        self.generic_visit(node)


def parse_file(path):
    # Script dòng lệnh: người chạy tự chọn tệp cần phân tích trên máy mình, không có kẻ tấn công
    # đứng giữa, nên cảnh báo Path Traversal ở đây được chủ động bỏ qua.
    with open(path, encoding="utf-8") as handle:  # analyzer-ignore: PY014
        return ast.parse(handle.read(), filename=path)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    here = os.path.dirname(os.path.abspath(__file__))
    args = sys.argv[1:]
    if args[:1] == ["--dump"]:
        func = args[1] if len(args) > 1 else "view_file"
        tree = parse_file(os.path.join(here, "vulnerable", "app.py"))
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == func)
        print(ast.dump(node, indent=2))
        return

    target = os.path.join(here, args[0] if args else os.path.join("vulnerable", "app.py"))
    tree = parse_file(target)
    print(f"Phân tích: {target}\n")

    # Tóm tắt hàm (function summary): hàm nội bộ có gọi sanitizer, ví dụ safe_storage_path()
    # gọi secure_filename(), thì giá trị nó trả về cũng được coi là đã làm sạch.
    builtin_sanitizers = {name.split(".")[-1] for name in SANITIZERS}
    for node in tree.body:
        is_route = any(isinstance(d, ast.Call) and dotted_name(d.func) == "app.route" for d in node.decorator_list) \
            if isinstance(node, ast.FunctionDef) else True
        if not is_route and any(
            isinstance(call, ast.Call) and (dotted_name(call.func) or "").split(".")[-1] in builtin_sanitizers
            for call in ast.walk(node)
        ):
            SANITIZERS.add(node.name)
            print(f"Tóm tắt hàm: {node.name}() gọi sanitizer -> coi là sanitizer\n")

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            print(f"Hàm {node.name}():")
            tracker = TaintTracker(node.name)
            for statement in node.body:
                tracker.visit(statement)
            print()


if __name__ == "__main__":
    main()
