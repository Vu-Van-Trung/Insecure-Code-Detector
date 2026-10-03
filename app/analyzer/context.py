"""Ngữ cảnh phân tích của một file, được truyền cho mọi rule."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from app.analyzer.parser import ParsedSource
from app.analyzer.taint import TaintConfig, TaintResult, analyze_taint
from app.analyzer.utils import SCOPE_NODES, collect_imports, resolve_name, walk_scope


@dataclass
class AnalysisContext:
    """Mọi thông tin mà một rule có thể cần về file đang phân tích.

    Engine tạo đúng một lần cho mỗi file (các phép tính tốn kém như taint chỉ
    chạy một lần, mọi rule dùng chung); rule chỉ được đọc, không được sửa.
    """

    filename: str
    source_lines: list[str]
    tree: ast.Module
    # Tên import -> tên đầy đủ, vd {"sp": "subprocess"} (xem utils.collect_imports).
    imports: dict[str, str] = field(default_factory=dict)
    # Node con -> node cha. ast không lưu node cha nên phải tự lập bảng này
    # (vd để biết một lời gọi random() nằm trong phép gán nào).
    parents: dict[ast.AST, ast.AST] = field(default_factory=dict)
    # Các tên do chính file định nghĩa (hàm, class, biến được gán).
    local_names: set[str] = field(default_factory=set)
    # Nhãn (tainted / static / unknown) của mọi biểu thức; xem taint.py.
    taint: TaintResult = field(default_factory=TaintResult)

    @classmethod
    def from_parsed(cls, parsed: ParsedSource, taint_config: TaintConfig | None = None) -> AnalysisContext:
        """Dựng context từ file đã parse: bảng cha-con, tên cục bộ, import và kết quả taint."""
        parents: dict[ast.AST, ast.AST] = {}
        local_names: set[str] = set()
        # Một lần duyệt cây thu thập cả quan hệ cha-con lẫn các tên được định nghĩa.
        for node in ast.walk(parsed.tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                local_names.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                local_names.add(node.id)
        imports = collect_imports(parsed.tree)
        # Không có cấu hình taint (một số test) thì dùng kết quả rỗng: mọi giá trị là "unknown".
        taint = analyze_taint(parsed.tree, imports, taint_config) if taint_config else TaintResult()
        return cls(
            filename=parsed.filename,
            source_lines=parsed.lines,
            tree=parsed.tree,
            imports=imports,
            parents=parents,
            local_names=local_names,
            taint=taint,
        )

    def get_line(self, lineno: int) -> str:
        """Dòng mã nguồn thứ ``lineno`` (tính từ 1) đã bỏ khoảng trắng hai đầu, hoặc chuỗi rỗng."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def resolve(self, node: ast.AST) -> str | None:
        """Tên đầy đủ của node Name/Attribute sau khi giải alias import."""
        return resolve_name(node, self.imports)

    def call_name(self, call: ast.Call) -> str | None:
        """Tên đầy đủ của hàm được gọi, vd ``sp.run(...)`` -> ``subprocess.run``."""
        return self.resolve(call.func)

    def parent(self, node: ast.AST) -> ast.AST | None:
        return self.parents.get(node)

    def enclosing_scope(self, node: ast.AST) -> ast.AST:
        """Hàm (hoặc lambda) gần nhất bao quanh node; ở cấp cao nhất thì là cả module."""
        current = self.parents.get(node)
        while current is not None:
            if isinstance(current, SCOPE_NODES):
                return current
            current = self.parents.get(current)
        return self.tree

    def enclosing_function_name(self, node: ast.AST) -> str | None:
        """Tên hàm bao quanh node (None nếu ở cấp module hoặc trong lambda).

        Vd PY009 dùng để biết ``random.randint()`` có nằm trong hàm ``generate_token`` không.
        """
        scope = self.enclosing_scope(node)
        return scope.name if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) else None

    def assignments_before(self, name: str, node: ast.AST) -> list[ast.stmt]:
        """Các phép gán cho biến ``name`` trong cùng scope, nằm trước ``node``.

        Gồm ``x = ...``, ``x: T = ...`` và ``x += ...``, sắp xếp theo dòng.
        Đây là xấp xỉ không phân biệt luồng (flow-insensitive): không phân biệt
        nhánh if/else hay vòng lặp - chấp nhận được với một prototype.
        """
        line = getattr(node, "lineno", 0)
        found: list[ast.stmt] = []
        for stmt in walk_scope(self.enclosing_scope(node)):
            # Chỉ xét câu lệnh nằm ở dòng trước node.
            if getattr(stmt, "lineno", line) >= line:
                continue
            if isinstance(stmt, ast.Assign):
                if any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                    found.append(stmt)
            elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                if isinstance(stmt.target, ast.Name) and stmt.target.id == name and stmt.value is not None:
                    found.append(stmt)
        # walk_scope duyệt bằng stack nên không theo thứ tự dòng -> sắp xếp lại.
        return sorted(found, key=lambda stmt: stmt.lineno)

    def is_shadowed_builtin(self, name: str) -> bool:
        """True nếu một hàm builtin như ``eval`` bị chính file định nghĩa lại.

        ``def eval(expr): ...`` rồi ``eval(x)`` là gọi hàm cục bộ, không phải
        builtin, nên báo cáo sẽ là false positive.
        """
        return "." not in name and name in self.local_names
