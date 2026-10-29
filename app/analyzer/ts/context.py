"""Ngữ cảnh phân tích một file cho rule Java/C# (bản tương ứng của AnalysisContext, dùng tree-sitter).

Khác với Python (rule được gọi theo từng node), rule Java/C# đọc các danh sách
đã thu thập sẵn ở đây: mọi lời gọi hàm, khai báo, phép gán, chuỗi... Việc thu
thập chỉ duyệt cây MỘT lần, rồi mọi rule dùng chung.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.analyzer.ts.adapters import CallSite, Declaration, MethodInfo, TreeSitterAdapter, normalize, simple_type

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node

    from app.analyzer.ts.taint import TSTaintResult

MODULE_SCOPE = 0  # id scope dùng cho code cấp class (field), không nằm trong method nào


@dataclass
class Assignment:
    """Một phép gán ``target = value`` (hoặc ``+=``, ``-=``...) trong mã nguồn."""

    node: Node
    target: str        # văn bản vế trái đã chuẩn hóa: x, this.x, cmd.CommandText
    value: Node
    augmented: bool    # True với +=, -= ...
    scope: int         # id của method chứa phép gán (MODULE_SCOPE nếu ở cấp class)


@dataclass
class TSContext:
    """Mọi thông tin rule Java/C# cần về một file. Rule chỉ đọc, không sửa."""

    filename: str
    language: str
    source_lines: list[str]
    root: Node
    # Adapter che đi khác biệt cú pháp giữa Java và C# (xem adapters.py).
    adapter: TreeSitterAdapter
    calls: list[CallSite] = field(default_factory=list)            # mọi lời gọi hàm / new T()
    methods: list[MethodInfo] = field(default_factory=list)        # mọi method/constructor
    declarations: list[Declaration] = field(default_factory=list)  # khai báo biến/field
    assignments: list[Assignment] = field(default_factory=list)
    strings: list[Node] = field(default_factory=list)              # mọi chuỗi hằng (cho rule secret)
    lambdas: list[Node] = field(default_factory=list)
    call_by_node: dict[int, CallSite] = field(default_factory=dict)  # id node -> lời gọi tại node đó
    scope_of_node: dict[int, int] = field(default_factory=dict)     # id node -> id method bao quanh
    method_by_id: dict[int, MethodInfo] = field(default_factory=dict)
    var_types: dict[int, dict[str, str]] = field(default_factory=dict)  # scope -> tên biến -> kiểu
    var_values: dict[int, dict[str, Node]] = field(default_factory=dict)  # scope -> tên biến -> giá trị khởi tạo
    # Kết quả taint, engine gán sau khi build (taint cần context đã hoàn chỉnh).
    taint: TSTaintResult | None = None

    # ------------------------------------------------------------------ xây dựng

    @classmethod
    def build(cls, filename: str, source: str, root: Node, adapter: TreeSitterAdapter) -> TSContext:
        """Tạo context: thu thập mọi thông tin trong một lần duyệt, rồi suy kiểu của receiver."""
        ctx = cls(filename=filename, language=adapter.language, source_lines=source.splitlines(),
                  root=root, adapter=adapter)
        ctx._collect()
        # Suy kiểu receiver sau cùng, vì cần đủ mọi khai báo biến trong file.
        ctx._resolve_receiver_types()
        return ctx

    def _collect(self) -> None:
        """Duyệt toàn cây một lần, ghi lại method, lời gọi, khai báo, phép gán, chuỗi và lambda."""
        adapter = self.adapter
        # Stack chứa (node, scope hiện tại) - duyệt không đệ quy để tránh tràn stack với file lớn.
        stack: list[tuple[Node, int]] = [(self.root, MODULE_SCOPE)]
        while stack:
            node, scope = stack.pop()
            info = adapter.method_info(node)
            if info is not None:
                # Vào một method mới: id của node method trở thành id scope.
                scope = node.id
                self.methods.append(info)
                self.method_by_id[scope] = info
                # Tham số có khai báo kiểu: ghi lại để suy kiểu receiver (vd Statement stmt).
                types = self.var_types.setdefault(scope, {})
                for param in info.params:
                    if param.type:
                        types[param.name] = param.type
            self.scope_of_node[node.id] = scope

            call = adapter.call_site(node)
            if call is not None:
                self.calls.append(call)
                self.call_by_node[node.id] = call
            declarations = adapter.declarations(node)
            if declarations:
                for declaration in declarations:
                    self.declarations.append(declaration)
                    # Field của class thuộc scope module, nhìn thấy từ mọi method.
                    decl_scope = MODULE_SCOPE if declaration.is_field else scope
                    # Ưu tiên kiểu thực từ "new T()" hơn kiểu khai báo (var x = new T() trong C#).
                    value_type = self._creation_type(declaration.value)
                    if value_type or declaration.type:
                        self.var_types.setdefault(decl_scope, {})[declaration.name] = value_type or declaration.type
                    if declaration.value is not None:
                        self.var_values.setdefault(decl_scope, {})[declaration.name] = declaration.value
            # Phép gán thường; bỏ qua "Prop = value" bên trong object initializer của C#
            # (new T { Prop = value }) vì đã được CallSite.initializer ghi lại.
            if node.type in adapter.assignment_types and node.parent is not None \
                    and node.parent.type != "initializer_expression":
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                if left is not None and right is not None:
                    target = normalize(adapter.text(left))
                    self.assignments.append(Assignment(node, target, right, adapter.operator(node) != "=", scope))
                    # x = new T() (PHP không có câu khai báo biến): ghi lại kiểu để suy kiểu receiver.
                    value_type = self._creation_type(right)
                    if value_type:
                        self.var_types.setdefault(scope, {})[target] = value_type
            if adapter.is_string(node):
                self.strings.append(node)
            if node.type in adapter.lambda_types:
                self.lambdas.append(node)
            # Đẩy con theo thứ tự ngược để lấy ra theo đúng thứ tự mã nguồn.
            stack.extend((child, scope) for child in reversed(node.named_children))
        # Sắp xếp lời gọi theo vị trí trong file để finding ra theo thứ tự ổn định.
        self.calls.sort(key=lambda call: call.node.start_byte)

    def _creation_type(self, value: Node | None) -> str | None:
        """Kiểu được tạo bởi ``new T(...)`` trong giá trị khởi tạo, nếu có."""
        if value is None:
            return None
        call = self.adapter.call_site(self.adapter.unwrap(value))
        return call.method if call is not None and call.is_constructor else None

    def _resolve_receiver_types(self) -> None:
        """Gán kiểu cho đối tượng nhận của mỗi lời gọi, vd ``stmt.executeQuery()`` -> Statement."""
        for call in self.calls:
            if call.receiver is not None and not call.is_constructor:
                call.receiver_type = self.type_of(call.receiver)

    # ------------------------------------------------------------------ truy vấn

    def type_of(self, node: Node) -> str | None:
        """Kiểu tĩnh (ước lượng tốt nhất có thể) của một biểu thức: kiểu khai báo, ``new T()``, ``T.factory()``.

        Không phân giải kiểu đầy đủ như trình biên dịch (không đọc import/using).
        """
        node = self.adapter.unwrap(node)
        text = self.adapter.text(node)
        if node.type in self.adapter.identifier_types:
            # Tìm trong method hiện tại trước, sau đó tới field của class.
            scope = self.scope_of_node.get(node.id, MODULE_SCOPE)
            for types in (self.var_types.get(scope, {}), self.var_types.get(MODULE_SCOPE, {})):
                if text in types:
                    return types[text]
            # Tên lạ viết hoa chữ đầu: theo quy ước Java/C# đó là tên class (lời gọi static).
            return text if text[:1].isupper() else None
        call = self.call_by_node.get(node.id)
        if call is not None:
            if call.is_constructor:
                return call.method
            # Factory static trên class: Runtime.getRuntime(), MD5.Create(), MessageDigest.getInstance()
            receiver = call.receiver
            if receiver is not None and receiver.type in self.adapter.identifier_types \
                    and self.adapter.text(receiver)[:1].isupper():
                return self.adapter.text(receiver)
            return None
        if node.type in self.adapter.member_types:
            if text[:1].isupper():
                return simple_type(text)  # System.IO.File -> File
            # Tên class viết đầy đủ package của Java: java.nio.file.Files -> Files.
            # Package viết thường, class viết hoa (chỉ Java: property C# cũng viết hoa, vd client.Http).
            parts = normalize(text).split(".")
            if self.language == "java" and parts[0] not in {"this", "super"} and parts[-1][:1].isupper() \
                    and all(part.isidentifier() and part[:1].islower() for part in parts[:-1]):
                return parts[-1]
        return None

    def get_line(self, lineno: int) -> str:
        """Dòng mã nguồn thứ ``lineno`` (tính từ 1) đã bỏ khoảng trắng hai đầu."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def scope(self, node: Node) -> int:
        """Id scope (method) chứa node; đi ngược lên cha cho tới node đã được ghi nhận."""
        current: Node | None = node
        while current is not None:
            if current.id in self.scope_of_node:
                return self.scope_of_node[current.id]
            current = current.parent
        return MODULE_SCOPE

    def enclosing_method_name(self, node: Node) -> str | None:
        """Tên method chứa node (vd để biết Random được dùng trong ``generateToken()``)."""
        info = self.method_by_id.get(self.scope(node))
        return info.name if info else None

    def initializer_of(self, name: str, node: Node) -> Node | None:
        """Giá trị khởi tạo của biến ``name`` nhìn thấy từ ``node`` (trong method trước, rồi tới field)."""
        return self.var_values.get(self.scope(node), {}).get(name) or self.var_values.get(MODULE_SCOPE, {}).get(name)

    def assignments_before(self, name: str, node: Node) -> list[tuple[int, Node, bool]]:
        """Các bộ (dòng, giá trị, là phép gán cộng dồn?) của khai báo/phép gán ``name`` trước ``node`` trong cùng method.

        Dùng để lần ngược cách một câu SQL được xây dựng qua nhiều dòng.
        """
        scope, row = self.scope(node), node.start_point[0]
        found = []
        for declaration in self.declarations:
            if (declaration.name == name and declaration.value is not None and not declaration.is_field
                    and self.scope(declaration.node) == scope and declaration.node.start_point[0] < row):
                found.append((declaration.node.start_point[0] + 1, declaration.value, False))
        for assignment in self.assignments:
            if assignment.target == name and assignment.scope == scope and assignment.node.start_point[0] < row:
                found.append((assignment.node.start_point[0] + 1, assignment.value, assignment.augmented))
        return sorted(found, key=lambda item: item[0])

    def assigned_name(self, node: Node) -> str | None:
        """Biến/field/property nhận giá trị của ``node`` (đi ngược lên tới câu lệnh chứa nó).

        Vd ``String token = rnd.nextInt()`` -> "token".
        """
        current = node.parent
        while current is not None and not self.adapter.is_statement(current):
            if current.type == "variable_declarator":
                return self.adapter.text(current.child_by_field_name("name"))
            if current.type in self.adapter.assignment_types:
                return self.adapter.text(current.child_by_field_name("left")).rsplit(".", 1)[-1]
            current = current.parent
        return None
