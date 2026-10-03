"""Adapter ngôn ngữ: chuyển node tree-sitter của Java và C# về một mô hình chung.

Rule và taint analyzer chỉ làm việc với mô hình này (CallSite, khai báo, phép
gán, method), nên chúng được viết MỘT lần cho cả hai ngôn ngữ (Adapter pattern).
Mỗi adapter chỉ mô tả tên các loại node trong grammar của ngôn ngữ đó, vd lời
gọi hàm là ``method_invocation`` trong Java nhưng ``invocation_expression`` trong C#.

BẢO MẬT: giống analyzer Python, mã nguồn chỉ được parse, không bao giờ được
biên dịch hay thực thi.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from app.analyzer.languages import CSHARP, JAVA

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node, Tree


class LanguageUnavailable(RuntimeError):
    """Chưa cài tree-sitter (hoặc grammar của ngôn ngữ đó)."""


def normalize(text: str) -> str:
    """Bỏ mọi khoảng trắng để ``Runtime . getRuntime ()`` == ``Runtime.getRuntime()``."""
    return re.sub(r"\s+", "", text)


def simple_type(text: str | None) -> str | None:
    """Tên kiểu ngắn gọn: ``java.util.List<String>[]`` -> ``List``; ``var`` -> None (không biết kiểu)."""
    if not text:
        return None
    # Bỏ tham số generic <...>, dấu mảng [] và dấu nullable ? của C#.
    text = re.sub(r"<.*>", "", text).replace("[]", "").replace("?", "").strip()
    # Bỏ tên package/namespace: java.util.List -> List.
    name = text.rsplit(".", 1)[-1]
    return None if name in {"var", ""} else name


# --------------------------------------------------------------------------- mô hình chung


@dataclass
class CallSite:
    """Một lời gọi method hoặc lời gọi constructor (``new T(...)``)."""

    node: Node
    method: str                      # tên method, hoặc tên kiểu với constructor
    args: list[Node]
    receiver: Node | None = None     # đối tượng đứng trước dấu chấm, vd stmt trong stmt.execute()
    receiver_text: str | None = None  # văn bản đã chuẩn hóa của receiver
    receiver_type: str | None = None  # kiểu của receiver, được TSContext suy ra sau
    is_constructor: bool = False
    initializer: dict[str, Node] = field(default_factory=dict)  # C#: new T { Prop = value }

    @property
    def names(self) -> frozenset[str]:
        """Các tên dùng để so với mẫu đã cấu hình (``Runtime.exec``, ``new ProcessBuilder``...).

        Vd ``stmt.executeQuery(q)`` với stmt kiểu Statement cho ra
        {"executeQuery", "stmt.executeQuery", "Statement.executeQuery"}.
        """
        if self.is_constructor:
            return frozenset({f"new {self.method}"})
        names = {self.method}
        if self.receiver_text:
            names.add(f"{self.receiver_text}.{self.method}")
        if self.receiver_type:
            names.add(f"{self.receiver_type}.{self.method}")
        return frozenset(names)

    @property
    def display(self) -> str:
        """Tên hiển thị trong message, ưu tiên tên kiểu (Statement.executeQuery()) hơn tên biến."""
        if self.is_constructor:
            return f"new {self.method}()"
        owner = self.receiver_type or self.receiver_text
        return f"{owner}.{self.method}()" if owner else f"{self.method}()"


@dataclass
class Parameter:
    """Tham số của method."""

    name: str
    type: str | None
    annotations: frozenset[str]  # Java @RequestParam / C# [FromQuery] (chỉ tên ngắn)


@dataclass
class MethodInfo:
    """Một method/constructor: tên, tham số và thân hàm."""

    node: Node
    name: str
    params: list[Parameter]
    body: Node | None  # None với method abstract / interface


@dataclass
class Declaration:
    """``Type name = value`` (biến cục bộ, field, property, resource của try-with-resources)."""

    node: Node
    name: str
    type: str | None
    value: Node | None
    is_field: bool = False


# --------------------------------------------------------------------------- adapter cơ sở


class TreeSitterAdapter:
    """Hành vi chung; lớp con khai báo các loại node của một grammar cụ thể.

    Các thuộc tính ``*_types`` là tập tên loại node của tree-sitter, vd
    ``string_types = {"string_literal"}``.
    """

    language: str
    comment_types: frozenset[str]
    string_types: frozenset[str]
    literal_types: frozenset[str]       # số, true/false, null...
    interpolated_types: frozenset[str] = frozenset()  # chuỗi nội suy $"..." của C#
    call_type: str
    constructor_types: frozenset[str]
    member_types: frozenset[str]        # truy cập thành viên obj.field
    element_types: frozenset[str]       # truy cập phần tử a[i]
    lambda_types: frozenset[str]
    method_types: frozenset[str]
    class_types: frozenset[str]
    branch_types: frozenset[str]        # câu lệnh rẽ nhánh / lặp / try
    assignment_type = "assignment_expression"
    binary_type = "binary_expression"
    ternary_types: frozenset[str]
    wrapper_types: frozenset[str]  # ngoặc / ép kiểu / argument: nhãn taint đi xuyên qua

    def __init__(self) -> None:
        # Import tree-sitter ở đây (lazy) để thiếu thư viện chỉ ảnh hưởng tới Java/C#.
        try:
            from tree_sitter import Language, Parser
        except ImportError as exc:  # pragma: no cover - phụ thuộc môi trường
            raise LanguageUnavailable("tree-sitter is not installed (pip install -r requirements.txt)") from exc
        self._parser = Parser(Language(self._grammar()))

    def _grammar(self) -> Any:  # pragma: no cover - lớp con ghi đè
        raise NotImplementedError

    def parse(self, data: bytes) -> Tree:
        return self._parser.parse(data)

    # ----------------------------------------------------------- tiện ích

    @staticmethod
    def text(node: Node | None) -> str:
        """Văn bản mã nguồn của node (errors="replace" để byte lỗi không làm hỏng phân tích)."""
        return node.text.decode("utf-8", errors="replace") if node is not None else ""

    @staticmethod
    def operator(node: Node) -> str:
        """Toán tử của biểu thức nhị phân/phép gán (node con không có tên đầu tiên, vd "+", "+=")."""
        return next((child.type for child in node.children if not child.is_named), "")

    def is_statement(self, node: Node) -> bool:
        return node.type.endswith("_statement") or node.type in self.statement_types

    # Các loại node được coi như câu lệnh dù tên không kết thúc bằng "_statement".
    statement_types: frozenset[str] = frozenset()

    def is_string(self, node: Node) -> bool:
        return node.type in self.string_types

    def string_value(self, node: Node) -> str | None:
        """Giá trị của chuỗi hằng thuần (None với chuỗi nội suy hoặc node không phải chuỗi)."""
        if node.type not in self.string_types:
            return None
        # Grammar mới tách nội dung chuỗi thành node con (string_fragment...).
        parts = [self.text(c) for c in node.named_children if c.type not in self.comment_types]
        if parts:
            return "".join(parts)
        # Chuỗi rỗng hoặc grammar không có node con: bỏ dấu nháy bằng regex.
        raw = self.text(node)
        match = re.match(r'^@?"""?(.*?)"""?$', raw, re.DOTALL)
        return match.group(1) if match else ""

    def is_static(self, node: Node | None) -> bool:
        """Giá trị cố định trong mã nguồn (dùng khi không có nhãn taint cho node)."""
        if node is None:
            return False
        if node.type in self.string_types or node.type in self.literal_types:
            return True
        if node.type == self.binary_type:
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            return self.is_static(left) and self.is_static(right)
        if node.type in self.wrapper_types:
            inner = self.unwrap(node)
            return inner.id != node.id and self.is_static(inner)
        if node.type in self.interpolated_types:
            # $"text" không có {..} thì là hằng số.
            return not self.interpolation_values(node)
        return False

    def unwrap(self, node: Node) -> Node:
        """Bỏ lớp bọc: (x), (T) x, ``argument`` của C# -> x."""
        while node.type in self.wrapper_types:
            inner = node.child_by_field_name("value") or (node.named_children[-1] if node.named_children else None)
            if inner is None or inner.id == node.id:
                break
            node = inner
        return node

    def interpolation_values(self, node: Node) -> list[Node]:
        """Các biểu thức bên trong {...} của chuỗi nội suy (Java không có nên trả rỗng)."""
        return []

    def comments(self, root: Node) -> list[tuple[int, str, bool]]:
        """(dòng, nội dung, comment có đứng riêng một dòng không) của mọi comment - dùng cho analyzer-ignore."""
        found: list[tuple[int, str, bool]] = []
        stack = [root]
        lines = None
        while stack:
            node = stack.pop()
            if node.type in self.comment_types:
                # Chỉ tách dòng khi file thật sự có comment.
                if lines is None:
                    lines = root.text.decode("utf-8", errors="replace").splitlines()
                row, column = node.start_point
                # Không có code nào phía trước comment trên cùng dòng -> comment đứng riêng.
                prefix = lines[row][:column] if row < len(lines) else ""
                found.append((row + 1, self.text(node), not prefix.strip()))
            stack.extend(node.children)
        return found

    # ----------------------------------------------------------- hook riêng của từng ngôn ngữ

    def call_site(self, node: Node) -> CallSite | None:  # pragma: no cover - lớp con ghi đè
        """CallSite nếu node là lời gọi hàm/constructor, ngược lại None."""
        raise NotImplementedError

    def declarations(self, node: Node) -> list[Declaration] | None:  # pragma: no cover
        """Danh sách khai báo nếu node là câu lệnh khai báo, ngược lại None."""
        raise NotImplementedError

    def method_info(self, node: Node) -> MethodInfo | None:  # pragma: no cover
        raise NotImplementedError

    def loop_binding(self, node: Node) -> tuple[str, Node] | None:  # pragma: no cover
        """(tên biến lặp, biểu thức được lặp) của vòng for-each."""
        raise NotImplementedError

    def member_object(self, node: Node) -> Node | None:  # pragma: no cover
        """Đối tượng ``obj`` trong ``obj.field``."""
        raise NotImplementedError

    def element_parts(self, node: Node) -> tuple[Node | None, list[Node]]:  # pragma: no cover
        """(mảng/container, các chỉ số) của ``a[i]``."""
        raise NotImplementedError

    def lambda_returns_true(self, node: Node) -> bool:
        """``(a, b) -> true`` / ``delegate { return true; }`` - dấu hiệu tắt kiểm tra chứng chỉ TLS."""
        body = node.child_by_field_name("body") or (node.named_children[-1] if node.named_children else None)
        if body is None:
            return False
        # Dạng biểu thức: (a, b) -> true
        if self.text(body).strip() == "true":
            return True
        # Dạng khối: { return true; }
        statements = [c for c in body.named_children if c.type not in self.comment_types]
        return (len(statements) == 1 and statements[0].type == "return_statement"
                and self.text(statements[0]).replace(" ", "") == "returntrue;")

    def _args(self, arguments: Node | None) -> list[Node]:
        """Các argument của lời gọi (đã bỏ lớp bọc, bỏ comment)."""
        if arguments is None:
            return []
        return [self.unwrap(child) for child in arguments.named_children if child.type not in self.comment_types]


# --------------------------------------------------------------------------- Java


class JavaAdapter(TreeSitterAdapter):
    """Mô tả grammar tree-sitter-java."""

    language = JAVA
    comment_types = frozenset({"line_comment", "block_comment"})
    string_types = frozenset({"string_literal", "text_block"})
    literal_types = frozenset({
        "decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal",
        "decimal_floating_point_literal", "hex_floating_point_literal", "true", "false",
        "character_literal", "null_literal", "class_literal",
    })
    call_type = "method_invocation"
    constructor_types = frozenset({"object_creation_expression"})
    member_types = frozenset({"field_access"})
    element_types = frozenset({"array_access"})
    lambda_types = frozenset({"lambda_expression"})
    method_types = frozenset({"method_declaration", "constructor_declaration", "compact_constructor_declaration"})
    class_types = frozenset({"class_declaration", "interface_declaration", "enum_declaration", "record_declaration",
                             "class_body"})
    branch_types = frozenset({
        "if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement",
        "try_statement", "try_with_resources_statement", "catch_clause", "finally_clause",
        "switch_expression", "switch_block", "switch_block_statement_group", "switch_rule",
    })
    statement_types = frozenset({"block", "catch_clause", "finally_clause", "switch_block",
                                 "switch_block_statement_group", "switch_rule", "resource_specification",
                                 "local_variable_declaration", "resource"})
    ternary_types = frozenset({"ternary_expression"})
    wrapper_types = frozenset({"parenthesized_expression", "cast_expression"})

    def _grammar(self) -> Any:
        try:
            import tree_sitter_java
        except ImportError as exc:  # pragma: no cover
            raise LanguageUnavailable("tree-sitter-java is not installed") from exc
        return tree_sitter_java.language()

    def call_site(self, node: Node) -> CallSite | None:
        if node.type == "method_invocation":
            # obj.method(args) - "object" có thể vắng mặt với lời gọi method của chính class.
            receiver = node.child_by_field_name("object")
            return CallSite(
                node=node,
                method=self.text(node.child_by_field_name("name")),
                args=self._args(node.child_by_field_name("arguments")),
                receiver=receiver,
                receiver_text=normalize(self.text(receiver)) if receiver is not None else None,
            )
        if node.type == "object_creation_expression":
            # new T(args)
            return CallSite(
                node=node,
                method=simple_type(self.text(node.child_by_field_name("type"))) or "",
                args=self._args(node.child_by_field_name("arguments")),
                is_constructor=True,
            )
        return None

    def declarations(self, node: Node) -> list[Declaration] | None:
        if node.type in {"local_variable_declaration", "field_declaration", "constant_declaration"}:
            type_name = simple_type(self.text(node.child_by_field_name("type")))
            result = []
            # Một câu khai báo có thể có nhiều biến: String a = "x", b = y;
            for declarator in node.children_by_field_name("declarator"):
                name = declarator.child_by_field_name("name")
                result.append(Declaration(node=declarator, name=self.text(name), type=type_name,
                                          value=declarator.child_by_field_name("value"),
                                          is_field=node.type != "local_variable_declaration"))
            return result
        if node.type == "resource" and node.child_by_field_name("name") is not None:
            # try (Connection c = ds.getConnection()) { ... }
            return [Declaration(node=node, name=self.text(node.child_by_field_name("name")),
                                type=simple_type(self.text(node.child_by_field_name("type"))),
                                value=node.child_by_field_name("value"))]
        return None

    def method_info(self, node: Node) -> MethodInfo | None:
        if node.type not in self.method_types:
            return None
        params = []
        parameters = node.child_by_field_name("parameters")
        for param in (parameters.named_children if parameters is not None else []):
            if param.type not in {"formal_parameter", "spread_parameter"}:
                continue
            name = param.child_by_field_name("name")
            if name is None:  # spread_parameter (String... args): tên nằm trong variable_declarator
                declarator = next((c for c in param.named_children if c.type == "variable_declarator"), None)
                name = declarator.child_by_field_name("name") if declarator is not None else None
            # Tên các annotation của tham số, vd {"RequestParam"} cho @RequestParam("q") String q.
            annotations = frozenset(
                self.text(a.child_by_field_name("name"))
                for modifiers in param.named_children if modifiers.type == "modifiers"
                for a in modifiers.named_children if a.type in {"annotation", "marker_annotation"}
            )
            params.append(Parameter(self.text(name), simple_type(self.text(param.child_by_field_name("type"))),
                                    annotations))
        return MethodInfo(node, self.text(node.child_by_field_name("name")), params,
                          node.child_by_field_name("body"))

    def loop_binding(self, node: Node) -> tuple[str, Node] | None:
        # for (String item : items)
        if node.type == "enhanced_for_statement":
            return self.text(node.child_by_field_name("name")), node.child_by_field_name("value")
        return None

    def member_object(self, node: Node) -> Node | None:
        return node.child_by_field_name("object")

    def element_parts(self, node: Node) -> tuple[Node | None, list[Node]]:
        index = node.child_by_field_name("index")
        return node.child_by_field_name("array"), [index] if index is not None else []

    def array_elements(self, node: Node) -> list[Node] | None:
        """Các phần tử của ``new String[]{"sh", "-c", cmd}`` / ``{...}`` (dùng cho Runtime.exec)."""
        if node.type == "array_creation_expression":
            value = node.child_by_field_name("value")
            return self.array_elements(value) if value is not None else None
        if node.type == "array_initializer":
            return [self.unwrap(c) for c in node.named_children if c.type not in self.comment_types]
        return None


# --------------------------------------------------------------------------- C#


class CSharpAdapter(TreeSitterAdapter):
    """Mô tả grammar tree-sitter-c-sharp."""

    language = CSHARP
    comment_types = frozenset({"comment"})
    string_types = frozenset({"string_literal", "verbatim_string_literal", "raw_string_literal"})
    literal_types = frozenset({"integer_literal", "real_literal", "boolean_literal", "null_literal",
                               "character_literal"})
    interpolated_types = frozenset({"interpolated_string_expression"})
    call_type = "invocation_expression"
    constructor_types = frozenset({"object_creation_expression", "implicit_object_creation_expression"})
    member_types = frozenset({"member_access_expression"})
    element_types = frozenset({"element_access_expression"})
    lambda_types = frozenset({"lambda_expression", "anonymous_method_expression"})
    method_types = frozenset({"method_declaration", "constructor_declaration", "local_function_statement",
                              "operator_declaration"})
    class_types = frozenset({"class_declaration", "struct_declaration", "record_declaration",
                             "interface_declaration", "declaration_list"})
    branch_types = frozenset({
        "if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement",
        "try_statement", "catch_clause", "finally_clause", "switch_statement", "switch_section",
        "switch_expression",
    })
    statement_types = frozenset({"block", "catch_clause", "finally_clause", "switch_section", "switch_body",
                                 "variable_declaration", "arrow_expression_clause"})
    ternary_types = frozenset({"conditional_expression"})
    wrapper_types = frozenset({"parenthesized_expression", "cast_expression", "argument"})

    def _grammar(self) -> Any:
        try:
            import tree_sitter_c_sharp
        except ImportError as exc:  # pragma: no cover
            raise LanguageUnavailable("tree-sitter-c-sharp is not installed") from exc
        return tree_sitter_c_sharp.language()

    def string_value(self, node: Node) -> str | None:
        if node.type == "verbatim_string_literal":
            # @"C:\path" - bỏ @" ở đầu và " ở cuối; "" bên trong là một dấu nháy.
            return self.text(node)[2:-1].replace('""', '"')
        return super().string_value(node)

    def interpolation_values(self, node: Node) -> list[Node]:
        """Biểu thức trong mỗi {..} của $"..."; bỏ phần căn lề (,10) và định dạng (:N2)."""
        values = []
        for child in node.named_children:
            if child.type == "interpolation":
                expressions = [c for c in child.named_children if c.type not in {
                    "interpolation_brace", "interpolation_alignment_clause", "interpolation_format_clause"}]
                values.extend(expressions[:1])
        return values

    def call_site(self, node: Node) -> CallSite | None:
        if node.type == "invocation_expression":
            function = node.child_by_field_name("function")
            receiver, method = None, self.text(function)
            if function is not None and function.type == "member_access_expression":
                # obj.Method(args)
                receiver = function.child_by_field_name("expression")
                method = self.text(function.child_by_field_name("name"))
            method = re.sub(r"<.*>", "", method)  # method generic: Deserialize<T> -> Deserialize
            return CallSite(
                node=node, method=method, args=self._args(node.child_by_field_name("arguments")),
                receiver=receiver, receiver_text=normalize(self.text(receiver)) if receiver is not None else None,
            )
        if node.type in self.constructor_types:
            # new T(args) { Prop = value } hoặc new(args) (kiểu suy ra từ vế trái)
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                arguments = next((c for c in node.named_children if c.type == "argument_list"), None)
            initializer = node.child_by_field_name("initializer") or next(
                (c for c in node.named_children if c.type == "initializer_expression"), None)
            # Ghi lại các "Prop = value" của object initializer, vd FileName = cmd trong ProcessStartInfo.
            members: dict[str, Node] = {}
            for assignment in (initializer.named_children if initializer is not None else []):
                if assignment.type == "assignment_expression":
                    members[self.text(assignment.child_by_field_name("left"))] = assignment.child_by_field_name("right")
            return CallSite(
                node=node, method=simple_type(self.text(node.child_by_field_name("type"))) or "",
                args=self._args(arguments), is_constructor=True, initializer=members,
            )
        return None

    def declarations(self, node: Node) -> list[Declaration] | None:
        if node.type == "variable_declaration":
            type_name = simple_type(self.text(node.child_by_field_name("type")))
            is_field = node.parent is not None and node.parent.type in {"field_declaration", "event_field_declaration"}
            result = []
            for declarator in (c for c in node.named_children if c.type == "variable_declarator"):
                name = declarator.child_by_field_name("name")
                # So sánh theo id: tree-sitter trả về một đối tượng Python mới mỗi lần truy cập.
                name_id = name.id if name is not None else None
                # Giá trị khởi tạo là node con còn lại (không phải tên, không phải comment).
                value = next((c for c in declarator.named_children if c.id != name_id and c.type not in
                              {"bracketed_argument_list"} | self.comment_types), None)
                # Một số phiên bản grammar bọc giá trị trong equals_value_clause (= value).
                if value is not None and value.type == "equals_value_clause":
                    value = value.named_children[0] if value.named_children else None
                result.append(Declaration(node=declarator, name=self.text(name), type=type_name, value=value,
                                          is_field=is_field))
            return result
        if node.type == "property_declaration" and node.child_by_field_name("value") is not None:
            # public string Password { get; set; } = "secret";
            return [Declaration(node=node, name=self.text(node.child_by_field_name("name")),
                                type=simple_type(self.text(node.child_by_field_name("type"))),
                                value=node.child_by_field_name("value"), is_field=True)]
        return None

    def method_info(self, node: Node) -> MethodInfo | None:
        if node.type not in self.method_types:
            return None
        params = []
        parameters = node.child_by_field_name("parameters")
        for param in (parameters.named_children if parameters is not None else []):
            if param.type != "parameter":
                continue
            # Attribute của tham số, vd [FromQuery] string q -> {"FromQuery"}.
            # [FromQueryAttribute] và [FromQuery] là một, nên bỏ hậu tố "Attribute".
            annotations = frozenset(
                self.text(attribute.child_by_field_name("name")).removesuffix("Attribute")
                for attribute_list in param.named_children if attribute_list.type == "attribute_list"
                for attribute in attribute_list.named_children if attribute.type == "attribute"
            )
            params.append(Parameter(self.text(param.child_by_field_name("name")),
                                    simple_type(self.text(param.child_by_field_name("type"))), annotations))
        return MethodInfo(node, self.text(node.child_by_field_name("name")), params,
                          node.child_by_field_name("body"))

    def loop_binding(self, node: Node) -> tuple[str, Node] | None:
        # foreach (var item in items)
        if node.type == "foreach_statement":
            return self.text(node.child_by_field_name("left")), node.child_by_field_name("right")
        return None

    def member_object(self, node: Node) -> Node | None:
        return node.child_by_field_name("expression")

    def element_parts(self, node: Node) -> tuple[Node | None, list[Node]]:
        subscript = node.child_by_field_name("subscript")
        return node.child_by_field_name("expression"), self._args(subscript)

    def array_elements(self, node: Node) -> list[Node] | None:
        """Các phần tử của new[] { ... } / new string[] { ... } / [ ... ] (collection expression)."""
        if node.type in {"array_creation_expression", "implicit_array_creation_expression"}:
            initializer = next((c for c in node.named_children if c.type == "initializer_expression"), None)
            return self._args(initializer) if initializer is not None else None
        if node.type in {"initializer_expression", "collection_expression"}:
            return self._args(node)
        return None


@lru_cache(maxsize=None)
def get_adapter(language: str) -> TreeSitterAdapter:
    """Mỗi ngôn ngữ một adapter (và một parser), tạo ở lần dùng đầu tiên rồi dùng lại (cache)."""
    if language == JAVA:
        return JavaAdapter()
    if language == CSHARP:
        return CSharpAdapter()
    raise ValueError(f"No tree-sitter adapter for {language}")
