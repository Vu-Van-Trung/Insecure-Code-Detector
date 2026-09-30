"""Per-file context for Java/C# rules (the tree-sitter counterpart of AnalysisContext)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.analyzer.ts.adapters import CallSite, Declaration, MethodInfo, TreeSitterAdapter, normalize, simple_type

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node

    from app.analyzer.ts.taint import TSTaintResult

MODULE_SCOPE = 0  # scope id used for class-level code (fields)


@dataclass
class Assignment:
    node: Node
    target: str        # normalized text of the left side: x, this.x, cmd.CommandText
    value: Node
    augmented: bool    # +=, -= ...
    scope: int


@dataclass
class TSContext:
    filename: str
    language: str
    source_lines: list[str]
    root: Node
    adapter: TreeSitterAdapter
    calls: list[CallSite] = field(default_factory=list)
    methods: list[MethodInfo] = field(default_factory=list)
    declarations: list[Declaration] = field(default_factory=list)
    assignments: list[Assignment] = field(default_factory=list)
    strings: list[Node] = field(default_factory=list)
    lambdas: list[Node] = field(default_factory=list)
    call_by_node: dict[int, CallSite] = field(default_factory=dict)
    scope_of_node: dict[int, int] = field(default_factory=dict)     # node id -> enclosing method id
    method_by_id: dict[int, MethodInfo] = field(default_factory=dict)
    var_types: dict[int, dict[str, str]] = field(default_factory=dict)  # scope -> name -> type
    var_values: dict[int, dict[str, Node]] = field(default_factory=dict)  # scope -> name -> initializer
    taint: TSTaintResult | None = None

    # ------------------------------------------------------------------ building

    @classmethod
    def build(cls, filename: str, source: str, root: Node, adapter: TreeSitterAdapter) -> TSContext:
        ctx = cls(filename=filename, language=adapter.language, source_lines=source.splitlines(),
                  root=root, adapter=adapter)
        ctx._collect()
        ctx._resolve_receiver_types()
        return ctx

    def _collect(self) -> None:
        adapter = self.adapter
        stack: list[tuple[Node, int]] = [(self.root, MODULE_SCOPE)]
        while stack:
            node, scope = stack.pop()
            info = adapter.method_info(node)
            if info is not None:
                scope = node.id
                self.methods.append(info)
                self.method_by_id[scope] = info
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
                    decl_scope = MODULE_SCOPE if declaration.is_field else scope
                    value_type = self._creation_type(declaration.value)
                    if value_type or declaration.type:
                        self.var_types.setdefault(decl_scope, {})[declaration.name] = value_type or declaration.type
                    if declaration.value is not None:
                        self.var_values.setdefault(decl_scope, {})[declaration.name] = declaration.value
            if node.type == adapter.assignment_type and node.parent is not None \
                    and node.parent.type != "initializer_expression":
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                if left is not None and right is not None:
                    self.assignments.append(Assignment(node, normalize(adapter.text(left)), right,
                                                       adapter.operator(node) != "=", scope))
            if adapter.is_string(node):
                self.strings.append(node)
            if node.type in adapter.lambda_types:
                self.lambdas.append(node)
            stack.extend((child, scope) for child in reversed(node.named_children))
        self.calls.sort(key=lambda call: call.node.start_byte)

    def _creation_type(self, value: Node | None) -> str | None:
        if value is None:
            return None
        call = self.adapter.call_site(self.adapter.unwrap(value))
        return call.method if call is not None and call.is_constructor else None

    def _resolve_receiver_types(self) -> None:
        for call in self.calls:
            if call.receiver is not None and not call.is_constructor:
                call.receiver_type = self.type_of(call.receiver)

    # ------------------------------------------------------------------ queries

    def type_of(self, node: Node) -> str | None:
        """Best-effort static type of an expression (declared type, ``new T()``, ``T.factory()``)."""
        node = self.adapter.unwrap(node)
        text = self.adapter.text(node)
        if node.type == "identifier":
            scope = self.scope_of_node.get(node.id, MODULE_SCOPE)
            for types in (self.var_types.get(scope, {}), self.var_types.get(MODULE_SCOPE, {})):
                if text in types:
                    return types[text]
            # Unknown identifier starting with an upper-case letter: a class (static call).
            return text if text[:1].isupper() else None
        call = self.call_by_node.get(node.id)
        if call is not None:
            if call.is_constructor:
                return call.method
            # Static factory on a class: Runtime.getRuntime(), MD5.Create(), MessageDigest.getInstance()
            receiver = call.receiver
            if receiver is not None and receiver.type == "identifier" and self.adapter.text(receiver)[:1].isupper():
                return self.adapter.text(receiver)
            return None
        if node.type in self.adapter.member_types:
            return simple_type(text) if text[:1].isupper() else None
        return None

    def get_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def scope(self, node: Node) -> int:
        current: Node | None = node
        while current is not None:
            if current.id in self.scope_of_node:
                return self.scope_of_node[current.id]
            current = current.parent
        return MODULE_SCOPE

    def enclosing_method_name(self, node: Node) -> str | None:
        info = self.method_by_id.get(self.scope(node))
        return info.name if info else None

    def initializer_of(self, name: str, node: Node) -> Node | None:
        """Initial value of variable ``name`` visible from ``node`` (same method, then fields)."""
        return self.var_values.get(self.scope(node), {}).get(name) or self.var_values.get(MODULE_SCOPE, {}).get(name)

    def assignments_before(self, name: str, node: Node) -> list[tuple[int, Node, bool]]:
        """(line, value, augmented) of declarations/assignments of ``name`` before ``node`` in the same method."""
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
        """Variable/field/property receiving the value of ``node`` (walks up to the statement)."""
        current = node.parent
        while current is not None and not self.adapter.is_statement(current):
            if current.type == "variable_declarator":
                return self.adapter.text(current.child_by_field_name("name"))
            if current.type == self.adapter.assignment_type:
                return self.adapter.text(current.child_by_field_name("left")).rsplit(".", 1)[-1]
            current = current.parent
        return None
