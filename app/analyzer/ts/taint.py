"""Basic intra-procedural taint tracking for Java and C#.

Same model as the Python analyzer (app/analyzer/taint.py): every expression of
a method gets a label TaintInfo (untrusted), STATIC (literal) or None
(unknown); assignments inside if/for/while/try only add taint.

Sources (configurable per language in app/config/taint_<language>.json):

* calls:        request.getParameter(), Console.ReadLine(), System.getenv() ...
* members:      Request.Query, Request.Form, request.getParameterMap ...
* parameters:   annotated with @RequestParam / [FromQuery] ..., and ``args`` of main()

Limitations: no inter-procedural analysis; fields are only seeded with their
constant initial values; sanitizers reduce confidence but are never trusted.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.analyzer.taint import STATIC, Label, TaintInfo, combine, join, taint_only
from app.analyzer.ts.adapters import normalize
from app.analyzer.ts.context import TSContext
from app.config.loader import CONFIG_DIR, ConfigError, get_string_list, load_json

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node

_COMPARISON_OPERATORS = frozenset({"==", "!=", "<", ">", "<=", ">=", "&&", "||", "instanceof", "is", "as", "??"})


@dataclass(frozen=True)
class TSTaintConfig:
    source_calls: frozenset[str] = frozenset()
    source_members: frozenset[str] = frozenset()
    source_annotations: frozenset[str] = frozenset()
    main_args: bool = True
    sanitizers: frozenset[str] = frozenset()

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "taint configuration") -> TSTaintConfig:
        sources = data.get("sources", {})
        if not isinstance(sources, dict):
            raise ConfigError(f"'sources' in {where} must be an object")
        main_args = sources.get("main_args", True)
        if not isinstance(main_args, bool):
            raise ConfigError(f"'main_args' in {where} must be true or false")
        return cls(
            source_calls=frozenset(get_string_list(sources, "calls", where)),
            source_members=frozenset(get_string_list(sources, "members", where)),
            source_annotations=frozenset(get_string_list(sources, "parameter_annotations", where)),
            main_args=main_args,
            sanitizers=frozenset(get_string_list(data, "sanitizers", where)),
        )

    @classmethod
    def load(cls, path: Path) -> TSTaintConfig:
        return cls.from_dict(load_json(path), str(path))

    @classmethod
    def load_default(cls, language: str) -> TSTaintConfig:
        return cls.load(CONFIG_DIR / f"taint_{language}.json")


@dataclass
class TSTaintResult:
    """Labels keyed by tree-sitter node id; same interface as TaintResult."""

    ctx: TSContext
    labels: dict[int, Label] = field(default_factory=dict)

    def lookup(self, node: Node | None) -> TaintInfo | None:
        if node is None:
            return None
        label = self.labels.get(self.ctx.adapter.unwrap(node).id)
        return label if isinstance(label, TaintInfo) else None

    def is_static(self, node: Node | None) -> bool:
        if node is None:
            return False
        node = self.ctx.adapter.unwrap(node)
        if node.id in self.labels:
            return self.labels[node.id] is STATIC
        return self.ctx.adapter.is_static(node)


class TSTaintAnalyzer:
    def __init__(self, ctx: TSContext, config: TSTaintConfig) -> None:
        self.ctx = ctx
        self.adapter = ctx.adapter
        self.config = config
        self.result = TSTaintResult(ctx)
        self.state: dict[str, Label] = {}

    def analyze(self) -> TSTaintResult:
        # Class fields: only literal initial values are kept (constants).
        seed: dict[str, Label] = {}
        for declaration in self.ctx.declarations:
            if declaration.is_field and declaration.value is not None:
                self.state = {}
                label = self.eval(declaration.value)
                seed[declaration.name] = label if label is STATIC else None
        for method in self.ctx.methods:
            self.state = dict(seed)
            for param in method.params:
                self.state.pop(param.name, None)
                source = self._parameter_source(method.name, param)
                if source:
                    self.state[param.name] = TaintInfo(source=source, path=(source, param.name))
            if method.body is not None:
                self._run(method.body, in_branch=False)
        return self.result

    def _parameter_source(self, method_name: str, param: Any) -> str | None:
        matched = param.annotations & self.config.source_annotations
        if matched:
            marker = "@" if self.ctx.language == "java" else ""
            return f"{marker}{sorted(matched)[0]}" if marker else f"[{sorted(matched)[0]}]"
        if self.config.main_args and method_name.lower() == "main" and param.name == "args":
            return "args (command line)"
        return None

    # ------------------------------------------------------------------ statements

    def _run(self, node: Node, in_branch: bool) -> None:
        adapter = self.adapter
        if node.type in adapter.comment_types:
            return
        if node.type in adapter.lambda_types or adapter.method_info(node) is not None \
                or node.type in adapter.class_types:
            return  # analyzed as its own scope (or not at all for lambdas)
        declarations = adapter.declarations(node)
        if declarations is not None:
            for declaration in declarations:
                label = self.eval(declaration.value) if declaration.value is not None else None
                self._bind(declaration.name, label, in_branch)
            return
        if node.type == adapter.assignment_type:
            self._assign(node, in_branch)
            return
        loop = adapter.loop_binding(node)
        if loop is not None:
            name, iterable = loop
            if iterable is not None:
                self._bind(name, taint_only(self.eval(iterable)), in_branch=True)
            body = node.child_by_field_name("body")
            if body is not None:
                self._run(body, in_branch=True)
            return
        if node.type == "expression_statement":
            for child in node.named_children:
                if child.type == adapter.assignment_type:
                    self._assign(child, in_branch)
                else:
                    self.eval(child)
            return
        if adapter.is_statement(node) or node.type in adapter.branch_types:
            branch = in_branch or node.type in adapter.branch_types
            for child in node.named_children:
                if adapter.is_statement(child) or child.type in adapter.branch_types \
                        or adapter.declarations(child) is not None:
                    self._run(child, branch)
                else:
                    self.eval(child)
            return
        self.eval(node)

    def _assign(self, node: Node, in_branch: bool) -> None:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None:
            return
        value = self.eval(right)
        key = self._key(left)
        if key is None:
            return
        if self.adapter.operator(node) != "=":
            value = combine([self.state.get(key), value])
        if left.type in self.adapter.element_types:
            # d[k] = tainted -> the whole container is tainted.
            if isinstance(value, TaintInfo):
                self.state[key] = join(self.state.get(key), value.through(key))
            return
        self._bind(key, value, in_branch)

    def _key(self, target: Node) -> str | None:
        target = self.adapter.unwrap(target)
        if target.type in self.adapter.element_types:
            base, _ = self.adapter.element_parts(target)
            return self._key(base) if base is not None else None
        text = normalize(self.adapter.text(target))
        return text.removeprefix("this.") if text else None

    def _bind(self, name: str, label: Label, in_branch: bool) -> None:
        new = label.through(name) if isinstance(label, TaintInfo) else label
        self.state[name] = join(self.state.get(name), new) if in_branch else new

    # ------------------------------------------------------------------ expressions

    def eval(self, node: Node) -> Label:
        label = self._eval(node)
        self.result.labels[node.id] = label
        return label

    def _eval(self, node: Node) -> Label:
        adapter = self.adapter
        kind = node.type
        if kind in adapter.string_types or kind in adapter.literal_types:
            return STATIC
        if kind in adapter.interpolated_types:
            return combine([STATIC, *(self.eval(value) for value in adapter.interpolation_values(node))])
        if kind == "identifier":
            return self.state.get(adapter.text(node))
        if kind in {"this", "this_expression", "base_expression", "super"}:
            return None
        if kind in adapter.member_types:
            return self._eval_member(node)
        if kind in adapter.element_types:
            base, indexes = adapter.element_parts(node)
            base_label = self.eval(base) if base is not None else None
            index_labels = [self.eval(index) for index in indexes]
            if isinstance(base_label, TaintInfo):
                return base_label
            return STATIC if base_label is STATIC and all(i is STATIC for i in index_labels) else None
        call = self.ctx.call_by_node.get(node.id)
        if call is not None:
            return self._eval_call(call)
        if kind == adapter.binary_type:
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            labels = [self.eval(side) for side in (left, right) if side is not None]
            operator = adapter.operator(node)
            if operator in _COMPARISON_OPERATORS:
                return None
            return combine(labels) if operator == "+" else taint_only(combine(labels))
        if kind in adapter.ternary_types:
            condition = node.child_by_field_name("condition")
            if condition is not None:
                self.eval(condition)
            branches = [node.child_by_field_name(name) for name in ("consequence", "alternative")]
            return combine([self.eval(branch) for branch in branches if branch is not None])
        if kind in adapter.wrapper_types:
            inner = adapter.unwrap(node)
            return self.eval(inner) if inner.id != node.id else None
        if kind in adapter.lambda_types:
            return None
        if kind == adapter.assignment_type:
            self._assign(node, in_branch=True)
            return None
        children = [child for child in node.named_children if child.type not in adapter.comment_types]
        return taint_only(combine([self.eval(child) for child in children]))

    def _eval_member(self, node: Node) -> Label:
        text = normalize(self.adapter.text(node))
        source = self._member_source(text)
        if source:
            return TaintInfo(source=source, path=(source,))
        key = text.removeprefix("this.")
        if key in self.state:
            return self.state[key]
        obj = self.adapter.member_object(node)
        label = self.eval(obj) if obj is not None else None
        return label if isinstance(label, TaintInfo) else None

    def _member_source(self, text: str) -> str | None:
        for member in self.config.source_members:
            if text == member or text.endswith("." + member):
                return member
        return None

    def _eval_call(self, call: Any) -> Label:
        receiver = self.eval(call.receiver) if call.receiver is not None else None
        arguments = [self.eval(arg) for arg in call.args]
        arguments += [self.eval(value) for value in call.initializer.values()]
        if call.names & self.config.source_calls:
            label = f"{call.receiver_text}.{call.method}()" if call.receiver_text else f"{call.method}()"
            return TaintInfo(source=label, path=(label,))
        sanitizer = next(iter(sorted(call.names & self.config.sanitizers)), None)
        if sanitizer:
            data = combine(arguments)
            if isinstance(data, TaintInfo):
                return replace(data.through(f"{sanitizer}()"), sanitizer=sanitizer)
            return None
        # Unknown call: taint of the receiver or arguments flows into the result.
        return taint_only(combine([receiver, *arguments]))


def analyze_ts_taint(ctx: TSContext, config: TSTaintConfig) -> TSTaintResult:
    return TSTaintAnalyzer(ctx, config).analyze()
