"""Taint tracking cơ bản trong phạm vi một method (intra-procedural) cho Java và C#.

Cùng mô hình với analyzer Python (app/analyzer/taint.py): mỗi biểu thức trong
method nhận nhãn TaintInfo (không tin cậy), STATIC (hằng số) hoặc None (không
rõ); phép gán trong if/for/while/try chỉ THÊM taint.

Source (cấu hình riêng cho từng ngôn ngữ trong app/config/taint_<language>.json):

* lời gọi:      request.getParameter(), Console.ReadLine(), System.getenv() ...
* thuộc tính:   Request.Query, Request.Form, request.getParameterMap ...
* tham số:      có annotation @RequestParam / [FromQuery] ..., và ``args`` của main()

Hạn chế: không phân tích liên hàm; field chỉ được khởi tạo với giá trị hằng
ban đầu; sanitizer làm giảm confidence nhưng không bao giờ được tin hoàn toàn.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Dùng lại nhãn và các phép gộp của analyzer Python để hai bên chấm điểm giống nhau.
from app.analyzer.taint import STATIC, Label, TaintInfo, combine, join, taint_only
from app.analyzer.ts.adapters import normalize
from app.analyzer.ts.context import TSContext
from app.config.loader import CONFIG_DIR, ConfigError, get_string_list, load_json

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node

# Toán tử cho ra kết quả boolean/kiểu (không phải văn bản do kẻ tấn công kiểm soát).
_COMPARISON_OPERATORS = frozenset({"==", "!=", "<", ">", "<=", ">=", "&&", "||", "instanceof", "is", "as", "??",
                                   "===", "!==", "<>", "<=>", "and", "or", "xor"})


@dataclass(frozen=True)
class TSTaintConfig:
    """Cấu hình taint của một ngôn ngữ (Java hoặc C#)."""

    source_calls: frozenset[str] = frozenset()        # vd "request.getParameter"
    source_members: frozenset[str] = frozenset()      # vd "Request.Query"
    source_variables: frozenset[str] = frozenset()    # vd "$_GET" (biến toàn cục của PHP)
    source_annotations: frozenset[str] = frozenset()  # vd "RequestParam", "FromQuery"
    main_args: bool = True                            # coi args của main() là source
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
            source_variables=frozenset(get_string_list(sources, "variables", where)),
            source_annotations=frozenset(get_string_list(sources, "parameter_annotations", where)),
            main_args=main_args,
            sanitizers=frozenset(get_string_list(data, "sanitizers", where)),
        )

    @classmethod
    def load(cls, path: Path) -> TSTaintConfig:
        return cls.from_dict(load_json(path), str(path))

    @classmethod
    def load_default(cls, language: str) -> TSTaintConfig:
        """Nạp file cấu hình mặc định, vd taint_java.json."""
        return cls.load(CONFIG_DIR / f"taint_{language}.json")


@dataclass
class TSTaintResult:
    """Nhãn theo id node của tree-sitter; giao diện giống TaintResult của Python.

    Nhờ cùng giao diện (lookup / is_static), các hàm chấm điểm trong rules/base.py
    dùng chung được cho cả ba ngôn ngữ.
    """

    ctx: TSContext
    # Dùng node.id (số nguyên) làm khóa vì đối tượng Node của tree-sitter được tạo mới mỗi lần truy cập.
    labels: dict[int, Label] = field(default_factory=dict)

    def lookup(self, node: Node | None) -> TaintInfo | None:
        if node is None:
            return None
        # unwrap bỏ lớp ngoặc / ép kiểu, vd (String) x -> x.
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
    """Tính nhãn cho mọi biểu thức của các method trong một file Java/C#."""

    def __init__(self, ctx: TSContext, config: TSTaintConfig) -> None:
        self.ctx = ctx
        self.adapter = ctx.adapter
        self.config = config
        self.result = TSTaintResult(ctx)
        # Tên biến -> nhãn hiện tại trong method đang phân tích.
        self.state: dict[str, Label] = {}

    def analyze(self) -> TSTaintResult:
        # Field của class: chỉ giữ giá trị khởi tạo là hằng số (hằng của class).
        seed: dict[str, Label] = {}
        for declaration in self.ctx.declarations:
            if declaration.is_field and declaration.value is not None:
                self.state = {}
                label = self.eval(declaration.value)
                seed[declaration.name] = label if label is STATIC else None
        # Biến toàn cục chứa dữ liệu request ($_GET, $_POST...): nhìn thấy ở mọi nơi.
        for name in self.config.source_variables:
            seed[name] = TaintInfo(source=name, path=(name,))
        if self.adapter.top_level_code:
            # Script PHP: code nằm ngay cấp file (ngoài mọi hàm) cũng được chạy.
            self.state = dict(seed)
            for child in self.ctx.root.named_children:
                self._run(child, in_branch=False)
        for method in self.ctx.methods:
            self.state = dict(seed)
            for param in method.params:
                # Tham số che field cùng tên; mặc định không rõ nguồn...
                self.state.pop(param.name, None)
                # ...trừ khi là tham số nhận dữ liệu từ request (@RequestParam, [FromQuery]...).
                source = self._parameter_source(method.name, param)
                if source:
                    self.state[param.name] = TaintInfo(source=source, path=(source, param.name))
            if method.body is not None:
                self._run(method.body, in_branch=False)
        return self.result

    def _parameter_source(self, method_name: str, param: Any) -> str | None:
        """Tên source nếu tham số nhận dữ liệu không tin cậy, ngược lại None."""
        matched = param.annotations & self.config.source_annotations
        if matched:
            # Hiển thị đúng cú pháp từng ngôn ngữ: @RequestParam (Java) / [FromQuery] (C#).
            marker = "@" if self.ctx.language == "java" else ""
            return f"{marker}{sorted(matched)[0]}" if marker else f"[{sorted(matched)[0]}]"
        if self.config.main_args and method_name.lower() == "main" and param.name == "args":
            return "args (command line)"
        return None

    # ------------------------------------------------------------------ câu lệnh

    def _run(self, node: Node, in_branch: bool) -> None:
        """Cập nhật state theo một câu lệnh (đệ quy vào các khối lồng bên trong)."""
        adapter = self.adapter
        if node.type in adapter.comment_types:
            return
        if node.type in adapter.lambda_types or adapter.method_info(node) is not None \
                or node.type in adapter.class_types:
            return  # được phân tích như scope riêng (lambda thì không phân tích)
        declarations = adapter.declarations(node)
        if declarations is not None:
            # String x = ..., y = ...;
            for declaration in declarations:
                label = self.eval(declaration.value) if declaration.value is not None else None
                self._bind(declaration.name, label, in_branch)
            return
        if node.type in adapter.assignment_types:
            self._assign(node, in_branch)
            return
        loop = adapter.loop_binding(node)
        if loop is not None:
            # for (String x : items) / foreach (var x in items): x nhận taint của items.
            name, iterable = loop
            if iterable is not None:
                self._bind(name, taint_only(self.eval(iterable)), in_branch=True)
            body = node.child_by_field_name("body")
            if body is not None:
                self._run(body, in_branch=True)
            return
        if node.type == "expression_statement":
            for child in node.named_children:
                if child.type in adapter.assignment_types:
                    self._assign(child, in_branch)
                else:
                    self.eval(child)
            return
        if adapter.is_statement(node) or node.type in adapter.branch_types:
            # if/while/try...: khối con là nhánh có điều kiện; biểu thức (điều kiện...) được đánh giá.
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
        """Xử lý phép gán ``left = right`` (kể cả ``+=``)."""
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None:
            return
        value = self.eval(right)
        key = self._key(left)
        if key is None:
            return
        if self.adapter.operator(node) != "=":
            # x += y  ==  x = x + y
            value = combine([self.state.get(key), value])
        if left.type in self.adapter.element_types:
            # d[k] = tainted -> cả container bị taint.
            if isinstance(value, TaintInfo):
                self.state[key] = join(self.state.get(key), value.through(key))
            return
        self._bind(key, value, in_branch)

    def _key(self, target: Node) -> str | None:
        """Tên được theo dõi của vế trái: x, field (bỏ "this."), hoặc container của a[i]."""
        target = self.adapter.unwrap(target)
        if target.type in self.adapter.element_types:
            base, _ = self.adapter.element_parts(target)
            return self._key(base) if base is not None else None
        text = normalize(self.adapter.text(target))
        return text.removeprefix(self.adapter.this_prefix) if text else None

    def _bind(self, name: str, label: Label, in_branch: bool) -> None:
        """Gán nhãn cho biến; trong nhánh thì gộp với giá trị cũ thay vì ghi đè."""
        new = label.through(name) if isinstance(label, TaintInfo) else label
        self.state[name] = join(self.state.get(name), new) if in_branch else new

    # ------------------------------------------------------------------ biểu thức

    def eval(self, node: Node) -> Label:
        """Nhãn của một biểu thức; kết quả được lưu theo node.id để rule tra cứu."""
        label = self._eval(node)
        self.result.labels[node.id] = label
        return label

    def _eval(self, node: Node) -> Label:
        adapter = self.adapter
        kind = node.type
        if kind in adapter.string_types or kind in adapter.literal_types:
            return STATIC
        if kind in adapter.interpolated_types:
            # $"SELECT ... {id}" (C#): phần chữ là STATIC, phần {..} theo nhãn của biểu thức.
            return combine([STATIC, *(self.eval(value) for value in adapter.interpolation_values(node))])
        if kind in adapter.identifier_types:
            return self.state.get(adapter.text(node))
        if kind in {"this", "this_expression", "base_expression", "super"}:
            return None
        cast = adapter.sanitizing_cast(node)
        if cast:
            # (int) $x: kết quả là một con số, giống lời gọi sanitizer intval($x).
            data = taint_only(combine([self.eval(child) for child in node.named_children]))
            return replace(data.through(cast), sanitizer=cast) if isinstance(data, TaintInfo) else None
        if kind in adapter.member_types:
            return self._eval_member(node)
        if kind in adapter.element_types:
            # a[i]: phần tử của dữ liệu tainted là tainted.
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
            # Chỉ phép "+" (nối chuỗi) mới có thể cho ra hằng số từ hai hằng số mà ta quan tâm;
            # phép toán khác (-, *, ...) chỉ giữ taint.
            return combine(labels) if operator in adapter.concat_operators else taint_only(combine(labels))
        if kind in adapter.ternary_types:
            # cond ? a : b - có thể là a hoặc b.
            condition = node.child_by_field_name("condition")
            if condition is not None:
                self.eval(condition)
            branches = [node.child_by_field_name(name) for name in adapter.ternary_fields]
            return combine([self.eval(branch) for branch in branches if branch is not None])
        if kind in adapter.wrapper_types:
            # Ngoặc, ép kiểu...: nhãn của biểu thức bên trong.
            inner = adapter.unwrap(node)
            return self.eval(inner) if inner.id != node.id else None
        if kind in adapter.lambda_types:
            return None
        if kind in adapter.assignment_types:
            # Phép gán dùng như biểu thức, vd while ((line = reader.readLine()) != null).
            self._assign(node, in_branch=True)
            return None
        # Mọi loại node khác: gộp nhãn của các node con (chỉ giữ taint).
        children = [child for child in node.named_children if child.type not in adapter.comment_types]
        return taint_only(combine([self.eval(child) for child in children]))

    def _eval_member(self, node: Node) -> Label:
        """obj.field: có thể là source (Request.Query), biến đã gán (this.cmd), hoặc thuộc tính của dữ liệu tainted."""
        text = normalize(self.adapter.text(node))
        source = self._member_source(text)
        if source:
            return TaintInfo(source=source, path=(source,))
        key = text.removeprefix(self.adapter.this_prefix)
        if key in self.state:
            return self.state[key]
        obj = self.adapter.member_object(node)
        label = self.eval(obj) if obj is not None else None
        return label if isinstance(label, TaintInfo) else None

    def _member_source(self, text: str) -> str | None:
        """Khớp chính xác hoặc khớp phần đuôi (HttpContext.Request.Query khớp "Request.Query")."""
        for member in self.config.source_members:
            if text == member or text.endswith("." + member):
                return member
        return None

    def _eval_call(self, call: Any) -> Label:
        """Nhãn kết quả lời gọi: source, sanitizer, hoặc lan truyền taint từ receiver/argument."""
        receiver = self.eval(call.receiver) if call.receiver is not None else None
        arguments = [self.eval(arg) for arg in call.args]
        # Giá trị trong object initializer của C# (new T { Prop = value }) cũng là "đầu vào".
        arguments += [self.eval(value) for value in call.initializer.values()]
        if call.names & self.config.source_calls:
            label = f"{call.receiver_text}.{call.method}()" if call.receiver_text else f"{call.method}()"
            return TaintInfo(source=label, path=(label,))
        # sorted() để chọn sanitizer ổn định nếu tên lời gọi khớp nhiều mục.
        sanitizer = next(iter(sorted(call.names & self.config.sanitizers)), None)
        if sanitizer:
            data = combine(arguments)
            if isinstance(data, TaintInfo):
                return replace(data.through(f"{sanitizer}()"), sanitizer=sanitizer)
            return None
        # Lời gọi không biết: taint của receiver hoặc argument chảy vào kết quả.
        return taint_only(combine([receiver, *arguments]))


def analyze_ts_taint(ctx: TSContext, config: TSTaintConfig) -> TSTaintResult:
    """Điểm vào: tính nhãn taint cho mọi biểu thức của một file Java/C#."""
    return TSTaintAnalyzer(ctx, config).analyze()
