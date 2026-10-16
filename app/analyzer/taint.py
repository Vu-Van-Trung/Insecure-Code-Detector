"""Bounded, call-context-sensitive taint analysis for Python.

Ý tưởng: theo dõi dữ liệu từ NGUỒN không tin cậy (source, vd ``input()``) đi qua
các biến tới chỗ NGUY HIỂM (sink, vd ``os.system()``). Nếu dữ liệu tới được sink
thì lỗ hổng gần như chắc chắn có thật -> severity CRITICAL, confidence 0.95.

Mỗi biểu thức được đánh giá trong một scope (module, thân class hoặc hàm) nhận
một trong ba nhãn:

* ``TaintInfo`` - giá trị có thể chứa dữ liệu từ một *source* không tin cậy
  (``input()``, ``request.args``, ``sys.argv``...); lưu lại source và các biến
  mà dữ liệu đã đi qua (taint path);
* ``STATIC``    - giá trị cố định trong mã nguồn (hằng số và biến chứa hằng số);
* ``None``      - không rõ (tham số hàm, kết quả của lời gọi hàm bất kỳ...).

Sau đó rule tra nhãn của argument đi vào sink để quyết định mức độ nghiêm trọng.

Hạn chế (prototype, được ghi rõ có chủ đích):

* local named functions support argument/return propagation; dynamic dispatch
  and cross-file calls use conservative argument propagation;
* recursion is bounded to 32 active functions and 2000 expansions per file;
* nhánh rẽ được gộp bảo thủ: phép gán trong ``if``/``for``/``while``/``try``
  có thể THÊM taint nhưng không bao giờ XÓA taint;
* container được theo dõi như một khối (``d["a"] = tainted`` làm cả ``d`` bị taint).

BẢO MẬT: sanitizer chỉ *giảm* confidence. Analyzer không chứng minh được một
sanitizer phù hợp với sink cụ thể (``shlex.quote`` không chống được SQL
injection), nên luồng đã sanitize vẫn được báo với severity thấp.
Sanitizer theo loại sink (``sink_sanitizers`` trong taint.json, vd
``os.path.basename`` cho đường dẫn file) thì khác: nó chỉ làm sạch dữ liệu cho
ĐÚNG MỘT loại sink, mọi sink khác vẫn thấy dữ liệu là tainted.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace
from functools import reduce
from pathlib import Path
from typing import Any, Final

from app.analyzer.utils import get_dotted_name, is_static_value, resolve_name
from app.config.loader import CONFIG_DIR, ConfigError, get_string_list, load_json

DEFAULT_TAINT_CONFIG = CONFIG_DIR / "taint.json"


# --------------------------------------------------------------------------- cấu hình


@dataclass(frozen=True)
class TaintConfig:
    """Cấu hình taint của Python, đọc từ app/config/taint.json."""

    # Hàm trả về dữ liệu không tin cậy, vd "input", "request.get_json".
    source_functions: frozenset[str]
    # Thuộc tính chứa dữ liệu không tin cậy, vd "request.args", "sys.argv".
    source_attributes: frozenset[str]
    # Hàm làm sạch chung, vd "shlex.quote", "int".
    sanitizers: frozenset[str]
    # Loại sink (path, html, url...) -> các hàm chỉ làm sạch dữ liệu cho loại sink đó.
    # hash=False: dict không băm được, loại khỏi __hash__ của dataclass frozen.
    sink_sanitizers: dict[str, frozenset[str]] = field(default_factory=dict, hash=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "taint configuration") -> TaintConfig:
        """Tạo cấu hình từ dict JSON, kiểm tra kiểu của từng mục."""
        sources = data.get("sources", {})
        if not isinstance(sources, dict):
            raise ConfigError(f"'sources' in {where} must be an object")
        sink_sanitizers = data.get("sink_sanitizers", {})
        if not isinstance(sink_sanitizers, dict):
            raise ConfigError(f"'sink_sanitizers' in {where} must be an object")
        return cls(
            source_functions=frozenset(get_string_list(sources, "functions", where)),
            source_attributes=frozenset(get_string_list(sources, "attributes", where)),
            sanitizers=frozenset(get_string_list(data, "sanitizers", where)),
            sink_sanitizers={
                category: frozenset(get_string_list(sink_sanitizers, category, where))
                for category in sink_sanitizers
            },
        )

    @classmethod
    def load(cls, path: Path = DEFAULT_TAINT_CONFIG) -> TaintConfig:
        return cls.from_dict(load_json(path), str(path))


# --------------------------------------------------------------------------- nhãn


@dataclass(frozen=True)
class TaintInfo:
    """Dữ liệu không tin cậy và đường nó đã đi: ``input() -> command -> ...``.

    Bất biến (frozen): mỗi bước đi qua một biến tạo ra đối tượng mới, nên nhãn
    của biểu thức trước đó không bị thay đổi theo.
    """

    source: str                     # nguồn gốc, vd "request.args"
    path: tuple[str, ...]           # các bước, vd ("request.args", "name", "query")
    sanitizer: str | None = None    # sanitizer chung đã đi qua (nếu có)
    # Các loại sink mà dữ liệu đã được làm sạch bởi sanitizer theo loại sink.
    safe_for: frozenset[str] = frozenset()

    @property
    def sanitized(self) -> bool:
        return self.sanitizer is not None

    def through(self, step: str) -> TaintInfo:
        """Thêm một biến/hàm vào taint path (không lặp lại nếu trùng bước cuối)."""
        if self.path and self.path[-1] == step:
            return self
        return replace(self, path=(*self.path, step))


class _Static:
    """Nhãn của giá trị cố định trong mã nguồn.

    Singleton (chỉ có một đối tượng duy nhất) để so sánh nhanh bằng ``is STATIC``.
    """

    _instance: _Static | None = None

    def __new__(cls) -> _Static:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "STATIC"


STATIC: Final = _Static()
# Một nhãn là: TaintInfo (tainted), STATIC (hằng số) hoặc None (không rõ).
Label = TaintInfo | _Static | None


def combine(labels: list[Label]) -> Label:
    """Nhãn của một giá trị ghép từ nhiều phần (nối chuỗi, f-string...).

    Có một phần tainted là cả kết quả tainted (phần chưa sanitize được ưu tiên);
    kết quả chỉ static khi MỌI phần đều static. Kết quả chỉ an toàn cho một loại
    sink khi MỌI phần tainted (chưa sanitize) đều an toàn cho loại sink đó.

    Vd ``"/data/" + basename(input())`` -> tainted, safe_for={"path"};
    ``basename(a) + a`` -> tainted, safe_for={} (phần ``a`` chưa được làm sạch).
    """
    tainted = [label for label in labels if isinstance(label, TaintInfo)]
    if tainted:
        candidates = [info for info in tainted if not info.sanitized] or tainted
        # Chọn phần "nguy hiểm nhất" (an toàn cho ít loại sink nhất); hòa thì lấy phần đầu tiên.
        chosen = min(candidates, key=lambda info: len(info.safe_for))
        # Giao (intersection) các tập safe_for: chỉ giữ loại sink mà mọi phần đều an toàn.
        safe_for = reduce(frozenset.intersection, (info.safe_for for info in candidates))
        return chosen if chosen.safe_for == safe_for else replace(chosen, safe_for=safe_for)
    if labels and all(label is STATIC for label in labels):
        return STATIC
    return None


def join(old: Label, new: Label) -> Label:
    """Gộp hai giá trị có thể có của một biến (phép gán nằm trong một nhánh rẽ).

    Vì không biết nhánh nào sẽ chạy, kết quả phải "tệ nhất" trong hai giá trị.
    """
    if isinstance(old, TaintInfo) and isinstance(new, TaintInfo):
        # Đặt giá trị chưa sanitize lên trước để combine ưu tiên nó.
        return combine([old, new] if new.sanitized else [new, old])
    if isinstance(new, TaintInfo) and not new.sanitized:
        return new
    if isinstance(old, TaintInfo):
        return old
    if isinstance(new, TaintInfo):
        return new
    return STATIC if old is STATIC and new is STATIC else None


def taint_only(label: Label) -> Label:
    """Giữ nhãn tainted, bỏ nhãn STATIC.

    Lặp qua / unpack một container hằng số không cho ra một giá trị hằng cụ thể
    đã biết, nên phần tử được coi là "không rõ" chứ không phải STATIC.
    """
    return label if isinstance(label, TaintInfo) else None


# --------------------------------------------------------------------------- kết quả


@dataclass
class TaintResult:
    """Nhãn của các biểu thức trong một file, để các rule tra cứu."""

    # Node AST -> nhãn. Dùng chính đối tượng node làm khóa (mỗi node là duy nhất).
    labels: dict[ast.AST, Label] = field(default_factory=dict)

    def lookup(self, node: ast.AST | None) -> TaintInfo | None:
        """TaintInfo của node nếu node bị taint, ngược lại None."""
        label = self.labels.get(node) if node is not None else None
        return label if isinstance(label, TaintInfo) else None

    def is_static(self, node: ast.AST | None) -> bool:
        """True nếu giá trị của node cố định trong mã nguồn."""
        if node is None:
            return False
        if node in self.labels:
            return self.labels[node] is STATIC
        # Node chưa được analyzer đánh giá (vd không có cấu hình taint): xét trực tiếp cú pháp.
        return is_static_value(node)


# --------------------------------------------------------------------------- analyzer

_SCOPES = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
# Định nghĩa lồng bên trong được phân tích như một scope riêng.
_NESTED_SCOPES = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


class TaintAnalyzer:
    """Tính nhãn cho mọi biểu thức của một module.

    Chạy từng câu lệnh theo thứ tự (giống một trình thông dịch "ảo"), với
    ``self.state`` là bảng tên biến -> nhãn hiện tại.
    """

    def __init__(self, tree: ast.Module, imports: dict[str, str], config: TaintConfig) -> None:
        self.tree = tree
        self.imports = imports
        self.config = config
        self.result = TaintResult()
        # Tên biến (x, self.x) -> nhãn hiện tại trong scope đang phân tích.
        self.state: dict[str, Label] = {}
        # Đảo bảng cấu hình: tên sanitizer -> các loại sink nó làm sạch (để tra cứu nhanh).
        self.sink_sanitizers: dict[str, frozenset[str]] = {}
        for category, functions in config.sink_sanitizers.items():
            for function in functions:
                self.sink_sanitizers[function] = self.sink_sanitizers.get(function, frozenset()) | {category}

        # Resolve lexical scopes by AST identity; names alone collide across classes.
        self.parents = {child: parent for parent in ast.walk(tree)
                        for child in ast.iter_child_nodes(parent)}
        self.functions = [n for n in ast.walk(tree)
                          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.definitions: dict[ast.AST, dict[str, list[ast.AST]]] = {}
        for function in self.functions:
            owner = self._scope(function)
            self.definitions.setdefault(owner, {}).setdefault(function.name, []).append(function)
        self.current_scope: ast.AST = tree
        self.active: set[ast.AST] = set()
        self.returns: list[Label] = []
        self.module_state: dict[str, Label] = {}
        self.call_budget = 2000

    def _scope(self, node: ast.AST) -> ast.AST:
        parent = self.parents.get(node)
        while parent is not None and not isinstance(parent, _SCOPES):
            parent = self.parents.get(parent)
        return parent or self.tree

    def analyze(self) -> TaintResult:
        """Analyze bodies on demand with call-specific arguments and bounded recursion."""
        self._run_scope(self.tree.body, {})
        self.module_state = dict(self.state)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                self.current_scope = node
                self._run_scope(node.body, dict(self.module_state))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._invoke(node, {}, dict(self.module_state))
        self.current_scope = self.tree
        return self.result

    def _resolve_local(self, node: ast.Call):
        # Dynamic receivers/aliases remain conservative unknown calls.
        if not isinstance(node.func, ast.Name) or node.func.id in self.state:
            return None
        scope = self.current_scope
        while True:
            candidates = self.definitions.get(scope, {}).get(node.func.id, [])
            if candidates:
                return candidates[0] if len(candidates) == 1 else None
            if scope is self.tree:
                return None
            scope = self._scope(scope)
            # A class namespace is not a lexical scope of its methods.
            while isinstance(scope, ast.ClassDef):
                scope = self._scope(scope)

    def _invoke(self, function, bindings: dict[str, Label], initial: dict[str, Label]) -> Label:
        if function in self.active or len(self.active) >= 32 or (self.call_budget <= 0 and self.active):
            return taint_only(combine(list(bindings.values())))
        self.call_budget -= 1
        saved = self.state, self.current_scope, self.returns
        self.current_scope, self.returns = function, []
        self.active.add(function)
        self.state = dict(initial)
        for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs,
                    function.args.vararg, function.args.kwarg):
            if arg is not None:
                value = bindings.get(arg.arg)
                self.state[arg.arg] = value.through(arg.arg) if isinstance(value, TaintInfo) else value
        try:
            self._run_block(function.body, in_branch=False)
            value = combine(self.returns) if self.returns else STATIC
            return value.through(function.name + "()") if isinstance(value, TaintInfo) else value
        finally:
            self.active.remove(function)
            self.state, self.current_scope, self.returns = saved

    def _call_local(self, function, node: ast.Call, arguments: list[Label]) -> Label:
        positional = [a.arg for a in (*function.args.posonlyargs, *function.args.args)]
        bindings = dict(zip(positional, arguments[:len(node.args)]))
        if function.args.vararg:
            bindings[function.args.vararg.arg] = combine(arguments[len(positional):len(node.args)])
        extra = []
        for keyword, label in zip(node.keywords, arguments[len(node.args):]):
            if keyword.arg is None:
                # Unknown **kwargs can populate any parameter.
                for param in positional + [a.arg for a in function.args.kwonlyargs]:
                    bindings[param] = join(bindings.get(param), label)
            elif keyword.arg in positional or keyword.arg in [a.arg for a in function.args.kwonlyargs]:
                bindings[keyword.arg] = label
            else:
                extra.append(label)
        if function.args.kwarg:
            bindings[function.args.kwarg.arg] = combine(extra)
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            expanded = taint_only(combine(arguments[:len(node.args)]))
            for param in positional:
                bindings[param] = join(bindings.get(param), expanded)
        defaults = dict(zip(positional[-len(function.args.defaults):], function.args.defaults)) if function.args.defaults else {}
        defaults.update({a.arg: d for a, d in zip(function.args.kwonlyargs, function.args.kw_defaults) if d is not None})
        for param, default in defaults.items():
            if param not in bindings:
                bindings[param] = self.eval(default)
        owner = self._scope(function)
        initial = self.state if owner is self.current_scope else self.module_state
        return self._invoke(function, bindings, initial)

    def _run_scope(self, body: list[ast.stmt], initial_state: dict[str, Label]) -> None:
        self.state = initial_state
        self._run_block(body, in_branch=False)

    # ------------------------------------------------------------------ câu lệnh

    def _run_block(self, body: list[ast.stmt], in_branch: bool) -> None:
        for stmt in body:
            self._run_statement(stmt, in_branch)
            if isinstance(stmt, (ast.Return, ast.Raise)):
                break

    def _run_statement(self, stmt: ast.stmt, in_branch: bool) -> None:
        """Cập nhật bảng state theo một câu lệnh.

        ``in_branch=True`` nghĩa là câu lệnh có thể không chạy (nằm trong if/for/try...).
        """
        if isinstance(stmt, _NESTED_SCOPES):
            return  # được phân tích như một scope riêng
        if isinstance(stmt, ast.Assign):
            # x = y = value: mọi target nhận cùng một nhãn.
            label = self.eval(stmt.value)
            for target in stmt.targets:
                self._bind(target, label, in_branch)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._bind(stmt.target, self.eval(stmt.value), in_branch)
        elif isinstance(stmt, ast.AugAssign):
            # x += value  ==  x = x + value
            current = self.state.get(_state_key(stmt.target) or "")
            self._bind(stmt.target, combine([current, self.eval(stmt.value)]), in_branch)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            # Biến lặp nhận taint của thứ được lặp; thân vòng lặp có thể chạy 0 lần nên là nhánh.
            self._bind(stmt.target, taint_only(self.eval(stmt.iter)), in_branch=True)
            self._run_block(stmt.body, in_branch=True)
            self._run_block(stmt.orelse, in_branch=True)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            # with open(path) as f: - f nhận taint của biểu thức sau "with".
            for item in stmt.items:
                label = self.eval(item.context_expr)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, taint_only(label), in_branch)
            self._run_block(stmt.body, in_branch)
        elif isinstance(stmt, ast.Return):
            self.returns.append(self.eval(stmt.value) if stmt.value is not None else STATIC)
        else:
            # If/While/Try/Match/Return/Expr/...: đánh giá các biểu thức của chính
            # câu lệnh, rồi chạy các khối lồng bên trong theo thứ tự mã nguồn.
            # Mọi khối lồng đều là nhánh có điều kiện.
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self.eval(child)
            self._run_block(getattr(stmt, "body", []), in_branch=True)
            for handler in getattr(stmt, "handlers", []):
                self._run_block(handler.body, in_branch=True)
            for case in getattr(stmt, "cases", []):
                self._run_block(case.body, in_branch=True)
            self._run_block(getattr(stmt, "orelse", []), in_branch=True)
            self._run_block(getattr(stmt, "finalbody", []), in_branch=True)

    def _bind(self, target: ast.AST, label: Label, in_branch: bool) -> None:
        """Gán nhãn cho đích của phép gán (biến, thuộc tính, phần tử, tuple...)."""
        if isinstance(target, (ast.Tuple, ast.List)):
            # a, b = value: mỗi phần tử nhận nhãn của value (STATIC giữ nguyên, còn lại chỉ giữ taint).
            for element in target.elts:
                self._bind(element, label if label is STATIC else taint_only(label), in_branch)
            return
        if isinstance(target, ast.Starred):
            self._bind(target.value, taint_only(label), in_branch)
            return
        key = _state_key(target)
        if key is None:
            return
        if isinstance(target, ast.Subscript):
            # d["k"] = tainted  ->  cả container d bị taint.
            # Gán giá trị sạch vào một phần tử thì KHÔNG xóa taint của các phần tử khác.
            if isinstance(label, TaintInfo):
                self.state[key] = join(self.state.get(key), label.through(key))
            return
        new = label.through(key) if isinstance(label, TaintInfo) else label
        # Trong nhánh: gộp với giá trị cũ (có thể nhánh không chạy); ngoài nhánh: ghi đè.
        self.state[key] = join(self.state.get(key), new) if in_branch else new

    # ------------------------------------------------------------------ biểu thức

    def eval(self, node: ast.expr) -> Label:
        """Nhãn của một biểu thức; kết quả được lưu lại để rule tra cứu sau."""
        label = self._eval(node)
        self.result.labels[node] = join(self.result.labels[node], label) if node in self.result.labels else label
        return label

    def _eval(self, node: ast.expr) -> Label:
        if isinstance(node, ast.Constant):
            return STATIC
        if isinstance(node, ast.Name):
            # Tên có thể chính là một source (vd "from sys import argv" rồi dùng "argv").
            if self._is_source_attribute(node):
                return self._source_label(node)
            return self.state.get(node.id)
        if isinstance(node, ast.Attribute):
            return self._eval_attribute(node)
        if isinstance(node, ast.Call):
            return self._eval_call(node)
        if isinstance(node, ast.Subscript):
            # request.args["q"]: phần tử của dữ liệu tainted cũng tainted.
            value, index = self.eval(node.value), self.eval(node.slice)
            if isinstance(value, TaintInfo):
                return value
            # Chỉ chỉ số tainted (CONST[key]) thì không taint: kết quả là một trong các giá trị cố định.
            return STATIC if value is STATIC and index is STATIC else None
        if isinstance(node, ast.Compare):
            for child in (node.left, *node.comparators):
                self.eval(child)
            return None  # kết quả là True/False, không phải văn bản do kẻ tấn công kiểm soát
        if isinstance(node, ast.IfExp):
            # a if cond else b: có thể là a hoặc b.
            self.eval(node.test)
            return combine([self.eval(node.body), self.eval(node.orelse)])
        if isinstance(node, ast.NamedExpr):
            # Toán tử walrus (x := value) vừa gán vừa trả giá trị.
            label = self.eval(node.value)
            self._bind(node.target, label, in_branch=True)
            return label
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._eval_comprehension(node)
        if isinstance(node, ast.Lambda):
            return None
        # BinOp, BoolOp, UnaryOp, JoinedStr, FormattedValue, List, Tuple, Dict, Set, Starred, Await...:
        # gộp nhãn của mọi biểu thức con.
        return combine([self.eval(child) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)])

    def _eval_attribute(self, node: ast.Attribute) -> Label:
        if self._is_source_attribute(node):
            return self._source_label(node)
        key = get_dotted_name(node)
        if key is not None and key in self.state:
            return self.state[key]  # vd self.command đã được gán trước đó
        value = self.eval(node.value)
        # Mọi thuộc tính của dữ liệu tainted đều tainted (request.args -> request.args.get).
        return value if isinstance(value, TaintInfo) else None

    def _eval_call(self, node: ast.Call) -> Label:
        """Nhãn kết quả của lời gọi hàm: source, sanitizer, sanitizer theo sink, hoặc hàm bất kỳ."""
        name = resolve_name(node.func, self.imports)  # tên đã giải alias import
        raw = get_dotted_name(node.func)              # tên đúng như viết trong code
        # Đánh giá cả đối tượng nhận (receiver) và mọi argument để chúng cũng có nhãn.
        receiver = self.eval(node.func.value) if isinstance(node.func, ast.Attribute) else None
        arguments = [self.eval(arg) for arg in node.args]
        arguments += [self.eval(keyword.value) for keyword in node.keywords]

        local_target = self._resolve_local(node)
        if local_target is not None:
            return self._call_local(local_target, node, arguments)

        # 1) Hàm source: tạo taint mới, vd input() -> TaintInfo(source="input()").
        if name in self.config.source_functions or raw in self.config.source_functions:
            label = f"{raw or name}()"
            return TaintInfo(source=label, path=(label,))
        # 2) Sanitizer chung: vẫn tainted nhưng đánh dấu đã sanitize (rule báo LOW).
        if name in self.config.sanitizers:
            data = combine(arguments)
            if isinstance(data, TaintInfo):
                return replace(data.through(f"{name}()"), sanitizer=name)
            return None
        # 3) Sanitizer theo loại sink: vẫn tainted, chỉ thêm loại sink an toàn vào safe_for.
        if name in self.sink_sanitizers:
            data = combine(arguments)
            if isinstance(data, TaintInfo):
                return replace(data.through(f"{name}()"), safe_for=data.safe_for | self.sink_sanitizers[name])
            return None
        # 5) Hàm không biết: argument hoặc receiver bị taint thì kết quả bị taint
        # (user.strip(), "".join(parts), str(x), request.args.get("q")...).
        return taint_only(combine([receiver, *arguments]))

    def _eval_comprehension(self, node: ast.expr) -> Label:
        """[f(x) for x in items if cond]: kết quả bị taint nếu items hoặc biểu thức bị taint."""
        saved = dict(self.state)
        labels: list[Label] = []
        for generator in node.generators:  # type: ignore[attr-defined]
            iterable = taint_only(self.eval(generator.iter))
            labels.append(iterable)
            self._bind(generator.target, iterable, in_branch=False)
            for condition in generator.ifs:
                self.eval(condition)
        if isinstance(node, ast.DictComp):
            labels += [self.eval(node.key), self.eval(node.value)]
        else:
            labels.append(self.eval(node.elt))  # type: ignore[attr-defined]
        self.state = saved  # biến của comprehension không "rò" ra ngoài (giống Python 3)
        return taint_only(combine(labels))

    # ------------------------------------------------------------------ source

    def _is_source_attribute(self, node: ast.expr) -> bool:
        """So khớp cả tên như viết (request.args) lẫn tên đã giải alias (flask.request.args)."""
        sources = self.config.source_attributes
        return get_dotted_name(node) in sources or resolve_name(node, self.imports) in sources

    @staticmethod
    def _source_label(node: ast.expr) -> TaintInfo:
        label = get_dotted_name(node) or "<source>"
        return TaintInfo(source=label, path=(label,))


def _state_key(target: ast.AST) -> str | None:
    """Tên được theo dõi cho đích của phép gán: x, self.x, hoặc container d của d[...]."""
    if isinstance(target, ast.Subscript):
        return get_dotted_name(target.value)
    return get_dotted_name(target)


def analyze_taint(tree: ast.Module, imports: dict[str, str], config: TaintConfig) -> TaintResult:
    """Điểm vào: tính nhãn taint cho mọi biểu thức của một module."""
    return TaintAnalyzer(tree, imports, config).analyze()
