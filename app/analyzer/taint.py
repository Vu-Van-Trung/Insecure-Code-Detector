"""Basic intra-procedural taint tracking.

Every expression evaluated in a scope (module, class body or function) gets one
of three labels:

* ``TaintInfo`` - the value may contain data from an untrusted *source*
  (``input()``, ``request.args``, ``sys.argv``, ...); it records the source and
  the variables the data flowed through (the taint path);
* ``STATIC``    - the value is fixed in the source code (literals and variables
  holding literals);
* ``None``      - unknown (function parameters, results of arbitrary calls, ...).

Rules then look up the label of the argument that reaches their sink.

Limitations (prototype, documented on purpose):

* no inter-procedural analysis: taint does not flow through function calls,
  return values or parameters;
* branches are merged conservatively: an assignment inside ``if``/``for``/
  ``while``/``try`` can add taint but never removes it;
* containers are tracked as a whole (``d["a"] = tainted`` taints ``d``).

SECURITY: sanitizers only *reduce* confidence. The analyzer cannot prove that
a sanitizer is appropriate for a given sink (``shlex.quote`` does not prevent
SQL injection), so sanitized flows are still reported with a low severity.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final

from app.analyzer.utils import get_dotted_name, is_static_value, resolve_name
from app.config.loader import CONFIG_DIR, ConfigError, get_string_list, load_json

DEFAULT_TAINT_CONFIG = CONFIG_DIR / "taint.json"


# --------------------------------------------------------------------------- configuration


@dataclass(frozen=True)
class TaintConfig:
    source_functions: frozenset[str]
    source_attributes: frozenset[str]
    sanitizers: frozenset[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "taint configuration") -> TaintConfig:
        sources = data.get("sources", {})
        if not isinstance(sources, dict):
            raise ConfigError(f"'sources' in {where} must be an object")
        return cls(
            source_functions=frozenset(get_string_list(sources, "functions", where)),
            source_attributes=frozenset(get_string_list(sources, "attributes", where)),
            sanitizers=frozenset(get_string_list(data, "sanitizers", where)),
        )

    @classmethod
    def load(cls, path: Path = DEFAULT_TAINT_CONFIG) -> TaintConfig:
        return cls.from_dict(load_json(path), str(path))


# --------------------------------------------------------------------------- labels


@dataclass(frozen=True)
class TaintInfo:
    """Untrusted data and how it travelled: ``input() -> command -> ...``."""

    source: str
    path: tuple[str, ...]
    sanitizer: str | None = None

    @property
    def sanitized(self) -> bool:
        return self.sanitizer is not None

    def through(self, step: str) -> TaintInfo:
        """Append a variable/function to the path (without repeating the last step)."""
        if self.path and self.path[-1] == step:
            return self
        return replace(self, path=(*self.path, step))


class _Static:
    """Label of values fixed in the source code."""

    _instance: _Static | None = None

    def __new__(cls) -> _Static:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "STATIC"


STATIC: Final = _Static()
Label = TaintInfo | _Static | None


def combine(labels: list[Label]) -> Label:
    """Label of a value built from several parts (concatenation, f-string, ...).

    Any tainted part taints the result (unsanitized taint wins); the result is
    static only if every part is static.
    """
    tainted = [label for label in labels if isinstance(label, TaintInfo)]
    if tainted:
        unsanitized = [info for info in tainted if not info.sanitized]
        return (unsanitized or tainted)[0]
    if labels and all(label is STATIC for label in labels):
        return STATIC
    return None


def join(old: Label, new: Label) -> Label:
    """Merge two possible values of a variable (assignment inside a branch)."""
    if isinstance(new, TaintInfo) and not new.sanitized:
        return new
    if isinstance(old, TaintInfo):
        return old
    if isinstance(new, TaintInfo):
        return new
    return STATIC if old is STATIC and new is STATIC else None


def taint_only(label: Label) -> Label:
    """Iterating over / unpacking a static container does not give a known literal."""
    return label if isinstance(label, TaintInfo) else None


# --------------------------------------------------------------------------- result


@dataclass
class TaintResult:
    """Labels of the expressions of one file, queried by the rules."""

    labels: dict[ast.AST, Label] = field(default_factory=dict)

    def lookup(self, node: ast.AST | None) -> TaintInfo | None:
        label = self.labels.get(node) if node is not None else None
        return label if isinstance(label, TaintInfo) else None

    def is_static(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if node in self.labels:
            return self.labels[node] is STATIC
        return is_static_value(node)


# --------------------------------------------------------------------------- analyzer

_SCOPES = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
_NESTED_SCOPES = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


class TaintAnalyzer:
    """Computes a label for every expression of a module."""

    def __init__(self, tree: ast.Module, imports: dict[str, str], config: TaintConfig) -> None:
        self.tree = tree
        self.imports = imports
        self.config = config
        self.result = TaintResult()
        self.state: dict[str, Label] = {}

    def analyze(self) -> TaintResult:
        self._run_scope(self.tree.body, {})
        # Module-level values (e.g. CMD = "ls") are visible inside functions.
        module_state = dict(self.state)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                self._run_scope(node.body, dict(module_state))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seed = dict(module_state)
                # Parameters shadow module variables and are unknown (no inter-procedural analysis).
                for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                            node.args.vararg, node.args.kwarg):
                    if arg is not None:
                        seed.pop(arg.arg, None)
                self._run_scope(node.body, seed)
        return self.result

    def _run_scope(self, body: list[ast.stmt], initial_state: dict[str, Label]) -> None:
        self.state = initial_state
        self._run_block(body, in_branch=False)

    # ------------------------------------------------------------------ statements

    def _run_block(self, body: list[ast.stmt], in_branch: bool) -> None:
        for stmt in body:
            self._run_statement(stmt, in_branch)

    def _run_statement(self, stmt: ast.stmt, in_branch: bool) -> None:
        if isinstance(stmt, _NESTED_SCOPES):
            return  # analyzed as its own scope
        if isinstance(stmt, ast.Assign):
            label = self.eval(stmt.value)
            for target in stmt.targets:
                self._bind(target, label, in_branch)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._bind(stmt.target, self.eval(stmt.value), in_branch)
        elif isinstance(stmt, ast.AugAssign):
            current = self.state.get(_state_key(stmt.target) or "")
            self._bind(stmt.target, combine([current, self.eval(stmt.value)]), in_branch)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._bind(stmt.target, taint_only(self.eval(stmt.iter)), in_branch=True)
            self._run_block(stmt.body, in_branch=True)
            self._run_block(stmt.orelse, in_branch=True)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                label = self.eval(item.context_expr)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, taint_only(label), in_branch)
            self._run_block(stmt.body, in_branch)
        else:
            # If/While/Try/Match/Return/Expr/...: evaluate the statement's own
            # expressions, then run nested blocks in source order. Every nested
            # block is a conditional branch.
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
        if isinstance(target, (ast.Tuple, ast.List)):
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
            # d["k"] = tainted  ->  the whole container d becomes tainted.
            if isinstance(label, TaintInfo):
                self.state[key] = join(self.state.get(key), label.through(key))
            return
        new = label.through(key) if isinstance(label, TaintInfo) else label
        self.state[key] = join(self.state.get(key), new) if in_branch else new

    # ------------------------------------------------------------------ expressions

    def eval(self, node: ast.expr) -> Label:
        """Label of an expression; the result is recorded for later lookups."""
        label = self._eval(node)
        self.result.labels[node] = label
        return label

    def _eval(self, node: ast.expr) -> Label:
        if isinstance(node, ast.Constant):
            return STATIC
        if isinstance(node, ast.Name):
            if self._is_source_attribute(node):
                return self._source_label(node)
            return self.state.get(node.id)
        if isinstance(node, ast.Attribute):
            return self._eval_attribute(node)
        if isinstance(node, ast.Call):
            return self._eval_call(node)
        if isinstance(node, ast.Subscript):
            value, index = self.eval(node.value), self.eval(node.slice)
            if isinstance(value, TaintInfo):
                return value
            return STATIC if value is STATIC and index is STATIC else None
        if isinstance(node, ast.Compare):
            for child in (node.left, *node.comparators):
                self.eval(child)
            return None  # a boolean, not attacker-controlled text
        if isinstance(node, ast.IfExp):
            self.eval(node.test)
            return combine([self.eval(node.body), self.eval(node.orelse)])
        if isinstance(node, ast.NamedExpr):
            label = self.eval(node.value)
            self._bind(node.target, label, in_branch=True)
            return label
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._eval_comprehension(node)
        if isinstance(node, ast.Lambda):
            return None
        # BinOp, BoolOp, UnaryOp, JoinedStr, FormattedValue, List, Tuple, Dict, Set, Starred, Await...
        return combine([self.eval(child) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)])

    def _eval_attribute(self, node: ast.Attribute) -> Label:
        if self._is_source_attribute(node):
            return self._source_label(node)
        key = get_dotted_name(node)
        if key is not None and key in self.state:
            return self.state[key]  # e.g. self.command assigned earlier
        value = self.eval(node.value)
        # Any attribute of tainted data is tainted (request.args -> request.args.get).
        return value if isinstance(value, TaintInfo) else None

    def _eval_call(self, node: ast.Call) -> Label:
        name = resolve_name(node.func, self.imports)
        raw = get_dotted_name(node.func)
        receiver = self.eval(node.func.value) if isinstance(node.func, ast.Attribute) else None
        arguments = [self.eval(arg) for arg in node.args]
        arguments += [self.eval(keyword.value) for keyword in node.keywords]

        if name in self.config.source_functions or raw in self.config.source_functions:
            label = f"{raw or name}()"
            return TaintInfo(source=label, path=(label,))
        if name in self.config.sanitizers:
            data = combine(arguments)
            if isinstance(data, TaintInfo):
                return replace(data.through(f"{name}()"), sanitizer=name)
            return None
        # Unknown call: tainted arguments or receiver taint the result
        # (user.strip(), "".join(parts), str(x), request.args.get("q"), ...).
        return taint_only(combine([receiver, *arguments]))

    def _eval_comprehension(self, node: ast.expr) -> Label:
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
        self.state = saved  # comprehension variables do not leak
        return taint_only(combine(labels))

    # ------------------------------------------------------------------ sources

    def _is_source_attribute(self, node: ast.expr) -> bool:
        sources = self.config.source_attributes
        return get_dotted_name(node) in sources or resolve_name(node, self.imports) in sources

    @staticmethod
    def _source_label(node: ast.expr) -> TaintInfo:
        label = get_dotted_name(node) or "<source>"
        return TaintInfo(source=label, path=(label,))


def _state_key(target: ast.AST) -> str | None:
    """Variable tracked for an assignment target: x, self.x, or the container of d[...]."""
    if isinstance(target, ast.Subscript):
        return get_dotted_name(target.value)
    return get_dotted_name(target)


def analyze_taint(tree: ast.Module, imports: dict[str, str], config: TaintConfig) -> TaintResult:
    return TaintAnalyzer(tree, imports, config).analyze()
