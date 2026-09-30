"""Shared building blocks for Java (JVxxx) and C# (CSxxx) rules.

The leading underscore keeps the registry from loading this module as a rule
module; concrete rules live in java_rules.py and csharp_rules.py and mostly
only declare API names.
"""

from __future__ import annotations

import ast
import re
from abc import abstractmethod
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any, ClassVar

from app.analyzer.taint import TaintInfo
from app.analyzer.ts.context import TSContext
from app.config.settings import Whitelist
from app.models.finding import Finding, Severity
from app.analyzer.utils import split_identifier
from app.rules._keywords import is_secret_name, is_security_value_name
from app.rules.base import (
    SANITIZED_CONFIDENCE,
    SANITIZED_SEVERITY,
    TAINTED_CONFIDENCE,
    ArgumentKind,
    SecurityRule,
    classify_argument,
    sanitized_message,
    taint_details,
)
from app.rules.secret_rule import (
    HIGH_ENTROPY_MIN_LENGTH,
    HIGH_ENTROPY_THRESHOLD,
    is_placeholder,
    mask_secret,
    match_known_format,
    shannon_entropy,
)
from app.rules.sql_rule import SQL_KEYWORDS

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node

    from app.config.settings import AnalyzerSettings

# Worst first: a tainted argument decides the finding even if others are constant.
_KIND_ORDER = {ArgumentKind.TAINTED: 0, ArgumentKind.DYNAMIC: 1, ArgumentKind.SANITIZED: 2, ArgumentKind.STATIC: 3}

SHELLS = frozenset({"sh", "bash", "zsh", "ksh", "/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/zsh",
                    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"})
SHELL_FLAGS = frozenset({"-c", "/c", "/C", "-Command", "-command", "/k", "/K"})


class TSRule(SecurityRule):
    """A rule for a tree-sitter language: it inspects the whole file context at once."""

    _abstract_rule = True
    node_types = ()

    def check(self, node: ast.AST, context: Any) -> Iterable[Finding]:
        return ()  # not used: the engine calls check_file() for Java/C#

    @abstractmethod
    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        """Yield the findings of one Java/C# file."""

    # ------------------------------------------------------------------ grading helpers

    def worst_argument(self, args: Iterable[Node], ctx: TSContext) -> tuple[ArgumentKind, TaintInfo | None]:
        graded = [classify_argument(arg, ctx) for arg in args]
        if not graded:
            return ArgumentKind.DYNAMIC, None
        return min(graded, key=lambda item: _KIND_ORDER[item[0]])

    def graded_finding(
        self,
        node: Node,
        ctx: TSContext,
        kind: ArgumentKind,
        info: TaintInfo | None,
        sink: str,
        *,
        dynamic_message: str,
        static_message: str | None = None,
        dynamic_confidence: float = 0.8,
        static_confidence: float = 0.6,
        tainted_severity: Severity = Severity.CRITICAL,
        static_severity: Severity = Severity.LOW,
        cwe: str | None = None,
    ) -> Finding | None:
        """Finding for a sink, graded like the Python rules (tainted > dynamic > sanitized > static)."""
        if kind is ArgumentKind.TAINTED and info is not None:
            return self.create_finding(
                node, ctx, f"Untrusted input from {info.source} reaches {sink}.",
                severity=tainted_severity, confidence=TAINTED_CONFIDENCE, cwe=cwe, **taint_details(info, sink),
            )
        if kind is ArgumentKind.SANITIZED and info is not None:
            return self.create_finding(
                node, ctx, sanitized_message(info, sink),
                severity=SANITIZED_SEVERITY, confidence=SANITIZED_CONFIDENCE, cwe=cwe, **taint_details(info, sink),
            )
        if kind is ArgumentKind.STATIC:
            if static_message is None:
                return None
            return self.create_finding(node, ctx, static_message, severity=static_severity,
                                       confidence=static_confidence, cwe=cwe)
        return self.create_finding(node, ctx, dynamic_message, confidence=dynamic_confidence, cwe=cwe)


def string_value(ctx: TSContext, node: Node | None) -> str | None:
    if node is None:
        return None
    return ctx.adapter.string_value(ctx.adapter.unwrap(node))


def string_parts(ctx: TSContext, node: Node) -> list[str]:
    """Literal text fragments of an expression (concatenations, interpolations, format calls)."""
    parts: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        value = ctx.adapter.string_value(current)
        if value is not None:
            parts.append(value)
            continue
        if current.type == "string_content":
            parts.append(ctx.adapter.text(current))
        stack.extend(current.named_children)
    return parts


# --------------------------------------------------------------------------- command injection


def flatten_command(ctx: TSContext, args: list[Node]) -> list[Node]:
    """Program + arguments: ``new String[]{"sh", "-c", c}``, ``List.of(...)``, varargs."""
    if len(args) == 1:
        elements = ctx.adapter.array_elements(ctx.adapter.unwrap(args[0]))
        if elements is not None:
            return elements
        inner = ctx.call_by_node.get(ctx.adapter.unwrap(args[0]).id)
        if inner is not None and inner.names & {"Arrays.asList", "List.of"}:
            return inner.args
    return args


class CommandRuleMixin(TSRule):
    """Grades an executable + argument list the way PY003/PY004 do for Python."""

    _abstract_rule = True

    def grade_program(self, node: Node, ctx: TSContext, program: list[Node], sink: str) -> Finding | None:
        if not program:
            return None
        executable = program[0]
        if not ctx.taint.is_static(executable):
            kind, info = classify_argument(executable, ctx)
            return self.graded_finding(node, ctx, kind, info, sink,
                                       dynamic_message=f"{sink} runs a program chosen at runtime.")
        name = (string_value(ctx, executable) or "").strip().lower()
        if name.split(" ", 1)[0] not in SHELLS and name not in SHELLS:
            # Program fixed and no shell: arguments cannot inject new commands.
            return None
        rest = [arg for arg in program[1:] if (string_value(ctx, arg) or "") not in SHELL_FLAGS]
        kind, info = self.worst_argument(rest, ctx)
        return self.graded_finding(
            node, ctx, kind, info, sink,
            dynamic_message=f"{sink} runs a dynamically built command through a shell.",
            static_message=f"{sink} runs a constant command through a shell.",
            dynamic_confidence=0.85,
        )

    def grade_command_line(self, node: Node, ctx: TSContext, command: Node, sink: str) -> Finding | None:
        """A single command string (Runtime.exec(String), Process.Start(string))."""
        kind, info = classify_argument(command, ctx)
        return self.graded_finding(
            node, ctx, kind, info, sink,
            dynamic_message=f"{sink} runs a dynamically built command line.",
            static_message=f"{sink} runs a constant command line.",
        )


# --------------------------------------------------------------------------- SQL injection


def unsafe_query_build(ctx: TSContext, node: Node) -> bool:
    """String built from literals mixed with dynamic values (+, interpolation, format)."""
    adapter = ctx.adapter
    node = adapter.unwrap(node)
    if adapter.is_static(node):
        return False
    if node.type == adapter.binary_type and adapter.operator(node) == "+":
        return bool(string_parts(ctx, node))
    if node.type in adapter.interpolated_types:
        return bool(adapter.interpolation_values(node))
    call = ctx.call_by_node.get(node.id)
    if call is not None and call.method.lower() in {"format", "formatted", "concat", "join"}:
        return bool(string_parts(ctx, node)) and not all(ctx.taint.is_static(arg) for arg in call.args)
    return False


class SqlRuleBase(TSRule):
    """Shared logic of JV002 / CS002."""

    _abstract_rule = True
    cwe = "CWE-89"
    category = "SQL Injection"
    severity = Severity.HIGH
    db_words: ClassVar[frozenset[str]] = frozenset({
        "statement", "stmt", "st", "ps", "conn", "connection", "db", "database", "session", "jdbc", "template",
        "em", "entity", "manager", "cmd", "command", "context", "ctx", "sql",
    })

    def grade_query(self, node: Node, ctx: TSContext, query: Node, sink: str, certain_sink: bool,
                    receiver: Node | None = None) -> Finding | None:
        likely_db = certain_sink or self._db_receiver(ctx, receiver)
        kind, info = classify_argument(query, ctx)
        if kind in (ArgumentKind.TAINTED, ArgumentKind.SANITIZED):
            if not likely_db and not SQL_KEYWORDS.search(" ".join(string_parts(ctx, query))):
                return None
            if kind is ArgumentKind.TAINTED:
                return self.create_finding(
                    node, ctx, f"Untrusted input from {info.source} is used to build the SQL query passed to {sink}.",
                    severity=Severity.CRITICAL, confidence=TAINTED_CONFIDENCE, **taint_details(info, sink),
                )
            return self.graded_finding(node, ctx, kind, info, sink, dynamic_message="")
        if kind is ArgumentKind.STATIC:
            return None
        built_at, parts = self._find_unsafe_build(ctx, query, node)
        if built_at is None:
            return None
        looks_like_sql = bool(SQL_KEYWORDS.search(" ".join(parts)))
        if not looks_like_sql and not likely_db:
            return None
        where = "" if built_at == node.start_point[0] + 1 else f" (built on line {built_at})"
        if looks_like_sql:
            return self.create_finding(node, ctx, f"SQL query built from dynamic values{where} is passed to {sink}.",
                                       confidence=0.85, sink=sink)
        return self.create_finding(node, ctx, f"Dynamically built string{where} is passed to {sink}.",
                                   severity=Severity.MEDIUM, confidence=0.55, sink=sink)

    def _find_unsafe_build(self, ctx: TSContext, query: Node, sink_node: Node) -> tuple[int | None, list[str]]:
        query = ctx.adapter.unwrap(query)
        if unsafe_query_build(ctx, query):
            return sink_node.start_point[0] + 1, string_parts(ctx, query)
        if query.type != "identifier":
            return None, []
        history = ctx.assignments_before(ctx.adapter.text(query), sink_node)
        start = max((i for i, (_, _, augmented) in enumerate(history) if not augmented), default=0)
        relevant = history[start:]
        parts = [part for _, value, _ in relevant for part in string_parts(ctx, value)]
        for line, value, augmented in relevant:
            unsafe = not ctx.taint.is_static(value) if augmented else unsafe_query_build(ctx, value)
            if unsafe:
                return line, parts
        return None, []

    def _db_receiver(self, ctx: TSContext, receiver: Node | None) -> bool:
        if receiver is None:
            return False
        words = split_identifier(ctx.adapter.text(receiver).rsplit(".", 1)[-1])
        type_name = ctx.type_of(receiver) or ""
        return any(word in self.db_words for word in words) or any(
            word in self.db_words for word in split_identifier(type_name))


# --------------------------------------------------------------------------- crypto, random


class WeakAlgorithmRuleBase(TSRule):
    """Calls whose name (or constant algorithm argument) selects a weak algorithm."""

    _abstract_rule = True
    weak_calls: ClassVar[frozenset[str]] = frozenset()       # MD5.Create, new MD5CryptoServiceProvider
    algorithm_calls: ClassVar[frozenset[str]] = frozenset()  # MessageDigest.getInstance("MD5")
    weak_algorithm: ClassVar[re.Pattern[str]] = re.compile(r"(?!)")  # never matches
    weak_members: ClassVar[frozenset[str]] = frozenset()     # CipherMode.ECB
    confidence: ClassVar[float] = 0.7

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.names & self.weak_calls:
                yield self.create_finding(call.node, ctx, f"{call.display} uses a weak algorithm.",
                                          confidence=self.confidence)
            elif call.names & self.algorithm_calls and call.args:
                algorithm = string_value(ctx, call.args[0])
                if algorithm is not None and self.weak_algorithm.search(algorithm):
                    yield self.create_finding(call.node, ctx, f"{call.display} selects weak algorithm '{algorithm}'.",
                                              confidence=0.85)
        if self.weak_members:
            stack = [ctx.root]
            while stack:
                node = stack.pop()
                if node.type in ctx.adapter.member_types and ctx.adapter.text(node).replace(" ", "") in self.weak_members:
                    yield self.create_finding(node, ctx, f"{ctx.adapter.text(node)} is an insecure mode.",
                                              confidence=0.8)
                    continue
                stack.extend(node.named_children)


class InsecureRandomRuleBase(TSRule):
    _abstract_rule = True
    cwe = "CWE-330"
    category = "Insecure Randomness"
    severity = Severity.MEDIUM
    random_types: ClassVar[frozenset[str]] = frozenset({"Random"})
    random_calls: ClassVar[frozenset[str]] = frozenset()  # Math.random, RandomStringUtils.random...

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.is_constructor:
                continue
            uses_random = (call.receiver_type in self.random_types) or bool(call.names & self.random_calls)
            if not uses_random:
                continue
            target = ctx.assigned_name(call.node)
            if target and is_security_value_name(target):
                yield self.create_finding(call.node, ctx, f"{call.display} generates a value stored in '{target}'.",
                                          confidence=0.75)
                continue
            method = ctx.enclosing_method_name(call.node)
            if method and is_security_value_name(method):
                yield self.create_finding(call.node, ctx, f"{call.display} is used inside '{method}()'.",
                                          confidence=0.6)


# --------------------------------------------------------------------------- secrets

# "Password=xyz;" inside JDBC URLs / ADO.NET connection strings.
_CONNECTION_PASSWORD = re.compile(r"(?i)(?:^|[;?&])\s*(?:password|pwd)\s*=\s*([^;&\s\"']+)")


class HardcodedSecretRuleBase(TSRule):
    _abstract_rule = True
    cwe = "CWE-798"
    category = "Hardcoded Credentials"
    severity = Severity.HIGH
    description = (
        "A credential (password, API key, token, private key, connection string password) is written "
        "directly in the source code, where anyone with access to the repository or binaries can read it."
    )

    def __init__(self) -> None:
        self.whitelist = Whitelist()

    def configure(self, settings: AnalyzerSettings) -> None:
        self.whitelist = settings.whitelist

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        reported: set[int] = set()
        for string in ctx.strings:
            value = ctx.adapter.string_value(string)
            if value is None or self.whitelist.is_secret_allowed(value):
                continue
            known = match_known_format(value)
            if known:
                description, severity = known
                reported.add(string.id)
                yield self.create_finding(string, ctx, f"Hardcoded {description} found in a string literal.",
                                          severity=severity, confidence=0.95, code=self._masked(ctx, string, value))
                continue
            match = _CONNECTION_PASSWORD.search(value)
            if match and not is_placeholder(match.group(1)):
                reported.add(string.id)
                yield self.create_finding(string, ctx, "Connection string contains a hardcoded password.",
                                          confidence=0.85, code=self._masked(ctx, string, match.group(1)))
        for name, value_node in self._named_values(ctx):
            value_node = ctx.adapter.unwrap(value_node)
            value = ctx.adapter.string_value(value_node)
            if value is None or value_node.id in reported or not is_secret_name(name):
                continue
            if is_placeholder(value) or self.whitelist.is_secret_allowed(value):
                continue
            code = self._masked(ctx, value_node, value)
            if len(value) >= HIGH_ENTROPY_MIN_LENGTH and shannon_entropy(value) >= HIGH_ENTROPY_THRESHOLD:
                yield self.create_finding(value_node, ctx,
                                          f"High-entropy string assigned to '{name}' looks like a hardcoded secret.",
                                          confidence=0.85, code=code)
            else:
                yield self.create_finding(value_node, ctx,
                                          f"String literal assigned to '{name}' may be a hardcoded secret.",
                                          severity=Severity.MEDIUM, confidence=0.6, code=code)

    @staticmethod
    def _named_values(ctx: TSContext) -> Iterator[tuple[str, Node]]:
        for declaration in ctx.declarations:
            if declaration.value is not None:
                yield declaration.name, declaration.value
        for assignment in ctx.assignments:
            yield assignment.target.rsplit(".", 1)[-1], assignment.value
        for call in ctx.calls:
            for prop, value in call.initializer.items():  # C# new X { Password = "..." }
                yield prop, value

    @staticmethod
    def _masked(ctx: TSContext, node: Node, secret: str) -> str:
        line = ctx.get_line(node.start_point[0] + 1)
        return line.replace(secret, mask_secret(secret)) if secret and secret in line else "<secret value masked>"

