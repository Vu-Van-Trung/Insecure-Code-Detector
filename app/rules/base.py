"""Base class every security rule inherits from."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from enum import Enum
from typing import Any, ClassVar

from app.analyzer.context import AnalysisContext
from app.analyzer.taint import TaintInfo
from app.analyzer.utils import get_argument
from app.models.finding import Finding, Severity


class SecurityRule(ABC):
    """A pluggable detector for one unsafe coding pattern.

    Subclasses declare their metadata as class attributes and implement
    :meth:`check`. The engine only calls ``check`` for AST nodes whose type is
    listed in ``node_types``, so rules never need to walk the tree themselves.
    """

    id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    severity: ClassVar[Severity]
    cwe: ClassVar[str]
    category: ClassVar[str]
    recommendation: ClassVar[str]
    node_types: ClassVar[tuple[type[ast.AST], ...]] = (ast.Call,)

    _REQUIRED_ATTRIBUTES: ClassVar[tuple[str, ...]] = (
        "id", "name", "description", "severity", "cwe", "category", "recommendation",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Fail fast at import time if a concrete rule forgets its metadata.
        # Intermediate base classes opt out with ``_abstract_rule = True``.
        if getattr(cls, "__abstractmethods__", None) or cls.__dict__.get("_abstract_rule", False):
            return
        missing = [attr for attr in cls._REQUIRED_ATTRIBUTES if not hasattr(cls, attr)]
        if missing:
            raise TypeError(f"Rule {cls.__name__} is missing attributes: {', '.join(missing)}")
        cls.severity = Severity.parse(cls.severity)

    @abstractmethod
    def check(self, node: ast.AST, context: AnalysisContext) -> Iterable[Finding]:
        """Inspect one AST node and yield zero or more findings."""

    def create_finding(
        self,
        node: ast.AST,
        context: AnalysisContext,
        message: str,
        *,
        confidence: float,
        severity: Severity | None = None,
        source: str | None = None,
        sink: str | None = None,
        taint_path: list[str] | None = None,
        code: str | None = None,
    ) -> Finding:
        """Build a Finding pre-filled with this rule's metadata and node location.

        ``severity`` may override the rule default when the context makes the
        issue more or less serious (e.g. untrusted input reaching a sink).
        ``code`` replaces the source line shown in reports, e.g. to mask a secret.
        """
        line = getattr(node, "lineno", 0)
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=severity or self.severity,
            confidence=confidence,
            file=context.filename,
            line=line,
            column=getattr(node, "col_offset", 0),
            message=message,
            description=self.description,
            code=code if code is not None else context.get_line(line),
            recommendation=self.recommendation,
            cwe=self.cwe,
            category=self.category,
            source=source,
            sink=sink,
            taint_path=list(taint_path or []),
        )

    def metadata(self) -> dict[str, str]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "category": self.category,
            "description": self.description,
        }


class DangerousCallRule(SecurityRule):
    """Base for rules that flag calls to specific dangerous functions.

    The finding is graded by where the checked argument comes from:

    * tainted (untrusted source reaches the sink): ``tainted_severity``, with
      source, sink and taint path attached;
    * sanitized (source -> sanitizer -> sink): LOW, low confidence;
    * dynamic (parameter, call result, ...): the rule's default ``severity``
      with ``dynamic_confidence``;
    * static (fixed in the source): ``static_severity`` with
      ``static_confidence``, because an attacker cannot influence it directly.

    Subclasses only declare ``target_functions`` (fully qualified names, import
    aliases are resolved) and the messages.
    """

    _abstract_rule = True

    target_functions: ClassVar[frozenset[str]]
    argument_position: ClassVar[int] = 0
    argument_keyword: ClassVar[str | None] = None
    dynamic_message: ClassVar[str]
    static_message: ClassVar[str]
    dynamic_confidence: ClassVar[float] = 0.8
    static_severity: ClassVar[Severity] = Severity.LOW
    static_confidence: ClassVar[float] = 0.6

    tainted_severity: ClassVar[Severity] = Severity.CRITICAL

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not isinstance(node, ast.Call):
            return
        name = context.call_name(node)
        if name not in self.target_functions or context.is_shadowed_builtin(name):
            return
        argument = get_argument(node, self.argument_position, self.argument_keyword)
        if argument is None:
            return
        kind, info = classify_argument(argument, context)
        sink = f"{name}()"
        if kind is ArgumentKind.TAINTED:
            yield self.create_finding(
                node, context, f"Untrusted input from {info.source} reaches {sink}.",
                severity=self.tainted_severity, confidence=TAINTED_CONFIDENCE, **taint_details(info, sink),
            )
        elif kind is ArgumentKind.SANITIZED:
            yield self.create_finding(
                node, context, sanitized_message(info, sink),
                severity=SANITIZED_SEVERITY, confidence=SANITIZED_CONFIDENCE, **taint_details(info, sink),
            )
        elif kind is ArgumentKind.STATIC:
            yield self.create_finding(
                node, context, self.static_message.format(name=name),
                severity=self.static_severity, confidence=self.static_confidence,
            )
        else:
            yield self.create_finding(
                node, context, self.dynamic_message.format(name=name),
                confidence=self.dynamic_confidence,
            )


# ------------------------------------------------------------------ taint helpers

# Untrusted data provably reaches the sink.
TAINTED_CONFIDENCE = 0.95
# Data passed through a configured sanitizer. Still reported: the analyzer cannot
# prove the sanitizer fits this sink (e.g. shlex.quote does not stop SQL injection).
SANITIZED_SEVERITY = Severity.LOW
SANITIZED_CONFIDENCE = 0.4


class ArgumentKind(Enum):
    TAINTED = "tainted"      # comes from an untrusted source
    SANITIZED = "sanitized"  # comes from a source but went through a sanitizer
    STATIC = "static"        # fixed in the source code
    DYNAMIC = "dynamic"      # unknown origin (parameter, call result, ...)


def classify_argument(argument: ast.AST, context: AnalysisContext) -> tuple[ArgumentKind, TaintInfo | None]:
    info = context.taint.lookup(argument)
    if info is not None:
        return (ArgumentKind.SANITIZED if info.sanitized else ArgumentKind.TAINTED), info
    if context.taint.is_static(argument):
        return ArgumentKind.STATIC, None
    return ArgumentKind.DYNAMIC, None


def taint_details(info: TaintInfo, sink: str) -> dict[str, Any]:
    """Keyword arguments for create_finding describing the data flow."""
    return {"source": info.source, "sink": sink, "taint_path": [*info.path, sink]}


def sanitized_message(info: TaintInfo, sink: str) -> str:
    return (
        f"Input from {info.source} reaches {sink} after {info.sanitizer}(); "
        "the analyzer cannot prove this sanitizer is sufficient."
    )
