"""Base class every security rule inherits from."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from typing import ClassVar

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument, is_static_value
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
    ) -> Finding:
        """Build a Finding pre-filled with this rule's metadata and node location.

        ``severity`` may override the rule default when the context makes the
        issue more or less serious (e.g. untrusted input reaching a sink).
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
            code=context.get_line(line),
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

    The finding is graded by how the checked argument is built:

    * dynamic argument (variable, call, f-string with placeholders): the rule's
      default ``severity`` with ``dynamic_confidence``;
    * static argument (a literal fixed in the source): ``static_severity`` with
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

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not isinstance(node, ast.Call):
            return
        name = context.call_name(node)
        if name not in self.target_functions or context.is_shadowed_builtin(name):
            return
        argument = get_argument(node, self.argument_position, self.argument_keyword)
        if argument is None:
            return
        if is_static_value(argument):
            yield self.create_finding(
                node, context, self.static_message.format(name=name),
                severity=self.static_severity, confidence=self.static_confidence,
            )
        else:
            yield self.create_finding(
                node, context, self.dynamic_message.format(name=name),
                confidence=self.dynamic_confidence,
            )
