"""PY012 / PY013 - functions and modules listed in blacklist.json.

These generic rules let users flag additional APIs without writing code. When a
specific rule (e.g. PY001 for eval) reports the same location, the engine drops
the generic duplicate.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from typing import TYPE_CHECKING

from app.analyzer.context import AnalysisContext
from app.config.settings import BlacklistEntry
from app.models.finding import Finding, Severity
from app.rules.base import SecurityRule
from app.rules.registry import register_rule

if TYPE_CHECKING:
    from app.config.settings import AnalyzerSettings


@register_rule
class BlacklistedFunctionRule(SecurityRule):
    id = "PY012"
    name = "Call to blacklisted function"
    description = "The called function is listed in blacklist.json as dangerous for this project."
    severity = Severity.MEDIUM
    cwe = "CWE-676"
    category = "Dangerous Function"
    recommendation = "Review whether this call is necessary and replace it with a safer alternative."
    generic = True

    def __init__(self) -> None:
        self.entries: dict[str, BlacklistEntry] = {}

    def configure(self, settings: AnalyzerSettings) -> None:
        self.entries = settings.blacklist.functions

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not isinstance(node, ast.Call) or not self.entries:
            return
        name = context.call_name(node)
        entry = self.entries.get(name) if name else None
        if entry is None or context.is_shadowed_builtin(name):
            return
        yield self.create_finding(
            node, context, f"Call to blacklisted function {name}(): {entry.reason}.",
            severity=entry.severity, confidence=0.6, cwe=entry.cwe,
        )


@register_rule
class BlacklistedModuleRule(SecurityRule):
    id = "PY013"
    name = "Import of blacklisted module"
    description = (
        "The imported module is listed in blacklist.json. Importing it is not a "
        "vulnerability by itself, but every use of it deserves a review."
    )
    severity = Severity.INFO
    cwe = "CWE-676"
    category = "Dangerous Module"
    recommendation = "Check how the module is used; prefer the safer alternative named in the blacklist reason."
    node_types = (ast.Import, ast.ImportFrom)
    generic = True

    def __init__(self) -> None:
        self.entries: dict[str, BlacklistEntry] = {}

    def configure(self, settings: AnalyzerSettings) -> None:
        self.entries = settings.blacklist.modules

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not self.entries:
            return
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            modules = [node.module]
        else:
            return
        for module in modules:
            entry = self._match(module)
            if entry is not None:
                yield self.create_finding(
                    node, context, f"Import of blacklisted module '{module}': {entry.reason}.",
                    severity=entry.severity, confidence=0.5, cwe=entry.cwe,
                )

    def _match(self, module: str) -> BlacklistEntry | None:
        """'xml.etree' matches an entry for 'xml' as well as 'xml.etree'."""
        parts = module.split(".")
        for i in range(len(parts), 0, -1):
            entry = self.entries.get(".".join(parts[:i]))
            if entry is not None:
                return entry
        return None
