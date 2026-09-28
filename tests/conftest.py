"""Shared fixtures.

Phase 1 has no real rules yet, so the engine is exercised with a small test
rule that flags calls to ``dangerous_demo()`` (by any import alias).
"""

from __future__ import annotations

import ast
import textwrap
from collections.abc import Callable, Iterator

import pytest

from app.analyzer.context import AnalysisContext
from app.analyzer.engine import AnalyzerEngine
from app.models.finding import Finding, Severity
from app.rules.base import SecurityRule
from app.rules.registry import RuleRegistry


class DemoCallRule(SecurityRule):
    id = "TEST001"
    name = "Call to dangerous_demo()"
    description = "Test rule used to exercise the engine."
    severity = Severity.HIGH
    cwe = "CWE-000"
    category = "Test"
    recommendation = "Do not call dangerous_demo()."

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        assert isinstance(node, ast.Call)
        name = context.call_name(node)
        if name in {"dangerous_demo", "demo_module.dangerous_demo"}:
            yield self.create_finding(node, context, f"Call to {name}()", confidence=0.9)


@pytest.fixture
def demo_registry() -> RuleRegistry:
    registry = RuleRegistry()
    registry.register(DemoCallRule)
    return registry


@pytest.fixture
def demo_engine(demo_registry: RuleRegistry) -> AnalyzerEngine:
    return AnalyzerEngine(registry=demo_registry)


@pytest.fixture(scope="session")
def engine() -> AnalyzerEngine:
    """Engine with all built-in rules."""
    return AnalyzerEngine()


@pytest.fixture
def find(engine: AnalyzerEngine) -> Callable[[str, str], list[Finding]]:
    """``find(code, "PY001")`` -> findings of that rule for the given source."""

    def _find(source: str, rule_id: str) -> list[Finding]:
        result = engine.scan_source(textwrap.dedent(source), "snippet.py")
        assert not result.errors, result.errors
        return [finding for finding in result.findings if finding.rule_id == rule_id]

    return _find
