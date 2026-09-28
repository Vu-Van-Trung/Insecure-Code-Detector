"""AST visitor that dispatches nodes to the rules interested in them."""

from __future__ import annotations

import ast
import logging
from collections import defaultdict

from app.analyzer.context import AnalysisContext
from app.models.finding import Finding
from app.rules.base import SecurityRule

logger = logging.getLogger(__name__)


class SecurityVisitor(ast.NodeVisitor):
    """Walks the whole tree once and runs every matching rule on each node."""

    def __init__(self, rules: list[SecurityRule], context: AnalysisContext) -> None:
        self.context = context
        self.findings: list[Finding] = []
        # Index rules by node type so each node only reaches relevant rules.
        self._rules_by_type: dict[type[ast.AST], list[SecurityRule]] = defaultdict(list)
        for rule in rules:
            for node_type in rule.node_types:
                self._rules_by_type[node_type].append(rule)

    def generic_visit(self, node: ast.AST) -> None:
        for rule in self._rules_by_type.get(type(node), ()):
            self._run_rule(rule, node)
        super().generic_visit(node)

    def _run_rule(self, rule: SecurityRule, node: ast.AST) -> None:
        # A bug in one rule must not abort the scan of the whole file.
        try:
            new_findings = list(rule.check(node, self.context) or ())
        except Exception:
            logger.exception(
                "Rule %s crashed on %s line %s",
                rule.id, self.context.filename, getattr(node, "lineno", "?"),
            )
            return
        for finding in new_findings:
            # Log only metadata; never the matched code, which may hold secrets.
            logger.info("Rule triggered: %s at %s:%d", finding.rule_id, finding.file, finding.line)
        self.findings.extend(new_findings)
