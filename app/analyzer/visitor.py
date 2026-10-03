"""Bộ duyệt AST (Visitor pattern) phân phối từng node tới các rule quan tâm đến loại node đó."""

from __future__ import annotations

import ast
import logging
from collections import defaultdict

from app.analyzer.context import AnalysisContext
from app.models.finding import Finding
from app.rules.base import SecurityRule

logger = logging.getLogger(__name__)


class SecurityVisitor(ast.NodeVisitor):
    """Duyệt toàn bộ cây AST đúng MỘT lần và chạy mọi rule phù hợp trên từng node.

    Thay vì mỗi rule tự duyệt cây (N rule = N lần duyệt), visitor duyệt một lần và
    gọi các rule đã đăng ký cho loại node hiện tại.
    """

    def __init__(self, rules: list[SecurityRule], context: AnalysisContext) -> None:
        self.context = context
        self.findings: list[Finding] = []
        # Lập chỉ mục rule theo loại node (ast.Call -> [PY001, PY003, ...]) để mỗi
        # node chỉ được đưa tới các rule liên quan, không phải hỏi tất cả rule.
        self._rules_by_type: dict[type[ast.AST], list[SecurityRule]] = defaultdict(list)
        for rule in rules:
            for node_type in rule.node_types:
                self._rules_by_type[node_type].append(rule)

    def generic_visit(self, node: ast.AST) -> None:
        """Được NodeVisitor gọi cho mọi node: chạy các rule của loại node này rồi đi tiếp vào node con."""
        for rule in self._rules_by_type.get(type(node), ()):
            self._run_rule(rule, node)
        super().generic_visit(node)

    def _run_rule(self, rule: SecurityRule, node: ast.AST) -> None:
        """Chạy một rule trên một node và thu thập finding."""
        # Lỗi (bug) trong một rule không được làm hỏng việc scan cả file:
        # ghi log lỗi rồi bỏ qua rule đó tại node này, các rule khác vẫn chạy.
        try:
            new_findings = list(rule.check(node, self.context) or ())
        except Exception:
            logger.exception(
                "Rule %s crashed on %s line %s",
                rule.id, self.context.filename, getattr(node, "lineno", "?"),
            )
            return
        for finding in new_findings:
            # Chỉ log metadata; không bao giờ log đoạn code khớp vì có thể chứa secret.
            logger.info("Rule triggered: %s at %s:%d", finding.rule_id, finding.file, finding.line)
        self.findings.extend(new_findings)
