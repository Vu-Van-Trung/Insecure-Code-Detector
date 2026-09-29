"""PY011 - SQL query built with string concatenation / formatting."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument, get_dotted_name, is_static_value, split_identifier, string_parts
from app.models.finding import Finding, Severity
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
from app.rules.registry import register_rule

# Methods that send a SQL string to the database (DB-API, SQLAlchemy, Django, pandas).
_SQL_SINK_METHODS = frozenset({"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"})
# Wrappers that turn a string into a query object without escaping anything.
_QUERY_WRAPPERS = frozenset({"sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text"})
# Receiver names that make it likely the call really targets a database.
_DB_RECEIVER_WORDS = frozenset({"cursor", "cur", "conn", "connection", "db", "database", "session", "engine", "sqlite", "pd"})

_SQL_KEYWORDS = re.compile(
    r"\b(select|insert|update|delete|replace|create|drop|alter|truncate|where|from|into|values|union|join)\b",
    re.IGNORECASE,
)


def unsafe_query_build(expr: ast.AST | None) -> bool:
    """True if ``expr`` builds a string by mixing literals with dynamic values.

    ``"... " + user_id``, ``f"... {user_id}"``, ``"... %s" % user_id`` and
    ``"... {}".format(user_id)``. Fully static strings are safe.
    """
    if expr is None or is_static_value(expr):
        return False
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return bool(string_parts(expr))
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return isinstance(expr.func.value, ast.Constant) and isinstance(expr.func.value.value, str)
    return False


def unwrap_query(query: ast.AST | None, context: AnalysisContext) -> ast.AST | None:
    """``text(f"...")`` -> the inner f-string."""
    if isinstance(query, ast.Call) and context.call_name(query) in _QUERY_WRAPPERS:
        return get_argument(query, 0)
    return query


@register_rule
class SqlInjectionRule(SecurityRule):
    id = "PY011"
    name = "SQL query built with string concatenation"
    description = (
        "The SQL statement is assembled from strings and variables, so a value containing "
        "quotes or SQL syntax (e.g. \"1 OR 1=1\") changes the meaning of the query. This "
        "allows reading, modifying or deleting data (SQL injection)."
    )
    severity = Severity.HIGH
    cwe = "CWE-89"
    category = "SQL Injection"
    recommendation = (
        "Use parameterized queries and pass values separately, e.g. "
        "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,)). "
        "Never format values into the SQL string."
    )

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            return
        method = node.func.attr
        if method not in _SQL_SINK_METHODS:
            return
        query = get_argument(node, 0, "sql") or get_argument(node, 0, "query")
        query = unwrap_query(query, context)
        if query is None:
            return
        sink = f"{get_dotted_name(node.func) or '.' + method}()"

        kind, info = classify_argument(query, context)
        if kind is ArgumentKind.TAINTED:
            yield self.create_finding(
                node, context, f"Untrusted input from {info.source} is used to build the SQL query passed to {sink}.",
                severity=Severity.CRITICAL, confidence=TAINTED_CONFIDENCE, **taint_details(info, sink),
            )
            return
        if kind is ArgumentKind.SANITIZED:
            yield self.create_finding(
                node, context, sanitized_message(info, sink),
                severity=SANITIZED_SEVERITY, confidence=SANITIZED_CONFIDENCE, **taint_details(info, sink),
            )
            return
        if kind is ArgumentKind.STATIC:
            return  # e.g. built only from constants

        # Origin unknown (e.g. a function parameter): report string building itself.
        built_at, literal_parts = self._find_unsafe_build(query, node, context)
        if built_at is None:
            return
        looks_like_sql = bool(_SQL_KEYWORDS.search(" ".join(literal_parts)))
        if not looks_like_sql and not self._db_receiver(node.func.value):
            return

        where = "" if built_at == node.lineno else f" (built on line {built_at})"
        if looks_like_sql:
            yield self.create_finding(
                node, context, f"SQL query built from dynamic values{where} is passed to {sink}.",
                confidence=0.85, sink=sink,
            )
        else:
            yield self.create_finding(
                node, context, f"Dynamically built string{where} is passed to {sink}.",
                severity=Severity.MEDIUM, confidence=0.55, sink=sink,
            )

    @staticmethod
    def _find_unsafe_build(
        query: ast.AST, call: ast.Call, context: AnalysisContext,
    ) -> tuple[int | None, list[str]]:
        """Line where an unsafe query string is built, plus its literal fragments."""
        if unsafe_query_build(query):
            return call.lineno, string_parts(query)
        if not isinstance(query, ast.Name):
            return None, []

        # query = "SELECT ..." + user_id ; query += " AND ..." ; cursor.execute(query)
        assignments = context.assignments_before(query.id, call)
        # Start from the last plain assignment: earlier values were overwritten.
        start = max(
            (i for i, stmt in enumerate(assignments) if not isinstance(stmt, ast.AugAssign)), default=0,
        )
        relevant = assignments[start:]
        parts = [part for stmt in relevant for part in string_parts(stmt.value)]
        for stmt in relevant:
            if isinstance(stmt, ast.AugAssign):
                unsafe = not is_static_value(stmt.value)
            else:
                unsafe = unsafe_query_build(unwrap_query(stmt.value, context))
            if unsafe:
                return stmt.lineno, parts
        return None, []

    @staticmethod
    def _db_receiver(receiver: ast.AST) -> bool:
        name = get_dotted_name(receiver)
        if not name:
            return False
        words = split_identifier(name.rsplit(".", 1)[-1])
        return any(word in _DB_RECEIVER_WORDS for word in words)
