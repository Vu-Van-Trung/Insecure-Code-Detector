"""PY011 - Câu SQL được ghép bằng nối chuỗi / định dạng chuỗi (SQL injection)."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument, get_dotted_name, is_static_value, split_identifier, string_parts
from app.models.finding import Finding, Severity
from app.rules.base import ArgumentKind, CallRule, classify_argument
from app.rules.registry import register_rule

# Method gửi chuỗi SQL tới cơ sở dữ liệu (DB-API, SQLAlchemy, Django, pandas).
_SQL_SINK_METHODS = frozenset({"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"})
# Hàm bọc biến chuỗi thành đối tượng query mà KHÔNG escape gì (text(f"...") vẫn nguy hiểm).
_QUERY_WRAPPERS = frozenset({"sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text"})
# Tên đối tượng nhận khiến lời gọi nhiều khả năng thật sự nhắm tới database
# (vì "execute" là tên method rất phổ biến, không chỉ của database).
DB_RECEIVER_WORDS = frozenset({"cursor", "cur", "conn", "connection", "db", "database", "session", "engine", "sqlite", "pd"})

# Từ khóa SQL: phần chữ của chuỗi chứa chúng thì gần như chắc chắn là một câu SQL.
# Dùng chung với rule Java/C# (_ts_common.py).
SQL_KEYWORDS = re.compile(
    r"\b(select|insert|update|delete|replace|create|drop|alter|truncate|where|from|into|values|union|join)\b",
    re.IGNORECASE,
)


def unsafe_query_build(expr: ast.AST | None) -> bool:
    """True nếu ``expr`` tạo chuỗi bằng cách trộn chữ cố định với giá trị động.

    ``"... " + user_id``, ``f"... {user_id}"``, ``"... %s" % user_id`` và
    ``"... {}".format(user_id)``. Chuỗi hoàn toàn tĩnh thì an toàn.
    """
    if expr is None or is_static_value(expr):
        return False
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        # Có ít nhất một mảnh chuỗi hằng -> đang ghép chuỗi (không phải cộng số).
        return bool(string_parts(expr))
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return isinstance(expr.func.value, ast.Constant) and isinstance(expr.func.value.value, str)
    return False


def unwrap_query(query: ast.AST | None, context: AnalysisContext) -> ast.AST | None:
    """Bóc lớp bọc: ``text(f"...")`` -> f-string bên trong."""
    if isinstance(query, ast.Call) and context.call_name(query) in _QUERY_WRAPPERS:
        return get_argument(query, 0)
    return query


@register_rule
class SqlInjectionRule(CallRule):
    """PY011: tainted -> CRITICAL; không rõ nguồn nhưng ghép chuỗi SQL -> HIGH; query tham số hóa -> không báo."""

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

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        # Chỉ xét method (obj.execute(...)): đối tượng nhận thường là cursor/connection không suy ra được kiểu.
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in _SQL_SINK_METHODS:
            return
        method = node.func.attr
        query = get_argument(node, 0, "sql") or get_argument(node, 0, "query")
        query = unwrap_query(query, context)
        if query is None:
            return
        sink = f"{get_dotted_name(node.func) or '.' + method}()"

        kind, info = classify_argument(query, context)
        if kind is ArgumentKind.TAINTED:
            yield self.tainted_finding(
                node, context, info, sink,
                f"Untrusted input from {info.source} is used to build the SQL query passed to {sink}.",
                severity=Severity.CRITICAL,
            )
            return
        if kind is ArgumentKind.SANITIZED:
            yield self.sanitized_finding(node, context, info, sink)
            return
        if kind is ArgumentKind.STATIC:
            return  # vd chỉ ghép từ các hằng số

        # Không rõ nguồn (vd tham số hàm): báo chính hành vi ghép chuỗi SQL.
        built_at, literal_parts = self._find_unsafe_build(query, node, context)
        if built_at is None:
            return
        looks_like_sql = bool(SQL_KEYWORDS.search(" ".join(literal_parts)))
        # Không có từ khóa SQL và đối tượng nhận cũng không giống database -> có lẽ không phải SQL.
        if not looks_like_sql and not self._db_receiver(node.func.value):
            return

        # Nếu câu SQL được ghép ở dòng khác, ghi rõ số dòng để người đọc tìm.
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
        """Dòng nơi chuỗi query không an toàn được tạo, kèm các mảnh chữ của nó."""
        if unsafe_query_build(query):
            return call.lineno, string_parts(query)
        if not isinstance(query, ast.Name):
            return None, []

        # query = "SELECT ..." + user_id ; query += " AND ..." ; cursor.execute(query)
        assignments = context.assignments_before(query.id, call)
        # Bắt đầu từ phép gán thường (=) cuối cùng: các giá trị trước đó đã bị ghi đè.
        start = max(
            (i for i, stmt in enumerate(assignments) if not isinstance(stmt, ast.AugAssign)), default=0,
        )
        relevant = assignments[start:]
        parts = [part for stmt in relevant for part in string_parts(stmt.value)]
        for stmt in relevant:
            if isinstance(stmt, ast.AugAssign):
                # query += <giá trị động> cũng là ghép chuỗi không an toàn.
                unsafe = not is_static_value(stmt.value)
            else:
                unsafe = unsafe_query_build(unwrap_query(stmt.value, context))
            if unsafe:
                return stmt.lineno, parts
        return None, []

    @staticmethod
    def _db_receiver(receiver: ast.AST) -> bool:
        """True nếu tên đối tượng nhận (từ cuối) giống database, vd ``self.db_cursor``."""
        name = get_dotted_name(receiver)
        if not name:
            return False
        words = split_identifier(name.rsplit(".", 1)[-1])
        return any(word in DB_RECEIVER_WORDS for word in words)
