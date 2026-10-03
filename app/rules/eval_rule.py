"""PY001 - Dùng eval() nguy hiểm (code injection)."""

from app.models.finding import Severity
from app.rules.base import DangerousCallRule
from app.rules.registry import register_rule


@register_rule
class EvalRule(DangerousCallRule):
    """PY001: chỉ khai báo thuộc tính - logic chấm điểm nằm ở lớp cha DangerousCallRule.

    ``eval(input())`` -> CRITICAL; ``eval(expr)`` (không rõ nguồn) -> CRITICAL theo
    severity mặc định; ``eval("1 + 2")`` -> LOW.
    """

    id = "PY001"
    name = "Dangerous use of eval()"
    description = (
        "eval() evaluates an arbitrary Python expression. If any part of the "
        "expression comes from user input, an attacker can run arbitrary code "
        "(e.g. __import__('os').system('...')) with the privileges of the application."
    )
    severity = Severity.CRITICAL
    cwe = "CWE-95"
    category = "Code Injection"
    recommendation = (
        "Avoid eval(). Use ast.literal_eval() for Python literals, json.loads() for "
        "data, or an explicit mapping of allowed operations."
    )
    # Chỉ builtin eval: ast.literal_eval và model.eval() (PyTorch) có tên đầy đủ khác nên không bị báo nhầm.
    target_functions = frozenset({"eval", "builtins.eval"})
    dynamic_message = "Use of {name}() on a dynamic expression may allow arbitrary code execution."
    static_message = "Use of {name}() on a constant expression; eval() is unnecessary here."
    dynamic_confidence = 0.85
