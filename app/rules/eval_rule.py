"""PY001 - Dangerous use of eval()."""

from app.models.finding import Severity
from app.rules.base import DangerousCallRule
from app.rules.registry import register_rule


@register_rule
class EvalRule(DangerousCallRule):
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
    # Only the builtin: ast.literal_eval and model.eval() resolve to other names.
    target_functions = frozenset({"eval", "builtins.eval"})
    dynamic_message = "Use of {name}() on a dynamic expression may allow arbitrary code execution."
    static_message = "Use of {name}() on a constant expression; eval() is unnecessary here."
    dynamic_confidence = 0.85
