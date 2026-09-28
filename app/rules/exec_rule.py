"""PY002 - Dangerous use of exec()."""

from app.models.finding import Severity
from app.rules.base import DangerousCallRule
from app.rules.registry import register_rule


@register_rule
class ExecRule(DangerousCallRule):
    id = "PY002"
    name = "Dangerous use of exec()"
    description = (
        "exec() executes arbitrary Python statements. Passing data that an "
        "attacker can influence lets them run any code inside the application process."
    )
    severity = Severity.CRITICAL
    cwe = "CWE-95"
    category = "Code Injection"
    recommendation = (
        "Avoid exec(). Replace dynamic code with regular functions, a dispatch "
        "dictionary, or a safe configuration format such as JSON."
    )
    target_functions = frozenset({"exec", "builtins.exec"})
    dynamic_message = "Use of {name}() on dynamic code may allow arbitrary code execution."
    static_message = "Use of {name}() on constant code; exec() is unnecessary here."
    dynamic_confidence = 0.85
