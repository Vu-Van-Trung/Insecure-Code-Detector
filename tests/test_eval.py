"""PY001 - eval()."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code",
    [
        "user_input = input()\nresult = eval(user_input)",
        "eval(input('expr: '))",
        "eval(f'{a} + {b}')",
        "eval('1 + ' + value)",
        "import builtins\nbuiltins.eval(expr)",
        "result = eval(request.args.get('q'))",
    ],
)
def test_dynamic_eval_is_critical(find, code):
    findings = find(code, "PY001")
    assert findings
    finding = findings[-1]
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence >= 0.8
    assert finding.cwe == "CWE-95"
    assert finding.category == "Code Injection"


def test_finding_location_and_code_snippet(find):
    [finding] = find("x = 1\n\ndef f(data):\n    return eval(data)\n", "PY001")
    assert (finding.line, finding.column) == (4, 11)
    assert finding.code == "return eval(data)"
    assert finding.recommendation


def test_constant_eval_is_low_severity(find):
    [finding] = find("value = eval('1 + 2')", "PY001")
    assert finding.severity is Severity.LOW
    assert finding.confidence < 0.8


@pytest.mark.parametrize(
    "code",
    [
        "import ast\nast.literal_eval(user_input)",  # the safe alternative
        "model.eval()",  # e.g. PyTorch: a method, not the builtin
        "self.eval(data)",
        "text = 'eval(user_input)'",  # only a string
        "# eval(user_input)",  # only a comment
    ],
)
def test_safe_code_is_not_flagged(find, code):
    assert find(code, "PY001") == []


def test_locally_defined_eval_is_not_flagged(find):
    code = """
    def eval(expression):
        return calculator.compute(expression)

    eval(user_input)
    """
    assert find(code, "PY001") == []


def test_eval_imported_from_other_module_is_not_builtin(find):
    assert find("from mylib import eval\neval(data)", "PY001") == []
