"""PY002 - exec()."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code",
    [
        "code = input()\nexec(code)",
        "exec(request.form['code'])",
        "exec(f'x = {value}')",
        "exec(open(path).read())",
        "exec(source, {}, {})",
    ],
)
def test_dynamic_exec_is_critical(find, code):
    [finding] = find(code, "PY002")
    assert finding.severity is Severity.CRITICAL
    assert finding.cwe == "CWE-95"
    assert finding.confidence >= 0.8


def test_constant_exec_is_low_severity(find):
    [finding] = find("exec('import this')", "PY002")
    assert finding.severity is Severity.LOW


@pytest.mark.parametrize(
    "code",
    [
        "cursor.exec(query)",  # a method named exec
        "import subprocess\nsubprocess.run(['ls'])",
        "executor.submit(job)",
        "exec_count = 3",
    ],
)
def test_safe_code_is_not_flagged(find, code):
    assert find(code, "PY002") == []


def test_eval_and_exec_are_reported_by_their_own_rule(find):
    code = "eval(a)\nexec(b)"
    assert [f.line for f in find(code, "PY001")] == [1]
    assert [f.line for f in find(code, "PY002")] == [2]
