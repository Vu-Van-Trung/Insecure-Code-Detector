"""End-to-end check of the fixture files in tests/vulnerable and tests/safe.

Each line expected to be reported carries a ``# expect: PY001`` marker
(``// expect: JV001`` in Java/C#/PHP; comma-separated for several rules).
The analyzer must report exactly those
(rule, line) pairs: nothing missing (false negatives) and nothing extra
(false positives).
"""

import re
from pathlib import Path

import pytest

from app.models.finding import Severity

FIXTURES = Path(__file__).parent
EXPECT_MARKER = re.compile(r"(?:#|//)\s*expect:\s*([A-Z0-9, ]+)")
EXTENSIONS = (".py", ".java", ".cs", ".php")


def expected_findings(path: Path) -> set[tuple[str, int]]:
    expected = set()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = EXPECT_MARKER.search(line)
        if match:
            expected |= {(rule.strip(), lineno) for rule in match.group(1).split(",") if rule.strip()}
    return expected


VULNERABLE_FILES = sorted(p for p in (FIXTURES / "vulnerable").iterdir() if p.suffix in EXTENSIONS)
SAFE_FILES = sorted(p for p in (FIXTURES / "safe").iterdir() if p.suffix in EXTENSIONS)


@pytest.mark.parametrize("path", VULNERABLE_FILES, ids=lambda p: p.name)
def test_vulnerable_fixture_reports_exactly_expected_findings(engine, path):
    result = engine.scan_path(path)
    assert result.errors == []
    expected = expected_findings(path)
    assert expected, f"{path.name} has no '# expect:' markers"
    assert {(f.rule_id, f.line) for f in result.findings} == expected


@pytest.mark.parametrize("path", SAFE_FILES, ids=lambda p: p.name)
def test_safe_fixture_has_no_findings(engine, path):
    """INFO notes (e.g. PY013 'import pickle') are allowed: they ask for review, not a fix."""
    result = engine.scan_path(path)
    assert result.errors == []
    assert [f for f in result.findings if f.severity is not Severity.INFO] == []


def test_every_vulnerable_fixture_has_a_safe_counterpart():
    safe_names = {p.name.replace("_safe", "") for p in SAFE_FILES}
    vulnerable_names = {p.name.replace("_vulnerable", "") for p in VULNERABLE_FILES}
    assert vulnerable_names == safe_names
