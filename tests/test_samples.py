"""Phase 8 - the demo samples behave as documented."""

from pathlib import Path

import pytest

from app.models.finding import Severity

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

EXPECTED_RULES = {
    "eval_vulnerable.py": {"PY001", "PY002"},
    "command_vulnerable.py": {"PY003", "PY004"},
    "sql_vulnerable.py": {"PY011"},
    "crypto_vulnerable.py": {"PY008", "PY009", "PY010"},
    "secret_vulnerable.py": {"PY007"},
    "pickle_vulnerable.py": {"PY005", "PY006"},
    "web_vulnerable.py": {"PY014", "PY015", "PY016", "PY017", "PY018"},
    "UserController_vulnerable.java": {"JV001", "JV002", "JV003", "JV005", "JV007", "JV008"},
    "AccountController_vulnerable.cs": {"CS001", "CS002", "CS003", "CS005", "CS008", "CS009"},
}
SOURCE_SUFFIXES = (".py", ".java", ".cs")


def sample_files(folder: str) -> list[Path]:
    return sorted(p for p in (SAMPLES / folder).iterdir() if p.suffix in SOURCE_SUFFIXES)


def test_all_required_samples_exist():
    assert {p.name for p in sample_files("vulnerable")} == set(EXPECTED_RULES)
    assert {p.name.replace("_safe", "_vulnerable") for p in sample_files("safe")} == set(EXPECTED_RULES)


@pytest.mark.parametrize("name, rules", sorted(EXPECTED_RULES.items()))
def test_vulnerable_sample_is_detected(engine, name, rules):
    result = engine.scan_path(SAMPLES / "vulnerable" / name)
    assert result.errors == []
    assert rules <= {f.rule_id for f in result.findings}


@pytest.mark.parametrize("path", sample_files("safe"), ids=lambda p: p.name)
def test_safe_sample_has_no_real_findings(engine, path):
    result = engine.scan_path(path)
    assert result.errors == []
    assert [f for f in result.findings if f.severity is not Severity.INFO] == []


def test_taint_samples_are_critical(engine):
    result = engine.scan_path(SAMPLES / "vulnerable")
    critical = {(f.rule_id, f.source) for f in result.findings if f.severity is Severity.CRITICAL}
    assert ("PY011", "request.args") in critical
    assert ("PY005", "request.cookies") in critical
    assert ("PY003", "input()") in critical
    assert ("PY018", "request.args") in critical
    assert ("JV002", "@RequestParam") in critical
    assert ("CS001", "[FromQuery]") in critical
