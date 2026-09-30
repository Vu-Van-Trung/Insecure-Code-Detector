"""Phase 5 - severity (context, overrides, thresholds) and confidence."""

import json

import pytest

from app.analyzer.engine import AnalyzerEngine
from app.config.loader import ConfigError
from app.config.settings import AnalyzerSettings, RULES_CONFIG
from app.models.finding import Severity
from app.rules.registry import load_builtin_rules

MIXED = """
import os, hashlib
os.system(input())
os.system("ls")
hashlib.md5(data)
"""


def severities(result) -> list[str]:
    return [f.severity.value for f in result.findings]


def test_severity_depends_on_context(engine):
    """Same rule, different severity: tainted vs constant argument."""
    result = engine.scan_source(MIXED)
    by_line = {f.line: f for f in result.findings}
    assert by_line[3].severity is Severity.CRITICAL
    assert by_line[4].severity is Severity.LOW
    assert by_line[5].severity is Severity.MEDIUM


def test_not_everything_is_critical():
    levels = {rule.severity for rule in load_builtin_rules()}
    assert {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO} <= levels


def test_confidence_reflects_certainty(engine):
    result = engine.scan_source(MIXED)
    by_line = {f.line: f for f in result.findings}
    assert by_line[3].confidence == 0.95  # untrusted input proven to reach the sink
    assert by_line[4].confidence == 0.6   # constant command
    assert all(0.0 <= f.confidence <= 1.0 for f in result.findings)


def test_severity_override():
    settings = AnalyzerSettings.load().with_changes(severity_overrides={"PY008": Severity.LOW})
    result = AnalyzerEngine(settings=settings).scan_source(MIXED)
    assert {f.line: f.severity for f in result.findings}[5] is Severity.LOW


def test_min_severity_filters_and_counts():
    settings = AnalyzerSettings.load().with_changes(min_severity=Severity.MEDIUM)
    result = AnalyzerEngine(settings=settings).scan_source(MIXED)
    assert severities(result) == ["CRITICAL", "MEDIUM"]
    assert result.filtered_count == 1


def test_min_confidence_filters():
    settings = AnalyzerSettings.load().with_changes(min_confidence=0.9)
    result = AnalyzerEngine(settings=settings).scan_source(MIXED)
    assert [f.line for f in result.findings] == [3]
    assert result.filtered_count == 2


def test_highest_severity(engine):
    assert engine.scan_source(MIXED).highest_severity() is Severity.CRITICAL
    assert engine.scan_source("x = 1").highest_severity() is None


def write_config(tmp_path, rules: dict | None = None, severity: dict | None = None):
    rules_path, severity_path = tmp_path / "rules.json", tmp_path / "severity.json"
    base_rules = json.loads(RULES_CONFIG.read_text(encoding="utf-8"))
    rules_path.write_text(json.dumps({**base_rules, **(rules or {})}), encoding="utf-8")
    severity_path.write_text(json.dumps(severity or {"overrides": {}}), encoding="utf-8")
    return rules_path, severity_path


def test_severity_json_overrides_are_loaded(tmp_path):
    rules_path, severity_path = write_config(tmp_path, severity={"overrides": {"py009": "low"}})
    settings = AnalyzerSettings.load(rules_path=rules_path, severity_path=severity_path)
    assert settings.severity_overrides == {"PY009": Severity.LOW}


@pytest.mark.parametrize(
    "rules, severity, message",
    [
        ({"min_confidence": 2}, None, "min_confidence"),
        ({"max_file_size": -1}, None, "max_file_size"),
        ({"min_severity": "SEVERE"}, None, "Unknown severity"),
        ({"disabled_rules": ["eval"]}, None, "Invalid rule id"),
        (None, {"overrides": {"PY001": "NOPE"}}, "Unknown severity"),
        (None, {"overrides": ["PY001"]}, "'overrides'"),
    ],
)
def test_invalid_rules_or_severity_config(tmp_path, rules, severity, message):
    rules_path, severity_path = write_config(tmp_path, rules, severity)
    with pytest.raises(ConfigError, match=message):
        AnalyzerSettings.load(rules_path=rules_path, severity_path=severity_path)


def test_excluded_dirs_come_from_rules_json(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text("eval(x)\n")
    rules_path, severity_path = write_config(tmp_path, {"excluded_dirs": ["vendor"]})
    engine = AnalyzerEngine(settings=AnalyzerSettings.load(rules_path=rules_path, severity_path=severity_path))
    assert engine.scan_path(tmp_path).files_scanned == 0
