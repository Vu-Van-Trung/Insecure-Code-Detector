"""Phase 5 - blacklist-driven rules PY012 (functions) and PY013 (modules)."""

import pytest

from app.analyzer.engine import AnalyzerEngine
from app.config.loader import ConfigError
from app.config.settings import AnalyzerSettings, Blacklist
from app.models.finding import Severity


def engine_with_blacklist(data: dict) -> AnalyzerEngine:
    return AnalyzerEngine(settings=AnalyzerSettings.load().with_changes(blacklist=Blacklist.from_dict(data)))


def test_blacklisted_function_from_default_file(find):
    [finding] = find("import marshal\nmarshal.loads(blob)", "PY012")
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-502"  # CWE taken from the blacklist entry


def test_generic_finding_is_dropped_when_specific_rule_reports_same_call(find, engine):
    result = engine.scan_source("eval(user_input)\n")
    assert [f.rule_id for f in result.findings] == ["PY001"]


def test_generic_finding_is_kept_when_specific_rule_is_disabled():
    settings = AnalyzerSettings.load().with_changes(disabled_rules=frozenset({"PY001"}))
    result = AnalyzerEngine(settings=settings).scan_source("eval(user_input)\n")
    assert [f.rule_id for f in result.findings] == ["PY012"]


def test_new_function_can_be_added_without_code_changes():
    engine = engine_with_blacklist({"dangerous_functions": [
        {"name": "legacy.crypto.encrypt", "severity": "HIGH", "cwe": "CWE-327", "reason": "uses DES"},
    ]})
    [finding] = engine.scan_source("from legacy.crypto import encrypt\nencrypt(data)\n").findings
    assert (finding.rule_id, finding.severity, finding.cwe) == ("PY012", Severity.HIGH, "CWE-327")
    assert "uses DES" in finding.message


def test_plain_string_entries_use_defaults():
    engine = engine_with_blacklist({"dangerous_functions": ["os.remove"], "dangerous_modules": ["ftplib"]})
    result = engine.scan_source("import os\nimport ftplib\nos.remove(path)\n")
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["PY012"].severity is Severity.MEDIUM
    assert by_rule["PY013"].severity is Severity.INFO


@pytest.mark.parametrize(
    "code",
    ["import pickle", "import pickle as pk", "from pickle import loads", "import telnetlib, os"],
)
def test_blacklisted_module_imports(find, code):
    assert len(find(code, "PY013")) == 1


def test_submodule_import_matches_parent_entry():
    engine = engine_with_blacklist({"dangerous_modules": ["xml"]})
    assert [f.rule_id for f in engine.scan_source("import xml.etree.ElementTree\n").findings] == ["PY013"]


@pytest.mark.parametrize("code", ["import json", "from . import pickle_utils", "import pickles", "json.loads(x)"])
def test_non_blacklisted_code(find, code):
    assert find(code, "PY012") == [] and find(code, "PY013") == []


@pytest.mark.parametrize(
    "data, message",
    [
        ({"dangerous_functions": "eval"}, "must be a list"),
        ({"dangerous_functions": [{"severity": "HIGH"}]}, "needs a 'name'"),
        ({"dangerous_modules": [{"name": "x", "severity": "URGENT"}]}, "Unknown severity"),
    ],
)
def test_invalid_blacklist(data, message):
    with pytest.raises(ConfigError, match=message):
        Blacklist.from_dict(data)


def test_project_blacklist_contains_spec_entries():
    from app.config.settings import DEFAULT_BLACKLIST

    blacklist = Blacklist.load(DEFAULT_BLACKLIST)
    assert {"eval", "exec", "os.system"} <= blacklist.functions.keys()
    assert "pickle" in blacklist.modules
