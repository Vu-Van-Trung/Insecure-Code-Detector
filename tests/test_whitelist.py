"""Phase 5 - whitelist and inline suppression.

Suppression only hides warnings; these tests also check that suppressed
findings stay visible in the result (counted, not silently dropped).
"""

import json
import textwrap

import pytest

from app.analyzer.engine import AnalyzerEngine
from app.analyzer.suppression import ALL_RULES, is_suppressed, parse_inline_ignores
from app.config.loader import ConfigError
from app.config.settings import AnalyzerSettings, Whitelist


def engine_with(whitelist: dict | None = None, **changes) -> AnalyzerEngine:
    settings = AnalyzerSettings.load()
    if whitelist is not None:
        settings = settings.with_changes(whitelist=Whitelist.from_dict(whitelist))
    return AnalyzerEngine(settings=settings.with_changes(**changes))


def scan(code: str, engine: AnalyzerEngine | None = None):
    return (engine or engine_with()).scan_source(textwrap.dedent(code), "app.py")


# =========================================================== inline comments


def test_parse_inline_ignores_same_line_and_next_line():
    source = textwrap.dedent("""
        x = eval(a)  # analyzer-ignore: PY001
        # analyzer-ignore: PY002, py003
        exec(b)
        y = 1  # analyzer-ignore
    """)
    ignores = parse_inline_ignores(source)
    assert ignores[2] == {"PY001"}
    assert ignores[4] == {"PY002", "PY003"}
    assert ignores[5] == {ALL_RULES}


def test_marker_inside_string_is_not_a_comment():
    assert parse_inline_ignores("x = '# analyzer-ignore: PY001'\n") == {}


def test_is_suppressed():
    ignores = {3: frozenset({"PY001"}), 5: frozenset({ALL_RULES})}
    assert is_suppressed("PY001", 3, ignores)
    assert not is_suppressed("PY002", 3, ignores)
    assert is_suppressed("PY011", 5, ignores)
    assert not is_suppressed("PY001", 4, ignores)


def test_inline_ignore_suppresses_only_listed_rule():
    code = """
    # analyzer-ignore: PY001
    result = eval(expression)
    exec(code)
    """
    result = scan(code)
    assert [f.rule_id for f in result.findings] == ["PY002"]
    assert [f.rule_id for f in result.suppressed] == ["PY001"]
    assert result.summary()["suppressed"] == 1


def test_inline_ignore_with_wrong_rule_id_does_not_suppress():
    result = scan("eval(x)  # analyzer-ignore: PY002\n")
    assert [f.rule_id for f in result.findings] == ["PY001"]
    assert result.suppressed == []


def test_inline_ignores_can_be_disabled():
    result = scan("eval(x)  # analyzer-ignore: PY001\n", engine_with(honor_inline_ignores=False))
    assert [f.rule_id for f in result.findings] == ["PY001"]


# =========================================================== whitelist.json


def test_whitelisted_files_are_skipped(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_eval.py").write_text("eval(x)\n")
    (tmp_path / "app.py").write_text("eval(x)\n")
    result = engine_with({"files": ["tests/test_*.py"]}).scan_path(tmp_path)
    assert result.files_scanned == 1
    assert [f.file.rsplit("/", 1)[-1] for f in result.findings] == ["app.py"]
    assert result.skipped_files[0].endswith("tests/test_eval.py")


def test_disabled_rules_in_whitelist():
    result = scan("import random\ntoken = random.random()\neval(x)", engine_with({"disabled_rules": ["PY009"]}))
    assert [f.rule_id for f in result.findings] == ["PY001"]


def test_allowed_secrets_regex():
    code = 'API_KEY = "test_9f86d081884c7d659a2feaa0c55ad015"\nTOKEN = "a8f5f167f44f4964e6c998dee827110c"'
    result = scan(code, engine_with({"allowed_secrets": [r"test_[0-9a-f]{32}"]}))
    assert [f.line for f in result.findings] == [2]


def test_whitelist_file_matching():
    whitelist = Whitelist(files=("tests/test_*.py", "legacy/*"))
    assert whitelist.is_file_ignored("tests/test_eval.py")
    assert whitelist.is_file_ignored("E:/project/tests/test_eval.py")
    assert whitelist.is_file_ignored("legacy/old.py")
    assert not whitelist.is_file_ignored("app/tests_helper.py")


def test_whitelist_load_from_file(tmp_path):
    path = tmp_path / "whitelist.json"
    path.write_text(json.dumps({"files": ["a.py"], "disabled_rules": ["py009"]}), encoding="utf-8")
    whitelist = Whitelist.load(path)
    assert whitelist.disabled_rules == {"PY009"}


@pytest.mark.parametrize(
    "data, message",
    [
        ({"files": "a.py"}, "'files'"),
        ({"disabled_rules": ["not a rule"]}, "Invalid rule id"),
        ({"allowed_secrets": ["("]}, "Invalid regex"),
    ],
)
def test_invalid_whitelist(data, message):
    with pytest.raises(ConfigError, match=message):
        Whitelist.from_dict(data)


def test_project_whitelist_is_valid():
    """The whitelist.json shipped with the project must load."""
    from app.config.settings import DEFAULT_WHITELIST

    assert Whitelist.load(DEFAULT_WHITELIST).files
