import pytest

from app.analyzer.engine import AnalyzerEngine
from app.config.settings import AnalyzerSettings

VULNERABLE = "import demo_module as dm\n\ndef f(x):\n    return dm.dangerous_demo(x)\n"
SAFE = "def f(x):\n    return x + 1\n"


def test_scan_source_reports_finding_with_location(demo_engine):
    result = demo_engine.scan_source(VULNERABLE, "sample.py")
    assert result.files_scanned == 1
    assert result.lines_scanned == 4
    [finding] = result.findings
    assert finding.rule_id == "TEST001"
    assert (finding.file, finding.line, finding.column) == ("sample.py", 4, 11)
    assert finding.code == "return dm.dangerous_demo(x)"
    assert finding.message == "Call to demo_module.dangerous_demo()"


def test_safe_source_has_no_findings(demo_engine):
    assert demo_engine.scan_source(SAFE).findings == []


def test_syntax_error_is_recorded_not_raised(demo_engine):
    result = demo_engine.scan_source("x = 1\nif :\n", "bad.py")
    assert result.files_scanned == 0
    [error] = result.errors
    assert (error.file, error.error_type, error.line) == ("bad.py", "SyntaxError", 2)


def test_scan_directory_skips_excluded_dirs_and_continues_after_errors(demo_engine, tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "vuln.py").write_text(VULNERABLE)
    (tmp_path / "safe.py").write_text(SAFE)
    (tmp_path / "broken.py").write_text("def (:\n")
    (tmp_path / "notes.txt").write_text("dangerous_demo()")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text(VULNERABLE)

    result = demo_engine.scan_path(tmp_path)

    assert result.files_scanned == 2
    assert len(result.errors) == 1 and result.errors[0].file.endswith("broken.py")
    assert [f.file.endswith("pkg/vuln.py") for f in result.findings] == [True]


def test_scan_single_file(demo_engine, tmp_path):
    target = tmp_path / "one.py"
    target.write_text(VULNERABLE)
    result = demo_engine.scan_path(target)
    assert result.files_scanned == 1 and len(result.findings) == 1


def test_scan_non_python_file_is_rejected(demo_engine, tmp_path):
    target = tmp_path / "script.sh"
    target.write_text("rm -rf /")
    result = demo_engine.scan_path(target)
    assert result.files_scanned == 0
    assert result.errors[0].error_type == "UnsupportedFile"


def test_missing_target_raises(demo_engine, tmp_path):
    with pytest.raises(FileNotFoundError):
        demo_engine.scan_path(tmp_path / "nope")


def test_disabled_rule_produces_no_findings(demo_registry):
    settings = AnalyzerSettings.load().with_changes(disabled_rules=frozenset({"TEST001"}))
    engine = AnalyzerEngine(registry=demo_registry, settings=settings)
    assert engine.scan_source(VULNERABLE).findings == []


def test_crashing_rule_does_not_abort_scan(demo_registry, monkeypatch):
    from tests.conftest import DemoCallRule

    def boom(self, node, context):
        raise RuntimeError("bug in rule")

    monkeypatch.setattr(DemoCallRule, "check", boom)
    result = AnalyzerEngine(registry=demo_registry).scan_source(VULNERABLE)
    assert result.files_scanned == 1 and result.findings == []


def test_directory_with_several_languages(engine, tmp_path):
    (tmp_path / "a.py").write_text("eval(input())\n")
    (tmp_path / "B.java").write_text('class B { void m() throws Exception { Runtime.getRuntime().exec("ls"); } }\n')
    (tmp_path / "C.cs").write_text("class C { void M() { var h = System.Security.Cryptography.MD5.Create(); } }\n")
    (tmp_path / "notes.md").write_text("eval(x)\n")
    result = engine.scan_path(tmp_path)
    assert result.files_scanned == 3
    assert {f.language for f in result.files} == {"python", "java", "csharp"}
    assert {f.rule_id for f in result.findings} == {"PY001", "JV001", "CS005"}


def test_missing_tree_sitter_only_affects_java_and_csharp(engine, tmp_path, monkeypatch):
    from app.analyzer.ts import adapters

    def unavailable(language):
        raise adapters.LanguageUnavailable("tree-sitter is not installed")

    monkeypatch.setattr(adapters, "get_adapter", unavailable)
    (tmp_path / "a.py").write_text("eval(x)\n")
    (tmp_path / "B.java").write_text("class B {}\n")
    result = engine.scan_path(tmp_path)
    assert [f.rule_id for f in result.findings] == ["PY001"]
    assert [e.error_type for e in result.errors] == ["LanguageUnavailable"]
