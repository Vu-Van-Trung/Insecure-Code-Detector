import pytest

from app.analyzer.engine import AnalyzerEngine

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
    engine = AnalyzerEngine(registry=demo_registry, disabled_rules={"TEST001"})
    assert engine.scan_source(VULNERABLE).findings == []


def test_crashing_rule_does_not_abort_scan(demo_registry, monkeypatch):
    from tests.conftest import DemoCallRule

    def boom(self, node, context):
        raise RuntimeError("bug in rule")

    monkeypatch.setattr(DemoCallRule, "check", boom)
    result = AnalyzerEngine(registry=demo_registry).scan_source(VULNERABLE)
    assert result.files_scanned == 1 and result.findings == []
