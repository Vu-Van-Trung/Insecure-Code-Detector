import io
import json

import pytest

from app import cli
from app.analyzer.engine import AnalyzerEngine

VULNERABLE = "dangerous_demo('x')\n"


@pytest.fixture(autouse=True)
def use_demo_rules(monkeypatch, demo_registry):
    """Run the CLI with the demo rule and without writing log files."""
    monkeypatch.setattr(
        cli, "AnalyzerEngine", lambda settings=None: AnalyzerEngine(registry=demo_registry, settings=settings),
    )
    monkeypatch.setattr(cli, "load_builtin_rules", lambda: demo_registry)
    monkeypatch.setattr(cli, "setup_logging", lambda: None)


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_scan_text_output(tmp_path):
    (tmp_path / "a.py").write_text(VULNERABLE)
    code, out, _ = run("scan", str(tmp_path))
    assert code == cli.EXIT_FINDINGS
    assert "Files scanned: 1" in out
    assert "HIGH:     1" in out
    assert "Total findings: 1" in out
    assert "TEST001" in out


def test_scan_clean_file_exits_zero(tmp_path):
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n")
    code, out, _ = run("scan", str(target))
    assert code == cli.EXIT_OK
    assert "Total findings: 0" in out


def test_scan_json_output(tmp_path):
    (tmp_path / "a.py").write_text(VULNERABLE)
    _, out, _ = run("scan", str(tmp_path), "--format", "json")
    report = json.loads(out)
    assert report["summary"]["total_findings"] == 1
    assert report["findings"][0]["rule_id"] == "TEST001"


def test_scan_writes_output_file(tmp_path):
    (tmp_path / "a.py").write_text(VULNERABLE)
    report_path = tmp_path / "report.json"
    run("scan", str(tmp_path / "a.py"), "--format", "json", "-o", str(report_path))
    assert json.loads(report_path.read_text(encoding="utf-8"))["summary"]["files_scanned"] == 1


def test_scan_missing_target(tmp_path):
    code, _, err = run("scan", str(tmp_path / "missing"))
    assert code == cli.EXIT_USAGE_ERROR
    assert "not found" in err


def test_scan_reports_syntax_errors(tmp_path):
    (tmp_path / "bad.py").write_text("x = 1\ndef (:\n")
    _, out, _ = run("scan", str(tmp_path))
    assert "SyntaxError" in out and "bad.py:2" in out


def test_rules_command_lists_rules():
    code, out, _ = run("rules")
    assert code == cli.EXIT_OK
    assert "TEST001" in out and "CWE-000" in out
