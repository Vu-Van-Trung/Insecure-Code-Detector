"""Phase 7 - JSON, CSV and HTML reports."""

import csv
import io
import json

import pytest

from app.reports import REPORT_FORMATS, render_report
from app.reports.csv_report import COLUMNS, escape_cell

CODE = """
import os
command = input("Command: ")
os.system(command)
eval(data)  # analyzer-ignore: PY001
"""


@pytest.fixture
def result(engine):
    return engine.scan_source(CODE, "app.py")


def test_json_report_contains_all_sections(result):
    report = json.loads(render_report(result, "json"))
    assert report["report"]["tool"] == "Secure Code Analyzer"
    assert "not an exact probability" in report["report"]["note"]
    assert report["scan"]["target"] == "app.py"
    assert report["summary"]["severity_counts"]["CRITICAL"] == 1
    assert report["summary"]["suppressed"] == 1
    assert report["files"] == [{"path": "app.py", "lines": 5, "findings": 1, "language": "python"}]
    finding = report["findings"][0]
    assert finding["cwe"] == "CWE-78" and finding["recommendation"]
    assert finding["taint_path"] == ["input()", "command", "os.system()"]


def test_csv_report_has_one_row_per_finding(result):
    rows = list(csv.DictReader(io.StringIO(render_report(result, "csv"))))
    assert list(rows[0].keys()) == COLUMNS
    assert len(rows) == 1
    assert rows[0]["taint_path"] == "input() -> command -> os.system()"
    assert rows[0]["severity"] == "CRITICAL"


@pytest.mark.parametrize("value", ["=HYPERLINK(\"http://evil\")", "+1+1", "-2", "@SUM(A1)"])
def test_csv_formula_injection_is_neutralised(value):
    assert escape_cell(value) == "'" + value


def test_csv_normal_values_unchanged():
    assert escape_cell("os.system(cmd)") == "os.system(cmd)"
    assert escape_cell(None) == ""


def test_csv_escapes_attacker_controlled_file_name(engine):
    result = engine.scan_source("eval(x)\n", "=HYPERLINK(1).py")
    [row] = list(csv.DictReader(io.StringIO(render_report(result, "csv"))))
    assert row["file"] == "'=HYPERLINK(1).py"


def test_html_report_contains_all_sections(result):
    html = render_report(result, "html")
    for text in ("Secure Code Analyzer report", "Summary", "Files", "Findings", "CWE-78",
                 "Recommendation", "Taint path", "Suppressed findings", "does not make the code safe"):
        assert text in html


def test_html_report_escapes_scanned_content(engine):
    result = engine.scan_source("eval('<img src=x onerror=alert(1)>')\n", "<b>x</b>.py")
    html = render_report(result, "html")
    assert "<img src=x" not in html and "<b>x</b>" not in html
    assert "&lt;img src=x" in html


def test_html_report_lists_errors(engine):
    html = render_report(engine.scan_source("def (:\n", "bad.py"), "html")
    assert "SyntaxError" in html and "bad.py" in html


def test_unknown_format():
    with pytest.raises(ValueError, match="Unknown report format"):
        render_report(None, "pdf")  # type: ignore[arg-type]


def test_every_format_registered():
    assert set(REPORT_FORMATS) == {"json", "csv", "html", "sarif"}


def test_sarif_report_format(result):
    sarif_str = render_report(result, "sarif")
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Secure Code Analyzer"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "PY003"
    assert results[0]["level"] == "error"
    assert results[0]["codeFlows"]
