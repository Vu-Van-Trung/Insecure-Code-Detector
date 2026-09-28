import pytest

from app.models.finding import Finding, ScanResult, Severity


def make_finding(**overrides) -> Finding:
    data = dict(
        rule_id="PY001", rule_name="eval", severity="CRITICAL", confidence=0.95,
        file="a.py", line=3, column=4, message="m", description="d", code="eval(x)",
        recommendation="r", cwe="CWE-95", category="Code Injection",
    )
    data.update(overrides)
    return Finding(**data)


def test_finding_contains_all_required_fields():
    data = make_finding().to_dict()
    required = {
        "rule_id", "rule_name", "severity", "confidence", "file", "line", "column", "message",
        "description", "code", "recommendation", "cwe", "category",
    }
    assert required <= data.keys()
    assert data["severity"] == "CRITICAL"
    assert data["taint_path"] == []


def test_severity_parse_is_case_insensitive_and_rejects_unknown():
    assert Severity.parse("high") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.parse("URGENT")


def test_severity_rank_ordering():
    ranks = [s.rank for s in Severity]
    assert ranks == sorted(ranks, reverse=True)


@pytest.mark.parametrize("confidence", [-0.1, 1.01])
def test_confidence_must_be_in_range(confidence):
    with pytest.raises(ValueError):
        make_finding(confidence=confidence)


def test_scan_result_summary_counts_every_severity():
    result = ScanResult(target="x", files_scanned=1, lines_scanned=10)
    result.findings = [make_finding(), make_finding(severity="LOW", line=1)]
    summary = result.to_dict()["summary"]
    assert summary["total_findings"] == 2
    assert summary["severity_counts"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 0}


def test_sort_findings_by_location():
    result = ScanResult(target="x")
    result.findings = [make_finding(line=9), make_finding(line=2)]
    result.sort_findings()
    assert [f.line for f in result.findings] == [2, 9]
