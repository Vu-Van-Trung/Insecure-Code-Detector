"""CSV report: one row per finding, for spreadsheets and issue trackers.

Scan metadata and the summary are in the JSON/HTML reports; a CSV file is kept
as a single flat table so it can be imported and filtered directly.
"""

from __future__ import annotations

import csv
import io

from app.models.finding import Finding, ScanResult

COLUMNS = [
    "rule_id", "rule_name", "language", "severity", "confidence", "cwe", "category", "file", "line", "column",
    "message", "code", "recommendation", "source", "sink", "taint_path",
]

# SECURITY (CWE-1236): spreadsheet apps execute cells starting with these
# characters as formulas. Scanned code is attacker-controlled, so such cells
# are prefixed with a quote to be displayed as plain text.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def escape_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def _row(finding: Finding) -> list[str]:
    data = finding.to_dict()
    data["taint_path"] = " -> ".join(finding.taint_path)
    return [escape_cell(data[column]) for column in COLUMNS]


def render_csv(result: ScanResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    writer.writerows(_row(finding) for finding in result.findings)
    return buffer.getvalue()
