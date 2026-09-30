"""Report renderers (JSON, CSV, HTML). Standard library only."""

from __future__ import annotations

from collections.abc import Callable

from app.models.finding import ScanResult
from app.reports.csv_report import render_csv
from app.reports.html_report import render_html
from app.reports.json_report import render_json

# format -> (renderer, media type, file extension)
REPORT_FORMATS: dict[str, tuple[Callable[[ScanResult], str], str, str]] = {
    "json": (render_json, "application/json", "json"),
    "csv": (render_csv, "text/csv", "csv"),
    "html": (render_html, "text/html", "html"),
}


def render_report(result: ScanResult, report_format: str) -> str:
    try:
        renderer = REPORT_FORMATS[report_format][0]
    except KeyError:
        raise ValueError(f"Unknown report format '{report_format}'. Allowed: {', '.join(REPORT_FORMATS)}") from None
    return renderer(result)
