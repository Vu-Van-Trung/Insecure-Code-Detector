"""Các bộ xuất report (JSON, CSV, HTML). Chỉ dùng thư viện chuẩn của Python."""

from __future__ import annotations

from collections.abc import Callable

from app.models.finding import ScanResult
from app.reports.csv_report import render_csv
from app.reports.html_report import render_html
from app.reports.json_report import render_json

# Định dạng -> (hàm render, media type cho HTTP response, extension của file tải về).
# Thêm một định dạng mới chỉ cần viết hàm render và thêm một dòng vào đây;
# CLI (--format) và Web UI (nút Export) tự đọc danh sách từ bảng này.
REPORT_FORMATS: dict[str, tuple[Callable[[ScanResult], str], str, str]] = {
    "json": (render_json, "application/json", "json"),
    "csv": (render_csv, "text/csv", "csv"),
    "html": (render_html, "text/html", "html"),
}


def render_report(result: ScanResult, report_format: str) -> str:
    """Xuất kết quả scan theo định dạng ``report_format`` ("json", "csv" hoặc "html")."""
    try:
        renderer = REPORT_FORMATS[report_format][0]
    except KeyError:
        # "from None" để thông báo lỗi gọn, không kèm KeyError gốc khó hiểu.
        raise ValueError(f"Unknown report format '{report_format}'. Allowed: {', '.join(REPORT_FORMATS)}") from None
    return renderer(result)
