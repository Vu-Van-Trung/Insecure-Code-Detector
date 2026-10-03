"""Report JSON: toàn bộ kết quả scan, phù hợp cho công cụ CI/CD đọc tự động."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from app.models.finding import ScanResult

# Ghi chú kèm trong mọi report, nhắc người đọc cách hiểu đúng confidence và suppression.
REPORT_NOTE = (
    "Confidence is a heuristic score of the analyzer, not an exact probability. "
    "Suppressed findings were hidden by the whitelist or inline comments; suppression "
    "does not make code safe."
)


def render_json(result: ScanResult) -> str:
    """Tạo chuỗi JSON: phần "report" (metadata của tool) + toàn bộ ScanResult.to_dict()."""
    data = {
        "report": {
            "tool": "Secure Code Analyzer",
            # Thời điểm theo UTC, định dạng ISO 8601 (vd 2026-10-03T08:00:00+00:00).
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "note": REPORT_NOTE,
        },
        **result.to_dict(),
    }
    # ensure_ascii=False giữ nguyên ký tự Unicode (tiếng Việt, ...) thay vì \uXXXX.
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
