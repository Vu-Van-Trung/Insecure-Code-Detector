"""JSON report: the complete scan result, suitable for CI/CD tooling."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from app.models.finding import ScanResult

REPORT_NOTE = (
    "Confidence is a heuristic score of the analyzer, not an exact probability. "
    "Suppressed findings were hidden by the whitelist or inline comments; suppression "
    "does not make code safe."
)


def render_json(result: ScanResult) -> str:
    data = {
        "report": {
            "tool": "Secure Code Analyzer",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "note": REPORT_NOTE,
        },
        **result.to_dict(),
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
