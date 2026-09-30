"""JSON storage of web scan results (no database needed for this project).

Each scan is stored as ``data/scans/<scan_id>.json``. Scan ids are random
128-bit hex strings and are validated before any filesystem access, so a
crafted id such as ``../../etc/passwd`` can never escape the storage folder.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from pathlib import Path

from app.config.settings import PROJECT_ROOT
from app.models.finding import ScanResult

logger = logging.getLogger(__name__)

DEFAULT_STORAGE_DIR = PROJECT_ROOT / "data" / "scans"
_SCAN_ID = re.compile(r"^[0-9a-f]{32}$")


def is_valid_scan_id(scan_id: str) -> bool:
    return bool(_SCAN_ID.fullmatch(scan_id))


class ScanStore:
    """Keeps the most recent ``max_scans`` results as JSON files."""

    def __init__(self, directory: Path = DEFAULT_STORAGE_DIR, max_scans: int = 100) -> None:
        self.directory = directory
        self.max_scans = max_scans

    def save(self, result: ScanResult) -> str:
        self.directory.mkdir(parents=True, exist_ok=True)
        scan_id = uuid.uuid4().hex
        path = self.directory / f"{scan_id}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(result.to_dict(), ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, path)  # atomic: readers never see a half-written file
        self._prune(keep=path)
        return scan_id

    def load(self, scan_id: str) -> ScanResult | None:
        if not is_valid_scan_id(scan_id):
            return None
        path = self.directory / f"{scan_id}.json"
        try:
            return ScanResult.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError, KeyError):
            logger.exception("Stored scan %s is unreadable", scan_id)
            return None

    def _prune(self, keep: Path) -> None:
        """Delete the oldest scans beyond ``max_scans``; never the one just saved.

        Several files can share the same mtime (coarse clock resolution), so the
        new file is excluded explicitly instead of relying on the sort order.
        """
        others = [p for p in self.directory.glob("*.json") if p != keep]
        others.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
        for old in others[self.max_scans - 1:]:
            try:
                old.unlink()
            except OSError:
                logger.warning("Could not delete old scan %s", old.name)
