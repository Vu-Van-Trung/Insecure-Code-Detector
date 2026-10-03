"""Lưu kết quả scan của Web UI dưới dạng file JSON (dự án này không cần cơ sở dữ liệu).

Mỗi lần scan được lưu thành ``data/scans/<scan_id>.json``. scan_id là chuỗi hex
ngẫu nhiên 128 bit và được kiểm tra định dạng TRƯỚC mọi thao tác với file, nên
một id độc hại như ``../../etc/passwd`` không bao giờ thoát ra khỏi thư mục lưu
trữ (chống path traversal).
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
# Đúng 32 ký tự hex thường - chính là định dạng của uuid4().hex.
_SCAN_ID = re.compile(r"^[0-9a-f]{32}$")


def is_valid_scan_id(scan_id: str) -> bool:
    """True nếu scan_id đúng định dạng; id chứa "/", ".." hay ký tự lạ đều bị từ chối."""
    return bool(_SCAN_ID.fullmatch(scan_id))


class ScanStore:
    """Giữ ``max_scans`` kết quả scan gần nhất dưới dạng file JSON; bản cũ hơn bị xóa dần."""

    def __init__(self, directory: Path = DEFAULT_STORAGE_DIR, max_scans: int = 100) -> None:
        self.directory = directory
        self.max_scans = max_scans

    def save(self, result: ScanResult) -> str:
        """Lưu kết quả và trả về scan_id mới (dùng trong URL /scan/<scan_id>)."""
        self.directory.mkdir(parents=True, exist_ok=True)
        # uuid4 ngẫu nhiên nên không đoán được id kết quả scan của người khác.
        scan_id = uuid.uuid4().hex
        path = self.directory / f"{scan_id}.json"
        # Ghi ra file tạm rồi đổi tên: os.replace là thao tác nguyên tử (atomic),
        # nên người đọc không bao giờ thấy một file mới ghi được một nửa.
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(result.to_dict(), ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, path)
        self._prune(keep=path)
        return scan_id

    def load(self, scan_id: str) -> ScanResult | None:
        """Đọc lại kết quả theo scan_id; trả None nếu id sai định dạng, không tồn tại hoặc file hỏng."""
        # Kiểm tra id trước khi ghép vào đường dẫn - đây là chốt chặn path traversal.
        if not is_valid_scan_id(scan_id):
            return None
        path = self.directory / f"{scan_id}.json"
        try:
            return ScanResult.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError, KeyError):
            # File hỏng: ghi log để điều tra, nhưng người dùng chỉ thấy "không tìm thấy".
            logger.exception("Stored scan %s is unreadable", scan_id)
            return None

    def _prune(self, keep: Path) -> None:
        """Xóa các bản scan cũ nhất vượt quá ``max_scans``; không bao giờ xóa bản vừa lưu.

        Nhiều file có thể có cùng thời điểm sửa đổi (đồng hồ hệ thống có độ phân
        giải thấp), nên file mới được loại ra một cách tường minh thay vì dựa vào
        thứ tự sắp xếp.
        """
        others = [p for p in self.directory.glob("*.json") if p != keep]
        # Mới nhất trước; giữ (max_scans - 1) file khác + file vừa lưu = max_scans file.
        others.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
        for old in others[self.max_scans - 1:]:
            try:
                old.unlink()
            except OSError:
                # Không xóa được (file đang bị mở...) thì bỏ qua, lần lưu sau sẽ thử lại.
                logger.warning("Could not delete old scan %s", old.name)
