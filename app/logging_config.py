"""Cấu hình logging dùng chung cho CLI và web server.

BẢO MẬT: log chỉ chứa metadata (tên file, mã rule, số lượng...). Mã nguồn được
scan và các secret phát hiện được KHÔNG BAO GIỜ được ghi ra log, vì file log
thường được nhiều người đọc hơn mã nguồn.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

DEFAULT_LOG_DIR = Path("logs")
LOG_FILE_NAME = "analyzer.log"
# Ví dụ một dòng log: "2026-10-03 10:00:00,123 INFO    app.analyzer.engine: Scanned 3 files"
_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def setup_logging(log_dir: Path = DEFAULT_LOG_DIR, level: int = logging.INFO) -> Path | None:
    """Ghi log của analyzer vào ``<log_dir>/analyzer.log``; trả về đường dẫn file log.

    Nếu không tạo được thư mục log (vd không có quyền ghi), logging được bỏ qua
    và hàm trả None: một lần scan không bao giờ được thất bại chỉ vì logging.
    """
    # Chỉ cấu hình logger "app" (và các logger con app.*), không đụng tới root logger
    # để không làm thay đổi log của thư viện khác (uvicorn, fastapi...).
    logger = logging.getLogger("app")
    logger.setLevel(level)
    log_path = log_dir / LOG_FILE_NAME
    # Gọi setup_logging nhiều lần (vd trong test) không được gắn thêm handler trùng,
    # nếu không mỗi dòng log sẽ bị ghi lặp lại nhiều lần.
    if any(getattr(h, "baseFilename", None) == str(log_path.resolve()) for h in logger.handlers):
        return log_path
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        # RotatingFileHandler: file đạt ~1 MB thì đổi tên thành analyzer.log.1 ... và
        # giữ tối đa 3 bản cũ, tránh file log phình to vô hạn.
        handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    except OSError:
        return None
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    logger.addHandler(handler)
    return log_path
