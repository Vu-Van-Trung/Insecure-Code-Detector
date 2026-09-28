"""Logging setup shared by the CLI and the web server.

Log messages contain only metadata (file names, rule ids, counts). Source code
and detected secrets are never written to the log.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

DEFAULT_LOG_DIR = Path("logs")
LOG_FILE_NAME = "analyzer.log"
_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def setup_logging(log_dir: Path = DEFAULT_LOG_DIR, level: int = logging.INFO) -> Path | None:
    """Send analyzer logs to ``<log_dir>/analyzer.log``; returns the log path.

    If the log directory cannot be created, logging is left unconfigured and
    None is returned; a scan must never fail because of logging.
    """
    logger = logging.getLogger("app")
    logger.setLevel(level)
    log_path = log_dir / LOG_FILE_NAME
    if any(getattr(h, "baseFilename", None) == str(log_path.resolve()) for h in logger.handlers):
        return log_path
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    except OSError:
        return None
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    logger.addHandler(handler)
    return log_path
