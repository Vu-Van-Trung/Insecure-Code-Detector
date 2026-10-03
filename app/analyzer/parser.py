"""Đọc mã nguồn an toàn và parse thành AST.

BẢO MẬT: mã nguồn chỉ được đọc như VĂN BẢN và parse bằng ``ast.parse``.
Nó không bao giờ được import, compile để thực thi hay chạy. Vì vậy scan một
file độc hại (vd chứa ``os.system("rm -rf /")``) không gây hại cho máy scan.
"""

from __future__ import annotations

import ast
import io
import tokenize
from dataclasses import dataclass
from pathlib import Path

# File lớn hơn giới hạn này bị từ chối để tránh tốn quá nhiều bộ nhớ/CPU
# (vd ai đó upload file vài trăm MB để làm treo server).
DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MiB


class SourceError(Exception):
    """Lỗi khi không đọc hoặc không parse được file nguồn.

    Engine bắt lỗi này và chuyển thành ScanError trong report, thay vì dừng cả lần scan.
    """

    def __init__(self, error_type: str, reason: str, line: int | None = None) -> None:
        super().__init__(reason)
        self.error_type = error_type  # vd "SyntaxError", "FileTooLarge"
        self.reason = reason          # mô tả cho người dùng
        self.line = line              # dòng gây lỗi, nếu biết


@dataclass
class ParsedSource:
    """Văn bản mã nguồn cùng với cây AST của nó."""

    filename: str
    source: str
    tree: ast.Module

    @property
    def lines(self) -> list[str]:
        """Các dòng của file (rule dùng để lấy đoạn code hiển thị trong finding)."""
        return self.source.splitlines()

    @property
    def line_count(self) -> int:
        return len(self.lines)


def decode_source(data: bytes) -> str:
    """Giải mã bytes theo khai báo encoding PEP 263 (``# -*- coding: ... -*-``), mặc định UTF-8.

    Dùng đúng cách Python tự đọc file .py, nên file khai báo latin-1 vẫn được đọc đúng.
    """
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        return data.decode(encoding)
    except (SyntaxError, LookupError) as exc:
        # detect_encoding ném SyntaxError khi khai báo coding sai hoặc không tồn tại.
        raise SourceError("UnicodeDecodeError", f"Invalid source encoding: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise SourceError("UnicodeDecodeError", f"Cannot decode source: {exc.reason}") from exc


def parse_source(source: str, filename: str = "<input>") -> ParsedSource:
    """Parse văn bản Python thành AST mà không thực thi nó."""
    try:
        tree = ast.parse(source, filename=filename, type_comments=False)
    except SyntaxError as exc:
        reason = f"Python SyntaxError: {exc.msg}"
        raise SourceError("SyntaxError", reason, exc.lineno) from exc
    except (ValueError, RecursionError, MemoryError) as exc:
        # ValueError: mã nguồn chứa byte null; RecursionError: code lồng nhau quá sâu bất thường
        # (có thể là file cố tình tạo ra để làm sập parser).
        raise SourceError(type(exc).__name__, f"Cannot parse source: {exc}") from exc
    return ParsedSource(filename=filename, source=source, tree=tree)


def parse_bytes(data: bytes, filename: str = "<input>") -> ParsedSource:
    """Giải mã rồi parse bytes thô (dùng cho file upload và file trên đĩa)."""
    return parse_source(decode_source(data), filename)


def read_source_file(path: Path, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> bytes:
    """Đọc một file nguồn (mọi ngôn ngữ); lỗi hệ điều hành được chuyển thành SourceError."""
    try:
        # Kiểm tra kích thước TRƯỚC khi đọc, để không nạp file khổng lồ vào bộ nhớ.
        size = path.stat().st_size
        if size > max_file_size:
            raise SourceError(
                "FileTooLarge", f"File is {size} bytes, limit is {max_file_size} bytes"
            )
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise SourceError("FileNotFoundError", "File not found") from exc
    except PermissionError as exc:
        raise SourceError("PermissionError", "Permission denied") from exc
    except IsADirectoryError as exc:
        raise SourceError("IsADirectoryError", "Expected a file, got a directory") from exc
    except OSError as exc:
        raise SourceError("OSError", f"Cannot read file: {exc.strerror or exc}") from exc


def decode_text(data: bytes) -> str:
    """Giải mã mã nguồn Java/C#: UTF-8 (có hoặc không có BOM - Visual Studio hay thêm BOM)."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SourceError("UnicodeDecodeError", f"Cannot decode source as UTF-8: {exc.reason}") from exc


def parse_file(
    path: Path,
    display_name: str | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> ParsedSource:
    """Đọc và parse một file Python trên đĩa.

    ``display_name`` là tên hiển thị trong report (vd đường dẫn tương đối thay vì tuyệt đối).
    """
    return parse_bytes(read_source_file(path, max_file_size), display_name or str(path))
