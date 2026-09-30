"""Safe source loading and AST parsing.

SECURITY: source code is only ever read as text and parsed with ``ast.parse``.
It is never imported, compiled for execution, or run.
"""

from __future__ import annotations

import ast
import io
import tokenize
from dataclasses import dataclass
from pathlib import Path

# Files larger than this are rejected to avoid excessive memory/CPU usage.
DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MiB


class SourceError(Exception):
    """Raised when a source file cannot be read or parsed."""

    def __init__(self, error_type: str, reason: str, line: int | None = None) -> None:
        super().__init__(reason)
        self.error_type = error_type
        self.reason = reason
        self.line = line


@dataclass
class ParsedSource:
    """Source text together with its AST."""

    filename: str
    source: str
    tree: ast.Module

    @property
    def lines(self) -> list[str]:
        return self.source.splitlines()

    @property
    def line_count(self) -> int:
        return len(self.lines)


def decode_source(data: bytes) -> str:
    """Decode bytes using the PEP 263 encoding declaration (default UTF-8)."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        return data.decode(encoding)
    except (SyntaxError, LookupError) as exc:
        # detect_encoding raises SyntaxError for invalid/unknown coding cookies.
        raise SourceError("UnicodeDecodeError", f"Invalid source encoding: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise SourceError("UnicodeDecodeError", f"Cannot decode source: {exc.reason}") from exc


def parse_source(source: str, filename: str = "<input>") -> ParsedSource:
    """Parse Python source text into an AST without executing it."""
    try:
        tree = ast.parse(source, filename=filename, type_comments=False)
    except SyntaxError as exc:
        reason = f"Python SyntaxError: {exc.msg}"
        raise SourceError("SyntaxError", reason, exc.lineno) from exc
    except (ValueError, RecursionError, MemoryError) as exc:
        # ValueError: null bytes in source; RecursionError: pathologically nested code.
        raise SourceError(type(exc).__name__, f"Cannot parse source: {exc}") from exc
    return ParsedSource(filename=filename, source=source, tree=tree)


def parse_bytes(data: bytes, filename: str = "<input>") -> ParsedSource:
    """Decode then parse raw bytes (used for uploads and files)."""
    return parse_source(decode_source(data), filename)


def read_source_file(path: Path, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> bytes:
    """Read a source file (any language), translating OS errors into SourceError."""
    try:
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
    """Decode Java/C# source: UTF-8 (with or without BOM)."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SourceError("UnicodeDecodeError", f"Cannot decode source as UTF-8: {exc.reason}") from exc


def parse_file(
    path: Path,
    display_name: str | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> ParsedSource:
    """Read and parse a Python file from disk."""
    return parse_bytes(read_source_file(path, max_file_size), display_name or str(path))
