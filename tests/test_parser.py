import ast

import pytest

from app.analyzer.parser import SourceError, parse_bytes, parse_file, parse_source


def test_parse_valid_source_returns_ast():
    parsed = parse_source("x = 1\nprint(x)\n", "ok.py")
    assert isinstance(parsed.tree, ast.Module)
    assert parsed.line_count == 2


def test_syntax_error_reports_line():
    with pytest.raises(SourceError) as info:
        parse_source("x = 1\n\ndef broken(:\n    pass\n")
    assert info.value.error_type == "SyntaxError"
    assert info.value.line == 3
    assert "SyntaxError" in info.value.reason


def test_null_bytes_are_rejected_cleanly():
    with pytest.raises(SourceError):
        parse_source("x = 1\x00")


def test_parse_does_not_execute_code(tmp_path):
    marker = tmp_path / "executed.txt"
    source = f"open({str(marker)!r}, 'w').write('pwned')\n"
    parse_source(source)
    assert not marker.exists()


def test_invalid_utf8_raises_decode_error():
    with pytest.raises(SourceError) as info:
        parse_bytes(b"x = '\xff\xfe'\n")
    assert info.value.error_type == "UnicodeDecodeError"


def test_pep263_encoding_cookie_is_respected():
    data = "# -*- coding: latin-1 -*-\nname = 'caf\xe9'\n".encode("latin-1")
    parsed = parse_bytes(data)
    assert "café" in parsed.source


def test_utf8_bom_is_accepted():
    parsed = parse_bytes(b"\xef\xbb\xbfx = 1\n")
    assert parsed.line_count == 1


def test_missing_file(tmp_path):
    with pytest.raises(SourceError) as info:
        parse_file(tmp_path / "missing.py")
    assert info.value.error_type == "FileNotFoundError"


def test_file_too_large(tmp_path):
    big = tmp_path / "big.py"
    big.write_text("x = 1\n" * 100)
    with pytest.raises(SourceError) as info:
        parse_file(big, max_file_size=50)
    assert info.value.error_type == "FileTooLarge"
