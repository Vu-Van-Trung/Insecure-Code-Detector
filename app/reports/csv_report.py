"""Report CSV: mỗi finding một dòng, để mở bằng Excel/Google Sheets hoặc nhập vào issue tracker.

Metadata của lần scan và phần tổng quan nằm trong report JSON/HTML; file CSV
được giữ là một bảng phẳng duy nhất để có thể import và lọc trực tiếp.
"""

from __future__ import annotations

import csv
import io

from app.models.finding import Finding, ScanResult

# Thứ tự cột trong file CSV (cũng là tên khóa trong Finding.to_dict()).
COLUMNS = [
    "rule_id", "rule_name", "language", "severity", "confidence", "cwe", "category", "file", "line", "column",
    "message", "code", "recommendation", "source", "sink", "taint_path",
]

# BẢO MẬT (CWE-1236 - CSV/Formula injection): Excel, LibreOffice... coi ô bắt đầu
# bằng các ký tự này là công thức và có thể thực thi nó (vd =HYPERLINK(...), =cmd|...).
# Code được scan do người khác viết (có thể là kẻ tấn công), nên các ô như vậy
# được thêm dấu ' ở đầu để luôn hiển thị như văn bản thường.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def escape_cell(value: object) -> str:
    """Chuyển giá trị thành chuỗi an toàn cho ô CSV (None -> chuỗi rỗng)."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def _row(finding: Finding) -> list[str]:
    """Một dòng CSV của finding, theo đúng thứ tự COLUMNS."""
    data = finding.to_dict()
    # taint_path là list; gộp thành một chuỗi "a -> b -> c" để nằm gọn trong một ô.
    data["taint_path"] = " -> ".join(finding.taint_path)
    return [escape_cell(data[column]) for column in COLUMNS]


def render_csv(result: ScanResult) -> str:
    """Tạo nội dung file CSV (dòng tiêu đề + một dòng cho mỗi finding)."""
    # Ghi vào bộ nhớ (StringIO) thay vì file, vì Web UI trả nội dung trực tiếp qua HTTP.
    buffer = io.StringIO()
    # lineterminator="\n" để kết quả giống nhau trên mọi hệ điều hành.
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    writer.writerows(_row(finding) for finding in result.findings)
    return buffer.getvalue()
