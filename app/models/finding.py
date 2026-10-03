"""Mô hình dữ liệu dùng chung cho lõi analyzer, CLI, report và Web UI.

Lõi cố ý chỉ dùng dataclass của thư viện chuẩn (không phụ thuộc thư viện ngoài),
để có thể dùng lại từ CLI hoặc pipeline CI/CD mà không cần cài các gói web.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Mức độ nghiêm trọng, xếp từ nặng nhất đến nhẹ nhất.

    Kế thừa ``str`` nên ``Severity.HIGH == "HIGH"`` và serialize JSON trực tiếp được.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Rank càng cao càng nghiêm trọng (dùng để sắp xếp và so sánh với ngưỡng)."""
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        """Đọc tên severity không phân biệt hoa thường ("high" -> HIGH); tên lạ gây ValueError."""
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).strip().upper())
        except ValueError:
            # Liệt kê các giá trị hợp lệ để người dùng sửa cấu hình dễ dàng.
            allowed = ", ".join(s.value for s in cls)
            raise ValueError(f"Unknown severity '{value}'. Allowed: {allowed}") from None


# Không so sánh trực tiếp chuỗi ("HIGH" < "LOW" theo bảng chữ cái là sai nghĩa) mà dùng số.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@dataclass
class Finding:
    """Một vấn đề bảo mật do một rule báo cáo.

    ``confidence`` là điểm heuristic trong [0.0, 1.0] thể hiện mức chắc chắn của
    analyzer rằng đây là lỗi thật, khai thác được. Đây KHÔNG phải xác suất toán
    học chính xác. Các mức thường dùng trong rule:

    * 0.95      taint tracking chứng minh dữ liệu từ source tới được sink
    * 0.80-0.90 API nguy hiểm nhận argument động
    * 0.50-0.75 dựa vào heuristic tên biến / ngữ cảnh
    * 0.40      dữ liệu đã qua sanitizer mà analyzer không chứng minh được là đủ
    """

    rule_id: str           # vd "PY003"
    rule_name: str
    severity: Severity
    confidence: float
    file: str
    line: int              # dòng, bắt đầu từ 1
    column: int            # cột, bắt đầu từ 0
    message: str           # mô tả cụ thể cho vị trí này
    description: str       # mô tả chung của rule (vì sao nguy hiểm)
    code: str              # dòng code liên quan (secret đã được che)
    recommendation: str    # cách sửa
    cwe: str               # mã CWE, vd "CWE-78"
    category: str          # nhóm lỗ hổng, vd "Command Injection"
    # Thông tin luồng dữ liệu (tùy chọn), do các rule có dùng taint tracking điền vào.
    source: str | None = None      # nguồn không tin cậy, vd "request.args"
    sink: str | None = None        # nơi nguy hiểm nhận dữ liệu, vd "os.system()"
    taint_path: list[str] = field(default_factory=list)  # vd ["input()", "host", "os.system()"]
    language: str = ""

    def __post_init__(self) -> None:
        # Chuẩn hóa và kiểm tra ngay khi tạo, để mọi Finding trong hệ thống luôn hợp lệ.
        self.severity = Severity.parse(self.severity)
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be within [0.0, 1.0], got {self.confidence}")
        # Làm tròn 2 chữ số để report gọn và so sánh trong test ổn định.
        self.confidence = round(float(self.confidence), 2)

    def to_dict(self) -> dict[str, Any]:
        """Chuyển thành dict JSON-serializable (severity thành chuỗi)."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Tạo lại Finding từ dict (vd kết quả scan cũ lưu dạng JSON).

        Bỏ qua khóa lạ để file JSON của phiên bản cũ/mới hơn vẫn đọc được.
        """
        known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})


@dataclass
class ScanError:
    """Một file không phân tích được (lỗi cú pháp, sai encoding, quá lớn...)."""

    file: str
    error_type: str
    reason: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileSummary:
    """Thông tin từng file hiển thị trong report (số dòng, số finding, ngôn ngữ)."""

    path: str
    lines: int
    findings: int = 0
    language: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Kết quả tổng hợp khi scan một file hoặc cả một thư mục."""

    target: str
    tool_version: str = ""
    started_at: str = ""
    duration_ms: int = 0
    files_scanned: int = 0
    lines_scanned: int = 0
    files: list[FileSummary] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Finding bị ẩn bởi whitelist hoặc comment "# analyzer-ignore". Vẫn được giữ lại
    # để report cho thấy có cảnh báo đã bị ẩn (bị ẩn != an toàn).
    suppressed: list[Finding] = field(default_factory=list)
    # Số finding bị bỏ vì thấp hơn min_severity / min_confidence.
    filtered_count: int = 0
    skipped_files: list[str] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        """Số finding theo từng severity; luôn có đủ mọi mức (mức không có finding = 0) để vẽ biểu đồ."""
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def sort_findings(self) -> None:
        """Sắp xếp theo file/dòng/cột (cùng vị trí thì nặng trước) để report ổn định và dễ đọc."""
        self.findings.sort(key=lambda f: (f.file, f.line, f.column, -f.severity.rank, f.rule_id))

    def highest_severity(self) -> Severity | None:
        """Severity cao nhất trong kết quả (None nếu không có finding); CLI dùng cho --fail-on."""
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)

    def summary(self) -> dict[str, Any]:
        """Các con số tổng quan hiển thị ở đầu report và dashboard."""
        return {
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts(),
            "suppressed": len(self.suppressed),
            "filtered": self.filtered_count,
            "files_skipped": len(self.skipped_files),
            "errors": len(self.errors),
        }

    def to_dict(self) -> dict[str, Any]:
        """Cấu trúc đầy đủ của report JSON (cũng là định dạng lưu kết quả scan của Web UI)."""
        return {
            "scan": {
                "target": self.target,
                "tool_version": self.tool_version,
                "started_at": self.started_at,
                "duration_ms": self.duration_ms,
            },
            "summary": self.summary(),
            "files": [item.to_dict() for item in self.files],
            "findings": [finding.to_dict() for finding in self.findings],
            "suppressed": [finding.to_dict() for finding in self.suppressed],
            "skipped_files": list(self.skipped_files),
            "errors": [error.to_dict() for error in self.errors],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        """Ngược lại với to_dict: dựng lại ScanResult từ JSON đã lưu (Web UI mở lại kết quả cũ)."""
        scan, summary = data.get("scan", {}), data.get("summary", {})
        return cls(
            target=scan.get("target", ""),
            tool_version=scan.get("tool_version", ""),
            started_at=scan.get("started_at", ""),
            duration_ms=scan.get("duration_ms", 0),
            files_scanned=summary.get("files_scanned", 0),
            lines_scanned=summary.get("lines_scanned", 0),
            files=[FileSummary(**item) for item in data.get("files", [])],
            findings=[Finding.from_dict(item) for item in data.get("findings", [])],
            suppressed=[Finding.from_dict(item) for item in data.get("suppressed", [])],
            filtered_count=summary.get("filtered", 0),
            skipped_files=list(data.get("skipped_files", [])),
            errors=[ScanError(**item) for item in data.get("errors", [])],
        )
