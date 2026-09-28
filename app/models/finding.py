"""Data models shared by the analyzer core, CLI, reports and web UI.

The core deliberately uses plain dataclasses (standard library only) so it can be
reused from the CLI or a CI/CD pipeline without pulling in web dependencies.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Higher rank means more severe (useful for sorting and thresholds)."""
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        """Parse a severity name case-insensitively, raising ValueError if unknown."""
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).strip().upper())
        except ValueError:
            allowed = ", ".join(s.value for s in cls)
            raise ValueError(f"Unknown severity '{value}'. Allowed: {allowed}") from None


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@dataclass
class Finding:
    """A single security issue reported by a rule.

    ``confidence`` is a heuristic score in [0.0, 1.0] expressing how sure the
    analyzer is about the finding. It is NOT a mathematically exact probability.
    """

    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float
    file: str
    line: int
    column: int
    message: str
    description: str
    code: str
    recommendation: str
    cwe: str
    category: str
    # Optional data-flow information, filled in by taint-aware rules.
    source: str | None = None
    sink: str | None = None
    taint_path: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be within [0.0, 1.0], got {self.confidence}")
        self.confidence = round(float(self.confidence), 2)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ScanError:
    """A file that could not be analyzed (syntax error, bad encoding, ...)."""

    file: str
    error_type: str
    reason: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Aggregated result of scanning one file or a whole directory."""

    target: str
    files_scanned: int = 0
    lines_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        """Number of findings per severity, always containing every level."""
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def sort_findings(self) -> None:
        """Sort by file/line so reports are stable and easy to read."""
        self.findings.sort(key=lambda f: (f.file, f.line, f.column, -f.severity.rank, f.rule_id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "summary": {
                "files_scanned": self.files_scanned,
                "lines_scanned": self.lines_scanned,
                "total_findings": len(self.findings),
                "severity_counts": self.severity_counts(),
                "errors": len(self.errors),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": [error.to_dict() for error in self.errors],
        }
