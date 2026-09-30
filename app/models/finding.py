"""Data models shared by the analyzer core, CLI, reports and web UI.

The core deliberately uses plain dataclasses (standard library only) so it can be
reused from the CLI or a CI/CD pipeline without pulling in web dependencies.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
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
    analyzer is that the finding is a real, exploitable issue. It is NOT a
    mathematically exact probability. Typical values used by the rules:

    * 0.95      untrusted source provably reaches the sink (taint tracking)
    * 0.80-0.90 dangerous API with a dynamic argument
    * 0.50-0.75 pattern depends on naming/context heuristics
    * 0.40      data went through a sanitizer the analyzer cannot verify
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
    language: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be within [0.0, 1.0], got {self.confidence}")
        self.confidence = round(float(self.confidence), 2)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})


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
class FileSummary:
    """Per-file information shown in reports."""

    path: str
    lines: int
    findings: int = 0
    language: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Aggregated result of scanning one file or a whole directory."""

    target: str
    tool_version: str = ""
    started_at: str = ""
    duration_ms: int = 0
    files_scanned: int = 0
    lines_scanned: int = 0
    files: list[FileSummary] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Hidden by the whitelist or an inline "# analyzer-ignore" comment. Kept so
    # reports can show that something was suppressed (suppressed != safe).
    suppressed: list[Finding] = field(default_factory=list)
    # Findings dropped because they are below min_severity / min_confidence.
    filtered_count: int = 0
    skipped_files: list[str] = field(default_factory=list)
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

    def highest_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)

    def summary(self) -> dict[str, Any]:
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
