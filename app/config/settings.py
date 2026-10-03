"""Gom toàn bộ cấu hình của analyzer từ các file JSON thành một đối tượng ``AnalyzerSettings``.

* ``app/config/rules.json``    - giá trị mặc định của engine (ngưỡng lọc, giới hạn kích thước, thư mục bỏ qua)
* ``app/config/severity.json`` - ghi đè severity theo từng rule
* ``app/config/taint.json``    - nguồn dữ liệu không tin cậy (source) và sanitizer cho taint tracking
* ``blacklist.json``           - hàm/module nguy hiểm do người dùng khai báo (rule PY012/PY013)
* ``whitelist.json``           - danh sách bỏ qua cảnh báo của dự án được scan

QUAN TRỌNG: whitelist chỉ ẨN (suppress) cảnh báo. Nó không làm code trở nên an
toàn; một lỗ hổng thật bị ẩn đi vẫn có thể bị khai thác.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from app.analyzer.languages import CSHARP, JAVA
from app.analyzer.taint import TaintConfig
from app.analyzer.ts.taint import TSTaintConfig
from app.config.loader import CONFIG_DIR, ConfigError, get_string_list, load_json
from app.models.finding import Severity

# Thư mục gốc của project (chứa blacklist.json, whitelist.json mặc định).
PROJECT_ROOT = CONFIG_DIR.parent.parent
RULES_CONFIG = CONFIG_DIR / "rules.json"
SEVERITY_CONFIG = CONFIG_DIR / "severity.json"
DEFAULT_BLACKLIST = PROJECT_ROOT / "blacklist.json"
DEFAULT_WHITELIST = PROJECT_ROOT / "whitelist.json"

# Mã rule hợp lệ: chữ in hoa + số, vd PY001, JV002, CS009.
_RULE_ID = re.compile(r"^[A-Z]+[0-9]+$")


def _rule_ids(values: list[str], where: str) -> frozenset[str]:
    """Chuẩn hóa (bỏ khoảng trắng, in hoa) và kiểm tra danh sách mã rule trong file cấu hình.

    Báo lỗi ngay khi có mã sai (vd "PY-001") thay vì im lặng bỏ qua: nếu không,
    người dùng tưởng đã tắt rule nhưng thực ra rule vẫn chạy.
    """
    ids = {value.strip().upper() for value in values}
    invalid = sorted(rule_id for rule_id in ids if not _RULE_ID.match(rule_id))
    if invalid:
        raise ConfigError(f"Invalid rule id(s) in {where}: {', '.join(invalid)}")
    return frozenset(ids)


def _severity(value: Any, where: str) -> Severity:
    """Chuyển chuỗi ("high", "LOW"...) thành Severity; giá trị sai được báo bằng ConfigError."""
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from exc


# --------------------------------------------------------------------------- whitelist


@dataclass(frozen=True)
class Whitelist:
    """Các cấu hình bỏ qua cảnh báo của dự án được scan (xem whitelist.json).

    ``frozen=True``: đối tượng bất biến, có thể dùng chung an toàn giữa các lần scan.
    """

    # Glob pattern của các file không scan, vd "tests/test_*.py".
    files: tuple[str, ...] = ()
    # Rule bị tắt cho dự án này.
    disabled_rules: frozenset[str] = frozenset()
    # Regex các giá trị chắc chắn không phải secret thật (dùng cho PY007/JV008/CS008).
    allowed_secrets: tuple[re.Pattern[str], ...] = ()
    # Đường dẫn file whitelist đã nạp (để hiển thị trong report).
    source: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "whitelist") -> Whitelist:
        """Tạo Whitelist từ dict JSON; regex được biên dịch trước để báo lỗi sớm."""
        patterns = []
        for pattern in get_string_list(data, "allowed_secrets", where):
            try:
                patterns.append(re.compile(pattern))
            except re.error as exc:
                raise ConfigError(f"Invalid regex in 'allowed_secrets' of {where}: {pattern!r} ({exc})") from exc
        return cls(
            # Đổi "\" thành "/" để pattern viết trên Windows vẫn khớp đường dẫn posix.
            files=tuple(path.replace("\\", "/") for path in get_string_list(data, "files", where)),
            disabled_rules=_rule_ids(get_string_list(data, "disabled_rules", where), where),
            allowed_secrets=tuple(patterns),
            source=where,
        )

    @classmethod
    def load(cls, path: Path) -> Whitelist:
        return cls.from_dict(load_json(path), str(path))

    def is_file_ignored(self, path: str) -> bool:
        """So khớp glob trên đường dẫn dạng posix; pattern được phép khớp phần đuôi bất kỳ của đường dẫn.

        Vd pattern ``legacy/*`` khớp cả ``legacy/a.py`` lẫn ``src/legacy/a.py``.
        """
        normalized = path.replace("\\", "/")
        return any(
            fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(normalized, f"*/{pattern}")
            for pattern in self.files
        )

    def is_secret_allowed(self, value: str) -> bool:
        """True nếu giá trị khớp TOÀN BỘ một regex trong allowed_secrets (fullmatch, không phải search).

        Dùng fullmatch để regex ngắn như ``test`` không vô tình cho qua mọi chuỗi chứa "test".
        """
        return any(pattern.fullmatch(value) for pattern in self.allowed_secrets)


# --------------------------------------------------------------------------- blacklist


@dataclass(frozen=True)
class BlacklistEntry:
    """Một mục trong blacklist: tên hàm/module và thông tin dùng để tạo finding."""

    name: str
    severity: Severity
    cwe: str
    reason: str


@dataclass(frozen=True)
class Blacklist:
    """Hàm và module nguy hiểm do người dùng cấu hình (xem blacklist.json).

    Cho phép mở rộng bộ phát hiện mà không cần viết code (rule PY012/PY013).
    """

    # Tên đầy đủ của hàm/module -> mục blacklist, để tra cứu O(1) khi duyệt AST.
    functions: dict[str, BlacklistEntry] = field(default_factory=dict)
    modules: dict[str, BlacklistEntry] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "blacklist") -> Blacklist:
        # Hàm mặc định MEDIUM; import module mặc định INFO (chỉ nhắc review, chưa phải lỗ hổng).
        return cls(
            functions=cls._entries(data, "dangerous_functions", where, Severity.MEDIUM),
            modules=cls._entries(data, "dangerous_modules", where, Severity.INFO),
        )

    @classmethod
    def load(cls, path: Path) -> Blacklist:
        return cls.from_dict(load_json(path), str(path))

    @staticmethod
    def _entries(data: dict[str, Any], key: str, where: str, default_severity: Severity) -> dict[str, BlacklistEntry]:
        """Mỗi mục có thể là tên ngắn gọn ("eval") hoặc object có thêm severity/cwe/reason."""
        raw = data.get(key, [])
        if not isinstance(raw, list):
            raise ConfigError(f"'{key}' in {where} must be a list")
        entries: dict[str, BlacklistEntry] = {}
        for item in raw:
            # Dạng rút gọn "eval" được chuẩn hóa thành {"name": "eval"} để xử lý chung một kiểu.
            if isinstance(item, str):
                item = {"name": item}
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
                raise ConfigError(f"Each entry of '{key}' in {where} needs a 'name' string")
            name = item["name"]
            entries[name] = BlacklistEntry(
                name=name,
                severity=_severity(item.get("severity", default_severity), f"{where} ({name})"),
                # CWE-676: "Use of Potentially Dangerous Function" - CWE chung khi người dùng không ghi rõ.
                cwe=str(item.get("cwe", "CWE-676")),
                reason=str(item.get("reason", "listed as dangerous in the blacklist")),
            )
        return entries


# --------------------------------------------------------------------------- settings


@dataclass(frozen=True)
class AnalyzerSettings:
    """Toàn bộ cấu hình mà engine và các rule cần cho một lần scan."""

    # Source/sanitizer cho taint tracking của Python (app/config/taint.json).
    taint: TaintConfig
    # Source/sanitizer của Java và C# (app/config/taint_<language>.json).
    language_taint: dict[str, TSTaintConfig] = field(default_factory=dict)
    blacklist: Blacklist = field(default_factory=Blacklist)
    whitelist: Whitelist = field(default_factory=Whitelist)
    # Rule bị tắt trong rules.json hoặc qua tùy chọn --disable của CLI.
    disabled_rules: frozenset[str] = frozenset()
    # Mã rule -> severity mới (severity.json), áp dụng sau khi rule đã tạo finding.
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    # Finding thấp hơn các ngưỡng này bị loại khỏi kết quả (được đếm là "filtered").
    min_confidence: float = 0.0
    min_severity: Severity = Severity.INFO
    # File lớn hơn giới hạn này bị bỏ qua để tránh tốn bộ nhớ/thời gian (mặc định 1 MB).
    max_file_size: int = 1024 * 1024
    # Tên thư mục không duyệt vào khi scan cả thư mục (.git, venv, node_modules...).
    excluded_dirs: frozenset[str] = frozenset()
    # Có tôn trọng comment "# analyzer-ignore" trong code hay không.
    honor_inline_ignores: bool = True

    @classmethod
    def load(
        cls,
        whitelist_path: Path | None = None,
        blacklist_path: Path | None = DEFAULT_BLACKLIST,
        rules_path: Path = RULES_CONFIG,
        severity_path: Path = SEVERITY_CONFIG,
        taint_config: TaintConfig | None = None,
    ) -> AnalyzerSettings:
        """Nạp mọi file cấu hình; nội dung không hợp lệ được báo bằng ConfigError."""
        rules = load_json(rules_path)
        where = str(rules_path)
        # Kiểm tra kiểu và miền giá trị ngay khi nạp, để lỗi cấu hình hiện ra rõ ràng
        # thay vì gây lỗi khó hiểu ở giữa quá trình scan.
        min_confidence = rules.get("min_confidence", 0.0)
        if not isinstance(min_confidence, (int, float)) or not 0.0 <= min_confidence <= 1.0:
            raise ConfigError(f"'min_confidence' in {where} must be a number between 0 and 1")
        max_file_size = rules.get("max_file_size", 1024 * 1024)
        if not isinstance(max_file_size, int) or max_file_size <= 0:
            raise ConfigError(f"'max_file_size' in {where} must be a positive integer")

        severity = load_json(severity_path)
        overrides = severity.get("overrides", {})
        if not isinstance(overrides, dict):
            raise ConfigError(f"'overrides' in {severity_path} must be an object")

        return cls(
            taint=taint_config or TaintConfig.load(),
            language_taint={language: TSTaintConfig.load_default(language) for language in (JAVA, CSHARP)},
            blacklist=Blacklist.load(blacklist_path) if blacklist_path else Blacklist(),
            whitelist=Whitelist.load(whitelist_path) if whitelist_path else Whitelist(),
            disabled_rules=_rule_ids(get_string_list(rules, "disabled_rules", where), where),
            severity_overrides={
                rule_id: _severity(value, f"{severity_path} ({rule_id})")
                for rule_id, value in zip(_rule_ids(list(overrides), str(severity_path)), overrides.values())
            } if overrides else {},
            min_confidence=float(min_confidence),
            min_severity=_severity(rules.get("min_severity", "INFO"), where),
            max_file_size=max_file_size,
            excluded_dirs=frozenset(get_string_list(rules, "excluded_dirs", where)),
        )

    def all_disabled_rules(self) -> frozenset[str]:
        """Rule bị tắt từ cấu hình của tool cộng với rule bị tắt trong whitelist của dự án."""
        return self.disabled_rules | self.whitelist.disabled_rules

    def with_changes(self, **changes: Any) -> AnalyzerSettings:
        """Bản sao có thay đổi một số trường (đối tượng frozen nên không sửa trực tiếp được).

        Vd CLI dùng ``settings.with_changes(min_severity=Severity.HIGH)`` cho tùy chọn dòng lệnh.
        """
        return replace(self, **changes)
