"""Analyzer settings assembled from the JSON configuration files.

* ``app/config/rules.json``    - engine defaults (thresholds, limits, excluded dirs)
* ``app/config/severity.json`` - per-rule severity overrides
* ``app/config/taint.json``    - taint sources and sanitizers
* ``blacklist.json``           - user-defined dangerous functions/modules (PY012/PY013)
* ``whitelist.json``           - suppressions for the scanned project

IMPORTANT: the whitelist only SUPPRESSES warnings. It does not make the code
safe; a suppressed issue is still exploitable if it is real.
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

PROJECT_ROOT = CONFIG_DIR.parent.parent
RULES_CONFIG = CONFIG_DIR / "rules.json"
SEVERITY_CONFIG = CONFIG_DIR / "severity.json"
DEFAULT_BLACKLIST = PROJECT_ROOT / "blacklist.json"
DEFAULT_WHITELIST = PROJECT_ROOT / "whitelist.json"

_RULE_ID = re.compile(r"^[A-Z]+[0-9]+$")


def _rule_ids(values: list[str], where: str) -> frozenset[str]:
    ids = {value.strip().upper() for value in values}
    invalid = sorted(rule_id for rule_id in ids if not _RULE_ID.match(rule_id))
    if invalid:
        raise ConfigError(f"Invalid rule id(s) in {where}: {', '.join(invalid)}")
    return frozenset(ids)


def _severity(value: Any, where: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from exc


# --------------------------------------------------------------------------- whitelist


@dataclass(frozen=True)
class Whitelist:
    """Suppressions for the scanned project (see whitelist.json)."""

    files: tuple[str, ...] = ()
    disabled_rules: frozenset[str] = frozenset()
    allowed_secrets: tuple[re.Pattern[str], ...] = ()
    source: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "whitelist") -> Whitelist:
        patterns = []
        for pattern in get_string_list(data, "allowed_secrets", where):
            try:
                patterns.append(re.compile(pattern))
            except re.error as exc:
                raise ConfigError(f"Invalid regex in 'allowed_secrets' of {where}: {pattern!r} ({exc})") from exc
        return cls(
            files=tuple(path.replace("\\", "/") for path in get_string_list(data, "files", where)),
            disabled_rules=_rule_ids(get_string_list(data, "disabled_rules", where), where),
            allowed_secrets=tuple(patterns),
            source=where,
        )

    @classmethod
    def load(cls, path: Path) -> Whitelist:
        return cls.from_dict(load_json(path), str(path))

    def is_file_ignored(self, path: str) -> bool:
        """Glob match on the posix path; a pattern may match any trailing part of it."""
        normalized = path.replace("\\", "/")
        return any(
            fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(normalized, f"*/{pattern}")
            for pattern in self.files
        )

    def is_secret_allowed(self, value: str) -> bool:
        return any(pattern.fullmatch(value) for pattern in self.allowed_secrets)


# --------------------------------------------------------------------------- blacklist


@dataclass(frozen=True)
class BlacklistEntry:
    name: str
    severity: Severity
    cwe: str
    reason: str


@dataclass(frozen=True)
class Blacklist:
    """Dangerous functions and modules configured by the user (see blacklist.json)."""

    functions: dict[str, BlacklistEntry] = field(default_factory=dict)
    modules: dict[str, BlacklistEntry] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "blacklist") -> Blacklist:
        return cls(
            functions=cls._entries(data, "dangerous_functions", where, Severity.MEDIUM),
            modules=cls._entries(data, "dangerous_modules", where, Severity.INFO),
        )

    @classmethod
    def load(cls, path: Path) -> Blacklist:
        return cls.from_dict(load_json(path), str(path))

    @staticmethod
    def _entries(data: dict[str, Any], key: str, where: str, default_severity: Severity) -> dict[str, BlacklistEntry]:
        """Entries may be plain names ("eval") or objects with severity/cwe/reason."""
        raw = data.get(key, [])
        if not isinstance(raw, list):
            raise ConfigError(f"'{key}' in {where} must be a list")
        entries: dict[str, BlacklistEntry] = {}
        for item in raw:
            if isinstance(item, str):
                item = {"name": item}
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
                raise ConfigError(f"Each entry of '{key}' in {where} needs a 'name' string")
            name = item["name"]
            entries[name] = BlacklistEntry(
                name=name,
                severity=_severity(item.get("severity", default_severity), f"{where} ({name})"),
                cwe=str(item.get("cwe", "CWE-676")),
                reason=str(item.get("reason", "listed as dangerous in the blacklist")),
            )
        return entries


# --------------------------------------------------------------------------- settings


@dataclass(frozen=True)
class AnalyzerSettings:
    taint: TaintConfig
    # Taint sources/sanitizers of Java and C# (app/config/taint_<language>.json).
    language_taint: dict[str, TSTaintConfig] = field(default_factory=dict)
    blacklist: Blacklist = field(default_factory=Blacklist)
    whitelist: Whitelist = field(default_factory=Whitelist)
    disabled_rules: frozenset[str] = frozenset()
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    # Findings below these thresholds are left out of the result (counted as filtered).
    min_confidence: float = 0.0
    min_severity: Severity = Severity.INFO
    max_file_size: int = 1024 * 1024
    excluded_dirs: frozenset[str] = frozenset()
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
        """Load every configuration file; raises ConfigError on invalid content."""
        rules = load_json(rules_path)
        where = str(rules_path)
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
        return self.disabled_rules | self.whitelist.disabled_rules

    def with_changes(self, **changes: Any) -> AnalyzerSettings:
        return replace(self, **changes)
