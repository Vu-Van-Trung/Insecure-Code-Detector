"""Supported source languages and their file extensions."""

from __future__ import annotations

from pathlib import PurePath

PYTHON, JAVA, CSHARP = "python", "java", "csharp"

EXTENSIONS: dict[str, str] = {".py": PYTHON, ".java": JAVA, ".cs": CSHARP}
DISPLAY_NAMES: dict[str, str] = {PYTHON: "Python", JAVA: "Java", CSHARP: "C#"}
# Rule id prefix of each language (PY001, JV001, CS001).
RULE_PREFIXES: dict[str, str] = {PYTHON: "PY", JAVA: "JV", CSHARP: "CS"}


def language_of(filename: str) -> str | None:
    """Language of a file from its extension, or None if unsupported."""
    return EXTENSIONS.get(PurePath(filename).suffix.lower())


def extension_of(language: str) -> str:
    return next(ext for ext, lang in EXTENSIONS.items() if lang == language)


def supported_extensions_text() -> str:
    return ", ".join(EXTENSIONS)
