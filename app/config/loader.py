"""Loading of JSON configuration files with clear error reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(__file__).resolve().parent


class ConfigError(ValueError):
    """Raised when a configuration file is missing, malformed or invalid."""


def load_json(path: Path) -> dict[str, Any]:
    """Read a JSON object from ``path``, raising ConfigError on any problem."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {path}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Cannot read configuration file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {path} (line {exc.lineno}): {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a JSON object")
    return data


def get_string_list(data: dict[str, Any], key: str, where: str) -> list[str]:
    """Return ``data[key]`` validated as a list of strings (empty if absent)."""
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"'{key}' in {where} must be a list of strings")
    return value
