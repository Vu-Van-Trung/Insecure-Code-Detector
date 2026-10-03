"""Đọc các file cấu hình JSON và báo lỗi rõ ràng khi file sai.

Mọi lỗi cấu hình đều được chuyển thành ``ConfigError`` với thông điệp dễ hiểu
(tên file, số dòng lỗi JSON...), để CLI/Web chỉ cần bắt một loại exception và
hiển thị cho người dùng thay vì in ra traceback.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Thư mục app/config/ chứa các file JSON mặc định (rules.json, taint.json...).
CONFIG_DIR = Path(__file__).resolve().parent


class ConfigError(ValueError):
    """File cấu hình bị thiếu, sai cú pháp JSON hoặc có giá trị không hợp lệ."""


def load_json(path: Path) -> dict[str, Any]:
    """Đọc một object JSON từ ``path``; mọi sự cố đều được báo bằng ConfigError."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {path}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Cannot read configuration file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        # Kèm số dòng để người dùng tìm ngay chỗ sai (thiếu dấu phẩy, ngoặc...).
        raise ConfigError(f"Invalid JSON in {path} (line {exc.lineno}): {exc.msg}") from exc
    # File cấu hình luôn phải là object {...}; một list hay số ở gốc là sai định dạng.
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a JSON object")
    return data


def get_string_list(data: dict[str, Any], key: str, where: str) -> list[str]:
    """Lấy ``data[key]`` và kiểm tra đó là list các chuỗi (trả list rỗng nếu không có khóa).

    ``where`` là tên file/vị trí, chỉ dùng để thông báo lỗi chỉ rõ chỗ sai.
    """
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"'{key}' in {where} must be a list of strings")
    return value
