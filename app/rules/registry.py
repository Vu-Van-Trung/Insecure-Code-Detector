"""Registry (sổ đăng ký) các rule, tự động phát hiện các module rule.

Thêm một rule mới (vd PY019) chỉ cần tạo một module trong ``app/rules/`` chứa
một lớp con của ``SecurityRule`` gắn decorator ``@register_rule``. Lõi analyzer
không cần sửa gì (nguyên tắc Open/Closed: mở để mở rộng, đóng với sửa đổi).
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Iterator

from app.rules.base import SecurityRule

logger = logging.getLogger(__name__)

# Các module trong app/rules là hạ tầng, không phải rule.
_NON_RULE_MODULES = {"base", "registry"}


class DuplicateRuleError(ValueError):
    """Hai rule dùng cùng một mã (id)."""


class RuleRegistry:
    """Lưu các lớp rule theo mã rule."""

    def __init__(self) -> None:
        # Mã rule (in hoa) -> lớp rule. Lưu LỚP chứ không phải đối tượng: engine tự tạo đối tượng.
        self._rules: dict[str, type[SecurityRule]] = {}

    def register(self, rule_cls: type[SecurityRule]) -> type[SecurityRule]:
        """Đăng ký một lớp rule; trả lại chính lớp đó để dùng được như decorator."""
        if not (isinstance(rule_cls, type) and issubclass(rule_cls, SecurityRule)):
            raise TypeError(f"{rule_cls!r} is not a SecurityRule subclass")
        rule_id = rule_cls.id.upper()
        existing = self._rules.get(rule_id)
        # Đăng ký lại đúng lớp cũ (vd module bị import 2 lần) thì không sao; lớp khác trùng mã thì lỗi.
        if existing is not None and existing is not rule_cls:
            raise DuplicateRuleError(
                f"Rule id {rule_id} is used by both {existing.__name__} and {rule_cls.__name__}"
            )
        self._rules[rule_id] = rule_cls
        return rule_cls

    def get(self, rule_id: str) -> type[SecurityRule] | None:
        return self._rules.get(rule_id.upper())

    def rule_ids(self) -> list[str]:
        return sorted(self._rules)

    def create_rules(
        self, disabled: set[str] | frozenset[str] = frozenset(), language: str | None = None,
    ) -> list[SecurityRule]:
        """Tạo đối tượng cho mọi rule đang bật (chỉ của một ngôn ngữ, nếu có chỉ định), sắp theo mã."""
        disabled_upper = {rule_id.upper() for rule_id in disabled}
        return [
            self._rules[rule_id]() for rule_id in self.rule_ids()
            if rule_id not in disabled_upper and (language is None or self._rules[rule_id].language == language)
        ]

    # Các phương thức đặc biệt cho phép dùng: "PY001" in registry, for rule in registry, len(registry).

    def __contains__(self, rule_id: object) -> bool:
        return isinstance(rule_id, str) and rule_id.upper() in self._rules

    def __iter__(self) -> Iterator[type[SecurityRule]]:
        return (self._rules[rule_id] for rule_id in self.rule_ids())

    def __len__(self) -> int:
        return len(self._rules)


# Registry mặc định mà các rule có sẵn tự đăng ký vào.
default_registry = RuleRegistry()


def register_rule(rule_cls: type[SecurityRule]) -> type[SecurityRule]:
    """Decorator của class: đăng ký rule vào registry mặc định.

    Vd::

        @register_rule
        class EvalRule(DangerousCallRule): ...
    """
    return default_registry.register(rule_cls)


# Chỉ quét package một lần dù load_builtin_rules được gọi nhiều lần.
_builtin_rules_loaded = False


def load_builtin_rules() -> RuleRegistry:
    """Import mọi module trong package ``app.rules`` để các rule tự đăng ký (qua @register_rule)."""
    global _builtin_rules_loaded
    if not _builtin_rules_loaded:
        import app.rules as rules_package

        for module_info in pkgutil.iter_modules(rules_package.__path__):
            # Bỏ qua hạ tầng (base, registry) và module dùng chung có tên bắt đầu bằng "_".
            if module_info.name in _NON_RULE_MODULES or module_info.name.startswith("_"):
                continue
            # Chỉ cần import: decorator @register_rule trong module sẽ chạy và đăng ký rule.
            importlib.import_module(f"{rules_package.__name__}.{module_info.name}")
            logger.debug("Loaded rule module %s", module_info.name)
        _builtin_rules_loaded = True
    return default_registry
