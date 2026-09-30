"""Rule registry with automatic discovery of rule modules.

Adding a new rule (e.g. PY016) only requires creating a module in
``app/rules/`` containing a ``SecurityRule`` subclass decorated with
``@register_rule``. The analyzer core does not need to change.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Iterator

from app.rules.base import SecurityRule

logger = logging.getLogger(__name__)

# Modules inside app/rules that are infrastructure, not rules.
_NON_RULE_MODULES = {"base", "registry"}


class DuplicateRuleError(ValueError):
    """Raised when two rules share the same id."""


class RuleRegistry:
    """Holds rule classes keyed by rule id."""

    def __init__(self) -> None:
        self._rules: dict[str, type[SecurityRule]] = {}

    def register(self, rule_cls: type[SecurityRule]) -> type[SecurityRule]:
        if not (isinstance(rule_cls, type) and issubclass(rule_cls, SecurityRule)):
            raise TypeError(f"{rule_cls!r} is not a SecurityRule subclass")
        rule_id = rule_cls.id.upper()
        existing = self._rules.get(rule_id)
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
        """Instantiate every enabled rule (of one language, if given), ordered by id."""
        disabled_upper = {rule_id.upper() for rule_id in disabled}
        return [
            self._rules[rule_id]() for rule_id in self.rule_ids()
            if rule_id not in disabled_upper and (language is None or self._rules[rule_id].language == language)
        ]

    def __contains__(self, rule_id: object) -> bool:
        return isinstance(rule_id, str) and rule_id.upper() in self._rules

    def __iter__(self) -> Iterator[type[SecurityRule]]:
        return (self._rules[rule_id] for rule_id in self.rule_ids())

    def __len__(self) -> int:
        return len(self._rules)


default_registry = RuleRegistry()


def register_rule(rule_cls: type[SecurityRule]) -> type[SecurityRule]:
    """Class decorator registering a rule in the default registry."""
    return default_registry.register(rule_cls)


_builtin_rules_loaded = False


def load_builtin_rules() -> RuleRegistry:
    """Import every module in the ``app.rules`` package so rules self-register."""
    global _builtin_rules_loaded
    if not _builtin_rules_loaded:
        import app.rules as rules_package

        for module_info in pkgutil.iter_modules(rules_package.__path__):
            if module_info.name in _NON_RULE_MODULES or module_info.name.startswith("_"):
                continue
            importlib.import_module(f"{rules_package.__name__}.{module_info.name}")
            logger.debug("Loaded rule module %s", module_info.name)
        _builtin_rules_loaded = True
    return default_registry
