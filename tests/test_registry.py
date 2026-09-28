import pytest

from app.models.finding import Severity
from app.rules.base import SecurityRule
from app.rules.registry import DuplicateRuleError, RuleRegistry, load_builtin_rules
from tests.conftest import DemoCallRule


def test_register_and_lookup(demo_registry):
    assert "TEST001" in demo_registry
    assert "test001" in demo_registry
    assert demo_registry.get("TEST001") is DemoCallRule
    assert demo_registry.rule_ids() == ["TEST001"]


def test_duplicate_rule_id_is_rejected(demo_registry):
    class Clash(DemoCallRule):
        pass

    with pytest.raises(DuplicateRuleError):
        demo_registry.register(Clash)


def test_registering_same_class_twice_is_idempotent(demo_registry):
    demo_registry.register(DemoCallRule)
    assert len(demo_registry) == 1


def test_non_rule_cannot_be_registered():
    with pytest.raises(TypeError):
        RuleRegistry().register(object)  # type: ignore[arg-type]


def test_disabled_rules_are_not_instantiated(demo_registry):
    assert [r.id for r in demo_registry.create_rules()] == ["TEST001"]
    assert demo_registry.create_rules({"test001"}) == []


def test_rule_missing_metadata_fails_at_definition():
    with pytest.raises(TypeError, match="missing attributes"):
        class Incomplete(SecurityRule):  # noqa: F841
            id = "X1"

            def check(self, node, context):
                return []


def test_rule_severity_string_is_normalised():
    class StringSeverity(DemoCallRule):
        id = "TEST002"
        severity = "medium"  # type: ignore[assignment]

    assert StringSeverity.severity is Severity.MEDIUM


def test_load_builtin_rules_returns_registry():
    registry = load_builtin_rules()
    assert isinstance(registry, RuleRegistry)
    assert all(issubclass(rule, SecurityRule) for rule in registry)
    assert all(rule.node_types for rule in registry)


def test_builtin_rules_are_auto_discovered():
    registry = load_builtin_rules()
    assert {"PY001", "PY002", "PY003", "PY004", "PY005"} <= set(registry.rule_ids())


def test_builtin_rules_do_not_all_share_one_severity():
    severities = {rule.severity for rule in load_builtin_rules()}
    assert len(severities) > 1
