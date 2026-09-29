"""PY006 - Unsafe YAML loading (PyYAML)."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument
from app.models.finding import Finding, Severity
from app.rules.base import SecurityRule
from app.rules.registry import register_rule

# Loaders that only build plain Python data (dict, list, str, ...).
_SAFE_LOADERS = frozenset({"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"})
# FullLoader blocks the worst gadgets but had several bypasses (CVE-2020-1747, CVE-2020-14343).
_FULL_LOADERS = frozenset({"FullLoader", "CFullLoader"})
# Functions whose safety depends on the Loader argument.
_LOADER_FUNCTIONS = frozenset({"yaml.load", "yaml.load_all"})
_UNSAFE_FUNCTIONS = frozenset({"yaml.unsafe_load", "yaml.unsafe_load_all"})
_FULL_FUNCTIONS = frozenset({"yaml.full_load", "yaml.full_load_all"})


@register_rule
class UnsafeYamlRule(SecurityRule):
    id = "PY006"
    name = "Unsafe YAML loading"
    description = (
        "PyYAML's unsafe loaders can construct arbitrary Python objects from tags such "
        "as !!python/object/apply:os.system, so loading attacker-controlled YAML leads "
        "to remote code execution."
    )
    severity = Severity.HIGH
    cwe = "CWE-502"
    category = "Insecure Deserialization"
    recommendation = "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)."

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not isinstance(node, ast.Call):
            return
        name = context.call_name(node)
        if name in _UNSAFE_FUNCTIONS:
            yield self.create_finding(node, context, f"{name}() can construct arbitrary Python objects.",
                                      confidence=0.9)
        elif name in _FULL_FUNCTIONS:
            yield self._full_loader_finding(node, context, name)
        elif name in _LOADER_FUNCTIONS:
            yield from self._check_loader_argument(node, context, name)

    def _check_loader_argument(self, node: ast.Call, context: AnalysisContext, name: str) -> Iterator[Finding]:
        loader = get_argument(node, 1, "Loader")
        if loader is None:
            # Before PyYAML 5.1 the default loader was the unsafe one.
            yield self.create_finding(
                node, context, f"{name}() called without an explicit safe Loader.", confidence=0.8,
            )
            return
        loader_name = context.resolve(loader)
        short_name = loader_name.rsplit(".", 1)[-1] if loader_name else None
        if short_name in _SAFE_LOADERS:
            return
        if short_name in _FULL_LOADERS:
            yield self._full_loader_finding(node, context, name)
        elif short_name in {"Loader", "UnsafeLoader", "CLoader", "CUnsafeLoader"}:
            yield self.create_finding(
                node, context, f"{name}() uses the unsafe {short_name}.", confidence=0.9,
            )
        else:
            yield self.create_finding(
                node, context, f"{name}() uses a Loader that cannot be verified as safe.",
                severity=Severity.MEDIUM, confidence=0.5,
            )

    def _full_loader_finding(self, node: ast.Call, context: AnalysisContext, name: str) -> Finding:
        return self.create_finding(
            node, context, f"{name}() uses FullLoader, which has had known bypasses; prefer SafeLoader.",
            severity=Severity.MEDIUM, confidence=0.6,
        )
