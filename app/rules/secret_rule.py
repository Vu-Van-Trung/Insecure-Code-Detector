"""PY007 - Hardcoded secrets.

Two complementary detectors:

1. Name-based (AST): a string literal assigned to a credential-like name
   (``API_KEY = "..."``, ``self.password = "..."``, ``connect(password="...")``,
   ``{"token": "..."}``). Placeholders are ignored and the value's entropy is
   used to grade confidence.
2. Format-based (regex): any string literal matching a well-known credential
   format (AWS access key, GitHub token, private key block, ...), whatever the
   variable name. Regex is used here because such formats cannot be expressed
   with the AST.

SECURITY: the secret value itself is never logged and is masked in the
``code`` snippet so reports do not leak it.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.models.finding import Finding, Severity
from app.rules._keywords import is_secret_name
from app.rules.base import SecurityRule
from app.rules.registry import register_rule

MIN_SECRET_LENGTH = 4
# Shannon entropy (bits per character) above which a value looks randomly generated.
HIGH_ENTROPY_THRESHOLD = 3.5
HIGH_ENTROPY_MIN_LENGTH = 16

# Obvious placeholders / non-secret values.
_PLACEHOLDER = re.compile(
    r"""^(
        x+ | \*+ | \.+ | -+ | 0+ | \#+
      | change[_ -]?me | replace[_ -]?me | placeholder | redacted | dummy | fake
      | todo | tbd | fixme | none | null | nil | n/?a | empty | default
      | (your|my|insert|enter)[_ -].* | .*[_ -]here
      | example.* | sample.* | test | testing
      | password | passwd | secret | token | api[_ -]?key
      | <.*> | \{.*\} | \$\{.*\} | \$[A-Z_]+ | %\(.*\)s | \{\{.*\}\}
    )$""",
    re.IGNORECASE | re.VERBOSE,
)
# An all-caps identifier is usually the *name* of an env var, e.g. TOKEN = "GITHUB_TOKEN".
_ENV_VAR_NAME = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")

# Well-known credential formats: (description, pattern, severity).
KNOWN_SECRET_FORMATS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.HIGH),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.HIGH),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
    ("Stripe live secret key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"), Severity.HIGH),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
)


def shannon_entropy(value: str) -> float:
    """Average information per character; random tokens score high, words low."""
    if not value:
        return 0.0
    length = len(value)
    return -sum(count / length * math.log2(count / length) for count in Counter(value).values())


def is_placeholder(value: str) -> bool:
    stripped = value.strip()
    return (
        len(stripped) < MIN_SECRET_LENGTH
        or bool(_PLACEHOLDER.match(stripped))
        or bool(_ENV_VAR_NAME.match(stripped))
    )


def match_known_format(value: str) -> tuple[str, Severity] | None:
    for description, pattern, severity in KNOWN_SECRET_FORMATS:
        if pattern.search(value):
            return description, severity
    return None


def mask_secret(value: str) -> str:
    """Keep only a short prefix so the finding stays recognisable."""
    visible = min(4, len(value) // 4)
    return value[:visible] + "*" * 8


def _target_name(target: ast.AST) -> str | None:
    """Name used for a value: ``x``, ``obj.x`` -> x, ``d["x"]`` -> x."""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        key = target.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
    return None


@register_rule
class HardcodedSecretRule(SecurityRule):
    id = "PY007"
    name = "Hardcoded secret"
    description = (
        "A credential (password, API key, token, private key) is written directly in "
        "the source code. Anyone with access to the repository, its history, a build "
        "artifact or a leaked copy can use it, and rotating it requires a code change."
    )
    severity = Severity.HIGH
    cwe = "CWE-798"
    category = "Hardcoded Credentials"
    recommendation = (
        "Load secrets at runtime from environment variables or a secret manager "
        "(e.g. os.environ['API_KEY']), and revoke/rotate any secret that was committed."
    )
    node_types = (ast.Assign, ast.AnnAssign, ast.keyword, ast.Dict, ast.Constant)

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if isinstance(node, ast.Constant):
            yield from self._check_known_format(node, context)
        else:
            for name, value in self._named_values(node):
                yield from self._check_named_value(node, name, value, context)

    # -------------------------------------------------------------- detectors

    def _check_known_format(self, node: ast.Constant, context: AnalysisContext) -> Iterator[Finding]:
        if not isinstance(node.value, str):
            return
        known = match_known_format(node.value)
        if known is None:
            return
        description, severity = known
        yield self.create_finding(
            node, context, f"Hardcoded {description} found in a string literal.",
            severity=severity, confidence=0.95, code=self._masked_line(node, node.value, context),
        )

    def _check_named_value(
        self, node: ast.AST, name: str, value: ast.AST, context: AnalysisContext,
    ) -> Iterator[Finding]:
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            return
        secret = value.value
        # Values with a known format are reported by _check_known_format already.
        if not is_secret_name(name) or is_placeholder(secret) or match_known_format(secret):
            return
        code = self._masked_line(value, secret, context)
        if len(secret) >= HIGH_ENTROPY_MIN_LENGTH and shannon_entropy(secret) >= HIGH_ENTROPY_THRESHOLD:
            yield self.create_finding(
                value, context, f"High-entropy string assigned to '{name}' looks like a hardcoded secret.",
                confidence=0.85, code=code,
            )
        else:
            yield self.create_finding(
                value, context, f"String literal assigned to '{name}' may be a hardcoded secret.",
                severity=Severity.MEDIUM, confidence=0.6, code=code,
            )

    # -------------------------------------------------------------- helpers

    @staticmethod
    def _named_values(node: ast.AST) -> Iterator[tuple[str, ast.AST]]:
        """(name, value) pairs for assignments, keyword arguments and dict items."""
        if isinstance(node, ast.Assign):
            for target in node.targets:
                name = _target_name(target)
                if name:
                    yield name, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            name = _target_name(node.target)
            if name:
                yield name, node.value
        elif isinstance(node, ast.keyword) and node.arg:
            yield node.arg, node.value
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    yield key.value, value

    @staticmethod
    def _masked_line(node: ast.AST, secret: str, context: AnalysisContext) -> str:
        line = context.get_line(getattr(node, "lineno", 0))
        if secret in line:
            return line.replace(secret, mask_secret(secret))
        # Multi-line or escaped literal: do not risk echoing the secret at all.
        return "<secret value masked>"
