"""PY010 - TLS certificate verification disabled."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_keyword
from app.models.finding import Finding, Severity
from app.rules.base import SecurityRule
from app.rules.registry import register_rule

# HTTP client libraries whose functions/classes accept verify=.
_HTTP_LIBRARIES = ("requests.", "httpx.")
# Method names of session/client objects (e.g. session.get(url, verify=False)),
# where the receiver's type cannot be resolved statically.
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request", "send"})
_UNVERIFIED_CONTEXT = frozenset({"ssl._create_unverified_context", "ssl._create_stdlib_context"})


@register_rule
class TlsVerificationDisabledRule(SecurityRule):
    id = "PY010"
    name = "TLS certificate verification disabled"
    description = (
        "Without certificate verification the client accepts any certificate, so an "
        "attacker on the network (public Wi-Fi, compromised router, proxy) can intercept "
        "and modify HTTPS traffic, including credentials (man-in-the-middle)."
    )
    severity = Severity.MEDIUM
    cwe = "CWE-295"
    category = "Insecure Transport"
    recommendation = (
        "Keep verify=True (the default). For internal or self-signed certificates, pass "
        "the CA bundle path instead: requests.get(url, verify='/path/to/ca.pem')."
    )
    node_types = (ast.Call, ast.Attribute, ast.Name)

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if isinstance(node, ast.Call):
            yield from self._check_call(node, context)
        elif isinstance(node.ctx, ast.Load) and context.resolve(node) == "ssl.CERT_NONE":
            # e.g. ctx.verify_mode = ssl.CERT_NONE
            yield self.create_finding(
                node, context, "ssl.CERT_NONE disables certificate verification.", confidence=0.8,
            )

    def _check_call(self, node: ast.Call, context: AnalysisContext) -> Iterator[Finding]:
        name = context.call_name(node)
        if name in _UNVERIFIED_CONTEXT:
            yield self.create_finding(
                node, context, f"{name}() creates an SSL context without certificate verification.",
                confidence=0.85,
            )
            return

        verify = get_keyword(node, "verify")
        # Only a literal False/0 is reported. verify='ca.pem' is correct usage and
        # verify=None means "use the default" (verification on) in requests.
        if verify is None or not isinstance(verify.value, ast.Constant):
            return
        if verify.value.value is None or verify.value.value not in (False, 0):
            return
        if name and name.startswith(_HTTP_LIBRARIES):
            yield self.create_finding(
                node, context, f"{name}() is called with verify=False.", confidence=0.9,
            )
        elif isinstance(node.func, ast.Attribute) and node.func.attr in _HTTP_METHODS:
            # Probably a requests.Session / httpx.Client method; type not provable.
            yield self.create_finding(
                node, context, f".{node.func.attr}() is called with verify=False.", confidence=0.7,
            )
