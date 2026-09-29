"""PY008 - Weak hash algorithms and PY009 - Insecure randomness for security values."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument, get_keyword, is_constant
from app.models.finding import Finding, Severity
from app.rules._keywords import is_password_name, is_security_value_name
from app.rules.base import SecurityRule
from app.rules.registry import register_rule

_WEAK_ALGORITHMS = frozenset({"md5", "sha1", "md4", "md2"})
# Constructors whose name already fixes the algorithm.
_WEAK_HASH_CONSTRUCTORS: dict[str, str] = {
    "hashlib.md5": "md5",
    "hashlib.sha1": "sha1",
    "cryptography.hazmat.primitives.hashes.MD5": "md5",
    "cryptography.hazmat.primitives.hashes.SHA1": "sha1",
    "Crypto.Hash.MD5.new": "md5",
    "Crypto.Hash.SHA1.new": "sha1",
    "Cryptodome.Hash.MD5.new": "md5",
    "Cryptodome.Hash.SHA1.new": "sha1",
}


@register_rule
class WeakHashRule(SecurityRule):
    id = "PY008"
    name = "Weak cryptographic hash (MD5/SHA-1)"
    description = (
        "MD5 and SHA-1 are broken: practical collision attacks exist, and they are far "
        "too fast for password storage (billions of guesses per second on a GPU)."
    )
    severity = Severity.MEDIUM
    cwe = "CWE-328"
    category = "Weak Cryptography"
    recommendation = (
        "Use SHA-256/SHA-3 for integrity, HMAC-SHA256 for message authentication, and "
        "a password hashing function (argon2, bcrypt, scrypt or hashlib.pbkdf2_hmac) for "
        "passwords. For non-security checksums pass usedforsecurity=False."
    )

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not isinstance(node, ast.Call):
            return
        algorithm = self._weak_algorithm(node, context)
        if algorithm is None:
            return
        # Python 3.9+: usedforsecurity=False explicitly declares a non-security use
        # (checksums, cache keys), which is acceptable.
        used_for_security = get_keyword(node, "usedforsecurity")
        if used_for_security is not None and is_constant(used_for_security.value, False):
            return
        if self._hashes_password(node):
            yield self.create_finding(
                node, context, f"{algorithm.upper()} is used to hash a password.",
                severity=Severity.HIGH, confidence=0.85,
            )
        else:
            yield self.create_finding(
                node, context, f"Weak hash algorithm {algorithm.upper()} is used.", confidence=0.7,
            )

    @staticmethod
    def _weak_algorithm(call: ast.Call, context: AnalysisContext) -> str | None:
        name = context.call_name(call)
        if name in _WEAK_HASH_CONSTRUCTORS:
            return _WEAK_HASH_CONSTRUCTORS[name]
        if name == "hashlib.new":
            algorithm = get_argument(call, 0, "name")
            if isinstance(algorithm, ast.Constant) and isinstance(algorithm.value, str):
                normalized = algorithm.value.lower().replace("-", "")
                if normalized in _WEAK_ALGORITHMS:
                    return normalized
        return None

    @staticmethod
    def _hashes_password(call: ast.Call) -> bool:
        """True if a password-like variable appears in the hashed data."""
        for arg in call.args:
            for child in ast.walk(arg):
                name = child.id if isinstance(child, ast.Name) else getattr(child, "attr", None)
                if name and is_password_name(name):
                    return True
        return False


# random-module functions that return random values (seed/getstate are not flagged).
_RANDOM_FUNCTIONS = frozenset({
    f"random.{name}" for name in (
        "random", "randint", "randrange", "choice", "choices", "sample", "shuffle",
        "getrandbits", "randbytes", "uniform",
    )
})


@register_rule
class InsecureRandomRule(SecurityRule):
    id = "PY009"
    name = "Insecure random generator for security value"
    description = (
        "The random module uses the Mersenne Twister PRNG, which is predictable: after "
        "observing enough outputs an attacker can reconstruct its state and predict "
        "future tokens, passwords or reset codes."
    )
    severity = Severity.MEDIUM
    cwe = "CWE-330"
    category = "Insecure Randomness"
    recommendation = (
        "Use the secrets module (secrets.token_urlsafe(), secrets.token_hex(), "
        "secrets.choice()) or random.SystemRandom for security-sensitive values."
    )

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not isinstance(node, ast.Call):
            return
        name = context.call_name(node)
        if name not in _RANDOM_FUNCTIONS:
            return
        # random is fine for games, sampling, simulations... Only report it when
        # the surrounding code suggests a security value.
        target = self._assigned_name(node, context)
        if target and is_security_value_name(target):
            yield self.create_finding(
                node, context, f"{name}() generates a value stored in '{target}'.", confidence=0.75,
            )
            return
        function = context.enclosing_function_name(node)
        if function and is_security_value_name(function):
            yield self.create_finding(
                node, context, f"{name}() is used inside '{function}()'.", confidence=0.6,
            )

    @staticmethod
    def _assigned_name(node: ast.AST, context: AnalysisContext) -> str | None:
        """Name that receives the value: variable, attribute, dict key or keyword argument."""
        current = context.parent(node)
        while current is not None and not isinstance(current, ast.stmt):
            if isinstance(current, ast.keyword) and current.arg:
                return current.arg
            current = context.parent(current)
        if isinstance(current, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = current.targets if isinstance(current, ast.Assign) else [current.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    return target.id
                if isinstance(target, ast.Attribute):
                    return target.attr
                if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                    return str(target.slice.value)
        return None
