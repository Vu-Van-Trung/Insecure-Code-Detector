"""PY008 - Thuật toán hash yếu và PY009 - Sinh số ngẫu nhiên không an toàn cho giá trị bảo mật."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from typing import Any

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument, get_keyword, is_constant
from app.models.finding import Finding, Severity
from app.rules._keywords import is_password_name, is_security_value_name
from app.rules.base import CallRule
from app.rules.registry import register_rule

# Tên thuật toán yếu khi chọn bằng chuỗi: hashlib.new("md5").
_WEAK_ALGORITHMS = frozenset({"md5", "sha1", "md4", "md2"})
# Hàm/constructor mà chính tên của nó đã xác định thuật toán (hashlib, cryptography, PyCryptodome).
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
class WeakHashRule(CallRule):
    """PY008: MD5/SHA-1. Hash mật khẩu bằng chúng được nâng lên HIGH."""

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

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        algorithm = self._weak_algorithm(node, name)
        if algorithm is None:
            return
        # Python 3.9+: usedforsecurity=False khai báo rõ là không dùng cho bảo mật
        # (checksum, khóa cache) - chấp nhận được, không báo.
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
    def _weak_algorithm(call: ast.Call, name: str | None) -> str | None:
        """Tên thuật toán yếu được dùng trong lời gọi, hoặc None."""
        if name in _WEAK_HASH_CONSTRUCTORS:
            return _WEAK_HASH_CONSTRUCTORS[name]
        if name == "hashlib.new":
            algorithm = get_argument(call, 0, "name")
            if isinstance(algorithm, ast.Constant) and isinstance(algorithm.value, str):
                # "SHA-1" và "sha1" là một.
                normalized = algorithm.value.lower().replace("-", "")
                if normalized in _WEAK_ALGORITHMS:
                    return normalized
        return None

    @staticmethod
    def _hashes_password(call: ast.Call) -> bool:
        """True nếu dữ liệu được hash có chứa một biến tên giống mật khẩu (vd user.password)."""
        for arg in call.args:
            for child in ast.walk(arg):
                name = child.id if isinstance(child, ast.Name) else getattr(child, "attr", None)
                if name and is_password_name(name):
                    return True
        return False


# Hàm của module random trả về giá trị ngẫu nhiên (seed/getstate không bị báo).
_RANDOM_FUNCTIONS = frozenset({
    f"random.{name}" for name in (
        "random", "randint", "randrange", "choice", "choices", "sample", "shuffle",
        "getrandbits", "randbytes", "uniform",
    )
})


class InsecureRandomMixin:
    """Dùng chung cho PY009, JV007 và CS007 (mixin: trộn vào một lớp con của SecurityRule).

    Bộ sinh số giả ngẫu nhiên không mật mã vẫn ổn cho game, lấy mẫu hay mô phỏng,
    nên lời gọi chỉ bị báo khi code xung quanh gợi ý một giá trị bảo mật.

    Mixin chứa metadata và logic chung; mỗi ngôn ngữ chỉ cần tìm lời gọi random
    và tên biến/hàm xung quanh rồi gọi :meth:`random_use_finding`.
    """

    name = "Insecure random generator for security value"
    severity = Severity.MEDIUM
    cwe = "CWE-330"
    category = "Insecure Randomness"

    def random_use_finding(
        self: Any, node: Any, context: Any, call: str, target: str | None, function: str | None,
    ) -> Finding | None:
        """Finding nếu ngữ cảnh gợi ý giá trị bảo mật, ngược lại None.

        ``target``: tên nhận giá trị (vd ``token = random.randint(...)``);
        ``function``: hàm/method bao quanh (vd ``def generate_otp()``).
        Tên biến là bằng chứng mạnh hơn tên hàm nên confidence cao hơn.
        """
        if target and is_security_value_name(target):
            return self.create_finding(node, context, f"{call} generates a value stored in '{target}'.",
                                       confidence=0.75)
        if function and is_security_value_name(function):
            return self.create_finding(node, context, f"{call} is used inside '{function}()'.", confidence=0.6)
        return None


@register_rule
class InsecureRandomRule(InsecureRandomMixin, CallRule):
    """PY009. Thứ tự kế thừa: mixin đứng trước để metadata của nó được dùng (theo MRO)."""

    id = "PY009"
    description = (
        "The random module uses the Mersenne Twister PRNG, which is predictable: after "
        "observing enough outputs an attacker can reconstruct its state and predict "
        "future tokens, passwords or reset codes."
    )
    recommendation = (
        "Use the secrets module (secrets.token_urlsafe(), secrets.token_hex(), "
        "secrets.choice()) or random.SystemRandom for security-sensitive values."
    )

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        if name in _RANDOM_FUNCTIONS:
            finding = self.random_use_finding(
                node, context, f"{name}()", self._assigned_name(node, context), context.enclosing_function_name(node),
            )
            if finding is not None:
                yield finding

    @staticmethod
    def _assigned_name(node: ast.AST, context: AnalysisContext) -> str | None:
        """Tên nhận giá trị: biến, thuộc tính, khóa dict hoặc keyword argument."""
        # Đi ngược lên cha tới câu lệnh chứa lời gọi; gặp keyword trước thì lấy tên keyword
        # (vd create_user(password=random.choice(...)) -> "password").
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
