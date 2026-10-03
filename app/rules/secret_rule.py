"""PY007 - Secret được ghi cứng trong code (hardcoded secrets).

Hai bộ phát hiện bổ sung cho nhau:

1. Theo tên (AST): một chuỗi hằng được gán cho tên trông như thông tin đăng
   nhập (``API_KEY = "..."``, ``self.password = "..."``, ``connect(password="...")``,
   ``{"token": "..."}``). Giá trị giữ chỗ (placeholder) bị bỏ qua và độ hỗn loạn
   (entropy) của giá trị được dùng để chấm confidence.
2. Theo định dạng (regex): mọi chuỗi hằng khớp một định dạng secret nổi tiếng
   (AWS access key, GitHub token, khối private key...), bất kể tên biến. Ở đây
   dùng regex vì các định dạng này không biểu diễn được bằng AST.

BẢO MẬT: giá trị secret không bao giờ được ghi log và bị che (mask) trong đoạn
``code`` hiển thị, để report không làm lộ secret.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from app.analyzer.context import AnalysisContext
from app.config.settings import Whitelist
from app.models.finding import Finding, Severity
from app.rules._keywords import is_secret_name
from app.rules.base import SecurityRule, node_location
from app.rules.registry import register_rule

if TYPE_CHECKING:
    from app.config.settings import AnalyzerSettings

# Chuỗi ngắn hơn 4 ký tự gần như không thể là secret thật.
MIN_SECRET_LENGTH = 4
# Entropy Shannon (bit/ký tự) mà từ đó giá trị trông như được sinh ngẫu nhiên.
# Từ tiếng Anh thường ~2.5-3.0; token ngẫu nhiên base64/hex thường > 3.5.
HIGH_ENTROPY_THRESHOLD = 3.5
HIGH_ENTROPY_MIN_LENGTH = 16

# Giá trị giữ chỗ / rõ ràng không phải secret ("changeme", "<your-key>", "${API_KEY}"...).
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
# Định danh toàn chữ hoa thường là TÊN của biến môi trường, vd TOKEN = "GITHUB_TOKEN".
_ENV_VAR_NAME = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")

# Các định dạng secret nổi tiếng: (mô tả, regex, severity).
KNOWN_SECRET_FORMATS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.HIGH),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.HIGH),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
    ("Stripe live secret key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"), Severity.HIGH),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
)


def shannon_entropy(value: str) -> float:
    """Lượng thông tin trung bình trên mỗi ký tự; token ngẫu nhiên có điểm cao, từ ngữ có điểm thấp.

    Công thức: H = -Σ p(c) * log2(p(c)), với p(c) là tần suất xuất hiện của ký tự c.
    """
    if not value:
        return 0.0
    length = len(value)
    return -sum(count / length * math.log2(count / length) for count in Counter(value).values())


def is_placeholder(value: str) -> bool:
    """True nếu giá trị quá ngắn, là placeholder hoặc là tên biến môi trường."""
    stripped = value.strip()
    return (
        len(stripped) < MIN_SECRET_LENGTH
        or bool(_PLACEHOLDER.match(stripped))
        or bool(_ENV_VAR_NAME.match(stripped))
    )


def match_known_format(value: str) -> tuple[str, Severity] | None:
    """(mô tả, severity) của định dạng secret nổi tiếng mà giá trị khớp, hoặc None."""
    for description, pattern, severity in KNOWN_SECRET_FORMATS:
        if pattern.search(value):
            return description, severity
    return None


def mask_secret(value: str) -> str:
    """Chỉ giữ vài ký tự đầu để vẫn nhận ra được finding, vd ``"AKIA********"``."""
    # Tối đa 4 ký tự và không quá 1/4 độ dài, để secret ngắn không bị lộ phần lớn.
    visible = min(4, len(value) // 4)
    return value[:visible] + "*" * 8


def masked_line(node: Any, context: Any, secret: str) -> str:
    """Dòng mã nguồn của ``node`` với secret đã bị che, để report không làm lộ secret."""
    line = context.get_line(node_location(node)[0])
    if secret and secret in line:
        return line.replace(secret, mask_secret(secret))
    # Chuỗi nhiều dòng hoặc có ký tự escape (không tìm thấy nguyên văn trên dòng):
    # không mạo hiểm in ra dòng code, che toàn bộ.
    return "<secret value masked>"


class HardcodedSecretMixin:
    """Metadata, whitelist và cách chấm điểm dùng chung cho PY007, JV008 và CS008.

    Mixin được trộn vào một lớp con của :class:`SecurityRule`; rule của từng
    ngôn ngữ chỉ cần tìm các chuỗi hằng và tên mà chúng được gán cho.
    """

    name = "Hardcoded secret"
    severity = Severity.HIGH
    cwe = "CWE-798"
    category = "Hardcoded Credentials"

    def __init__(self) -> None:
        self.whitelist = Whitelist()

    def configure(self, settings: AnalyzerSettings) -> None:
        # whitelist.json "allowed_secrets": regex các giá trị đã biết không phải secret
        # (dữ liệu test, key mẫu công khai). Chỉ bị ẩn, không phải được coi là an toàn.
        self.whitelist = settings.whitelist

    def check_known_format(self: Any, node: Any, context: Any, value: str) -> Iterator[Finding]:
        """Mọi chuỗi hằng khớp định dạng secret nổi tiếng, bất kể tên biến (confidence 0.95)."""
        known = match_known_format(value)
        if known is None or self.whitelist.is_secret_allowed(value):
            return
        description, severity = known
        yield self.create_finding(
            node, context, f"Hardcoded {description} found in a string literal.",
            severity=severity, confidence=0.95, code=masked_line(node, context, value),
        )

    def check_named_value(self: Any, node: Any, context: Any, name: str, secret: str) -> Iterator[Finding]:
        """Chuỗi hằng gán cho tên giống thông tin đăng nhập, chấm điểm theo entropy."""
        # Giá trị khớp định dạng nổi tiếng đã được check_known_format báo rồi -> tránh trùng.
        if not is_secret_name(name) or is_placeholder(secret) or match_known_format(secret):
            return
        if self.whitelist.is_secret_allowed(secret):
            return
        code = masked_line(node, context, secret)
        # Dài và ngẫu nhiên -> gần như chắc chắn là secret thật (HIGH, 0.85);
        # ngắn hoặc giống từ ngữ (vd "admin123") -> có thể là mật khẩu yếu/giá trị test (MEDIUM, 0.6).
        if len(secret) >= HIGH_ENTROPY_MIN_LENGTH and shannon_entropy(secret) >= HIGH_ENTROPY_THRESHOLD:
            yield self.create_finding(
                node, context, f"High-entropy string assigned to '{name}' looks like a hardcoded secret.",
                confidence=0.85, code=code,
            )
        else:
            yield self.create_finding(
                node, context, f"String literal assigned to '{name}' may be a hardcoded secret.",
                severity=Severity.MEDIUM, confidence=0.6, code=code,
            )


def _target_name(target: ast.AST) -> str | None:
    """Tên dùng cho một giá trị: ``x``, ``obj.x`` -> x, ``d["x"]`` -> x."""
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
class HardcodedSecretRule(HardcodedSecretMixin, SecurityRule):
    """PY007 cho Python: tìm chuỗi hằng trong AST rồi giao cho logic của mixin."""

    id = "PY007"
    description = (
        "A credential (password, API key, token, private key) is written directly in "
        "the source code. Anyone with access to the repository, its history, a build "
        "artifact or a leaked copy can use it, and rotating it requires a code change."
    )
    recommendation = (
        "Load secrets at runtime from environment variables or a secret manager "
        "(e.g. os.environ['API_KEY']), and revoke/rotate any secret that was committed."
    )
    # Constant: kiểm tra định dạng; các loại còn lại: kiểm tra theo tên.
    node_types = (ast.Assign, ast.AnnAssign, ast.keyword, ast.Dict, ast.Constant)

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                yield from self.check_known_format(node, context, node.value)
            return
        for name, value in self._named_values(node):
            # Chỉ xét giá trị là chuỗi hằng; os.environ["X"] hay biến khác thì không phải hardcode.
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                yield from self.check_named_value(value, context, name, value.value)

    @staticmethod
    def _named_values(node: ast.AST) -> Iterator[tuple[str, ast.AST]]:
        """Các cặp (tên, giá trị) của phép gán, keyword argument và phần tử dict."""
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
