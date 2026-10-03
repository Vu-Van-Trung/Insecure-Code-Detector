"""Từ khóa trong tên biến dùng chung cho nhiều rule (PY007 secret, PY008 crypto, PY009 random và bản Java/C#).

Đặt ở một chỗ để các rule nhất quán với nhau. Dấu gạch dưới ở đầu tên module
khiến registry không coi đây là một module rule.
"""

from __future__ import annotations

from app.analyzer.utils import split_identifier

# Một từ đơn lẻ tự nó đã cho thấy biến chứa thông tin đăng nhập.
SECRET_WORDS = frozenset({
    "password", "passwd", "pwd", "passphrase", "secret", "token", "apikey", "credential", "credentials",
})
# Hai từ liên tiếp cùng nhau mới chỉ ra thông tin đăng nhập ("key" đứng một mình
# quá chung chung: sort_key, cache_key, key của dict...).
SECRET_WORD_PAIRS = frozenset({
    ("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"),
    ("encryption", "key"), ("signing", "key"), ("auth", "key"), ("master", "key"),
})
# Tên kết thúc bằng một trong các từ này mô tả *thông tin về* secret
# (PASSWORD_MIN_LENGTH, token_url, password_field), không phải chính secret.
NON_SECRET_SUFFIXES = frozenset({
    "url", "uri", "endpoint", "path", "file", "filename", "dir", "name", "field", "label",
    "length", "len", "min", "max", "size", "count", "prompt", "message", "msg", "hint",
    "type", "header", "env", "var", "regex", "pattern", "format", "expiry", "expires",
    "ttl", "timeout", "id", "placeholder", "column", "policy", "validator", "error",
})

# Từ gợi ý một giá trị ngẫu nhiên được dùng cho mục đích bảo mật (PY009).
SECURITY_VALUE_WORDS = SECRET_WORDS | frozenset({
    "salt", "nonce", "otp", "pin", "session", "sessionid", "csrf", "xsrf", "captcha",
    "verification", "reset", "activation", "auth", "iv", "cookie", "signature",
})

# Từ chỉ mật khẩu (PY008: hash mật khẩu bằng MD5 nặng hơn hash dữ liệu thường).
PASSWORD_WORDS = frozenset({"password", "passwd", "pwd", "passphrase"})


def _has_pair(words: list[str], pairs: frozenset[tuple[str, str]]) -> bool:
    """True nếu có hai từ LIỀN NHAU tạo thành một cặp trong ``pairs`` (vd api + key)."""
    return any((a, b) in pairs for a, b in zip(words, words[1:]))


def is_secret_name(identifier: str) -> bool:
    """True nếu tên biến/thuộc tính/khóa trông như đang chứa thông tin đăng nhập.

    Vd ``DB_PASSWORD``, ``apiKey`` -> True; ``password_field``, ``sort_key`` -> False.
    """
    words = split_identifier(identifier)
    if not words or words[-1] in NON_SECRET_SUFFIXES:
        return False
    return any(word in SECRET_WORDS for word in words) or _has_pair(words, SECRET_WORD_PAIRS)


def is_security_value_name(identifier: str) -> bool:
    """True nếu tên gợi ý một giá trị nhạy cảm về bảo mật (token, salt, otp...).

    Khác ``is_secret_name``: hậu tố "id" không loại trừ, vì ``session_id`` sinh
    bằng random là một lỗ hổng thật.
    """
    words = split_identifier(identifier)
    if not words or words[-1] in NON_SECRET_SUFFIXES - {"id"}:
        return False
    return any(word in SECURITY_VALUE_WORDS for word in words) or _has_pair(words, SECRET_WORD_PAIRS)


def is_password_name(identifier: str) -> bool:
    """True nếu tên có chứa một từ chỉ mật khẩu."""
    return any(word in PASSWORD_WORDS for word in split_identifier(identifier))
