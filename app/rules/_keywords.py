"""Identifier keywords shared by several rules (PY007 secrets, PY008 crypto, PY009 random).

Kept in one place so the rules stay consistent. The leading underscore stops
the registry from treating this module as a rule module.
"""

from __future__ import annotations

from app.analyzer.utils import split_identifier

# A single word that on its own marks a credential.
SECRET_WORDS = frozenset({
    "password", "passwd", "pwd", "passphrase", "secret", "token", "apikey", "credential", "credentials",
})
# Two consecutive words that together mark a credential ("key" alone is too generic:
# sort_key, cache_key, dict key...).
SECRET_WORD_PAIRS = frozenset({
    ("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"),
    ("encryption", "key"), ("signing", "key"), ("auth", "key"), ("master", "key"),
})
# If the identifier ends with one of these words it describes *metadata about*
# a secret (PASSWORD_MIN_LENGTH, token_url, password_field), not the secret itself.
NON_SECRET_SUFFIXES = frozenset({
    "url", "uri", "endpoint", "path", "file", "filename", "dir", "name", "field", "label",
    "length", "len", "min", "max", "size", "count", "prompt", "message", "msg", "hint",
    "type", "header", "env", "var", "regex", "pattern", "format", "expiry", "expires",
    "ttl", "timeout", "id", "placeholder", "column", "policy", "validator", "error",
})

# Words suggesting that a random value is used for security purposes (PY009).
SECURITY_VALUE_WORDS = SECRET_WORDS | frozenset({
    "salt", "nonce", "otp", "pin", "session", "sessionid", "csrf", "xsrf", "captcha",
    "verification", "reset", "activation", "auth", "iv", "cookie", "signature",
})

PASSWORD_WORDS = frozenset({"password", "passwd", "pwd", "passphrase"})


def _has_pair(words: list[str], pairs: frozenset[tuple[str, str]]) -> bool:
    return any((a, b) in pairs for a, b in zip(words, words[1:]))


def is_secret_name(identifier: str) -> bool:
    """True if a variable/attribute/key name looks like it holds a credential."""
    words = split_identifier(identifier)
    if not words or words[-1] in NON_SECRET_SUFFIXES:
        return False
    return any(word in SECRET_WORDS for word in words) or _has_pair(words, SECRET_WORD_PAIRS)


def is_security_value_name(identifier: str) -> bool:
    """True if a name suggests a security-sensitive value (token, salt, otp...)."""
    words = split_identifier(identifier)
    if not words or words[-1] in NON_SECRET_SUFFIXES - {"id"}:
        return False
    return any(word in SECURITY_VALUE_WORDS for word in words) or _has_pair(words, SECRET_WORD_PAIRS)


def is_password_name(identifier: str) -> bool:
    return any(word in PASSWORD_WORDS for word in split_identifier(identifier))
