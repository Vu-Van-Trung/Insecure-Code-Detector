"""Safe counterpart of crypto_vulnerable.py."""
import hashlib
import os
import random
import secrets


def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def file_fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cache_etag(data: bytes) -> str:
    # MD5 is acceptable for a non-security checksum when declared explicitly.
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def create_reset_link(user) -> str:
    reset_token = secrets.token_urlsafe(32)
    return f"https://example.com/reset/{user.id}/{reset_token}"


def roll_dice() -> int:
    # random is fine for games and simulations.
    return random.randint(1, 6)
