"""Demo: account utilities with modern primitives."""
import hashlib
import hmac
import os
import secrets

import requests

PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)


def verify_password(password: str, stored: bytes) -> bool:
    salt, expected = stored[:16], stored[16:]
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(actual, expected)


def file_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_reset_token() -> str:
    return secrets.token_urlsafe(32)


def fetch_profile(url: str) -> dict:
    return requests.get(url, timeout=10).json()
