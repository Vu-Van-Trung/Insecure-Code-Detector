"""Intentionally vulnerable test fixture: PY008 / PY009. Never run this file."""
import hashlib
import random
import string


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # expect: PY008


def file_fingerprint(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()  # expect: PY008


def create_reset_link(user) -> str:
    reset_token = "".join(random.choice(string.ascii_letters) for _ in range(32))  # expect: PY009
    return f"https://example.com/reset/{user.id}/{reset_token}"


def generate_otp() -> str:
    return str(random.randint(100000, 999999))  # expect: PY009
