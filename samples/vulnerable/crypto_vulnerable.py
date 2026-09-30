"""Demo: account utilities with weak hashing, predictable tokens and no TLS checks.

INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only.
"""
import hashlib
import random
import string

import requests


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # PY008 (HIGH: password)


def file_checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()  # PY008


def create_reset_token() -> str:
    reset_token = "".join(random.choices(string.ascii_letters + string.digits, k=32))  # PY009
    return reset_token


def fetch_profile(url: str) -> dict:
    return requests.get(url, verify=False, timeout=10).json()  # PY010
