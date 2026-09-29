"""Intentionally vulnerable test fixture: PY010. Never run this file."""
import ssl

import requests


def fetch(url: str):
    return requests.get(url, verify=False, timeout=10)  # expect: PY010


def upload(session: requests.Session, url: str, data: bytes):
    return session.post(url, data=data, verify=False)  # expect: PY010


def insecure_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # expect: PY010
    return context
