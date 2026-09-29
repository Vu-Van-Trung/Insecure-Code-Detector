"""Safe counterpart of requests_vulnerable.py."""
import ssl

import requests

INTERNAL_CA_BUNDLE = "/etc/ssl/certs/internal-ca.pem"


def fetch(url: str):
    return requests.get(url, timeout=10)


def fetch_internal(url: str):
    return requests.get(url, verify=INTERNAL_CA_BUNDLE, timeout=10)


def secure_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED
    return context
