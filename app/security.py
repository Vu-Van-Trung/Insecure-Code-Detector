"""Bảo vệ ứng dụng Web: CSRF protection và Authentication (Basic Auth / API Key).

Thiết kế an toàn:
* CSRF: Sử dụng Double-Submit Cookie Pattern với token cryptographically random (secrets.token_hex).
  So khớp chuỗi thời gian hằng số (hmac.compare_digest) để chống timing attack.
* Web Authentication: HTTP Basic Auth khi cấu hình ANALYZER_WEB_USER và ANALYZER_WEB_PASSWORD.
* API Authentication: Header X-API-Key hoặc Bearer token khi cấu hình ANALYZER_API_KEY.
* Mặc định ở môi trường phát triển cục bộ (khi không đặt biến môi trường), ứng dụng chạy mở không cần mật khẩu.
"""

from __future__ import annotations

import base64
import hmac
import os
import secrets
import re
from typing import Final
from urllib.parse import urlsplit

from fastapi import Request

CSRF_COOKIE_NAME: Final = "csrf_token"
CSRF_FORM_NAME: Final = "csrf_token"
CSRF_HEADER_NAME: Final = "X-CSRF-Token"


def generate_csrf_token(secret: bytes) -> str:
    """Create a random token authenticated by this server."""
    nonce = secrets.token_hex(32)
    signature = hmac.digest(secret, nonce.encode("ascii"), "sha256").hex()
    return nonce + "." + signature


def verify_csrf_token(provided: str | None, expected: str | None, secret: bytes) -> bool:
    """Reject missing, malformed, unsigned or mismatching tokens without exceptions."""
    if not provided or not expected:
        return False
    if not re.fullmatch(r"[0-9a-f]{64}[.][0-9a-f]{64}", provided):
        return False
    if not re.fullmatch(r"[0-9a-f]{64}[.][0-9a-f]{64}", expected):
        return False
    nonce, signature = expected.split(".")
    valid = hmac.digest(secret, nonce.encode("ascii"), "sha256").hex()
    return hmac.compare_digest(provided, expected) and hmac.compare_digest(signature, valid)


def is_web_auth_configured() -> bool:
    """True nếu thông tin đăng nhập web được cấu hình trong biến môi trường."""
    return bool(os.environ.get("ANALYZER_WEB_USER") and os.environ.get("ANALYZER_WEB_PASSWORD"))


def is_api_auth_configured() -> bool:
    """True nếu API key được cấu hình trong biến môi trường."""
    return bool(os.environ.get("ANALYZER_API_KEY"))


def verify_basic_auth(request: Request) -> bool:
    """Kiểm tra HTTP Basic Auth cho các route web giao diện."""
    if not is_web_auth_configured():
        return True

    expected_user = os.environ.get("ANALYZER_WEB_USER", "")
    expected_pass = os.environ.get("ANALYZER_WEB_PASSWORD", "")

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        return False

    try:
        encoded = auth_header.split(" ", 1)[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        return False

    return (
        hmac.compare_digest(username, expected_user)
        and hmac.compare_digest(password, expected_pass)
    )


def verify_api_key(request: Request) -> bool:
    """Kiểm tra API Key cho các route /api/."""
    if not is_api_auth_configured():
        return True

    expected_key = os.environ.get("ANALYZER_API_KEY", "")
    if not expected_key:
        return True

    # Kiểm tra X-API-Key header
    provided_key = request.headers.get("X-API-Key")
    if provided_key and hmac.compare_digest(provided_key.strip(), expected_key):
        return True

    # Kiểm tra Authorization: Bearer <key>
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        bearer_token = auth_header.split(" ", 1)[1]
        if hmac.compare_digest(bearer_token.strip(), expected_key):
            return True

    return False


def same_origin_request(request: Request) -> bool:
    """Reject browser requests explicitly originating from a different origin."""
    fetch_site = request.headers.get("sec-fetch-site", "").lower()
    if fetch_site == "cross-site":
        return False
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return True  # Non-browser clients must still supply the CSRF token.
    # Sandboxed/embedded browsers can omit the Referer and serialize their opaque
    # origin as "null" even for a same-origin form. In that case rely on the
    # browser's Fetch Metadata signal; the route still requires a valid CSRF token.
    if origin == "null":
        return fetch_site == "same-origin"
    try:
        parsed = urlsplit(origin)
        expected = urlsplit(str(request.base_url))
        def authority(url):
            host = (url.hostname or "").lower()
            if host in ("127.0.0.1", "localhost", "::1"):
                host = "localhost"
            return (url.scheme.lower(), host,
                    url.port or (443 if url.scheme == "https" else 80))
        return authority(parsed) == authority(expected)
    except ValueError:
        return False
