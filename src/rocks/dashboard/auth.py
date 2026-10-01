from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from urllib.parse import parse_qs

from fastapi import Request


@dataclass(frozen=True)
class DashboardAuthConfig:
    username: str
    password_hash: str
    session_secret: str
    cookie_secure: bool = False
    session_max_age: int = 3600

    @property
    def configured(self) -> bool:
        return bool(self.username and self.password_hash and self.session_secret)


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    if not password:
        raise ValueError("password cannot be empty")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        expected = bytes.fromhex(digest_hex)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180_000)
    return hmac.compare_digest(actual, expected)


def create_session(username: str, secret: str, max_age: int) -> str:
    if not secret:
        raise ValueError("session secret cannot be empty")
    payload = {
        "sid": secrets.token_urlsafe(32),
        "username": username,
        "expires": int(time.time()) + max_age,
    }
    encoded = _encode(payload)
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
    return f"{encoded}.{_b64encode(signature)}"


def verify_session(value: str | None, secret: str) -> str | None:
    if not value or "." not in value or len(value) > 4096:
        return None
    encoded, signature = value.rsplit(".", 1)
    expected = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
    try:
        supplied = _b64decode(signature)
        payload = json.loads(_b64decode(encoded).decode("utf-8"))
    except (ValueError, TypeError, OverflowError):
        return None
    if not hmac.compare_digest(supplied, expected):
        return None
    if not isinstance(payload, dict):
        return None
    session_id = payload.get("sid")
    if not isinstance(session_id, str) or not session_id.strip() or len(session_id) > 128:
        return None
    expires = payload.get("expires")
    if isinstance(expires, bool) or not isinstance(expires, int) or expires <= int(time.time()):
        return None
    username = payload.get("username")
    return username if isinstance(username, str) and username else None


def is_authenticated(request: Request, config: DashboardAuthConfig) -> bool:
    return verify_session(request.cookies.get("rocks_dashboard_session"), config.session_secret) is not None


def parse_login_body(body: bytes) -> tuple[str, str]:
    values = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return values.get("username", [""])[0], values.get("password", [""])[0]


def _encode(value: dict[str, object]) -> str:
    return _b64encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
