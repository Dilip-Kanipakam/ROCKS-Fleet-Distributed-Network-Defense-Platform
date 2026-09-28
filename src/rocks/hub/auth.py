from __future__ import annotations

import hashlib
import hmac
import secrets


_ITERATIONS = 120_000


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def hash_api_key(api_key: str, *, salt: bytes | None = None) -> str:
    if not api_key:
        raise ValueError("API key cannot be empty")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", api_key.encode(), salt, _ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", api_key.encode(), salt, _ITERATIONS)
    return hmac.compare_digest(actual, expected)
