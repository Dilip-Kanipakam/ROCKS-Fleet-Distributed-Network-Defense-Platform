from __future__ import annotations

from rocks.hub.auth import generate_api_key, hash_api_key, verify_api_key


def test_api_key_is_generated_and_only_hash_is_stored():
    key = generate_api_key()
    stored = hash_api_key(key)
    assert key not in stored
    assert verify_api_key(key, stored) is True
    assert verify_api_key("wrong-key", stored) is False


def test_malformed_hash_is_rejected():
    assert verify_api_key("key", "not-a-hash") is False
