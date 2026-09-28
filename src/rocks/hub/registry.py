from __future__ import annotations

from rocks.hub.auth import generate_api_key, hash_api_key, verify_api_key
from rocks.hub.models import EdgeInfo
from rocks.hub.storage import HubStorage


class EdgeRegistry:
    def __init__(self, storage: HubStorage) -> None:
        self.storage = storage

    def register(self, sensor_id: str, name: str | None = None) -> tuple[EdgeInfo, str]:
        if not sensor_id.strip():
            raise ValueError("sensor_id is required")
        api_key = generate_api_key()
        edge = self.storage.register_edge(sensor_id, name or sensor_id, hash_api_key(api_key))
        return edge, api_key

    def authenticate(self, sensor_id: str, api_key: str) -> bool:
        stored_hash = self.storage.get_api_key_hash(sensor_id)
        return stored_hash is not None and verify_api_key(api_key, stored_hash)

    def get(self, sensor_id: str) -> EdgeInfo | None:
        return self.storage.get_edge(sensor_id)

    def list(self) -> list[EdgeInfo]:
        return self.storage.list_edges()

    def touch(self, sensor_id: str) -> None:
        self.storage.touch_edge(sensor_id)
