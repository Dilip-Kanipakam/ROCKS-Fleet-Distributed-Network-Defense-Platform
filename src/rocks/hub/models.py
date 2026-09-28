from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EdgeInfo:
    sensor_id: str
    name: str
    status: str
    created_at: str
    last_seen: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sensor_id": self.sensor_id,
            "name": self.name,
            "status": self.status,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
        }
