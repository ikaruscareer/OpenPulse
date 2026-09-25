"""Collector base interface — all collectors return raw dicts, never OSSEvents directly."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseCollector(ABC):
    name: str = "base"

    @abstractmethod
    def collect(self, project_slug: str) -> list[dict[str, Any]]:
        raise NotImplementedError
