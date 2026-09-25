"""Analyzer base — pure functions: raw collector output -> partial OSSEvent fields."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

class BaseAnalyzer(ABC):
    name: str = "base"
    @abstractmethod
    def analyze(self, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise NotImplementedError
