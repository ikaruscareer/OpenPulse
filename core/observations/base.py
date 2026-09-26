"""Shared observation metadata — one envelope for every source kind.

RegistryObservation, GitHubRepositoryObservation and
LifecycleObservation all carry: observation_id, source,
entity_reference, observed_at, content_hash, parser_version.
Source-specific facts live in each subclass payload. Future
collectors emit these instead of inventing new shapes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from core.evidence.provenance import PARSER_VERSION, hash_content


class ObservationBase(BaseModel):
    observation_id: str = ""
    source: str = "unknown"
    entity_reference: str = ""
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_hash: str | None = None
    parser_version: str = PARSER_VERSION

    def seal(self, body: dict[str, Any]) -> ObservationBase:
        """Hash the payload; derive a stable observation id. Immutable after."""
        self.content_hash = hash_content(body)
        assert self.content_hash is not None
        short = self.content_hash.split(":")[1][:12]
        if not self.observation_id:
            self.observation_id = f"{self.source}:{self.entity_reference}:{short}"
        return self


class GitHubRepositoryObservation(ObservationBase):
    source: str = "github"
    repo: str = ""
    archived: bool = False
    pushed_at: str | None = None
    default_branch: str | None = None
    license: str | None = None

    def seal(self, body: dict[str, Any] | None = None) -> GitHubRepositoryObservation:  # type: ignore[override]
        self.entity_reference = self.entity_reference or self.repo
        return super().seal(
            body
            or {
                "repo": self.repo,
                "archived": self.archived,
                "pushed_at": self.pushed_at,
                "license": self.license,
            }
        )  # type: ignore[return-value]


class LifecycleObservation(ObservationBase):
    source: str = "endoflife"
    product: str = ""
    cycle: str = ""
    eol: Any = None
    support: Any = None
    latest: str | None = None

    def seal(self, body: dict[str, Any] | None = None) -> LifecycleObservation:  # type: ignore[override]
        self.entity_reference = self.entity_reference or f"{self.product}:{self.cycle}"
        return super().seal(
            body
            or {
                "product": self.product,
                "cycle": self.cycle,
                "eol": self.eol,
                "support": self.support,
                "latest": self.latest,
            }
        )  # type: ignore[return-value]
