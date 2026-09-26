"""OpenPulse Intelligence Schema v0.2.0 — pydantic models (source of truth)."""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl

from .enums import Confidence, EventType, Impact

SCHEMA_VERSION = "0.2.0"


class Source(BaseModel):
    name: str  # e.g. "bitnami/official-blog", "endoflife.date", "osv.dev"
    url: HttpUrl
    authority: str = Field(description="official | primary | secondary | tertiary")
    fetched_at: datetime
    # Provenance (all optional — v0.1.0 documents still validate).
    family: str | None = Field(
        default=None,
        description="Independent-source family (e.g. 'bitnami'); "
        "republished copies share the originator's family",
    )
    derived_from: str | None = Field(
        default=None, description="Source name this evidence derives from, if any"
    )
    acquisition_method: str | None = Field(
        default=None, description="e.g. 'https-collector', 'manual-curation'"
    )
    parser_version: str | None = Field(default=None, description="Parser that produced this record")
    content_hash: str | None = Field(
        default=None, description="sha256:<hex> over canonical source content"
    )


class Evidence(BaseModel):
    source: Source
    excerpt: str = Field(max_length=2000)
    effective_date: date | None = None
    announcement_date: date | None = None
    relation: Literal["supports", "context", "contradicts"] = Field(
        default="supports",
        description="How this evidence relates to the event claim",
    )


class CanonicalProject(BaseModel):
    """Entity resolution root: one project, many names/packages."""

    slug: str  # e.g. "bitnami", "redis", "postgresql"
    display_name: str
    github_repo: str | None = None  # "org/repo"
    website: HttpUrl | None = None
    purls: list[str] = []
    cpes: list[str] = []
    aliases: list[str] = []  # e.g. ["redis", "redis-server", "docker.io/redis", "bitnami/redis"]
    docker_images: list[str] = []


class Artifact(BaseModel):
    kind: str  # docker-image | helm-chart | npm | pypi | maven | ...
    ref: str  # e.g. "docker.io/bitnami/redis:7.2"


class OSSEvent(BaseModel):
    id: str
    schema_version: str = SCHEMA_VERSION
    project_slug: str
    event_type: EventType
    title: str
    summary: str
    confidence: Confidence
    impact: Impact
    affected_versions: list[str] = []
    affected_artifacts: list[Artifact] = []
    evidences: list[Evidence] = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def requires_action(self) -> bool:
        return self.impact in (Impact.ACTION, Impact.CRITICAL)
