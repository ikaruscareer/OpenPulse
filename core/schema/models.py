"""OpenPulse Intelligence Schema v0.1.0 — pydantic models (source of truth)."""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl

from .enums import Confidence, EventType, Impact

SCHEMA_VERSION = "0.1.0"


class Source(BaseModel):
    name: str  # e.g. "bitnami/official-blog", "endoflife.date", "osv.dev"
    url: HttpUrl
    authority: str = Field(description="official | primary | secondary | tertiary")
    fetched_at: datetime


class Evidence(BaseModel):
    source: Source
    excerpt: str = Field(max_length=2000)
    effective_date: Optional[date] = None
    announcement_date: Optional[date] = None


class CanonicalProject(BaseModel):
    """Entity resolution root: one project, many names/packages."""
    slug: str  # e.g. "bitnami", "redis", "postgresql"
    display_name: str
    github_repo: Optional[str] = None  # "org/repo"
    website: Optional[HttpUrl] = None
    purls: List[str] = []
    cpes: List[str] = []
    aliases: List[str] = []  # e.g. ["redis", "redis-server", "docker.io/redis", "bitnami/redis"]
    docker_images: List[str] = []


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
    affected_versions: List[str] = []
    affected_artifacts: List[Artifact] = []
    evidences: List[Evidence] = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def requires_action(self) -> bool:
        return self.impact in (Impact.ACTION, Impact.CRITICAL)
