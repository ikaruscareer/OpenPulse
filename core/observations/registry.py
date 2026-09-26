"""Registry observations — immutable, digest-aware facts about a repository.

A tag is NOT an identity: `latest` today may resolve to a different
digest tomorrow. Observations persist tag→digest mappings so change
detection compares facts against facts, never a snapshot against a
hunch. No observation, no change claim: a first sighting is a
baseline, not an event.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from core.observations.base import ObservationBase


class RegistryObservation(ObservationBase):
    source: str = "docker-hub"
    collector: str = "registries"
    registry: str = "docker.io"
    namespace: str
    repository: str
    tags: dict[str, list[str]] = Field(
        default_factory=dict, description="tag -> sorted image digests (multi-arch aware)"
    )
    tag_count: int | None = None
    missing: bool = False

    def seal(self, body: dict | None = None) -> RegistryObservation:  # type: ignore[override]
        """Attach content hash + observation id. Immutable after sealing."""
        self.entity_reference = self.entity_reference or (
            f"{self.registry}/{self.namespace}/{self.repository}"
        )
        super().seal(
            body
            or {
                "registry": self.registry,
                "namespace": self.namespace,
                "repository": self.repository,
                "tags": self.tags,
                "missing": self.missing,
            }
        )
        return self


class Change(BaseModel):
    """One detected difference between two observations of the same repository."""

    type: str = Field(
        description="tag_appeared | tag_disappeared | tag_digest_changed | "
        "latest_moved | repo_missing | repo_restored"
    )
    registry: str = "docker.io"
    namespace: str
    repository: str
    tag: str | None = None
    previous: list[str] | None = None
    current: list[str] | None = None
    previous_hash: str | None = Field(default=None, description="Previous observation content_hash")
    current_hash: str | None = Field(default=None, description="Current observation content_hash")
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def to_observation(probe: dict, observed_at: datetime | None = None) -> RegistryObservation:
    """Registry probe dict (from the docker collector) -> sealed observation."""
    return RegistryObservation(
        registry=probe.get("registry", "docker.io"),
        namespace=probe.get("namespace", ""),
        repository=probe.get("repo", ""),
        observed_at=observed_at or datetime.now(timezone.utc),
        tags=dict(probe.get("digests", {})),
        tag_count=probe.get("count"),
        missing=bool(probe.get("missing")),
    ).seal()


def diff_observations(prev: RegistryObservation | None, curr: RegistryObservation) -> list[Change]:
    """Compare two observations. No previous observation -> baseline -> no changes."""
    if prev is None:
        return []
    if prev.content_hash == curr.content_hash and prev.missing == curr.missing:
        return []
    changes: list[Change] = []
    common = {
        "registry": curr.registry,
        "namespace": curr.namespace,
        "repository": curr.repository,
        "previous_hash": prev.content_hash,
        "current_hash": curr.content_hash,
    }
    if curr.missing and not prev.missing:
        return [Change(type="repo_missing", observed_at=curr.observed_at, **common)]
    if not curr.missing and prev.missing:
        return [Change(type="repo_restored", observed_at=curr.observed_at, **common)]
    prev_tags, curr_tags = prev.tags or {}, curr.tags or {}
    for tag in sorted(set(curr_tags) - set(prev_tags)):
        changes.append(
            Change(
                type="tag_appeared",
                tag=tag,
                current=curr_tags[tag],
                observed_at=curr.observed_at,
                **common,
            )
        )
    for tag in sorted(set(prev_tags) - set(curr_tags)):
        changes.append(
            Change(
                type="tag_disappeared",
                tag=tag,
                previous=prev_tags[tag],
                observed_at=curr.observed_at,
                **common,
            )
        )
    for tag in sorted(set(prev_tags) & set(curr_tags)):
        if prev_tags[tag] != curr_tags[tag]:
            changes.append(
                Change(
                    type="latest_moved" if tag == "latest" else "tag_digest_changed",
                    tag=tag,
                    previous=prev_tags[tag],
                    current=curr_tags[tag],
                    observed_at=curr.observed_at,
                    **common,
                )
            )
    return changes
