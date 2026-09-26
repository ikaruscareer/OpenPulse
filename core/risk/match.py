"""Impact match — minimal Phase-10 preview: does an OSSEvent affect a dependency ref?

Matching is conservative on purpose:
- Artifact triple (registry, namespace, name, tag stripped) equality.
- Otherwise project-slug equality via entity resolution.

`docker.io/redis:7.2` does NOT match a `docker.io/bitnami/redis`
artifact: different namespace, different stack. That distinction is
the whole point of the Bitnami case.
"""

from __future__ import annotations

from core.entities.resolve import normalize_ref, resolve_project
from core.schema.models import OSSEvent


def split_image_ref(ref: str) -> tuple[str, str, str]:
    """(registry, namespace, name) with tags/digests/schemes stripped."""
    r = normalize_ref(ref)
    for scheme in ("oci://", "https://", "http://", "docker://"):
        if r.startswith(scheme):
            r = r[len(scheme) :]
    parts = r.split("/")
    if len(parts) >= 3 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, rest = parts[0], parts[1:]
    else:
        registry, rest = "docker.io", parts
    if len(rest) == 1:
        namespace, name = "library", rest[0]
    else:
        namespace, name = "/".join(rest[:-1]), rest[-1]
    return registry, namespace, name


def match_artifact(ref: str, artifact_ref: str) -> bool:
    return split_image_ref(ref) == split_image_ref(artifact_ref)


def event_affects_ref(event: OSSEvent, ref: str) -> dict[str, str | bool | None]:
    """Return {affected, via, relationship, detail} for one dependency ref."""
    for a in event.affected_artifacts:
        if match_artifact(ref, a.ref):
            return {
                "affected": True,
                "via": "artifact",
                "relationship": "AFFECTS_ARTIFACT",
                "detail": f"{ref} matches affected artifact {a.ref}",
            }
    if resolve_project(ref) == event.project_slug:
        return {
            "affected": True,
            "via": "project",
            "relationship": "AFFECTS_PROJECT",
            "detail": f"{ref} resolves to watched project {event.project_slug}",
        }
    return {
        "affected": False,
        "via": None,
        "relationship": "UNKNOWN",
        "detail": f"{ref} matches nothing in {event.id}",
    }
