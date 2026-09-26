"""Typed identity references — same identity evidence, same thing.

The slug resolver (`resolve.py`) stays the default path. These refs
add explicit, typed identity where correlation strength matters
(security findings, artifact attribution) so reviewers can see *why*
two names were treated as the same thing.
"""

from __future__ import annotations

from typing import Any, Literal

IdentityKind = Literal[
    "project", "package", "artifact", "repository", "registry_artifact", "purl", "cpe"
]


def identity_refs_for(ref: str) -> list[dict[str, str]]:
    """All identity forms derivable from one dependency ref, strongest first."""
    from core.entities.catalog import purl_for
    from core.entities.resolve import normalize_ref, resolve_project
    from core.risk.match import split_image_ref

    normalized = normalize_ref(ref)
    slug = resolve_project(ref)
    refs = [
        {"kind": "project", "value": slug},
        {"kind": "artifact", "value": normalized},
    ]
    registry, namespace, name = split_image_ref(ref)
    refs.append({"kind": "registry_artifact", "value": f"{registry}/{namespace}/{name}"})
    if "/" in normalized and "docker.io" not in normalized and "@" not in normalized:
        parts = normalized.split("/")
        if len(parts) == 2:
            refs.append({"kind": "repository", "value": normalized})
            refs.append({"kind": "purl", "value": purl_for("github", parts[0], parts[1])})
    refs.append({"kind": "purl", "value": purl_for("docker", namespace, name)})
    return refs


def same_identity(a: list[dict[str, str]], b: list[dict[str, str]]) -> dict[str, Any]:
    """Do two ref-sets share any identity value? Returns the shared ref or {}."""
    values_b = {r["value"] for r in b}
    for ref in a:
        if ref["value"] in values_b:
            return {"same": True, "via": ref}
    return {"same": False, "via": None}
