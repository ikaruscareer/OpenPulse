"""Canonical catalog loader — data/canonical_projects.yaml.

The catalog is the single source for entity resolution. Aliases in the
file must be lowercase and tag/digest-free (enforced by tests).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "data" / "canonical_projects.yaml"


@lru_cache(maxsize=4)
def load_catalog(path: str | None = None) -> list[dict[str, Any]]:
    with open(path or DEFAULT_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def catalog_alias_map(catalog: list[dict[str, Any]]) -> dict[str, str]:
    """alias -> slug for every alias and docker image in the catalog."""
    out: dict[str, str] = {}
    for entry in catalog:
        slug = entry.get("slug", "")
        for alias in (entry.get("aliases") or []) + (entry.get("docker_images") or []):
            out.setdefault(str(alias).strip().lower(), slug)
    return out


def purl_for(kind: str, namespace: str, name: str, version: str | None = None) -> str:
    """Minimal Package-URL builder (https://github.com/package-url/purl-spec)."""
    base = {
        "docker": f"pkg:docker/{namespace}/{name}",
        "github": f"pkg:github/{namespace}/{name}",
        "generic": f"pkg:generic/{name}",
    }.get(kind, f"pkg:generic/{name}")
    return f"{base}@{version}" if version else base
