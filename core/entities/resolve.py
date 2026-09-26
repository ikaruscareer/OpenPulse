"""Entity resolution: normalize aliases -> CanonicalProject slug.

Precedence:
1. EXPLICIT_ALIASES — curated overrides (Bitnami stacks first).
2. Catalog (data/canonical_projects.yaml) aliases + docker images.
3. Bitnami-namespace rule — any bitnami/bitnamilegacy/bitnamisecure
   image ref becomes a `bitnami-{image}` slug, preserving impact
   attribution for distribution events.
4. Fallback — the normalized ref itself.
"""

from __future__ import annotations

import re
from functools import lru_cache

EXPLICIT_ALIASES = {
    "redis": "redis",
    "redis-server": "redis",
    "docker.io/redis": "redis",
    "docker.io/library/redis": "redis",
    "bitnami/redis": "bitnami-redis-stack",
    "docker.io/bitnami/redis": "bitnami-redis-stack",
    "docker.io/bitnamilegacy/redis": "bitnami-redis-stack",
    "docker.io/bitnamisecure/redis": "bitnami-redis-stack",
    "bitnami": "bitnami",
}

BITNAMI_NAMESPACES = (
    "bitnami/",
    "docker.io/bitnami/",
    "bitnamilegacy/",
    "docker.io/bitnamilegacy/",
    "bitnamisecure/",
    "docker.io/bitnamisecure/",
)


def normalize_ref(ref: str) -> str:
    r = ref.strip().lower()
    r = re.sub(r":.*$", "", r)  # strip :tag
    r = re.sub(r"@.*$", "", r)  # strip @digest
    return r


@lru_cache(maxsize=1)
def _catalog_map() -> dict[str, str]:
    try:
        from core.entities.catalog import catalog_alias_map, load_catalog

        return catalog_alias_map(load_catalog())
    except Exception:
        return {}


def _bitnami_rule(normalized: str) -> str | None:
    for ns in BITNAMI_NAMESPACES:
        if normalized.startswith(ns):
            image = normalized[len(ns) :].split("/")[0]
            if image and image not in ("bitnami", "bitnamilegacy", "bitnamisecure"):
                return f"bitnami-{image}"
    return None


def resolve_project(ref: str) -> str:
    """Return canonical slug for a package/artifact ref."""
    n = normalize_ref(ref)
    if n in EXPLICIT_ALIASES:
        return EXPLICIT_ALIASES[n]
    catalog_hit = _catalog_map().get(n)
    if catalog_hit:
        return catalog_hit
    return _bitnami_rule(n) or n
