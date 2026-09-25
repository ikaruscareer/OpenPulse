"""Entity resolution: normalize aliases -> CanonicalProject slug."""
from __future__ import annotations

import re

ALIAS_MAP = {
    "redis": "redis",
    "redis-server": "redis",
    "docker.io/redis": "redis",
    "docker.io/library/redis": "redis",
    "bitnami/redis": "bitnami-redis-stack",
    "docker.io/bitnami/redis": "bitnami-redis-stack",
    "bitnami": "bitnami",
}

def normalize_ref(ref: str) -> str:
    r = ref.strip().lower()
    r = re.sub(r":.*$", "", r)  # strip :tag
    r = re.sub(r"@.*$", "", r)  # strip @digest
    return r

def resolve_project(ref: str) -> str:
    """Return canonical slug for a package/artifact ref. Falls back to normalized ref."""
    n = normalize_ref(ref)
    return ALIAS_MAP.get(n, n)
