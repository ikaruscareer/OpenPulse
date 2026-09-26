"""Registry collector — distribution signals (bitnami vs legacy vs secure)."""

from __future__ import annotations

from typing import Any

import httpx

from collectors.base import BaseCollector
from collectors.errors import as_error


def docker_hub_url(namespace: str, repo: str) -> str:
    return f"https://hub.docker.com/v2/repositories/{namespace}/{repo}/tags?page_size=5"


def parse_tags(namespace: str, repo: str, payload: dict[str, Any]) -> dict[str, Any]:
    tags = [t.get("name") for t in payload.get("results", [])]
    digests = {}
    for t in payload.get("results", []):
        if not t.get("name"):
            continue
        ds = sorted({img.get("digest") for img in t.get("images", []) if img.get("digest")})
        digests[t["name"]] = ds
    return {
        "collector": "registries",
        "registry": "docker.io",
        "namespace": namespace,
        "repo": repo,
        "tags_sample": tags,
        "digests": digests,
        "count": payload.get("count"),
        "has_versioned_tags": any(t != "latest" for t in tags),
        "latest_only": bool(tags) and all(t == "latest" for t in tags),
    }


class RegistryCollector(BaseCollector):
    name = "registries"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def check_image(self, namespace: str, repo: str) -> dict[str, Any]:
        try:
            r = httpx.get(docker_hub_url(namespace, repo), timeout=self.timeout)
            if r.status_code == 404:
                return {
                    "collector": "registries",
                    "namespace": namespace,
                    "repo": repo,
                    "missing": True,
                }
            r.raise_for_status()
            return parse_tags(namespace, repo, r.json())
        except Exception as e:
            return as_error("registries", e, namespace=namespace, repo=repo)

    def collect(self, project_slug: str) -> list[dict[str, Any]]:
        # Generic acquisition knows nothing product-specific: callers use
        # check_image(namespace, repo) directly, or a named reference set
        # from collectors/registries/reference.py for rehearsed scenarios.
        return [
            {
                "collector": "registries",
                "project": project_slug,
                "skipped": "use check_image(namespace, repo)",
            }
        ]
