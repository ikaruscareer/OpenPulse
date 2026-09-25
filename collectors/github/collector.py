"""GitHub releases collector — upstream source of truth for tags, archive/deprecation signals."""

from __future__ import annotations

from typing import Any

import httpx

from collectors.base import BaseCollector

API = "https://api.github.com/repos/{repo}/releases?per_page=20"


def parse_releases(repo: str, payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in payload:
        out.append(
            {
                "collector": "github",
                "repo": repo,
                "tag": r.get("tag_name"),
                "name": r.get("name"),
                "published_at": r.get("published_at"),
                "prerelease": bool(r.get("prerelease")),
                "url": r.get("html_url"),
            }
        )
    return out


class GitHubCollector(BaseCollector):
    name = "github"

    def __init__(self, repo_map: dict[str, str] | None = None, timeout: float = 15.0):
        # project_slug -> "org/repo", e.g. {"redis": "redis/redis"}
        self.repo_map = repo_map or {}
        self.timeout = timeout

    def collect(self, project_slug: str) -> list[dict[str, Any]]:
        repo = self.repo_map.get(project_slug)
        if not repo:
            return [
                {
                    "collector": "github",
                    "project": project_slug,
                    "skipped": f"no repo mapping for {project_slug}",
                }
            ]
        try:
            r = httpx.get(
                API.format(repo=repo),
                timeout=self.timeout,
                headers={"Accept": "application/vnd.github+json"},
            )
            r.raise_for_status()
            return parse_releases(repo, r.json())
        except Exception as e:  # network/API failure must never crash pipeline
            return [{"collector": "github", "project": project_slug, "repo": repo, "error": str(e)}]
