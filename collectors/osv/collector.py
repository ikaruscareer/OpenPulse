"""OSV collector — security source. POST https://api.osv.dev/v1/query"""

from __future__ import annotations

from typing import Any

import httpx

from collectors.base import BaseCollector

API = "https://api.osv.dev/v1/query"


def parse_vulns(package: str, ecosystem: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for v in payload.get("vulns", []):
        out.append(
            {
                "collector": "osv",
                "package": package,
                "ecosystem": ecosystem,
                "id": v.get("id"),
                "summary": v.get("summary"),
                "severity": v.get("severity"),
                "references": [x.get("url") for x in v.get("references", []) if x.get("url")],
            }
        )
    return out


class OSVCollector(BaseCollector):
    name = "osv"

    def __init__(
        self, ecosystem_map: dict[str, tuple[str, str]] | None = None, timeout: float = 15.0
    ):
        # project_slug -> (package, ecosystem), e.g. {"redis": ("redis", "PyPI")}
        self.ecosystem_map = ecosystem_map or {}
        self.timeout = timeout

    def collect(self, project_slug: str) -> list[dict[str, Any]]:
        mapping = self.ecosystem_map.get(project_slug)
        if not mapping:
            return [
                {
                    "collector": "osv",
                    "project": project_slug,
                    "skipped": f"no ecosystem mapping for {project_slug}",
                }
            ]
        package, ecosystem = mapping
        try:
            r = httpx.post(
                API,
                json={"package": {"name": package, "ecosystem": ecosystem}},
                timeout=self.timeout,
            )
            r.raise_for_status()
            vulns = parse_vulns(package, ecosystem, r.json())
            return vulns or [
                {"collector": "osv", "package": package, "ecosystem": ecosystem, "vulns": 0}
            ]
        except Exception as e:
            return [{"collector": "osv", "project": project_slug, "error": str(e)}]
