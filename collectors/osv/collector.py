"""OSV collector — security source. POST https://api.osv.dev/v1/query"""

from __future__ import annotations

from typing import Any

import httpx

from collectors.base import BaseCollector
from collectors.errors import as_error

API = "https://api.osv.dev/v1/query"


def _affected_ranges(entry: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """(ranges with events, fixed versions) for one OSV affected entry."""
    ranges = []
    fixed: list[str] = []
    for rng in entry.get("ranges", []) or []:
        events = [e for e in rng.get("events", []) or [] if isinstance(e, dict)]
        for event in events:
            if event.get("fixed") and event["fixed"] not in fixed:
                fixed.append(str(event["fixed"]))
        ranges.append({"type": rng.get("type"), "events": events})
    return ranges, fixed


def parse_vulns(package: str, ecosystem: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for v in payload.get("vulns", []):
        affected = []
        for a in v.get("affected", []) or []:
            pkg = a.get("package", {}) or {}
            ranges, fixed = _affected_ranges(a)
            affected.append(
                {
                    "package": pkg.get("name", package),
                    "ecosystem": pkg.get("ecosystem", ecosystem),
                    "ranges": ranges,
                    "fixed": fixed,
                    "versions": (a.get("versions", []) or [])[:50],
                }
            )
        out.append(
            {
                "collector": "osv",
                "package": package,
                "ecosystem": ecosystem,
                "id": v.get("id"),
                "summary": v.get("summary"),
                "severity": v.get("severity"),
                "affected": affected,
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
            return [as_error("osv", e, project=project_slug)]
