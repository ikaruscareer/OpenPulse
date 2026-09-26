"""KEV collector — CISA Known Exploited Vulnerabilities catalog.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
The catalog is fetched whole (~1-2k entries) and filtered locally by
CVE ID or vendor/product keyword. Cached per instance for one run.
"""

from __future__ import annotations

from typing import Any

import httpx

from collectors.base import BaseCollector

API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def filter_catalog(catalog: dict[str, Any], project_slug: str) -> list[dict[str, Any]]:
    slug = project_slug.strip().lower()
    out = []
    for v in catalog.get("vulnerabilities", []):
        cve_id = str(v.get("cveID", "")).upper()
        hay = f"{v.get('vendorProject', '')} {v.get('product', '')}".lower()
        if slug == cve_id.lower() or (slug and slug in hay):
            out.append(
                {
                    "collector": "kev",
                    "cve_id": v.get("cveID"),
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "name": v.get("vulnerabilityName"),
                    "date_added": v.get("dateAdded"),
                    "due_date": v.get("dueDate"),
                    "action": v.get("requiredAction"),
                }
            )
    return out


class KEVCollector(BaseCollector):
    name = "kev"

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout
        self._catalog: dict[str, Any] | None = None

    def _fetch(self) -> dict[str, Any]:
        if self._catalog is None:
            r = httpx.get(API, timeout=self.timeout)
            r.raise_for_status()
            self._catalog = r.json()
        return self._catalog

    def is_exploited(self, cve_id: str) -> bool:
        try:
            return bool(filter_catalog(self._fetch(), cve_id))
        except Exception:
            return False

    def collect(self, project_slug: str) -> list[dict[str, Any]]:
        try:
            catalog = self._fetch()
            matches = filter_catalog(catalog, project_slug)
            if matches:
                return matches
            return [
                {
                    "collector": "kev",
                    "project": project_slug,
                    "matches": 0,
                    "catalog_count": len(catalog.get("vulnerabilities", [])),
                }
            ]
        except Exception as e:  # network/API failure must never crash pipeline
            return [{"collector": "kev", "project": project_slug, "error": str(e)}]
