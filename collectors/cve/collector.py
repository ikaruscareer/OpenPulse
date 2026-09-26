"""CVE collector — single-record lookup via MITRE CVE Services (public, no key).

GET https://cveawg.mitre.org/api/cve/{CVE-ID}
Used to enrich CVE IDs found by NVD/OSV with CNA data (state,
affected products, descriptions). Pass a CVE ID to `collect`;
project slugs are not resolvable here and return a `skipped` dict.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from collectors.base import BaseCollector
from collectors.errors import as_error

API = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _en_descriptions(descriptions: list[dict[str, Any]]) -> list[str]:
    return [d.get("value", "") for d in descriptions if d.get("lang") == "en" and d.get("value")]


def parse_record(payload: dict[str, Any]) -> dict[str, Any]:
    meta = payload.get("cveMetadata", {})
    cna = payload.get("containers", {}).get("cna", {})
    affected = []
    for a in cna.get("affected", []):
        affected.append(
            {
                "vendor": a.get("vendor"),
                "product": a.get("product"),
                "versions": [v.get("version") for v in a.get("versions", []) if v.get("version")],
            }
        )
    return {
        "collector": "cve",
        "id": meta.get("cveId"),
        "state": meta.get("state"),
        "assigner": meta.get("assignerShortName"),
        "date_published": meta.get("datePublished"),
        "descriptions": _en_descriptions(cna.get("descriptions", [])),
        "affected": affected,
        "references": [r.get("url") for r in cna.get("references", []) if r.get("url")],
    }


class CVECollector(BaseCollector):
    name = "cve"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def collect(self, project_slug: str) -> list[dict[str, Any]]:
        cve_id = project_slug.strip().upper()
        if not CVE_RE.match(cve_id):
            return [
                {
                    "collector": "cve",
                    "project": project_slug,
                    "skipped": "pass a CVE ID (e.g. CVE-2024-0001); "
                    "project->CVE discovery belongs to nvd/osv",
                }
            ]
        try:
            r = httpx.get(API.format(cve_id=cve_id), timeout=self.timeout)
            if r.status_code == 404:
                return [{"collector": "cve", "id": cve_id, "skipped": "not found"}]
            r.raise_for_status()
            return [parse_record(r.json())]
        except Exception as e:  # network/API failure must never crash pipeline
            return [as_error("cve", e, id=cve_id)]
