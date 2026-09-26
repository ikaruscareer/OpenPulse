"""NVD collector — CVE enrichment via NVD API 2.0 keyword search.

Docs: https://nvd.nist.gov/developers/api
Rate limits: 5 req/30s without key, 50 req/30s with `apiKey` header.
"""

from __future__ import annotations

from typing import Any

import httpx

from collectors.base import BaseCollector
from collectors.errors import as_error

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _description(descriptions: list[dict[str, Any]]) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "version": key,
                "base_score": data.get("baseScore"),
                "severity": data.get("baseSeverity"),
            }
    return {}


_RANGE_ATTRS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


def _cpes(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """CPE match criteria — the identity evidence keyword search cannot give."""
    out = []
    for config in configurations:
        for node in config.get("nodes", []) + config.get("children", []):
            for match in node.get("cpeMatch", []) + node.get("cpe_match", []):
                criteria = match.get("criteria")
                if criteria and not any(c["criteria"] == criteria for c in out):
                    entry = {"criteria": criteria, "vulnerable": bool(match.get("vulnerable"))}
                    for attr in _RANGE_ATTRS:
                        if match.get(attr) is not None:
                            entry[attr] = match[attr]
                    out.append(entry)
    return out


def parse_cves(payload: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        out.append(
            {
                "collector": "nvd",
                "id": cve.get("id"),
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "description": _description(cve.get("descriptions", [])),
                "cvss": _cvss(cve.get("metrics", {})),
                "cpes": _cpes(cve.get("configurations", [])),
                "references": [r.get("url") for r in cve.get("references", []) if r.get("url")],
            }
        )
    return out


class NVDCollector(BaseCollector):
    name = "nvd"

    def __init__(
        self,
        keyword_map: dict[str, str] | None = None,
        api_key: str | None = None,
        timeout: float = 20.0,
    ):
        # project_slug -> NVD keywordSearch, e.g. {"redis": "redis"}
        self.keyword_map = keyword_map or {}
        self.api_key = api_key
        self.timeout = timeout

    def collect(self, project_slug: str) -> list[dict[str, Any]]:
        keyword = self.keyword_map.get(project_slug, project_slug)
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            r = httpx.get(
                API,
                params={"keywordSearch": keyword, "resultsPerPage": 20},
                headers=headers,
                timeout=self.timeout,
            )
            r.raise_for_status()
            vulns = parse_cves(r.json())
            return vulns or [{"collector": "nvd", "keyword": keyword, "vulns": 0}]
        except Exception as e:  # network/API failure must never crash pipeline
            return [as_error("nvd", e, project=project_slug)]
