"""KEV collector — CISA Known Exploited Vulnerabilities catalog.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
The catalog is fetched whole (~1-2k entries) and filtered locally by
exact CVE ID or token-set vendor/product match. Cached per instance.
Match strength: exact (CVE ID) > strong (name/token identity) > weak
(substring only — surfaced, never auto-promoted to CRITICAL).
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from collectors.base import BaseCollector
from collectors.errors import as_error

API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def match_strength(slug: str, vendor: str, product: str) -> str | None:
    """How strongly does a slug identify this catalog entry?"""
    slug = slug.strip().lower()
    if not slug:
        return None
    vendor_norm, product_norm = vendor.strip().lower(), product.strip().lower()
    if slug in (vendor_norm, product_norm):
        return "strong"
    slug_tokens = _tokens(slug)
    hay_tokens = _tokens(f"{vendor} {product}")
    if slug_tokens and slug_tokens <= hay_tokens:
        return "strong"
    if slug in f"{vendor_norm} {product_norm}":
        return "weak"
    return None


def filter_catalog(catalog: dict[str, Any], project_slug: str) -> list[dict[str, Any]]:
    out = []
    for v in catalog.get("vulnerabilities", []):
        cve_id = str(v.get("cveID", "")).upper()
        vendor, product = v.get("vendorProject", ""), v.get("product", "")
        if project_slug.strip().upper() == cve_id:
            strength = "exact"
        else:
            strength = match_strength(project_slug, vendor, product)
        if strength:
            out.append(
                {
                    "collector": "kev",
                    "cve_id": v.get("cveID"),
                    "vendor": vendor,
                    "product": product,
                    "name": v.get("vulnerabilityName"),
                    "date_added": v.get("dateAdded"),
                    "due_date": v.get("dueDate"),
                    "action": v.get("requiredAction"),
                    "match": strength,
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
            return [as_error("kev", e, project=project_slug)]
