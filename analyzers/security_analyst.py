"""Security Analyst — correlate CVE/OSV/NVD/KEV records per CVE ID.

Pure functions: no network, deterministic. Merges every source that
mentions the same CVE ID, keeps the max CVSS score, and labels the
*relationship* to the project under review:

- AFFECTS_PACKAGE — identity evidence (OSV query scope, CPE
  vendor/product match, or CNA affected-product match).
- RELATED — the CVE exists (and may be exploited) but nothing ties it
  to this project; keyword-only NVD hits land here.
- UNKNOWN — no score and no identity signal.

RELATED findings cap at REVIEW: a weak name resemblance must never
become CRITICAL/ACTION on its own. KEV promotes to CRITICAL only for
exact/strong matches. The Evidence Analyst and the gate decide what
becomes an OSSEvent.
"""

from __future__ import annotations

import re
from typing import Any


def _cve_id(entry: dict[str, Any]) -> str | None:
    for key in ("id", "cve_id"):
        value = entry.get(key)
        if isinstance(value, str) and value.upper().startswith("CVE-"):
            return value.upper()
    return None


def _score(entry: dict[str, Any]) -> float | None:
    cvss = entry.get("cvss")
    if isinstance(cvss, dict) and isinstance(cvss.get("base_score"), (int, float)):
        return float(cvss["base_score"])
    for sev in entry.get("severity", []) or []:
        if isinstance(sev, dict) and isinstance(sev.get("score"), (int, float)):
            return float(sev["score"])
    return None


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _cpe_vendor_product(criteria: str) -> tuple[str, str]:
    """(vendor, product) from a CPE 2.3 string; ('','') when unparseable."""
    parts = criteria.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[3].lower(), parts[4].lower()
    return "", ""


def _project_tokens(project: dict[str, Any] | None) -> set[str]:
    if not project:
        return set()
    texts = [str(project.get("slug", ""))]
    texts += [str(a) for a in project.get("aliases", []) or []]
    texts += [str(v) for v in project.get("vendors", []) or []]
    out: set[str] = set()
    for text in texts:
        out |= _tokens(text)
    return {t for t in out if len(t) >= 3}


def _cpe_matches_project(cpes: list[dict[str, Any]], tokens: set[str]) -> bool:
    for cpe in cpes:
        vendor, product = _cpe_vendor_product(str(cpe.get("criteria", "")))
        if not cpe.get("vulnerable", True):
            continue
        hay = _tokens(f"{vendor} {product}")
        if tokens & hay:
            return True
    return False


def _cna_matches_project(affected: list[dict[str, Any]], tokens: set[str]) -> bool:
    for a in affected:
        hay = _tokens(f"{a.get('vendor', '')} {a.get('product', '')}")
        if tokens & hay:
            return True
    return False


def correlate(
    raw: dict[str, list[dict[str, Any]]], project: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Merge osv/nvd/cve/kev entries by CVE ID, labeled with relationship."""
    tokens = _project_tokens(project)
    merged: dict[str, dict[str, Any]] = {}
    for source_entries in (
        raw.get("osv", []),
        raw.get("nvd", []),
        raw.get("cve", []),
        raw.get("kev", []),
    ):
        for e in source_entries:
            if e.get("error") or e.get("skipped"):
                continue
            cid = _cve_id(e)
            if not cid:
                continue
            slot = merged.setdefault(
                cid,
                {
                    "analyst": "security",
                    "cve_id": cid,
                    "sources": [],
                    "max_score": None,
                    "severity": None,
                    "in_kev": False,
                    "identity": False,
                    "references": [],
                },
            )
            collector = e.get("collector", "?")
            if collector not in slot["sources"]:
                slot["sources"].append(collector)
            if collector == "kev" and e.get("match", "exact") in ("exact", "strong"):
                slot["in_kev"] = True
            if collector == "osv":
                slot["identity"] = True  # OSV queries are package/ecosystem-scoped
            if collector == "nvd" and tokens and _cpe_matches_project(e.get("cpes", []), tokens):
                slot["identity"] = True
            if (
                collector == "cve"
                and tokens
                and _cna_matches_project(e.get("affected", []), tokens)
            ):
                slot["identity"] = True
            score = _score(e)
            if score is not None and (slot["max_score"] is None or score > slot["max_score"]):
                slot["max_score"] = score
            for ref in e.get("references", []) or []:
                if ref and ref not in slot["references"]:
                    slot["references"].append(ref)

    findings = []
    for cid, slot in sorted(merged.items()):
        score = slot["max_score"]
        if slot["identity"]:
            relationship = "AFFECTS_PACKAGE"
        elif score is None and not slot["in_kev"]:
            relationship = "UNKNOWN"
        else:
            relationship = "RELATED"
        slot["relationship"] = relationship
        if slot["in_kev"] and relationship == "AFFECTS_PACKAGE":
            impact = "CRITICAL"
        elif slot["in_kev"]:
            impact = "REVIEW"  # exploited in the wild, project relation unconfirmed
        elif relationship == "RELATED":
            if score is not None and score >= 7.0:
                impact = "REVIEW"  # capped: keyword resemblance is not impact
            elif score is not None and score >= 4.0:
                impact = "WATCH"
            else:
                impact = "WATCH"
        elif score is not None and score >= 9.0:
            impact = "ACTION"
        elif score is not None and score >= 7.0:
            impact = "REVIEW"
        elif score is not None and score >= 4.0:
            impact = "WATCH"
        else:
            impact = "WATCH"
        slot["impact"] = impact
        slot["title"] = f"{cid} [{relationship}] tracked by {', '.join(slot['sources'])}" + (
            " — exploited in the wild (CISA KEV)" if slot["in_kev"] else ""
        )
        findings.append(slot)
    return findings
