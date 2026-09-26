"""Security Analyst — correlate CVE/OSV/NVD/KEV records per CVE ID.

Pure functions: no network, deterministic. Merges every source that
mentions the same CVE ID, keeps the max CVSS score, flags CISA KEV
(exploited in the wild) and proposes an impact. The Evidence Analyst
and the gate decide what becomes an OSSEvent.
"""

from __future__ import annotations

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


def correlate(raw: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Merge osv/nvd/cve/kev entries by CVE ID."""
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
                    "references": [],
                },
            )
            collector = e.get("collector", "?")
            if collector not in slot["sources"]:
                slot["sources"].append(collector)
            if collector == "kev":
                slot["in_kev"] = True
            score = _score(e)
            if score is not None and (slot["max_score"] is None or score > slot["max_score"]):
                slot["max_score"] = score
            for ref in e.get("references", []) or []:
                if ref and ref not in slot["references"]:
                    slot["references"].append(ref)

    findings = []
    for cid, slot in sorted(merged.items()):
        score = slot["max_score"]
        if slot["in_kev"]:
            impact = "CRITICAL"
        elif score is not None and score >= 9.0:
            impact = "ACTION"
        elif score is not None and score >= 7.0:
            impact = "REVIEW"
        elif score is not None and score >= 4.0:
            impact = "WATCH"
        else:
            impact = "WATCH"
        slot["impact"] = impact
        slot["title"] = f"{cid} tracked by {', '.join(slot['sources'])}" + (
            " — exploited in the wild (CISA KEV)" if slot["in_kev"] else ""
        )
        findings.append(slot)
    return findings
