"""Security Analyst — correlate CVE/OSV/NVD/KEV records per CVE ID.

Pure functions: no network, deterministic. Identity rule (never
weaken it): token overlap is NOT identity. A CPE/CNA product counts
only on normalized exact equality with the project's slug or aliases;
`spring` never matches `spring-shell`.

Relationship ladder: UNKNOWN < RELATED < AFFECTS_PACKAGE <
AFFECTS_VERSION. Version ranges (OSV events, NVD CPE range
attributes) are evaluated when the project version is known; without
it, the ceiling is AFFECTS_PACKAGE. keyword_only never yields
AFFECTS_VERSION or AFFECTS_ARTIFACT. Weak KEV matches never set
in_kev. Every finding records match_method + identity_evidence so the
reasoning is auditable.
"""

from __future__ import annotations

import re
from typing import Any

from core.versions import cpe_applicable, osv_applicable

_MATCH_ORDER = [
    "artifact_exact",
    "osv_package",
    "cpe_exact",
    "cpe_version_range",
    "cpe_vendor_product",
    "manual_catalog",
    "purl",
    "keyword_only",
]


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


def _norm(name: str) -> str:
    return re.sub(r"[-_.]", "", str(name).lower())


def _names(project: dict[str, Any] | None) -> set[str]:
    if not project:
        return set()
    names = {str(project.get("slug", "")), str(project.get("package", ""))}
    names |= {str(a) for a in project.get("aliases", []) or []}
    names |= {str(v) for v in project.get("vendors", []) or []}
    return {_norm(n) for n in names if n and n != "None"}


def _cpe_product(criteria: str) -> str:
    parts = str(criteria).split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return _norm(parts[4])
    return ""


def _severity(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def correlate(
    raw: dict[str, list[dict[str, Any]]], project: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Merge osv/nvd/cve/kev entries by CVE ID, labeled with relationship."""
    names = _names(project)
    version = str(project.get("version", "")) if project and project.get("version") else None
    pkg = _norm(str(project.get("package", ""))) if project and project.get("package") else ""
    eco = str(project.get("ecosystem", "")).lower() if project and project.get("ecosystem") else ""
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
                    "severity": "UNKNOWN",
                    "in_kev": False,
                    "kev_weak": False,
                    "kev_match": None,
                    "relationship": "UNKNOWN",
                    "match_method": "keyword_only",
                    "identity_evidence": [],
                    "affected_package": None,
                    "affected_version": None,
                    "fixed_version": None,
                    "references": [],
                },
            )
            collector = e.get("collector", "?")
            if collector not in slot["sources"]:
                slot["sources"].append(collector)
            if collector == "kev" and e.get("match", "exact") in ("exact", "strong"):
                slot["in_kev"] = True
                slot["kev_match"] = e.get("match", "exact")
            elif collector == "kev":
                slot["kev_weak"] = True
                slot["kev_match"] = slot["kev_match"] or e.get("match")
            if collector == "osv":
                _absorb_osv(slot, e, names, pkg, eco, version)
            if collector == "nvd":
                _absorb_nvd(slot, e, names, version)
            if collector == "cve":
                _absorb_cna(slot, e, names)
            score = _score(e)
            if score is not None and (slot["max_score"] is None or score > slot["max_score"]):
                slot["max_score"] = score
            for ref in e.get("references", []) or []:
                if ref and ref not in slot["references"]:
                    slot["references"].append(ref)

    findings = []
    for cid, slot in sorted(merged.items()):
        _decide(slot)
        slot["title"] = (
            f"{cid} [{slot['relationship']}] tracked by {', '.join(slot['sources'])}"
            + (" — exploited in the wild (CISA KEV)" if slot["in_kev"] else "")
        )
        findings.append(slot)
    return findings


def _osv_identity(entry: dict[str, Any], names: set[str], pkg: str, eco: str) -> bool:
    """OSV query scope counts as identity; explicit project package must agree."""
    if pkg and _norm(str(entry.get("package", ""))) != pkg:
        return False
    if eco and str(entry.get("ecosystem", "")).lower() != eco:
        return False
    return True


def _absorb_osv(
    slot: dict[str, Any],
    e: dict[str, Any],
    names: set[str],
    pkg: str,
    eco: str,
    version: str | None,
) -> None:
    if not _osv_identity(e, names, pkg, eco):
        return
    package = str(e.get("package", ""))
    slot["affected_package"] = slot["affected_package"] or package
    evaluated, applies, fixed = False, False, None
    for affected in e.get("affected", []) or []:
        result = osv_applicable(version, affected) if version else None
        if result is not None:
            evaluated = True
        if result is True:
            applies = True
        for candidate in affected.get("fixed", []) or []:
            fixed = fixed or str(candidate)
    if applies:
        slot["relationship"] = "AFFECTS_VERSION"
        slot["match_method"] = "osv_package+version_range"
        slot["affected_version"] = version
        slot["fixed_version"] = fixed
        slot["identity_evidence"].append(f"osv:{e.get('ecosystem')}/{package}")
    elif not evaluated and slot["relationship"] != "AFFECTS_VERSION":
        slot["relationship"] = "AFFECTS_PACKAGE"
        slot["match_method"] = "osv_package"
        slot["identity_evidence"].append(f"osv:{e.get('ecosystem')}/{package}")


def _absorb_nvd(
    slot: dict[str, Any], e: dict[str, Any], names: set[str], version: str | None
) -> None:
    for cpe in e.get("cpes", []) or []:
        product = _cpe_product(str(cpe.get("criteria", "")))
        if not product or product not in names:
            continue
        criteria = str(cpe["criteria"])
        if criteria not in slot["identity_evidence"]:
            slot["identity_evidence"].append(criteria)
        result = cpe_applicable(version, cpe) if version else None
        if result is True:
            slot["relationship"] = "AFFECTS_VERSION"
            slot["match_method"] = "cpe_version_range"
            slot["affected_version"] = version
        elif slot["relationship"] not in ("AFFECTS_VERSION",):
            slot["relationship"] = "AFFECTS_PACKAGE"
            slot["match_method"] = "cpe_vendor_product"


def _absorb_cna(slot: dict[str, Any], e: dict[str, Any], names: set[str]) -> None:
    for a in e.get("affected", []) or []:
        product = _norm(str(a.get("product", "")))
        if product and product in names:
            slot["relationship"] = "AFFECTS_PACKAGE"
            slot["match_method"] = "cpe_vendor_product"
            slot["affected_package"] = slot["affected_package"] or str(a.get("product", ""))
            slot["identity_evidence"].append(f"cna:{a.get('vendor')}/{a.get('product')}")


def _decide(slot: dict[str, Any]) -> None:
    score = slot["max_score"]
    slot["severity"] = _severity(score)
    relationship = slot["relationship"]
    if relationship == "UNKNOWN" and (score is not None or slot["in_kev"]):
        relationship = "RELATED"
        slot["relationship"] = relationship
    if slot["in_kev"] and relationship in ("AFFECTS_VERSION", "AFFECTS_PACKAGE"):
        impact, urgency = "CRITICAL", "high"
    elif slot["in_kev"]:
        impact, urgency = "REVIEW", "medium"
    elif relationship == "RELATED":
        if slot.get("kev_weak") or (score is not None and score >= 7.0):
            impact = "REVIEW"  # exploited/serious but unconfirmed — capped here
        elif score is not None and score >= 4.0:
            impact = "WATCH"
        else:
            impact = "WATCH"
        urgency = "low"
    elif relationship == "AFFECTS_VERSION":
        impact = (
            "ACTION" if score is None or score >= 7.0 else ("REVIEW" if score >= 4.0 else "WATCH")
        )
        urgency = "medium"
    elif score is not None and score >= 9.0:
        impact, urgency = "ACTION", "medium"
    elif score is not None and score >= 7.0:
        impact, urgency = "REVIEW", "low"
    elif score is not None and score >= 4.0:
        impact, urgency = "WATCH", "low"
    else:
        impact, urgency = ("WATCH", "low") if score is not None else ("INFORMATIONAL", "low")
    slot["impact"] = impact
    slot["urgency"] = urgency
    fixed = slot.get("fixed_version")
    if fixed:
        slot["recommended_action"] = f"upgrade to {fixed}+"
    elif slot["in_kev"] and relationship in ("AFFECTS_VERSION", "AFFECTS_PACKAGE"):
        slot["recommended_action"] = "prioritize remediation — exploited in the wild"
    elif impact == "ACTION":
        slot["recommended_action"] = "assess exposure and plan upgrade"
    elif impact == "REVIEW":
        slot["recommended_action"] = "review in next planning cycle"
    elif impact == "WATCH":
        slot["recommended_action"] = "track"
    else:
        slot["recommended_action"] = "none"
