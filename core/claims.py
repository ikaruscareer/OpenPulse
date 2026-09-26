"""Claims — the smallest unit OpenPulse argues about.

Observation < finding < claim < evidence < event. A claim states one
checkable thing ("docker.io/bitnami/redis is affected") and names the
evidence supporting it. No knowledge graph: claims are flat,
per-event, and validated by the gate (every claim needs support;
contradictions stay visible; unresolved high-impact conflicts block
promotion).
"""

from __future__ import annotations

from typing import Any, Literal

from core.schema.models import Claim

ConflictStatus = Literal["NONE", "MINOR", "UNRESOLVED"]


def _relation(evidence: Any) -> str:
    if isinstance(evidence, dict):
        return str(evidence.get("relation", "supports"))
    return str(getattr(evidence, "relation", "supports"))


def _authority(evidence: Any) -> str | None:
    source = (
        evidence.get("source", {})
        if isinstance(evidence, dict)
        else getattr(evidence, "source", None)
    )
    if isinstance(source, dict):
        return source.get("authority")
    return getattr(source, "authority", None)


def conflict_status(evidences: list[Any]) -> ConflictStatus:
    """NONE: no contradiction. MINOR: only tertiary contradiction.
    UNRESOLVED: any stronger contradiction alongside support."""
    relations = [_relation(e) for e in evidences]
    if "contradicts" not in relations:
        return "NONE"
    if "supports" not in relations:
        return "UNRESOLVED"
    authorities = [_authority(e) for e in evidences if _relation(e) == "contradicts"]
    if authorities and all(a == "tertiary" for a in authorities):
        return "MINOR"
    return "UNRESOLVED"


def claims_from_finding(finding: dict[str, Any], subject: str) -> list[Claim]:
    """One finding -> one claim naming the finding's sources as evidence."""
    kind = str(finding.get("event_type") or "vulnerability")
    slug = str(finding.get("cve_id") or finding.get("analyst", "analyst"))
    return [
        Claim(
            id=f"claim:{slug}:{kind}".lower().replace(" ", "-"),
            type=kind,
            subject=subject,
            statement=str(finding.get("title", "")),
            evidence_refs=list(finding.get("sources", [])),
        )
    ]
