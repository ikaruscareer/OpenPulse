"""Evidence gate — Phase 2 veto rules. Pure function, no network."""

from __future__ import annotations

from core.claims import conflict_status
from core.evidence.independence import independent_count
from core.schema.enums import Confidence, EventType, Impact
from core.schema.models import OSSEvent

REQUIRES_ARTIFACTS = {
    "DISTRIBUTION_CHANGE",
    "REGISTRY_CHANGE",
    "SUPPORT_CHANGE",
    "LICENSE_CHANGE",
    "OWNERSHIP_CHANGE",
}

REQUIRES_DATES = {
    "DISTRIBUTION_CHANGE",
    "SUPPORT_CHANGE",
    "LICENSE_CHANGE",
    "EOL",
    "EOS",
    "DEPRECATION",
}


def _v(x) -> str:
    return x.value if isinstance(x, Confidence | Impact | EventType) else str(x)


def gate(event: OSSEvent) -> list[str]:
    """Return list of violations; empty = passes gate."""
    violations: list[str] = []
    conf, imp, typ = _v(event.confidence), _v(event.impact), _v(event.event_type)

    # 1. Confidence/impact coupling
    if conf == "UNVERIFIED" and imp in ("ACTION", "CRITICAL", "REVIEW"):
        violations.append(f"UNVERIFIED cannot emit {imp} (max WATCH)")
    if conf == "EMERGING" and imp in ("ACTION", "CRITICAL"):
        violations.append(f"EMERGING cannot emit {imp} (max REVIEW)")
    if imp in ("ACTION", "CRITICAL") and conf not in ("CONFIRMED", "CORROBORATED"):
        violations.append(f"{imp} requires CONFIRMED or CORROBORATED, got {conf}")

    # 2. CONFIRMED needs an official source
    if conf == "CONFIRMED":
        if not any(e.source.authority == "official" for e in event.evidences):
            violations.append("CONFIRMED requires at least one evidence with authority=official")

    # 3. CORROBORATED needs 2+ independent sources (families, not names;
    #    derived_from chains fold into their origin — see independence.py)
    if conf == "CORROBORATED":
        if independent_count([e.model_dump() for e in event.evidences]) < 2:
            violations.append(
                "CORROBORATED requires >=2 independent evidences "
                "(republished copies do not corroborate)"
            )

    # 3b. A claim needs at least one non-contradicting evidence.
    relations = {e.relation for e in event.evidences}
    if relations and relations == {"contradicts"}:
        violations.append("event has only contradicting evidence — no support for the claim")

    # 3c. Explicit claims must each resolve to supporting evidence.
    # An official-but-unrelated source never satisfies a claim.
    supporting = {e.source.name for e in event.evidences if e.relation in ("supports", "context")}
    for claim in event.claims:
        if not set(claim.evidence_refs) & supporting:
            violations.append(f"claim {claim.id} has no supporting evidence")

    # 3d. Unresolved conflict blocks strong action; provenance is
    # required for high-impact conclusions.
    if conflict_status([e.model_dump() for e in event.evidences]) == "UNRESOLVED" and imp in (
        "ACTION",
        "CRITICAL",
    ):
        violations.append("unresolved conflicting evidence blocks ACTION/CRITICAL")
    if imp in ("ACTION", "CRITICAL"):
        proven = any(
            e.source.authority in ("official", "primary")
            or e.source.content_hash
            or e.source.parser_version
            for e in event.evidences
        )
        if not proven:
            violations.append("ACTION/CRITICAL requires official/primary or hashed provenance")

    # 4. Distribution/support/license/ownership must name affected artifacts
    if typ in REQUIRES_ARTIFACTS and not event.affected_artifacts:
        violations.append(f"{typ} requires affected_artifacts (which images/charts/packages?)")

    # 5. Lifecycle-ish events must carry a date (announcement or effective)
    if typ in REQUIRES_DATES:
        if not any(e.announcement_date or e.effective_date for e in event.evidences):
            violations.append(
                f"{typ} requires announcement_date or effective_date in at least one evidence"
            )

    return violations
