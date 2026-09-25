"""Evidence gate — Phase 2 veto rules. Pure function, no network."""

from __future__ import annotations

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

    # 3. CORROBORATED needs 2+ distinct sources
    if conf == "CORROBORATED":
        names = {e.source.name for e in event.evidences}
        if len(event.evidences) < 2 or len(names) < 2:
            violations.append("CORROBORATED requires >=2 evidences from distinct sources")

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
