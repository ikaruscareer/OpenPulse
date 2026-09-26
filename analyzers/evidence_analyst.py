"""Evidence Analyst — confidence, dates, assembly of OSSEvents.

Pure functions: no network, deterministic. Turns analyst findings +
curated evidences into OSSEvent candidates and runs them through the
gate (core/evidence/policy.py). The gate has veto power — this module
never emits an event that fails it silently; violations are returned
alongside so callers must handle them explicitly.
"""

from __future__ import annotations

from typing import Any

from core.evidence.independence import independent_count
from core.evidence.policy import gate
from core.schema.enums import Confidence
from core.schema.models import OSSEvent


def assess_confidence(evidences: list[dict[str, Any]]) -> Confidence:
    """Official source -> CONFIRMED; 2+ independent -> CORROBORATED; else EMERGING/UNVERIFIED.

    Independence (not name count): derived_from chains fold into the
    group they derive from, so a republished copy never corroborates.
    """
    if not evidences:
        return Confidence.UNVERIFIED
    authorities = [e.get("source", {}).get("authority") for e in evidences]
    if "official" in authorities:
        return Confidence.CONFIRMED
    if independent_count(evidences) >= 2:
        return Confidence.CORROBORATED
    if any(a == "secondary" for a in authorities):
        return Confidence.EMERGING
    return Confidence.UNVERIFIED


def assemble_event(
    *,
    id: str,
    project_slug: str,
    event_type: str,
    title: str,
    summary: str,
    impact: str,
    affected_versions: list[str] | None = None,
    affected_artifacts: list[dict[str, str]] | None = None,
    evidences: list[dict[str, Any]],
) -> tuple[OSSEvent, list[str]]:
    """Build an OSSEvent with inferred confidence; return (event, gate violations)."""
    event = OSSEvent(
        id=id,
        project_slug=project_slug,
        event_type=event_type,  # type: ignore[arg-type]
        title=title,
        summary=summary,
        confidence=assess_confidence(evidences),
        impact=impact,  # type: ignore[arg-type]
        affected_versions=affected_versions or [],
        affected_artifacts=affected_artifacts or [],  # type: ignore[arg-type]
        evidences=evidences,  # type: ignore[arg-type]
    )
    return event, gate(event)
