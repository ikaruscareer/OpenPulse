"""Report Analyst — structured events/findings to human-readable text.

Pure functions. Every claim in the output traces back to an evidence
URL or a named collector output — no invented facts.
"""

from __future__ import annotations

from typing import Any

from core.schema.models import OSSEvent

BADGE = {
    "CRITICAL": "🔴",
    "ACTION": "🔴",
    "REVIEW": "🟠",
    "WATCH": "🟡",
    "INFORMATIONAL": "🟢",
}

ADVICE = {
    "CRITICAL": "Act now: exploited in the wild or production-breaking.",
    "ACTION": "Schedule action: migration or upgrade needed before the effective date.",
    "REVIEW": "Review in the next planning cycle.",
    "WATCH": "Watch: no immediate action, track for changes.",
    "INFORMATIONAL": "Informational.",
}


def _impact_of(item: Any) -> str:
    impact = item.get("impact") if isinstance(item, dict) else getattr(item, "impact", None)
    return impact.value if hasattr(impact, "value") else str(impact)


def render_event_md(event: OSSEvent) -> str:
    """One event -> markdown section with evidence links."""
    impact = _impact_of(event)
    lines = [
        f"## {BADGE.get(impact, '⚪')} {event.title}",
        "",
        f"Impact: **{impact}** · Confidence: **{event.confidence.value}**",
        f"Type: `{event.event_type.value}`",
        "",
        event.summary,
        "",
    ]
    if event.affected_versions:
        lines += ["Affected versions: " + ", ".join(f"`{v}`" for v in event.affected_versions), ""]
    if event.affected_artifacts:
        lines.append("Affected artifacts:")
        lines += [f"- `{a.ref}` ({a.kind})" for a in event.affected_artifacts]
        lines.append("")
    lines.append("Evidence:")
    for e in event.evidences:
        src = e.source
        dates = " / ".join(
            f"{k}={v}"
            for k, v in (("announced", e.announcement_date), ("effective", e.effective_date))
            if v
        )
        lines.append(
            f"- [{src.name}]({src.url}) (authority={src.authority}"
            + (f", {dates}" if dates else "")
            + ")"
        )
        lines.append(f"  > {e.excerpt}")
    lines += ["", f"Recommendation: {ADVICE.get(impact, '')}"]
    return "\n".join(lines)


def render_finding_md(finding: dict[str, Any]) -> str:
    """One analyst finding (not yet an event) -> short markdown."""
    impact = _impact_of(finding)
    return (
        f"{BADGE.get(impact, '⚪')} **[{finding.get('event_type')}]** {finding.get('title')} "
        f"(_analyst={finding.get('analyst')}, suggested impact={impact}_)\n"
        f"{finding.get('summary')}"
    )


def render_digest(events: list[OSSEvent]) -> str:
    """Event list -> grouped digest with counts."""
    order = ["CRITICAL", "ACTION", "REVIEW", "WATCH", "INFORMATIONAL"]
    groups: dict[str, list] = {k: [] for k in order}
    for e in events:
        groups.setdefault(_impact_of(e), []).append(e)
    lines = [f"# OpenPulse digest — {len(events)} events", ""]
    for level in order:
        items = groups.get(level, [])
        if items:
            lines.append(f"## {BADGE[level]} {level} ({len(items)})")
            lines += [f"- {e.title} (`{e.project_slug}`, {e.confidence.value})" for e in items]
            lines.append("")
    return "\n".join(lines).rstrip()
