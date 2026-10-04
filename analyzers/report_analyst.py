"""Report Analyst — structured events/findings to human-readable text.

Pure functions. Every claim in the output traces back to an evidence
URL or a named collector output — no invented facts.
"""

from __future__ import annotations

import re
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
        marker = "⚠️ CONTRADICTS: " if e.relation == "contradicts" else "- "
        lines.append(
            f"{marker}[{src.name}]({src.url}) (authority={src.authority}"
            + (f", {dates}" if dates else "")
            + ")"
        )
        lines.append(f"  > {e.excerpt}")
    if event.claims:
        lines += ["", "Claims:"]
        lines += [
            f"- `{c.id}` ({c.type}) → {', '.join(c.evidence_refs) or 'no refs'}"
            for c in event.claims
        ]
    lines += ["", f"Recommendation: {ADVICE.get(impact, '')}"]
    return "\n".join(lines)


def render_finding_md(finding: dict[str, Any]) -> str:
    """One analyst finding (not yet an event) -> short markdown."""
    impact = _impact_of(finding)
    label = finding.get("event_type") or ("SECURITY" if finding.get("cve_id") else "?")
    summary = finding.get("summary") or finding.get("description") or ""
    return (
        f"{BADGE.get(impact, '⚪')} **[{label}]** {finding.get('title')} "
        f"(_analyst={finding.get('analyst')}, suggested impact={impact}_)\n"
        f"{summary}"
    )


#: Display-only evidence confidence for findings. Findings carry
#: relationships and strengths, not event confidence — this maps what
#: exists onto the report vocabulary WITHOUT inventing corroboration:
#: explicit finding confidence wins; a directly observed fact from one
#: source is EMERGING (single credible); heuristics are UNVERIFIED;
#: only reserved official announcements could be CONFIRMED.
_VALID_CONFIDENCE = ("CONFIRMED", "CORROBORATED", "EMERGING", "UNVERIFIED")

CONFIDENCE_MEANINGS = {
    "CONFIRMED": "official announcement from the source itself",
    "CORROBORATED": "confirmed by 2+ independent source families",
    "EMERGING": "single credible source",
    "UNVERIFIED": "weak or unconfirmed signal — never action-framed",
}


def finding_confidence(finding: dict[str, Any]) -> str:
    """Report vocabulary confidence for one finding (display, not semantics)."""
    if not isinstance(finding, dict):
        return "UNVERIFIED"
    declared = str(finding.get("confidence") or "").upper()
    if declared in _VALID_CONFIDENCE:
        return declared
    strength = str(finding.get("evidence_strength") or "").lower()
    if strength == "strong":
        return "CONFIRMED"
    if strength == "weak":
        return "UNVERIFIED"
    return "EMERGING"


#: (category, eligibility) -> recommended investigation. Conditional
#: wording only ("check whether") — instructions, never claims about
#: the reader's environment.
_INVESTIGATIONS = {
    ("Lifecycle", "ACTION"): (
        "Check whether you run the affected versions "
        "(`openpulse check --watchlist <file>`); plan upgrade or extended support."
    ),
    ("Lifecycle", "REVIEW"): (
        "Track the affected versions in your inventory; schedule migration planning."
    ),
    ("Lifecycle", "WATCH"): "Note the upcoming date; confirm you have migration runway.",
    ("Distribution", "ACTION"): (
        "Verify pulls and mirrors for the affected artifacts; "
        "plan migration off affected references."
    ),
    ("Distribution", "REVIEW"): (
        "Confirm whether this is a removal or a rename (pull/mirror check); "
        "review pinned references."
    ),
    ("Distribution", "WATCH"): "No action; track the repository for further changes.",
    ("Security", "ACTION"): (
        "Check whether the affected package and version are in your inventory; "
        "prioritize by severity and KEV status."
    ),
    ("Security", "REVIEW"): (
        "Assess whether the affected package and version are in your inventory."
    ),
    ("Security", "WATCH"): "Track the advisory; confirm exposure if a version match emerges.",
}

_FALLBACK_INVESTIGATION = {
    "ACTION": "Investigate whether this change touches your inventory; scope first, then plan.",
    "REVIEW": "Review in the next planning cycle.",
    "WATCH": "Watch for further changes; no action now.",
}


def recommended_investigation(finding: dict[str, Any], category: str = "") -> str:
    """One conditional next step for a finding card."""
    eligibility = ((finding.get("_assessment") or {}) if isinstance(finding, dict) else {}).get(
        "eligibility", ""
    )
    if not eligibility and isinstance(finding, dict):
        eligibility = str(finding.get("impact", "")).upper()
    hit = _INVESTIGATIONS.get((category, str(eligibility)))
    if hit:
        return hit
    return _FALLBACK_INVESTIGATION.get(str(eligibility), "Track this signal for changes.")


def _scope_line(finding: dict[str, Any]) -> str:
    scope = finding.get("scope") or {}
    parts: list[str] = []
    for key in ("versions", "artifacts", "packages", "registries"):
        for value in scope.get(key) or []:
            parts.append(str(value))
    if parts:
        return ", ".join(f"`{p}`" for p in parts)
    return str(scope.get("kind", "project"))


def _announced_line(finding: dict[str, Any]) -> str:
    """Upstream announcement date with provenance. Published is shown
    only as an unconfirmed fallback; scan/analysis dates are never
    substituted in."""
    announced = finding.get("announced_at")
    if announced:
        provenance = str(finding.get("announcement_provenance") or "official")
        return f"Announcement: {str(announced)[:10]} ({provenance})"
    published = finding.get("published")
    if published:
        return (
            f"Announcement: Unknown (published {str(published)[:10]} on record, "
            "provenance unconfirmed)"
        )
    return "Announcement: Unknown"


def _effective_line(finding: dict[str, Any]) -> str:
    """Effective date or Unknown — never inferred."""
    from datetime import date

    from core.leadtime import parse_day

    effective = parse_day(finding.get("effective_at") or finding.get("event_date"))
    if effective is None:
        return "Effective: Unknown"
    if effective > date.today():
        return f"Effective: {effective} (upcoming)"
    return f"Effective: {effective} (already effective)"


def _detected_line(finding: dict[str, Any]) -> str:
    """First OpenPulse detection, or Unknown. Re-observations never
    stand in for discovery."""
    detected = finding.get("first_detected_at")
    if detected:
        return f"First detected by OpenPulse: {str(detected)[:10]}"
    return "First detected by OpenPulse: Unknown"


def _verified_line(finding: dict[str, Any]) -> str:
    """Most recent verification, or Unknown."""
    verified = finding.get("last_observed_at") or finding.get("observed_at")
    if verified:
        return f"Last verified: {str(verified)[:10]}"
    return "Last verified: Unknown"


def _timing_line(finding: dict[str, Any]) -> str | None:
    """Detection lead time before the effective date, plus the
    announcement-to-detection gap when both ends are known.

    Returns None when the metric cannot be computed — never a number
    from missing or incompatible dates. Background findings keep their
    label so old news never reads as current.

    Note: "detection lead time" deliberately replaces the older
    "warning window" wording — it measures detection-to-effect, not a
    promise about customer impact (no customer-impact validation yet).
    """
    from core.freshness import is_background
    from core.leadtime import finding_lead_time, parse_day

    days, detected, eff = finding_lead_time(finding)
    if days is None or not detected or not eff:
        return None
    background = " (background: outside 12-month research window)" if is_background(finding) else ""
    lines = [
        f"Detection lead time before effective date: {days} days "
        f"(first detected {detected} → effective {eff}){background}"
    ]
    announced = parse_day(finding.get("announced_at"))
    first = parse_day(finding.get("first_detected_at"))
    if announced is not None and first is not None:
        gap = (first - announced).days
        if gap >= 0:
            lines.append(f"Announcement → detection: {gap} days ({announced} → {first})")
    return "\n".join(lines)


def _why_line(finding: dict[str, Any]) -> str:
    reasons = (finding.get("_assessment") or {}).get("reasons") or []
    text = str(reasons[0]) if reasons else str(finding.get("summary") or "No assessment recorded.")
    # Assessment reasons embed Python list reprs (scoped versions
    # ['5.0']) — render them as readable version literals.
    return re.sub(r"\['([^']+)'(?:, '([^']+)')*\]", _version_list, text)


def _version_list(match: re.Match) -> str:
    inner = match.group(0)[1:-1]
    parts = [p.strip().strip("'\"") for p in inner.split(",")]
    return ", ".join(f"`{p}`" for p in parts if p)


def render_finding_card(
    project: str,
    finding: dict[str, Any],
    category: str,
    number: int | None = None,
    max_refs: int | None = None,
) -> str:
    """One decision-support block. No implementation metadata
    (`_analyst`, raw impact proposals): only category, evidence
    confidence, assessment, scope, timing, investigation, evidence.
    """
    assessment = (finding.get("_assessment") or {}) if isinstance(finding, dict) else {}
    head = f"**{project}** — {finding.get('title', 'untitled')}"
    if number is not None:
        head = f"{number}. {head}"
    lines = [
        f"### {head}",
        "",
        f"Category: {category} · Evidence confidence: {finding_confidence(finding)} · "
        f"Assessment: {assessment.get('assessment', '?')} ({assessment.get('eligibility', '?')})",
        "",
        f"Scope: {_scope_line(finding)}",
        "",
    ]
    if finding.get("affected_package"):
        lines.append(
            f"Affected dependency: {finding['affected_package']} "
            f"{finding.get('affected_version') or '(version unknown)'}"
        )
        lines.append("")
    sources = [str(s) for s in (finding.get("sources") or []) if s]
    if sources:
        lines.append(f"Sources: {', '.join(sources)}")
        lines.append("")
    lines += [
        _announced_line(finding),
        "",
        _effective_line(finding),
        "",
        _detected_line(finding),
        "",
        _verified_line(finding),
        "",
        f"Status: {finding.get('_freshness', 'UNKNOWN_DATE')}",
        "",
    ]
    timing = _timing_line(finding)
    if timing:
        lines.append(timing)
        lines.append("")
    lines += [
        f"Why it matters: {_why_line(finding)}",
        "",
        f"Investigate: {recommended_investigation(finding, category)}",
    ]
    refs = [r for r in (finding.get("_refs") or []) if r]
    if refs:
        lines.append("")
        lines.append(f"Source: {refs[0]}")
        if len(refs) > 1:
            lines.append("Evidence:")
            shown = refs[1:] if max_refs is None else refs[1 : max_refs + 1]
            lines += [f"- {ref}" for ref in shown]
            extra = len(refs) - 1 - len(shown)
            if extra > 0:
                lines.append(f"- (+{extra} more in the appendix)")
    return "\n".join(lines)


def render_security_finding_md(finding: dict[str, Any]) -> str:
    """Security finding -> explainable block. Prints only what evidence establishes."""
    lines = [
        f"{finding.get('cve_id')}",
        f"Relationship: {finding.get('relationship')}",
        f"Match method: {finding.get('match_method')}",
        f"Severity: {finding.get('severity', 'UNKNOWN')}",
        f"KEV: {'yes' if finding.get('in_kev') else 'no'}",
    ]
    if finding.get("affected_package"):
        lines.append(f"Affected package: {finding['affected_package']}")
    if finding.get("affected_version"):
        lines.append(f"Affected version: {finding['affected_version']}")
    if finding.get("fixed_version"):
        lines.append(f"Fixed version: {finding['fixed_version']}")
    sources = finding.get("sources", [])
    if sources:
        lines.append("Evidence:")
        lines += [f"- {s}" for s in sources]
    if finding.get("recommended_action") and finding["recommended_action"] != "none":
        lines += ["Recommended action:", f"  {finding['recommended_action']}"]
    return "\n".join(lines)


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


def _verdict_field(verdict: Any, name: str, default: Any = None) -> Any:
    if isinstance(verdict, dict):
        return verdict.get(name, default)
    return getattr(verdict, name, default)


def render_check_digest(verdicts: list[Any], title: str = "OpenPulse watchlist digest") -> str:
    """DependencyVerdicts -> AFFECTED / NOT_AFFECTED / RELATED / UNKNOWN sections.

    One line per dependency (label + relationship + reason). Reads
    verdicts defensively so offline dict fixtures work in tests.
    """
    sections: dict[str, tuple[str, list]] = {
        "AFFECTED": ("🚨", []),
        "NOT_AFFECTED": ("✅", []),
        "RELATED": ("ℹ️", []),
        "UNKNOWN": ("❓", []),
    }
    for verdict in verdicts:
        if _verdict_field(verdict, "affected", False):
            bucket = "AFFECTED"
        else:
            relationship = str(_verdict_field(verdict, "relationship", "UNKNOWN"))
            bucket = (
                "NOT_AFFECTED"
                if relationship == "NOT_AFFECTED"
                else ("RELATED" if relationship in ("RELATED", "AFFECTS_PROJECT") else "UNKNOWN")
            )
        icon, items = sections[bucket]
        first_detected = _verdict_field(verdict, "first_detected", None)
        first_note = f" · first detected {first_detected}" if first_detected else ""
        items.append(
            f"{icon} {_verdict_field(verdict, 'dependency', '?')}"
            f" [{_verdict_field(verdict, 'relationship', '?')}]"
            f" — {_verdict_field(verdict, 'reason', '')}{first_note}"
        )
    affected = len(sections["AFFECTED"][1])
    lines = [f"# {title}", "", f"{affected}/{len(verdicts)} dependencies affected", ""]
    for name, (icon, items) in sections.items():
        if items:
            lines.append(f"## {icon} {name} ({len(items)})")
            lines += [f"- {line}" for line in items]
            lines.append("")
    return "\n".join(lines).rstrip()
