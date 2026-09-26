"""OSS Pulse — per-project facet status computed from analyst output.

Seven facets, no opaque score. Each facet takes the worst impact among
the findings/events mapped to it and keeps the strongest title as the
reason, so every dot is traceable back to a finding. Pure functions:
no network, deterministic (pass `today` in tests).
"""

from __future__ import annotations

from datetime import date
from typing import Any, Literal

FACETS = ["activity", "security", "lifecycle", "support", "licence", "distribution", "popularity"]

DISPLAY = {
    "activity": "Activity",
    "security": "Security",
    "lifecycle": "Lifecycle",
    "support": "Support",
    "licence": "Licence",
    "distribution": "Distribution",
    "popularity": "Popularity",
}

SYMBOL = {"ok": "🟢", "watch": "🟡", "review": "🟠", "action": "🔴"}

RANK = {"ok": 0, "watch": 1, "review": 2, "action": 3}

Status = Literal["ok", "watch", "review", "action"]

EVENT_FACET = {
    "EOL": "lifecycle",
    "EOS": "lifecycle",
    "MAJOR_RELEASE": "lifecycle",
    "BREAKING_CHANGE": "lifecycle",
    "DEPRECATION": "lifecycle",
    "PROJECT_ARCHIVED": "lifecycle",
    "SECURITY": "security",
    "LICENSE_CHANGE": "licence",
    "SUPPORT_CHANGE": "support",
    "OWNERSHIP_CHANGE": "support",
    "MAINTAINER_CHANGE": "support",
    "DISTRIBUTION_CHANGE": "distribution",
    "REGISTRY_CHANGE": "distribution",
    "OTHER_CRITICAL": "activity",
}

STALE_RELEASE_DAYS = 365


def _impact_of(item: Any) -> str:
    impact = item.get("impact") if isinstance(item, dict) else getattr(item, "impact", None)
    value = impact.value if hasattr(impact, "value") else str(impact)
    return value.upper() if value else "INFORMATIONAL"


def _type_of(item: Any) -> str:
    kind = item.get("event_type") if isinstance(item, dict) else getattr(item, "event_type", None)
    value = kind.value if hasattr(kind, "value") else str(kind)
    return value.upper() if value else ""


def _title_of(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("title", ""))
    return str(getattr(item, "title", ""))


def impact_to_status(impact: str) -> Status:
    return {
        "INFORMATIONAL": "ok",
        "WATCH": "watch",
        "REVIEW": "review",
        "ACTION": "action",
        "CRITICAL": "action",
    }.get(impact.upper(), "watch")


def activity_status(
    activity: dict[str, Any] | None, today: date | None = None
) -> tuple[Status, str]:
    """Repo metadata + release recency -> activity facet."""
    today = today or date.today()
    if not activity:
        return "ok", "no activity data observed"
    meta = activity.get("repo_meta") or {}
    if meta.get("archived"):
        return "action", f"{meta.get('repo', '?')} is archived — no fixes will land"
    newest = None
    for release in activity.get("releases", []) or []:
        published = str(release.get("published_at", ""))[:10]
        try:
            day = date.fromisoformat(published)
        except ValueError:
            continue
        if newest is None or day > newest:
            newest = day
    if newest is None:
        return "ok", "no releases observed"
    age = (today - newest).days
    if age > STALE_RELEASE_DAYS:
        return "review", f"no release in {age} days (latest {newest})"
    return "ok", f"latest release {newest} ({age} days ago)"


def compute_pulse(
    project: str,
    findings: list[dict[str, Any]] | None = None,
    events: list[Any] | None = None,
    activity: dict[str, Any] | None = None,
    popularity_note: str | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Worst-impact-wins per facet; strongest title kept as the reason."""
    best: dict[str, tuple[int, str]] = {facet: (-1, "") for facet in FACETS}
    for item in list(findings or []) + list(events or []):
        facet = EVENT_FACET.get(_type_of(item))
        if not facet:
            continue
        status = impact_to_status(_impact_of(item))
        if RANK[status] > best[facet][0]:
            best[facet] = (RANK[status], _title_of(item))
    facets: dict[str, dict[str, str]] = {}
    for facet in FACETS:
        if facet == "activity":
            status, reason = activity_status(activity, today)
        elif facet == "popularity":
            status, reason = "ok", popularity_note or "popularity methodology pending"
        elif best[facet][0] < 0:
            status, reason = "ok", f"no {facet} signals observed"
        else:
            rank, title = best[facet]
            status = next(s for s, r in RANK.items() if r == rank)
            reason = title
        facets[facet] = {"status": status, "reason": reason}
    summary = {level: sum(1 for f in facets.values() if f["status"] == level) for level in RANK}
    return {"project": project, "facets": facets, "summary": summary}


def format_pulse(pulse: dict[str, Any]) -> str:
    """Render lines: `redis` + one `Facet SYMBOL status — reason` per facet."""
    lines = [pulse.get("project", "?")]
    for facet in FACETS:
        info = pulse["facets"][facet]
        lines.append(
            f"{DISPLAY[facet]} {SYMBOL[info['status']]} {info['status']} — {info['reason']}"
        )
    return "\n".join(lines)
