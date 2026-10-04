"""Monthly report — seed + facets + top findings to ranked markdown.

Pure functions (no network): `collect_project` turns one raw bundle
into a report item; `build_report` ranks items into intelligence
sections. Every item names its evidence — findings carry sources and
references, never bare assertions.

Report semantics (§11): public findings describe OSS ecosystem
changes, never customer impact. Placement follows impact eligibility
(``core.risk.impact``), not raw analyst proposals: only evidence- and
scope-justified findings appear as actionable, and the report states
its incompleteness explicitly.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from analyzers import change_analyst, security_analyst
from analyzers.event_correlation import aggregate_lifecycle, lifecycle_first
from analyzers.report_analyst import (
    CONFIDENCE_MEANINGS,
    finding_confidence,
    recommended_investigation,
    render_finding_card,
)
from core.entities.catalog import project_context
from core.freshness import (
    MAIN_REPORT_STATES,
    UNKNOWN_DATE,
    classify,
    is_background,
)
from core.pulse import compute_pulse
from core.risk.impact import evaluate_impact
from core.risk.metrics import finding_source_distribution

DISCLAIMER = (
    "_Public report findings describe OSS ecosystem changes. They are "
    "not assertions that a particular customer's environment is "
    "affected._"
)

_ELIGIBLE = ("ACTION", "REVIEW", "WATCH")


def collect_project(
    slug: str, raw: dict[str, list[dict[str, Any]]], version: str | None = None
) -> dict[str, Any]:
    """One raw bundle -> report item (pulse + findings)."""
    context = project_context(slug)
    if version:
        context["version"] = version
    findings = change_analyst.analyze(raw)
    findings += security_analyst.correlate(raw, context)
    metas = [e for e in raw.get("github_meta", []) if e.get("kind") == "repo_meta"]
    activity = {"releases": raw.get("github", []), "repo_meta": metas[0] if metas else None}
    stars = (metas[0].get("stargazers") if metas else None) or None
    pulse = compute_pulse(
        slug, findings=findings, activity=activity, popularity_note=_popularity_note(stars)
    )
    return {"project": slug, "pulse": pulse, "findings": findings}


def _popularity_note(stars: Any) -> str:
    return f"popularity {popularity_tier(stars)}" + (
        f" ({stars} stars)" if isinstance(stars, int) else " (unranked)"
    )


def popularity_tier(stars: Any) -> str:
    """Documented bands (see METHODOLOGY): stars inform reach, never risk."""
    if not isinstance(stars, int):
        return "unranked"
    if stars >= 50000:
        return "very high"
    if stars >= 10000:
        return "high"
    if stars >= 1000:
        return "medium"
    return "low"


def _fresh(finding: dict[str, Any], since: str | None) -> bool:
    """Recency gate for dated findings only.

    Security findings carry `published`; lifecycle findings carry
    `event_date` (EOL/support dates — future ones always pass, they are
    early warnings). Undated findings always pass. Only dated items
    older than `since` (YYYY-MM-DD) are held back.
    """
    if since is None:
        return True
    stamp = str(finding.get("published") or finding.get("event_date") or "")[:10]
    if not stamp:
        return True
    return stamp >= since


def _narrate(finding: dict[str, Any], include_related: bool) -> bool:
    """Monthly narrative rule: established relationships and all change
    findings; keyword-only RELATED/UNKNOWN items are counted, not told."""
    relationship = str(finding.get("relationship", ""))
    if relationship in ("RELATED", "UNKNOWN"):
        return include_related
    return True


def _eligibility(finding: dict[str, Any]) -> dict[str, Any]:
    """Public-context eligibility, computed fresh (never stored)."""
    try:
        return evaluate_impact(finding)
    except Exception:
        return {
            "assessment": "PROJECT_SIGNAL",
            "eligibility": "INFORMATIONAL",
            "reasons": ["eligibility evaluation failed; held back"],
        }


def _change_class(finding: dict[str, Any]) -> str:
    """Intelligence section for one finding (legacy grouping, kept for compat)."""
    event_type = str(finding.get("event_type", ""))
    signal = str(finding.get("signal", ""))
    if event_type in ("EOL", "EOS"):
        return "Lifecycle changes"
    if event_type in ("DISTRIBUTION_CHANGE", "REGISTRY_CHANGE") or signal == "distribution":
        return "Distribution changes"
    if event_type == "SECURITY" or signal == "security" or finding.get("cve_id"):
        return "Security changes"
    return "Project signals"


#: Briefing categories, fixed order — public report groups meaningful
#: findings without letting lifecycle volume dominate. Security leads
#: because it is the most time-critical; lifecycle never first.
CATEGORY_ORDER = (
    "Security",
    "Lifecycle",
    "Distribution",
    "Repository",
    "Support",
    "License",
    "Ownership",
    "Other",
)


def category_of(finding: dict[str, Any]) -> str:
    """One finding -> briefing category (deterministic)."""
    event_type = str(finding.get("event_type", ""))
    signal = str(finding.get("signal", ""))
    if event_type in ("DISTRIBUTION_CHANGE", "REGISTRY_CHANGE") or signal == "distribution":
        return "Distribution"
    if event_type == "SECURITY" or signal == "security" or finding.get("cve_id"):
        return "Security"
    if event_type == "LICENSE_CHANGE":
        return "License"
    if event_type in ("EOL", "EOS"):
        return "Lifecycle"
    if event_type == "SUPPORT_CHANGE":
        return "Support"
    if event_type == "OWNERSHIP_CHANGE":
        return "Ownership"
    if event_type in ("PROJECT_ARCHIVED", "MAINTAINER_CHANGE"):
        return "Repository"
    return "Other"


#: Ranking order is separate from display order: Top Changes leads
#: with non-lifecycle work, so Lifecycle ranks last here even though
#: the Changes-by-Category table lists Security first.
_RANK_CATEGORY = {
    "Security": 0,
    "Distribution": 1,
    "License": 2,
    "Support": 3,
    "Ownership": 4,
    "Repository": 5,
    "Other": 6,
    "Lifecycle": 7,
}
_ELIGIBILITY_RANK = {"ACTION": 0, "REVIEW": 1, "WATCH": 2}
_CONFIDENCE_RANK = {"CONFIRMED": 0, "CORROBORATED": 1, "EMERGING": 2, "UNVERIFIED": 3}
_STATUS_RANK = {
    "NEW": 0,
    "UPCOMING": 1,
    "RECENTLY_UPDATED": 2,
    "ACTIVE": 3,
    "UNKNOWN_DATE": 4,
    "EXPIRED": 5,
}

#: Top-changes shortlist size.
_TOP_N = 10


def _has_future_effective(finding: dict[str, Any], today: date | None = None) -> bool:
    from core.leadtime import parse_day

    today = today or date.today()
    effective = parse_day(finding.get("effective_at") or finding.get("event_date"))
    return effective is not None and effective > today


def rank_key(project: str, finding: dict[str, Any], today: date | None = None) -> tuple:
    """Deterministic evidence-aware ranking: non-lifecycle first, then
    actionability, then confidence, then freshness status, then upcoming
    effective dates — never raw finding counts. Ties break on project +
    title.

    Background findings (effective over 12 months ago) sink below
    current ones within their bucket: last year's EOL never headlines
    this month's briefing, but stays narrated with its label.
    """
    from core.freshness import classify as _classify

    assessment = finding.get("_assessment") or {}
    status = finding.get("_freshness") or _classify(finding, today=today)[0]
    return (
        _RANK_CATEGORY.get(category_of(finding), 99),
        _ELIGIBILITY_RANK.get(assessment.get("eligibility", ""), 99),
        _CONFIDENCE_RANK.get(finding_confidence(finding), 99),
        _STATUS_RANK.get(status, 99),
        0 if _has_future_effective(finding) else 1,
        1 if is_background(finding) else 0,
        str(project),
        str(finding.get("title", "")),
    )


def _attach_refs(finding: dict[str, Any]) -> dict[str, Any]:
    """Copy with deduplicated `_refs` for card rendering."""
    seen: set[str] = set()
    refs = []
    for ref in (
        list(finding.get("references", []) or [])
        + _supporting_urls(finding)
        + list(finding.get("evidence_links", []) or [])
    ):
        if ref and ref not in seen:
            seen.add(ref)
            refs.append(ref)
    return {**finding, "_refs": refs}


def _month_title(month: str) -> str:
    """'2026-10' -> 'October 2026'. Raw input passes through unchanged."""
    try:
        return date(int(month[:4]), int(month[5:7]), 1).strftime("%B %Y")
    except (ValueError, IndexError):
        return month


def _in_main_report(finding: dict[str, Any]) -> bool:
    """Placement rule: freshness states NEW/UPCOMING/ACTIVE/
    RECENTLY_UPDATED narrate in the main report; EXPIRED findings live
    in the Historical appendix. UNKNOWN_DATE joins the main report
    only when REVIEW/ACTION-eligible (benefit of the doubt, stated)."""
    status = finding.get("_freshness")
    if status in MAIN_REPORT_STATES:
        return True
    if status == UNKNOWN_DATE:
        return (finding.get("_assessment") or {}).get("eligibility") in ("ACTION", "REVIEW")
    return False


def _ledger_fact(finding: dict[str, Any]) -> tuple[str, list[str]] | None:
    """(finding_class, subject, scope terms) for one finding in ledger terms.

    Identity contract - MUST mirror ``check.detections_from_verdicts``
    exactly: security facts key as (project, SECURITY, CVE id, no
    scope); lifecycle facts key as (project, LIFECYCLE, event_type,
    sorted cycle versions). Findings with no stable subject
    (distribution changes etc.) -> None; those keep their own
    durable first-detection through observation history, never the
    ledger.
    """
    from core.detections.ledger import LIFECYCLE, SECURITY

    cve = finding.get("cve_id")
    if cve:
        return (SECURITY, str(cve), [])
    event_type = str(finding.get("event_type") or "")
    if event_type in ("EOL", "EOS", "DEPRECATION"):
        scope = finding.get("scope") or {}
        versions = [str(v) for v in scope.get("versions") or []] or [
            str(v) for v in finding.get("affected_versions") or []
        ]
        if not versions:
            return None
        return (LIFECYCLE, event_type, sorted(versions))
    return None


def _with_ledger_first_detected(
    finding: dict[str, Any], project: str | None, ledger_root: str | None
) -> dict[str, Any]:
    """Copy of one finding with ledger first_seen as first_detected_at.

    No-op unless ALL of: ledger enabled, finding lacks a
    first_detected_at already, and the finding maps to a durable
    ledger fact. Never invents - absent entry -> unchanged finding.
    """
    if not ledger_root:
        return finding
    if finding.get("first_detected_at"):
        return finding
    fact = _ledger_fact(finding)
    if fact is None:
        return finding
    from core.detections.ledger import first_seen

    finding_class, subject, scope = fact
    earliest = first_seen(str(project or ""), finding_class, subject, scope=scope, root=ledger_root)
    if not earliest:
        return finding
    return {**finding, "first_detected_at": str(earliest)[:10]}


def prepare_report(
    items: list[dict[str, Any]],
    sweep_findings: list[dict[str, Any]] | None = None,
    since: str | None = None,
    include_related: bool = False,
    today: date | None = None,
    ledger_root: str | None = None,
) -> dict[str, Any]:
    """Assess + classify + place findings without rendering.

    Shared by `build_report` and metadata/CLI consumers so placement
    logic lives in exactly one place. Never mutates the caller's items.

    `ledger_root` (from ``openpulse report --ledger``) attaches the
    durable detection ledger's ``first_seen`` to findings lacking a
    ``first_detected_at`` (lifecycle findings from endoflife.date and
    security findings from CVE correlation have none), so warning
    windows survive across runs. An existing first_detected_at is
    never overwritten, and an absent ledger entry adds nothing -
    unknown stays unknown, never estimated.
    """
    today = today or date.today()
    held_back = 0
    scoped = []
    for item in items:
        # Copy: filtering must never mutate the caller's bundles.
        kept = [f for f in item.get("findings", []) if _fresh(f, since)]
        kept = [_with_ledger_first_detected(f, item.get("project"), ledger_root) for f in kept]
        held_back += sum(1 for f in kept if not _narrate(f, include_related))
        narrated = aggregate_lifecycle([f for f in kept if _narrate(f, include_related)])
        assessed = []
        for finding in narrated:
            assessment = _eligibility(finding)
            if assessment["eligibility"] not in _ELIGIBLE:
                held_back += 1
                continue
            status, _ = classify(finding, today=today)
            assessed.append({**finding, "_assessment": assessment, "_freshness": status})
        scoped.append({**item, "findings": assessed})
    assessed_sweep = []
    for finding in sweep_findings or []:
        if not _fresh(finding, since):
            continue
        assessment = _eligibility(finding)
        if assessment["eligibility"] == "INFORMATIONAL":
            continue
        status, _ = classify(finding, today=today)
        assessed_sweep.append(
            _attach_refs({**finding, "_assessment": assessment, "_freshness": status})
        )
    for item in scoped:
        item["findings"] = [_attach_refs(f) for f in item["findings"]]
    pairs = [(item["project"], finding) for item in scoped for finding in item["findings"]]
    pairs += [("registry sweep", finding) for finding in assessed_sweep]
    return {
        "scoped": scoped,
        "assessed_sweep": assessed_sweep,
        "held_back": held_back,
        "pairs": pairs,
        "main_pairs": [pf for pf in pairs if _in_main_report(pf[1])],
        "historical": [pf for pf in pairs if not _in_main_report(pf[1])],
    }


def build_report(
    month: str,
    items: list[dict[str, Any]],
    since: str | None = None,
    include_related: bool = False,
    notes: list[str] | None = None,
    sweep_findings: list[dict[str, Any]] | None = None,
    today: date | None = None,
    ledger_root: str | None = None,
) -> str:
    """Monthly public intelligence briefing — web-frontend-ready markdown.

    Narrative = eligible findings (eligibility above INFORMATIONAL
    after recency), placed by freshness: current findings narrate in
    the main report, EXPIRED findings move to the Historical appendix
    (never deleted). Only evidence- and scope-justified findings
    appear action-framed, and the report states its incompleteness
    explicitly.

    `sweep_findings` (distribution discovery output) joins the same
    ranking — cross-project observations keep the "registry sweep"
    project label so provenance stays visible. `today` pins all date
    arithmetic for deterministic tests; defaults to the current date.
    """
    today = today or date.today()
    prepared = prepare_report(
        items, sweep_findings, since, include_related, today, ledger_root=ledger_root
    )
    scoped = prepared["scoped"]
    assessed_sweep = prepared["assessed_sweep"]
    held_back = prepared["held_back"]
    pairs = prepared["pairs"]
    main_pairs = prepared["main_pairs"]
    historical = prepared["historical"]
    ranked = sorted(main_pairs, key=lambda pf: rank_key(pf[0], pf[1], today=today))
    attention = [
        pf for pf in ranked if (pf[1].get("_assessment") or {}).get("eligibility") == "ACTION"
    ]
    upcoming = _upcoming_changes(main_pairs, today=today)
    material = [
        pf
        for pf in main_pairs
        if (pf[1].get("_assessment") or {}).get("eligibility") in ("ACTION", "REVIEW")
    ]
    discoveries = [pf for pf in main_pairs if category_of(pf[1]) != "Lifecycle"]
    confidence_counts = _confidence_counts([f for _, f in main_pairs])
    background = sum(1 for _, f in pairs if is_background(f))
    unknown_dates = sum(1 for _, f in main_pairs if (f.get("_freshness") == UNKNOWN_DATE))
    silent = sorted(i["project"] for i in scoped if not i["findings"])
    month_title = _month_title(month)

    lines = [
        "# OpenPulse OSS Dependency Intelligence",
        "",
        f"## {month_title}",
        "",
        _introduction(month_title, len(scoped), len(material), len(discoveries)),
        "",
        DISCLAIMER,
        "",
        "## Executive Summary",
        "",
    ]
    lines += _executive_summary(
        month=month,
        projects=len(scoped),
        material=len(material),
        attention=len(attention),
        upcoming=len(upcoming),
        discoveries=len(discoveries),
        confidence_counts=confidence_counts,
        background=background,
        silent=len(silent),
        held_back=held_back,
        unknown_dates=unknown_dates,
    )
    lines.append("")
    lines.append("## Top Changes")
    lines.append("")
    if not ranked:
        lines.append("No material upstream changes detected this month.")
        lines.append("")
    for number, (project, finding) in enumerate(ranked[:_TOP_N], 1):
        lines.append(
            render_finding_card(project, finding, category_of(finding), number=number, max_refs=3)
        )
        lines.append("")
    reference = _reference_candidate(main_pairs)
    if reference is not None:
        lines.append("## OpenPulse Discovery of the Month")
        lines.append("")
        lines.append(
            "OpenPulse detects upstream changes and connects them to dependency identity."
        )
        lines.append("")
        lines += _reference_block(reference[0], reference[1])
        lines.append("")
    lines.append("## Changes Requiring Attention")
    lines.append("")
    if not attention:
        lines.append(
            "No changes met the action bar this month: nothing with "
            "evidence and scope justifying action-oriented framing."
        )
        lines.append("")
    for project, finding in attention:
        lines.append(f"- **{project}** — {finding.get('title', 'untitled')}")
        lines.append(
            f"  Scope: {_scope_text(finding)} · "
            f"Investigate: {recommended_investigation(finding, category_of(finding))}"
        )
    if attention:
        lines.append("")
    lines.append("## Upcoming Changes")
    lines.append("")
    if not upcoming:
        lines.append("No upcoming changes with trustworthy dates this month.")
        lines.append("")
    for detected, effective, days, project, finding in upcoming:
        announced = finding.get("announced_at") or "Unknown"
        first = finding.get("first_detected_at") or detected
        lines.append(f"- **{project}** — {finding.get('title', 'untitled')}")
        lines.append(
            f"  Announced: {announced} · Effective: {effective} · "
            f"{days} days until effective · OpenPulse first detected: {first}"
        )
    if upcoming:
        lines.append("")
    lines.append("## Changes by Category")
    lines.append("")
    lines.append("| Category | Changes | Requiring attention |")
    lines.append("|---|---|---|")
    for category in CATEGORY_ORDER:
        in_category = [pf for pf in main_pairs if category_of(pf[1]) == category]
        need_attention = sum(
            1 for _, f in in_category if (f.get("_assessment") or {}).get("eligibility") == "ACTION"
        )
        lines.append(f"| {category} | {len(in_category)} | {need_attention} |")
    lines.append("")
    lines.append("## Evidence Quality")
    lines.append("")
    for level in ("CONFIRMED", "CORROBORATED", "EMERGING", "UNVERIFIED"):
        lines.append(
            f"- {level} ({confidence_counts.get(level, 0)}): {CONFIDENCE_MEANINGS[level]}."
        )
    lines.append("")
    lines.append("## What OpenPulse Watches")
    lines.append("")
    lines.append(
        "OpenPulse watches what can change underneath software dependencies: "
        "security disclosures, lifecycle and support ends, distribution and "
        "registry changes, repository archival, license and ownership changes. "
        "Findings above are grouped by these categories — not by CVE counts or "
        "EOL tables — because the question is always what changed, not how many "
        "records a database holds."
    )
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Findings rest on named sources with content hashes; confidence "
        "(CONFIRMED / CORROBORATED / EMERGING / UNVERIFIED) follows evidence "
        "strength, never match precision. Dependency identity is resolved "
        "before impact is assessed, and unknown scope stays unknown. "
        "Freshness states (NEW / UPCOMING / ACTIVE / RECENTLY_UPDATED / "
        "EXPIRED) derive from announcement, effective, detection, and "
        "verification dates — expired findings move to the Historical "
        "appendix, never deleted. Full model: `docs/METHODOLOGY.md`."
    )
    lines.append("")
    lines.append("## What OpenPulse Added This Month")
    lines.append("")
    metrics = finding_source_distribution([f for _, f in main_pairs])
    lines += _value_section(
        pairs=main_pairs,
        upcoming=upcoming,
        confidence_counts=confidence_counts,
        metrics=metrics,
        reference=reference,
    )
    lines.append("")
    lines.append("## For Your Environment")
    lines.append("")
    lines.append(
        "This report describes open-source ecosystem intelligence. It does "
        "not establish that a specific customer environment is affected."
    )
    lines.append("")
    lines.append(
        "Dependency-aware impact requires a customer watchlist, inventory, "
        "or equivalent dependency context: public intelligence → dependency "
        "context (`openpulse check --watchlist <file>`) → affected dependency "
        "→ actionable warning. Only that last step can speak about your environment."
    )
    lines.append("")
    lines.append("## Appendix")
    lines.append("")
    lines.append("### A. Historical findings")
    lines.append("")
    if not historical:
        lines.append("No findings aged into the historical record this month.")
        lines.append("")
    for project, finding in sorted(historical, key=lambda pf: (pf[0], str(pf[1].get("title", "")))):
        announced = finding.get("announced_at") or "Unknown"
        effective = finding.get("effective_at") or finding.get("event_date") or "Unknown"
        reasons = (finding.get("_assessment") or {}).get("reasons") or []
        lines.append(f"- **{project}** — {finding.get('title', 'untitled')}")
        lines.append(
            f"  Status: {finding.get('_freshness', 'EXPIRED')} · "
            f"Announced: {announced} · Effective: {effective}"
        )
        if reasons:
            lines.append(f"  Note: {reasons[0]}")
    if historical:
        lines.append("")
    lines.append("### B. All current findings")
    lines.append("")
    current_by_project: dict[str, list[dict[str, Any]]] = {}
    for item in scoped:
        current = [f for f in item["findings"] if _in_main_report(f)]
        if current:
            current_by_project[item["project"]] = current
    for item in lifecycle_first(sorted(scoped, key=lambda i: i["project"])):
        if item["project"] not in current_by_project:
            continue
        lines.append(f"#### {item['project']}")
        lines.append("")
        for finding in current_by_project[item["project"]]:
            lines.append(render_finding_card(item["project"], finding, category_of(finding)))
            lines.append("")
    current_sweep = [f for f in assessed_sweep if _in_main_report(f)]
    if current_sweep:
        lines.append("#### Catalog-wide registry observations")
        lines.append("")
        for finding in current_sweep:
            lines.append(render_finding_card("registry sweep", finding, category_of(finding)))
            lines.append("")
    lines.append("### C. Source references")
    lines.append("")
    distribution = metrics["finding_source_distribution"]
    if distribution:
        lines.append(
            "Finding source distribution: "
            + ", ".join(f"{source} {pct}%" for source, pct in distribution.items())
        )
    else:
        lines.append("Finding source distribution: no findings this month.")
    lines.append(
        f"Independent source families observed: {metrics['source_family_count']} "
        f"(across {metrics['source_count']} recorded source labels)."
    )
    lines.append("")
    lines.append("### D. Data gaps and limitations")
    lines.append("")
    if silent:
        lines.append(f"No signals observed for: {', '.join(silent)}.")
        lines.append("")
    if held_back:
        lines.append(
            f"{held_back} related-but-unconfirmed or below-bar records held back "
            "(see `openpulse analyze` for the full stream)."
        )
        lines.append("")
    if not silent and not held_back:
        lines.append("No data gaps this month: every monitored project produced narrated findings.")
        lines.append("")
    if notes:
        lines.append("### E. Notes")
        lines.append("")
        lines += [f"- {note}" for note in notes]
        lines.append("")
    return "\n".join(lines).rstrip()


def build_report_metadata(
    month: str,
    items: list[dict[str, Any]],
    pairs: list[tuple[str, dict[str, Any]]],
    historical: list[tuple[str, dict[str, Any]]],
    sweep_included: bool,
    today: date | None = None,
) -> dict[str, Any]:
    """Machine-readable companion to the Markdown report: counts and
    provenance for web frontends. No finding content, no infrastructure
    details — identification and coverage only. Deterministic except
    `generated_at` (UTC instant of generation)."""
    from datetime import datetime, timezone

    from core.freshness import recency_days

    try:
        from importlib.metadata import version as _pkg_version

        openpulse_version = _pkg_version("openpulse")
    except Exception:
        openpulse_version = "unknown"
    today = today or date.today()
    status_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for _, finding in pairs:
        status = str(finding.get("_freshness", "UNKNOWN_DATE"))
        status_counts[status] = status_counts.get(status, 0) + 1
        category = category_of(finding)
        category_counts[category] = category_counts.get(category, 0) + 1
    return {
        "report_id": f"openpulse-{month}",
        "reporting_period": month,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "openpulse_version": openpulse_version,
        "freshness_policy": {
            "name": "freshness/v1",
            "recency_days": recency_days(),
            "research_window_days": 365,
        },
        "coverage": {
            "projects_monitored": len(items),
            "sweep_included": bool(sweep_included),
        },
        "counts": {
            "narrated_findings": len(pairs),
            "historical_findings": len(historical),
            "by_status": status_counts,
            "by_category": category_counts,
        },
        "report_date": str(today),
    }


def _supporting_urls(finding: dict[str, Any]) -> list[str]:
    """Source URLs carried inside supporting raw entries (endoflife links,
    GitHub release/advisory URLs). Deduplicated by the caller."""
    urls = []
    for entry in finding.get("supporting", []) or []:
        if not isinstance(entry, dict):
            continue
        for key in ("link", "url"):
            value = entry.get(key)
            if isinstance(value, str) and value.startswith("http") and value not in urls:
                urls.append(value)
    return urls


def _confidence_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """How many narrated findings sit at each confidence level."""
    counts = {"CONFIRMED": 0, "CORROBORATED": 0, "EMERGING": 0, "UNVERIFIED": 0}
    for finding in findings:
        counts[finding_confidence(finding)] += 1
    return counts


def _n(count: int, singular: str, plural: str | None = None) -> str:
    """'1 project' / '3 projects' — the summary screen respects grammar."""
    return f"{count} {singular}" if count == 1 else f"{count} {plural or singular + 's'}"


def _executive_summary(
    *,
    month: str,
    projects: int,
    material: int,
    attention: int,
    upcoming: int,
    discoveries: int,
    confidence_counts: dict[str, int],
    background: int,
    silent: int,
    held_back: int,
    unknown_dates: int,
) -> list[str]:
    """One-screen value statement + key numbers. Never raw counts alone:
    every number arrives inside a sentence about what it means."""
    if material:
        lines = [
            f"OpenPulse detected {_n(material, 'material upstream change')} across "
            f"{_n(projects, 'monitored project')} in {month}."
            + (
                f" That includes "
                f"{_n(discoveries, 'non-lifecycle discovery', 'non-lifecycle discoveries')} "
                "— changes no lifecycle database records."
                if discoveries
                else ""
            )
            + f" {_n(attention, 'change requires', 'changes require')} attention now"
            + (
                f"; {_n(upcoming, 'upcoming change still has', 'upcoming changes still have')} "
                "warning on the clock."
                if upcoming
                else "; no upcoming changes carry warning windows."
            )
        ]
    else:
        lines = [
            f"No material upstream changes detected across "
            f"{_n(projects, 'monitored project')} in {month}."
        ]
    lines += [
        "",
        f"- Projects monitored: {projects}",
        f"- Material changes (action + review): {material}",
        f"- Changes requiring attention: {attention}",
        f"- Upcoming changes with warning: {upcoming}",
        f"- Non-lifecycle discoveries: {discoveries}",
        "- Evidence confidence: "
        + ", ".join(
            f"{confidence_counts[level]} {level}"
            for level in ("CONFIRMED", "CORROBORATED", "EMERGING", "UNVERIFIED")
        ),
        f"- Background findings (effective over 12 months ago): {background}",
        "- Data gaps: "
        f"{_n(silent, 'project')} with no signals, {_n(held_back, 'record')} held back",
        f"- What remains uncertain: {_n(unknown_dates, 'finding carries')} unknown dates, "
        f"{_n(held_back, 'record was', 'records were')} held back for weak evidence",
    ]
    return lines


def _introduction(month_title: str, projects: int, material: int, discoveries: int) -> str:
    """One paragraph: what changed this month and what teams should know."""
    if not material:
        return (
            f"No material upstream changes were detected across "
            f"{_n(projects, 'monitored project')} in {month_title}. "
            "The appendices record coverage and gaps."
        )
    return (
        f"In {month_title}, OpenPulse identified {material} material upstream "
        f"changes worth a software team's attention, including {discoveries} "
        "non-lifecycle discoveries no lifecycle database records. "
        "Every item below names its evidence, its scope, and when it matters — "
        "and none of it speaks about your environment without a watchlist to prove it."
    )


def _upcoming_changes(
    pairs: list[tuple[str, dict[str, Any]]],
    today: date | None = None,
) -> list[tuple[str, str, int, str, dict[str, Any]]]:
    """(detected, effective, days, project, finding), sorted by effective
    date. Only first-trustworthy-detection windows — never estimates."""
    from core.leadtime import finding_lead_time, parse_day

    today = today or date.today()
    upcoming = []
    for project, finding in pairs:
        days, detected, effective = finding_lead_time(finding)
        if days is None or detected is None or effective is None:
            continue
        if (parse_day(effective) or date.min) <= today:
            continue
        upcoming.append((detected, effective, days, str(project), finding))
    upcoming.sort(key=lambda row: (row[1], row[3], str(row[4].get("title", ""))))
    return upcoming


def _scope_text(finding: dict[str, Any]) -> str:
    scope = finding.get("scope") or {}
    parts = []
    for key in ("versions", "artifacts", "packages", "registries"):
        parts += [str(v) for v in scope.get(key) or []]
    return ", ".join(parts) if parts else str(scope.get("kind", "project"))


def _reference_candidate(
    pairs: list[tuple[str, dict[str, Any]]],
) -> tuple[str, dict[str, Any]] | None:
    """Strongest non-lifecycle story: distribution model changes first,
    then high-significance distribution/registry changes. None when no
    suitable finding exists (section omitted, never padded)."""
    scored = []
    for project, finding in pairs:
        category = category_of(finding)
        if category == "Lifecycle" and not finding.get("distribution_model_change"):
            continue
        if category not in ("Distribution", "Security"):
            continue
        # Showcase-worthy only: model changes, high significance, or
        # corroborated-plus evidence. A RELATED-only record is never
        # the reference story.
        if not (
            finding.get("distribution_model_change")
            or str(finding.get("significance") or "") == "high"
            or finding_confidence(finding) in ("CONFIRMED", "CORROBORATED")
        ):
            continue
        scored.append(
            (
                1 if finding.get("distribution_model_change") else 0,
                1 if str(finding.get("significance") or "") == "high" else 0,
                str(project),
                str(finding.get("title", "")),
                project,
                finding,
            )
        )
    if not scored:
        return None
    scored.sort(key=lambda row: (-row[0], -row[1], row[2], row[3]))
    return scored[0][4], scored[0][5]


def _reference_block(project: str, finding: dict[str, Any]) -> list[str]:
    """Canonical WHAT/WAY/EVIDENCE breakout for the reference discovery."""
    evidence = finding.get("observation_evidence") or {}
    lines = [
        f"### {finding.get('title', 'untitled')}",
        "",
        "WHAT CHANGED",
        "",
        str(finding.get("summary") or finding.get("title", "")),
        "",
        "WHY IT MATTERS",
        "",
        _why_text(finding),
        "",
        "HOW OPENPULSE DETECTED IT",
        "",
        _detection_text(finding),
        "",
        "WHAT WAS AFFECTED",
        "",
    ]
    affected = [
        str(a.get("ref")) for a in finding.get("affected_artifacts", []) or []
        if isinstance(a, dict) and a.get("ref")
    ]
    versions = [str(v) for v in finding.get("affected_versions", []) or [] if v != "*"]
    for ref in affected:
        lines.append(f"- `{ref}`")
    for version in versions:
        lines.append(f"- version `{version}`")
    if not affected and not versions:
        lines.append(f"- {project} (project scope)")
    lines += ["", "WHAT WAS NOT AFFECTED", ""]
    not_affected = _not_affected_text(project, finding)
    if not_affected:
        lines.append(not_affected)
    else:
        lines.append("Not established from the available evidence — omitted, not assumed.")
    lines += ["", "EVIDENCE", ""]
    for ref in finding.get("_refs", []) or []:
        lines.append(f"- {ref}")
    if evidence.get("observation_id"):
        lines.append(f"- observation `{evidence.get('observation_id')}`")
    if evidence.get("content_hash"):
        lines.append(f"- content `{evidence.get('content_hash')}`")
    if evidence.get("chain_hash"):
        lines.append(f"- chain `{evidence.get('chain_hash')}`")
    lines += ["", "ANNOUNCED", ""]
    announced = finding.get("announced_at")
    if announced:
        provenance = str(finding.get("announcement_provenance") or "official")
        lines.append(f"{str(announced)[:10]} ({provenance} upstream publication date).")
    else:
        lines.append("Unknown — no trustworthy upstream publication date on record.")
    lines += ["", "OPENPULSE DETECTION", ""]
    from core.leadtime import finding_lead_time, parse_day

    first = parse_day(finding.get("first_detected_at"))
    if first is not None:
        lines.append(f"First detected by OpenPulse: {first}.")
        if announced and parse_day(announced) is not None:
            gap = (first - parse_day(announced)).days
            if gap >= 0:
                lines.append(
                    f"Announcement → detection: {gap} days ({announced} → {first})."
                )
    else:
        lines.append("First detection unrecorded.")
    lines += ["", "WARNING WINDOW", ""]
    days, detected, effective = finding_lead_time(finding)
    if days is not None and detected and effective:
        lines.append(
            f"Detection lead time before effective date: {days} days "
            f"(first detected {detected} → effective {effective})."
        )
    else:
        lines.append("No trustworthy warning window — first detection unrecorded.")
    return lines


def _why_text(finding: dict[str, Any]) -> str:
    reasons = (finding.get("_assessment") or {}).get("reasons") or []
    if reasons:
        return str(reasons[0])
    return str(finding.get("summary") or "No assessment recorded.")


def _detection_text(finding: dict[str, Any]) -> str:
    method = str(finding.get("detection_method") or "")
    evidence = finding.get("observation_evidence") or {}
    fact = evidence.get("fact") or {}
    if method == "registry_observation" and fact:
        window = ""
        if evidence.get("previous_observed_at") or evidence.get("observed_at"):
            window = (
                f" between {evidence.get('previous_observed_at', '?')} "
                f"and {evidence.get('observed_at', '?')}"
            )
        link = ""
        if evidence.get("previous_observation_id") and evidence.get("observation_id"):
            link = (
                f" Chain-verified observations "
                f"`{evidence['previous_observation_id']}` → `{evidence['observation_id']}`."
            )
        return (
            f"Direct registry observation: `{fact.get('type')}` for "
            f"`{fact.get('image', '?')}:{fact.get('tag', '')}`{window}.{link}"
        )
    if method == "namespace_heuristic":
        return (
            "Namespace pattern analysis across registry probes "
            "(discovery heuristic — corroborate pulls and mirrors before acting)."
        )
    return "Analyst rules over collector output, gated by evidence before reporting."


def _not_affected_text(project: str, finding: dict[str, Any]) -> str:
    """Concrete NOT-AFFECTED scope, only from evidence on hand."""
    evidence = finding.get("observation_evidence") or {}
    fact = evidence.get("fact") or {}
    if finding.get("event_type") == "DISTRIBUTION_CHANGE":
        gone = [str(t.get("tag")) for t in fact.get("tags", []) or []]
        if not gone and fact.get("tag") is not None:
            gone = [str(fact.get("tag"))]
        others = [t for t in fact.get("tags_present") or [] if str(t) not in gone]
        if gone and others:
            rendered = ", ".join(f"`{t}`" for t in sorted(others))
            return (
                f"Other tags still published in the same repository ({rendered}): "
                "no change observed for these."
            )
    if finding.get("distribution_model_change"):
        return (
            "`latest`-tag consumers: latest-only publication continues; "
            "pinned version references need a migration plan."
        )
    return ""


def _value_section(
    *,
    pairs: list[tuple[str, dict[str, Any]]],
    upcoming: list[tuple[str, str, int, str, dict[str, Any]]],
    confidence_counts: dict[str, int],
    metrics: dict[str, Any],
    reference: tuple[str, dict[str, Any]] | None,
) -> list[str]:
    """What OpenPulse added this month — demonstrated, not claimed.

    Every line derives from this report's data: categories, examples,
    counts, and the reference case all come from narrated findings.
    Empty dimensions are omitted, never padded; nothing here is a
    vanity metric (project counts never headline).
    """
    findings = [f for _, f in pairs]
    lines = [
        "OpenPulse is designed to answer a question traditional dependency "
        "monitoring often does not answer: Something changed upstream. Does "
        "it affect what we depend on?",
        "",
        "This month the report answers it with the findings below — detected "
        "upstream changes, explained in context, correlated across sources, "
        "attributed to dependency identity, with warning where dates allow. "
        "OpenPulse does not replace SCA, SBOM, vulnerability, or lifecycle "
        "databases — it is an intelligence layer across them.",
        "",
        "### Upstream Change Detection",
        "",
    ]
    by_category: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for project, finding in pairs:
        by_category.setdefault(category_of(finding), []).append((project, finding))
    for category in CATEGORY_ORDER:
        group = by_category.get(category, [])
        if not group:
            continue
        example = sorted(group, key=lambda pf: rank_key(pf[0], pf[1]))[0]
        lines.append(
            f"- {category} ({len(group)}): e.g. **{example[0]}** — "
            f"{example[1].get('title', 'untitled')}"
        )
    lines += ["", "### Dependency Attribution", ""]
    lines += _attribution_lines(pairs, reference)
    lines += ["", "### Evidence-backed Intelligence", ""]
    total_refs = sum(len(f.get("_refs") or []) for f in findings)
    scoped = sum(1 for f in findings if _scope_text(f) != "project")
    dated = sum(1 for f in findings if f.get("effective_at") or f.get("event_date"))
    strongest = next(
        (
            level
            for level in ("CONFIRMED", "CORROBORATED", "EMERGING", "UNVERIFIED")
            if confidence_counts.get(level)
        ),
        "UNVERIFIED",
    )
    lines.append(
        f"- Confirmation level: strongest finding this month is {strongest}; "
        "full breakdown in Evidence Quality. No opaque risk scores."
    )
    families = _n(
        metrics["source_family_count"],
        "independent source family",
        "independent source families",
    )
    lines.append(f"- {families} across {_n(total_refs, 'supporting reference')}.")
    lines.append(f"- Scope established for {scoped}/{len(findings)} findings.")
    lines.append(f"- Effective date known for {dated}/{len(findings)} findings.")
    lines += ["", "### Early Warning", ""]
    if upcoming:
        longest = max(days for _, _, days, _, _ in upcoming)
        lines.append(
            f"- {_n(len(upcoming), 'upcoming change carries', 'upcoming changes carry')} "
            f"a warning window measured from first trustworthy detection "
            f"(up to {longest} days). Details in Upcoming Changes."
        )
    else:
        lines.append(
            "- No upcoming changes with trustworthy dates this month — "
            "nothing to warn about yet."
        )
    if reference is not None:
        lines += ["", "### Reference Case", ""]
        lines += _reference_case_lines(reference[0], reference[1])
    lines += ["", "### From Public Intelligence to Early Warning", ""]
    lines += [
        "- Public intelligence: “What is changing in OSS?” — this report.",
        "- Dependency intelligence: “What is changing in the OSS projects I use?” — "
        "`openpulse check --watchlist <file>`.",
        "- Customer impact: “Does this affect my software?” — matched dependencies only.",
        "- Early warning: “How much warning do I have?” — warning windows above.",
    ]
    return lines


def _attribution_lines(
    pairs: list[tuple[str, dict[str, Any]]],
    reference: tuple[str, dict[str, Any]] | None,
) -> list[str]:
    """Scope-kind examples from ranked findings + the Bitnami distinction
    when bitnami-namespaced evidence is present. Absent kinds are absent
    lines — never invented examples."""
    seen_kinds: dict[str, tuple[str, dict[str, Any]]] = {}
    for project, finding in sorted(pairs, key=lambda pf: rank_key(pf[0], pf[1])):
        scope = finding.get("scope") or {}
        for kind in ("artifacts", "versions", "packages"):
            values = scope.get(kind) or []
            if values and kind not in seen_kinds:
                seen_kinds[kind] = (project, finding)
        if scope.get("kind") == "project" and "project" not in seen_kinds:
            seen_kinds["project"] = (project, finding)
    labels = {
        "artifacts": "Affected artifact",
        "versions": "Affected version",
        "packages": "Affected package",
        "project": "Related project",
    }
    lines = []
    for kind in ("artifacts", "versions", "packages", "project"):
        if kind not in seen_kinds:
            continue
        project, finding = seen_kinds[kind]
        scope = finding.get("scope") or {}
        if kind == "project":
            example = project
        else:
            example = f"`{(scope.get(kind) or ['?'])[0]}`"
        lines.append(f"- {labels[kind]}: {example} — {finding.get('title', 'untitled')}")
    bitnami_ref = _bitnami_example(pairs)
    if bitnami_ref:
        lines.append(
            f"- `{bitnami_ref}` resolves to the Bitnami distribution identity, "
            "not the upstream project."
        )
        lines.append(
            "docker.io/bitnami/redis is not docker.io/redis: namespace-aware "
            "resolution keeps distribution packaging apart from upstream code."
        )
    if reference is not None:
        not_affected = _not_affected_text(reference[0], reference[1])
        if not_affected:
            lines.append(f"- Not affected: {not_affected}")
    if not lines:
        lines.append("No scoped attributions this month.")
    return lines


def _bitnami_example(pairs: list[tuple[str, dict[str, Any]]]) -> str:
    """First bitnami-namespaced ref in ranked findings, or '' when the
    Bitnami case is not present (callout omitted, never padded)."""
    for project, finding in sorted(pairs, key=lambda pf: rank_key(pf[0], pf[1])):
        haystacks: list[str] = []
        scope = finding.get("scope") or {}
        for key in ("artifacts", "versions", "packages", "registries"):
            haystacks += [str(v) for v in scope.get(key) or []]
        haystacks += [
            str(a.get("ref"))
            for a in finding.get("affected_artifacts", []) or []
            if isinstance(a, dict) and a.get("ref")
        ]
        for text in haystacks:
            lowered = text.lower()
            if "bitnami" in lowered and "/" in lowered:
                return text.strip("`")
    return ""


def _reference_case_lines(project: str, finding: dict[str, Any]) -> list[str]:
    """Problem → Signal → Evidence → Identity → Applicability →
    Recommended investigation — every line rendered from the finding's
    own data. Reproducible: same finding, same case."""
    from core.leadtime import finding_lead_time

    evidence = finding.get("observation_evidence") or {}
    assessment = finding.get("_assessment") or {}
    refs = finding.get("_refs") or []
    days, detected, effective = finding_lead_time(finding)
    window = (
        f"{days} days (Detected {detected} → Effective {effective})"
        if days is not None and detected and effective
        else "unrecorded (first detection unknown)"
    )
    return [
        f"Problem: {finding.get('title', 'untitled')}",
        "",
        f"Signal: {category_of(finding)} · {finding.get('detection_method', 'analyst rules')} · "
        f"significance {finding.get('significance', 'unstated')}.",
        "",
        f"Evidence: {finding_confidence(finding)} confidence · {len(refs)} references"
        + (
            f" · observation `{evidence.get('observation_id')}`"
            if evidence.get("observation_id")
            else ""
        )
        + ".",
        "",
        f"Identity: {_scope_text(finding)}.",
        "",
        f"Applicability: {assessment.get('assessment', '?')} "
        f"({assessment.get('eligibility', '?')}) — {_why_text(finding)}",
        "",
        f"Recommended investigation: {recommended_investigation(finding, category_of(finding))}",
        "",
        f"Warning window: {window}.",
    ]
