"""Watchlist checking — Dependency Early Warning.

A watchlist names the dependencies a team actually runs (image refs
and/or packages with versions). Checking keeps two reasoning streams
separate — event-based intelligence (explicit upstream events) and
security correlation (CVE/package/version applicability) — and
combines them only at the final verdict, retaining each cause.

Decision matrix (final relationship):
  AFFECTS_ARTIFACT > AFFECTS_VERSION > AFFECTS_PACKAGE
  > NOT_AFFECTED > RELATED > AFFECTS_PROJECT > UNKNOWN
`affected` is True only for ARTIFACT/VERSION/PACKAGE. A project-only
tie (AFFECTS_PROJECT) is contextual, never impact. Pure functions.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from analyzers.security_analyst import correlate
from core.entities.identity import resolution_trust
from core.entities.resolve import resolve_project
from core.risk.match import event_affects_ref
from core.schema.models import OSSEvent
from core.versions import compare

_RANK = {
    "UNKNOWN": 0,
    "RELATED": 1,
    "AFFECTS_PROJECT": 2,
    "NOT_AFFECTED": 3,
    "AFFECTS_PACKAGE": 4,
    "AFFECTS_VERSION": 5,
    "AFFECTS_ARTIFACT": 6,
}

_AFFECTED = ("AFFECTS_ARTIFACT", "AFFECTS_VERSION", "AFFECTS_PACKAGE")

#: Match strength answers "what matches" — never "how trustworthy is
#: the underlying claim". The ceiling below is what a match *alone*
#: can justify; the verdict confidence is the conservative minimum of
#: this ceiling and the evidence behind the event.
_MATCH_CEILING = {
    "AFFECTS_ARTIFACT": "CONFIRMED",
    "AFFECTS_VERSION": "CORROBORATED",
    "AFFECTS_PACKAGE": "EMERGING",
    "NOT_AFFECTED": "CORROBORATED",
    "AFFECTS_PROJECT": "EMERGING",
    "RELATED": "UNVERIFIED",
    "UNKNOWN": "UNVERIFIED",
}

_MATCH_STRENGTH = {
    "AFFECTS_ARTIFACT": "exact",
    "AFFECTS_VERSION": "scoped",
    "AFFECTS_PACKAGE": "scoped",
    "NOT_AFFECTED": "exclusion",
    "AFFECTS_PROJECT": "contextual",
    "RELATED": "contextual",
    "UNKNOWN": "none",
}

_CONFIDENCE_ORDER = {"UNVERIFIED": 0, "EMERGING": 1, "CORROBORATED": 2, "CONFIRMED": 3}

#: Identity statuses that must not silently elevate impact. Exact
#: artifact equality (self-identity) is exempt — see identity.py.
_UNTRUSTED_IDENTITY = ("REVIEW_REQUIRED", "UNVERIFIED")
_IDENTITY_CAP = "EMERGING"


def _weaker(first: str, second: str) -> str:
    order = _CONFIDENCE_ORDER
    return first if order.get(first, 0) <= order.get(second, 0) else second


class DependencyVerdict(BaseModel):
    """One dependency, fully explained. `affected` derives from evidence."""

    dependency: str
    affected: bool
    relationship: str
    confidence: str = "UNVERIFIED"
    match_strength: str = "none"
    evidence_confidence: str = "UNVERIFIED"
    identity_status: str = "VERIFIED"
    match_method: str | None = None
    evidence: list[str] = Field(default_factory=list)
    events: list[str] = Field(default_factory=list)
    reason: str = ""
    verdicts: list[dict[str, Any]] = Field(
        default_factory=list, description="Retained per-cause verdicts (streams stay separate)"
    )
    first_detected: str | None = Field(
        default=None,
        description=(
            "Earliest durable ledger detection across this verdict's recorded "
            "lifecycle/security causes; None when nothing is recorded (never a guess)"
        ),
    )


def load_watchlist_doc(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate a parsed watchlist document into normalized dep entries.

    Optional passthrough (never required): source, environment, owner.
    """
    if not isinstance(doc, dict):
        raise ValueError("watchlist must be a mapping")
    deps = doc.get("dependencies", [])
    if not isinstance(deps, list) or not deps:
        raise ValueError("watchlist needs a non-empty `dependencies` list")
    normalized = []
    for i, dep in enumerate(deps):
        if not isinstance(dep, dict):
            raise ValueError(f"dependency #{i} must be a mapping")
        extra = {}
        for key in ("source", "environment", "owner"):
            if dep.get(key) is not None:
                if not isinstance(dep[key], str):
                    raise ValueError(f"dependency #{i} field `{key}` must be a string")
                extra[key] = dep[key]
        if dep.get("ref"):
            normalized.append({"kind": "image", "ref": str(dep["ref"]), **extra})
        elif dep.get("package"):
            normalized.append(
                {
                    "kind": "package",
                    "package": str(dep["package"]),
                    "ecosystem": str(dep.get("ecosystem", "")),
                    "version": str(dep["version"]) if dep.get("version") else None,
                    **extra,
                }
            )
        else:
            raise ValueError(f"dependency #{i} needs `ref` or `package`")
    return normalized


def _dep_label(dep: dict[str, Any]) -> str:
    if dep["kind"] == "image":
        return str(dep["ref"])
    version = dep.get("version")
    return f"{dep['package']}=={version}" if version else str(dep["package"])


def _event_scope_cause(dep: dict[str, Any], event: OSSEvent) -> dict[str, Any] | None:
    """Package dep vs one event's scope. None when the event says nothing usable."""
    slug = resolve_project(str(dep["package"]))
    if slug != event.project_slug:
        return None
    trust = resolution_trust(str(dep["package"]))
    scope = event.scope
    version = dep.get("version")
    base: dict[str, Any] = {
        "cause": "upstream_change",
        "event_id": event.id,
        "event_type": event.event_type.value,
        "project": event.project_slug,
        "impact": event.impact.value,
        "evidence": [e.source.name for e in event.evidences],
        "evidence_confidence": event.confidence.value,
        "identity_status": trust["identity_status"],
        "identity_via": trust["via"],
    }
    if scope is None:
        return {
            **base,
            "relationship": "RELATED",
            "affected": False,
            "match_method": "project_scope",
            "reason": f"{dep['package']} belongs to event project {slug}; impact not established",
        }
    kind = scope.kind
    if kind == "version" and scope.versions:
        if not version:
            return {
                **base,
                "relationship": "RELATED",
                "affected": False,
                "match_method": "project_scope",
                "reason": f"event is version-scoped to {scope.versions}; dep version unknown",
            }
        for scoped in scope.versions:
            if compare(str(version), str(scoped)) == 0:
                return {
                    **base,
                    "relationship": "AFFECTS_VERSION",
                    "affected": True,
                    "match_method": "event_scope_version",
                    "reason": f"{dep['package']}=={version} matches event scope version {scoped}",
                }
        return {
            **base,
            "relationship": "NOT_AFFECTED",
            "affected": False,
            "match_method": "event_scope_version",
            "reason": (f"{dep['package']}=={version} is outside scope versions {scope.versions}"),
        }
    if kind == "package" and scope.packages:
        names = {str(p).lower() for p in scope.packages}
        if str(dep["package"]).lower() in names or slug in names:
            return {
                **base,
                "relationship": "AFFECTS_PACKAGE",
                "affected": True,
                "match_method": "event_scope_package",
                "reason": f"{dep['package']} is inside event scope packages {scope.packages}",
            }
        return {
            **base,
            "relationship": "NOT_AFFECTED",
            "affected": False,
            "match_method": "event_scope_package",
            "reason": f"{dep['package']} is outside event scope packages {scope.packages}",
        }
    if kind == "artifact":
        return {
            **base,
            "relationship": "RELATED",
            "affected": False,
            "match_method": "project_scope",
            "reason": "event is artifact-scoped; a package ref cannot match artifacts",
        }
    return {
        **base,
        "relationship": "AFFECTS_PROJECT",
        "affected": False,
        "match_method": "project_scope",
        "reason": (f"{dep['package']} belongs to {slug}; project ties are contextual, not impact"),
    }


Cause = dict[str, Any]


def _security_causes(dep: dict[str, Any], bundles: dict[str, dict[str, Any]]) -> list[Cause]:
    """CVE/package/version applicability stream (independent of events)."""
    if dep["kind"] != "package":
        return []
    slug = resolve_project(str(dep["package"]))
    raw = bundles.get(slug)
    if raw is None:
        return []
    context = {
        "slug": slug,
        "package": dep["package"],
        "ecosystem": dep.get("ecosystem", ""),
        "version": dep.get("version"),
    }
    causes = []
    trust = resolution_trust(str(dep["package"]))
    for finding in correlate(raw, context):
        relationship = str(finding.get("relationship", "UNKNOWN"))
        if relationship == "UNKNOWN":
            continue
        causes.append(
            {
                "cause": "security_vulnerability",
                "relationship": relationship,
                "affected": relationship in ("AFFECTS_VERSION", "AFFECTS_PACKAGE"),
                "match_method": finding.get("match_method"),
                "event_id": finding.get("cve_id"),
                "event_type": "SECURITY",
                "project": slug,
                "impact": finding.get("impact"),
                "evidence": list(finding.get("sources", [])),
                "evidence_confidence": str(finding.get("confidence") or "UNVERIFIED"),
                "identity_status": trust["identity_status"],
                "identity_via": trust["via"],
                "reason": (
                    f"{finding.get('cve_id')} [{relationship}] via {finding.get('match_method')}"
                ),
            }
        )
    return causes


def _combine(dep: dict[str, Any], causes: list[Cause]) -> DependencyVerdict:
    """Explicit decision matrix over retained causes.

    Final confidence is the conservative minimum of what the match
    alone justifies (match ceiling) and the evidence behind the
    winning cause — a precise match on a weak claim stays weak.
    Verdicts that rely on untrusted identity mappings (anything but
    exact artifact equality through REVIEW_REQUIRED/UNVERIFIED
    mappings) are capped at EMERGING.
    """
    label = _dep_label(dep)
    if not causes:
        return DependencyVerdict(
            dependency=label,
            affected=False,
            relationship="UNKNOWN",
            reason="no applicable evidence",
        )
    for cause in causes:
        cause.setdefault("detail", cause.get("reason", ""))
        cause.setdefault("evidence_confidence", "UNVERIFIED")
        cause.setdefault("identity_status", "VERIFIED")
    top = max(causes, key=lambda c: _RANK.get(str(c["relationship"]), 0))
    relationship = str(top["relationship"])
    affected = relationship in _AFFECTED
    match_strength = _MATCH_STRENGTH.get(relationship, "none")
    evidence_confidence = str(top.get("evidence_confidence") or "UNVERIFIED")
    confidence = _weaker(
        _MATCH_CEILING.get(relationship, "UNVERIFIED"), evidence_confidence
    )
    identity_status = str(top.get("identity_status") or "VERIFIED")
    via_artifact_exact = str(top.get("match_method") or "") == "event_scope:artifact"
    capped_identity = False
    if affected and not via_artifact_exact and identity_status in _UNTRUSTED_IDENTITY:
        confidence = _weaker(confidence, _IDENTITY_CAP)
        capped_identity = True
    evidence: list[str] = []
    events: list[str] = []
    for cause in causes:
        for item in cause.get("evidence", []) or []:
            if item not in evidence:
                evidence.append(str(item))
        event_id = cause.get("event_id")
        if event_id and event_id not in events:
            events.append(str(event_id))
    if affected:
        reason = "; ".join(c.get("reason", "") for c in causes if c.get("affected")) or top.get(
            "reason", ""
        )
    else:
        reason = top.get("reason", "") or f"evaluated {label}: no established impact"
    if capped_identity:
        reason = (
            f"{reason} [identity {identity_status} via "
            f"{top.get('identity_via', '?')}: confidence capped at {_IDENTITY_CAP}]"
        )
    return DependencyVerdict(
        dependency=label,
        affected=affected,
        relationship=relationship,
        confidence=confidence,
        match_strength=match_strength,
        evidence_confidence=evidence_confidence,
        identity_status=identity_status,
        match_method=top.get("match_method"),
        evidence=evidence,
        events=events,
        reason=reason,
        verdicts=causes,
    )


_ACTION_IMPACTS = ("ACTION", "CRITICAL")


def strict_affected(results: list[DependencyVerdict]) -> bool:
    """Whether --strict should fail: an affected verdict carried by an
    ACTION-level cause. REVIEW/WATCH-level affected verdicts (e.g. weak
    evidence capped findings) never trip the gate on their own."""
    for result in results:
        if not result.affected:
            continue
        for cause in result.verdicts:
            if cause.get("affected") and str(cause.get("impact", "")).upper() in _ACTION_IMPACTS:
                return True
    return False


Verdict = DependencyVerdict


def check_dependency(
    dep: dict[str, Any], events: list[OSSEvent], bundles: dict[str, dict[str, Any]] | None = None
) -> DependencyVerdict:
    """One dep vs events (+ optional raw bundles) -> explicit verdict."""
    bundles = bundles or {}
    causes: list[Cause] = []
    if dep["kind"] == "image":
        trust = resolution_trust(str(dep["ref"]))
        for event in events:
            match = event_affects_ref(event, dep["ref"])
            exact = match["via"] == "artifact"
            causes.append(
                {
                    "cause": "upstream_change",
                    "relationship": match["relationship"],
                    "affected": bool(match["affected"]),
                    "match_method": f"event_scope:{match['via']}"
                    if match["via"]
                    else "project_scope",
                    "event_id": event.id,
                    "event_type": event.event_type.value,
                    "project": event.project_slug,
                    "impact": event.impact.value,
                    "evidence": [e.source.name for e in event.evidences],
                    "evidence_confidence": event.confidence.value,
                    # Exact artifact equality is self-identity (no
                    # mapping involved); anything coarser relies on the
                    # slug resolution and inherits its trust.
                    "identity_status": "VERIFIED" if exact else trust["identity_status"],
                    "identity_via": "exact-artifact" if exact else trust["via"],
                    "reason": str(match["detail"]),
                }
            )
    else:
        for event in events:
            cause = _event_scope_cause(dep, event)
            if cause is not None:
                causes.append(cause)
        causes.extend(_security_causes(dep, bundles))
    return _combine(dep, causes)


def check_watchlist(
    deps: list[dict[str, Any]],
    events: list[OSSEvent],
    bundles: dict[str, dict[str, Any]] | None = None,
) -> list[DependencyVerdict]:
    """Whole watchlist -> one verdict per dependency."""
    return [check_dependency(dep, events, bundles) for dep in deps]


#: Event types whose findings describe a *durable* lifecycle fact -
#: re-detectable across runs, and the ledger is what makes their first
#: detection survive the process. Distribution/registry changes keep
#: their own durable first-detection via observation history diffs.
_LIFECYCLE_EVENT_TYPES = frozenset({"EOL", "EOS", "DEPRECATION", "SUPPORT_CHANGE"})

#: Relationships asserting the dependency is implicated: the only
#: ones that start (or continue) a durable detection record.
_AFFECTED_RELATIONSHIPS = frozenset({"AFFECTS_VERSION", "AFFECTS_PACKAGE", "AFFECTS_ARTIFACT"})


def detections_from_verdicts(
    verdicts: list[DependencyVerdict],
    events: list[OSSEvent] | None = None,
) -> list[dict[str, Any]]:
    """Durable detection facts carried by check verdicts.

    Pure function - verdicts in, ledger-shaped fact descriptors out
    (project, finding_class, subject, scope terms); no writes here.
    The fact identity is deliberately announcement-independent:
    lifecycle facts key as (project, event_type, cycle versions) and
    security facts as (project, CVE id), so the same underlying fact
    reported by different events/sources across runs maps to ONE
    ledger entry. `events` supplies the scope versions for lifecycle
    causes (the cause carries the event id). Only impact-asserting
    relationships contribute: a RELATED tie is context, not a
    detection worth remembering, and UNKNOWN means no evidence.
    Never invents: causes without a usable identity are skipped.
    """
    from core.detections import ledger

    events_by_id = {e.id: e for e in events or []}
    facts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    for verdict in verdicts:
        for cause in verdict.verdicts:
            if str(cause.get("relationship", "")) not in _AFFECTED_RELATIONSHIPS:
                continue
            project = str(cause.get("project") or "")
            if not project:
                continue  # no stable project -> nothing durable
            if cause.get("cause") == "security_vulnerability":
                subject = str(cause.get("event_id") or "")
                if not subject:
                    continue
                key = (project, ledger.SECURITY, subject, ())
                if key in seen:
                    continue
                seen.add(key)
                facts.append(
                    {
                        "project": project,
                        "finding_class": ledger.SECURITY,
                        "subject": subject,
                        "scope": [],
                    }
                )
                continue
            if cause.get("cause") != "upstream_change":
                continue
            event_type = str(cause.get("event_type") or "")
            if event_type not in _LIFECYCLE_EVENT_TYPES:
                continue  # distribution changes keep observation-history detection
            event = events_by_id.get(str(cause.get("event_id") or ""))
            if event is None or event.scope is None:
                continue
            versions = sorted({str(v) for v in event.scope.versions or []})
            if not versions:
                continue
            key = (project, ledger.LIFECYCLE, event_type, tuple(versions))
            if key in seen:
                continue
            seen.add(key)
            facts.append(
                {
                    "project": project,
                    "finding_class": ledger.LIFECYCLE,
                    "subject": event_type,
                    "scope": versions,
                }
            )
    return facts
