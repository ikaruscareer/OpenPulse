"""Change Analyst — lifecycle/distribution signals from raw collector output.

Pure functions: no network, deterministic. Consumes the raw dicts
produced by collectors (endoflife, registries, github) and emits
finding dicts. Findings are *proposals* — the Evidence Analyst and
the gate in core/evidence/policy.py decide what becomes an OSSEvent.
"""

from __future__ import annotations

from datetime import date
from typing import Any

EOL_WARN_DAYS = 180


def _parse_date(value: Any) -> date | None:
    if value is True:
        return date.min  # endoflife.date uses `true` for "already EOL"
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def analyze_endoflife(
    entries: list[dict[str, Any]], today: date | None = None
) -> list[dict[str, Any]]:
    """Map endoflife.date cycles to EOL/EOS findings."""
    today = today or date.today()
    findings = []
    for e in entries:
        if e.get("error") or e.get("skipped"):
            continue
        cycle, product = e.get("cycle"), e.get("product", "?")
        eol = _parse_date(e.get("eol"))
        if eol is not None and eol <= today:
            findings.append(
                {
                    "analyst": "change",
                    "event_type": "EOL",
                    "signal": "lifecycle",
                    "title": f"{product} {cycle} is end-of-life",
                    "summary": f"Cycle {cycle} reached EOL on {e.get('eol')}; "
                    "no further fixes. Plan upgrade or extended support.",
                    "impact": "ACTION",
                    "affected_versions": [str(cycle)],
                    "affected_artifacts": [],
                    "supporting": [e],
                }
            )
            continue
        if eol is not None and (eol - today).days <= EOL_WARN_DAYS:
            findings.append(
                {
                    "analyst": "change",
                    "event_type": "EOL",
                    "signal": "lifecycle",
                    "title": f"{product} {cycle} EOL approaching ({e.get('eol')})",
                    "summary": f"Cycle {cycle} ends in {(eol - today).days} days. "
                    "Start migration planning now.",
                    "impact": "REVIEW",
                    "affected_versions": [str(cycle)],
                    "affected_artifacts": [],
                    "supporting": [e],
                }
            )
        support = _parse_date(e.get("support"))
        if support is not None and support <= today:
            findings.append(
                {
                    "analyst": "change",
                    "event_type": "EOS",
                    "signal": "support",
                    "title": f"{product} {cycle} ended active support",
                    "summary": f"Active support for cycle {cycle} ended "
                    f"({e.get('support')}); only security fixes, if any.",
                    "impact": "REVIEW",
                    "affected_versions": [str(cycle)],
                    "affected_artifacts": [],
                    "supporting": [e],
                }
            )
    return findings


def analyze_registries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map registry probes to distribution findings.

    Bitnami pattern: mainline latest-only + legacy holding versioned
    tags == versioned distribution moved behind a new model.
    """
    by_repo = {
        (e.get("namespace"), e.get("repo")): e
        for e in entries
        if not e.get("error") and e.get("repo")
    }
    findings = []
    main = by_repo.get(("bitnami", "redis"))
    legacy = by_repo.get(("bitnamilegacy", "redis"))
    if main and main.get("latest_only") and legacy and legacy.get("has_versioned_tags"):
        findings.append(
            {
                "analyst": "change",
                "event_type": "DISTRIBUTION_CHANGE",
                "signal": "distribution",
                "title": "Bitnami mainline is latest-only; versioned tags live in legacy",
                "summary": "docker.io/bitnami serves only `latest` while "
                "docker.io/bitnamilegacy holds versioned tags with no updates. "
                "Pinned bitnami/* references need a migration plan.",
                "impact": "ACTION",
                "affected_versions": ["*"],
                "affected_artifacts": [
                    {"kind": "docker-image", "ref": "docker.io/bitnami/redis:<version>"},
                    {"kind": "docker-image", "ref": "docker.io/bitnamilegacy/redis:<version>"},
                ],
                "supporting": [main, legacy],
            }
        )
        return findings
    for (ns, repo), e in by_repo.items():
        if e.get("latest_only"):
            findings.append(
                {
                    "analyst": "change",
                    "event_type": "DISTRIBUTION_CHANGE",
                    "signal": "distribution",
                    "title": f"{ns}/{repo} publishes latest-only tags",
                    "summary": "Only the `latest` tag is published; version "
                    "pinning is impossible. Avoid in production.",
                    "impact": "WATCH",
                    "affected_versions": ["*"],
                    "affected_artifacts": [
                        {"kind": "docker-image", "ref": f"docker.io/{ns}/{repo}:<version>"}
                    ],
                    "supporting": [e],
                }
            )
        if e.get("missing"):
            findings.append(
                {
                    "analyst": "change",
                    "event_type": "REGISTRY_CHANGE",
                    "signal": "distribution",
                    "title": f"{ns}/{repo} missing from registry",
                    "summary": "Repository not found — possible removal or rename. "
                    "Verify pulls and mirrors.",
                    "impact": "REVIEW",
                    "affected_versions": ["*"],
                    "affected_artifacts": [
                        {"kind": "docker-image", "ref": f"docker.io/{ns}/{repo}"}
                    ],
                    "supporting": [e],
                }
            )
    return findings


def analyze(raw: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Run all change rules over a raw collector bundle."""
    findings = analyze_endoflife(raw.get("endoflife", []))
    findings += analyze_registries(raw.get("registries", []))
    return findings
