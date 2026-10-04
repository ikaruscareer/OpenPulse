"""openpulse CLI — validate + pulse + analyze + demo-bitnami."""

import json
import sys
from typing import Any

import click

from analyzers import change_analyst, report_analyst, security_analyst
from core.entities.resolve import resolve_project
from core.schema.models import OSSEvent


@click.group()
def cli():
    pass


MAX_INPUT_BYTES = 1_000_000
MAX_EVIDENCES = 100
MAX_ARTIFACTS = 500


def _load_json(path: str) -> dict:
    """Bounded JSON load: size cap + clean errors (no tracebacks to users)."""
    try:
        size = __import__("os").path.getsize(path)
    except OSError as e:
        raise click.ClickException(f"cannot read {path}: {e.strerror or e}")
    if size > MAX_INPUT_BYTES:
        raise click.ClickException(f"{path} is {size} bytes (limit {MAX_INPUT_BYTES})")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise click.ClickException(f"{path} is not valid JSON: {e}")
    except UnicodeDecodeError:
        raise click.ClickException(f"{path} is not UTF-8 text")


def _load_event(path: str) -> OSSEvent:
    from pydantic import ValidationError

    data = _load_json(path)
    if isinstance(data, dict):
        if len(data.get("evidences", [])) > MAX_EVIDENCES:
            raise click.ClickException(f"too many evidences (limit {MAX_EVIDENCES})")
        if len(data.get("affected_artifacts", [])) > MAX_ARTIFACTS:
            raise click.ClickException(f"too many artifacts (limit {MAX_ARTIFACTS})")
    try:
        return OSSEvent(**data)
    except ValidationError as e:
        first = e.errors()[0]
        loc = ".".join(str(p) for p in first["loc"])
        raise click.ClickException(f"{path} fails schema at `{loc}`: {first['msg']}")


@cli.command()
@click.option("--event", required=True, help="Path to OSSEvent JSON fixture")
@click.option("--strict", is_flag=True, help="Fail if evidence gate violations exist")
def validate(event, strict):
    e = _load_event(event)
    from core.evidence.policy import gate

    violations = gate(e)
    _echo(
        f"OK {e.id} [{e.event_type.value}] confidence={e.confidence.value} impact={e.impact.value}"
    )
    if violations:
        _echo("GATE VIOLATIONS:")
        for v in violations:
            _echo(f"  - {v}")
        if strict:
            raise SystemExit(1)
    else:
        _echo("gate: PASS")


@cli.command()
@click.option("--project", required=True, help="Project slug or artifact ref")
@click.option("--show-signals", is_flag=True, help="Show facet signals (always shown)")
@click.option(
    "--raw-bundle", type=click.Path(exists=True), help="Offline raw collector bundle JSON"
)
def pulse(project, show_signals, raw_bundle):
    """OSS Pulse: computed facet status for one project (live or offline bundle)."""
    from core.entities.catalog import project_context
    from core.pulse import compute_pulse, format_pulse

    slug = resolve_project(project)
    if raw_bundle:
        raw = _load_json(raw_bundle)
    else:
        raw = _live_bundle(slug)
    findings = change_analyst.analyze(raw)
    findings += security_analyst.correlate(raw, project_context(slug))
    metas = [e for e in raw.get("github_meta", []) if e.get("kind") == "repo_meta"]
    activity = {"releases": raw.get("github", []), "repo_meta": metas[0] if metas else None}
    _echo(format_pulse(compute_pulse(slug, findings=findings, activity=activity)))


def _live_bundle(slug):
    """Run live collectors; each degrades to error/skipped dicts, never raises."""
    import os as _os

    from collectors.endoflife.collector import EndoflifeCollector
    from collectors.github.collector import GitHubCollector
    from collectors.kev.collector import KEVCollector
    from collectors.nvd.collector import NVDCollector
    from collectors.osv.collector import OSVCollector
    from collectors.registries.docker import RegistryCollector
    from collectors.registries.reference import bitnami_distribution_probes
    from core.entities.catalog import endoflife_map, load_catalog, osv_map

    token = _os.environ.get("GITHUB_TOKEN") or _os.environ.get("GH_TOKEN")
    repo_map = {e["slug"]: e["github"] for e in load_catalog() if e.get("github")}
    github = GitHubCollector(repo_map, token=token)
    registries = RegistryCollector()
    endoflife = EndoflifeCollector(endoflife_map())
    osv = OSVCollector(osv_map())
    return {
        "endoflife": endoflife.collect(slug),
        "github": github.collect(slug),
        "github_meta": [github.fetch_repo_meta(slug)],
        "nvd": NVDCollector().collect(slug),
        "kev": KEVCollector().collect(slug),
        "osv": osv.collect(slug),
        # Bitnami is a rehearsed reference scenario, not generic acquisition.
        "registries": bitnami_distribution_probes(registries)
        if slug == "bitnami"
        else registries.collect(slug),
    }


@cli.command()
@click.option("--project", required=True, help="Project slug or artifact ref")
@click.option(
    "--raw-bundle", type=click.Path(exists=True), help="Offline raw collector bundle JSON"
)
@click.option(
    "--version",
    "project_version",
    default=None,
    help="Deployed version (enables version-applicability checks)",
)
def analyze(project, raw_bundle, project_version):
    """Run analysts over live collectors (or an offline bundle) and print findings."""
    slug = resolve_project(project)
    if raw_bundle:
        raw = _load_json(raw_bundle)
        _echo(f"bundle: {raw_bundle}")
    else:
        raw = _live_bundle(slug)
        for name, entries in raw.items():
            problems = [e for e in entries if e.get("error") or e.get("skipped")]
            _echo(f"collector {name}: {len(entries)} records ({len(problems)} error/skipped)")
    change = change_analyst.analyze(raw)
    from core.entities.catalog import project_context

    context = project_context(slug)
    if project_version:
        context["version"] = project_version
    security = security_analyst.correlate(raw, context)
    _echo(f"\n## Change findings ({len(change)})")
    for finding in change:
        _echo("\n" + report_analyst.render_finding_md(finding))
    _echo(f"\n## Security findings ({len(security)})")
    for finding in security[:10]:
        _echo("\n" + report_analyst.render_finding_md(finding))
    _echo("\nnote: findings are proposals — Evidence Analyst + gate decide events.")


@cli.command(name="demo-bitnami")
def demo_bitnami():
    """Offline north-star demo: Bitnami event -> gate -> who is affected -> report."""
    from core.evidence.policy import gate
    from core.risk.match import event_affects_ref

    event = _load_event("data/fixtures/bitnami/event.json")
    violations = gate(event)
    _echo(
        "(Historical replay: recorded August 2025 distribution event; "
        "live registry state may have moved on.)"
    )
    _echo(f"event: {event.id} [{event.event_type.value}]")
    _echo(f"confidence={event.confidence.value} impact={event.impact.value}")
    _echo(f"gate: {'PASS' if not violations else violations}")
    watchlist = [
        "docker.io/bitnami/redis:7.2",
        "docker.io/bitnami/postgresql:16",
        "docker.io/bitnamilegacy/redis:7.2",
        "docker.io/redis:7.2",
        "postgres:16",
        "nginx:latest",
    ]
    _echo("\n## Impact on sample watchlist")
    for ref in watchlist:
        result = event_affects_ref(event, ref)
        icon = "🚨" if result["affected"] else "✅"
        _echo(f"{icon} {ref}: [{result['relationship']}] {result['detail']}")
    _echo("\n" + report_analyst.render_event_md(event))


@cli.command()
@click.option("--namespace", required=True, help="Registry namespace (e.g. bitnami)")
@click.option("--repo", "repository", required=True, help="Repository (e.g. redis)")
@click.option("--store", default=".openpulse/observations", help="History root directory")
def observe(namespace, repository, store):
    """Probe a Docker Hub repo, persist the observation, diff against history."""
    from collectors.registries.docker import RegistryCollector
    from core.observations.sweep import observe_repository

    probe = RegistryCollector().check_image(namespace, repository)
    if probe.get("error"):
        _echo(f"error: {probe.get('safe_message')} (category={probe.get('category')})")
        raise SystemExit(1)
    result = observe_repository("docker.io", namespace, repository, probe, store_root=store)
    if result["error"] is not None:
        _echo(
            f"error: {result['error'].get('safe_message')} "
            f"(category={result['error'].get('category')})"
        )
        raise SystemExit(1)
    _echo(f"saved: {result['saved_path']}")
    if result["history_status"] == "GENESIS":
        _echo("baseline recorded — no previous observation, no change claims.")
        return
    if not result["changes"]:
        _echo("no changes since last observation.")
        return
    for change in result["changes"]:
        _echo(
            f"- {change['type']}: {change.get('tag') or ''} "
            f"{change.get('previous')} -> {change.get('current')}"
        )
    for finding in change_analyst.analyze_diffs(result["changes"]):
        _echo("\n" + report_analyst.render_finding_md(finding))


@cli.command()
@click.option("--month", required=True, help="Report month, e.g. 2026-09")
@click.option("--projects", default="", help="Comma-separated slugs (default: whole catalog)")
@click.option(
    "--raw-bundle-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Offline {slug}.json bundles",
)
@click.option("--out", default="", help="Output path (default reports/{month}-openpulse.md)")
@click.option("--since", default="", help="Recency floor for dated findings (YYYY-MM-DD)")
@click.option("--include-related", is_flag=True, help="Narrate RELATED findings too")
@click.option(
    "--with-sweep",
    is_flag=True,
    help="Run live distribution sweep first and include its findings",
)
@click.option("--store", default=".openpulse/observations", help="History root for --with-sweep")
@click.option(
    "--ledger",
    "ledger_root",
    default=".openpulse/detections",
    show_default=True,
    help="Durable detection ledger root ('' disables; feeds first_detected_at in findings)",
)
@click.option(
    "--metadata-out",
    default="",
    help="Metadata JSON path (default: <out> with .meta.json extension)",
)
def report(
    month,
    projects,
    raw_bundle_dir,
    out,
    since,
    include_related,
    with_sweep,
    store,
    ledger_root,
    metadata_out,
):
    """Monthly OSS Dependency Risk Report over seed projects."""
    import json as _json
    from pathlib import Path as _Path

    from core.entities.catalog import load_catalog
    from reports.generate import (
        build_report,
        build_report_metadata,
        collect_project,
        prepare_report,
    )

    slugs = [s.strip() for s in projects.split(",") if s.strip()] or [
        e["slug"] for e in load_catalog()
    ]
    items = []
    for slug in slugs:
        raw = None
        if raw_bundle_dir:
            bundle = _Path(raw_bundle_dir) / f"{slug}.json"
            if bundle.exists():
                raw = _json.loads(bundle.read_text(encoding="utf-8"))
        if raw is None:
            if raw_bundle_dir:
                _echo(f"skip {slug}: no bundle in {raw_bundle_dir}")
                continue
            raw = _live_bundle(slug)
        items.append(collect_project(slug, raw))
    import os

    sweep_findings: list = []
    if with_sweep:
        from collectors.registries.docker import RegistryCollector
        from core.entities.catalog import load_catalog as _load_catalog
        from core.observations.sweep import sweep_catalog

        catalog = _load_catalog()
        wanted = set(slugs)
        selected = [e for e in catalog if e.get("slug") in wanted]
        _echo("running distribution sweep...")
        sweep_findings = sweep_catalog(selected, RegistryCollector().check_image, store_root=store)[
            "findings"
        ]
        _echo(f"sweep findings: {len(sweep_findings)}")
    notes = [
        "Collectors: endoflife.date, GitHub releases + repo metadata, NVD, CISA KEV, Docker Hub.",
        "GitHub calls authenticated (5000 req/hr budget)."
        if (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
        else "GitHub calls unauthenticated (60 req/hr budget); some repos may show gaps.",
        "NVD queried without API key (5 req/30s); misses degrade to gaps, not findings.",
        "Keyword-associated CVE records without identity evidence are held back, not narrated.",
        "Public intelligence describes project-level change; whether it affects "
        "YOUR dependencies needs a watchlist (`openpulse check`).",
    ]
    markdown = build_report(
        month,
        items,
        since=since or None,
        include_related=include_related,
        notes=notes,
        sweep_findings=sweep_findings,
        ledger_root=ledger_root or None,
    )
    destination = out or f"reports/{month}-openpulse.md"
    _Path(destination).write_text(markdown + "\n", encoding="utf-8")
    _echo(f"wrote {destination} ({len(items)} projects)")
    prepared = prepare_report(
        items,
        sweep_findings,
        since=since or None,
        include_related=include_related,
        ledger_root=ledger_root or None,
    )
    metadata = build_report_metadata(
        month,
        items,
        prepared["pairs"],
        prepared["historical"],
        sweep_included=bool(with_sweep),
    )
    meta_destination = metadata_out or (str(destination).removesuffix(".md") + ".meta.json")
    _Path(meta_destination).write_text(_json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    _echo(f"wrote {meta_destination}")


@cli.command(name="lifecycle-report")
@click.option("--month", required=True, help="Report month, e.g. 2026-09")
@click.option("--projects", default="", help="Comma-separated slugs (default: whole catalog)")
@click.option(
    "--raw-bundle-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Offline {slug}.json bundles",
)
@click.option("--out", default="", help="Output path (default reports/lifecycle-{month}.md)")
def lifecycle_report(month, projects, raw_bundle_dir, out):
    """Lifecycle posture and planning view over seed projects."""
    import json as _json
    from pathlib import Path as _Path

    from core.entities.catalog import endoflife_map, load_catalog
    from reports.lifecycle import build_lifecycle_report, collect_lifecycle_status

    slugs = [s.strip() for s in projects.split(",") if s.strip()] or [
        e["slug"] for e in load_catalog()
    ]
    live_collector = None
    statuses = []
    for slug in slugs:
        raw = None
        if raw_bundle_dir:
            bundle = _Path(raw_bundle_dir) / f"{slug}.json"
            if bundle.exists():
                raw = _json.loads(bundle.read_text(encoding="utf-8"))
        if raw is None:
            if raw_bundle_dir:
                _echo(f"skip {slug}: no bundle in {raw_bundle_dir}")
                continue
            if live_collector is None:
                from collectors.endoflife.collector import EndoflifeCollector

                live_collector = EndoflifeCollector(endoflife_map())
            raw = {"endoflife": live_collector.collect(slug)}
        statuses.append(collect_lifecycle_status(slug, raw))
    markdown = build_lifecycle_report(month, statuses)
    destination = out or f"reports/lifecycle-{month}.md"
    _Path(destination).write_text(markdown + "\n", encoding="utf-8")
    _echo(f"wrote {destination} ({len(statuses)} projects)")


def _load_yaml(path: str) -> dict:
    """Bounded YAML load with clean errors (mirrors _load_json)."""
    import os as _os

    import yaml as _yaml

    try:
        size = _os.path.getsize(path)
    except OSError as e:
        raise click.ClickException(f"cannot read {path}: {e.strerror or e}")
    if size > MAX_INPUT_BYTES:
        raise click.ClickException(f"{path} is {size} bytes (limit {MAX_INPUT_BYTES})")
    try:
        with open(path, encoding="utf-8") as f:
            data = _yaml.safe_load(f)
    except _yaml.YAMLError as e:
        raise click.ClickException(f"{path} is not valid YAML: {e}")
    except UnicodeDecodeError:
        raise click.ClickException(f"{path} is not UTF-8 text")
    if not isinstance(data, dict):
        raise click.ClickException(f"{path} must contain a mapping")
    return data


_GLYPH_FALLBACKS = {
    "🚨": "[affected]",
    "✅": "[ok]",
    "ℹ️": "[related]",
    "ℹ": "[related]",
    "❓": "[unknown]",
    # facet status symbols (core.pulse.SYMBOL)
    "🟢": "[ok]",
    "🟡": "[watch]",
    "🟠": "[review]",
    "🔴": "[action]",
    # impact badges (analyzers.report_analyst.BADGE) + the unknown-impact dot
    "⚪": "[unknown]",
}


def _safe_text(text: Any, stream: Any = None) -> str:
    """Format text safely for output streams that cannot encode unicode glyphs."""
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    target = stream or sys.stdout
    encoding = (
        getattr(target, "encoding", None) or getattr(sys.__stdout__, "encoding", None) or "utf-8"
    )
    try:
        text.encode(encoding)
        return text
    except (UnicodeEncodeError, LookupError):
        pass

    out = text
    for glyph, ascii_marker in _GLYPH_FALLBACKS.items():
        out = out.replace(glyph, ascii_marker)
    try:
        out.encode(encoding)
        return out
    except (UnicodeEncodeError, LookupError):
        out = out.replace("—", "-").replace("–", "-")
    try:
        out.encode(encoding)
        return out
    except (UnicodeEncodeError, LookupError):
        return out.encode(encoding, errors="replace").decode(encoding)


def _echo(msg: Any = "", **kwargs: Any) -> None:
    """Echo helper falling back to ASCII markers when the stream cannot encode glyphs."""
    file = kwargs.get("file")
    stream = file or (sys.stderr if kwargs.get("err") else sys.stdout)
    click.echo(_safe_text(msg, stream=stream), **kwargs)


@cli.command()
@click.option(
    "--watchlist", required=True, type=click.Path(exists=True), help="Watchlist YAML file"
)
@click.option(
    "--event",
    "events",
    multiple=True,
    type=click.Path(exists=True),
    help="Intelligence event JSON (repeatable)",
)
@click.option(
    "--raw-bundle-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Offline {slug}.json bundles for version checks",
)
@click.option("--strict", is_flag=True, help="Exit 1 when any dependency is affected")
@click.option(
    "--ledger",
    "ledger_root",
    default=".openpulse/detections",
    show_default=True,
    help="Durable first-detection ledger root (recording is the default; '' disables)",
)
@click.option(
    "--digest",
    is_flag=True,
    help="Print grouped digest instead of per-dependency lines (cron-friendly)",
)
@click.option(
    "--webhook",
    default="",
    help="POST the digest markdown to a JSON-text webhook (e.g. Slack incoming)",
)
@click.option(
    "--webhook-allow-http",
    is_flag=True,
    help="Opt in to plain-http webhooks (https is required by default)",
)
def check(
    watchlist, events, raw_bundle_dir, ledger_root, strict, digest, webhook, webhook_allow_http
):
    """Dependency Early Warning: evaluate a watchlist against events."""
    import json as _json
    from pathlib import Path as _Path

    from core.entities.resolve import resolve_project as _resolve
    from core.risk.check import check_dependency, load_watchlist_doc

    try:
        deps = load_watchlist_doc(_load_yaml(watchlist))
    except ValueError as e:
        raise click.ClickException(f"{watchlist}: {e}")
    loaded_events = [_load_event(path) for path in events]
    bundles = {}
    if raw_bundle_dir:
        for dep in deps:
            if dep["kind"] != "package":
                continue
            slug = _resolve(dep["package"])
            bundle = _Path(raw_bundle_dir) / f"{slug}.json"
            if bundle.exists():
                bundles[slug] = _json.loads(bundle.read_text(encoding="utf-8"))
    affected = 0
    # A flag, not a subcommand: digest is a presentation of the same run,
    # so --strict semantics stay identical in both shapes.
    results = [check_dependency(dep, loaded_events, bundles) for dep in deps]
    # Durable detection ledger: an empty --ledger value disables it
    # (per-run behavior, exactly like today); anything else is the root.
    if ledger_root:
        from core.detections.ledger import first_seen, record_detection
        from core.risk.check import detections_from_verdicts

        for fact in detections_from_verdicts(results, loaded_events):
            record_detection(
                fact["project"],
                fact["finding_class"],
                fact["subject"],
                scope=fact["scope"],
                root=ledger_root,
            )
        for result in results:
            # Earliest across ALL of this verdict's recorded facts, not
            # the first recorded fact: a dependency can carry a fresh
            # lifecycle cause and a security record detected days earlier
            # (lifecycle causes are appended before security ones), and
            # the reported first detection must be the earliest of them.
            earliest = min(
                (
                    seen
                    for fact in detections_from_verdicts([result], loaded_events)
                    if (
                        seen := first_seen(
                            fact["project"],
                            fact["finding_class"],
                            fact["subject"],
                            scope=fact["scope"],
                            root=ledger_root,
                        )
                    )
                ),
                default=None,
            )
            if earliest:
                result.first_detected = str(earliest)[:10]
    if digest or webhook:
        from analyzers.report_analyst import render_check_digest

        text = render_check_digest(results)
        _echo(text)
        if webhook:
            from core.notify import WebhookPolicy, post_digest

            delivery = post_digest(
                webhook, text, policy=WebhookPolicy(allow_http=webhook_allow_http)
            )
            if delivery["ok"]:
                _echo(f"posted digest (http {delivery['status_code']})")
            else:
                # Delivery failure must not mask the check result itself.
                _echo(f"webhook delivery failed: {delivery['error']}")
        affected = sum(1 for r in results if r.affected)
        _echo(f"\n{affected}/{len(deps)} dependencies affected")
        from core.risk.check import strict_affected

        if strict and strict_affected(results):
            raise SystemExit(1)
        return
    for dep, result in zip(deps, results):
        label = dep.get("ref") or f"{dep.get('package')}=={dep.get('version') or '?'}"
        relationship = result.relationship
        if result.affected:
            affected += 1
            first_note = (
                f" · first detected {result.first_detected}" if result.first_detected else ""
            )
            _echo(f"🚨 {label}: AFFECTED ({relationship}){first_note}")
            for verdict in result.verdicts:
                if verdict["affected"]:
                    _echo(f"   - [{verdict['impact']}] {verdict['detail']}")
        elif relationship == "NOT_AFFECTED":
            _echo(f"✅ {label}: NOT_AFFECTED — {result.reason}")
        elif relationship == "RELATED":
            _echo(f"ℹ️ {label}: RELATED — {result.reason}")
        else:
            _echo(f"❓ {label}: UNKNOWN — evaluated, no applicable evidence")
    _echo(f"\n{affected}/{len(deps)} dependencies affected")
    from core.risk.check import strict_affected

    if strict and strict_affected(results):
        raise SystemExit(1)


@cli.command()
@click.option("--store", default=".openpulse/observations", help="History root directory")
@click.option(
    "--projects", default="", help="Comma-separated slugs (default: every image in the catalog)"
)
@click.option("--out", default="", help="Write findings JSON here (default: print only)")
def sweep(store, projects, out):
    """Distribution discovery: probe every catalog image, diff against history."""
    from collectors.registries.docker import RegistryCollector
    from core.entities.catalog import load_catalog
    from core.observations.sweep import sweep_catalog, sweep_targets

    catalog = load_catalog()
    slugs = [s.strip() for s in projects.split(",") if s.strip()] or None
    targets = sweep_targets(catalog)
    _echo(f"probing {len(targets)} catalog images...")
    collector = RegistryCollector()
    result = sweep_catalog(catalog, collector.check_image, store_root=store, slugs=slugs)
    _echo(
        f"observations: {len(result['observations'])}, "
        f"changes: {len(result['changes'])}, "
        f"findings: {len(result['findings'])}, "
        f"errors: {len(result['errors'])}"
    )
    for finding in result["findings"]:
        _echo(f"- [{finding['impact']}] {finding['title']}")
    for error in result["errors"]:
        _echo(f"! {error.get('slug')}: {error.get('safe_message')}")
    if not result["changes"]:
        _echo("no changes since last observations (first sightings are baselines).")
    if out:
        import json as _json
        from pathlib import Path as _Path

        _Path(out).write_text(_json.dumps(result["findings"], indent=2), encoding="utf-8")
        _echo(f"wrote {out}")
