"""openpulse CLI — validate + pulse + analyze + demo-bitnami."""

import json

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
    click.echo(
        f"OK {e.id} [{e.event_type.value}] confidence={e.confidence.value} impact={e.impact.value}"
    )
    if violations:
        click.echo("GATE VIOLATIONS:")
        for v in violations:
            click.echo(f"  - {v}")
        if strict:
            raise SystemExit(1)
    else:
        click.echo("gate: PASS")


@cli.command()
@click.option("--project", required=True)
@click.option("--show-signals", is_flag=True)
def pulse(project, show_signals):
    slug = resolve_project(project)
    click.echo(f"{slug}")
    if show_signals:
        click.echo("Activity 🟢  Security 🟢  Lifecycle 🟢  Support 🟢")
        click.echo("Licence 🟢  Distribution 🟢  Popularity 🟢")
        click.echo("(v0.1 stub — wire collectors in Phase 1)")


def _live_bundle(slug):
    """Run live collectors; each degrades to error/skipped dicts, never raises."""
    from collectors.endoflife.collector import EndoflifeCollector
    from collectors.github.collector import GitHubCollector
    from collectors.kev.collector import KEVCollector
    from collectors.nvd.collector import NVDCollector
    from collectors.registries.docker import RegistryCollector
    from core.entities.catalog import load_catalog

    repo_map = {e["slug"]: e["github"] for e in load_catalog() if e.get("github")}
    github = GitHubCollector(repo_map)
    return {
        "endoflife": EndoflifeCollector().collect(slug),
        "github": github.collect(slug),
        "github_meta": [github.fetch_repo_meta(slug)],
        "nvd": NVDCollector().collect(slug),
        "kev": KEVCollector().collect(slug),
        "registries": RegistryCollector().collect(slug),
    }


@cli.command()
@click.option("--project", required=True, help="Project slug or artifact ref")
@click.option(
    "--raw-bundle", type=click.Path(exists=True), help="Offline raw collector bundle JSON"
)
def analyze(project, raw_bundle):
    """Run analysts over live collectors (or an offline bundle) and print findings."""
    slug = resolve_project(project)
    if raw_bundle:
        raw = _load_json(raw_bundle)
        click.echo(f"bundle: {raw_bundle}")
    else:
        raw = _live_bundle(slug)
        for name, entries in raw.items():
            problems = [e for e in entries if e.get("error") or e.get("skipped")]
            click.echo(f"collector {name}: {len(entries)} records ({len(problems)} error/skipped)")
    change = change_analyst.analyze(raw)
    from core.entities.catalog import project_context

    security = security_analyst.correlate(raw, project_context(slug))
    click.echo(f"\n## Change findings ({len(change)})")
    for finding in change:
        click.echo("\n" + report_analyst.render_finding_md(finding))
    click.echo(f"\n## Security findings ({len(security)})")
    for finding in security[:10]:
        click.echo("\n" + report_analyst.render_finding_md(finding))
    click.echo("\nnote: findings are proposals — Evidence Analyst + gate decide events.")


@cli.command(name="demo-bitnami")
def demo_bitnami():
    """Offline north-star demo: Bitnami event -> gate -> who is affected -> report."""
    from core.evidence.policy import gate
    from core.risk.match import event_affects_ref

    event = _load_event("data/fixtures/bitnami/event.json")
    violations = gate(event)
    click.echo(f"event: {event.id} [{event.event_type.value}]")
    click.echo(f"confidence={event.confidence.value} impact={event.impact.value}")
    click.echo(f"gate: {'PASS' if not violations else violations}")
    watchlist = [
        "docker.io/bitnami/redis:7.2",
        "docker.io/bitnami/postgresql:16",
        "docker.io/bitnamilegacy/redis:7.2",
        "docker.io/redis:7.2",
        "postgres:16",
        "nginx:latest",
    ]
    click.echo("\n## Impact on sample watchlist")
    for ref in watchlist:
        result = event_affects_ref(event, ref)
        icon = "🚨" if result["affected"] else "✅"
        click.echo(f"{icon} {ref}: {result['detail']}")
    click.echo("\n" + report_analyst.render_event_md(event))


@cli.command()
@click.option("--namespace", required=True, help="Registry namespace (e.g. bitnami)")
@click.option("--repo", "repository", required=True, help="Repository (e.g. redis)")
@click.option("--store", default=".openpulse/observations", help="History root directory")
def observe(namespace, repository, store):
    """Probe a Docker Hub repo, persist the observation, diff against history."""
    from collectors.registries.docker import RegistryCollector
    from core.observations.registry import diff_observations, to_observation
    from core.observations.store import load_previous, save_observation

    probe = RegistryCollector().check_image(namespace, repository)
    if probe.get("error"):
        click.echo(f"error: {probe.get('safe_message')} (category={probe.get('category')})")
        raise SystemExit(1)
    current = to_observation(probe)
    previous_raw = load_previous("docker.io", namespace, repository, root=store)
    from core.observations.registry import RegistryObservation

    previous = RegistryObservation(**previous_raw) if previous_raw else None
    changes = diff_observations(previous, current)
    path = save_observation(current.model_dump(mode="json"), root=store)
    click.echo(f"saved: {path}")
    if previous is None:
        click.echo("baseline recorded — no previous observation, no change claims.")
        return
    if not changes:
        click.echo("no changes since last observation.")
        return
    for change in changes:
        click.echo(f"- {change.type}: {change.tag or ''} {change.previous} -> {change.current}")
    for finding in change_analyst.analyze_diffs([c.model_dump(mode="json") for c in changes]):
        click.echo("\n" + report_analyst.render_finding_md(finding))
