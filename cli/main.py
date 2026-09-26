"""openpulse CLI — validate + pulse + analyze + demo-bitnami."""

import json

import click

from analyzers import change_analyst, report_analyst, security_analyst
from core.entities.resolve import resolve_project
from core.schema.models import OSSEvent


@click.group()
def cli():
    pass


@cli.command()
@click.option("--event", required=True, help="Path to OSSEvent JSON fixture")
@click.option("--strict", is_flag=True, help="Fail if evidence gate violations exist")
def validate(event, strict):
    data = json.load(open(event))
    e = OSSEvent(**data)
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
    return {
        "endoflife": EndoflifeCollector().collect(slug),
        "github": GitHubCollector(repo_map).collect(slug),
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
        with open(raw_bundle, encoding="utf-8") as f:
            raw = json.load(f)
        click.echo(f"bundle: {raw_bundle}")
    else:
        raw = _live_bundle(slug)
        for name, entries in raw.items():
            problems = [e for e in entries if e.get("error") or e.get("skipped")]
            click.echo(f"collector {name}: {len(entries)} records ({len(problems)} error/skipped)")
    change = change_analyst.analyze(raw)
    security = security_analyst.correlate(raw)
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

    with open("data/fixtures/bitnami/event.json", encoding="utf-8") as f:
        event = OSSEvent(**json.load(f))
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
