"""openpulse CLI — v0.1 minimal: validate + pulse."""

import json

import click

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
