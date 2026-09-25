"""openpulse CLI — v0.1 minimal: validate + pulse."""
import json
import click
from core.schema.models import OSSEvent
from core.entities.resolve import resolve_project

@click.group()
def cli():
    pass

@cli.command()
@click.option("--event", required=True, help="Path to OSSEvent JSON fixture")
def validate(event):
    data = json.load(open(event))
    e = OSSEvent(**data)
    click.echo(f"OK {e.id} [{e.event_type}] confidence={e.confidence} impact={e.impact}")

@cli.command()
@click.option("--project", required=True)
@click.option("--show-signals", is_flag=True)
def pulse(project):
    slug = resolve_project(project)
    click.echo(f"{slug}")
    if show_signals:
        click.echo("Activity 🟢  Security 🟢  Lifecycle 🟢  Support 🟢  Licence 🟢  Distribution 🟢  Popularity 🟢")
        click.echo("(v0.1 stub — wire collectors in Phase 1)")
