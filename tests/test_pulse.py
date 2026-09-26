"""OSS Pulse tests: facet mapping, worst-wins, activity, golden output."""

import json
from datetime import date


def test_empty_pulse_is_all_ok():
    from core.pulse import compute_pulse

    pulse = compute_pulse("redis")
    assert all(info["status"] == "ok" for info in pulse["facets"].values())
    assert pulse["summary"] == {"ok": 7, "watch": 0, "review": 0, "action": 0}


def test_lifecycle_action_from_eol_finding():
    from analyzers.change_analyst import analyze_endoflife
    from core.pulse import compute_pulse

    raw = [
        {
            "collector": "endoflife",
            "product": "redis",
            "cycle": "6.2",
            "eol": "2024-01-01",
            "support": "2023-01-01",
        }
    ]
    findings = analyze_endoflife(raw, today=date(2026, 9, 26))
    pulse = compute_pulse("redis", findings=findings)
    assert pulse["facets"]["lifecycle"]["status"] == "action"
    assert "6.2" in pulse["facets"]["lifecycle"]["reason"]
    assert pulse["facets"]["security"]["status"] == "ok"


def test_worst_wins_and_reason_kept():
    from core.pulse import compute_pulse

    findings = [
        {
            "analyst": "change",
            "event_type": "DISTRIBUTION_CHANGE",
            "impact": "WATCH",
            "title": "latest-only",
        },
        {
            "analyst": "change",
            "event_type": "DISTRIBUTION_CHANGE",
            "impact": "ACTION",
            "title": "moved to legacy",
        },
    ]
    pulse = compute_pulse("bitnami", findings=findings)
    assert pulse["facets"]["distribution"] == {"status": "action", "reason": "moved to legacy"}


def test_security_maps_to_security_facet():
    from core.pulse import compute_pulse

    findings = [
        {
            "analyst": "security",
            "cve_id": "CVE-1",
            "event_type": "SECURITY",
            "impact": "CRITICAL",
            "title": "x",
        }
    ]
    assert compute_pulse("redis", findings=findings)["facets"]["security"]["status"] == "action"


def test_activity_archived_is_action():
    from core.pulse import compute_pulse

    activity = {"repo_meta": {"repo": "o/r", "archived": True}, "releases": []}
    pulse = compute_pulse("o", activity=activity)
    assert pulse["facets"]["activity"]["status"] == "action"


def test_activity_stale_releases_is_review():
    from core.pulse import compute_pulse

    activity = {
        "releases": [{"published_at": "2020-01-01T00:00:00Z"}],
        "repo_meta": {"archived": False},
    }
    pulse = compute_pulse("o", activity=activity, today=date(2026, 9, 26))
    assert pulse["facets"]["activity"]["status"] == "review"


def test_popularity_never_red():
    from core.pulse import compute_pulse

    assert compute_pulse("x")["facets"]["popularity"]["status"] == "ok"


def test_golden_redis_bundle():
    from analyzers.change_analyst import analyze
    from core.pulse import compute_pulse, format_pulse

    raw = json.load(open("data/fixtures/redis/raw_bundle.json"))
    findings = analyze(raw)
    pulse = compute_pulse(
        "redis",
        findings=findings,
        activity={"releases": raw["github"], "repo_meta": raw["github_meta"][0]},
        today=date(2026, 9, 26),
    )
    assert pulse["facets"]["lifecycle"]["status"] == "action"
    assert pulse["facets"]["activity"]["status"] == "ok"
    assert pulse["summary"]["action"] == 1
    text = format_pulse(pulse)
    assert text.startswith("redis\n")
    assert "Lifecycle 🔴 action" in text


def test_pulse_cli_offline():
    from click.testing import CliRunner

    from cli.main import cli

    result = CliRunner().invoke(
        cli, ["pulse", "--project", "redis", "--raw-bundle", "data/fixtures/redis/raw_bundle.json"]
    )
    assert result.exit_code == 0, result.output
    assert "Lifecycle 🔴 action" in result.output
