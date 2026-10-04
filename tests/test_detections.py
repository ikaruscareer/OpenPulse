"""Detection ledger tests: durability, concurrency, degradation (#41)."""

import json
import threading

import pytest

from core.detections import ledger
from core.risk.check import (
    check_dependency,
    check_watchlist,
    detections_from_verdicts,
)
from core.schema.models import OSSEvent

LEDGER_ROOT = ".openpulse-test/detections"


@pytest.fixture
def root(tmp_path):
    return tmp_path / "ledger"


@pytest.fixture
def django_eol():
    return OSSEvent(**json.load(open("data/fixtures/django-eol/event.json")))


@pytest.fixture
def bitnami_event():
    return OSSEvent(**json.load(open("data/fixtures/bitnami/event.json")))


def _osv_bundle(version):
    return {
        "osv": [
            {
                "collector": "osv",
                "package": "django",
                "ecosystem": "PyPI",
                "id": "CVE-2026-0100",
                "severity": [{"score": 8.0}],
                "affected": [
                    {
                        "package": "django",
                        "ecosystem": "PyPI",
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "5.1.1"}],
                            }
                        ],
                        "fixed": ["5.1.1"],
                        "versions": [],
                    }
                ],
                "references": [],
            }
        ]
    }


# ---------------------------------------------------------------------------
# Ledger mechanics: stability, earliest-wins, degradation
# ---------------------------------------------------------------------------


def test_two_consecutive_runs_prove_stability(root):
    """First run records; second run reports the original date."""
    first = ledger.record_detection(
        "django", "lifecycle", "EOL", ["4.2"], detected_at="2026-07-01T00:00:00+00:00", root=root
    )
    assert first["recorded_now"] is True
    second = ledger.record_detection(
        "django", "lifecycle", "EOL", ["4.2"], detected_at="2026-10-01T00:00:00+00:00", root=root
    )
    assert second["recorded_now"] is False
    assert second["first_seen"] == "2026-07-01T00:00:00+00:00"
    assert ledger.first_seen("django", "lifecycle", "EOL", ["4.2"], root=root) == (
        "2026-07-01T00:00:00+00:00"
    )


def test_earlier_stamp_wins_both_directions(root):
    """Clock skew: a later stamp never overwrites; an earlier one does."""
    ledger.record_detection(
        "redis", "security", "CVE-1", [], detected_at="2026-09-15T00:00:00+00:00", root=root
    )
    entry = ledger.record_detection(
        "redis", "security", "CVE-1", [], detected_at="2026-08-01T00:00:00+00:00", root=root
    )
    assert entry["first_seen"] == "2026-08-01T00:00:00+00:00"
    entry = ledger.record_detection(
        "redis", "security", "CVE-1", [], detected_at="2026-09-01T00:00:00+00:00", root=root
    )
    assert entry["first_seen"] == "2026-08-01T00:00:00+00:00"
    # last_seen tracks the LATEST sighting (max), independent of first_seen.
    assert entry["last_seen"] == "2026-09-15T00:00:00+00:00"


def test_scope_order_and_case_do_not_split_history(root):
    """Same fact, different scope shapes -> one ledger entry."""
    ledger.record_detection(
        "django",
        "lifecycle",
        "EOL",
        ["4.2", "5.0"],
        detected_at="2026-07-01T00:00:00+00:00",
        root=root,
    )
    entry = ledger.record_detection(
        "django",
        "lifecycle",
        "EOL",
        ["5.0", "4.2"],
        detected_at="2026-09-01T00:00:00+00:00",
        root=root,
    )
    assert entry["recorded_now"] is False
    assert entry["first_seen"] == "2026-07-01T00:00:00+00:00"


def test_concurrent_runs_cannot_corrupt_the_ledger(root):
    """Lock/atomicity: same bar as observation history."""

    def write(i):
        ledger.record_detection(
            "django",
            "lifecycle",
            "EOL",
            ["4.2"],
            detected_at=f"2026-09-01T00:00:{i:02d}+00:00",
            root=root,
        )

    threads = [threading.Thread(target=write, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    firsts = {
        ledger.record_detection(
            "django",
            "lifecycle",
            "EOL",
            ["4.2"],
            detected_at="2026-10-01T00:00:00+00:00",
            root=root,
        )["first_seen"]
    }
    # Every thread's write landed; earliest survived; exactly one entry file.
    assert firsts == {"2026-09-01T00:00:00+00:00"}
    files = list((root / "django").glob("*.json"))
    assert len(files) == 1
    assert json.loads(files[0].read_text(encoding="utf-8"))["first_seen"] == (
        "2026-09-01T00:00:00+00:00"
    )


def test_lock_contention_is_an_error_not_corruption(root):
    """Busy ledger -> TimeoutError; never a silent unlocked write."""
    acquired = threading.Event()

    def holder():
        with ledger.ledger_lock(root, "django", wait_seconds=30):
            acquired.set()
            import time

            time.sleep(0.5)

    thread = threading.Thread(target=holder)
    thread.start()
    assert acquired.wait(timeout=5)
    try:
        with pytest.raises(TimeoutError):
            with ledger.ledger_lock(root, "django", wait_seconds=0.1):
                pass
    finally:
        thread.join()
    assert not (root / "django" / ".ledger-lock").exists()


def test_corrupt_entry_degrades_to_unknown(root):
    """Unreadable ledger -> None (no claim), never an exception."""
    ledger.record_detection(
        "django", "lifecycle", "EOL", ["4.2"], detected_at="2026-07-01T00:00:00+00:00", root=root
    )
    path = root / "django" / (ledger.fact_key("django", "lifecycle", "EOL", ["4.2"]) + ".json")
    path.write_text("{corrupt", encoding="utf-8")
    assert ledger.first_seen("django", "lifecycle", "EOL", ["4.2"], root=root) is None
    # Re-detection over a corrupt entry recovers (writes fresh).
    entry = ledger.record_detection(
        "django", "lifecycle", "EOL", ["4.2"], detected_at="2026-09-01T00:00:00+00:00", root=root
    )
    assert entry["recorded_now"] is True


def test_deleting_the_ledger_degrades_to_no_claims(root):
    """Wiped ledger -> first_seen is None; re-detection starts fresh."""
    ledger.record_detection(
        "django", "lifecycle", "EOL", ["4.2"], detected_at="2026-07-01T00:00:00+00:00", root=root
    )
    for path in (root / "django").glob("*.json"):
        path.unlink()
    assert ledger.first_seen("django", "lifecycle", "EOL", ["4.2"], root=root) is None


def test_hostile_project_name_stays_inside_root(root):
    """Path traversal in project names cannot escape the ledger root."""
    ledger.record_detection("..", "lifecycle", "EOL", ["4.2"], root=root)
    ledger.record_detection("a/b", "lifecycle", "EOL", ["4.2"], root=root)
    inside = [p for p in root.rglob("*.json")]
    assert all(root in p.parents for p in inside)
    assert ledger.first_seen("..", "lifecycle", "EOL", ["4.2"], root=root)


# ---------------------------------------------------------------------------
# Extraction: verdicts -> durable facts (pure)
# ---------------------------------------------------------------------------


def test_lifecycle_fact_extraction_from_verdicts(django_eol):
    dep = {"kind": "package", "package": "django", "ecosystem": "PyPI", "version": "4.2"}
    result = check_dependency(dep, [django_eol])
    facts = detections_from_verdicts([result], [django_eol])
    assert len(facts) == 1
    assert facts[0]["project"] == "django"
    assert facts[0]["finding_class"] == ledger.LIFECYCLE
    assert facts[0]["subject"] == "EOL"
    assert facts[0]["scope"] == ["4.2"]


def test_security_fact_extraction_from_verdicts(django_eol):
    dep = {"kind": "package", "package": "django", "ecosystem": "PyPI", "version": "4.2"}
    bundle = {
        "django": {
            "osv": [
                {
                    "collector": "osv",
                    "package": "django",
                    "ecosystem": "PyPI",
                    "id": "CVE-2026-0100",
                    "severity": [{"score": 8.0}],
                    "affected": [
                        {
                            "package": "django",
                            "ecosystem": "PyPI",
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "5.1.1"},
                                    ],
                                }
                            ],
                            "fixed": ["5.1.1"],
                            "versions": [],
                        }
                    ],
                    "references": [],
                }
            ]
        }
    }
    result = check_dependency(dep, [django_eol], bundle)
    facts = detections_from_verdicts([result], [django_eol])
    security = [f for f in facts if f["finding_class"] == ledger.SECURITY]
    assert len(security) == 1
    assert security[0]["subject"] == "CVE-2026-0100"
    assert security[0]["project"] == "django"


def test_not_affected_and_related_never_record(bitnami_event):
    """Context ties and exclusions start no detection clock."""
    deps = [
        {"kind": "image", "ref": "docker.io/redis:7.2"},  # NOT_AFFECTED
        {"kind": "package", "package": "django", "version": "5.2"},
    ]
    results = check_watchlist(deps, [bitnami_event])
    assert detections_from_verdicts(results, [bitnami_event]) == []


def test_distribution_change_is_not_a_ledger_fact(bitnami_event):
    """Distribution/registry changes keep observation-history detection."""
    dep = {"kind": "image", "ref": "docker.io/bitnami/redis:7.2"}
    result = check_dependency(dep, [bitnami_event])
    assert result.affected is True
    assert detections_from_verdicts([result], [bitnami_event]) == []


# ---------------------------------------------------------------------------
# CLI: two consecutive runs prove stability end-to-end (acceptance)
# ---------------------------------------------------------------------------

_WL_LINES = [
    "version: 1",
    "dependencies:",
    "  - package: django",
    "    ecosystem: PyPI",
    '    version: "4.2"',
]


def _write_watchlist(tmp_path):
    watchlist = tmp_path / "wl.yaml"
    watchlist.write_text("\n".join(_WL_LINES) + "\n", encoding="utf-8")
    return watchlist


def test_check_cli_two_runs_report_original_first_detected(tmp_path, monkeypatch):
    """Acceptance: first run records, second run reports the original date."""
    from click.testing import CliRunner

    from cli.main import cli as _cli

    ledger_root = tmp_path / "ledger"
    watchlist = _write_watchlist(tmp_path)

    def run(now):
        monkeypatch.setattr("core.detections.ledger.now_iso", lambda: now)
        out = CliRunner().invoke(
            _cli,
            [
                "check",
                "--watchlist",
                str(watchlist),
                "--event",
                "data/fixtures/django-eol/event.json",
                "--ledger",
                str(ledger_root),
            ],
        )
        assert out.exit_code == 0, out.output
        return out.output

    first = run("2026-07-01T00:00:00+00:00")
    assert "django==4.2: AFFECTED (AFFECTS_VERSION)" in first, first
    # First run records and reports its own detection day.
    assert "first detected 2026-07-01" in first, first

    second = run("2026-10-01T00:00:00+00:00")
    # Second run reports the ORIGINAL date, not today.
    assert "first detected 2026-07-01" in second, second
    assert "first detected 2026-10-01" not in second


def test_check_cli_ledger_disabled_keeps_per_run_behavior(tmp_path):
    """--ledger '' records nothing and claims nothing (current behavior)."""
    from click.testing import CliRunner

    from cli.main import cli as _cli

    watchlist = _write_watchlist(tmp_path)
    out = CliRunner().invoke(
        _cli,
        [
            "check",
            "--watchlist",
            str(watchlist),
            "--event",
            "data/fixtures/django-eol/event.json",
            "--ledger",
            "",
        ],
    )
    assert out.exit_code == 0, out.output
    assert "django==4.2: AFFECTED" in out.output
    assert "first detected" not in out.output
    assert not (tmp_path / "ledger").exists()


def test_check_cli_digest_carries_first_detected(tmp_path, monkeypatch):
    """Digest shape (cron/webhook) surfaces the first-seen date too."""
    from click.testing import CliRunner

    from cli.main import cli as _cli

    ledger_root = tmp_path / "ledger"
    watchlist = _write_watchlist(tmp_path)

    monkeypatch.setattr("core.detections.ledger.now_iso", lambda: "2026-07-01T00:00:00+00:00")
    first = CliRunner().invoke(
        _cli,
        [
            "check",
            "--watchlist",
            str(watchlist),
            "--event",
            "data/fixtures/django-eol/event.json",
            "--ledger",
            str(ledger_root),
        ],
    )
    assert first.exit_code == 0, first.output

    monkeypatch.setattr("core.detections.ledger.now_iso", lambda: "2026-10-01T00:00:00+00:00")
    second = CliRunner().invoke(
        _cli,
        [
            "check",
            "--watchlist",
            str(watchlist),
            "--event",
            "data/fixtures/django-eol/event.json",
            "--ledger",
            str(ledger_root),
            "--digest",
        ],
    )
    assert second.exit_code == 0, second.output
    assert "first detected 2026-07-01" in second.output


def test_check_cli_records_under_default_dot_openpulse(tmp_path, monkeypatch):
    """Default root .openpulse/detections under the working directory."""
    from pathlib import Path

    from click.testing import CliRunner

    from cli.main import cli as _cli

    watchlist = _write_watchlist(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("core.detections.ledger.now_iso", lambda: "2026-07-01T00:00:00+00:00")
    event_path = (
        Path(__file__).resolve().parent.parent / "data" / "fixtures" / "django-eol" / "event.json"
    )
    out = CliRunner().invoke(
        _cli,
        [
            "check",
            "--watchlist",
            str(watchlist),
            "--event",
            str(event_path),
        ],
    )
    assert out.exit_code == 0, out.output
    ledger_dir = tmp_path / ".openpulse" / "detections" / "django"
    assert ledger_dir.is_dir()
    entries = list(ledger_dir.glob("*.json"))
    assert len(entries) == 1
    payload = json.loads(entries[0].read_text(encoding="utf-8"))
    assert payload["finding_class"] == ledger.LIFECYCLE
    assert payload["subject"] == "EOL"
    assert payload["scope"] == ["4.2"]
    assert payload["first_seen"] == "2026-07-01T00:00:00+00:00"
    # Git-ignored by default: .openpulse/ is already in .gitignore.


def test_check_cli_reports_earliest_first_detected_across_causes(tmp_path, monkeypatch):
    """A dep with a fresh lifecycle cause and an older security record
    reports the security record's date - earliest across all of the
    verdict's recorded facts, not the first recorded fact."""
    from click.testing import CliRunner

    from cli.main import cli as _cli

    ledger_root = tmp_path / "ledger"
    watchlist = tmp_path / "wl.yaml"
    watchlist.write_text(
        "\n".join(_WL_LINES) + "\n",
        encoding="utf-8",
    )
    bundle_dir = tmp_path / "bundles"
    bundle_dir.mkdir()
    (bundle_dir / "django.json").write_text(
        json.dumps(_osv_bundle("4.2")),
        encoding="utf-8",
    )

    # July: a security run detects the CVE first.
    monkeypatch.setattr("core.detections.ledger.now_iso", lambda: "2026-07-01T00:00:00+00:00")
    security_only = CliRunner().invoke(
        _cli,
        [
            "check",
            "--watchlist",
            str(watchlist),
            "--raw-bundle-dir",
            str(bundle_dir),
            "--ledger",
            str(ledger_root),
        ],
    )
    assert security_only.exit_code == 0, security_only.output

    # October: same run now also sees the lifecycle event. The security
    # record from July is the earliest fact for this dependency.
    monkeypatch.setattr("core.detections.ledger.now_iso", lambda: "2026-10-01T00:00:00+00:00")
    both = CliRunner().invoke(
        _cli,
        [
            "check",
            "--watchlist",
            str(watchlist),
            "--event",
            "data/fixtures/django-eol/event.json",
            "--raw-bundle-dir",
            str(bundle_dir),
            "--ledger",
            str(ledger_root),
        ],
    )
    assert both.exit_code == 0, both.output
    assert "first detected 2026-07-01" in both.output, both.output
    assert "first detected 2026-10-01" not in both.output, both.output


# ---------------------------------------------------------------------------
# Report feed: ledger first_seen survives into lead time / Upcoming Changes
# ---------------------------------------------------------------------------


def _report_item(project, finding):
    return {"project": project, "pulse": {"facets": {}}, "findings": [finding]}


def test_report_ledger_feeds_upcoming_changes_across_runs(tmp_path):
    """Warning windows survive across runs via the ledger (issue #41)."""
    from core.detections import ledger as ledger_mod
    from reports.generate import build_report

    root = tmp_path / "ledger"
    # A check run in July first detected django 4.2's upcoming EOL.
    ledger_mod.record_detection(
        "django",
        "lifecycle",
        "EOL",
        ["4.2"],
        detected_at="2026-07-01T00:00:00+00:00",
        root=root,
    )
    finding = {
        "analyst": "change",
        "event_type": "EOL",
        "signal": "lifecycle",
        "impact": "REVIEW",
        "title": "Django 4.2 EOL approaching",
        "event_date": "2026-12-15",
        "effective_at": "2026-12-15",
        "scope": {"kind": "version", "versions": ["4.2"]},
        "affected_versions": ["4.2"],
        "sources": ["endoflife.date"],
    }
    markdown = build_report(
        "2026-10",
        [_report_item("django", finding)],
        today=None,
        ledger_root=str(root),
    )
    assert "OpenPulse first detected: 2026-07-01" in markdown, markdown
    assert "167 days until effective" in markdown


def test_report_without_ledger_makes_no_detection_claim(tmp_path):
    """No ledger -> no invented first-detected date (unknown stays unknown)."""
    from reports.generate import build_report

    finding = {
        "analyst": "change",
        "event_type": "EOL",
        "signal": "lifecycle",
        "impact": "REVIEW",
        "title": "Django 4.2 EOL approaching",
        "event_date": "2026-12-15",
        "effective_at": "2026-12-15",
        "scope": {"kind": "version", "versions": ["4.2"]},
        "affected_versions": ["4.2"],
        "sources": ["endoflife.date"],
    }
    markdown = build_report("2026-10", [_report_item("django", finding)], today=None)
    assert "OpenPulse first detected: 2026-07-01" not in markdown


def test_report_existing_first_detected_at_is_never_overwritten(tmp_path):
    """Sweep/observation-derived dates win; the ledger never rewrites them."""
    from core.detections import ledger as ledger_mod
    from reports.generate import build_report

    root = tmp_path / "ledger"
    ledger_mod.record_detection(
        "django",
        "lifecycle",
        "EOL",
        ["4.2"],
        detected_at="2026-07-01T00:00:00+00:00",
        root=root,
    )
    finding = {
        "analyst": "change",
        "event_type": "EOL",
        "signal": "lifecycle",
        "impact": "REVIEW",
        "title": "Django 4.2 EOL approaching",
        "event_date": "2026-12-15",
        "effective_at": "2026-12-15",
        "first_detected_at": "2026-09-01",
        "scope": {"kind": "version", "versions": ["4.2"]},
        "affected_versions": ["4.2"],
        "sources": ["endoflife.date"],
    }
    markdown = build_report(
        "2026-10", [_report_item("django", finding)], today=None, ledger_root=str(root)
    )
    assert "OpenPulse first detected: 2026-09-01" in markdown
    assert "OpenPulse first detected: 2026-07-01" not in markdown
