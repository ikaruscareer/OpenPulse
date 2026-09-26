"""Permanent acceptance test for the north-star scenario (§23).

A user depends on docker.io/bitnami/redis. Upstream distribution
changes. OpenPulse must answer WHAT/WHEN/WHICH/HOW confidently — and
must NOT implicate docker.io/redis merely because both contain "redis".
"""

import json

import pytest

from analyzers.report_analyst import render_event_md
from core.evidence.policy import gate
from core.risk.match import event_affects_ref
from core.schema.models import OSSEvent


@pytest.fixture(scope="module")
def event():
    return OSSEvent(**json.load(open("data/fixtures/bitnami/event.json")))


def test_what_changed(event):
    assert event.event_type.value == "DISTRIBUTION_CHANGE"
    assert event.title and event.summary


def test_when_announced_and_effective(event):
    announced = {e.announcement_date for e in event.evidences if e.announcement_date}
    effective = {e.effective_date for e in event.evidences if e.effective_date}
    assert "2025-07-16" in {str(d) for d in announced}
    assert "2025-08-28" in {str(d) for d in effective}


def test_which_source_and_trust(event):
    urls = [str(e.source.url) for e in event.evidences]
    assert any("bitnami/containers" in u for u in urls)
    assert event.confidence.value == "CONFIRMED"
    assert any(e.source.authority == "official" for e in event.evidences)
    assert gate(event) == []


def test_which_artifact_and_dependency(event):
    from core.entities.resolve import resolve_project

    refs = [a.ref for a in event.affected_artifacts]
    assert any("bitnami/redis" in r for r in refs)
    assert resolve_project("docker.io/bitnami/redis:7.2") == "bitnami-redis-stack"


def test_user_dependency_matches(event):
    result = event_affects_ref(event, "docker.io/bitnami/redis:7.2")
    assert result["affected"] is True
    assert result["via"] == "artifact"


def test_upstream_redis_must_not_match(event):
    result = event_affects_ref(event, "docker.io/redis:7.2")
    assert result["affected"] is False, "namespace-blind matching is a regression"


def test_versions_and_confidence(event):
    assert event.affected_versions and event.affected_artifacts
    assert event.impact.value in ("ACTION", "CRITICAL")


def test_investigation_guidance(event):
    md = render_event_md(event)
    assert "Recommendation" in md and "Evidence" in md
    assert "github.com/bitnami" in md
