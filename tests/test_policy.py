import json


def test_bitnami_fixture_passes_gate():
    from core.evidence.policy import gate
    from core.schema.models import OSSEvent

    e = OSSEvent(**json.load(open("data/fixtures/bitnami/event.json")))
    assert gate(e) == [], f"Bitnami fixture must pass gate: {gate(e)}"


def test_unverified_cannot_be_action():
    from core.evidence.policy import gate
    from core.schema.models import OSSEvent

    e = OSSEvent(**json.load(open("data/fixtures/bitnami/event.json")))
    e.confidence = "UNVERIFIED"
    e.impact = "ACTION"
    assert gate(e), "UNVERIFIED + ACTION must be rejected"


def test_distribution_requires_artifacts():
    from core.evidence.policy import gate
    from core.schema.models import OSSEvent

    e = OSSEvent(**json.load(open("data/fixtures/bitnami/event.json")))
    e.affected_artifacts = []
    assert any("affected_artifacts" in v for v in gate(e))


def test_confirmed_requires_official():
    from core.evidence.policy import gate
    from core.schema.models import OSSEvent

    e = OSSEvent(**json.load(open("data/fixtures/bitnami/event.json")))
    for ev in e.evidences:
        ev.source.authority = "secondary"
    assert any("official" in v for v in gate(e))
