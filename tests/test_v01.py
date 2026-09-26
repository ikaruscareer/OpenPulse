def test_schema_import():
    from core.schema.models import SCHEMA_VERSION

    assert SCHEMA_VERSION == "0.2.0"


def test_bitnami_fixture_validates():
    import json

    from core.schema.models import OSSEvent

    data = json.load(open("data/fixtures/bitnami/event.json"))
    e = OSSEvent(**data)
    assert e.project_slug == "bitnami"
    assert e.requires_action()


def test_entity_resolution():
    from core.entities.resolve import resolve_project

    assert resolve_project("bitnami/redis:7.2") == "bitnami-redis-stack"
    assert resolve_project("docker.io/redis:7") == "redis"
