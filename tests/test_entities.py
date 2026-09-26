def test_legacy_aliases_preserved():
    from core.entities.resolve import resolve_project

    assert resolve_project("bitnami/redis:7.2") == "bitnami-redis-stack"
    assert resolve_project("docker.io/redis:7") == "redis"


def test_bitnami_namespace_rule():
    from core.entities.resolve import resolve_project

    assert resolve_project("docker.io/bitnami/postgresql:16") == "bitnami-postgresql"
    assert resolve_project("docker.io/bitnamilegacy/kafka:3.7") == "bitnami-kafka"
    assert resolve_project("bitnamisecure/redis:latest") == "bitnami-redis-stack"


def test_catalog_aliases():
    from core.entities.resolve import resolve_project

    assert resolve_project("postgres:16") == "postgresql"
    assert resolve_project("docker.io/library/postgres:16") == "postgresql"
    assert resolve_project("apache/kafka") == "kafka"


def test_catalog_hygiene():
    from core.entities.catalog import catalog_alias_map, load_catalog

    catalog = load_catalog()
    assert len(catalog) >= 10
    for entry in catalog:
        assert entry.get("slug")
    for alias in catalog_alias_map(catalog):
        assert alias == alias.strip().lower()
        assert ":" not in alias and "@" not in alias


def test_purl_builder():
    from core.entities.catalog import purl_for

    assert purl_for("docker", "bitnami", "redis", "7.2") == "pkg:docker/bitnami/redis@7.2"
    assert purl_for("github", "redis", "redis") == "pkg:github/redis/redis"
