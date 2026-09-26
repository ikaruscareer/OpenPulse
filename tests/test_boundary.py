"""Security boundary contract (§22): ten invariants that must never break."""

import json


def _nvd(cve, product, score=9.8, version_attrs=None):
    cpe = {"criteria": f"cpe:2.3:a:vendor:{product}:*:*:*:*:*:*:*:*", "vulnerable": True}
    cpe.update(version_attrs or {})
    return {
        "collector": "nvd",
        "id": cve,
        "cvss": {"base_score": score},
        "cpes": [cpe],
        "references": [],
    }


def test_1_keyword_mention_is_not_affected():
    """CVE mentions 'redis' must not mean docker.io/redis is affected."""
    from analyzers.security_analyst import correlate

    out = correlate({"nvd": [_nvd("CVE-2026-0001", "something-else")]}, {"slug": "redis"})[0]
    assert out["relationship"] in ("RELATED", "UNKNOWN")
    assert out["relationship"] != "AFFECTS_VERSION"
    assert out["impact"] in ("REVIEW", "WATCH", "INFORMATIONAL")


def test_2_bitnami_change_spares_upstream_redis():
    import json as _json

    from core.risk.match import event_affects_ref
    from core.schema.models import OSSEvent

    event = OSSEvent(**_json.load(open("data/fixtures/bitnami/event.json")))
    assert event_affects_ref(event, "docker.io/redis:7.2")["affected"] is False


def test_3_weak_kev_similarity_never_critical():
    from analyzers.security_analyst import correlate

    raw = {
        "nvd": [_nvd("CVE-2026-0002", "reddish-widget", score=10.0)],
        "kev": [{"collector": "kev", "cve_id": "CVE-2026-0002", "match": "weak"}],
    }
    out = correlate(raw, {"slug": "redis"})[0]
    assert out["in_kev"] is False
    assert out["impact"] != "CRITICAL"


def test_4_cpe_token_overlap_is_not_affects_version():
    """spring-boot vs spring-shell: overlap without identity evidence."""
    from analyzers.security_analyst import correlate

    raw = {"nvd": [_nvd("CVE-2026-0003", "spring-shell", score=9.8)]}
    project = {"slug": "spring-boot", "aliases": ["spring"], "version": "3.2.1"}
    out = correlate(raw, project)[0]
    assert out["relationship"] != "AFFECTS_VERSION"
    assert out["impact"] in ("REVIEW", "WATCH", "INFORMATIONAL")


def test_5_no_previous_observation_is_baseline():
    from core.observations.registry import RegistryObservation, diff_observations

    curr = RegistryObservation(namespace="x", repository="y", tags={"latest": ["sha256:A"]}).seal()
    assert diff_observations(None, curr) == []


def test_6_latest_move_is_not_a_security_event():
    from analyzers.change_analyst import analyze_diffs

    out = analyze_diffs(
        [
            {
                "type": "latest_moved",
                "namespace": "x",
                "repository": "y",
                "tag": "latest",
                "observed_at": "2026-01-01",
            }
        ]
    )
    assert out and all(f["event_type"] != "SECURITY" for f in out)
    assert out[0]["impact"] == "WATCH"


def test_7_contradicting_evidence_preserved():
    from core.claims import conflict_status

    evidences = [
        {"source": {"name": "a", "authority": "official"}, "relation": "supports"},
        {"source": {"name": "b", "authority": "secondary"}, "relation": "contradicts"},
    ]
    assert conflict_status(evidences) == "UNRESOLVED"


def test_8_unrelated_official_evidence_fails_claim_gate():
    from analyzers.evidence_analyst import assemble_event

    data = json.load(open("data/fixtures/bitnami/event.json"))
    _, violations = assemble_event(
        id="evt-boundary-8",
        project_slug="bitnami",
        event_type="DISTRIBUTION_CHANGE",
        title="t",
        summary="s",
        impact="ACTION",
        affected_versions=["*"],
        affected_artifacts=[{"kind": "docker-image", "ref": "docker.io/bitnami/redis:7.2"}],
        evidences=data["evidences"],
        claims=[
            {
                "id": "claim:x",
                "type": "DISTRIBUTION_CHANGE",
                "subject": "bitnami",
                "statement": "s",
                "evidence_refs": ["unrelated-source"],
            }
        ],
    )
    assert any("no supporting evidence" in v for v in violations)


def test_9_package_without_version_claims_no_version():
    from analyzers.security_analyst import correlate

    raw = {
        "osv": [
            {
                "collector": "osv",
                "package": "django",
                "ecosystem": "PyPI",
                "id": "CVE-2026-0004",
                "severity": [],
                "affected": [
                    {
                        "package": "django",
                        "ecosystem": "PyPI",
                        "ranges": [],
                        "fixed": [],
                        "versions": [],
                    }
                ],
                "references": [],
            }
        ]
    }
    out = correlate(raw, {"slug": "django", "package": "django", "ecosystem": "PyPI"})[0]
    assert out["relationship"] == "AFFECTS_PACKAGE"
    assert out["affected_version"] is None


def test_10_exact_artifact_identity():
    import json as _json

    from core.risk.match import event_affects_ref
    from core.schema.models import OSSEvent

    event = OSSEvent(**_json.load(open("data/fixtures/bitnami/event.json")))
    result = event_affects_ref(event, "docker.io/bitnami/redis:7.2")
    assert result["affected"] is True
    assert result["relationship"] == "AFFECTS_ARTIFACT"


def test_versions_django_example():
    """OSV range: django 5.0 affected (<5.1), 5.1.1 fixed."""
    from core.versions import osv_applicable

    affected = {
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.1.1"}]}]
    }
    assert osv_applicable("5.0", affected) is True
    assert osv_applicable("5.1.1", affected) is False
    assert osv_applicable(None, affected) is None


def test_identity_refs_keep_redis_separate():
    from core.entities.identity import identity_refs_for, same_identity

    a = identity_refs_for("docker.io/bitnami/redis:7.2")
    b = identity_refs_for("docker.io/redis:7.2")
    assert a[0] != b[0]
    assert same_identity(a, b)["same"] is False
    assert same_identity(a, identity_refs_for("docker.io/bitnami/redis:7.4"))["same"] is True
