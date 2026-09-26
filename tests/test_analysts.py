import json
from datetime import date


def _raw_endoflife():
    return [
        {
            "collector": "endoflife",
            "product": "nodejs",
            "cycle": "18",
            "eol": "2025-04-30",
            "support": "2024-10-01",
            "latest": "18.20.0",
        },
        {
            "collector": "endoflife",
            "product": "nodejs",
            "cycle": "22",
            "eol": "2027-04-30",
            "support": "2026-10-21",
            "latest": "22.11.0",
        },
    ]


def test_change_eol_past_is_action():
    from analyzers.change_analyst import analyze_endoflife

    out = analyze_endoflife(_raw_endoflife(), today=date(2026, 9, 26))
    by_title = {f["title"]: f for f in out}
    assert by_title["nodejs 18 is end-of-life"]["impact"] == "ACTION"
    assert by_title["nodejs 18 is end-of-life"]["event_type"] == "EOL"


def test_change_eol_approaching_is_review():
    from analyzers.change_analyst import analyze_endoflife

    entries = [
        {
            "collector": "endoflife",
            "product": "x",
            "cycle": "9",
            "eol": "2026-12-01",
            "support": "2026-12-01",
        }
    ]
    out = analyze_endoflife(entries, today=date(2026, 9, 26))
    assert out[0]["impact"] == "REVIEW"
    assert "approaching" in out[0]["title"]


def test_change_bitnami_distribution_pattern():
    from analyzers.change_analyst import analyze_registries

    raw = [
        {"collector": "registries", "namespace": "bitnami", "repo": "redis", "latest_only": True},
        {
            "collector": "registries",
            "namespace": "bitnamilegacy",
            "repo": "redis",
            "has_versioned_tags": True,
        },
    ]
    out = analyze_registries(raw)
    assert len(out) == 1
    assert out[0]["event_type"] == "DISTRIBUTION_CHANGE"
    assert out[0]["impact"] == "ACTION"


def test_change_missing_repo():
    from analyzers.change_analyst import analyze_registries

    out = analyze_registries(
        [{"collector": "registries", "namespace": "bitnami", "repo": "gone", "missing": True}]
    )
    assert out[0]["event_type"] == "REGISTRY_CHANGE"


def test_security_correlate_kev_is_critical():
    """KEV exact-ID + identity evidence (OSV scope) -> CRITICAL/AFFECTS."""
    from analyzers.security_analyst import correlate

    raw = {
        "osv": [
            {
                "collector": "osv",
                "id": "CVE-2024-0001",
                "severity": [{"score": 5.0}],
                "references": [],
            }
        ],
        "kev": [{"collector": "kev", "cve_id": "CVE-2024-0001"}],
        "nvd": [],
        "cve": [],
    }
    out = correlate(raw)
    assert out[0]["impact"] == "CRITICAL"
    assert out[0]["in_kev"] is True
    assert out[0]["relationship"] == "AFFECTS_PACKAGE"
    assert set(out[0]["sources"]) == {"osv", "kev"}


def test_security_kev_without_identity_is_review():
    """Exploited CVE with no project tie -> RELATED, capped at REVIEW."""
    from analyzers.security_analyst import correlate

    raw = {
        "nvd": [
            {
                "collector": "nvd",
                "id": "CVE-2024-0001",
                "cvss": {"base_score": 5.0},
                "references": [],
            }
        ],
        "kev": [{"collector": "kev", "cve_id": "CVE-2024-0001"}],
        "osv": [],
        "cve": [],
    }
    out = correlate(raw)
    assert out[0]["impact"] == "REVIEW"
    assert out[0]["relationship"] == "RELATED"


def test_security_score_bands_keyword_only_capped():
    """Keyword-only NVD hits are RELATED: severe scores cap at REVIEW."""
    from analyzers.security_analyst import correlate

    def finding(score):
        return correlate(
            {
                "nvd": [
                    {
                        "collector": "nvd",
                        "id": "CVE-2024-0009",
                        "cvss": {"base_score": score},
                        "references": [],
                    }
                ]
            }
        )[0]

    assert finding(9.5)["impact"] == "REVIEW"
    assert finding(9.5)["relationship"] == "RELATED"
    assert finding(7.5)["impact"] == "REVIEW"
    assert finding(5.0)["impact"] == "WATCH"


def test_security_cpe_match_restores_action():
    """CPE vendor/product identity turns the same CVE into AFFECTS_PACKAGE."""
    from analyzers.security_analyst import correlate

    raw = {
        "nvd": [
            {
                "collector": "nvd",
                "id": "CVE-2024-0009",
                "cvss": {"base_score": 9.5},
                "cpes": [{"criteria": "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", "vulnerable": True}],
                "references": [],
            }
        ]
    }
    project = {"slug": "redis", "aliases": ["redis-server"], "vendors": ["Redis"]}
    out = correlate(raw, project)[0]
    assert out["relationship"] == "AFFECTS_PACKAGE"
    assert out["impact"] == "ACTION"


def test_security_weak_kev_never_critical():
    from analyzers.security_analyst import correlate

    raw = {
        "nvd": [
            {
                "collector": "nvd",
                "id": "CVE-2024-0011",
                "cvss": {"base_score": 9.8},
                "references": [],
            }
        ],
        "kev": [{"collector": "kev", "cve_id": "CVE-2024-0011", "match": "weak"}],
    }
    out = correlate(raw)[0]
    assert out["in_kev"] is False
    assert out["impact"] == "REVIEW"


def test_evidence_assess():
    from analyzers.evidence_analyst import assess_confidence
    from core.schema.enums import Confidence

    official = [{"source": {"name": "a", "authority": "official"}}]
    assert assess_confidence(official) == Confidence.CONFIRMED
    two = [
        {"source": {"name": "a", "authority": "secondary"}},
        {"source": {"name": "b", "authority": "secondary"}},
    ]
    assert assess_confidence(two) == Confidence.CORROBORATED
    one = [{"source": {"name": "a", "authority": "secondary"}}]
    assert assess_confidence(one) == Confidence.EMERGING
    assert assess_confidence([]).value == "UNVERIFIED"


def test_evidence_assemble_passes_gate():
    from analyzers.evidence_analyst import assemble_event

    data = json.load(open("data/fixtures/bitnami/event.json"))
    event, violations = assemble_event(
        id="evt-test-001",
        project_slug="bitnami",
        event_type="DISTRIBUTION_CHANGE",
        title="t",
        summary="s",
        impact="ACTION",
        affected_versions=["*"],
        affected_artifacts=[{"kind": "docker-image", "ref": "docker.io/bitnami/redis:7.2"}],
        evidences=data["evidences"],
    )
    assert violations == []
    assert event.confidence.value == "CONFIRMED"


def test_report_renders():
    from analyzers.report_analyst import render_digest, render_event_md
    from core.schema.models import OSSEvent

    event = OSSEvent(**json.load(open("data/fixtures/bitnami/event.json")))
    md = render_event_md(event)
    assert "bitnami/containers" in md
    assert "Recommendation" in md
    digest = render_digest([event])
    assert "ACTION (1)" in digest


def test_match_bitnami_vs_upstream():
    from core.risk.match import event_affects_ref
    from core.schema.models import OSSEvent

    event = OSSEvent(**json.load(open("data/fixtures/bitnami/event.json")))
    assert event_affects_ref(event, "docker.io/bitnami/redis:7.2")["affected"] is True
    assert event_affects_ref(event, "docker.io/bitnamilegacy/redis:7.2")["affected"] is True
    # Upstream images are a different stack — must NOT match.
    assert event_affects_ref(event, "docker.io/redis:7.2")["affected"] is False
    assert event_affects_ref(event, "postgres:16")["affected"] is False
