"""Change-engine tests: digest-aware observations, diffs, history, archived repos."""

from datetime import datetime, timezone


def _obs(**kw):
    from core.observations.registry import RegistryObservation

    base = {
        "namespace": "bitnami",
        "repository": "redis",
        "observed_at": datetime(2026, 9, 1, tzinfo=timezone.utc),
        "tags": {"latest": ["sha256:AAA"], "7.2.0": ["sha256:111"]},
    }
    base.update(kw)
    return RegistryObservation(**base).seal()


def test_parse_captures_digests():
    from collectors.registries.docker import parse_tags

    payload = {
        "count": 2,
        "results": [
            {"name": "latest", "images": [{"digest": "sha256:BBB"}, {"digest": "sha256:CCC"}]},
            {"name": "7.2.0", "images": [{"digest": "sha256:111"}]},
        ],
    }
    out = parse_tags("bitnami", "redis", payload)
    assert out["digests"] == {"latest": ["sha256:BBB", "sha256:CCC"], "7.2.0": ["sha256:111"]}


def test_baseline_claims_no_changes():
    from core.observations.registry import diff_observations

    assert diff_observations(None, _obs()) == []


def test_identical_observations_no_changes():
    from core.observations.registry import diff_observations

    assert diff_observations(_obs(), _obs()) == []


def test_tag_appeared_disappeared_digest_changed():
    from core.observations.registry import diff_observations

    prev = _obs()
    curr = _obs(
        observed_at=datetime(2026, 9, 2, tzinfo=timezone.utc),
        tags={"latest": ["sha256:AAA"], "7.4.0": ["sha256:222"]},
    )
    by_type = {c.type: c for c in diff_observations(prev, curr)}
    assert by_type["tag_appeared"].tag == "7.4.0"
    assert by_type["tag_disappeared"].tag == "7.2.0"
    assert "tag_digest_changed" not in by_type


def test_latest_move_detected():
    from core.observations.registry import diff_observations

    prev = _obs()
    curr = _obs(
        observed_at=datetime(2026, 9, 2, tzinfo=timezone.utc),
        tags={"latest": ["sha256:BBB"], "7.2.0": ["sha256:111"]},
    )
    changes = diff_observations(prev, curr)
    assert [c.type for c in changes] == ["latest_moved"]
    assert changes[0].previous == ["sha256:AAA"]


def test_repo_missing_and_restored():
    from core.observations.registry import diff_observations

    assert diff_observations(_obs(), _obs(missing=True))[0].type == "repo_missing"
    assert diff_observations(_obs(missing=True), _obs())[0].type == "repo_restored"


def test_store_roundtrip(tmp_path):
    from core.observations.store import load_previous, save_observation

    obs = _obs().model_dump(mode="json")
    path = save_observation(obs, root=tmp_path)
    assert path.exists()
    assert (
        load_previous("docker.io", "bitnami", "redis", root=tmp_path)["content_hash"]
        == obs["content_hash"]
    )


def test_archived_repo_finding():
    from analyzers.change_analyst import analyze_github_meta

    out = analyze_github_meta(
        [
            {
                "collector": "github",
                "kind": "repo_meta",
                "repo": "o/r",
                "archived": True,
                "pushed_at": "2020-01-01",
            }
        ]
    )
    assert out[0]["event_type"] == "PROJECT_ARCHIVED"
    assert out[0]["impact"] == "ACTION"


def test_diff_driven_findings():
    from analyzers.change_analyst import analyze_diffs

    out = analyze_diffs(
        [
            {
                "type": "tag_disappeared",
                "namespace": "bitnami",
                "repository": "redis",
                "tag": "7.2.0",
                "observed_at": "2026-09-02",
            }
        ]
    )
    assert out[0]["event_type"] == "DISTRIBUTION_CHANGE"
    assert out[0]["impact"] == "REVIEW"
