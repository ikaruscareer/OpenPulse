"""Trust foundation tests: structured errors, provenance, independence, CLI guards."""


def test_error_shape_hides_raw_detail():
    from collectors.errors import as_error

    try:
        raise RuntimeError("/home/user/.config/proxy secret-token abc")
    except RuntimeError as e:
        err = as_error("nvd", e, project="x")
    assert err["error"] is True
    assert err["category"] == "unknown"
    assert err["retryable"] is False
    assert "secret-token" not in err["safe_message"]
    assert len(err["safe_message"]) <= 200


def test_error_classify_rate_limit_retryable():
    import httpx

    from collectors.errors import as_error

    req = httpx.Request("GET", "https://example.com")
    resp = httpx.Response(429, request=req)
    err = as_error("nvd", httpx.HTTPStatusError("slow", request=req, response=resp))
    assert (err["category"], err["retryable"], err["status_code"]) == ("rate_limit", True, 429)


def test_error_classify_timeout_retryable():
    import httpx

    from collectors.errors import as_error

    err = as_error("kev", httpx.ConnectTimeout("boom"))
    assert (err["category"], err["retryable"]) == ("network", True)


def test_hash_stable_and_sensitive():
    from core.evidence.provenance import PARSER_VERSION, hash_content

    assert hash_content({"b": 1, "a": [1, 2]}) == hash_content({"a": [1, 2], "b": 1})
    assert hash_content({"a": 1}) != hash_content({"a": 2})
    assert PARSER_VERSION.startswith("openpulse-parsers/")


def test_independence_folds_derived_chains():
    from core.evidence.independence import independent_count

    evidences = [
        {"source": {"name": "official-blog", "authority": "official"}},
        {
            "source": {
                "name": "news-site",
                "authority": "secondary",
                "derived_from": "official-blog",
            }
        },
    ]
    assert independent_count(evidences) == 1


def test_independence_groups_families():
    from core.evidence.independence import independent_count

    evidences = [
        {"source": {"name": "containers-issue", "family": "bitnami", "authority": "official"}},
        {"source": {"name": "charts-issue", "family": "bitnami", "authority": "official"}},
        {"source": {"name": "broadcom-blog", "family": "broadcom", "authority": "official"}},
    ]
    assert independent_count(evidences) == 2


def test_gate_rejects_contradicts_only_claim():
    import json

    from core.evidence.policy import gate
    from core.schema.models import OSSEvent

    data = json.load(open("data/fixtures/bitnami/event.json"))
    for e in data["evidences"]:
        e["relation"] = "contradicts"
    assert any("contradict" in v for v in gate(OSSEvent(**data)))


def test_cli_rejects_malformed_json(tmp_path):
    from click.testing import CliRunner

    from cli.main import cli

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = CliRunner().invoke(cli, ["validate", "--event", str(bad)])
    assert result.exit_code != 0
    assert "not valid JSON" in result.output


def test_cli_rejects_oversized_input(tmp_path):
    from click.testing import CliRunner

    from cli.main import MAX_INPUT_BYTES, cli

    big = tmp_path / "big.json"
    big.write_text("x" * (MAX_INPUT_BYTES + 1), encoding="utf-8")
    result = CliRunner().invoke(cli, ["validate", "--event", str(big)])
    assert result.exit_code != 0
    assert "limit" in result.output


def test_cli_reports_schema_location(tmp_path):
    from click.testing import CliRunner

    from cli.main import cli

    bad = tmp_path / "empty.json"
    bad.write_text("{}", encoding="utf-8")
    result = CliRunner().invoke(cli, ["validate", "--event", str(bad)])
    assert result.exit_code != 0
    assert "fails schema" in result.output
