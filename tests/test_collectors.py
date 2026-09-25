def test_github_parse():
    from collectors.github.collector import parse_releases

    out = parse_releases(
        "redis/redis",
        [
            {
                "tag_name": "7.2.0",
                "name": "7.2",
                "published_at": "2024-01-01T00:00:00Z",
                "prerelease": False,
                "html_url": "https://github.com/redis/redis/releases/tag/7.2.0",
            }
        ],
    )
    assert out[0]["tag"] == "7.2.0"


def test_endoflife_parse():
    from collectors.endoflife.collector import parse_product

    out = parse_product(
        "nodejs",
        [{"cycle": "20", "eol": "2026-04-30", "support": "2025-10-21", "latest": "20.11.0"}],
    )
    assert out[0]["cycle"] == "20"


def test_osv_parse():
    from collectors.osv.collector import parse_vulns

    out = parse_vulns(
        "redis",
        "PyPI",
        {
            "vulns": [
                {
                    "id": "CVE-2024-0001",
                    "summary": "x",
                    "severity": [],
                    "references": [{"url": "https://example.com"}],
                }
            ]
        },
    )
    assert out[0]["id"] == "CVE-2024-0001"


def test_registry_parse_latest_only():
    from collectors.registries.docker import parse_tags

    out = parse_tags("bitnami", "redis", {"count": 1, "results": [{"name": "latest"}]})
    assert out["latest_only"] is True
    out2 = parse_tags(
        "bitnamilegacy", "redis", {"count": 2, "results": [{"name": "7.2.0"}, {"name": "latest"}]}
    )
    assert out2["has_versioned_tags"] is True
