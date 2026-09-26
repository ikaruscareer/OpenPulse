def _nvd_payload():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Test vuln"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "references": [{"url": "https://example.com/advisory"}],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-0002",
                    "published": "2024-02-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "No metrics yet"}],
                    "metrics": {},
                    "references": [],
                }
            },
        ]
    }


def test_nvd_parse():
    from collectors.nvd.collector import parse_cves

    out = parse_cves(_nvd_payload())
    assert out[0]["id"] == "CVE-2024-0001"
    assert out[0]["cvss"]["base_score"] == 9.8
    assert out[0]["references"] == ["https://example.com/advisory"]
    assert out[1]["cvss"] == {}


def _cve_payload():
    return {
        "cveMetadata": {
            "cveId": "CVE-2024-0001",
            "state": "PUBLISHED",
            "assignerShortName": "test-cna",
            "datePublished": "2024-01-01T00:00:00.000Z",
        },
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Test vuln"}],
                "affected": [
                    {
                        "vendor": "testvendor",
                        "product": "testproduct",
                        "versions": [{"version": "1.0"}],
                    }
                ],
                "references": [{"url": "https://example.com/fix"}],
            }
        },
    }


def test_cve_parse():
    from collectors.cve.collector import parse_record

    out = parse_record(_cve_payload())
    assert out["id"] == "CVE-2024-0001"
    assert out["state"] == "PUBLISHED"
    assert out["affected"][0]["product"] == "testproduct"
    assert out["references"] == ["https://example.com/fix"]


def test_cve_rejects_non_id():
    from collectors.cve.collector import CVECollector

    out = CVECollector().collect("redis")
    assert "skipped" in out[0]


def _kev_catalog():
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "TestVendor",
                "product": "TestProduct",
                "vulnerabilityName": "Test Vuln",
                "dateAdded": "2024-03-01",
                "dueDate": "2024-03-22",
                "requiredAction": "Apply updates.",
            }
        ]
    }


def test_kev_filter_by_cve():
    from collectors.kev.collector import filter_catalog

    out = filter_catalog(_kev_catalog(), "cve-2024-0001")
    assert len(out) == 1
    assert out[0]["product"] == "TestProduct"


def test_kev_filter_no_match():
    from collectors.kev.collector import filter_catalog

    assert filter_catalog(_kev_catalog(), "nosuchproject") == []
