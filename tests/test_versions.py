"""Version applicability unit tests (OSV events, CPE ranges, comparison)."""

from core.versions import compare, cpe_applicable, satisfies


def test_compare_numeric_and_prerelease():
    assert compare("5.1", "5.1.1") == -1
    assert compare("5.1.1", "5.1.1") == 0
    assert compare("8.0", "7.4.2") == 1
    assert compare("1.0rc1", "1.0") == -1
    assert compare("latest", "1.0") is None


def test_satisfies_osv_style():
    assert satisfies("5.0", {"introduced": "0", "fixed": "5.1.1"}) is True
    assert satisfies("5.1.1", {"introduced": "0", "fixed": "5.1.1"}) is False
    assert satisfies("4.2", {"last_affected": "5.0"}) is True
    assert satisfies("5.0.1", {"last_affected": "5.0"}) is False
    assert satisfies("1.0", {}) is None


def test_satisfies_cpe_style():
    constraint = {"versionStartIncluding": "7.0", "versionEndExcluding": "7.4"}
    assert satisfies("7.2", constraint) is True
    assert satisfies("7.4", constraint) is False
    assert satisfies("6.9", constraint) is False


def test_cpe_applicable_exact_and_range():
    assert (
        cpe_applicable("8.0", {"criteria": "cpe:2.3:a:v:p:8.0:*:*:*:*:*:*:*", "vulnerable": True})
        is True
    )
    assert (
        cpe_applicable("8.0.1", {"criteria": "cpe:2.3:a:v:p:8.0:*:*:*:*:*:*:*", "vulnerable": True})
        is False
    )
    assert (
        cpe_applicable(None, {"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "vulnerable": True})
        is None
    )
    assert (
        cpe_applicable("1.0", {"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "vulnerable": False})
        is False
    )
