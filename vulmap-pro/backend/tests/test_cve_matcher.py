"""Unit tests for the CVE matcher.

Network calls are mocked via a fake `requests.Session` so these tests run
in CI without NVD access. The "messy version" test catches normalization
regressions early.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from backend.db.session import init_db, session_scope
from scanner import cve_matcher
from scanner.models import PortResult, ScanResult, ServiceInfo


# --------------------------------------------------------------------------- normalization
def test_normalize_strips_ubuntu_patch_suffix():
    """The deliberately messy version string from the spec."""
    norm = cve_matcher.normalize_service_string(
        product="OpenSSH",
        version="8.2p1",
        extra="Ubuntu-4ubuntu0.5",
    )
    assert norm is not None
    vendor, product, version = norm
    assert vendor == "OpenSSH"
    assert "openssh" in product
    # Stripping `p1` patch and Ubuntu suffix leaves a clean "8.2"
    assert version.startswith("8.2")


def test_normalize_strips_distro_name_from_version_only():
    norm = cve_matcher.normalize_service_string(
        product="Apache httpd",
        version="2.4.41",
        extra=None,
    )
    assert norm is not None
    assert norm[0] == "Apache"
    assert norm[2] == "2.4.41"


def test_normalize_handles_dot_ubuntu_tail():
    norm = cve_matcher.normalize_service_string(
        product="MySQL",
        version="5.7.33-0ubuntu0.16.04.1",
        extra=None,
    )
    assert norm is not None
    assert norm[0] == "MySQL"
    assert norm[2] == "5.7.33"


def test_normalize_returns_none_without_version():
    assert cve_matcher.normalize_service_string(product="nginx", version=None) is None


def test_normalize_returns_none_without_product():
    assert cve_matcher.normalize_service_string(product=None, version="1.2.3") is None


# --------------------------------------------------------------------------- CPE construction
def test_build_cpe_uris_includes_stripped_product_fallback():
    uris = cve_matcher.build_cpe_uris("Apache", "Apache httpd", "2.4.41")
    assert any("apache" in u for u in uris)
    assert any("httpd" in u or "http_server" in u or "apache_httpd" in u for u in uris)
    # All URIs start with the CPE 2.3 prefix.
    assert all(u.startswith("cpe:2.3:a:") for u in uris)


def test_build_cpe_uris_escapes_spaces_and_colons():
    uris = cve_matcher.build_cpe_uris("Microsoft", "HTTP API", "2.0")
    joined = " ".join(uris)
    # Spaces must be escaped as '\ '.
    assert "\\ " in joined
    # No unescaped colons inside vendor/product fields.
    for u in uris:
        # count colons after the leading 'cpe:2.3:' part — there should be exactly 10
        prefix = "cpe:2.3:"
        body = u[len(prefix):]
        # Each '\:' is escaped, each ':' is a field separator.
        assert body.count(":") - body.count("\\:") == 10


# --------------------------------------------------------------------------- end-to-end with mocked NVD
@pytest.fixture
def fake_http_session():
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-12345",
                    "descriptions": [{"lang": "en", "value": "Bad thing"}],
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
                    "published": "2021-03-04T05:15:00.000",
                }
            }
        ]
    }
    session.get.return_value = resp
    return session


def test_match_cves_uses_cpe_and_caches(tmp_path, monkeypatch, fake_http_session):
    # isolated DB
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'e2e.db'}")
    from backend.config import get_settings
    get_settings.cache_clear()
    init_db()

    port = PortResult(
        number=22,
        service=ServiceInfo(name="ssh", product="OpenSSH", version="8.2p1", extra="Ubuntu-4ubuntu0.5"),
    )
    scan_result = ScanResult(target="127.0.0.1")
    scan_result.hosts.append(__import__("scanner.models", fromlist=["HostResult"]).HostResult(ip="127.0.0.1"))
    scan_result.hosts[0].ports.append(port)

    with session_scope() as db:
        results = cve_matcher.match_cves_for_scan(scan_result, db, http_session=fake_http_session)

    assert len(results) == 1
    cves = results[0]
    assert any(c.cve_id == "CVE-2021-12345" for c in cves)
    assert any(c.cvss.severity == "CRITICAL" for c in cves)

    # Second call should hit the cache and NOT call requests.get again.
    fake_http_session.get.reset_mock()
    with session_scope() as db:
        again = cve_matcher.match_cves_for_scan(scan_result, db, http_session=fake_http_session)
    assert fake_http_session.get.call_count == 0
    assert again[0] and again[0][0].cve_id == "CVE-2021-12345"


def test_match_cves_handles_nvd_unreachable(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'unreach.db'}")
    from backend.config import get_settings
    get_settings.cache_clear()
    init_db()

    bad = MagicMock()
    bad.get.side_effect = RuntimeError("network down")
    port = PortResult(
        number=80,
        service=ServiceInfo(name="http", product="nginx", version="1.18.0"),
    )

    with session_scope() as db:
        cves = cve_matcher.match_cves_for_port(port, db, http_session=bad)

    # Failure path: empty list, no crash.
    assert cves == []


def test_match_cves_handles_rate_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'ratelimit.db'}")
    from backend.config import get_settings
    get_settings.cache_clear()
    init_db()

    rl = MagicMock()
    rl_resp = MagicMock()
    rl_resp.status_code = 429
    rl.get.return_value = rl_resp
    port = PortResult(
        number=443,
        service=ServiceInfo(name="https", product="nginx", version="1.18.0"),
    )
    with session_scope() as db:
        cves = cve_matcher.match_cves_for_port(port, db, http_session=rl)
    assert cves == []
