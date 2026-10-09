import pytest
import datetime
import os
import cve_matcher
import threat_intel
import json

# Fixtures for deterministic testing
MOCK_NVD_RESP = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]
                }
            }
        }
    ]
}

@pytest.fixture(autouse=True)
def mock_threat_intel(monkeypatch):
    def mock_search_nvd_by_cpe(cpe):
        if "log4j" in cpe.lower() or "apache" in cpe.lower():
            return {"data": MOCK_NVD_RESP, "retrieved_at": "2026-01-01T00:00:00Z"}
        return {"data": {"vulnerabilities": []}, "retrieved_at": "2026-01-01T00:00:00Z"}
        
    def mock_search_nvd(keyword):
        if "apache" in keyword.lower():
            return {"data": MOCK_NVD_RESP, "retrieved_at": "2026-01-01T00:00:00Z"}
        return {"data": {"vulnerabilities": []}, "retrieved_at": "2026-01-01T00:00:00Z"}

    def mock_fetch_epss(cve_ids):
        results = {}
        for cve in cve_ids:
            if cve == "CVE-2021-44228":
                results[cve] = {"epss": 0.95, "date": "2026-01-01"}
        return {"data": results, "retrieved_at": "2026-01-01T00:00:00Z"}

    def mock_fetch_kev():
        return {"data": {"cves": ["CVE-2021-44228"]}, "retrieved_at": "2026-01-01T00:00:00Z"}
        
    monkeypatch.setattr(cve_matcher, "search_nvd_by_cpe", mock_search_nvd_by_cpe)
    monkeypatch.setattr(cve_matcher, "search_nvd", mock_search_nvd)
    monkeypatch.setattr(cve_matcher, "fetch_epss", mock_fetch_epss)
    monkeypatch.setattr(cve_matcher, "fetch_kev", mock_fetch_kev)

def test_match_known_cve_and_product():
    finding = {"product": "apache http_server", "version": "2.4.49", "service": "http"}
    results = cve_matcher.match_findings_to_cves([finding])
    
    assert len(results) == 1
    enriched = results[0]
    
    assert len(enriched["cve_matches"]) == 1
    match = enriched["cve_matches"][0]
    assert match["cve_id"] == "CVE-2021-44228"
    assert match["match_confidence"] == "confirmed"
    assert match["epss_probability"] == 0.95
    assert match["kev_listed"] is True
    assert match["cvss_score"] == 10.0

def test_missing_data_handled():
    finding = {"product": "unknown_product", "version": "1.0", "service": "unknown"}
    results = cve_matcher.match_findings_to_cves([finding])
    
    assert len(results) == 1
    assert len(results[0]["cve_matches"]) == 0

def test_api_failure_handled(monkeypatch):
    def mock_error(*args, **kwargs):
        return {"error": "API rate limited"}
    monkeypatch.setattr(cve_matcher, "search_nvd_by_cpe", mock_error)
    monkeypatch.setattr(cve_matcher, "search_nvd", mock_error)
    monkeypatch.setattr(cve_matcher, "fetch_epss", mock_error)
    monkeypatch.setattr(cve_matcher, "fetch_kev", mock_error)
    
    finding = {"product": "apache http_server", "version": "2.4.49"}
    results = cve_matcher.match_findings_to_cves([finding])
    assert len(results[0]["cve_matches"]) == 0

def test_cache_behavior(tmp_path, monkeypatch):
    monkeypatch.setattr(threat_intel, "CACHE_DIR", str(tmp_path))
    
    # Force a real mock of requests.get to test caching
    class MockResponse:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"data": {"cves": ["CVE-CACHE"]}}
    
    call_count = 0
    def mock_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return MockResponse()
        
    import requests
    monkeypatch.setattr(requests, "get", mock_get)
    
    # First call should hit requests.get
    res1 = threat_intel.fetch_kev()
    assert call_count == 1
    
    # Second call should use cache
    res2 = threat_intel.fetch_kev()
    assert call_count == 1
    assert res1["data"]["cves"] == res2["data"]["cves"]
