import pytest
import datetime
import cve_matcher

# Mock responses
MOCK_NVD_RESP = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"value": "Log4j RCE"}]
            }
        }
    ]
}

MOCK_EPSS_RESP = {
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.95"}
    ]
}

MOCK_KEV_RESP = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228"}
    ]
}

@pytest.fixture(autouse=True)
def mock_threat_intel(monkeypatch):
    def mock_search_nvd(keyword):
        return {
            "source": "nvd",
            "source_record_id": f"search:{keyword}",
            "retrieved_at": datetime.datetime.now().isoformat(),
            "data": MOCK_NVD_RESP if "apache" in keyword.lower() else {"vulnerabilities": []}
        }

    def mock_fetch_epss(cve_ids):
        results = {}
        for cve in cve_ids:
            if cve == "CVE-2021-44228":
                results[cve] = 0.95
        return {
            "source": "epss",
            "source_record_id": "batch",
            "retrieved_at": datetime.datetime.now().isoformat(),
            "data": results
        }

    def mock_fetch_kev():
        return {
            "source": "kev",
            "source_record_id": "cisa_kev",
            "retrieved_at": datetime.datetime.now().isoformat(),
            "data": {"cves": ["CVE-2021-44228"]}
        }
        
    monkeypatch.setattr(cve_matcher, "search_nvd", mock_search_nvd)
    monkeypatch.setattr(cve_matcher, "fetch_epss", mock_fetch_epss)
    monkeypatch.setattr(cve_matcher, "fetch_kev", mock_fetch_kev)

def test_match_known_cve_and_product():
    finding = {"product": "apache http_server", "version": "2.4.49"}
    results = cve_matcher.match_findings_to_cves([finding])
    
    assert len(results) == 1
    enriched = results[0]
    
    assert len(enriched["cve_matches"]) == 1
    match = enriched["cve_matches"][0]
    assert match["cve_id"] == "CVE-2021-44228"
    assert match["match_confidence"] == "high"
    assert "rationale" in match["match_rationale"].lower() or "keyword match" in match["match_rationale"].lower()
    
    assert enriched["epss_scores"].get("CVE-2021-44228") == 0.95
    assert "CVE-2021-44228" in enriched["kev_matches"]

def test_unknown_version_yields_low_confidence():
    finding = {"product": "apache http_server", "version": None}
    results = cve_matcher.match_findings_to_cves([finding])
    
    enriched = results[0]
    assert len(enriched["cve_matches"]) == 1
    match = enriched["cve_matches"][0]
    
    assert match["match_confidence"] == "low"
    assert "version unknown" in match["match_rationale"].lower()

def test_missing_epss_handled(monkeypatch):
    def mock_fetch_epss_error(cve_ids):
        return {
            "source": "epss",
            "source_record_id": "batch",
            "retrieved_at": datetime.datetime.now().isoformat(),
            "error": "API rate limited"
        }
    monkeypatch.setattr(cve_matcher, "fetch_epss", mock_fetch_epss_error)
    
    finding = {"product": "apache http_server", "version": "2.4.49"}
    results = cve_matcher.match_findings_to_cves([finding])
    
    enriched = results[0]
    assert isinstance(enriched["epss_scores"], dict)
    assert len(enriched["epss_scores"]) == 0
