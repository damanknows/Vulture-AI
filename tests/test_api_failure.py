import pytest
import threat_intel

def test_nvd_api_failure(monkeypatch):
    def mock_fetch(url, headers=None):
        return {"error": "Connection timeout"}
        
    monkeypatch.setattr(threat_intel, "_fetch_url", mock_fetch)
    
    res = threat_intel.fetch_nvd("CVE-2021-44228")
    assert "error" in res
    assert res["error"] == "Connection timeout"
    assert res["source_record_id"] == "CVE-2021-44228"
    assert "data" not in res
