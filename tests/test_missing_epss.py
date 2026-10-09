import pytest
from risk_engine import compute_vrs

def test_missing_epss_degrades_gracefully():
    finding = {
        "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
        "cve_matches": [
            {
                "cve_id": "CVE-TEST",
                "intel": {"data": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]}}}
            }
        ],
        "epss_scores": {},  # Missing EPSS
        "kev_matches": []
    }
    
    res = compute_vrs(finding)
    assert "epss_missing" in res["missing_data"]
    assert res["components"]["E"] == 0.0
    assert res["vrs"] > 0  # Should still compute a score based on CVSS
