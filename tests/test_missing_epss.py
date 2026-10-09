import pytest
from risk_engine import compute_vrs

def test_missing_epss_degrades_gracefully():
    finding = {
        "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
        "cve_matches": [
            {
                "cve_id": "CVE-TEST",
                "cvss_score": 5.0,
                "kev_listed": False
                # Missing epss_probability
            }
        ]
    }

    res = compute_vrs(finding)
    assert "epss_probability" in res["missing_data"]
    assert res["components"]["E"] == 0.0 # Handled by default policy
    assert any("Treated missing EPSS" in u for u in res["uncertainties"])
