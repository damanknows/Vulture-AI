import pytest
from risk_engine import (
    compute_vrs, rank_findings, validate_weights,
    compute_cvss_only, compute_epss_only, compute_cvss_epss_kev
)

def make_finding(cve_id, cvss, epss, kev, n=0.5, a=0.5):
    finding = {"finding": {}}
    if n is not None: finding["finding"]["network_exposure"] = n
    if a is not None: finding["finding"]["asset_criticality"] = a
    
    if cve_id:
        match = {"cve_id": cve_id}
        if cvss is not None: match["cvss_score"] = cvss
        if epss is not None: match["epss_probability"] = epss
        if kev is not None: match["kev_listed"] = kev
        finding["cve_matches"] = [match]
    else:
        finding["cve_matches"] = []
    
    return finding

def test_determinism():
    f1 = make_finding("CVE-1", 7.5, 0.1, False)
    f2 = make_finding("CVE-1", 7.5, 0.1, False)
    assert compute_vrs(f1) == compute_vrs(f2)

def test_kev_override_ranks_above_high_cvss():
    f_kev = make_finding("CVE-KEV", 4.0, 0.5, True)
    f_high = make_finding("CVE-HIGH", 9.8, 0.9, False)
    
    vrs_kev = compute_vrs(f_kev)
    vrs_high = compute_vrs(f_high)
    assert vrs_high["vrs"] > vrs_kev["vrs"]
    
    ranked = rank_findings([f_high, f_kev])
    assert ranked[0]["primary_cve"] == "CVE-KEV"
    assert ranked[0]["score_data"]["bucket"] == "urgent"
    assert ranked[1]["primary_cve"] == "CVE-HIGH"
    assert ranked[1]["score_data"]["bucket"] == "standard"

def test_missing_epss_handling():
    f = make_finding("CVE-X", 5.0, None, False)
    res = compute_vrs(f)
    assert "epss_probability" in res["missing_data"]
    assert res["components"]["E"] == 0.0
    assert any("Treated missing EPSS" in u for u in res["uncertainties"])
    assert res["data_completeness"] == "partial"

def test_missing_cvss_handling():
    f = make_finding("CVE-X", None, 0.5, False)
    res = compute_vrs(f)
    assert res["vrs"] is None
    assert res["bucket"] == "unavailable"

def test_boundary_conditions():
    with pytest.raises(ValueError):
        compute_vrs(make_finding("CVE-X", 11.0, 0.5, False))
    with pytest.raises(ValueError):
        compute_vrs(make_finding("CVE-X", 5.0, 1.5, False))
    with pytest.raises(ValueError):
        compute_vrs(make_finding("CVE-X", 5.0, 0.5, False, n=2.0))

def test_invalid_weights_raises():
    with pytest.raises(ValueError, match="sum to 1.0"):
        validate_weights({"w_C": 0.5, "w_E": 0.5, "w_K": 0.5})
        
    with pytest.raises(ValueError, match="negative"):
        validate_weights({"w_C": -0.1, "w_E": 0.5, "w_K": 0.2, "w_N": 0.2, "w_A": 0.2})

def test_all_baselines():
    f = make_finding("CVE-BASE", 10.0, 1.0, True, 1.0, 1.0)
    
    assert compute_vrs(f)["vrs"] == 100.0
    assert compute_cvss_only(f) == 100.0
    assert compute_epss_only(f) == 100.0
    assert compute_cvss_epss_kev(f) == 100.0
    
    f2 = make_finding("CVE-BASE2", 5.0, 0.0, False, 0.0, 0.0)
    assert compute_vrs(f2)["vrs"] == 12.5  
    assert compute_cvss_only(f2) == 50.0   
    assert compute_epss_only(f2) == 0.0
    assert compute_cvss_epss_kev(f2) == 16.67
