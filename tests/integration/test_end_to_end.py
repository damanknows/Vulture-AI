import pytest
from scanner import scan_target
from threat_intel import search_nvd, fetch_epss, fetch_kev
from cve_matcher import match_findings_to_cves
from risk_engine import compute_vrs

@pytest.mark.integration
@pytest.mark.skip(reason="Integration test requiring network/Nmap")
def test_full_pipeline():
    # 1. Scan (Assuming localhost is allowed and has something running)
    scan_res = scan_target("127.0.0.1", ports="22,80,443")
    assert scan_res["scan_status"] == "completed"
    
    # 2. Enrich
    enriched = match_findings_to_cves(scan_res["findings"])
    
    # 3. Score
    for f in enriched:
        # Mock asset criticality for testing
        f["finding"]["asset_criticality"] = 0.8
        f["finding"]["network_exposure"] = 0.5
        score = compute_vrs(f)
        assert "vrs" in score
        assert "bucket" in score
