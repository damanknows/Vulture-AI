import json
from threat_intel import search_nvd, fetch_epss, fetch_kev

def match_findings_to_cves(findings: list[dict]) -> list[dict]:
    # Cache KEV locally for the batch
    kev_resp = fetch_kev()
    kev_set = set(kev_resp.get("data", {}).get("cves", [])) if not kev_resp.get("error") else set()
    
    enriched_findings = []
    
    for finding in findings:
        product = finding.get("product")
        version = finding.get("version")
        
        cve_matches = []
        cve_ids_to_fetch_epss = []
        
        if not product:
            # Cannot match without product
            enriched_findings.append({
                "finding": finding,
                "cve_matches": [],
                "epss_scores": {},
                "kev_matches": []
            })
            continue
            
        keyword = product
        confidence = "medium"
        rationale = f"Keyword match on product: {product}"
        
        if version:
            keyword = f"{product} {version}"
            confidence = "high"
            rationale = f"Keyword match on product and version: {product} {version}"
        else:
            rationale += " (Warning: version unknown, confidence reduced to low)"
            confidence = "low"
            
        nvd_resp = search_nvd(keyword)
        if not nvd_resp.get("error") and "data" in nvd_resp:
            vulnerabilities = nvd_resp["data"].get("vulnerabilities", [])
            # To avoid exploding results, let's limit matches to top 10
            for v_item in vulnerabilities[:10]:
                cve_data = v_item.get("cve", {})
                cve_id = cve_data.get("id")
                if cve_id:
                    cve_matches.append({
                        "cve_id": cve_id,
                        "match_rationale": rationale,
                        "match_confidence": confidence,
                        "intel": {
                            "source": "nvd",
                            "source_record_id": cve_id,
                            "retrieved_at": nvd_resp["retrieved_at"],
                            "data": cve_data
                        }
                    })
                    cve_ids_to_fetch_epss.append(cve_id)
        
        # Fetch EPSS for matched CVEs
        epss_scores = {}
        if cve_ids_to_fetch_epss:
            epss_resp = fetch_epss(cve_ids_to_fetch_epss)
            if not epss_resp.get("error"):
                epss_scores = epss_resp.get("data", {})
                
        # Determine KEV matches
        kev_matches = [cid for cid in cve_ids_to_fetch_epss if cid in kev_set]
        
        enriched_findings.append({
            "finding": finding,
            "cve_matches": cve_matches,
            "epss_scores": epss_scores,
            "kev_matches": kev_matches
        })
        
    return enriched_findings
