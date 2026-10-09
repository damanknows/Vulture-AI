import sys
import os
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Inject vulmap-pro path to reuse existing NVD normalization
# rather than duplicating it.

import sys
import os

vulmap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulmap-pro")
if vulmap_path not in sys.path:
    sys.path.insert(0, vulmap_path)

# Safe import hack to avoid shadowing by root scanner.py
original_scanner = sys.modules.pop("scanner", None)
try:
    import scanner.cve_matcher as vulmap_cve_matcher
    normalize_service_string = vulmap_cve_matcher.normalize_service_string
    build_cpe_uris = vulmap_cve_matcher.build_cpe_uris
    _parse_cvss = vulmap_cve_matcher._parse_cvss
finally:
    if original_scanner:
        sys.modules["scanner"] = original_scanner

from threat_intel import search_nvd_by_cpe, search_nvd, fetch_epss, fetch_kev
from models import VulnerabilityRecord

logger = logging.getLogger(__name__)

def match_findings_to_cves(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Cache KEV locally for the batch
    kev_resp = fetch_kev()
    kev_set = set(kev_resp.get("data", {}).get("cves", [])) if not kev_resp.get("error") else set()
    
    enriched_findings = []
    
    for finding in findings:
        product = finding.get("product")
        version = finding.get("version")
        service = finding.get("service")
        
        cve_records: List[VulnerabilityRecord] = []
        cve_ids_to_fetch_epss = []
        
        if not product and not service:
            # Cannot match without product or service
            enriched_findings.append({
                "finding": finding,
                "cve_matches": []
            })
            continue
            
        # 1. Attempt CPE matching using the existing vulmap-pro normalizer
        # normalize_service_string returns (vendor, product, version)
        norm = normalize_service_string(product, version, "")
        
        if norm:
            vendor, norm_product, norm_version = norm
            cpe_candidates = build_cpe_uris(vendor, norm_product, norm_version)
            
            for cpe in cpe_candidates:
                nvd_resp = search_nvd_by_cpe(cpe)
                if not nvd_resp.get("error") and "data" in nvd_resp:
                    vulnerabilities = nvd_resp["data"].get("vulnerabilities", [])
                    for v_item in vulnerabilities:
                        rec = _build_record(v_item, finding, cpe, "confirmed")
                        if rec:
                            cve_records.append(rec)
                            cve_ids_to_fetch_epss.append(rec.cve_id)
                # Break after first successful CPE to avoid explosions? No, gather all matches.
                # Actually, NVD API limits to 20 per request by default in vulmap-pro, here we use default.
                
        # 2. If no matches from CPE, fall back to keyword search (Candidate)
        if not cve_records and product:
            keyword = product
            if version:
                keyword = f"{product} {version}"
            
            nvd_resp = search_nvd(keyword)
            if not nvd_resp.get("error") and "data" in nvd_resp:
                vulnerabilities = nvd_resp["data"].get("vulnerabilities", [])
                for v_item in vulnerabilities[:10]: # Limit to top 10 candidates
                    rec = _build_record(v_item, finding, f"keyword:{keyword}", "candidate")
                    if rec:
                        cve_records.append(rec)
                        cve_ids_to_fetch_epss.append(rec.cve_id)
                        
        # 3. Fetch EPSS for matched CVEs
        epss_scores = {}
        if cve_ids_to_fetch_epss:
            epss_resp = fetch_epss(cve_ids_to_fetch_epss)
            if not epss_resp.get("error"):
                epss_scores = epss_resp.get("data", {})
                
        # 4. Enrich records with EPSS and KEV
        for rec in cve_records:
            if rec.cve_id in kev_set:
                rec.kev_listed = True
            else:
                rec.kev_listed = False
                
            epss_data = epss_scores.get(rec.cve_id)
            if epss_data:
                rec.epss_probability = epss_data.get("epss")
                rec.epss_date = epss_data.get("date")
                
        # Format for output
        finding_matches = [rec.to_dict() for rec in cve_records]
        # De-duplicate by CVE ID prioritizing confirmed matches
        dedup = {}
        for fm in finding_matches:
            cid = fm["cve_id"]
            if cid not in dedup or fm["match_confidence"] == "confirmed":
                dedup[cid] = fm
                
        enriched_findings.append({
            "finding": finding,
            "cve_matches": list(dedup.values())
        })
        
    return enriched_findings

def _build_record(v_item: dict, finding: dict, match_basis: str, confidence: str) -> Optional[VulnerabilityRecord]:
    cve = v_item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
        
    metrics = cve.get("metrics") or {}
    cvss = _parse_cvss(metrics)
    
    return VulnerabilityRecord(
        cve_id=cve_id,
        cvss_score=cvss.score,
        cvss_version="3" if cvss.score else None,
        cvss_severity=cvss.severity,
        epss_probability=None,
        epss_date=None,
        kev_listed=None,
        affected_product=finding.get("product"),
        affected_version_range=finding.get("version"),
        match_confidence=confidence,
        match_status="matched",
        evidence_sources=[{"source": "nvd", "rationale": match_basis}],
        retrieved_at=datetime.now(timezone.utc).isoformat()
    )
