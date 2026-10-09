"""
Vulture Risk Score (VRS) - Core Risk Engine
===========================================

This module computes a transparent, deterministic vulnerability ranking score called 
the Vulture Risk Score (VRS). It combines five normalized components into a final score:

Formula: VRS = 100 * (w_C * C + w_E * E + w_K * K + w_N * N + w_A * A)

Components:
- C: Normalized CVSS severity (cvss_base_score / 10.0). Source: Common Vulnerability Scoring System (CVSS).
- E: EPSS probability (0.0 to 1.0). Source: Exploit Prediction Scoring System (EPSS).
- K: CISA KEV listing status (1 if in KEV, else 0). Source: CISA Known Exploited Vulnerabilities catalog.
- N: Network exposure score (0.0 to 1.0, default 0.5). Sourced from asset metadata.
- A: Asset criticality score (0.0 to 1.0, default 0.5). Sourced from asset metadata.

Initial weights (vrs-v1):
w_C=0.25, w_E=0.20, w_K=0.20, w_N=0.20, w_A=0.15

Policy Override:
If K == 1 (KEV listed), the finding is classified into an "urgent" bucket regardless 
of the numerical VRS.
"""

import math

DEFAULT_WEIGHTS = {
    "w_C": 0.25,
    "w_E": 0.20,
    "w_K": 0.20,
    "w_N": 0.20,
    "w_A": 0.15
}

def validate_weights(weights: dict):
    """Ensure weights sum to 1.0 and are non-negative."""
    total = sum(weights.values())
    if not math.isclose(total, 1.0, abs_tol=1e-6):
        raise ValueError(f"Weights must sum to 1.0, got {total}")
    for k, v in weights.items():
        if v < 0:
            raise ValueError(f"Weight {k} cannot be negative")

def _extract_max_cvss(enriched_finding: dict) -> float:
    max_score = 0.0
    for match in enriched_finding.get("cve_matches", []):
        data = match.get("intel", {}).get("data", {})
        metrics = data.get("metrics", {})
        # Try v31, then v30, then v2
        score = 0.0
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
        elif "cvssMetricV30" in metrics:
            score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)
        max_score = max(max_score, float(score))
    return max_score

def _extract_max_epss(enriched_finding: dict) -> float:
    epss_dict = enriched_finding.get("epss_scores", {})
    if not epss_dict:
        return -1.0 # Indicator for missing
    return float(max(epss_dict.values()))

def compute_vrs(finding: dict, weights: dict = None) -> dict:
    """Computes VRS for a given EnrichedFinding dict."""
    if weights is None:
        weights = DEFAULT_WEIGHTS
    
    validate_weights(weights)
    
    missing_data = []
    
    # C: CVSS
    cvss = _extract_max_cvss(finding)
    if cvss == 0.0 and not finding.get("cve_matches"):
        missing_data.append("cvss_missing")
    C = cvss / 10.0
    
    # E: EPSS
    raw_epss = _extract_max_epss(finding)
    if raw_epss < 0:
        E = 0.0
        missing_data.append("epss_missing")
    else:
        E = raw_epss
        
    # K: KEV
    kev_matches = finding.get("kev_matches", [])
    K = 1.0 if kev_matches else 0.0
    
    # N & A
    base_info = finding.get("finding", {})
    N = float(base_info.get("network_exposure", 0.5))
    A = float(base_info.get("asset_criticality", 0.5))
    
    vrs = 100 * (
        weights["w_C"] * C +
        weights["w_E"] * E +
        weights["w_K"] * K +
        weights["w_N"] * N +
        weights["w_A"] * A
    )
    
    # Policy override bucket
    bucket = "urgent" if K == 1.0 else "standard"
    
    return {
        "vrs": round(vrs, 2),
        "bucket": bucket,
        "components": {
            "C": C,
            "E": E,
            "K": K,
            "N": N,
            "A": A
        },
        "weights": weights,
        "formula_version": "vrs-v1",
        "missing_data": missing_data
    }

def compute_cvss_only(finding: dict) -> float:
    """Baseline: CVSS only."""
    C = _extract_max_cvss(finding) / 10.0
    return round(100 * C, 2)

def compute_epss_only(finding: dict) -> float:
    """Baseline: EPSS only."""
    raw_epss = _extract_max_epss(finding)
    E = raw_epss if raw_epss >= 0 else 0.0
    return round(100 * E, 2)

def compute_cvss_epss_kev(finding: dict) -> float:
    """Baseline: C, E, K equally weighted (33.3% each)."""
    C = _extract_max_cvss(finding) / 10.0
    raw_epss = _extract_max_epss(finding)
    E = raw_epss if raw_epss >= 0 else 0.0
    K = 1.0 if finding.get("kev_matches") else 0.0
    
    score = 100 * ( (1/3) * C + (1/3) * E + (1/3) * K )
    return round(score, 2)

def rank_findings(findings: list, weights: dict = None) -> list:
    """Ranks findings by bucket (urgent first), then VRS descending, then by primary CVE ID."""
    scored_findings = []
    for f in findings:
        score_data = compute_vrs(f, weights)
        
        # Determine primary CVE ID for tie-breaking
        cves = [m.get("cve_id", "") for m in f.get("cve_matches", [])]
        primary_cve = min(cves) if cves else "Z" # 'Z' ensures findings without CVEs sink to bottom on tie
        
        scored_findings.append({
            "finding_data": f,
            "score_data": score_data,
            "primary_cve": primary_cve
        })
    
    # Sort key:
    # 1. Bucket: 'urgent' > 'standard'. 'urgent' sorts first, so we use 0 for urgent, 1 for standard
    # 2. VRS: descending (negative)
    # 3. CVE: alphabetical ascending
    scored_findings.sort(key=lambda x: (
        0 if x["score_data"]["bucket"] == "urgent" else 1,
        -x["score_data"]["vrs"],
        x["primary_cve"]
    ))
    
    return scored_findings
