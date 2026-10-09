"""
Vulture Risk Score (VRS) - Core Risk Engine
===========================================

This module computes a transparent, deterministic vulnerability ranking score called 
the Vulture Risk Score (VRS). It combines five normalized components into a final score:

Formula: VRS = 100 * (w_C * C + w_E * E + w_K * K + w_N * N + w_A * A)

Components:
- C: Normalized CVSS severity (cvss_score / 10.0).
- E: EPSS probability (0.0 to 1.0).
- K: CISA KEV listing status (1.0 if in KEV, else 0.0).
- N: Network exposure score (0.0 to 1.0).
- A: Asset criticality score (0.0 to 1.0).

Initial unvalidated exploratory weights (vrs-v1):
w_C=0.25, w_E=0.20, w_K=0.20, w_N=0.20, w_A=0.15

Policy for missing data:
- Missing CVSS: The finding cannot be fully scored. VRS will be None (Unavailable).
- Missing EPSS: Default to missing_epss_default (default 0.0) and flag as uncertain.
- Missing Network Exposure: Default to missing_exposure_default (default 0.5) and flag.
- Missing Asset Criticality: Default to missing_criticality_default (default 0.5) and flag.
- Missing KEV: Default to 0.0.

Tie-breaking rules for ranking:
1. Bucket (urgent KEV matches sort first).
2. VRS score (descending).
3. Primary CVE ID (alphabetical, ascending).
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
    total = sum(weights.values())
    if not math.isclose(total, 1.0, abs_tol=1e-6):
        raise ValueError(f"Weights must sum to 1.0, got {total}")
    for k, v in weights.items():
        if v < 0:
            raise ValueError(f"Weight {k} cannot be negative")

def _extract_max_metric(finding: dict, key: str, default=None):
    cve_matches = finding.get("cve_matches", [])
    if not cve_matches:
        return default
        
    values = []
    for m in cve_matches:
        val = m.get(key)
        if val is not None:
            values.append(val)
            
    if not values:
        return default
    return max(values)

def compute_vrs(finding: dict, weights: dict = None, policies: dict = None) -> dict:
    if weights is None:
        weights = DEFAULT_WEIGHTS
    if policies is None:
        policies = {
            "missing_epss_default": 0.0,
            "missing_exposure_default": 0.5,
            "missing_criticality_default": 0.5
        }
        
    validate_weights(weights)
    missing_data = []
    uncertainties = []
    
    # C: CVSS
    cvss = _extract_max_metric(finding, "cvss_score")
    if cvss is None:
        missing_data.append("cvss_score")
        C = None
    else:
        if not (0.0 <= cvss <= 10.0):
            raise ValueError(f"CVSS out of range: {cvss}")
        C = cvss / 10.0
        
    # E: EPSS
    raw_epss = _extract_max_metric(finding, "epss_probability")
    if raw_epss is None:
        missing_data.append("epss_probability")
        uncertainties.append("Treated missing EPSS as default policy value")
        E = policies["missing_epss_default"]
    else:
        if not (0.0 <= raw_epss <= 1.0):
            raise ValueError(f"EPSS out of range: {raw_epss}")
        E = raw_epss
        
    # K: KEV
    # KEV is boolean in the new data model
    kev = _extract_max_metric(finding, "kev_listed")
    if kev is None:
        missing_data.append("kev_listed")
        K = 0.0
    else:
        K = 1.0 if kev else 0.0
        
    # N & A
    base_info = finding.get("finding", {})
    N_raw = base_info.get("network_exposure")
    if N_raw is None:
        missing_data.append("network_exposure")
        uncertainties.append("Treated missing network_exposure as default policy value")
        N = policies["missing_exposure_default"]
    else:
        N = float(N_raw)
        if not (0.0 <= N <= 1.0):
            raise ValueError(f"Network exposure out of range: {N}")
            
    A_raw = base_info.get("asset_criticality")
    if A_raw is None:
        missing_data.append("asset_criticality")
        uncertainties.append("Treated missing asset_criticality as default policy value")
        A = policies["missing_criticality_default"]
    else:
        A = float(A_raw)
        if not (0.0 <= A <= 1.0):
            raise ValueError(f"Asset criticality out of range: {A}")
            
    if C is None:
        vrs = None
        bucket = "unavailable"
    else:
        vrs = 100 * (
            weights["w_C"] * C +
            weights["w_E"] * E +
            weights["w_K"] * K +
            weights["w_N"] * N +
            weights["w_A"] * A
        )
        bucket = "urgent" if K == 1.0 and weights.get("w_K", 0) > 0 else "standard"
        
    return {
        "vrs": round(vrs, 2) if vrs is not None else None,
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
        "data_completeness": "complete" if not missing_data else "partial",
        "missing_data": missing_data,
        "uncertainties": uncertainties
    }

def compute_cvss_only(finding: dict) -> float:
    cvss = _extract_max_metric(finding, "cvss_score")
    if cvss is None:
        return None
    return round(100 * (cvss / 10.0), 2)

def compute_epss_only(finding: dict) -> float:
    raw_epss = _extract_max_metric(finding, "epss_probability")
    if raw_epss is None:
        return None
    return round(100 * raw_epss, 2)

def compute_cvss_epss_kev(finding: dict) -> float:
    cvss = _extract_max_metric(finding, "cvss_score")
    raw_epss = _extract_max_metric(finding, "epss_probability")
    kev = _extract_max_metric(finding, "kev_listed")
    
    if cvss is None:
        return None
        
    C = cvss / 10.0
    E = raw_epss if raw_epss is not None else 0.0
    K = 1.0 if kev else 0.0
    
    score = 100 * ( (1/3) * C + (1/3) * E + (1/3) * K )
    return round(score, 2)

def rank_findings(findings: list, weights: dict = None, policies: dict = None) -> list:
    scored_findings = []
    for f in findings:
        score_data = compute_vrs(f, weights, policies)
        
        cves = [m.get("cve_id", "") for m in f.get("cve_matches", []) if m.get("cve_id")]
        primary_cve = min(cves) if cves else "Z_NO_CVE" 
        
        scored_findings.append({
            "finding_data": f,
            "score_data": score_data,
            "primary_cve": primary_cve
        })
    
    # bucket sorts: urgent -> standard -> unavailable
    def bucket_rank(b):
        if b == "urgent": return 0
        if b == "standard": return 1
        return 2
        
    scored_findings.sort(key=lambda x: (
        bucket_rank(x["score_data"]["bucket"]),
        -x["score_data"]["vrs"] if x["score_data"]["vrs"] is not None else float('inf'),
        x["primary_cve"]
    ))
    
    return scored_findings
