"""
Vulture-AI Context-Aware Baseline Implementations
=================================================

Implements four context-aware baseline scoring methods:
1. EPSS × Exposure
2. Exposure × Asset Criticality
3. Context-Enhanced CVSS
4. EPSS × Context

All baselines use consistent feature normalization and missing-data handling.

Normalization scheme:
- CVSS: cvss_score / 10.0 → [0, 1]
- EPSS: already [0, 1]
- KEV: binary (0 or 1)
- Exposure: network_exposure, already [0, 1]
- Asset Criticality: asset_criticality, already [0, 1]

Missing data policy (matches VRS):
- Missing CVSS: score = None (cannot compute context-enhanced CVSS)
- Missing EPSS: defaults to 0.0
- Missing Exposure: defaults to 0.5
- Missing Asset Criticality: defaults to 0.5
- Missing KEV: defaults to 0.0
"""

def _extract_max_metric(finding: dict, key: str, default=None):
    """Extract maximum value from CVE matches."""
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


def compute_baseline_epss_exposure(finding: dict, policies: dict = None) -> float:
    """
    Baseline 1: EPSS × Exposure
    
    Rationale: Exploitation probability × reachability
    
    score = EPSS × Exposure (product of two [0,1] values)
    """
    if policies is None:
        policies = {
            "missing_epss_default": 0.0,
            "missing_exposure_default": 0.5,
        }
    
    # EPSS
    epss = _extract_max_metric(finding, "epss_probability")
    if epss is None:
        epss = policies["missing_epss_default"]
    
    # Exposure
    base_info = finding.get("finding", {})
    exposure = base_info.get("network_exposure")
    if exposure is None:
        exposure = policies["missing_exposure_default"]
    
    return epss * exposure


def compute_baseline_exposure_criticality(finding: dict, policies: dict = None) -> float:
    """
    Baseline 2: Exposure × Asset Criticality
    
    Rationale: Reachability × importance
    
    score = Exposure × AssetCriticality (product of two [0,1] values)
    """
    if policies is None:
        policies = {
            "missing_exposure_default": 0.5,
            "missing_criticality_default": 0.5,
        }
    
    # Exposure
    base_info = finding.get("finding", {})
    exposure = base_info.get("network_exposure")
    if exposure is None:
        exposure = policies["missing_exposure_default"]
    
    # Asset Criticality
    criticality = base_info.get("asset_criticality")
    if criticality is None:
        criticality = policies["missing_criticality_default"]
    
    return exposure * criticality


def compute_baseline_context_enhanced_cvss(finding: dict, policies: dict = None) -> float:
    """
    Baseline 3: Context-Enhanced CVSS
    
    Rationale: Base severity amplified by context (exposure and criticality)
    
    score = CVSS_norm × (0.5 + 0.5 × Exposure) × (0.5 + 0.5 × AssetCriticality)
    
    This formula:
    - Multiplies normalized CVSS by context factors
    - Ensures that maximum context (1.0, 1.0) gives 1.0x multiplier
    - Ensures that zero context (0, 0) still uses base CVSS (0.5x multiplier)
    - Returns None if CVSS is missing
    """
    if policies is None:
        policies = {
            "missing_exposure_default": 0.5,
            "missing_criticality_default": 0.5,
        }
    
    # CVSS (required)
    cvss = _extract_max_metric(finding, "cvss_score")
    if cvss is None:
        return None  # Cannot compute without CVSS
    
    if not (0.0 <= cvss <= 10.0):
        raise ValueError(f"CVSS out of range: {cvss}")
    
    cvss_norm = cvss / 10.0
    
    # Exposure
    base_info = finding.get("finding", {})
    exposure = base_info.get("network_exposure")
    if exposure is None:
        exposure = policies["missing_exposure_default"]
    
    # Asset Criticality
    criticality = base_info.get("asset_criticality")
    if criticality is None:
        criticality = policies["missing_criticality_default"]
    
    # Context-enhanced formula
    context_factor_exposure = 0.5 + 0.5 * exposure      # [0.5, 1.0]
    context_factor_criticality = 0.5 + 0.5 * criticality  # [0.5, 1.0]
    
    score = cvss_norm * context_factor_exposure * context_factor_criticality
    return score


def compute_baseline_epss_context(finding: dict, policies: dict = None) -> float:
    """
    Baseline 4: EPSS × Context
    
    Rationale: Exploitation probability amplified by environmental context
    
    score = EPSS × (0.5 + 0.5 × Exposure) × (0.5 + 0.5 × AssetCriticality)
    
    Similar to context-enhanced CVSS but uses EPSS as base metric instead.
    """
    if policies is None:
        policies = {
            "missing_epss_default": 0.0,
            "missing_exposure_default": 0.5,
            "missing_criticality_default": 0.5,
        }
    
    # EPSS
    epss = _extract_max_metric(finding, "epss_probability")
    if epss is None:
        epss = policies["missing_epss_default"]
    
    # Exposure
    base_info = finding.get("finding", {})
    exposure = base_info.get("network_exposure")
    if exposure is None:
        exposure = policies["missing_exposure_default"]
    
    # Asset Criticality
    criticality = base_info.get("asset_criticality")
    if criticality is None:
        criticality = policies["missing_criticality_default"]
    
    # Context factors
    context_factor_exposure = 0.5 + 0.5 * exposure
    context_factor_criticality = 0.5 + 0.5 * criticality
    
    score = epss * context_factor_exposure * context_factor_criticality
    return score


if __name__ == "__main__":
    # Demonstrate baselines on a synthetic finding
    test_finding = {
        "finding": {
            "network_exposure": 0.7,
            "asset_criticality": 0.9,
        },
        "cve_matches": [
            {
                "cvss_score": 8.5,
                "epss_probability": 0.75,
                "kev_listed": False,
            }
        ]
    }
    
    print("Context-Aware Baseline Demonstration")
    print("=" * 60)
    print(f"Input: CVSS=8.5, EPSS=0.75, Exposure=0.7, Criticality=0.9")
    print()
    print(f"Baseline 1 (EPSS × Exposure):              {compute_baseline_epss_exposure(test_finding):.4f}")
    print(f"Baseline 2 (Exposure × Criticality):       {compute_baseline_exposure_criticality(test_finding):.4f}")
    print(f"Baseline 3 (Context-Enhanced CVSS):        {compute_baseline_context_enhanced_cvss(test_finding):.4f}")
    print(f"Baseline 4 (EPSS × Context):               {compute_baseline_epss_context(test_finding):.4f}")
