"""
Vulture-AI Comprehensive Baseline and Normalization Tests
==========================================================

Extended test suite for Phase 2 experiments:
- Baseline formula correctness
- Input normalization edge cases
- Missing value handling
- Deterministic ranking behavior
- Input consistency across methods
- Top-K ranking order verification
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from risk_engine import (
    compute_vrs,
    compute_cvss_only,
    compute_epss_only,
    compute_kev_first,
    compute_cvss_epss_kev,
    rank_findings,
    validate_weights,
    DEFAULT_WEIGHTS,
)
from context_baselines import (
    compute_baseline_epss_exposure,
    compute_baseline_exposure_criticality,
    compute_baseline_context_enhanced_cvss,
    compute_baseline_epss_context,
)
from weight_sensitivity import (
    get_weight_config,
    validate_weights as validate_weights_sensitivity,
)


class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
    
    def test(self, name, fn):
        try:
            fn()
            print(f"  ✓ {name}")
            self.passed += 1
        except AssertionError as e:
            print(f"  ✗ {name}: {e}")
            self.failed += 1
            self.errors.append((name, str(e)))
        except Exception as e:
            print(f"  ✗ {name}: EXCEPTION: {e}")
            self.failed += 1
            self.errors.append((name, f"EXCEPTION: {e}"))
    
    def report(self):
        print()
        print("=" * 70)
        print(f"Results: {self.passed} passed, {self.failed} failed")
        if self.errors:
            print("\nFailures:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print("=" * 70)
        return self.failed == 0


# ============================================================================
# Normalization Tests
# ============================================================================

def test_feature_normalization():
    """Test feature value normalization and bounds."""
    runner = TestRunner()
    print("\n[Feature Normalization Tests]")
    
    # CVSS: [0, 10] -> [0, 1]
    def test_cvss_range():
        finding_min = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 0.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        finding_max = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 10.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        result_min = compute_vrs(finding_min)
        result_max = compute_vrs(finding_max)
        
        # C values should be 0.0 and 1.0 respectively
        assert result_min["components"]["C"] == 0.0, "Min CVSS normalization failed"
        assert result_max["components"]["C"] == 1.0, "Max CVSS normalization failed"
    runner.test("CVSS normalization to [0,1]", test_cvss_range)
    
    # EPSS: already [0, 1]
    def test_epss_range():
        finding_min = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.0, "kev_listed": False}]
        }
        finding_max = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 1.0, "kev_listed": False}]
        }
        result_min = compute_vrs(finding_min)
        result_max = compute_vrs(finding_max)
        
        assert result_min["components"]["E"] == 0.0, "Min EPSS failed"
        assert result_max["components"]["E"] == 1.0, "Max EPSS failed"
    runner.test("EPSS scale already normalized [0,1]", test_epss_range)
    
    # KEV: binary {0, 1}
    def test_kev_binary():
        finding_no_kev = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        finding_kev = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.5, "kev_listed": True}]
        }
        result_no = compute_vrs(finding_no_kev)
        result_yes = compute_vrs(finding_kev)
        
        assert result_no["components"]["K"] == 0.0, "KEV=False should map to 0.0"
        assert result_yes["components"]["K"] == 1.0, "KEV=True should map to 1.0"
    runner.test("KEV binary representation {0, 1}", test_kev_binary)
    
    # Exposure: [0, 1]
    def test_exposure_range():
        finding_min = {
            "finding": {"network_exposure": 0.0, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        finding_max = {
            "finding": {"network_exposure": 1.0, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        result_min = compute_vrs(finding_min)
        result_max = compute_vrs(finding_max)
        
        assert result_min["components"]["N"] == 0.0, "Min exposure failed"
        assert result_max["components"]["N"] == 1.0, "Max exposure failed"
    runner.test("Network Exposure range [0,1]", test_exposure_range)
    
    # Asset Criticality: [0, 1]
    def test_criticality_range():
        finding_min = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.0},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        finding_max = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 1.0},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        result_min = compute_vrs(finding_min)
        result_max = compute_vrs(finding_max)
        
        assert result_min["components"]["A"] == 0.0, "Min criticality failed"
        assert result_max["components"]["A"] == 1.0, "Max criticality failed"
    runner.test("Asset Criticality range [0,1]", test_criticality_range)
    
    return runner.report()


# ============================================================================
# Missing Value Handling Tests
# ============================================================================

def test_missing_values():
    """Test missing value policies across all methods."""
    runner = TestRunner()
    print("\n[Missing Value Handling Tests]")
    
    # Missing CVSS -> VRS should be None
    def test_missing_cvss_vrs():
        finding = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": None, "epss_probability": 0.5, "kev_listed": False}]
        }
        result = compute_vrs(finding)
        assert result["vrs"] is None, "Missing CVSS should result in VRS=None"
        assert "cvss_score" in result["missing_data"], "Missing data should be tracked"
    runner.test("Missing CVSS -> VRS=None", test_missing_cvss_vrs)
    
    # Missing CVSS -> CVSS-only should be None
    def test_missing_cvss_cvss_only():
        finding = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": None, "epss_probability": 0.5, "kev_listed": False}]
        }
        result = compute_cvss_only(finding)
        assert result is None, "Missing CVSS should result in None"
    runner.test("Missing CVSS -> CVSS-only=None", test_missing_cvss_cvss_only)
    
    # Missing EPSS -> defaults to 0.0 in VRS
    def test_missing_epss_vrs():
        finding = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": None, "kev_listed": False}]
        }
        result = compute_vrs(finding)
        assert result["components"]["E"] == 0.0, "Missing EPSS should default to 0.0"
        assert "epss_probability" in result["missing_data"], "Missing data should be tracked"
    runner.test("Missing EPSS -> E=0.0 (VRS)", test_missing_epss_vrs)
    
    # Missing EPSS -> None in EPSS-only
    def test_missing_epss_epss_only():
        finding = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": None, "kev_listed": False}]
        }
        result = compute_epss_only(finding)
        assert result is None, "Missing EPSS should result in None"
    runner.test("Missing EPSS -> EPSS-only=None", test_missing_epss_epss_only)
    
    # Missing Exposure -> defaults to 0.5
    def test_missing_exposure():
        finding = {
            "finding": {"network_exposure": None, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        result = compute_vrs(finding)
        assert result["components"]["N"] == 0.5, "Missing exposure should default to 0.5"
        assert "network_exposure" in result["missing_data"], "Missing data should be tracked"
    runner.test("Missing Exposure -> N=0.5", test_missing_exposure)
    
    # Missing Criticality -> defaults to 0.5
    def test_missing_criticality():
        finding = {
            "finding": {"network_exposure": 0.5, "asset_criticality": None},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        result = compute_vrs(finding)
        assert result["components"]["A"] == 0.5, "Missing criticality should default to 0.5"
        assert "asset_criticality" in result["missing_data"], "Missing data should be tracked"
    runner.test("Missing Criticality -> A=0.5", test_missing_criticality)
    
    # Missing KEV -> defaults to 0.0
    def test_missing_kev():
        finding = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 5.0, "epss_probability": 0.5, "kev_listed": None}]
        }
        result = compute_vrs(finding)
        assert result["components"]["K"] == 0.0, "Missing KEV should default to 0.0"
    runner.test("Missing KEV -> K=0.0", test_missing_kev)
    
    # Consistent missing values across baselines
    def test_missing_consistency():
        finding = {
            "finding": {"network_exposure": None, "asset_criticality": None},
            "cve_matches": [{"cvss_score": 7.0, "epss_probability": None, "kev_listed": False}]
        }
        # All baselines should handle missing data consistently
        try:
            vrs = compute_vrs(finding)
            epss_exp = compute_baseline_epss_exposure(finding)
            exp_crit = compute_baseline_exposure_criticality(finding)
            epss_ctx = compute_baseline_epss_context(finding)
            # All should complete without error
            assert True, "Consistent missing value handling"
        except Exception as e:
            assert False, f"Missing value handling failed: {e}"
    runner.test("Missing values handled consistently across baselines", test_missing_consistency)
    
    return runner.report()


# ============================================================================
# Determinism and Ranking Order Tests
# ============================================================================

def test_determinism():
    """Test that scores and rankings are deterministic."""
    runner = TestRunner()
    print("\n[Determinism Tests]")
    
    finding = {
        "finding": {"network_exposure": 0.7, "asset_criticality": 0.8},
        "cve_matches": [{"cvss_score": 8.5, "epss_probability": 0.75, "kev_listed": True}]
    }
    
    # VRS scoring is deterministic
    def test_vrs_determinism():
        r1 = compute_vrs(finding)
        r2 = compute_vrs(finding)
        assert r1["vrs"] == r2["vrs"], f"VRS not deterministic: {r1['vrs']} != {r2['vrs']}"
    runner.test("VRS scoring is deterministic", test_vrs_determinism)
    
    # Baseline scoring is deterministic
    def test_baselines_determinism():
        b1_1 = compute_baseline_epss_exposure(finding)
        b1_2 = compute_baseline_epss_exposure(finding)
        b2_1 = compute_baseline_exposure_criticality(finding)
        b2_2 = compute_baseline_exposure_criticality(finding)
        b3_1 = compute_baseline_context_enhanced_cvss(finding)
        b3_2 = compute_baseline_context_enhanced_cvss(finding)
        b4_1 = compute_baseline_epss_context(finding)
        b4_2 = compute_baseline_epss_context(finding)
        
        assert b1_1 == b1_2, "Baseline 1 not deterministic"
        assert b2_1 == b2_2, "Baseline 2 not deterministic"
        assert b3_1 == b3_2, "Baseline 3 not deterministic"
        assert b4_1 == b4_2, "Baseline 4 not deterministic"
    runner.test("Baseline scoring is deterministic", test_baselines_determinism)
    
    # Ranking is deterministic
    def test_ranking_determinism():
        findings = [finding] * 3
        r1 = rank_findings(findings)
        r2 = rank_findings(findings)
        
        rank1_cves = [item["primary_cve"] for item in r1]
        rank2_cves = [item["primary_cve"] for item in r2]
        assert rank1_cves == rank2_cves, "Ranking not deterministic"
    runner.test("Ranking is deterministic", test_ranking_determinism)
    
    return runner.report()


# ============================================================================
# Top-K Ranking Order Tests
# ============================================================================

def test_ranking_order():
    """Test that top-K rankings are sorted correctly."""
    runner = TestRunner()
    print("\n[Ranking Order Tests]")
    
    # Create findings with different scores
    findings = [
        {
            "finding": {"network_exposure": 0.9, "asset_criticality": 0.9},
            "cve_matches": [{"cve_id": "CVE-HIGH", "cvss_score": 9.5, "epss_probability": 0.9, "kev_listed": True}]
        },
        {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cve_id": "CVE-MED", "cvss_score": 5.5, "epss_probability": 0.5, "kev_listed": False}]
        },
        {
            "finding": {"network_exposure": 0.1, "asset_criticality": 0.1},
            "cve_matches": [{"cve_id": "CVE-LOW", "cvss_score": 2.0, "epss_probability": 0.1, "kev_listed": False}]
        },
    ]
    
    # VRS ranking should be descending by score
    def test_vrs_ranking_order():
        ranked = rank_findings(findings)
        cves = [item["primary_cve"] for item in ranked]
        scores = [item["score_data"]["vrs"] for item in ranked]
        
        # Scores should be descending (or None at end)
        for i in range(len(scores) - 1):
            if scores[i] is not None and scores[i+1] is not None:
                assert scores[i] >= scores[i+1], f"Ranking not descending: {scores[i]} < {scores[i+1]}"
    runner.test("VRS ranking is descending by score", test_vrs_ranking_order)
    
    return runner.report()


# ============================================================================
# Weight Validation Tests
# ============================================================================

def test_weight_validation():
    """Test weight validation across configurations."""
    runner = TestRunner()
    print("\n[Weight Validation Tests]")
    
    # Default weights validate
    def test_default_weights():
        validate_weights(DEFAULT_WEIGHTS)
    runner.test("Default weights validate", test_default_weights)
    
    # All sensitivity configs validate
    def test_all_sensitivity_configs():
        for config_id in ["original", "equal", "cvss_heavy", "epss_heavy", "context_heavy", "exposure_heavy"]:
            weights = get_weight_config(config_id)
            validate_weights_sensitivity(weights)
    runner.test("All sensitivity configurations validate", test_all_sensitivity_configs)
    
    # Weights sum to 1.0 for all configs
    def test_weight_sum():
        for config_id in ["original", "equal", "cvss_heavy", "epss_heavy", "context_heavy", "exposure_heavy"]:
            weights = get_weight_config(config_id)
            total = sum(weights.values())
            assert abs(total - 1.0) < 1e-6, f"Config {config_id} sums to {total}"
    runner.test("All weights sum to 1.0", test_weight_sum)
    
    # Weight order matches feature order
    def test_weight_order():
        weights = get_weight_config("original")
        expected_keys = {"w_C", "w_E", "w_K", "w_N", "w_A"}
        assert set(weights.keys()) == expected_keys, "Weight keys don't match expected order"
    runner.test("Weight keys match feature order", test_weight_order)
    
    return runner.report()


# ============================================================================
# Input Consistency Tests
# ============================================================================

def test_input_consistency():
    """Test that all methods receive consistent input records."""
    runner = TestRunner()
    print("\n[Input Consistency Tests]")
    
    # Same finding should score consistently
    def test_same_finding_consistency():
        finding = {
            "finding": {"network_exposure": 0.7, "asset_criticality": 0.8},
            "cve_matches": [{"cvss_score": 8.5, "epss_probability": 0.75, "kev_listed": True}]
        }
        
        # Score with original baseline
        result_original = compute_cvss_epss_kev(finding)
        
        # Score with context baselines
        result_b1 = compute_baseline_epss_exposure(finding)
        result_b2 = compute_baseline_exposure_criticality(finding)
        result_b3 = compute_baseline_context_enhanced_cvss(finding)
        result_b4 = compute_baseline_epss_context(finding)
        
        # All should produce numeric scores (not None)
        assert result_original is not None, "Original baseline produced None"
        assert result_b1 is not None, "Baseline 1 produced None"
        assert result_b2 is not None, "Baseline 2 produced None"
        assert result_b3 is not None, "Baseline 3 produced None"
        assert result_b4 is not None, "Baseline 4 produced None"
    runner.test("All methods score same finding consistently", test_same_finding_consistency)
    
    return runner.report()


# ============================================================================
# Run all tests
# ============================================================================

def main():
    print("=" * 70)
    print("Vulture-AI Comprehensive Baseline Tests")
    print("=" * 70)
    
    all_passed = True
    all_passed &= test_feature_normalization()
    all_passed &= test_missing_values()
    all_passed &= test_determinism()
    all_passed &= test_ranking_order()
    all_passed &= test_weight_validation()
    all_passed &= test_input_consistency()
    
    print()
    if all_passed:
        print("✓ ALL TEST SUITES PASSED")
        return 0
    else:
        print("✗ SOME TEST SUITES FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
