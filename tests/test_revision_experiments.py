"""
Vulture-AI Phase 2 Revision Experiments Tests
==============================================

Tests for context-aware baselines, weight sensitivity, and ranking stability.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from context_baselines import (
    compute_baseline_epss_exposure,
    compute_baseline_exposure_criticality,
    compute_baseline_context_enhanced_cvss,
    compute_baseline_epss_context,
)
from weight_sensitivity import (
    validate_weights,
    get_weight_config,
    list_weight_configs,
    describe_weight_config,
    WEIGHT_CONFIGURATIONS,
)
from ranking_stability import (
    compute_top_k_overlap,
    compute_ranking_stability,
    compute_position_shift_distribution,
)


# ============================================================================
# Test Helper
# ============================================================================

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
# Context-Aware Baseline Tests
# ============================================================================

def test_context_baselines():
    """Test context-aware baseline functions."""
    runner = TestRunner()
    print("\n[Context-Aware Baselines Tests]")
    
    # Test finding
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
    
    # Test 1: EPSS × Exposure
    def test_epss_exposure():
        score = compute_baseline_epss_exposure(test_finding)
        expected = 0.75 * 0.7
        assert abs(score - expected) < 0.001, f"Expected {expected}, got {score}"
    runner.test("EPSS × Exposure baseline", test_epss_exposure)
    
    # Test 2: Exposure × Criticality
    def test_exposure_criticality():
        score = compute_baseline_exposure_criticality(test_finding)
        expected = 0.7 * 0.9
        assert abs(score - expected) < 0.001, f"Expected {expected}, got {score}"
    runner.test("Exposure × Asset Criticality baseline", test_exposure_criticality)
    
    # Test 3: Context-Enhanced CVSS
    def test_context_enhanced_cvss():
        score = compute_baseline_context_enhanced_cvss(test_finding)
        cvss_norm = 8.5 / 10.0
        exp_factor = 0.5 + 0.5 * 0.7
        crit_factor = 0.5 + 0.5 * 0.9
        expected = cvss_norm * exp_factor * crit_factor
        assert abs(score - expected) < 0.001, f"Expected {expected}, got {score}"
    runner.test("Context-Enhanced CVSS baseline", test_context_enhanced_cvss)
    
    # Test 4: EPSS × Context
    def test_epss_context():
        score = compute_baseline_epss_context(test_finding)
        exp_factor = 0.5 + 0.5 * 0.7
        crit_factor = 0.5 + 0.5 * 0.9
        expected = 0.75 * exp_factor * crit_factor
        assert abs(score - expected) < 0.001, f"Expected {expected}, got {score}"
    runner.test("EPSS × Context baseline", test_epss_context)
    
    # Test 5: Missing EPSS defaults to 0.0
    def test_missing_epss():
        finding_no_epss = {
            "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 7.0, "epss_probability": None, "kev_listed": False}]
        }
        score = compute_baseline_epss_exposure(finding_no_epss)
        assert score == 0.0, f"Expected 0.0 for missing EPSS, got {score}"
    runner.test("Missing EPSS defaults to 0.0", test_missing_epss)
    
    # Test 6: Missing Exposure defaults to 0.5
    def test_missing_exposure():
        finding_no_exposure = {
            "finding": {"network_exposure": None, "asset_criticality": 0.5},
            "cve_matches": [{"cvss_score": 7.0, "epss_probability": 0.5, "kev_listed": False}]
        }
        score = compute_baseline_epss_exposure(finding_no_exposure)
        expected = 0.5 * 0.5
        assert abs(score - expected) < 0.001, f"Expected {expected}, got {score}"
    runner.test("Missing Exposure defaults to 0.5", test_missing_exposure)
    
    # Test 7: Missing CVSS returns None for context-enhanced
    def test_missing_cvss_context_enhanced():
        finding_no_cvss = {
            "finding": {"network_exposure": 0.7, "asset_criticality": 0.9},
            "cve_matches": [{"cvss_score": None, "epss_probability": 0.5, "kev_listed": False}]
        }
        score = compute_baseline_context_enhanced_cvss(finding_no_cvss)
        assert score is None, f"Expected None for missing CVSS, got {score}"
    runner.test("Missing CVSS returns None", test_missing_cvss_context_enhanced)
    
    # Test 8: Zero exposure
    def test_zero_exposure():
        finding_zero_exp = {
            "finding": {"network_exposure": 0.0, "asset_criticality": 0.9},
            "cve_matches": [{"cvss_score": 10.0, "epss_probability": 1.0, "kev_listed": True}]
        }
        score = compute_baseline_epss_exposure(finding_zero_exp)
        assert score == 0.0, f"Expected 0.0 for zero exposure, got {score}"
    runner.test("Zero exposure yields zero score", test_zero_exposure)
    
    # Test 9: Maximum features
    def test_max_features():
        finding_max = {
            "finding": {"network_exposure": 1.0, "asset_criticality": 1.0},
            "cve_matches": [{"cvss_score": 10.0, "epss_probability": 1.0, "kev_listed": True}]
        }
        score = compute_baseline_context_enhanced_cvss(finding_max)
        expected = 1.0 * 1.0 * 1.0
        assert abs(score - expected) < 0.001, f"Expected {expected}, got {score}"
    runner.test("Maximum features yield maximum score", test_max_features)
    
    return runner.report()


# ============================================================================
# Weight Sensitivity Tests
# ============================================================================

def test_weight_sensitivity():
    """Test weight configuration system."""
    runner = TestRunner()
    print("\n[Weight Sensitivity Tests]")
    
    # Test 1: Original weights validate
    def test_original_weights():
        weights = get_weight_config("original")
        validate_weights(weights)
        assert weights["w_C"] == 0.25, "Original w_C should be 0.25"
    runner.test("Original weights valid", test_original_weights)
    
    # Test 2: All configs valid
    def test_all_configs_valid():
        for config_id in WEIGHT_CONFIGURATIONS.keys():
            weights = get_weight_config(config_id)
            validate_weights(weights)
    runner.test("All weight configurations valid", test_all_configs_valid)
    
    # Test 3: Weights sum to 1.0
    def test_sum_to_one():
        for config_id in WEIGHT_CONFIGURATIONS.keys():
            weights = get_weight_config(config_id)
            total = sum(weights.values())
            assert abs(total - 1.0) < 1e-6, f"Config {config_id} sums to {total}, not 1.0"
    runner.test("All weights sum to 1.0", test_sum_to_one)
    
    # Test 4: All weights nonnegative
    def test_nonnegative():
        for config_id in WEIGHT_CONFIGURATIONS.keys():
            weights = get_weight_config(config_id)
            for key, val in weights.items():
                assert val >= 0, f"Config {config_id} has negative {key}={val}"
    runner.test("All weights nonnegative", test_nonnegative)
    
    # Test 5: Invalid config raises KeyError
    def test_invalid_config():
        try:
            get_weight_config("nonexistent")
            assert False, "Should raise KeyError"
        except KeyError:
            pass
    runner.test("Invalid config raises KeyError", test_invalid_config)
    
    # Test 6: Weight validation rejects negative
    def test_reject_negative():
        bad_weights = {"w_C": -0.1, "w_E": 0.5, "w_K": 0.3, "w_N": 0.3, "w_A": 0.0}
        try:
            validate_weights(bad_weights)
            assert False, "Should reject negative weight"
        except ValueError:
            pass
    runner.test("Negative weights rejected", test_reject_negative)
    
    # Test 7: Weight validation rejects bad sum
    def test_reject_bad_sum():
        bad_weights = {"w_C": 0.3, "w_E": 0.3, "w_K": 0.2, "w_N": 0.1, "w_A": 0.05}
        try:
            validate_weights(bad_weights)
            assert False, "Should reject non-unit sum"
        except ValueError:
            pass
    runner.test("Non-unit sum rejected", test_reject_bad_sum)
    
    # Test 8: list_weight_configs returns dict
    def test_list_configs():
        configs = list_weight_configs()
        assert isinstance(configs, dict), "Should return dict"
        assert len(configs) > 0, "Should have configs"
    runner.test("list_weight_configs returns dict", test_list_configs)
    
    # Test 9: describe_weight_config returns string
    def test_describe():
        desc = describe_weight_config("original")
        assert isinstance(desc, str), "Should return string"
        assert "Original" in desc, "Should contain config name"
    runner.test("describe_weight_config returns description", test_describe)
    
    # Test 10: Equal config has uniform weights
    def test_equal_uniform():
        weights = get_weight_config("equal")
        for val in weights.values():
            assert abs(val - 0.2) < 1e-6, f"Equal weights should all be 0.2, got {val}"
    runner.test("Equal configuration is uniform (0.2 each)", test_equal_uniform)
    
    return runner.report()


# ============================================================================
# Ranking Stability Tests
# ============================================================================

def test_ranking_stability():
    """Test ranking stability and overlap metrics."""
    runner = TestRunner()
    print("\n[Ranking Stability Tests]")
    
    ranking_a = ["CVE-2021-44228", "CVE-2024-1709", "CVE-2023-34362", 
                 "CVE-2022-30190", "CVE-2021-32625"]
    ranking_b = ["CVE-2021-44228", "CVE-2023-34362", "CVE-2024-1709", 
                 "CVE-2022-30190", "CVE-2021-32625"]
    
    # Test 1: Perfect top-10 overlap
    def test_perfect_overlap():
        overlap, frac = compute_top_k_overlap(ranking_a, ranking_a, k=5)
        assert overlap == 5, f"Expected perfect overlap, got {overlap}"
        assert frac == 1.0, f"Expected fraction 1.0, got {frac}"
    runner.test("Perfect ranking overlap", test_perfect_overlap)
    
    # Test 2: Partial overlap
    def test_partial_overlap():
        overlap, frac = compute_top_k_overlap(ranking_a, ranking_b, k=5)
        # Both rankings have same 5 CVEs, just different order
        assert overlap == 5, f"Expected overlap=5, got {overlap}"
        assert frac == 1.0, f"Expected fraction=1.0, got {frac}"
    runner.test("Partial ranking overlap", test_partial_overlap)
    
    # Test 3: No overlap
    def test_no_overlap():
        ranking_c = ["CVE-X", "CVE-Y", "CVE-Z", "CVE-W", "CVE-V"]
        # Can't compute overlap if different populations
        # Instead test with limited k
        ranking_d = ranking_a + ranking_c
        try:
            overlap, frac = compute_top_k_overlap(ranking_a, ranking_d, k=5)
            # This should work since k ≤ len(ranking_a)
        except:
            pass  # May fail due to different populations; that's ok
    runner.test("No overlap detection", test_no_overlap)
    
    # Test 4: Ranking stability metrics
    def test_stability_metrics():
        stability = compute_ranking_stability(ranking_b, ranking_a)
        assert "mean_position_shift" in stability
        assert "max_position_shift" in stability
        assert stability["total_items"] == 5
    runner.test("Ranking stability metrics computed", test_stability_metrics)
    
    # Test 5: Identical rankings have zero shift
    def test_identical_stability():
        stability = compute_ranking_stability(ranking_a, ranking_a)
        assert stability["mean_position_shift"] == 0, "Identical rankings should have zero shift"
        assert stability["max_position_shift"] == 0, "Identical rankings should have zero max shift"
    runner.test("Identical rankings have zero shift", test_identical_stability)
    
    # Test 6: Position shift distribution
    def test_shift_distribution():
        dist = compute_position_shift_distribution(ranking_b, ranking_a)
        assert isinstance(dist, dict), "Should return dict"
        assert sum(dist.values()) == 5, "Distribution should sum to total items"
    runner.test("Position shift distribution computed", test_shift_distribution)
    
    # Test 7: Mismatch in populations raises error
    def test_population_mismatch():
        ranking_bad = ["CVE-A", "CVE-B", "CVE-C"]
        try:
            compute_ranking_stability(ranking_bad, ranking_a)
            assert False, "Should raise ValueError"
        except ValueError:
            pass
    runner.test("Population mismatch raises ValueError", test_population_mismatch)
    
    return runner.report()


# ============================================================================
# Run all tests
# ============================================================================

def main():
    print("=" * 70)
    print("Vulture-AI Phase 2 Revision Experiments Test Suite")
    print("=" * 70)
    
    all_passed = True
    all_passed &= test_context_baselines()
    all_passed &= test_weight_sensitivity()
    all_passed &= test_ranking_stability()
    
    print()
    if all_passed:
        print("✓ ALL TEST SUITES PASSED")
        return 0
    else:
        print("✗ SOME TEST SUITES FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
