"""
Vulture-AI Weight Sensitivity Experiment
========================================

Implements configurable VRS weight sets and sensitivity analysis.

Weight configurations:
1. Original (vrs-v1):        w_C=0.25, w_E=0.20, w_K=0.20, w_N=0.20, w_A=0.15
2. Equal:                    w_C=0.20, w_E=0.20, w_K=0.20, w_N=0.20, w_A=0.20
3. CVSS-Heavy:               w_C=0.40, w_E=0.15, w_K=0.15, w_N=0.15, w_A=0.15
4. EPSS-Heavy:               w_C=0.15, w_E=0.30, w_K=0.25, w_N=0.15, w_A=0.15
5. Context-Heavy:            w_C=0.15, w_E=0.15, w_K=0.20, w_N=0.25, w_A=0.25
6. Exposure-Heavy:           w_C=0.15, w_E=0.15, w_K=0.15, w_N=0.40, w_A=0.20

All weights validated:
- Nonnegative
- Sum to 1.0 (tolerance: 1e-6)
"""

import math
from typing import Dict


WEIGHT_CONFIGURATIONS = {
    "original": {
        "name": "VRS Original (vrs-v1)",
        "description": "Initial exploratory weights from Phase 0",
        "weights": {
            "w_C": 0.25,
            "w_E": 0.20,
            "w_K": 0.20,
            "w_N": 0.20,
            "w_A": 0.15,
        }
    },
    "equal": {
        "name": "Equal Weights",
        "description": "All features weighted equally",
        "weights": {
            "w_C": 0.20,
            "w_E": 0.20,
            "w_K": 0.20,
            "w_N": 0.20,
            "w_A": 0.20,
        }
    },
    "cvss_heavy": {
        "name": "CVSS-Heavy",
        "description": "Prioritize CVSS severity",
        "weights": {
            "w_C": 0.40,
            "w_E": 0.15,
            "w_K": 0.15,
            "w_N": 0.15,
            "w_A": 0.15,
        }
    },
    "epss_heavy": {
        "name": "EPSS-Heavy",
        "description": "Prioritize exploitation probability",
        "weights": {
            "w_C": 0.15,
            "w_E": 0.30,
            "w_K": 0.25,
            "w_N": 0.15,
            "w_A": 0.15,
        }
    },
    "context_heavy": {
        "name": "Context-Heavy",
        "description": "Prioritize exposure and criticality",
        "weights": {
            "w_C": 0.15,
            "w_E": 0.15,
            "w_K": 0.20,
            "w_N": 0.25,
            "w_A": 0.25,
        }
    },
    "exposure_heavy": {
        "name": "Exposure-Heavy",
        "description": "Prioritize network exposure",
        "weights": {
            "w_C": 0.15,
            "w_E": 0.15,
            "w_K": 0.15,
            "w_N": 0.40,
            "w_A": 0.15,
        }
    },
}


def validate_weights(weights: Dict[str, float], tolerance: float = 1e-6) -> None:
    """
    Validate weight configuration.
    
    Args:
        weights: Dict mapping w_C, w_E, w_K, w_N, w_A to values
        tolerance: Sum tolerance (default 1e-6)
    
    Raises:
        ValueError: If weights invalid
    """
    required_keys = {"w_C", "w_E", "w_K", "w_N", "w_A"}
    
    if set(weights.keys()) != required_keys:
        raise ValueError(f"Weights must have exactly keys {required_keys}, got {set(weights.keys())}")
    
    # Check nonnegativity
    for key, val in weights.items():
        if val < 0:
            raise ValueError(f"Weight {key} cannot be negative: {val}")
    
    # Check sum
    total = sum(weights.values())
    if not math.isclose(total, 1.0, abs_tol=tolerance):
        raise ValueError(f"Weights must sum to 1.0 (tolerance {tolerance}), got {total}")


def get_weight_config(config_id: str) -> Dict[str, float]:
    """
    Retrieve a predefined weight configuration.
    
    Args:
        config_id: One of "original", "equal", "cvss_heavy", etc.
    
    Returns:
        Dict mapping w_C, w_E, w_K, w_N, w_A to values
    
    Raises:
        KeyError: If config_id not found
    """
    if config_id not in WEIGHT_CONFIGURATIONS:
        raise KeyError(f"Unknown weight configuration: {config_id}. "
                       f"Available: {list(WEIGHT_CONFIGURATIONS.keys())}")
    
    config = WEIGHT_CONFIGURATIONS[config_id]
    weights = config["weights"]
    
    # Validate before returning
    validate_weights(weights)
    
    return weights


def list_weight_configs() -> Dict[str, str]:
    """Return dict of config_id -> human-readable name."""
    return {
        config_id: config["name"]
        for config_id, config in WEIGHT_CONFIGURATIONS.items()
    }


def describe_weight_config(config_id: str) -> str:
    """Return human-readable description of a weight configuration."""
    if config_id not in WEIGHT_CONFIGURATIONS:
        raise KeyError(f"Unknown weight configuration: {config_id}")
    
    config = WEIGHT_CONFIGURATIONS[config_id]
    weights = config["weights"]
    
    lines = [
        f"Configuration: {config['name']}",
        f"Description: {config['description']}",
        f"Weights:",
    ]
    
    for key in ["w_C", "w_E", "w_K", "w_N", "w_A"]:
        lines.append(f"  {key}: {weights[key]:.2f}")
    
    lines.append(f"  Total: {sum(weights.values()):.6f}")
    
    return "\n".join(lines)


if __name__ == "__main__":
    print("Weight Configuration Registry")
    print("=" * 60)
    print()
    
    for config_id in WEIGHT_CONFIGURATIONS.keys():
        print(describe_weight_config(config_id))
        print()
