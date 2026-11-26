"""
Unit Tests for Annotation Infrastructure
========================================

Tests for:
- Annotation schema validation
- Annotation validator
- Agreement metrics
- Consensus computation
- CLI commands
"""

import pytest
import json
import tempfile
import os
from datetime import datetime, timezone

from annotation_schema import (
    Annotation,
    AnnotationFile,
    annotation_to_dict,
    annotation_from_dict,
    annotation_file_to_dict,
    annotation_file_from_dict,
    save_annotations,
    load_annotations,
    empty_annotation_file,
)

from annotation_validator import (
    validate_annotation,
    validate_annotation_file,
    validate_cve_id,
    validate_annotator_id,
    validate_label,
    validate_confidence,
    validate_timestamp,
    AnnotationValidationError,
)

from annotation_agreement import (
    compute_krippendorff_alpha_ordinal,
    compute_agreement_summary,
    agreement_interpretation,
    InsufficientAnnotationData,
    ordinal_distance,
)

from annotation_consensus import (
    majority_vote,
    majority_vote_with_tiebreak,
    compute_consensus_for_cve,
    compute_consensus_for_dataset,
    ConsensusTie,
)


# ============================================================================
# Schema Tests
# ============================================================================

class TestAnnotationSchema:
    """Test annotation data model."""
    
    def test_annotation_creation(self):
        """Test creating an Annotation."""
        ann = Annotation(
            cve_id="CVE-2021-44228",
            annotator_id="RATER_01",
            label="Act",
            confidence=0.95
        )
        assert ann.cve_id == "CVE-2021-44228"
        assert ann.annotator_id == "RATER_01"
        assert ann.label == "Act"
        assert ann.confidence == 0.95
    
    def test_annotation_serialization(self):
        """Test Annotation to dict and back."""
        ann = Annotation(
            cve_id="CVE-2021-44228",
            annotator_id="RATER_01",
            label="Act"
        )
        d = annotation_to_dict(ann)
        ann2 = annotation_from_dict(d)
        assert ann2.cve_id == ann.cve_id
        assert ann2.label == ann.label
    
    def test_annotation_rejects_vrs_fields(self):
        """Test that VRS fields are rejected in deserialization."""
        d = {
            "cve_id": "CVE-2021-44228",
            "annotator_id": "RATER_01",
            "label": "Act",
            "vrs_score": 95.0
        }
        with pytest.raises(ValueError, match="forbidden VRS field"):
            annotation_from_dict(d)
    
    def test_annotation_file_creation(self):
        """Test creating an AnnotationFile."""
        af = empty_annotation_file()
        assert af.schema_version == "1.0"
        assert len(af.annotations) == 0
        assert "INDEPENDENT" in af.provenance_note
    
    def test_annotation_file_save_load(self):
        """Test saving and loading annotation file."""
        ann = Annotation("CVE-2021-44228", "RATER_01", "Act", confidence=0.9)
        af = AnnotationFile()
        af.annotations.append(ann)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            save_annotations(af, temp_path)
            af2 = load_annotations(temp_path)
            assert len(af2.annotations) == 1
            assert af2.annotations[0].cve_id == "CVE-2021-44228"
        finally:
            os.unlink(temp_path)


# ============================================================================
# Validator Tests
# ============================================================================

class TestAnnotationValidator:
    """Test annotation validation."""
    
    def test_valid_cve_id(self):
        """Test valid CVE ID."""
        validate_cve_id("CVE-2021-44228")
        validate_cve_id("CVE-2024-1709")
    
    def test_invalid_cve_id(self):
        """Test invalid CVE IDs."""
        with pytest.raises(AnnotationValidationError):
            validate_cve_id("CVE-2021-1234567890")  # Too long
        with pytest.raises(AnnotationValidationError):
            validate_cve_id("2021-44228")  # Missing prefix
    
    def test_valid_annotator_id(self):
        """Test valid annotator IDs."""
        validate_annotator_id("RATER_01")
        validate_annotator_id("expert-003")
        validate_annotator_id("SecOps_Team2")
    
    def test_invalid_annotator_id_pii(self):
        """Test that PII is rejected."""
        with pytest.raises(AnnotationValidationError):
            validate_annotator_id("john.doe@example.com")
    
    def test_valid_labels(self):
        """Test valid labels."""
        for label in ["Act", "Attend", "Track", "Defer"]:
            validate_label(label)
    
    def test_invalid_label(self):
        """Test invalid label."""
        with pytest.raises(AnnotationValidationError):
            validate_label("Critical")
    
    def test_valid_confidence(self):
        """Test valid confidence values."""
        validate_confidence(0.0)
        validate_confidence(0.5)
        validate_confidence(1.0)
    
    def test_invalid_confidence(self):
        """Test invalid confidence."""
        with pytest.raises(AnnotationValidationError):
            validate_confidence(1.5)
        with pytest.raises(AnnotationValidationError):
            validate_confidence(-0.1)
    
    def test_valid_timestamp(self):
        """Test valid ISO-8601 timestamps."""
        validate_timestamp("2026-11-26T15:00:00Z")
        validate_timestamp("2026-11-26T15:00:00+00:00")
    
    def test_invalid_timestamp(self):
        """Test invalid timestamps."""
        with pytest.raises(AnnotationValidationError):
            validate_timestamp("2026/11/26 15:00")
    
    def test_validate_annotation_full(self):
        """Test full annotation validation."""
        ann = Annotation(
            cve_id="CVE-2021-44228",
            annotator_id="RATER_01",
            label="Act",
            confidence=0.95
        )
        errors = validate_annotation(ann)
        assert len(errors) == 0
    
    def test_validate_annotation_errors(self):
        """Test annotation with validation errors."""
        ann = Annotation(
            cve_id="INVALID",
            annotator_id="RATER_01",
            label="Invalid",
            confidence=1.5
        )
        errors = validate_annotation(ann)
        assert len(errors) > 0
    
    def test_validate_annotation_file_duplicates(self):
        """Test detection of duplicate annotations."""
        af = AnnotationFile()
        af.annotations.append(Annotation("CVE-2021-44228", "RATER_01", "Act"))
        af.annotations.append(Annotation("CVE-2021-44228", "RATER_01", "Attend"))
        
        result = validate_annotation_file(af)
        assert not result["is_valid"]
        assert result["duplicate_count"] == 1


# ============================================================================
# Agreement Tests
# ============================================================================

class TestAgreement:
    """Test inter-rater agreement computation."""
    
    def test_ordinal_distance(self):
        """Test ordinal distance computation."""
        assert ordinal_distance("Act", "Act") == 0.0
        assert ordinal_distance("Act", "Attend") == 1.0
        assert ordinal_distance("Act", "Defer") == 3.0
    
    def test_perfect_agreement(self):
        """Test Krippendorff's alpha with perfect agreement."""
        cve_anns = {
            "CVE-2021-44228": [
                Annotation("CVE-2021-44228", "RATER_01", "Act"),
                Annotation("CVE-2021-44228", "RATER_02", "Act"),
            ]
        }
        alpha, metadata = compute_krippendorff_alpha_ordinal(cve_anns)
        assert alpha == 1.0
    
    def test_complete_disagreement(self):
        """Test Krippendorff's alpha with complete disagreement."""
        cve_anns = {
            "CVE-2021-44228": [
                Annotation("CVE-2021-44228", "RATER_01", "Act"),
                Annotation("CVE-2021-44228", "RATER_02", "Defer"),
            ]
        }
        alpha, metadata = compute_krippendorff_alpha_ordinal(cve_anns)
        assert alpha < 0.0  # Worse than chance
    
    def test_insufficient_units(self):
        """Test that alpha rejects <2 units."""
        cve_anns = {
            "CVE-2021-44228": [
                Annotation("CVE-2021-44228", "RATER_01", "Act"),
                Annotation("CVE-2021-44228", "RATER_02", "Act"),
            ]
        }
        with pytest.raises(InsufficientAnnotationData):
            compute_krippendorff_alpha_ordinal(cve_anns)
    
    def test_insufficient_raters(self):
        """Test that alpha rejects <2 raters."""
        cve_anns = {
            "CVE-2021-44228": [Annotation("CVE-2021-44228", "RATER_01", "Act")],
            "CVE-2024-1709": [Annotation("CVE-2024-1709", "RATER_01", "Track")],
        }
        with pytest.raises(InsufficientAnnotationData):
            compute_krippendorff_alpha_ordinal(cve_anns)
    
    def test_agreement_interpretation(self):
        """Test alpha interpretation."""
        assert "Excellent" in agreement_interpretation(0.90)
        assert "Good" in agreement_interpretation(0.75)
        assert "Moderate" in agreement_interpretation(0.50)
        assert "Poor" in agreement_interpretation(0.20)
    
    def test_agreement_summary(self):
        """Test comprehensive agreement summary."""
        cve_anns = {
            "CVE-2021-44228": [
                Annotation("CVE-2021-44228", "RATER_01", "Act"),
                Annotation("CVE-2021-44228", "RATER_02", "Act"),
            ],
            "CVE-2024-1709": [
                Annotation("CVE-2024-1709", "RATER_01", "Track"),
                Annotation("CVE-2024-1709", "RATER_02", "Track"),
            ],
        }
        summary = compute_agreement_summary(cve_anns)
        assert summary["alpha"] == 1.0
        assert summary["n_units"] == 2
        assert summary["n_raters"] == 2


# ============================================================================
# Consensus Tests
# ============================================================================

class TestConsensus:
    """Test consensus label computation."""
    
    def test_majority_vote_clear_winner(self):
        """Test majority vote with clear winner."""
        label, votes, _ = majority_vote(["Act", "Act", "Track"])
        assert label == "Act"
        assert votes == 2
    
    def test_majority_vote_tie(self):
        """Test majority vote with tie."""
        with pytest.raises(ConsensusTie):
            majority_vote(["Act", "Track"])
    
    def test_majority_vote_with_tiebreak_severity(self):
        """Test tie-breaking by severity."""
        label, votes, tiebreak = majority_vote_with_tiebreak(
            ["Act", "Track"],
            tiebreak_method="severity"
        )
        assert label == "Act"  # Higher severity wins
        assert tiebreak == "tiebreak=severity"
    
    def test_consensus_for_cve_unanimous(self):
        """Test consensus with unanimous agreement."""
        anns = [
            Annotation("CVE-2021-44228", "RATER_01", "Act"),
            Annotation("CVE-2021-44228", "RATER_02", "Act"),
        ]
        result = compute_consensus_for_cve(anns)
        assert result["consensus_label"] == "Act"
        assert result["n_annotations"] == 2
    
    def test_consensus_for_cve_tie_allowed(self):
        """Test consensus with allowed tie."""
        anns = [
            Annotation("CVE-2024-1709", "RATER_01", "Act"),
            Annotation("CVE-2024-1709", "RATER_02", "Track"),
        ]
        result = compute_consensus_for_cve(anns, allow_tie=True)
        assert result["is_tie"] is True
        assert result["consensus_label"] is None
    
    def test_consensus_for_cve_tie_resolved(self):
        """Test consensus with tie resolution."""
        anns = [
            Annotation("CVE-2024-1709", "RATER_01", "Act"),
            Annotation("CVE-2024-1709", "RATER_02", "Track"),
        ]
        result = compute_consensus_for_cve(anns, allow_tie=False, tiebreak_method="severity")
        assert result["consensus_label"] == "Act"
        assert "tiebreak" in result["tiebreak_applied"]
    
    def test_consensus_for_dataset(self):
        """Test consensus for entire dataset."""
        cve_anns = {
            "CVE-2021-44228": [
                Annotation("CVE-2021-44228", "RATER_01", "Act"),
                Annotation("CVE-2021-44228", "RATER_02", "Act"),
            ],
            "CVE-2024-1709": [
                Annotation("CVE-2024-1709", "RATER_01", "Track"),
                Annotation("CVE-2024-1709", "RATER_02", "Track"),
            ],
        }
        result = compute_consensus_for_dataset(cve_anns)
        assert result["total_cves"] == 2
        assert result["consensus_cves"] == 2
        assert result["consensus_labels"]["CVE-2021-44228"] == "Act"
        assert result["consensus_labels"]["CVE-2024-1709"] == "Track"


# ============================================================================
# Benchmark Manifest Tests
# ============================================================================

class TestBenchmarkManifest:
    """Test benchmark provenance manifest."""
    
    def test_manifest_generation(self):
        """Test manifest can be generated."""
        from benchmark_manifest import generate_benchmark_manifest
        
        manifest = generate_benchmark_manifest(
            csv_path="data/benchmark/cves.csv"
        )
        
        assert manifest["metadata"]["schema_version"] == "1.0"
        assert "population" in manifest
        assert "feature_provenance" in manifest
        assert "critical_disclaimers" in manifest
        
        # Check disclaimers are present
        disclaimers = manifest["critical_disclaimers"]
        assert any("AUTHOR-CURATED" in d for d in disclaimers)
        assert any("SSVC" in d for d in disclaimers)


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
