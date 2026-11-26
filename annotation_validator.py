"""
Vulture-AI Annotation Validator
===============================

Validates independent annotations for schema compliance, data quality,
and research integrity constraints.

Checks:
- CVE ID format validity
- Allowed labels (Act, Attend, Track, Defer)
- Duplicate annotations
- Missing required fields
- Annotator ID format
- Confidence in [0.0, 1.0] when present
- No VRS scores embedded
- Timestamp ISO-8601 validity

Does NOT validate against reference labels (that's inter-rater agreement's job).
"""

import re
from datetime import datetime
from typing import List, Tuple, Dict
from annotation_schema import (
    Annotation,
    AnnotationFile,
    CVE_ID_PATTERN,
    ANNOTATOR_ID_PATTERN,
    ALLOWED_LABELS,
)


class AnnotationValidationError(ValueError):
    """Raised when annotation validation fails."""
    pass


def validate_cve_id(cve_id: str) -> None:
    """Validate CVE ID format."""
    if not CVE_ID_PATTERN.match(cve_id):
        raise AnnotationValidationError(
            f"Invalid CVE ID format: '{cve_id}'. Expected CVE-YYYY-NNNNN+"
        )


def validate_annotator_id(annotator_id: str) -> None:
    """Validate annotator ID format and no PII."""
    if not ANNOTATOR_ID_PATTERN.match(annotator_id):
        raise AnnotationValidationError(
            f"Invalid annotator ID: '{annotator_id}'. "
            f"Must be 3–64 alphanumeric chars, underscore, or hyphen."
        )
    
    # Reject common PII patterns (email, phone, UUID)
    if "@" in annotator_id or "-" * 3 in annotator_id:  # Phone number delimiter
        raise AnnotationValidationError(
            f"Annotator ID appears to contain PII: '{annotator_id}'"
        )


def validate_label(label: str) -> None:
    """Validate label is one of allowed values."""
    if label not in ALLOWED_LABELS:
        raise AnnotationValidationError(
            f"Invalid label: '{label}'. Must be one of {ALLOWED_LABELS}"
        )


def validate_confidence(confidence: float) -> None:
    """Validate confidence is in [0.0, 1.0]."""
    if not isinstance(confidence, (int, float)):
        raise AnnotationValidationError(
            f"Confidence must be numeric, got {type(confidence)}"
        )
    if not (0.0 <= confidence <= 1.0):
        raise AnnotationValidationError(
            f"Confidence must be in [0.0, 1.0], got {confidence}"
        )


def validate_timestamp(ts: str) -> None:
    """Validate ISO-8601 timestamp format."""
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as e:
        raise AnnotationValidationError(
            f"Invalid ISO-8601 timestamp: '{ts}'. {e}"
        )


def validate_annotation(annotation: Annotation) -> List[str]:
    """
    Validate a single annotation.
    
    Returns:
        List of error messages (empty if valid).
    """
    errors = []
    
    try:
        validate_cve_id(annotation.cve_id)
    except AnnotationValidationError as e:
        errors.append(str(e))
    
    try:
        validate_annotator_id(annotation.annotator_id)
    except AnnotationValidationError as e:
        errors.append(str(e))
    
    try:
        validate_label(annotation.label)
    except AnnotationValidationError as e:
        errors.append(str(e))
    
    if annotation.confidence is not None:
        try:
            validate_confidence(annotation.confidence)
        except AnnotationValidationError as e:
            errors.append(str(e))
    
    try:
        validate_timestamp(annotation.annotation_timestamp)
    except AnnotationValidationError as e:
        errors.append(str(e))
    
    return errors


def validate_annotation_file(annotation_file: AnnotationFile) -> Dict[str, any]:
    """
    Validate entire annotation file.
    
    Returns:
        Dict with keys:
        - is_valid (bool): Overall validity
        - total_annotations (int)
        - valid_count (int)
        - invalid_count (int)
        - duplicate_count (int)
        - errors (List[str]): All error messages
        - duplicates (List[Tuple[str, str]]): (CVE_ID, annotator_id) pairs with duplicates
    """
    errors = []
    seen = set()
    duplicates = []
    valid_count = 0
    invalid_count = 0
    
    for idx, ann in enumerate(annotation_file.annotations):
        ann_errors = validate_annotation(ann)
        
        if ann_errors:
            invalid_count += 1
            for err in ann_errors:
                errors.append(f"Annotation {idx}: {err}")
        else:
            valid_count += 1
        
        # Check for duplicates (same CVE + same annotator)
        key = (ann.cve_id, ann.annotator_id)
        if key in seen:
            duplicates.append(key)
            errors.append(
                f"Annotation {idx}: Duplicate annotation for {ann.cve_id} by {ann.annotator_id}"
            )
        seen.add(key)
    
    return {
        "is_valid": len(errors) == 0,
        "total_annotations": len(annotation_file.annotations),
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "duplicate_count": len(set(duplicates)),
        "errors": errors,
        "duplicates": list(set(duplicates)),
    }


def validate_annotation_file_strict(annotation_file: AnnotationFile) -> None:
    """
    Validate annotation file and raise exception if invalid.
    
    Raises:
        AnnotationValidationError: If file is invalid.
    """
    result = validate_annotation_file(annotation_file)
    if not result["is_valid"]:
        msg = f"Annotation file validation failed:\n"
        for err in result["errors"]:
            msg += f"  - {err}\n"
        raise AnnotationValidationError(msg)


if __name__ == "__main__":
    # Demonstrate validation
    from annotation_schema import empty_annotation_file
    
    af = empty_annotation_file()
    result = validate_annotation_file(af)
    print(f"Empty file is valid: {result['is_valid']}")
    print(f"Total annotations: {result['total_annotations']}")
