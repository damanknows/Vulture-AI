"""
Vulture-AI Independent Annotation Schema
=========================================

Defines the data model for independent CVE triage annotations collected
from human annotators following the labeling protocol.

IMPORTANT CONSTRAINTS:
- VRS scores and VRS rankings MUST NOT appear in annotation files.
- Annotator identities are pseudonymized opaque IDs.
- These annotations are INDEPENDENT of author-generated reference labels.
- Author-curated labels (cves.csv independent_label column) are NOT annotations
  for the purpose of this module; they serve as the reference rubric.

Schema version: 1.0
"""

import json
import re
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any


SCHEMA_VERSION = "1.0"
ALLOWED_LABELS = ["Act", "Attend", "Track", "Defer"]
# Ordinal order: Defer < Track < Attend < Act  (index = ordinal rank 0..3)
LABEL_ORDINAL = {"Defer": 0, "Track": 1, "Attend": 2, "Act": 3}

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
ANNOTATOR_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{3,64}$")


@dataclass
class Annotation:
    """
    Single annotation record for one CVE by one annotator.

    Fields
    ------
    cve_id : str
        CVE identifier (e.g. CVE-2021-44228). Must match NVD format.
    annotator_id : str
        Opaque, non-identifying annotator code (e.g. "RATER_01").
        Must NOT contain personal information.
    label : str
        Assigned priority tier: one of "Act", "Attend", "Track", "Defer".
    confidence : Optional[float]
        Annotator's self-reported confidence in [0.0, 1.0]. May be null.
    rationale : Optional[str]
        Free-text reasoning for the label. Encouraged but optional.
    annotation_timestamp : str
        ISO-8601 UTC timestamp when annotation was recorded.
    protocol_version : str
        Labeling protocol version used (must match SCHEMA_VERSION or later).
    """
    cve_id: str
    annotator_id: str
    label: str
    confidence: Optional[float] = None
    rationale: Optional[str] = None
    annotation_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    protocol_version: str = SCHEMA_VERSION


@dataclass
class AnnotationFile:
    """
    Container for a batch of annotations submitted by one or more annotators.
    
    Attributes
    ----------
    schema_version : str
        Version of this annotation schema.
    annotations : List[Annotation]
        Individual annotation records.
    provenance_note : str
        Required statement that these annotations are independent of VRS outputs.
    """
    schema_version: str = SCHEMA_VERSION
    annotations: List[Annotation] = field(default_factory=list)
    provenance_note: str = (
        "These annotations are INDEPENDENT of VRS scores and VRS rankings. "
        "Annotators followed the labeling protocol and had no access to VRS outputs."
    )


def annotation_to_dict(ann: Annotation) -> Dict[str, Any]:
    """Serialize Annotation to plain dict for JSON output."""
    d = asdict(ann)
    # Ensure no VRS fields exist
    for banned in ("vrs_score", "vrs", "vrs_rank", "vrs_bucket", "risk_score"):
        d.pop(banned, None)
    return d


def annotation_from_dict(d: Dict[str, Any]) -> Annotation:
    """Deserialize Annotation from dict (e.g. loaded from JSON)."""
    # Reject any dict that contains VRS fields
    for banned in ("vrs_score", "vrs", "vrs_rank", "vrs_bucket", "risk_score"):
        if banned in d:
            raise ValueError(
                f"Annotation contains forbidden VRS field '{banned}'. "
                "Annotations must be independent of VRS outputs."
            )
    return Annotation(
        cve_id=d["cve_id"],
        annotator_id=d["annotator_id"],
        label=d["label"],
        confidence=d.get("confidence"),
        rationale=d.get("rationale"),
        annotation_timestamp=d.get("annotation_timestamp", datetime.now(timezone.utc).isoformat()),
        protocol_version=d.get("protocol_version", SCHEMA_VERSION),
    )


def annotation_file_to_dict(af: AnnotationFile) -> Dict[str, Any]:
    """Serialize AnnotationFile to dict for JSON output."""
    return {
        "schema_version": af.schema_version,
        "provenance_note": af.provenance_note,
        "annotations": [annotation_to_dict(a) for a in af.annotations],
    }


def annotation_file_from_dict(d: Dict[str, Any]) -> AnnotationFile:
    """Deserialize AnnotationFile from dict."""
    annotations = [annotation_from_dict(a) for a in d.get("annotations", [])]
    return AnnotationFile(
        schema_version=d.get("schema_version", SCHEMA_VERSION),
        annotations=annotations,
        provenance_note=d.get("provenance_note", ""),
    )


def save_annotations(annotation_file: AnnotationFile, path: str) -> None:
    """Write annotation file to disk as JSON."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(annotation_file_to_dict(annotation_file), f, indent=2)


def load_annotations(path: str) -> AnnotationFile:
    """Load annotation file from JSON on disk."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return annotation_file_from_dict(raw)


def empty_annotation_file() -> AnnotationFile:
    """Return an empty AnnotationFile stub with correct provenance note."""
    return AnnotationFile()


if __name__ == "__main__":
    # Demonstrate an empty annotation file template
    af = empty_annotation_file()
    print(json.dumps(annotation_file_to_dict(af), indent=2))
