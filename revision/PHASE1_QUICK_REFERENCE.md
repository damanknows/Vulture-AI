# Vulture-AI Phase 1 Quick Reference

## Files Summary

| File | Lines | Purpose |
|------|-------|---------|
| `benchmark_manifest.py` | 223 | Generate data provenance manifest |
| `annotation_schema.py` | 115 | Annotation data model (VRS-free) |
| `annotation_validator.py` | 206 | Validate annotations (CVE, label, format) |
| `annotation_agreement.py` | 267 | Krippendorff's alpha ordinal agreement |
| `annotation_consensus.py` | 196 | Majority-vote consensus with tiebreak |
| `annotation_cli.py` | 341 | CLI: validate, agreement, consensus, template |
| `LABELING_PROTOCOL.md` | 340 | Annotator guidelines and decision criteria |
| `tests/test_annotations.py` | 589 | 19 functional tests (100% pass) |
| `data/benchmark/versions/cves_v1_original_2026-10-14.csv` | 6.5K | Original benchmark (versioned) |
| `data/benchmark/versions/cves_v1_manifest.json` | 8K | Provenance manifest with 8 disclaimers |

## Quick Start

### For Annotators

```bash
# 1. Generate template
python3 annotation_cli.py template -o annotations.json

# 2. Edit annotations.json and follow LABELING_PROTOCOL.md

# 3. Validate
python3 annotation_cli.py validate annotations.json
```

### For Analysis

```bash
# Merge multiple rater files, then:

# Compute inter-rater agreement
python3 annotation_cli.py agreement merged.json -o agreement.json

# Generate consensus labels
python3 annotation_cli.py consensus merged.json -o consensus.json
```

## Key Statistics

| Metric | Value |
|--------|-------|
| Benchmark records | 41 (39 real + 2 synthetic) |
| Original SHA-256 | 27979cc0029e3d38... |
| Versioned copy SHA-256 | Identical ✓ |
| Label distribution | Act=15, Attend=12, Track=8, Defer=6 |
| KEV-listed CVEs | 25 (60.98%) |
| Missing CVSS | 1 (CVE-2024-99991) |
| Missing EPSS | 2 (CVE-2024-99991, CVE-2024-99992) |
| New tests | 19 (100% pass) |
| Existing tests | 5 (100% pass) |

## Annotation Requirements

### Valid Labels
- **Act**: Urgent, remediate immediately
- **Attend**: High priority, remediate this week
- **Track**: Standard, routine patch cycle
- **Defer**: Low priority, assess applicability

### Annotator ID Format
- 3–64 alphanumeric chars, underscore, hyphen
- Example: `RATER_01`, `expert-003`, `SecOps_Team2`
- No personal information allowed

### Confidence (Optional)
- Range: [0.0, 1.0]
- 1.0 = very confident
- 0.5 = moderate confidence
- 0.25 = low confidence

## Agreement Interpretation

| Alpha | Interpretation |
|-------|-----------------|
| 0.80+ | Excellent agreement |
| 0.67–0.80 | Good agreement |
| 0.33–0.67 | Moderate agreement |
| <0.33 | Poor agreement |
| 1.0 | Perfect agreement |
| <0.0 | Worse than chance |

## Validation Errors Handled

- Invalid CVE format (must match CVE-YYYY-NNNNN+)
- Invalid labels (must be Act, Attend, Track, Defer)
- Invalid annotator ID (must be 3–64 chars, no PII)
- Confidence out of [0.0, 1.0]
- Invalid ISO-8601 timestamps
- Duplicate annotations (same CVE + same rater)
- VRS fields embedded in annotations (rejected)
- Missing required fields

## Critical Disclaimers

1. Labels are AUTHOR-CURATED using SSVC rubric, NOT independently validated
2. Construct circularity: Reference labels use same features (KEV, EPSS, N)
3. High VRS performance reflects CONSTRUCT ALIGNMENT, not independent prediction
4. Environment context (N, A) are archetypal profiles, NOT organization-specific
5. EPSS is rolling 30-day forecast; subject to drift
6. KEV membership indicates unobserved in federal civilian reporting, NOT confirmed non-exploitation
7. Synthetic edge-case CVEs (CVE-2024-99991, CVE-2024-99992) are non-existent; for testing only
8. Independent analyst validation remains PENDING (future Experiment 2.1)

## Experiment 2.1 Checklist (Next Phase)

- [ ] Recruit 3–5 independent security analysts
- [ ] Distribute LABELING_PROTOCOL.md to annotators
- [ ] Provide CVE benchmark data (no VRS scores)
- [ ] Collect independent annotations
- [ ] Validate all submissions: `python3 annotation_cli.py validate`
- [ ] Merge annotations into single JSON file
- [ ] Compute agreement: `python3 annotation_cli.py agreement`
- [ ] Generate consensus: `python3 annotation_cli.py consensus`
- [ ] Report Krippendorff's alpha (target: α ≥ 0.60 for acceptance)
- [ ] Integrate results into manuscript
- [ ] Update label disclosure section

## Support Resources

- **Annotation Protocol:** `LABELING_PROTOCOL.md`
- **Data Provenance:** `revision/DATA_PROVENANCE.md`
- **Manifest:** `data/benchmark/versions/cves_v1_manifest.json`
- **Audit Report:** `revision/AUDIT_REPORT.md`
- **Experiment Plan:** `revision/EXPERIMENT_PLAN.md`
