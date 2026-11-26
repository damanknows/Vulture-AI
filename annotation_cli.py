"""
Vulture-AI Annotation CLI
=========================

Command-line interface for managing independent CVE annotations:
- Validate annotation files
- Compute inter-rater agreement
- Generate consensus labels
- Export results
"""

import sys
import json
import argparse
from typing import Optional
from annotation_schema import load_annotations, empty_annotation_file, save_annotations
from annotation_validator import validate_annotation_file, AnnotationValidationError
from annotation_agreement import compute_agreement_summary, InsufficientAnnotationData
from annotation_consensus import compute_consensus_for_dataset


def cmd_validate(args) -> int:
    """Validate an annotation file."""
    try:
        af = load_annotations(args.annotation_file)
        result = validate_annotation_file(af)
        
        print(f"Annotation File Validation Report")
        print(f"{'=' * 60}")
        print(f"File: {args.annotation_file}")
        print(f"Valid: {result['is_valid']}")
        print(f"Total annotations: {result['total_annotations']}")
        print(f"Valid: {result['valid_count']}, Invalid: {result['invalid_count']}")
        print(f"Duplicates: {result['duplicate_count']}")
        
        if result['errors']:
            print(f"\nErrors:")
            for err in result['errors']:
                print(f"  - {err}")
            return 1
        
        print("\nAll validations passed.")
        return 0
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_agreement(args) -> int:
    """Compute inter-rater agreement."""
    try:
        af = load_annotations(args.annotation_file)
        
        # Validate first
        result = validate_annotation_file(af)
        if not result['is_valid']:
            print(f"Cannot compute agreement: annotation file is invalid", file=sys.stderr)
            for err in result['errors']:
                print(f"  - {err}", file=sys.stderr)
            return 1
        
        # Reorganize by CVE
        cve_annotations = {}
        for ann in af.annotations:
            if ann.cve_id not in cve_annotations:
                cve_annotations[ann.cve_id] = []
            cve_annotations[ann.cve_id].append(ann)
        
        # Compute agreement
        summary = compute_agreement_summary(cve_annotations)
        
        print(f"Inter-Rater Agreement Report")
        print(f"{'=' * 60}")
        print(f"File: {args.annotation_file}")
        print(f"CVEs annotated: {summary['n_units']}")
        print(f"Raters: {summary['n_raters']}")
        print(f"Pairable CVEs (>1 annotation): {summary['pairable_units']}")
        print(f"Total annotations: {summary['total_annotations']}")
        print(f"\nLabel Distribution:")
        for label, count in sorted(summary['label_distribution'].items()):
            print(f"  {label}: {count}")
        
        if summary['errors']:
            print(f"\nWarnings/Errors:")
            for err in summary['errors']:
                print(f"  - {err}")
        
        if summary['alpha'] is not None:
            print(f"\nKrippendorff's Alpha (Ordinal Distance):")
            print(f"  Alpha: {summary['alpha']:.4f}")
            print(f"  Interpretation: {summary['alpha_interpretation']}")
        
        if args.output:
            with open(args.output, "w") as f:
                json.dump(summary, f, indent=2)
            print(f"\nResults saved to: {args.output}")
        
        return 0
    
    except InsufficientAnnotationData as e:
        print(f"Cannot compute agreement: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_consensus(args) -> int:
    """Generate consensus labels."""
    try:
        af = load_annotations(args.annotation_file)
        
        # Validate first
        result = validate_annotation_file(af)
        if not result['is_valid']:
            print(f"Cannot generate consensus: annotation file is invalid", file=sys.stderr)
            return 1
        
        # Reorganize by CVE
        cve_annotations = {}
        for ann in af.annotations:
            if ann.cve_id not in cve_annotations:
                cve_annotations[ann.cve_id] = []
            cve_annotations[ann.cve_id].append(ann)
        
        # Compute consensus
        allow_ties = args.allow_ties
        tiebreak = args.tiebreak if not allow_ties else "severity"
        consensus_result = compute_consensus_for_dataset(
            cve_annotations,
            allow_ties=allow_ties,
            tiebreak_method=tiebreak
        )
        
        print(f"Consensus Label Computation Report")
        print(f"{'=' * 60}")
        print(f"File: {args.annotation_file}")
        print(f"Total CVEs: {consensus_result['total_cves']}")
        print(f"Consensus derived: {consensus_result['consensus_cves']}")
        print(f"Unresolved ties: {len(consensus_result['ties'])}")
        
        if consensus_result['ties']:
            print(f"\nTied CVEs (unresolved):")
            for cve_id in consensus_result['ties']:
                print(f"  - {cve_id}")
        
        if consensus_result['errors']:
            print(f"\nErrors:")
            for err in consensus_result['errors']:
                print(f"  - {err}")
        
        if args.output:
            output_data = {
                "schema_version": "1.0",
                "provenance_note": "Consensus labels derived from independent annotations via majority vote.",
                "consensus_labels": consensus_result['consensus_labels'],
                "ties": consensus_result['ties'],
                "summary": {
                    "total_cves": consensus_result['total_cves'],
                    "consensus_cves": consensus_result['consensus_cves'],
                    "unresolved_ties": len(consensus_result['ties']),
                }
            }
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2)
            print(f"\nConsensus labels saved to: {args.output}")
        
        return 0
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_template(args) -> int:
    """Generate empty annotation file template."""
    try:
        af = empty_annotation_file()
        
        if args.output:
            save_annotations(af, args.output)
            print(f"Template saved to: {args.output}")
        else:
            import json
            print(json.dumps({
                "schema_version": af.schema_version,
                "provenance_note": af.provenance_note,
                "annotations": []
            }, indent=2))
        
        return 0
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Vulture-AI Independent Annotation Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate annotations
  python annotation_cli.py validate annotations.json
  
  # Compute inter-rater agreement
  python annotation_cli.py agreement annotations.json -o agreement.json
  
  # Generate consensus labels
  python annotation_cli.py consensus annotations.json -o consensus.json
  
  # Generate template
  python annotation_cli.py template -o annotations_template.json
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")
    subparsers.required = True
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate annotation file")
    validate_parser.add_argument("annotation_file", help="Path to annotation JSON file")
    validate_parser.set_defaults(func=cmd_validate)
    
    # Agreement command
    agreement_parser = subparsers.add_parser("agreement", help="Compute inter-rater agreement")
    agreement_parser.add_argument("annotation_file", help="Path to annotation JSON file")
    agreement_parser.add_argument("-o", "--output", help="Output JSON file for agreement report")
    agreement_parser.set_defaults(func=cmd_agreement)
    
    # Consensus command
    consensus_parser = subparsers.add_parser("consensus", help="Generate consensus labels")
    consensus_parser.add_argument("annotation_file", help="Path to annotation JSON file")
    consensus_parser.add_argument("-o", "--output", help="Output JSON file for consensus labels")
    consensus_parser.add_argument("--allow-ties", action="store_true", 
                                   help="Flag ties instead of auto-breaking them")
    consensus_parser.add_argument("--tiebreak", choices=["severity"], default="severity",
                                   help="Tie-breaking method (default: severity)")
    consensus_parser.set_defaults(func=cmd_consensus)
    
    # Template command
    template_parser = subparsers.add_parser("template", help="Generate empty annotation template")
    template_parser.add_argument("-o", "--output", help="Output JSON file (default: stdout)")
    template_parser.set_defaults(func=cmd_template)
    
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
