"""
Scanner-to-CPE Matching Evaluation on Synthesized Public Nmap-Style Banners
==========================================================================

Evaluates `cve_matcher.normalize_service_string` and `cve_matcher.build_cpe_uris`
against 36 synthesized public Nmap-style banners in
`data/cpe_matching/labelled_banners.csv`.

Usage:
    python3 -m experiments.revision.cpe.matching_eval
"""

import csv
import json
from pathlib import Path
from typing import Dict, List

from cve_matcher import build_cpe_uris, normalize_service_string


BANNERS_CSV = Path("data/cpe_matching/labelled_banners.csv")
OUT_JSON = Path("experiments/revision/cpe/cpe_matching_results.json")


def evaluate_cpe_matching(
    banners_path: Path = BANNERS_CSV,
    out_path: Path = OUT_JSON,
) -> Dict[str, object]:
    with open(banners_path, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    tp = fp = fn = tn = 0
    per_banner: List[dict] = []
    errors: List[dict] = []

    for row in rows:
        bid = row["banner_id"]
        product = row["product"] or None
        version = row["version"] or None
        extra = row["extra"] or ""
        has_expected = int(row["has_expected_cpe"]) == 1
        exp_vendor = row["expected_vendor"].strip().lower()
        exp_prod = row["expected_product"].strip().lower()
        exp_ver = row["expected_version"].strip().lower()

        norm = normalize_service_string(product, version, extra)
        cpes = build_cpe_uris(*norm) if norm else []

        predicted_positive = len(cpes) > 0
        matched_exact = False
        failure_mode = ""

        if predicted_positive:
            pred_vendor, pred_prod, pred_ver = norm[0].lower(), norm[1].lower(), norm[2].lower()
            # Accept exact vendor/product/version match or stripped product token match
            prod_tokens = {pred_prod, pred_prod.split()[-1]}
            if has_expected and exp_ver == pred_ver and (exp_vendor == pred_vendor or exp_prod in prod_tokens):
                matched_exact = True
            else:
                if not has_expected:
                    failure_mode = "false_positive_unlabelled_or_generic_banner"
                elif exp_ver != pred_ver:
                    failure_mode = f"version_mismatch (pred={pred_ver}, exp={exp_ver})"
                else:
                    failure_mode = f"vendor_product_mismatch (pred={pred_vendor}:{pred_prod}, exp={exp_vendor}:{exp_prod})"
        else:
            if has_expected:
                failure_mode = "false_negative_nonstandard_or_unparsed_version"

        if has_expected and matched_exact:
            tp += 1
            verdict = "TP"
        elif predicted_positive and not matched_exact:
            fp += 1
            verdict = "FP"
        elif not predicted_positive and has_expected:
            fn += 1
            verdict = "FN"
        else:
            tn += 1
            verdict = "TN"

        rec = {
            "banner_id": bid,
            "product": product,
            "version": version,
            "extra": extra,
            "has_expected_cpe": has_expected,
            "expected_cpe_tuple": f"{exp_vendor}:{exp_prod}:{exp_ver}" if has_expected else "",
            "generated_cpes": cpes,
            "verdict": verdict,
            "failure_mode": failure_mode,
        }
        per_banner.append(rec)
        if verdict in ("FP", "FN"):
            errors.append(rec)

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    result = {
        "dataset": str(banners_path),
        "dataset_note": "Synthesized public Nmap-style banners (not live network captures).",
        "n_banners": len(rows),
        "confusion_matrix": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "metrics": {"precision": precision, "recall": recall, "f1": f1},
        "errors": errors,
        "per_banner": per_banner,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    rep = evaluate_cpe_matching()
    print(json.dumps({"confusion_matrix": rep["confusion_matrix"], "metrics": rep["metrics"], "n_errors": len(rep["errors"])}, indent=2))
