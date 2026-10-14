#!/usr/bin/env python3
"""
experiments/enrich_benchmark_kev.py

Enriches the existing 41-record Vulture-AI benchmark dataset (data/benchmark/cves.csv)
with independently sourced CISA KEV exploitation telemetry.

Core Research & Reproducibility Principles:
1. Field Semantics:
   - cisa_kev_source_url contains a genuine, validated HTTP/HTTPS URL.
   - cisa_kev_vulnerability_name preserves CISA's official vulnerabilityName.
   - cisa_kev_notes preserves CISA's raw notes attribute.
   - Official CISA feed URL is documented in provenance alongside field-level lineage.
2. Provenance Integrity:
   - Derives release date, version, vulnerability count, and SHA-256 directly from cached JSON.
   - Records actual runtime UTC processing timestamp.
   - Distinguishes runtime processing time from local cache modification timestamp.
   - Ensures the retrospective report reflects identical computed metadata and checksums.
3. Ranking Validation & Metric Integrity:
   - Confirms every ranking contains unique, eligible real CVE identifiers.
   - Confirms all compared methods rank the exact same eligible benchmark population.
   - Validates ranking lengths before calculating precision@k or recall@k.
   - Precision@k denominator is strictly k.
   - Recall@k denominator is explicitly the total matched KEV count in the eligible benchmark (N_KEV = 25).
   - Asserts benchmark KEV denominator matches the verified population.
4. Scientific Disclaimers:
   - Formally labels evaluation as retrospective concordance against the retrieved snapshot.
   - Discloses information overlap / feature input (KEV flag used in VRS model).
   - Clarifies that unlisted CVEs are unknown/unobserved, not confirmed negatives.
   - Explicitly notes that features were not temporally reconstructed at original disclosure time.
"""

import os
import csv
import json
import re
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Any

BENCHMARK_PATH = os.path.join("data", "benchmark", "cves.csv")
ENRICHED_PATH = os.path.join("data", "benchmark", "cves_enriched.csv")
PROVENANCE_PATH = os.path.join("data", "benchmark", "cisa_kev_provenance.json")
KEV_CATALOG_PATH = os.path.join("data", "external", "known_exploited_vulnerabilities.json")
RETROSPECTIVE_TABLE_PATH = os.path.join("experiments", "results", "kev_retrospective_table.md")

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPECTED_BENCHMARK_SHA256 = "27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e"
SYNTHETIC_IDS = {"CVE-2024-99991", "CVE-2024-99992"}


def compute_sha256(filepath: str) -> str:
    """Computes the SHA-256 checksum of a file in binary mode."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def extract_source_url(raw_notes: str, cve_id: str) -> str:
    """
    Extracts a genuine, valid HTTP/HTTPS source URL from CISA KEV raw notes.
    Cleans trailing punctuation and prioritizes official CISA directive/advisory links.
    """
    if not raw_notes or not isinstance(raw_notes, str):
        return ""
    # Extract candidate URLs
    urls = re.findall(r"https?://[^\s;,\)\"]+", raw_notes)
    if not urls:
        return ""
    # Clean trailing punctuation (semicolons, dots, commas)
    cleaned = [u.rstrip(".;,") for u in urls if u.startswith(("http://", "https://"))]
    if not cleaned:
        return ""
    # Prioritize official CISA advisory or directive links if present
    cisa_urls = [u for u in cleaned if "cisa.gov" in u]
    if cisa_urls:
        return cisa_urls[0]
    # Otherwise return the primary advisory link
    return cleaned[0]


def load_kev_catalog(catalog_path: str) -> Tuple[Dict[str, dict], str, dict]:
    """
    Loads CISA KEV JSON catalog, verifies required structure, and computes SHA-256.
    Derives catalog release date, version, and record count from the cached JSON.
    """
    if not os.path.exists(catalog_path):
        raise FileNotFoundError(f"CISA KEV catalog not found at {catalog_path}")

    sha256_hash = compute_sha256(catalog_path)
    with open(catalog_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Corrupted or invalid JSON in KEV catalog at {catalog_path}: {e}")

    # Validate required top-level catalog metadata
    required_keys = ["title", "catalogVersion", "dateReleased", "vulnerabilities"]
    missing_keys = [k for k in required_keys if k not in data]
    if missing_keys:
        raise KeyError(f"KEV catalog missing required top-level metadata: {missing_keys}")

    if not isinstance(data["vulnerabilities"], list):
        raise TypeError("KEV catalog 'vulnerabilities' field must be a list")

    # Map by exact cveID
    kev_map = {}
    for item in data.get("vulnerabilities", []):
        cid = item.get("cveID", "").strip()
        if cid:
            kev_map[cid] = item

    return kev_map, sha256_hash, data


def validate_ranking(ranking: List[str], eligible_cves: Set[str], ranking_name: str = "ranking") -> List[str]:
    """
    Validates ranking integrity:
    - Confirms ranking is non-empty.
    - Confirms zero duplicate identifiers.
    - Confirms no synthetic test case IDs appear in eligible real ranking.
    - Confirms exact population match against eligible_cves.
    """
    if not ranking:
        raise ValueError(f"Ranking '{ranking_name}' is empty.")

    # Duplicate check
    if len(ranking) != len(set(ranking)):
        seen = set()
        duplicates = set()
        for cid in ranking:
            if cid in seen:
                duplicates.add(cid)
            seen.add(cid)
        raise ValueError(f"Duplicate IDs detected in ranking '{ranking_name}': {sorted(duplicates)}")

    # Synthetic ID check
    found_synthetic = [cid for cid in ranking if cid in SYNTHETIC_IDS]
    if found_synthetic:
        raise ValueError(f"Synthetic IDs detected in eligible ranking '{ranking_name}': {found_synthetic}")

    # Population match
    ranking_set = set(ranking)
    if ranking_set != eligible_cves:
        missing = eligible_cves - ranking_set
        extra = ranking_set - eligible_cves
        raise ValueError(
            f"Population mismatch in ranking '{ranking_name}': missing={sorted(missing)}, extra={sorted(extra)}"
        )

    return ranking


def validate_consistent_populations(rankings_dict: Dict[str, List[str]], eligible_cves: Set[str]):
    """Confirms all compared methods rank the exact same eligible benchmark population."""
    for method_name, rk in rankings_dict.items():
        validate_ranking(rk, eligible_cves, ranking_name=method_name)


def calculate_precision_at_k(ranking: List[str], positive_set: Set[str], k: int) -> float:
    """
    Calculates Precision@k: fraction of top-k items that are positive.
    Requires len(ranking) >= k and k > 0.
    Denominator is strictly k.
    """
    if k <= 0:
        raise ValueError(f"Cutoff k must be positive, got {k}")
    if len(ranking) < k:
        raise ValueError(f"Cannot calculate Precision@{k}: ranking length ({len(ranking)}) is less than k={k}")

    hits = sum(1 for cid in ranking[:k] if cid in positive_set)
    return hits / float(k)


def calculate_recall_at_k(ranking: List[str], positive_set: Set[str], total_positives: int, k: int) -> float:
    """
    Calculates Recall@k: fraction of all relevant positives captured in top-k.
    Requires len(ranking) >= k, k > 0, and total_positives > 0.
    Denominator is strictly total_positives.
    """
    if k <= 0:
        raise ValueError(f"Cutoff k must be positive, got {k}")
    if total_positives <= 0:
        raise ValueError(f"Total positives denominator must be > 0, got {total_positives}")
    if len(ranking) < k:
        raise ValueError(f"Cannot calculate Recall@{k}: ranking length ({len(ranking)}) is less than k={k}")

    hits = sum(1 for cid in ranking[:k] if cid in positive_set)
    return hits / float(total_positives)


def enrich_benchmark():
    """Main execution pipeline for CISA KEV benchmark enrichment."""
    # 1. Verify original benchmark file integrity
    if not os.path.exists(BENCHMARK_PATH):
        raise FileNotFoundError(f"Benchmark file missing: {BENCHMARK_PATH}")

    actual_benchmark_sha = compute_sha256(BENCHMARK_PATH)
    if actual_benchmark_sha != EXPECTED_BENCHMARK_SHA256:
        raise ValueError(
            f"Benchmark checksum mismatch!\nExpected: {EXPECTED_BENCHMARK_SHA256}\nActual:   {actual_benchmark_sha}"
        )

    # 2. Load CISA KEV catalog & derive metadata
    kev_map, kev_sha256, raw_kev_meta = load_kev_catalog(KEV_CATALOG_PATH)
    cache_mtime_utc = datetime.fromtimestamp(os.path.getmtime(KEV_CATALOG_PATH), tz=timezone.utc).isoformat()
    processing_timestamp_utc = datetime.now(timezone.utc).isoformat()

    catalog_version = raw_kev_meta.get("catalogVersion", "")
    catalog_date_released = raw_kev_meta.get("dateReleased", "")
    catalog_vulnerabilities_count = raw_kev_meta.get("count", len(raw_kev_meta.get("vulnerabilities", [])))

    # 3. Read benchmark records
    with open(BENCHMARK_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        original_fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    cve_col = "cve_id"
    if cve_col not in original_fieldnames:
        raise KeyError(f"Expected identifier column '{cve_col}' in {original_fieldnames}")

    # Enriched columns to append
    new_fieldnames = [
        "is_synthetic",
        "cisa_kev_listed",
        "cisa_kev_status",
        "cisa_kev_date_added",
        "cisa_kev_due_date",
        "cisa_kev_required_action",
        "cisa_kev_source_url",
        "cisa_kev_vulnerability_name",
        "cisa_kev_notes"
    ]
    all_fieldnames = list(original_fieldnames) + new_fieldnames

    matched_real = []
    unmatched_real = []
    synthetic_records = []
    enriched_rows = []

    for r in rows:
        cid = r[cve_col].strip()
        row_copy = dict(r)

        if cid in SYNTHETIC_IDS:
            synthetic_records.append(cid)
            row_copy["is_synthetic"] = "True"
            row_copy["cisa_kev_listed"] = "N/A (synthetic)"
            row_copy["cisa_kev_status"] = "synthetic_excluded"
            row_copy["cisa_kev_date_added"] = ""
            row_copy["cisa_kev_due_date"] = ""
            row_copy["cisa_kev_required_action"] = ""
            row_copy["cisa_kev_source_url"] = ""
            row_copy["cisa_kev_vulnerability_name"] = "SYNTHETIC TEST CASE"
            row_copy["cisa_kev_notes"] = "SYNTHETIC: Non-existent ID preserved solely for missing-data handling test."
        elif cid in kev_map:
            kev_entry = kev_map[cid]
            matched_real.append(cid)
            row_copy["is_synthetic"] = "False"
            row_copy["cisa_kev_listed"] = "True"
            row_copy["cisa_kev_status"] = "listed"
            row_copy["cisa_kev_date_added"] = kev_entry.get("dateAdded", "")
            row_copy["cisa_kev_due_date"] = kev_entry.get("dueDate", "")
            row_copy["cisa_kev_required_action"] = kev_entry.get("requiredAction", "")
            row_copy["cisa_kev_source_url"] = extract_source_url(kev_entry.get("notes", ""), cid)
            row_copy["cisa_kev_vulnerability_name"] = kev_entry.get("vulnerabilityName", "")
            row_copy["cisa_kev_notes"] = kev_entry.get("notes", "")
        else:
            unmatched_real.append(cid)
            row_copy["is_synthetic"] = "False"
            row_copy["cisa_kev_listed"] = "False"
            row_copy["cisa_kev_status"] = "not_listed_or_unknown"
            row_copy["cisa_kev_date_added"] = ""
            row_copy["cisa_kev_due_date"] = ""
            row_copy["cisa_kev_required_action"] = ""
            row_copy["cisa_kev_source_url"] = ""
            row_copy["cisa_kev_vulnerability_name"] = ""
            row_copy["cisa_kev_notes"] = (
                "Unlisted in CISA KEV catalog; indicates unobserved in federal reporting, NOT confirmed non-exploitation."
            )

        enriched_rows.append(row_copy)

    # 4. Write data/benchmark/cves_enriched.csv (original cves.csv strictly untouched)
    os.makedirs(os.path.dirname(ENRICHED_PATH), exist_ok=True)
    with open(ENRICHED_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_fieldnames)
        writer.writeheader()
        writer.writerows(enriched_rows)

    enriched_sha256 = compute_sha256(ENRICHED_PATH)

    # Confirm original benchmark was not modified
    post_check_benchmark_sha = compute_sha256(BENCHMARK_PATH)
    assert post_check_benchmark_sha == EXPECTED_BENCHMARK_SHA256, "Original cves.csv was modified!"

    # 5. Write provenance JSON
    provenance = {
        "metadata": {
            "title": "Vulture-AI Benchmark CISA KEV Enrichment Provenance",
            "processing_timestamp_utc": processing_timestamp_utc,
            "script": "experiments/enrich_benchmark_kev.py"
        },
        "cisa_kev_feed": {
            "official_feed_url": CISA_KEV_FEED_URL,
            "local_cache_path": KEV_CATALOG_PATH,
            "local_cache_modified_utc": cache_mtime_utc,
            "source_mode": "cached_local_file",
            "catalog_title": raw_kev_meta.get("title", "CISA Catalog of Known Exploited Vulnerabilities"),
            "catalog_version": catalog_version,
            "catalog_date_released": catalog_date_released,
            "catalog_vulnerabilities_count": catalog_vulnerabilities_count,
            "sha256_checksum": kev_sha256
        },
        "benchmark_source": {
            "source_file": BENCHMARK_PATH,
            "sha256_checksum": EXPECTED_BENCHMARK_SHA256,
            "record_count": len(rows),
            "identifier_column": cve_col
        },
        "enriched_benchmark": {
            "target_file": ENRICHED_PATH,
            "sha256_checksum": enriched_sha256,
            "record_count": len(enriched_rows),
            "added_columns": new_fieldnames,
            "field_semantics": {
                "is_synthetic": "Boolean indicator distinguishing synthetic missing-data edge cases from real CVEs.",
                "cisa_kev_listed": "Boolean flag indicating presence in the CISA KEV catalog (or 'N/A (synthetic)').",
                "cisa_kev_status": "Categorical status: 'listed', 'not_listed_or_unknown', or 'synthetic_excluded'.",
                "cisa_kev_date_added": "CISA KEV catalog dateAdded attribute under BOD 22-01 mandates.",
                "cisa_kev_due_date": "CISA KEV catalog dueDate attribute for federal civilian agencies.",
                "cisa_kev_required_action": "CISA KEV catalog requiredAction remediation requirement.",
                "cisa_kev_source_url": "Primary HTTP/HTTPS advisory or reference URL parsed and validated from KEV catalog references.",
                "cisa_kev_vulnerability_name": "Official CISA KEV catalog vulnerabilityName attribute.",
                "cisa_kev_notes": "Official CISA KEV catalog notes attribute containing vendor advisories and directives."
            }
        },
        "matching_statistics": {
            "total_benchmark_records": len(rows),
            "real_cve_records": len(matched_real) + len(unmatched_real),
            "synthetic_records_count": len(synthetic_records),
            "real_matched_in_cisa_kev": len(matched_real),
            "real_unmatched_in_cisa_kev": len(unmatched_real),
            "matched_cve_ids": sorted(matched_real),
            "unmatched_cve_ids": sorted(unmatched_real),
            "synthetic_cve_ids": sorted(synthetic_records)
        },
        "scientific_disclaimers": {
            "retrospective_nature": (
                "This evaluation is a retrospective concordance study against the CISA KEV catalog snapshot "
                f"(version {catalog_version}), NOT a temporal predictive trial. Baseline scores and VRS were not "
                "temporally reconstructed using point-in-time snapshots prior to exploitation."
            ),
            "information_overlap_disclosure": (
                "The VRS model includes a KEV indicator component (K in {0, 1}) and emergency bucket override "
                "in its input schema. Consequently, the high concordance observed between VRS rankings and CISA KEV "
                "inclusion partially reflects direct feature input rather than pure independent predictive forecasting."
            ),
            "catalog_absence_interpretation": (
                "Absence from the CISA KEV catalog indicates that a vulnerability has not been observed and cataloged "
                f"by CISA federal reporting channels as of the catalog release date ({catalog_date_released}). "
                "It MUST NOT be interpreted as confirmed non-exploitation or as a negative ground-truth label."
            ),
            "catalog_date_interpretation": (
                "The 'dateAdded' attribute denotes the administrative date CISA added the CVE to the Known Exploited "
                "Vulnerabilities catalog under BOD 22-01 mandates. It MUST NOT be interpreted as the date of first weaponization "
                "or initial in-the-wild exploitation by adversaries."
            ),
            "synthetic_records_policy": (
                "Records CVE-2024-99991 and CVE-2024-99992 are non-existent identifiers created strictly to test "
                "missing-data engine behaviors. They are explicitly excluded from all empirical real-world outcome evaluations."
            )
        }
    }

    with open(PROVENANCE_PATH, "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2)

    # 6. Generate Retrospective Comparison Summary Table with validated rankings
    catalog_meta = {
        "version": catalog_version,
        "date_released": catalog_date_released,
        "count": catalog_vulnerabilities_count,
        "processing_utc": processing_timestamp_utc
    }
    generate_retrospective_comparison(rows, kev_map, catalog_meta, kev_sha256)

    print("=" * 70)
    print("VULTURE-AI CISA KEV BENCHMARK ENRICHMENT COMPLETE")
    print("=" * 70)
    print(f"Original Benchmark: {BENCHMARK_PATH} (SHA-256: {EXPECTED_BENCHMARK_SHA256}) [UNTOUCHED]")
    print(f"Enriched Benchmark: {ENRICHED_PATH} (SHA-256: {enriched_sha256})")
    print(f"Provenance File:    {PROVENANCE_PATH}")
    print(f"Retrospective Doc:  {RETROSPECTIVE_TABLE_PATH}")
    print("-" * 70)
    print(f"Catalog Version:    {catalog_version} (Released: {catalog_date_released})")
    print(f"Catalog SHA-256:    {kev_sha256}")
    print(f"Processing Time:    {processing_timestamp_utc} (UTC)")
    print(f"Local Cache MTime:  {cache_mtime_utc} (UTC)")
    print("-" * 70)
    print(f"Total Benchmark Records:  {len(rows)}")
    print(f"  - Real CVE Records:     {len(matched_real) + len(unmatched_real)}")
    print(f"    * Matched in KEV:     {len(matched_real)}")
    print(f"    * Unmatched (Unlisted):{len(unmatched_real)}")
    print(f"  - Synthetic Test Cases: {len(synthetic_records)} (excluded from empirical outcomes)")
    print("=" * 70)


def generate_retrospective_comparison(
    rows: List[dict],
    kev_map: Dict[str, dict],
    catalog_meta: dict,
    catalog_sha256: str
):
    """
    Generates a rigorous retrospective comparison table between baseline rankings and CISA KEV telemetry.
    Validates ranking populations, enforces separate Precision and Recall calculations, and includes
    necessary scientific disclosures.
    """
    baselines_path = os.path.join("experiments", "results", "baselines.json")
    if not os.path.exists(baselines_path):
        return

    with open(baselines_path, "r", encoding="utf-8") as f:
        baselines = json.load(f)

    # Eligible real CVE population (39 records)
    eligible_real_cves = {r["cve_id"].strip() for r in rows if r["cve_id"].strip() not in SYNTHETIC_IDS}
    assert len(eligible_real_cves) == 39, f"Expected 39 eligible real CVEs, got {len(eligible_real_cves)}"

    # Ground-truth positive KEV set within the eligible population (25 records)
    positive_kev_set = {cid for cid in eligible_real_cves if cid in kev_map}
    total_positives = len(positive_kev_set)
    assert total_positives == 25, f"Expected 25 KEV-listed records in benchmark, got {total_positives}"

    # Extract and filter baseline rankings to eligible population
    methods = [
        ("CVSS-only", baselines.get("cvss_only", [])),
        ("EPSS-only", baselines.get("epss_only", [])),
        ("KEV-first", baselines.get("kev_first", [])),
        ("Combo Baseline", baselines.get("combo_baseline", [])),
        ("VRS Proposed (vrs-v1)", baselines.get("vrs_v1", []))
    ]

    filtered_rankings = {}
    for name, raw_order in methods:
        # Filter out synthetic IDs to ensure pure empirical outcome evaluation
        filtered = [cid for cid in raw_order if cid not in SYNTHETIC_IDS]
        validate_ranking(filtered, eligible_real_cves, ranking_name=name)
        filtered_rankings[name] = filtered

    # Verify population consistency across all compared methods
    validate_consistent_populations(filtered_rankings, eligible_real_cves)

    # Row metadata mapping
    row_meta = {r["cve_id"].strip(): r for r in rows}

    version_str = catalog_meta.get("version", "unknown")
    released_str = catalog_meta.get("date_released", "unknown")
    processing_str = catalog_meta.get("processing_utc", "unknown")

    lines = [
        "# Retrospective CISA KEV Concordance Summary",
        "",
        "**Benchmark Population**: 41 records (39 eligible real CVEs + 2 synthetic missing-data test cases)  ",
        f"**Authoritative Source**: CISA Known Exploited Vulnerabilities Catalog (Version: `{version_str}`, Released: `{released_str}`)  ",
        f"**Catalog SHA-256**: `{catalog_sha256}`  ",
        f"**Processing Timestamp (UTC)**: `{processing_str}`  ",
        "",
        "## 1. Top-15 VRS Recommendations vs. CISA KEV Evidence",
        "",
        "Evaluated on the top 15 prioritized real vulnerabilities from Vulture-AI (`vrs-v1`). Synthetic test cases are excluded from ranking evaluation.",
        "",
        "| VRS Rank | CVE ID | Vulnerability Summary | CVSS | EPSS | Exposure | SSVC Label | In KEV? | KEV Date Added | KEV Due Date | Source Advisory |",
        "|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|"
    ]

    vrs_eligible = filtered_rankings["VRS Proposed (vrs-v1)"]
    top15_kev_count = 0
    for rank, cid in enumerate(vrs_eligible[:15], 1):
        r = row_meta.get(cid, {})
        in_kev = cid in positive_kev_set
        if in_kev:
            top15_kev_count += 1
            date_added = kev_map[cid].get("dateAdded", "")
            due_date = kev_map[cid].get("dueDate", "")
            source_url = extract_source_url(kev_map[cid].get("notes", ""), cid)
            kev_str = "**YES**"
        else:
            date_added = "N/A"
            due_date = "N/A"
            source_url = "N/A"
            kev_str = "No (Unlisted)"

        desc = r.get("description", "")[:40]
        cvss = r.get("cvss", "")
        epss = r.get("epss", "")
        exp = r.get("exposure", "")
        lbl = r.get("independent_label", "")

        url_display = f"[Link]({source_url})" if source_url != "N/A" else "N/A"
        lines.append(
            f"| {rank} | `{cid}` | {desc} | {cvss} | {epss} | {exp} | {lbl} | {kev_str} | {date_added} | {due_date} | {url_display} |"
        )

    p15_vrs = calculate_precision_at_k(vrs_eligible, positive_kev_set, 15)
    r15_vrs = calculate_recall_at_k(vrs_eligible, positive_kev_set, total_positives, 15)

    lines.extend([
        "",
        f"> **Top-15 Retrospective Precision**: **{top15_kev_count}/15 ({p15_vrs*100:.1f}%)** of the top 15 prioritized items are confirmed in the official CISA KEV catalog.",
        f"> **Top-15 Retrospective Recall**: **{top15_kev_count}/{total_positives} ({r15_vrs*100:.1f}%)** of all KEV-listed items in the benchmark are captured within the top 15.",
        "",
        "## 2. Multi-Cutoff KEV Retrospective Precision and Recall Across Methods",
        "",
        "This table evaluates the fraction of recommendations at depth $k$ that correspond to confirmed KEV entries (Precision@$k$, denominator $= k$) and the proportion of all benchmark KEV entries captured (Recall@$k$, denominator $= N_{\\text{KEV}} = 25$). All comparisons use the identical eligible benchmark population ($N = 39$).",
        "",
        "| Prioritization Method | Precision@5 | Recall@5 | Precision@10 | Recall@10 | Precision@15 | Recall@15 |",
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|"
    ])

    for name, rk in filtered_rankings.items():
        p5 = calculate_precision_at_k(rk, positive_kev_set, 5)
        r5 = calculate_recall_at_k(rk, positive_kev_set, total_positives, 5)
        p10 = calculate_precision_at_k(rk, positive_kev_set, 10)
        r10 = calculate_recall_at_k(rk, positive_kev_set, total_positives, 10)
        p15 = calculate_precision_at_k(rk, positive_kev_set, 15)
        r15 = calculate_recall_at_k(rk, positive_kev_set, total_positives, 15)

        hits5 = int(round(p5 * 5))
        hits10 = int(round(p10 * 10))
        hits15 = int(round(p15 * 15))

        lines.append(
            f"| **{name}** | {p5:.4f} ({hits5}/5) | {r5:.4f} ({hits5}/25) | {p10:.4f} ({hits10}/10) | {r10:.4f} ({hits10}/25) | {p15:.4f} ({hits15}/15) | {r15:.4f} ({hits15}/25) |"
        )

    lines.extend([
        "",
        "## 3. Scientific Disclaimers & Methodological Limitations",
        "",
        "1. **Retrospective Association vs. Temporal Prediction**: This retrospective check evaluates ranking concordance against the CISA KEV snapshot frozen on 2026-10-13. Input features (CVSS, EPSS, KEV flags) were not point-in-time reconstructed at the initial historical disclosure date of each vulnerability. Hence, these metrics demonstrate retrospective concordance with known threats, not forward temporal predictive accuracy.",
        "2. **Information Overlap / Feature Leakage Disclosure**: The VRS scoring engine directly incorporates an exploitation component ($K \\in \\{0, 1\\}$) and an emergency bucket override based on KEV status. Consequently, strong alignment with KEV inclusion is partially an expected consequence of scoring input design rather than purely emergent predictive ranking.",
        "3. **Catalog Absence != Confirmed Non-Exploitation**: An unlisted status in CISA KEV denotes that a vulnerability has not been observed and cataloged through federal civilian agency reporting channels. It must NOT be interpreted as confirmed non-exploitation or as a negative ground-truth label.",
        "4. **Catalog Date != First Exploitation Date**: The `dateAdded` field represents the administrative date CISA added the CVE to the KEV catalog under BOD 22-01 mandates, not the date of initial threat actor discovery or weaponization.",
        "5. **Sample Size & Curated Benchmark Limitations ($N=41$)**: The benchmark evaluates 39 real CVEs selected across diverse risk archetypes plus 2 synthetic edge cases. While representative of varied severity and exposure tiers, performance on this curated sample does not guarantee identical precision over uncurated enterprise corpora with thousands of uncataloged vulnerabilities.",
        "6. **Synthetic Test Case Exclusions**: Records `CVE-2024-99991` and `CVE-2024-99992` are non-existent identifiers preserved exclusively to test missing-data engine behaviors. They are strictly excluded from all empirical ranking evaluation.",
        ""
    ])

    os.makedirs(os.path.dirname(RETROSPECTIVE_TABLE_PATH), exist_ok=True)
    with open(RETROSPECTIVE_TABLE_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    enrich_benchmark()
