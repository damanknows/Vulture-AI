"""
Reproducible Temporal Exploitation Outcome Benchmark (TEOB) Builder
===================================================================

Constructs `data/benchmark/temporal/teob_2026-07-01_90d.csv` from cached
NVD CVE 2.0, NVD CVE History 2.0, FIRST EPSS (date=2026-07-01), and
CISA KEV (2026.10.13) data without using any post-cutoff input features
or author-assigned SSVC labels.

Usage:
    python3 -m experiments.build_temporal_benchmark
"""

import csv
import hashlib
import json
import math
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


CUTOFF_DATE = "2026-07-01"
CUTOFF_DT = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
HORIZON_DAYS = 90
HORIZON_END = (date.fromisoformat(CUTOFF_DATE) + timedelta(days=HORIZON_DAYS)).isoformat()

NVD_COHORT_CACHE = Path("data/benchmark/temporal/cache/nvd_pub_2026-06-01_to_2026-07-01.json")
NVD_HISTORY_CACHE = Path("data/benchmark/temporal/cache/nvd_cvss_history_post_2026-07-01.json")
EPSS_CACHE = Path("data/benchmark/temporal/cache/epss_2026-07-01.json")
KEV_CACHE = Path("data/external/known_exploited_vulnerabilities.json")

OUT_CSV = Path("data/benchmark/temporal/teob_2026-07-01_90d.csv")
OUT_MANIFEST = Path("data/benchmark/temporal/teob_manifest.json")

FIELDNAMES = [
    "cve_id",
    "cutoff_date",
    "published_date",
    "cvss_as_of_cutoff",
    "cvss_status_at_cutoff",
    "cvss_vector_as_of_cutoff",
    "cvss_source_at_cutoff",
    "epss_as_of_cutoff",
    "epss_percentile_as_of_cutoff",
    "kev_at_cutoff",
    "future_kev_addition_date",
    "future_kev_within_horizon",
    "outcome_label",
    "observation_horizon_days",
    "nvd_last_modified",
    "source_provenance",
]

_VECTOR_RE = re.compile(
    r"(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH])"
)
_NVD_ANALYSIS_EVENTS = {"Initial Analysis", "Reanalysis", "Modified Analysis"}


def parse_utc_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parses an ISO-8601 timestamp (naive assumed UTC) into a UTC-aware datetime."""
    if not ts or not isinstance(ts, str):
        return None
    s = ts.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalize_v3_vector(vector_str: Optional[str]) -> Optional[str]:
    if not vector_str:
        return None
    m = _VECTOR_RE.search(vector_str)
    return m.group(1) if m else None


def _roundup(val: float) -> float:
    int_input = round(val * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def compute_cvss_v3_base_from_vector(vector_str: str) -> Optional[float]:
    """Computes CVSS v3.0/v3.1 Base Score from a vector string (e.g. NIST AV:N/AC:L/...)."""
    if not vector_str:
        return None
    m = _VECTOR_RE.search(vector_str)
    if not m:
        return None
    av, ac, pr, ui, s, c, i, a = [part.split(":")[1] for part in m.group(1).split("/")]
    av_w = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[av]
    ac_w = {"L": 0.77, "H": 0.44}[ac]
    pr_w = (
        {"N": 0.85, "L": 0.68, "H": 0.50}[pr]
        if s == "C"
        else {"N": 0.85, "L": 0.62, "H": 0.27}[pr]
    )
    ui_w = {"N": 0.85, "R": 0.62}[ui]
    cia = {"N": 0.0, "L": 0.22, "H": 0.56}
    isc_base = 1.0 - ((1.0 - cia[c]) * (1.0 - cia[i]) * (1.0 - cia[a]))
    if s == "U":
        isc = 6.42 * isc_base
    else:
        isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    if isc <= 0:
        return 0.0
    esc = 8.22 * av_w * ac_w * pr_w * ui_w
    if s == "U":
        return min(_roundup(isc + esc), 10.0)
    return min(_roundup(1.08 * (isc + esc)), 10.0)


def _extract_current_v3_entries(cve_obj: dict) -> List[dict]:
    """Extracts all current CVSS v3.1 / v3.0 entries with type, source, vector, and score."""
    metrics = cve_obj.get("metrics", {})
    entries = []
    for key, ver in (("cvssMetricV31", "CVSS V3.1"), ("cvssMetricV30", "CVSS V3.0")):
        for e in metrics.get(key, []):
            cvss_data = e.get("cvssData", {})
            score = cvss_data.get("baseScore")
            vec = _normalize_v3_vector(cvss_data.get("vectorString", ""))
            if score is not None or vec is not None:
                entries.append(
                    {
                        "ver": ver,
                        "type": e.get("type", "Secondary"),
                        "source": e.get("source", "unknown"),
                        "vector": vec,
                        "score": float(score) if score is not None else compute_cvss_v3_base_from_vector(vec or ""),
                    }
                )
    return entries


def _pick_best_v3_entry(entries: List[dict]) -> Optional[dict]:
    """Selects CVSS v3.1 over v3.0, and Primary over Secondary/Reconstructed."""
    if not entries:
        return None
    ver_rank = {"CVSS V3.1": 0, "CVSS V3.0": 1}
    type_rank = {"Primary": 0, "Secondary": 1, "Reconstructed": 2}
    return min(
        entries,
        key=lambda e: (
            ver_rank.get(e.get("ver", "CVSS V3.1"), 2),
            type_rank.get(e.get("type", "Secondary"), 2),
        ),
    )


def extract_current_cvss_v3(cve_obj: dict) -> Optional[float]:
    """Extracts NVD Primary (or first available) CVSS v3.1 / v3.0 baseScore."""
    best = _pick_best_v3_entry(_extract_current_v3_entries(cve_obj))
    return best["score"] if best is not None else None


def resolve_cvss_as_of_cutoff(
    cve_obj: dict,
    history_events: List[dict],
    cutoff_date: str = CUTOFF_DATE,
) -> Tuple[Optional[float], str, str, str]:
    """
    Determines CVSS v3.x base score demonstrably available strictly before
    `cutoff_date` 00:00:00 UTC by walking post-cutoff NVD cvehistory events
    backwards from the current NVD metrics state.

    Returns:
        (score, status, vector_core, source_tag)
    """
    cutoff_dt = parse_utc_timestamp(f"{cutoff_date}T00:00:00Z")
    last_mod_dt = parse_utc_timestamp(cve_obj.get("lastModified", ""))
    current_entries = _extract_current_v3_entries(cve_obj)
    best_current = _pick_best_v3_entry(current_entries)

    if last_mod_dt is not None and cutoff_dt is not None and last_mod_dt < cutoff_dt:
        if best_current is None:
            return None, "missing_in_nvd", "", ""
        return (
            best_current["score"],
            "unchanged_since_cutoff",
            best_current.get("vector") or "",
            f"{best_current.get('type', '')}:{best_current.get('source', '')}",
        )

    # Filter CVSS v3.x events occurring at or after cutoff_dt (>= YYYY-MM-DDT00:00:00Z)
    v3_events = []
    for e in history_events:
        if "CVSS V3" not in e.get("type", ""):
            continue
        ev_dt = parse_utc_timestamp(e.get("created", ""))
        if ev_dt is None or cutoff_dt is None:
            continue
        if ev_dt >= cutoff_dt:
            v3_events.append((ev_dt, e))

    if not v3_events:
        if best_current is None:
            return None, "missing_in_nvd", "", ""
        return (
            best_current["score"],
            "no_post_cutoff_cvss_change",
            best_current.get("vector") or "",
            f"{best_current.get('type', '')}:{best_current.get('source', '')}",
        )

    # Walk backwards in reverse chronological order to undo post-cutoff Added/Removed/Changed
    state = [dict(entry) for entry in current_entries]
    v3_events.sort(key=lambda pair: pair[0], reverse=True)

    for _, ev in v3_events:
        action = ev.get("action", "")
        ev_name = ev.get("eventName", "")
        ev_ver = ev.get("type", "CVSS V3.1")
        is_nvd_ev = ev_name in _NVD_ANALYSIS_EVENTS

        if action == "Added":
            nv = _normalize_v3_vector(ev.get("newValue", ""))
            if not nv:
                return None, "unreconstructable_post_cutoff_change", "", ""
            # Prefer matching Primary if NVD analysis event, else any matching vector
            match_idx = None
            if is_nvd_ev:
                match_idx = next(
                    (i for i, s in enumerate(state) if s.get("vector") == nv and s.get("type") == "Primary"),
                    None,
                )
            if match_idx is None:
                match_idx = next((i for i, s in enumerate(state) if s.get("vector") == nv), None)
            if match_idx is None:
                return None, "unreconstructable_post_cutoff_change", "", ""
            state.pop(match_idx)

        elif action == "Removed":
            ov = _normalize_v3_vector(ev.get("oldValue", ""))
            ov_score = compute_cvss_v3_base_from_vector(ov or "")
            if ov is None or ov_score is None:
                return None, "unreconstructable_post_cutoff_change", "", ""
            state.append(
                {
                    "ver": ev_ver,
                    "type": "Primary" if is_nvd_ev else "Reconstructed",
                    "source": "nvd@nist.gov" if is_nvd_ev else "cvehistory_oldValue",
                    "vector": ov,
                    "score": ov_score,
                }
            )

        elif action == "Changed":
            nv = _normalize_v3_vector(ev.get("newValue", ""))
            ov = _normalize_v3_vector(ev.get("oldValue", ""))
            ov_score = compute_cvss_v3_base_from_vector(ov or "")
            if ov is None or ov_score is None:
                return None, "unreconstructable_post_cutoff_change", "", ""
            if nv:
                match_idx = next((i for i, s in enumerate(state) if s.get("vector") == nv), None)
                if match_idx is not None:
                    state.pop(match_idx)
            state.append(
                {
                    "ver": ev_ver,
                    "type": "Primary" if is_nvd_ev else "Reconstructed",
                    "source": "nvd@nist.gov" if is_nvd_ev else "cvehistory_oldValue",
                    "vector": ov,
                    "score": ov_score,
                }
            )
        else:
            return None, "unreconstructable_post_cutoff_change", "", ""

    if not state:
        return None, "added_after_cutoff_excluded", "", ""

    best_pre = _pick_best_v3_entry(state)
    if best_pre is None or best_pre.get("score") is None:
        return None, "unreconstructable_post_cutoff_change", "", ""
    return (
        best_pre["score"],
        "reconstructed_from_cvehistory",
        best_pre.get("vector") or "",
        f"{best_pre.get('type', '')}:{best_pre.get('source', '')}",
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_temporal_benchmark(
    nvd_cohort_path: Path = NVD_COHORT_CACHE,
    nvd_history_path: Path = NVD_HISTORY_CACHE,
    epss_path: Path = EPSS_CACHE,
    kev_path: Path = KEV_CACHE,
    out_csv: Path = OUT_CSV,
    out_manifest: Path = OUT_MANIFEST,
    cutoff_date: str = CUTOFF_DATE,
    horizon_days: int = HORIZON_DAYS,
) -> Dict[str, object]:
    cutoff_dt = parse_utc_timestamp(f"{cutoff_date}T00:00:00Z")
    horizon_end = (date.fromisoformat(cutoff_date) + timedelta(days=horizon_days)).isoformat()

    with open(nvd_cohort_path, "r", encoding="utf-8") as f:
        nvd_data = json.load(f)
    with open(nvd_history_path, "r", encoding="utf-8") as f:
        hist_raw = json.load(f)
    hist_data = hist_raw.get("cvss_changes", {})
    with open(epss_path, "r", encoding="utf-8") as f:
        epss_data = json.load(f).get("data", {})
    with open(kev_path, "r", encoding="utf-8") as f:
        kev_raw = json.load(f)

    # Validate NVD history retrieval covers the NVD cohort snapshot
    nvd_ret = parse_utc_timestamp(nvd_data.get("retrieved_utc"))
    hist_ret = parse_utc_timestamp(hist_raw.get("retrieved_utc"))
    if nvd_ret is not None and hist_ret is not None and hist_ret < nvd_ret:
        raise ValueError(
            f"NVD history cache ({hist_ret.isoformat()}) predates NVD cohort cache ({nvd_ret.isoformat()})."
        )

    # Validate KEV observation window completeness
    kev_released = parse_utc_timestamp(kev_raw.get("dateReleased"))
    horizon_end_dt = parse_utc_timestamp(f"{horizon_end}T23:59:59Z")
    if kev_released is not None and horizon_end_dt is not None and kev_released < horizon_end_dt:
        raise ValueError(
            f"KEV catalog dateReleased ({kev_released.isoformat()}) precedes horizon end ({horizon_end})."
        )

    kev_map: Dict[str, str] = {}
    for v in kev_raw.get("vulnerabilities", []):
        cid = v.get("cveID")
        da = v.get("dateAdded")
        if cid and da:
            date.fromisoformat(da)  # validate ISO date
            kev_map[cid] = da

    rows = []
    seen_ids = set()
    stats = {
        "nvd_total": len(nvd_data.get("vulnerabilities", [])),
        "excluded_duplicate": 0,
        "excluded_rejected": 0,
        "excluded_post_cutoff_published": 0,
        "excluded_invalid_published": 0,
        "excluded_kev_at_cutoff": 0,
        "eligible_total": 0,
        "positives_within_horizon": 0,
        "negatives_not_observed": 0,
        "cvss_status_counts": {},
        "epss_available": 0,
        "epss_missing": 0,
    }

    for item in nvd_data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cid = c.get("id", "")
        if not cid:
            continue
        if cid in seen_ids:
            stats["excluded_duplicate"] += 1
            continue
        seen_ids.add(cid)

        if c.get("vulnStatus") == "Rejected":
            stats["excluded_rejected"] += 1
            continue

        pub_dt = parse_utc_timestamp(c.get("published", ""))
        if pub_dt is None:
            stats["excluded_invalid_published"] += 1
            continue
        if cutoff_dt is not None and pub_dt >= cutoff_dt:
            stats["excluded_post_cutoff_published"] += 1
            continue
        pub_date = pub_dt.date().isoformat()

        kev_date = kev_map.get(cid)
        if kev_date and kev_date <= cutoff_date:
            stats["excluded_kev_at_cutoff"] += 1
            continue

        cvss_val, cvss_status, cvss_vec, cvss_src = resolve_cvss_as_of_cutoff(
            c, hist_data.get(cid, []), cutoff_date=cutoff_date
        )
        stats["cvss_status_counts"][cvss_status] = stats["cvss_status_counts"].get(cvss_status, 0) + 1

        ep = epss_data.get(cid)
        if ep is not None and ep.get("date") == cutoff_date:
            epss_val = float(ep["epss"])
            epss_pct = float(ep["percentile"])
            stats["epss_available"] += 1
        else:
            epss_val = None
            epss_pct = None
            stats["epss_missing"] += 1

        if kev_date and cutoff_date < kev_date <= horizon_end:
            in_horizon = 1
            future_date = kev_date
            outcome_label = "observed_kev_addition"
            stats["positives_within_horizon"] += 1
        else:
            in_horizon = 0
            future_date = ""
            outcome_label = "not observed in KEV during the horizon"
            stats["negatives_not_observed"] += 1

        prov = (
            f"nvd_cves_2.0:{cvss_status}|"
            f"first_epss:{cutoff_date if epss_val is not None else 'missing'}|"
            f"cisa_kev:{kev_raw.get('catalogVersion', '2026.10.13')}"
        )

        rows.append(
            {
                "cve_id": cid,
                "cutoff_date": cutoff_date,
                "published_date": pub_date,
                "cvss_as_of_cutoff": "" if cvss_val is None else f"{cvss_val:.1f}",
                "cvss_status_at_cutoff": cvss_status,
                "cvss_vector_as_of_cutoff": cvss_vec,
                "cvss_source_at_cutoff": cvss_src,
                "epss_as_of_cutoff": "" if epss_val is None else f"{epss_val:.9f}",
                "epss_percentile_as_of_cutoff": "" if epss_pct is None else f"{epss_pct:.9f}",
                "kev_at_cutoff": 0,
                "future_kev_addition_date": future_date,
                "future_kev_within_horizon": in_horizon,
                "outcome_label": outcome_label,
                "observation_horizon_days": horizon_days,
                "nvd_last_modified": c.get("lastModified", "")[:10],
                "source_provenance": prov,
            }
        )

    rows.sort(key=lambda r: r["cve_id"])
    stats["eligible_total"] = len(rows)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    manifest = {
        "benchmark": "TEOB",
        "version": "1.1.0",
        "cutoff_date": cutoff_date,
        "cutoff_timestamp_utc": cutoff_dt.isoformat() if cutoff_dt else "",
        "observation_horizon_days": horizon_days,
        "horizon_end_date": horizon_end,
        "output_csv": str(out_csv),
        "output_sha256": sha256_file(out_csv),
        "inputs": {
            "nvd_cohort": {"path": str(nvd_cohort_path), "sha256": sha256_file(nvd_cohort_path)},
            "nvd_history": {"path": str(nvd_history_path), "sha256": sha256_file(nvd_history_path)},
            "epss_snapshot": {"path": str(epss_path), "sha256": sha256_file(epss_path)},
            "cisa_kev": {"path": str(kev_path), "sha256": sha256_file(kev_path)},
        },
        "stats": stats,
    }
    with open(out_manifest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


if __name__ == "__main__":
    m = build_temporal_benchmark()
    print(json.dumps(m["stats"], indent=2))
