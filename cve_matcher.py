import sys
import os
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import re
from dataclasses import dataclass

@dataclass
class CVSSInfo:
    score: Optional[float]
    severity: Optional[str]

_DISTRO_SUFFIX_RE = re.compile(
    r"\b(Ubuntu|Debian|Fedora|RHEL|CentOS|Alpine|Arch|Gentoo|SUSE|openSUSE|"
    r"FreeBSD|NetBSD|OpenBSD|macOS|Windows|MS|Windows-?Server|"
    r"build|release|final|stable|legacy)\b",
    re.IGNORECASE,
)
_PATCH_TAIL_RE = re.compile(
    r"(p\d+)|(-0ubuntu[\w\.\-]*)|(-(\d+|\w+)ubuntu[\w\.\-]*)|"
    r"(\.el\d+)|(\.fc\d+)|(\.alpine[\w\.\-]*)",
    re.IGNORECASE,
)

def _split_product_string(raw: str) -> tuple[str, str]:
    raw = raw.strip()
    if not raw:
        return "", ""
    parts = raw.split(None, 1)
    if len(parts) == 1:
        return parts[0], parts[0].lower()
    vendor, product = parts[0], parts[1]
    return vendor, f"{vendor} {product}".lower()

def normalize_service_string(
    product: Optional[str],
    version: Optional[str],
    extra: Optional[str] = None,
) -> Optional[tuple[str, str, str]]:
    if not product or not version:
        return None
    vendor, prod_key = _split_product_string(product)
    raw_version = " ".join(p for p in [version, extra or ""] if p)
    cleaned = _DISTRO_SUFFIX_RE.sub("", raw_version)
    cleaned = _PATCH_TAIL_RE.sub("", cleaned)
    cleaned = cleaned.strip(" .-_")
    cleaned = re.sub(r"\s+", " ", cleaned)
    if not cleaned:
        return None
    m = re.match(r"^([0-9]+(?:\.[0-9]+){0,3})", cleaned)
    if m:
        cleaned = m.group(1)
    return vendor, prod_key, cleaned

def build_cpe_uris(vendor: str, product: str, version: str) -> List[str]:
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace(":", "\\:").replace(" ", "\\ ")

    v = esc(vendor.lower())
    p = esc(product.lower())
    ver = esc(version)
    p_stripped = esc(product.split()[-1].lower() if product else product)

    candidates = [
        f"cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*",
    ]
    if p_stripped and p_stripped != p:
        candidates.append(f"cpe:2.3:a:{v}:{p_stripped}:{ver}:*:*:*:*:*:*:*")

    seen = set()
    out = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out

def _parse_cvss(metrics: dict) -> CVSSInfo:
    primary = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    if not primary:
        primary = metrics.get("cvssMetricV2") or []
        if primary:
            entry = primary[0].get("cvssData", {})
            return CVSSInfo(
                score=entry.get("baseScore"),
                severity=entry.get("baseSeverity"),
            )
        return CVSSInfo(None, None)
    entry = primary[0].get("cvssData", {})
    return CVSSInfo(
        score=entry.get("baseScore"),
        severity=entry.get("baseSeverity"),
    )

from threat_intel import search_nvd_by_cpe, search_nvd, fetch_epss, fetch_kev
from models import VulnerabilityRecord

logger = logging.getLogger(__name__)

def match_findings_to_cves(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Cache KEV locally for the batch
    kev_resp = fetch_kev()
    kev_set = set(kev_resp.get("data", {}).get("cves", [])) if not kev_resp.get("error") else set()
    
    enriched_findings = []
    
    for finding in findings:
        product = finding.get("product")
        version = finding.get("version")
        service = finding.get("service")
        
        cve_records: List[VulnerabilityRecord] = []
        cve_ids_to_fetch_epss = []
        
        if not product and not service:
            # Cannot match without product or service
            enriched_findings.append({
                "finding": finding,
                "cve_matches": []
            })
            continue
            
        # 1. Attempt CPE matching using the existing vulmap-pro normalizer
        # normalize_service_string returns (vendor, product, version)
        norm = normalize_service_string(product, version, "")
        
        if norm:
            vendor, norm_product, norm_version = norm
            cpe_candidates = build_cpe_uris(vendor, norm_product, norm_version)
            
            for cpe in cpe_candidates:
                nvd_resp = search_nvd_by_cpe(cpe)
                if not nvd_resp.get("error") and "data" in nvd_resp:
                    vulnerabilities = nvd_resp["data"].get("vulnerabilities", [])
                    for v_item in vulnerabilities:
                        rec = _build_record(v_item, finding, cpe, "confirmed")
                        if rec:
                            cve_records.append(rec)
                            cve_ids_to_fetch_epss.append(rec.cve_id)
                # Break after first successful CPE to avoid explosions? No, gather all matches.
                # Actually, NVD API limits to 20 per request by default in vulmap-pro, here we use default.
                
        # 2. If no matches from CPE, fall back to keyword search (Candidate)
        if not cve_records and product:
            keyword = product
            if version:
                keyword = f"{product} {version}"
            
            nvd_resp = search_nvd(keyword)
            if not nvd_resp.get("error") and "data" in nvd_resp:
                vulnerabilities = nvd_resp["data"].get("vulnerabilities", [])
                for v_item in vulnerabilities[:10]: # Limit to top 10 candidates
                    rec = _build_record(v_item, finding, f"keyword:{keyword}", "candidate")
                    if rec:
                        cve_records.append(rec)
                        cve_ids_to_fetch_epss.append(rec.cve_id)
                        
        # 3. Fetch EPSS for matched CVEs
        epss_scores = {}
        if cve_ids_to_fetch_epss:
            epss_resp = fetch_epss(cve_ids_to_fetch_epss)
            if not epss_resp.get("error"):
                epss_scores = epss_resp.get("data", {})
                
        # 4. Enrich records with EPSS and KEV
        for rec in cve_records:
            if rec.cve_id in kev_set:
                rec.kev_listed = True
            else:
                rec.kev_listed = False
                
            epss_data = epss_scores.get(rec.cve_id)
            if epss_data:
                rec.epss_probability = epss_data.get("epss")
                rec.epss_date = epss_data.get("date")
                
        # Format for output
        finding_matches = [rec.to_dict() for rec in cve_records]
        # De-duplicate by CVE ID prioritizing confirmed matches
        dedup = {}
        for fm in finding_matches:
            cid = fm["cve_id"]
            if cid not in dedup or fm["match_confidence"] == "confirmed":
                dedup[cid] = fm
                
        enriched_findings.append({
            "finding": finding,
            "cve_matches": list(dedup.values())
        })
        
    return enriched_findings

def _build_record(v_item: dict, finding: dict, match_basis: str, confidence: str) -> Optional[VulnerabilityRecord]:
    cve = v_item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
        
    metrics = cve.get("metrics") or {}
    cvss = _parse_cvss(metrics)
    
    return VulnerabilityRecord(
        cve_id=cve_id,
        cvss_score=cvss.score,
        cvss_version="3" if cvss.score else None,
        cvss_severity=cvss.severity,
        epss_probability=None,
        epss_date=None,
        kev_listed=None,
        affected_product=finding.get("product"),
        affected_version_range=finding.get("version"),
        match_confidence=confidence,
        match_status="matched",
        evidence_sources=[{"source": "nvd", "rationale": match_basis}],
        retrieved_at=datetime.now(timezone.utc).isoformat()
    )
