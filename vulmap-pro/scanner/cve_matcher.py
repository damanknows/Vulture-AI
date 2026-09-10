"""CVE matcher: normalize service versions, build CPE URIs, query NVD.

The matcher:

1. Normalizes messy version strings ("OpenSSH 8.2p1 Ubuntu-4ubuntu0.5")
   into a vendor/product + clean version tuple.
2. Constructs CPE 2.3 URIs and queries the NVD API
   (`/rest/json/cves/2.0?cpeName=...`).
3. Caches NVD responses in the `cpe_cache` table to avoid rate-limiting
   during dev iteration.
4. Falls back gracefully when NVD is unreachable — an unreachable API never
   breaks a scan; it just logs and yields no CVEs.

CPE-matching accuracy is intentionally imperfect. See Known Limitations
in the README — this is a realistic, defensible MVP behavior.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

import requests
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.db.models import CPECache, Vulnerability
from scanner.models import PortResult, ScanResult

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- types
@dataclass
class CVSSInfo:
    score: Optional[float]
    severity: Optional[str]  # LOW / MEDIUM / HIGH / CRITICAL / None


@dataclass
class CVEResult:
    cve_id: str
    description: str
    cvss: CVSSInfo
    published: Optional[datetime]
    matched_cpe: str


# --------------------------------------------------------------------------- normalization
# Strip distro / patch suffixes so the version looks closer to the upstream.
# Examples:
#   "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"  -> ("OpenSSH", "openssh", "8.2p1")
#   "Apache httpd 2.4.41"             -> ("Apache", "apache", "2.4.41")
#   "MySQL 5.7.33-0ubuntu0.16.04.1"   -> ("Oracle", "mysql", "5.7.33")
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


def _split_product_string(raw: str) -> Tuple[str, str]:
    """Return (display_name, lowercase_key) from a raw product string.

    "Apache httpd"      -> ("Apache",    "apache httpd")
    "OpenSSH"           -> ("OpenSSH",   "openssh")
    "Microsoft HTTPAPI" -> ("Microsoft", "microsoft httpapi")
    The first token is treated as the vendor.
    """
    raw = raw.strip()
    if not raw:
        return "", ""
    # vendor is the first whitespace-delimited token; the rest is the product
    parts = raw.split(None, 1)
    if len(parts) == 1:
        return parts[0], parts[0].lower()
    vendor, product = parts[0], parts[1]
    return vendor, f"{vendor} {product}".lower()


def normalize_service_string(
    product: Optional[str],
    version: Optional[str],
    extra: Optional[str] = None,
) -> Optional[Tuple[str, str, str]]:
    """Return (vendor, product, version) suitable for CPE construction.

    Returns None when there is not enough information to attempt a lookup.
    """
    if not product or not version:
        return None

    vendor, prod_key = _split_product_string(product)

    # Combine version + extra and strip distro/patch noise.
    raw_version = " ".join(p for p in [version, extra or ""] if p)
    cleaned = _DISTRO_SUFFIX_RE.sub("", raw_version)
    cleaned = _PATCH_TAIL_RE.sub("", cleaned)
    cleaned = cleaned.strip(" .-_")
    # collapse whitespace
    cleaned = re.sub(r"\s+", " ", cleaned)

    if not cleaned:
        return None

    # If patch like "8.2p1" was stripped, prefer the upstream numeric core.
    m = re.match(r"^([0-9]+(?:\.[0-9]+){0,3})", cleaned)
    if m:
        cleaned = m.group(1)

    return vendor, prod_key, cleaned


# --------------------------------------------------------------------------- CPE
def build_cpe_uris(vendor: str, product: str, version: str) -> List[str]:
    """Construct CPE 2.3 URIs in `cpe:2.3:a:vendor:product:version:*:*:*:*:*:*`.

    We always escape spaces and colons per CPE 2.3 Appendix B.
    Multiple candidates are returned because the same software can have
    different CPE spellings (e.g. `apache:http_server` vs `apache:httpd`).
    """
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace(":", "\\:").replace(" ", "\\ ")

    v = esc(vendor.lower())
    p = esc(product.lower())
    ver = esc(version)

    # Also produce a stripped form (single token) for fuzzy matching.
    p_stripped = esc(product.split()[-1].lower() if product else product)

    candidates = [
        f"cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*",
    ]
    if p_stripped and p_stripped != p:
        candidates.append(f"cpe:2.3:a:{v}:{p_stripped}:{ver}:*:*:*:*:*:*:*")

    # Deduplicate while preserving order.
    seen = set()
    out = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


# --------------------------------------------------------------------------- NVD API
def _parse_cvss(metrics: dict) -> CVSSInfo:
    """Extract CVSS v3 score + severity from the NVD metrics block."""
    primary = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    if not primary:
        # fall back to v2
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


def _cve_from_nvd_item(item: dict, matched_cpe: str) -> Optional[CVEResult]:
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    descriptions = cve.get("descriptions") or []
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break
    if not desc and descriptions:
        desc = descriptions[0].get("value", "")

    metrics = cve.get("metrics") or {}
    cvss = _parse_cvss(metrics)

    published_str = cve.get("published")
    published: Optional[datetime] = None
    if published_str:
        try:
            published = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
        except ValueError:
            published = None

    return CVEResult(
        cve_id=cve_id,
        description=desc,
        cvss=cvss,
        published=published,
        matched_cpe=matched_cpe,
    )


def _nvd_request(
    cpe: str,
    *,
    session: requests.Session,
    api_key: Optional[str],
    base_url: str,
    timeout: float,
) -> Optional[dict]:
    """Issue a single NVD lookup. Returns the parsed JSON or None on failure.

    Network-level errors, unexpected exceptions raised by `session.get`
    (including test doubles that raise arbitrary exceptions), and bad JSON
    are all treated as "soft failures" — the caller falls back to the cache
    or returns no CVEs. A failure here must never crash a scan.
    """
    headers = {"User-Agent": get_settings().nvd_user_agent}
    if api_key:
        headers["apiKey"] = api_key
    params = {"cpeName": cpe, "resultsPerPage": 20}
    try:
        resp = session.get(base_url, headers=headers, params=params, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — intentional broad catch for resilience
        log.warning("NVD request failed for %s: %s", cpe, exc)
        return None
    if resp.status_code == 429:
        log.warning("NVD rate-limited (429); backing off 6s for %s", cpe)
        time.sleep(6)
        return None
    if resp.status_code != 200:
        log.warning("NVD returned %d for %s", resp.status_code, cpe)
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def _lookup_cached(cpe: str, db: Session, ttl_seconds: int = 7 * 24 * 3600) -> Optional[dict]:
    """Return a cached NVD JSON payload if fresh enough, else None."""
    row = db.query(CPECache).filter(CPECache.cpe_name == cpe).one_or_none()
    if row is None:
        return None
    age = (datetime.utcnow() - row.fetched_at).total_seconds()
    if age > ttl_seconds:
        return None
    try:
        return json.loads(row.payload)
    except ValueError:
        return None


def _store_cache(cpe: str, payload: dict, db: Session) -> None:
    """Persist NVD response. Upsert by cpe_name."""
    row = db.query(CPECache).filter(CPECache.cpe_name == cpe).one_or_none()
    text = json.dumps(payload)
    if row is None:
        db.add(CPECache(cpe_name=cpe, payload=text, fetched_at=datetime.utcnow()))
    else:
        row.payload = text
        row.fetched_at = datetime.utcnow()
    db.commit()


def query_nvd_for_cpe(
    cpe: str,
    db: Session,
    *,
    http_session: Optional[requests.Session] = None,
    force_refresh: bool = False,
) -> List[CVEResult]:
    """Query NVD for a single CPE URI. Always returns a list (possibly empty)."""
    settings = get_settings()
    http = http_session or requests.Session()

    if not force_refresh:
        cached = _lookup_cached(cpe, db)
        if cached is not None:
            items = cached.get("vulnerabilities") or []
            return [
                r for r in (_cve_from_nvd_item(it, cpe) for it in items) if r is not None
            ]

    payload = _nvd_request(
        cpe,
        session=http,
        api_key=settings.nvd_api_key,
        base_url=settings.nvd_base_url,
        timeout=settings.nvd_request_timeout,
    )
    if payload is None:
        # Failure path: return what we have in cache even if stale.
        row = db.query(CPECache).filter(CPECache.cpe_name == cpe).one_or_none()
        if row is not None:
            try:
                items = json.loads(row.payload).get("vulnerabilities") or []
                return [
                    r for r in (_cve_from_nvd_item(it, cpe) for it in items) if r is not None
                ]
            except ValueError:
                return []
        return []

    _store_cache(cpe, payload, db)
    items = payload.get("vulnerabilities") or []
    return [r for r in (_cve_from_nvd_item(it, cpe) for it in items) if r is not None]


# --------------------------------------------------------------------------- matching
def match_cves_for_port(
    port: PortResult,
    db: Session,
    *,
    http_session: Optional[requests.Session] = None,
) -> List[CVEResult]:
    """Find CVEs matching the service on a given port."""
    norm = normalize_service_string(
        port.service.product,
        port.service.version,
        port.service.extra,
    )
    if norm is None:
        return []
    vendor, product, version = norm
    cpe_candidates = build_cpe_uris(vendor, product, version)

    results: List[CVEResult] = []
    for cpe in cpe_candidates:
        results.extend(query_nvd_for_cpe(cpe, db, http_session=http_session))
    return results


def match_cves_for_scan(
    scan_result: ScanResult,
    db: Session,
    *,
    http_session: Optional[requests.Session] = None,
) -> dict[int, List[CVEResult]]:
    """Return a mapping: port_id (in DB) -> list of matched CVEs.

    The id is assigned when the Port is persisted. To keep this function
    DB-agnostic, it returns the *list index* per host.ports — callers
    persist in order so indices match the IDs.
    """
    by_index: dict[int, List[CVEResult]] = {}
    port_id = 0
    for host in scan_result.hosts:
        for port in host.ports:
            cves = match_cves_for_port(port, db, http_session=http_session)
            by_index[port_id] = cves
            port_id += 1
    return by_index


def vulnerability_rows_for(
    cves: Iterable[CVEResult],
) -> List[Vulnerability]:
    """Convert CVEResult objects into ORM Vulnerability rows (not yet persisted)."""
    rows: List[Vulnerability] = []
    for cve in cves:
        rows.append(
            Vulnerability(
                cve_id=cve.cve_id,
                description=cve.description,
                cvss_v3_score=cve.cvss.score,
                severity=(cve.cvss.severity or "").upper() or None,
                published=cve.published,
                matched_cpe=cve.matched_cpe,
            )
        )
    return rows


__all__ = [
    "CVSSInfo",
    "CVEResult",
    "normalize_service_string",
    "build_cpe_uris",
    "query_nvd_for_cpe",
    "match_cves_for_port",
    "match_cves_for_scan",
    "vulnerability_rows_for",
]
