import logging
import json

def _format_evidence(finding: dict, match: dict) -> dict:
    cve_id = match.get("cve_id", "")
    target = finding.get("finding", {}).get("target", "unknown")
    port = finding.get("finding", {}).get("port", "unknown")
    service = finding.get("finding", {}).get("service", "unknown")
    
    return {
        "source": "vulture_db",
        "source_id": f"{target}:{port}_{cve_id}",
        "retrieved_at": match.get("retrieved_at", ""),
        "cve_id": cve_id,
        "applicability": f"Target {target} on port {port} runs {service}",
        "content": json.dumps(match)
    }

def retrieve_by_cve(cve_id: str, dataset: list[dict]) -> list[dict]:
    """Exact lookup from the local enriched dataset."""
    results = []
    for finding in dataset:
        for match in finding.get("cve_matches", []):
            if match.get("cve_id", "").upper() == cve_id.upper():
                results.append(_format_evidence(finding, match))
    return results

def retrieve_by_query(query: str, dataset: list[dict], top_k: int = 5) -> list[dict]:
    """Hybrid: keyword match on CVE ID and product name first."""
    q = query.lower()
    results = []
    
    for finding in dataset:
        f_data = finding.get("finding", {})
        product = (f_data.get("product") or "").lower()
        service = (f_data.get("service") or "").lower()
        
        for match in finding.get("cve_matches", []):
            cve_id = match.get("cve_id", "").lower()
            
            if q in cve_id or q in product or q in service or cve_id in q or product in q:
                results.append(_format_evidence(finding, match))
                if len(results) >= top_k:
                    return results

    logging.warning("Vector store is not available, falling back to keyword-only search.")
    return results[:top_k]
