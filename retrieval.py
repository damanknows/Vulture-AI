import logging

def _format_evidence(finding: dict, match: dict) -> dict:
    cve_id = match.get("cve_id", "")
    return {
        "source": "vulture_db",
        "source_id": f"{finding.get('finding', {}).get('target', 'unknown')}_{cve_id}",
        "retrieved_at": match.get("intel", {}).get("retrieved_at", ""),
        "cve_id": cve_id,
        "content": str(match.get("intel", {}).get("data", {}))
    }

def retrieve_by_cve(cve_id: str, dataset: list[dict]) -> list[dict]:
    """Exact lookup from the local enriched dataset."""
    results = []
    for finding in dataset:
        for match in finding.get("cve_matches", []):
            if match.get("cve_id") == cve_id:
                results.append(_format_evidence(finding, match))
    return results

def retrieve_by_query(query: str, dataset: list[dict], top_k: int = 5) -> list[dict]:
    """Hybrid: keyword match on CVE ID and product name first, fallback to vector (not implemented)."""
    q = query.lower()
    results = []
    
    for finding in dataset:
        f_data = finding.get("finding", {})
        product = (f_data.get("product") or "").lower()
        
        for match in finding.get("cve_matches", []):
            cve_id = match.get("cve_id", "").lower()
            
            # Simple keyword match
            if q in cve_id or q in product or cve_id in q or product in q:
                results.append(_format_evidence(finding, match))
                if len(results) >= top_k:
                    return results

    # Fallback simulation if vector store was asked for
    logging.warning("Vector store is not available, falling back to keyword-only search.")
    
    return results[:top_k]
