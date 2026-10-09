from dataclasses import dataclass
from typing import Optional, List, Dict

@dataclass
class VulnerabilityRecord:
    cve_id: str
    cvss_score: Optional[float]
    cvss_version: Optional[str]
    cvss_severity: Optional[str]
    epss_probability: Optional[float]
    epss_date: Optional[str]
    kev_listed: Optional[bool]
    affected_product: Optional[str]
    affected_version_range: Optional[str]
    match_confidence: Optional[str] # confirmed, candidate, unverified
    match_status: Optional[str]
    evidence_sources: List[Dict[str, str]]
    retrieved_at: str

    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "cvss_severity": self.cvss_severity,
            "epss_probability": self.epss_probability,
            "epss_date": self.epss_date,
            "kev_listed": self.kev_listed,
            "affected_product": self.affected_product,
            "affected_version_range": self.affected_version_range,
            "match_confidence": self.match_confidence,
            "match_status": self.match_status,
            "evidence_sources": self.evidence_sources,
            "retrieved_at": self.retrieved_at
        }
