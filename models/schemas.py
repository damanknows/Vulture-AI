from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

@dataclass
class ThreatIntelRecord:
    source: str
    retrieved_at: str
    source_record_id: str
    data: dict = field(default_factory=dict)
    error: Optional[str] = None

@dataclass
class ScanFinding:
    target: str
    port: str
    protocol: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    evidence_source: str
    scan_timestamp: str

@dataclass
class CVEMatch:
    cve_id: str
    match_rationale: str
    match_confidence: str
    intel: ThreatIntelRecord

@dataclass
class EnrichedFinding:
    finding: ScanFinding
    cve_matches: List[CVEMatch] = field(default_factory=list)
    epss_scores: dict = field(default_factory=dict)
    kev_matches: List[str] = field(default_factory=list)
