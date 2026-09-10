"""Host/port read-only views."""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from backend.db.models import Host, Port, Scan, Vulnerability
from backend.db.session import get_session
from backend.routes.scans import HostOut, PortOut, VulnerabilityOut

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=List[HostOut])
def list_hosts(scan_id: int | None = None, db: Session = Depends(get_session)) -> List[HostOut]:
    q = db.query(Host).options(selectinload(Host.ports))
    if scan_id is not None:
        q = q.filter(Host.scan_id == scan_id)
    rows = q.order_by(Host.id.desc()).limit(200).all()
    return [
        HostOut(
            id=h.id,
            ip=h.ip,
            hostname=h.hostname,
            state=h.state,
            ports=[
                PortOut(
                    id=p.id,
                    number=p.port_number,
                    protocol=p.protocol,
                    state=p.state,
                    service_name=p.service_name,
                    service_product=p.service_product,
                    service_version=p.service_version,
                    service_extra=p.service_extra,
                )
                for p in h.ports
            ],
        )
        for h in rows
    ]


@router.get("/{host_id}/vulnerabilities", response_model=List[VulnerabilityOut])
def host_vulnerabilities(host_id: int, db: Session = Depends(get_session)) -> List[VulnerabilityOut]:
    host = (
        db.query(Host)
        .options(selectinload(Host.ports).selectinload(Port.vulnerabilities))
        .filter(Host.id == host_id)
        .one_or_none()
    )
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    out: List[VulnerabilityOut] = []
    for p in host.ports:
        for v in p.vulnerabilities:
            out.append(
                VulnerabilityOut(
                    id=v.id,
                    cve_id=v.cve_id,
                    description=v.description,
                    cvss_v3_score=v.cvss_v3_score,
                    severity=v.severity,
                    published=v.published,
                    matched_cpe=v.matched_cpe,
                )
            )
    return out


@router.get("/vulnerabilities", response_model=List[VulnerabilityOut])
def list_all_vulnerabilities(
    scan_id: int | None = None,
    db: Session = Depends(get_session),
) -> List[VulnerabilityOut]:
    """Flat view across all vulnerabilities (optionally filtered by scan)."""
    q = db.query(Vulnerability).join(Port, Vulnerability.port_id == Port.id).join(Host, Port.host_id == Host.id)
    if scan_id is not None:
        q = q.filter(Host.scan_id == scan_id)
    rows = q.order_by(Vulnerability.cvss_v3_score.desc().nullslast()).limit(500).all()
    return [
        VulnerabilityOut(
            id=v.id,
            cve_id=v.cve_id,
            description=v.description,
            cvss_v3_score=v.cvss_v3_score,
            severity=v.severity,
            published=v.published,
            matched_cpe=v.matched_cpe,
        )
        for v in rows
    ]


__all__ = ["router"]
