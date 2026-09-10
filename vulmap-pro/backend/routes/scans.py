"""Scan management API.

POST /scans       — create a scan against a target (queued, then runs in background).
GET  /scans       — list recent scans.
GET  /scans/{id}  — scan detail with explicit state for reliable polling.

The background task is what triggers the scanner engine and CVE matcher,
then transitions the scan state (queued -> running -> completed/failed).
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, selectinload

from backend.config import get_settings, is_target_allowed
from backend.db.models import Host, Port, Scan, ScanState, Vulnerability
from backend.db.session import get_session, session_scope
from scanner import cve_matcher
from scanner.scanner import run_scan

log = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


# ------------------------------------------------------------------ schemas
class ScanCreate(BaseModel):
    target: str = Field(..., description="IPv4/CIDR target to scan. Must be allowlisted.")


class PortOut(BaseModel):
    id: int
    number: int
    protocol: str
    state: str
    service_name: str | None = None
    service_product: str | None = None
    service_version: str | None = None
    service_extra: str | None = None

    class Config:
        from_attributes = True


class VulnerabilityOut(BaseModel):
    id: int
    cve_id: str
    description: str | None = None
    cvss_v3_score: float | None = None
    severity: str | None = None
    published: datetime | None = None
    matched_cpe: str | None = None

    class Config:
        from_attributes = True


class HostOut(BaseModel):
    id: int
    ip: str
    hostname: str | None = None
    state: str
    ports: List[PortOut] = []

    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    id: int
    target: str
    state: ScanState
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    host_count: int = 0
    vulnerability_count: int = 0

    class Config:
        from_attributes = True


class ScanDetail(ScanSummary):
    error: str | None = None
    hosts: List[HostOut] = []


# ------------------------------------------------------------------ routes
@router.post("", response_model=ScanSummary, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    background: BackgroundTasks,
    db: Session = Depends(get_session),
) -> ScanSummary:
    # Strict validation — also the command-injection guardrail.
    try:
        allowed = is_target_allowed(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"target {payload.target!r} is outside the allowlist",
        )

    scan = Scan(target=payload.target, state=ScanState.QUEUED)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background.add_task(_execute_scan_task, scan.id)
    log.info("queued scan id=%s target=%s", scan.id, scan.target)

    return ScanSummary(
        id=scan.id,
        target=scan.target,
        state=scan.state,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        host_count=0,
        vulnerability_count=0,
    )


@router.get("", response_model=List[ScanSummary])
def list_scans(db: Session = Depends(get_session)) -> List[ScanSummary]:
    rows = (
        db.query(Scan)
        .options(selectinload(Scan.hosts).selectinload(Host.ports).selectinload(Port.vulnerabilities))
        .order_by(Scan.created_at.desc())
        .limit(100)
        .all()
    )
    out: List[ScanSummary] = []
    for r in rows:
        vuln_count = sum(len(p.vulnerabilities) for h in r.hosts for p in h.ports)
        out.append(
            ScanSummary(
                id=r.id,
                target=r.target,
                state=r.state,
                created_at=r.created_at,
                started_at=r.started_at,
                finished_at=r.finished_at,
                host_count=len(r.hosts),
                vulnerability_count=vuln_count,
            )
        )
    return out


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_session)) -> ScanDetail:
    scan = (
        db.query(Scan)
        .options(selectinload(Scan.hosts).selectinload(Host.ports).selectinload(Port.vulnerabilities))
        .filter(Scan.id == scan_id)
        .one_or_none()
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")

    vuln_count = sum(len(p.vulnerabilities) for h in scan.hosts for p in h.ports)

    return ScanDetail(
        id=scan.id,
        target=scan.target,
        state=scan.state,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        host_count=len(scan.hosts),
        vulnerability_count=vuln_count,
        error=scan.error,
        hosts=[
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
            for h in scan.hosts
        ],
    )


# ------------------------------------------------------------------ background
def _execute_scan_task(scan_id: int) -> None:
    """Background worker: Nmap scan -> persist results -> CVE match."""
    settings = get_settings()

    # Move QUEUED -> RUNNING in its own session.
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            log.error("scan id=%s disappeared before start", scan_id)
            return
        if not scan.transition_to(ScanState.RUNNING):
            log.warning("scan id=%s could not transition to running (state=%s)", scan_id, scan.state)
            return

    # Run nmap (no DB lock held).
    try:
        result = run_scan(
            scan.target,
            nmap_binary=settings.nmap_binary,
            timeout=settings.scan_timeout_seconds,
        )
    except PermissionError as exc:
        log.error("scan %d denied: %s", scan_id, exc)
        _mark_failed(scan_id, str(exc))
        return
    except Exception as exc:  # last-resort guard
        log.exception("scan %d crashed", scan_id)
        _mark_failed(scan_id, f"unexpected error: {exc}")
        return

    if result.error and not result.hosts:
        # Unreachable / down host — mark completed with 0 hosts but record the
        # message in `error`. The frontend renders this gracefully.
        _mark_failed(scan_id, result.error)
        return

    # Persist hosts/ports and run CVE matching.
    try:
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:
                return

            # Persist hosts/ports.
            for host_result in result.hosts:
                host = Host(
                    ip=host_result.ip,
                    hostname=host_result.hostname,
                    state=host_result.state,
                )
                scan.hosts.append(host)
                for pr in host_result.ports:
                    host.ports.append(
                        Port(
                            port_number=pr.number,
                            protocol=pr.protocol,
                            state=pr.state,
                            service_name=pr.service.name,
                            service_product=pr.service.product,
                            service_version=pr.service.version,
                            service_extra=pr.service.extra,
                        )
                    )
            db.flush()

            # CVE matching. collect port IDs in order they were persisted.
            port_ids_in_order = [
                p.id
                for h in scan.hosts
                for p in h.ports
            ]
            port_by_index = {idx: pid for idx, pid in enumerate(port_ids_in_order)}

            port_results_in_order = [
                pr
                for h in result.hosts
                for pr in h.ports
            ]
            for idx, port in enumerate(port_results_in_order):
                cves = cve_matcher.match_cves_for_port(port, db)
                pid = port_by_index[idx]
                port_orm = db.get(Port, pid)
                if port_orm is None:
                    continue
                for cve in cves:
                    port_orm.vulnerabilities.extend(
                        cve_matcher.vulnerability_rows_for([cve])
                    )

            scan.transition_to(ScanState.COMPLETED)
    except Exception as exc:
        log.exception("scan %d failed during persistence", scan_id)
        _mark_failed(scan_id, f"persistence error: {exc}")


def _mark_failed(scan_id: int, message: str) -> None:
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.error = message
        scan.transition_to(ScanState.FAILED)


__all__ = ["router"]
