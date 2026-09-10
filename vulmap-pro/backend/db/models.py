"""ORM models for Vulmap Pro.

Tables:
    Scan:           top-level scan job with explicit state (queued/running/completed/failed).
    Host:           one row per discovered host.
    Port:           one row per open port on a host, with detected service info.
    Vulnerability:  one row per CVE matched against a port (or host).
    CPECache:       on-disk cache for NVD API responses, keyed by CPE name.
"""
from __future__ import annotations

import enum
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.session import Base


class ScanState(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# Allowed forward transitions — defensive guard against background-task bugs
# (e.g. completing a scan that never started).
_ALLOWED_TRANSITIONS: dict[ScanState, set[ScanState]] = {
    ScanState.QUEUED: {ScanState.RUNNING, ScanState.FAILED},
    ScanState.RUNNING: {ScanState.COMPLETED, ScanState.FAILED},
    ScanState.COMPLETED: set(),
    ScanState.FAILED: set(),
}


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    state: Mapped[ScanState] = mapped_column(
        SAEnum(ScanState, native_enum=False, length=16),
        nullable=False,
        default=ScanState.QUEUED,
        index=True,
    )
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    hosts: Mapped[List["Host"]] = relationship(
        "Host",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __init__(self, *args, **kwargs) -> None:
        # SQLAlchemy column defaults only fire on flush; tests construct
        # Scan() in-memory and expect state to be visible immediately.
        kwargs.setdefault("state", ScanState.QUEUED)
        kwargs.setdefault("created_at", datetime.utcnow())
        super().__init__(*args, **kwargs)

    def can_transition_to(self, new_state: ScanState) -> bool:
        return new_state in _ALLOWED_TRANSITIONS.get(self.state or ScanState.QUEUED, set())

    def transition_to(self, new_state: ScanState) -> bool:
        """Transition state if allowed. Returns True on success."""
        if not self.can_transition_to(new_state):
            return False
        self.state = new_state
        if new_state is ScanState.RUNNING:
            self.started_at = datetime.utcnow()
        if new_state in (ScanState.COMPLETED, ScanState.FAILED):
            self.finished_at = datetime.utcnow()
        return True


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="up", nullable=False)

    scan: Mapped[Scan] = relationship("Scan", back_populates="hosts")
    ports: Mapped[List["Port"]] = relationship(
        "Port",
        back_populates="host",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp", nullable=False)
    state: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    service_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    service_product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    service_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    service_extra: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    host: Mapped[Host] = relationship("Host", back_populates="ports")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="port",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("host_id", "port_number", "protocol", name="uq_host_port_proto"),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    port_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("ports.id", ondelete="CASCADE"), nullable=True, index=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cvss_v3_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # LOW/MEDIUM/HIGH/CRITICAL
    published: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    matched_cpe: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    port: Mapped[Optional[Port]] = relationship("Port", back_populates="vulnerabilities")


class CPECache(Base):
    """Cached NVD lookup keyed by a CPE 2.3 URI string."""

    __tablename__ = "cpe_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cpe_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False)  # JSON-serialized NVD response
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


__all__ = ["Scan", "Host", "Port", "Vulnerability", "CPECache", "ScanState"]
