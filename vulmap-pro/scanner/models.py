"""Structured dataclasses representing Nmap scan results.

Kept separate from the SQLAlchemy ORM models so the scanner engine is
unit-testable without a database.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ServiceInfo:
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra: Optional[str] = None  # e.g. "httpd", "p1", "Ubuntu-4ubuntu0.5"

    @property
    def raw_version_string(self) -> str:
        """Nmap-style combined version string used for CPE matching."""
        parts = [self.product or "", self.version or "", self.extra or ""]
        return " ".join(p for p in parts if p).strip()

    @property
    def banner_like(self) -> str:
        """Best-effort short description (product + version)."""
        return self.raw_version_string


@dataclass
class PortResult:
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: ServiceInfo = field(default_factory=ServiceInfo)


@dataclass
class HostResult:
    ip: str
    hostname: Optional[str] = None
    state: str = "up"
    ports: List[PortResult] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    hosts: List[HostResult] = field(default_factory=list)
    error: Optional[str] = None
    raw_xml: Optional[str] = None


__all__ = ["ServiceInfo", "PortResult", "HostResult", "ScanResult"]
