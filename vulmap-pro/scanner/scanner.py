"""Nmap wrapper: target validation + scan execution + result parsing.

The scanner uses `python-nmap` when available but degrades to invoking the
`nmap` binary directly with `-oX -` so tests can run without Nmap installed.

ALL target inputs pass through `is_target_allowed` (see backend.config) before
reaching the subprocess. This is the command-injection guardrail: targets
must be valid IP/CIDR strings, never free-form text.
"""
from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Iterable, List, Optional

from backend.config import is_target_allowed

from scanner.models import HostResult, PortResult, ScanResult, ServiceInfo

log = logging.getLogger(__name__)


# --------------------------------------------------------------------- public API
def run_scan(
    target: str,
    *,
    ports: str = "1-1024",
    arguments: str = "-sV --top-ports 100",
    nmap_binary: str = "nmap",
    timeout: int = 900,
) -> ScanResult:
    """Execute an Nmap scan and return a parsed ScanResult.

    Raises ValueError if `target` is not a valid IP/CIDR in the allowlist.
    """
    if not is_target_allowed(target):
        raise PermissionError(f"target {target!r} is outside the allowlist")

    if not shutil.which(nmap_binary):
        log.warning("nmap binary %r not found on PATH; returning empty result", nmap_binary)
        return ScanResult(target=target, error="nmap not installed")

    cmd: List[str] = [
        nmap_binary,
        *shlex.split(arguments),
        "-p", ports,
        "-oX", "-",  # XML to stdout for deterministic parsing
        target,
    ]
    log.info("executing nmap: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ScanResult(target=target, error=f"nmap timed out after {timeout}s")

    if proc.returncode != 0:
        return ScanResult(
            target=target,
            error=f"nmap exit {proc.returncode}: {proc.stderr.strip()[:500]}",
            raw_xml=proc.stdout,
        )

    try:
        return parse_nmap_xml(proc.stdout, target=target)
    except ET.ParseError as exc:
        return ScanResult(target=target, error=f"failed to parse nmap XML: {exc}", raw_xml=proc.stdout)


# --------------------------------------------------------------------- parsing
def parse_nmap_xml(xml_text: str, *, target: Optional[str] = None) -> ScanResult:
    """Parse Nmap XML output into a ScanResult.

    This function is the parsing boundary used by both the live scanner and
    the unit tests. Tests inject pre-canned XML strings to assert behavior
    without spawning Nmap.
    """
    if not xml_text or not xml_text.strip():
        return ScanResult(target=target or "", hosts=[])

    root = ET.fromstring(xml_text)
    scan_target = target or root.attrib.get("args", "").split()[-1] if root.attrib.get("args") else ""

    hosts: List[HostResult] = []
    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"

        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.attrib.get("addr", "")

        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.attrib.get("name") if hostname_el is not None else None

        host = HostResult(ip=ip, hostname=hostname, state=state)

        for port_el in host_el.findall("ports/port"):
            p_state_el = port_el.find("state")
            p_state = p_state_el.attrib.get("state", "unknown") if p_state_el is not None else "unknown"

            service_el = port_el.find("service")
            svc = ServiceInfo()
            if service_el is not None:
                svc.name = service_el.attrib.get("name")
                svc.product = service_el.attrib.get("product")
                svc.version = service_el.attrib.get("version")
                svc.extra = service_el.attrib.get("extrainfo")

            host.ports.append(
                PortResult(
                    number=int(port_el.attrib.get("portid", "0")),
                    protocol=port_el.attrib.get("protocol", "tcp"),
                    state=p_state,
                    service=svc,
                )
            )

        hosts.append(host)

    return ScanResult(target=scan_target, hosts=hosts, raw_xml=xml_text)


# Convenience for callers that want to use python-nmap if installed.
def try_python_nmap(target: str, arguments: str = "-sV") -> Optional[ScanResult]:
    """Best-effort fallback using python-nmap's wrapper. Returns None on failure."""
    try:
        import nmap  # type: ignore
    except Exception:
        return None

    if not is_target_allowed(target):
        raise PermissionError(f"target {target!r} is outside the allowlist")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments=arguments)
    except Exception as exc:  # nmap raises a generic Exception on failure
        return ScanResult(target=target, error=f"python-nmap error: {exc}")

    hosts: List[HostResult] = []
    for host in nm.all_hosts():
        h = HostResult(ip=host, hostname=None, state=nm[host].state())
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                info = nm[host][proto][port]
                svc = ServiceInfo(
                    name=info.get("name"),
                    product=info.get("product"),
                    version=info.get("version"),
                    extra=info.get("extrainfo"),
                )
                h.ports.append(
                    PortResult(
                        number=int(port),
                        protocol=proto,
                        state=info.get("state", "unknown"),
                        service=svc,
                    )
                )
        hosts.append(h)
    return ScanResult(target=target, hosts=hosts)


__all__ = ["run_scan", "parse_nmap_xml", "try_python_nmap"]
