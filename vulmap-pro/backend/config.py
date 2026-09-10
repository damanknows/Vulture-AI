"""Configuration loader for Vulmap Pro.

Loads secrets and operational knobs from a `.env` file via pydantic-settings.
The `.env` file must NOT be committed (see .gitignore).
"""
from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Resolve the project root and the .env file relative to this file.
# This file lives at <root>/backend/config.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Application settings loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    db_url: str = Field(
        default=f"sqlite:///{(PROJECT_ROOT / 'vulmap.db').as_posix()}",
        description="SQLAlchemy database URL.",
    )

    # NVD API
    nvd_api_key: Optional[str] = Field(
        default=None,
        description="NVD API key. Optional but strongly recommended (rate limit: 5/30s vs 50/30s).",
    )
    nvd_base_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_request_timeout: float = Field(default=15.0)
    nvd_user_agent: str = Field(default="vulmap-pro/0.1 (security-scanning)")

    # Scan target allowlist. Comma-separated CIDR/IP entries. Empty = default
    # allowlist (loopback + RFC1918) is used.
    allowed_targets: str = Field(
        default="",
        description="Comma-separated extra targets (CIDR/IP). Empty = loopback+RFC1918 default.",
    )

    # Nmap binary
    nmap_binary: str = Field(default="nmap")
    scan_timeout_seconds: int = Field(default=900)

    # Frontend CORS
    cors_origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"],
        description="Allowed CORS origins for the React frontend.",
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors(cls, v):  # noqa: D401
        """Accept JSON list or comma-separated string from env."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    # ------------------------------------------------------------------ allowlist
    def allowed_networks(self) -> List[ipaddress._BaseNetwork]:
        """Return the list of ipaddress networks the scanner is allowed to target.

        Always includes loopback + RFC1918. Additional ranges come from the
        ALLOWED_TARGETS env var (comma-separated CIDR or single IPs).
        """
        nets: List[ipaddress._BaseNetwork] = [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]

        extra = (self.allowed_targets or "").strip()
        if extra:
            for piece in extra.split(","):
                piece = piece.strip()
                if not piece:
                    continue
                # Accept either a CIDR or a single IP
                if "/" in piece:
                    nets.append(ipaddress.ip_network(piece, strict=False))
                else:
                    nets.append(ipaddress.ip_network(f"{piece}/32", strict=False))

        # De-duplicate
        return list({n.compressed: n for n in nets}.values())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor (avoid re-parsing .env on every call)."""
    return Settings()


def is_target_allowed(target: str, networks: Optional[List[ipaddress._BaseNetwork]] = None) -> bool:
    """Check whether a target IP/CIDR string falls inside an allowed network.

    Raises ValueError if `target` is not a valid IP/CIDR (caller should
    reject it before reaching the subprocess — this is the command-injection
    guardrail).
    """
    if not target or not isinstance(target, str):
        raise ValueError("target must be a non-empty string")

    candidate = target.strip()
    # Strict format check — reject anything that isn't an IP or CIDR.
    try:
        if "/" in candidate:
            ipaddress.ip_network(candidate, strict=False)
            probe_ip = ipaddress.ip_address(candidate.split("/")[0])
        else:
            probe_ip = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError(f"invalid IP/CIDR: {target!r}") from exc

    nets = networks if networks is not None else get_settings().allowed_networks()
    return any(probe_ip in n for n in nets)


__all__ = ["Settings", "get_settings", "is_target_allowed", "PROJECT_ROOT"]
