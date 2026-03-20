"""
Core data models for the targeting database.

All entities are plain dataclasses — the DB layer handles persistence.
Timestamps use ISO-8601 strings so they survive serialisation round-trips.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class HostStatus(str, Enum):
    ALIVE = "alive"
    DOWN = "down"
    UNKNOWN = "unknown"


class CredentialType(str, Enum):
    PASSWORD = "password"
    HASH = "hash"
    KEY = "key"
    TOKEN = "token"
    CERTIFICATE = "certificate"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


# ---------------------------------------------------------------------------
# Node models
# ---------------------------------------------------------------------------

@dataclass
class Host:
    """A single host / endpoint on a network."""
    uid: str = field(default_factory=_uuid)
    hostname: str | None = None
    os: str | None = None
    os_version: str | None = None
    arch: str | None = None
    status: HostStatus = HostStatus.UNKNOWN
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    tags: list[str] = field(default_factory=list)
    notes: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Interface:
    """A network interface on a host (eth0, wlan0, …)."""
    uid: str = field(default_factory=_uuid)
    name: str | None = None          # e.g. "eth0"
    mac: str | None = None
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class IPAddress:
    """An IP address (v4 or v6) bound to an interface at a point in time."""
    uid: str = field(default_factory=_uuid)
    address: str = ""
    version: int = 4                  # 4 or 6
    cidr: str | None = None           # e.g. "10.0.0.5/24"
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Network:
    """A logical or physical network / subnet."""
    uid: str = field(default_factory=_uuid)
    cidr: str = ""                    # e.g. "10.0.0.0/24"
    name: str | None = None
    vlan: int | None = None
    description: str | None = None
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Port:
    """A port/service on a host."""
    uid: str = field(default_factory=_uuid)
    number: int = 0
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.OPEN
    service: str | None = None        # e.g. "ssh", "http"
    product: str | None = None        # e.g. "OpenSSH"
    version: str | None = None        # e.g. "8.9p1"
    banner: str | None = None
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Credential:
    """A credential associated with a host or service."""
    uid: str = field(default_factory=_uuid)
    cred_type: CredentialType = CredentialType.PASSWORD
    username: str | None = None
    secret: str | None = None         # password / hash / key material
    domain: str | None = None
    realm: str | None = None
    source: str | None = None         # how it was obtained
    valid: bool | None = None
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Route:
    """A routing table entry observed on a host."""
    uid: str = field(default_factory=_uuid)
    destination: str = ""             # e.g. "0.0.0.0/0"
    gateway: str | None = None
    interface_name: str | None = None
    metric: int | None = None
    flags: str | None = None
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanEvent:
    """Records that a scan / data-ingestion event occurred."""
    uid: str = field(default_factory=_uuid)
    scan_type: str = ""               # "nmap", "sysadmin_log", …
    source_file: str | None = None
    timestamp: str = field(default_factory=_now)
    summary: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
