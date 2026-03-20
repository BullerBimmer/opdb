"""
Nmap XML parser.

Handles standard nmap XML output (``nmap -oX``).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import (
    Host, IPAddress, Port, Network, ScanEvent,
    HostStatus, Protocol, PortState,
)
from . import BaseParser

if TYPE_CHECKING:
    from ..db import TargetDB


_STATE_MAP = {
    "open": PortState.OPEN,
    "closed": PortState.CLOSED,
    "filtered": PortState.FILTERED,
    "open|filtered": PortState.OPEN_FILTERED,
}

_PROTO_MAP = {
    "tcp": Protocol.TCP,
    "udp": Protocol.UDP,
    "sctp": Protocol.SCTP,
}


class NmapParser(BaseParser):
    name = "nmap"
    description = "Parse nmap XML output (-oX)"

    def parse(self, db: "TargetDB", source: str | Path, *,
              host_uid: str | None = None,
              scan_uid: str | None = None) -> dict:
        path = Path(source)
        if path.is_file():
            tree = ET.parse(path)
            root = tree.getroot()
        else:
            # Treat source as raw XML string
            root = ET.fromstring(str(source))

        # Create scan event
        if scan_uid is None:
            se = ScanEvent(scan_type="nmap", source_file=str(source),
                           summary=root.attrib.get("args", ""))
            scan_uid = db.create_scan_event(se)

        stats = {"hosts": 0, "ports": 0, "networks": set()}

        # Try to infer target network from scan args (e.g. "10.0.1.0/24")
        scan_args = root.attrib.get("args", "")
        target_cidrs = self._extract_cidrs(scan_args)
        for cidr in target_cidrs:
            net = Network(cidr=cidr)
            db.merge_network(net, scan_uid=scan_uid)

        for host_el in root.iter("host"):
            h = self._parse_host(host_el)
            huid = db.merge_host(h, scan_uid=scan_uid)
            stats["hosts"] += 1

            # IPs
            for addr_el in host_el.findall("address"):
                addr_type = addr_el.get("addrtype", "")
                if addr_type in ("ipv4", "ipv6"):
                    addr = addr_el.get("addr", "")
                    ip = IPAddress(
                        address=addr,
                        version=4 if addr_type == "ipv4" else 6,
                    )
                    db.merge_ip(ip, host_uid=huid, scan_uid=scan_uid)

                    # Link to any matching target network
                    for cidr in target_cidrs:
                        if self._ip_in_cidr(addr, cidr):
                            db.link_ip_to_network(addr, cidr)

            # Ports
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    p = self._parse_port(port_el)
                    db.merge_port(p, huid, scan_uid=scan_uid)
                    stats["ports"] += 1

            # OS detection
            os_el = host_el.find("os")
            if os_el is not None:
                for osmatch in os_el.findall("osmatch"):
                    h.os = osmatch.get("name")
                    db.merge_host(h, scan_uid=scan_uid)
                    break

        # Auto-link IPs to networks
        db.auto_link_networks()

        stats["networks"] = len(stats["networks"])
        stats["scan_uid"] = scan_uid
        return stats

    @staticmethod
    def _parse_host(el: ET.Element) -> Host:
        status_el = el.find("status")
        status = HostStatus.UNKNOWN
        if status_el is not None:
            raw = status_el.get("state", "unknown")
            if raw == "up":
                status = HostStatus.ALIVE
            elif raw == "down":
                status = HostStatus.DOWN

        hostnames_el = el.find("hostnames")
        hostname = None
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                hostname = hn.get("name")
                break

        return Host(hostname=hostname, status=status)

    @staticmethod
    def _parse_port(el: ET.Element) -> Port:
        state_el = el.find("state")
        state = PortState.OPEN
        if state_el is not None:
            state = _STATE_MAP.get(state_el.get("state", "open"), PortState.OPEN)

        service_el = el.find("service")
        service = product = version = banner = None
        if service_el is not None:
            service = service_el.get("name")
            product = service_el.get("product")
            version = service_el.get("version")
            banner = service_el.get("extrainfo")

        return Port(
            number=int(el.get("portid", 0)),
            protocol=_PROTO_MAP.get(el.get("protocol", "tcp"), Protocol.TCP),
            state=state,
            service=service,
            product=product,
            version=version,
            banner=banner,
        )

    @staticmethod
    def _extract_cidrs(args: str) -> list[str]:
        """Pull CIDR notations from nmap command args."""
        import re
        return re.findall(r"\d+\.\d+\.\d+\.\d+/\d+", args)

    @staticmethod
    def _ip_in_cidr(addr: str, cidr: str) -> bool:
        """Check if an IPv4 address falls within a CIDR."""
        try:
            net_addr, prefix_str = cidr.split("/")
            prefix = int(prefix_str)
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            def to_int(ip: str) -> int:
                p = ip.split(".")
                return (int(p[0]) << 24) + (int(p[1]) << 16) + (int(p[2]) << 8) + int(p[3])
            return (to_int(addr) & mask) == (to_int(net_addr) & mask)
        except Exception:
            return False
