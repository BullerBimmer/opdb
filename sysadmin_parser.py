"""
Sysadmin log parser.

Parses output collected from inside a host:
  - ``ip a`` / ``ip addr``
  - ``ip route`` / ``ip r``
  - ``ifconfig``
  - ``hostname``
  - ``uname -a``

The parser auto-detects which sections are present in the input.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import (
    Host, Interface, IPAddress, Network, Route, ScanEvent,
)
from . import BaseParser

if TYPE_CHECKING:
    from ..db import TargetDB


class SysadminParser(BaseParser):
    name = "sysadmin"
    description = "Parse sysadmin command output (ip a, ip route, ifconfig, uname, hostname)"

    def parse(self, db: "TargetDB", source: str | Path, *,
              host_uid: str | None = None,
              scan_uid: str | None = None) -> dict:
        path = Path(source)
        if path.is_file():
            text = path.read_text()
        else:
            text = str(source)

        if scan_uid is None:
            se = ScanEvent(scan_type="sysadmin",
                           source_file=str(source) if path.is_file() else None,
                           summary="sysadmin log import")
            scan_uid = db.create_scan_event(se)

        stats = {"interfaces": 0, "ips": 0, "routes": 0}

        # Resolve or create the host
        hostname = self._extract_hostname(text)
        os_info = self._extract_uname(text)

        if host_uid is None:
            h = Host(hostname=hostname, os=os_info)
            host_uid = db.merge_host(h, scan_uid=scan_uid)
        elif hostname or os_info:
            h = Host(uid=host_uid, hostname=hostname, os=os_info)
            db.merge_host(h, scan_uid=scan_uid)

        # Parse ip a / ip addr
        for iface_name, mac, addrs in self._parse_ip_addr(text):
            iface = Interface(name=iface_name, mac=mac)
            iface_uid = db.merge_interface(iface, host_uid, scan_uid=scan_uid)
            stats["interfaces"] += 1

            for addr, prefix, ver in addrs:
                cidr = f"{addr}/{prefix}" if prefix else None
                ip = IPAddress(address=addr, version=ver, cidr=cidr)
                db.merge_ip(ip, interface_uid=iface_uid, host_uid=host_uid,
                            scan_uid=scan_uid)
                stats["ips"] += 1

                # Auto-create network for the subnet
                if prefix:
                    net_cidr = self._to_network_cidr(addr, int(prefix), ver)
                    if net_cidr:
                        net = Network(cidr=net_cidr)
                        db.merge_network(net, scan_uid=scan_uid)
                        db.link_ip_to_network(addr, net_cidr)

        # Parse ifconfig (fallback if ip a not present)
        if stats["interfaces"] == 0:
            for iface_name, mac, addrs in self._parse_ifconfig(text):
                iface = Interface(name=iface_name, mac=mac)
                iface_uid = db.merge_interface(iface, host_uid,
                                               scan_uid=scan_uid)
                stats["interfaces"] += 1
                for addr, prefix, ver in addrs:
                    cidr = f"{addr}/{prefix}" if prefix else None
                    ip = IPAddress(address=addr, version=ver, cidr=cidr)
                    db.merge_ip(ip, interface_uid=iface_uid,
                                host_uid=host_uid, scan_uid=scan_uid)
                    stats["ips"] += 1

        # Parse ip route
        for route in self._parse_ip_route(text):
            db.merge_route(route, host_uid, scan_uid=scan_uid)
            stats["routes"] += 1

        stats["scan_uid"] = scan_uid
        return stats

    # -- extraction helpers --------------------------------------------------

    @staticmethod
    def _extract_hostname(text: str) -> str | None:
        # Look for explicit "hostname" line or "hostname: xxx"
        m = re.search(r"^(?:hostname[:\s]+)(\S+)", text, re.MULTILINE | re.IGNORECASE)
        return m.group(1) if m else None

    @staticmethod
    def _extract_uname(text: str) -> str | None:
        m = re.search(r"^(Linux \S+ \S+.*?)$", text, re.MULTILINE)
        return m.group(1) if m else None

    @staticmethod
    def _parse_ip_addr(text: str) -> list[tuple[str, str | None, list[tuple[str, str | None, int]]]]:
        """Parse ``ip a`` output.

        Returns list of (iface_name, mac, [(addr, prefix_len, version), ...])
        """
        results: list[tuple[str, str | None, list[tuple[str, str | None, int]]]] = []

        # Split into interface blocks — each starts with a line like:
        # 2: eth0: <BROADCAST,...> ...
        blocks = re.split(r"(?m)^\d+:\s+", text)

        for block in blocks:
            if not block.strip():
                continue

            # Interface name
            m = re.match(r"(\S+?)[@:]", block)
            if not m:
                continue
            iface_name = m.group(1)

            # MAC
            mac = None
            mac_m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", block)
            if mac_m:
                mac = mac_m.group(1)

            # Addresses
            addrs: list[tuple[str, str | None, int]] = []
            for inet_m in re.finditer(
                r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", block
            ):
                addrs.append((inet_m.group(1), inet_m.group(2), 4))

            for inet6_m in re.finditer(
                r"inet6\s+([0-9a-fA-F:]+)/(\d+)", block
            ):
                addrs.append((inet6_m.group(1), inet6_m.group(2), 6))

            results.append((iface_name, mac, addrs))

        return results

    @staticmethod
    def _parse_ifconfig(text: str) -> list[tuple[str, str | None, list[tuple[str, str | None, int]]]]:
        """Parse legacy ``ifconfig`` output."""
        results: list[tuple[str, str | None, list[tuple[str, str | None, int]]]] = []

        blocks = re.split(r"(?m)^(\S+)", text)
        i = 1
        while i < len(blocks) - 1:
            iface_name = blocks[i].strip()
            body = blocks[i + 1]
            i += 2

            mac = None
            mac_m = re.search(r"(?:HWaddr|ether)\s+([0-9a-fA-F:]{17})", body)
            if mac_m:
                mac = mac_m.group(1)

            addrs: list[tuple[str, str | None, int]] = []
            inet_m = re.search(r"inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", body)
            if inet_m:
                mask_m = re.search(r"(?:Mask:|netmask\s+)(\d+\.\d+\.\d+\.\d+)", body)
                prefix = None
                if mask_m:
                    prefix = str(_mask_to_prefix(mask_m.group(1)))
                addrs.append((inet_m.group(1), prefix, 4))

            if addrs or mac:
                results.append((iface_name, mac, addrs))

        return results

    @staticmethod
    def _parse_ip_route(text: str) -> list[Route]:
        """Parse ``ip route`` / ``ip r`` output."""
        routes: list[Route] = []

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            # Match lines like:
            # default via 10.0.0.1 dev eth0 proto dhcp metric 100
            # 10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5
            m = re.match(
                r"(default|\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+(.*)", line
            )
            if not m:
                continue

            dest = m.group(1)
            rest = m.group(2)

            if dest == "default":
                dest = "0.0.0.0/0"

            gw = None
            gw_m = re.search(r"via\s+(\S+)", rest)
            if gw_m:
                gw = gw_m.group(1)

            dev = None
            dev_m = re.search(r"dev\s+(\S+)", rest)
            if dev_m:
                dev = dev_m.group(1)

            metric = None
            met_m = re.search(r"metric\s+(\d+)", rest)
            if met_m:
                metric = int(met_m.group(1))

            routes.append(Route(
                destination=dest,
                gateway=gw,
                interface_name=dev,
                metric=metric,
            ))

        return routes

    @staticmethod
    def _to_network_cidr(addr: str, prefix: int, version: int) -> str | None:
        """Compute the network CIDR from an address and prefix length."""
        if version != 4:
            return None
        parts = addr.split(".")
        if len(parts) != 4:
            return None
        ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
                 (int(parts[2]) << 8) + int(parts[3])
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        net_int = ip_int & mask
        net_addr = f"{(net_int >> 24) & 0xFF}.{(net_int >> 16) & 0xFF}.{(net_int >> 8) & 0xFF}.{net_int & 0xFF}"
        return f"{net_addr}/{prefix}"


def _mask_to_prefix(mask: str) -> int:
    """Convert dotted netmask to prefix length.  e.g. 255.255.255.0 -> 24"""
    parts = mask.split(".")
    bits = 0
    for p in parts:
        n = int(p)
        while n:
            bits += n & 1
            n >>= 1
    return bits
