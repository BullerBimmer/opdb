"""Network-topology analyzers."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from . import BaseAnalyzer, Finding

if TYPE_CHECKING:
    from ..db import TargetDB


class DualHomedHostAnalyzer(BaseAnalyzer):
    name = "dual-homed"
    description = "Find hosts with interfaces on multiple subnets (pivot points)"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (h:Host)-[:HAS_INTERFACE]->(i:Interface)-[:HAS_IP]->(ip:IPAddress)
              -[:IN_NETWORK]->(n:Network)
        WITH h, collect(DISTINCT n.cidr) AS nets
        WHERE size(nets) > 1
        RETURN h.uid AS uid, h.hostname AS hostname, nets
        """
        findings: list[Finding] = []
        for row in db.query(q):
            findings.append(Finding(
                title=f"Dual-homed host: {row.get('hostname') or row['uid']}",
                severity="high",
                detail=f"Present on subnets: {', '.join(row['nets'])}",
                data=row,
            ))
        return findings


class SharedSubnetAnalyzer(BaseAnalyzer):
    name = "shared-subnet"
    description = "List all hosts per subnet for lateral-movement mapping"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (h:Host)-[:HAS_INTERFACE|HAS_IP*1..2]->(ip:IPAddress)
              -[:IN_NETWORK]->(n:Network)
        WITH n.cidr AS cidr, collect(DISTINCT {uid: h.uid, hostname: h.hostname,
             ip: ip.address}) AS hosts
        RETURN cidr, hosts, size(hosts) AS count
        ORDER BY count DESC
        """
        findings: list[Finding] = []
        for row in db.query(q):
            findings.append(Finding(
                title=f"Subnet {row['cidr']}: {row['count']} host(s)",
                severity="info",
                detail=", ".join(
                    h.get("hostname") or h.get("ip") or h["uid"]
                    for h in row["hosts"]
                ),
                data=row,
            ))
        return findings


class GatewayAnalyzer(BaseAnalyzer):
    name = "gateways"
    description = "Identify gateway/router IPs from routing tables"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (h:Host)-[:HAS_ROUTE]->(r:Route)
        WHERE r.gateway IS NOT NULL
        WITH r.gateway AS gw, collect(DISTINCT h.hostname) AS seen_by
        RETURN gw, seen_by, size(seen_by) AS ref_count
        ORDER BY ref_count DESC
        """
        findings: list[Finding] = []
        for row in db.query(q):
            findings.append(Finding(
                title=f"Gateway {row['gw']} referenced by {row['ref_count']} host(s)",
                severity="medium",
                detail=f"Seen by: {', '.join(str(h) for h in row['seen_by'])}",
                data=row,
            ))
        return findings


class StaleHostAnalyzer(BaseAnalyzer):
    name = "stale-hosts"
    description = "Find hosts not seen in recent scans (default: 7 days)"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        days = kw.get("days", 7)
        q = """
        MATCH (h:Host)
        WHERE h.last_seen < datetime() - duration({days: $days})
        RETURN h.uid AS uid, h.hostname AS hostname, h.last_seen AS last_seen
        ORDER BY h.last_seen
        """
        findings: list[Finding] = []
        for row in db.query(q, days=days):
            findings.append(Finding(
                title=f"Stale host: {row.get('hostname') or row['uid']}",
                severity="low",
                detail=f"Last seen: {row['last_seen']}",
                data=row,
            ))
        return findings
