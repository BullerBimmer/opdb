"""
Attack path analysis — weighted graph traversal for lateral movement.

Scores hosts by "attackability" considering:
  - Open high-value services (SSH, RDP, SMB, databases)
  - Known credentials
  - Dual-homed position (pivot potential)
  - Reachability from a given starting host

Each host gets a composite score; paths between hosts are ranked by
cumulative difficulty.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from . import BaseAnalyzer, Finding

if TYPE_CHECKING:
    from ..db import TargetDB


# Points added per factor (higher = more interesting target)
_SCORE_WEIGHTS = {
    "has_cred":        50,   # we already have a credential
    "ssh_open":        20,
    "rdp_open":        25,
    "smb_open":        20,
    "database_open":   15,
    "telnet_open":     30,   # telnet = easy win
    "web_open":        10,
    "dual_homed":      40,   # pivot value
    "is_gateway":      35,
    "many_ports":      10,   # >5 open ports — large attack surface
}

_DB_SERVICES = {"mysql", "mssql", "postgresql", "oracle", "redis", "mongodb"}


class AttackScoreAnalyzer(BaseAnalyzer):
    name = "attack-score"
    description = "Score each host by attack surface and pivot value"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        # Gather per-host data in one query
        q = """
        MATCH (h:Host)
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
          WHERE p.state = 'open'
        OPTIONAL MATCH (c:Credential)-[:FOR_HOST]->(h)
        OPTIONAL MATCH (h)-[:HAS_INTERFACE]->(i)-[:HAS_IP]->(ip)-[:IN_NETWORK]->(n:Network)
        OPTIONAL MATCH (h)-[:HAS_ROUTE]->(r:Route)
          WHERE r.destination = '0.0.0.0/0' AND r.gateway IS NOT NULL
        WITH h,
             collect(DISTINCT p.service) AS services,
             collect(DISTINCT p.number) AS ports,
             count(DISTINCT c) AS cred_count,
             collect(DISTINCT n.cidr) AS networks,
             count(DISTINCT r) AS has_default_route
        RETURN h.uid AS uid, h.hostname AS hostname,
               services, ports, cred_count,
               networks, size(networks) AS net_count,
               has_default_route
        """
        findings: list[Finding] = []

        for row in db.query(q):
            score = 0
            reasons: list[str] = []
            services = set(s for s in (row.get("services") or []) if s)
            ports = set(row.get("ports") or [])

            if row.get("cred_count", 0) > 0:
                score += _SCORE_WEIGHTS["has_cred"]
                reasons.append(f"credentials: {row['cred_count']}")

            if "ssh" in services or 22 in ports:
                score += _SCORE_WEIGHTS["ssh_open"]
                reasons.append("SSH open")
            if "ms-wbt-server" in services or 3389 in ports:
                score += _SCORE_WEIGHTS["rdp_open"]
                reasons.append("RDP open")
            if "microsoft-ds" in services or 445 in ports:
                score += _SCORE_WEIGHTS["smb_open"]
                reasons.append("SMB open")
            if "telnet" in services or 23 in ports:
                score += _SCORE_WEIGHTS["telnet_open"]
                reasons.append("Telnet open")
            if services & _DB_SERVICES or ports & {3306, 1433, 5432, 1521, 6379, 27017}:
                score += _SCORE_WEIGHTS["database_open"]
                reasons.append(f"Database: {services & _DB_SERVICES or 'by port'}")
            if "http" in services or "https" in services or ports & {80, 443, 8080, 8443}:
                score += _SCORE_WEIGHTS["web_open"]
                reasons.append("Web service")

            net_count = row.get("net_count", 0)
            if net_count > 1:
                score += _SCORE_WEIGHTS["dual_homed"]
                reasons.append(f"Dual-homed ({net_count} networks)")
            if row.get("has_default_route", 0) > 0:
                score += _SCORE_WEIGHTS["is_gateway"]
                reasons.append("Has default route (possible gateway)")
            if len(ports) > 5:
                score += _SCORE_WEIGHTS["many_ports"]
                reasons.append(f"Large attack surface ({len(ports)} ports)")

            severity = "info"
            if score >= 80:
                severity = "critical"
            elif score >= 50:
                severity = "high"
            elif score >= 30:
                severity = "medium"
            elif score >= 15:
                severity = "low"

            findings.append(Finding(
                title=f"[{score:3d}] {row.get('hostname') or row['uid']}",
                severity=severity,
                detail="; ".join(reasons) if reasons else "Minimal attack surface",
                data={**row, "score": score, "reasons": reasons},
            ))

        findings.sort(key=lambda f: f.data.get("score", 0), reverse=True)
        return findings


class AttackPathAnalyzer(BaseAnalyzer):
    name = "attack-paths"
    description = "Find multi-hop lateral movement paths between hosts"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        from_uid = kw.get("from_uid")
        findings: list[Finding] = []

        if from_uid:
            return self._paths_from(db, from_uid)

        # Without a start host, find all interesting lateral movement
        # opportunities: host A has creds that work on host B
        q_cred_paths = """
        MATCH (c:Credential)-[:FOR_HOST]->(target:Host)
        MATCH (c)<-[:PRODUCED]-(s:ScanEvent)-[:PRODUCED]->(source:Host)
        WHERE source.uid <> target.uid
        RETURN source.hostname AS from_host, source.uid AS from_uid,
               target.hostname AS to_host, target.uid AS to_uid,
               c.username AS username, c.cred_type AS cred_type
        """
        for row in db.query(q_cred_paths):
            findings.append(Finding(
                title=f"Credential path: {row.get('from_host')} -> {row.get('to_host')}",
                severity="high",
                detail=f"Via credential: {row.get('username')} ({row.get('cred_type')})",
                data=row,
            ))

        # Pivot paths: dual-homed hosts bridging subnets
        q_pivots = """
        MATCH (h1:Host)-[:HAS_INTERFACE|HAS_IP*1..2]->(ip1:IPAddress)
              -[:IN_NETWORK]->(n1:Network)
        MATCH (pivot:Host)-[:HAS_INTERFACE|HAS_IP*1..2]->(ipA:IPAddress)
              -[:IN_NETWORK]->(n1)
        MATCH (pivot)-[:HAS_INTERFACE|HAS_IP*1..2]->(ipB:IPAddress)
              -[:IN_NETWORK]->(n2:Network)
        MATCH (h2:Host)-[:HAS_INTERFACE|HAS_IP*1..2]->(ip2:IPAddress)
              -[:IN_NETWORK]->(n2)
        WHERE h1.uid <> pivot.uid AND pivot.uid <> h2.uid AND h1.uid <> h2.uid
              AND n1.cidr <> n2.cidr
        RETURN DISTINCT
               h1.hostname AS source, pivot.hostname AS pivot_host,
               h2.hostname AS target,
               n1.cidr AS net1, n2.cidr AS net2,
               ipA.address AS pivot_ip1, ipB.address AS pivot_ip2
        """
        for row in db.query(q_pivots):
            findings.append(Finding(
                title=f"Pivot path: {row['source']} -> [{row['pivot_host']}] -> {row['target']}",
                severity="high",
                detail=f"Via {row['net1']} ({row['pivot_ip1']}) -> "
                       f"{row['net2']} ({row['pivot_ip2']})",
                data=row,
            ))

        # Same-service lateral: hosts on the same subnet running the same
        # service (e.g. SSH everywhere = spray opportunity)
        q_lateral = """
        MATCH (h1:Host)-[:HAS_PORT]->(p1:Port {state: 'open'})
        MATCH (h2:Host)-[:HAS_PORT]->(p2:Port {state: 'open'})
        WHERE h1.uid < h2.uid
          AND p1.service = p2.service AND p1.service IS NOT NULL
        MATCH (h1)-[:HAS_INTERFACE|HAS_IP*1..2]->(ip1:IPAddress)
              -[:IN_NETWORK]->(n:Network)<-[:IN_NETWORK]-(ip2:IPAddress)
              <-[:HAS_IP|HAS_INTERFACE*1..2]-(h2)
        WITH h1, h2, p1.service AS service, n.cidr AS net,
             collect(DISTINCT ip1.address)[0] AS ip1,
             collect(DISTINCT ip2.address)[0] AS ip2
        RETURN h1.hostname AS host1, h2.hostname AS host2,
               service, net, ip1, ip2
        ORDER BY service
        """
        for row in db.query(q_lateral):
            svc = row.get("service", "")
            sev = "medium" if svc in ("ssh", "smb", "rdp", "winrm") else "low"
            findings.append(Finding(
                title=f"Lateral via {svc}: {row['host1']} <-> {row['host2']}",
                severity=sev,
                detail=f"Same subnet {row['net']}: {row.get('ip1')} / {row.get('ip2')}",
                data=row,
            ))

        return findings

    def _paths_from(self, db: "TargetDB", from_uid: str) -> list[Finding]:
        """Find all hosts reachable from a given starting host."""
        # Direct subnet neighbours
        q = """
        MATCH (src:Host {uid: $uid})-[:HAS_INTERFACE|HAS_IP*1..2]->(ip1:IPAddress)
              -[:IN_NETWORK]->(n:Network)<-[:IN_NETWORK]-(ip2:IPAddress)
              <-[:HAS_IP|HAS_INTERFACE*1..2]-(target:Host)
        WHERE src.uid <> target.uid
        OPTIONAL MATCH (target)-[:HAS_PORT]->(p:Port {state: 'open'})
        WITH src, target, n, ip2,
             collect(DISTINCT p.service) AS services
        RETURN src.hostname AS source, target.hostname AS target,
               target.uid AS target_uid,
               n.cidr AS via_net, ip2.address AS target_ip,
               services
        ORDER BY target.hostname
        """
        findings: list[Finding] = []
        for row in db.query(q, uid=from_uid):
            svcs = [s for s in (row.get("services") or []) if s]
            findings.append(Finding(
                title=f"Reachable: {row['target']} ({row['target_ip']})",
                severity="info",
                detail=f"Via {row['via_net']}, services: {', '.join(svcs) or 'none detected'}",
                data=row,
            ))
        return findings
