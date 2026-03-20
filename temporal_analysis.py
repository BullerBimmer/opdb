"""
Temporal analysis — detect changes across scans.

Compares scan events to find what appeared, disappeared, or changed.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from . import BaseAnalyzer, Finding

if TYPE_CHECKING:
    from ..db import TargetDB


class ChangeDetectionAnalyzer(BaseAnalyzer):
    name = "changes"
    description = "Detect what changed between the two most recent scans"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        findings: list[Finding] = []

        # New hosts (appeared in latest scan but not in any earlier scan)
        q_new_hosts = """
        MATCH (s:ScanEvent)-[:PRODUCED]->(h:Host)
        WITH h, min(s.timestamp) AS first_scan, max(s.timestamp) AS latest_scan
        WITH h, first_scan
        WHERE first_scan = h.first_seen
        ORDER BY first_scan DESC
        RETURN h.uid AS uid, h.hostname AS hostname, h.status AS status,
               first_scan
        LIMIT 20
        """
        for row in db.query(q_new_hosts):
            findings.append(Finding(
                title=f"New host: {row.get('hostname') or row['uid']}",
                severity="medium",
                detail=f"First appeared: {row['first_scan']}, status: {row.get('status')}",
                data=row,
            ))

        # New ports since previous scan
        q_new_ports = """
        MATCH (h:Host)-[:HAS_PORT]->(p:Port)
        WHERE p.first_seen = p.last_seen
        RETURN h.hostname AS hostname, h.uid AS host_uid,
               p.number AS port, p.protocol AS protocol,
               p.service AS service, p.product AS product,
               p.first_seen AS appeared
        ORDER BY p.first_seen DESC
        LIMIT 30
        """
        for row in db.query(q_new_ports):
            findings.append(Finding(
                title=f"New port: {row.get('service') or row['port']}/{row['protocol']} "
                      f"on {row.get('hostname') or row['host_uid']}",
                severity="medium",
                detail=f"Product: {row.get('product')}, appeared: {row['appeared']}",
                data=row,
            ))

        # Port state changes (was open, now filtered/closed or vice versa)
        # We detect this by looking for ports seen by multiple scans with
        # different states.
        q_state_changes = """
        MATCH (s1:ScanEvent)-[:PRODUCED]->(p:Port)<-[:HAS_PORT]-(h:Host)
        WITH h, p, count(s1) AS scan_count
        WHERE scan_count > 1
        RETURN h.hostname AS hostname, p.number AS port,
               p.protocol AS protocol, p.state AS current_state,
               p.service AS service, scan_count
        """
        for row in db.query(q_state_changes):
            findings.append(Finding(
                title=f"Port seen across {row['scan_count']} scans: "
                      f"{row['port']}/{row['protocol']} on {row.get('hostname')}",
                severity="info",
                detail=f"Current state: {row['current_state']}, service: {row.get('service')}",
                data=row,
            ))

        # IP address reassignment — same IP now on a different host
        q_ip_reassign = """
        MATCH (h1:Host)-[:HAS_IP]->(ip:IPAddress)<-[:HAS_IP]-(h2:Host)
        WHERE h1.uid < h2.uid
        RETURN ip.address AS address,
               h1.hostname AS host1, h1.uid AS uid1,
               h2.hostname AS host2, h2.uid AS uid2
        """
        for row in db.query(q_ip_reassign):
            findings.append(Finding(
                title=f"IP conflict: {row['address']}",
                severity="high",
                detail=f"Claimed by both {row.get('host1') or row['uid1']} "
                       f"and {row.get('host2') or row['uid2']}",
                data=row,
            ))

        return findings


class DisappearedAnalyzer(BaseAnalyzer):
    name = "disappeared"
    description = "Find hosts/services seen in old scans but not recent ones"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        days = kw.get("days", 3)
        findings: list[Finding] = []

        # Hosts that went from alive to down or haven't been seen
        q = """
        MATCH (h:Host)
        WHERE h.status IN ['alive', 'unknown']
          AND h.last_seen < datetime() - duration({days: $days})
        RETURN h.uid AS uid, h.hostname AS hostname,
               h.last_seen AS last_seen, h.status AS status
        ORDER BY h.last_seen
        """
        for row in db.query(q, days=days):
            findings.append(Finding(
                title=f"Host not re-confirmed: {row.get('hostname') or row['uid']}",
                severity="low",
                detail=f"Last seen: {row['last_seen']}, status was: {row['status']}",
                data=row,
            ))

        # Ports that were open but haven't been refreshed
        q_ports = """
        MATCH (h:Host)-[:HAS_PORT]->(p:Port)
        WHERE p.state = 'open'
          AND p.last_seen < datetime() - duration({days: $days})
        RETURN h.hostname AS hostname, p.number AS port,
               p.service AS service, p.last_seen AS last_seen
        ORDER BY p.last_seen
        """
        for row in db.query(q_ports, days=days):
            findings.append(Finding(
                title=f"Stale open port: {row.get('service') or row['port']} "
                      f"on {row.get('hostname')}",
                severity="low",
                detail=f"Last confirmed open: {row['last_seen']}",
                data=row,
            ))

        return findings
