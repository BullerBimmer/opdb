"""Path / reachability analyzers."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from . import BaseAnalyzer, Finding

if TYPE_CHECKING:
    from ..db import TargetDB


class PathAnalyzer(BaseAnalyzer):
    name = "paths"
    description = "Find network paths between two hosts via shared subnets and gateways"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        """Find paths between source and target hosts.

        Kwargs:
            from_uid: source host uid
            to_uid:   target host uid

        If neither is given, returns all host pairs that share a subnet.
        """
        from_uid = kw.get("from_uid")
        to_uid = kw.get("to_uid")

        if from_uid and to_uid:
            return self._find_path(db, from_uid, to_uid)
        return self._all_reachable_pairs(db)

    def _find_path(self, db: "TargetDB", from_uid: str, to_uid: str) -> list[Finding]:
        # Direct subnet path
        q = """
        MATCH (h1:Host {uid: $from_uid})-[:HAS_INTERFACE|HAS_IP*1..2]->(ip1:IPAddress)
              -[:IN_NETWORK]->(n:Network)<-[:IN_NETWORK]-(ip2:IPAddress)
              <-[:HAS_IP|HAS_INTERFACE*1..2]-(h2:Host {uid: $to_uid})
        RETURN h1.hostname AS src, h2.hostname AS dst,
               ip1.address AS src_ip, ip2.address AS dst_ip,
               n.cidr AS via_network
        """
        findings: list[Finding] = []
        for row in db.query(q, from_uid=from_uid, to_uid=to_uid):
            findings.append(Finding(
                title=f"Direct path: {row['src']} -> {row['dst']}",
                severity="info",
                detail=f"{row['src_ip']} --[{row['via_network']}]--> {row['dst_ip']}",
                data=row,
            ))

        if not findings:
            # Try multi-hop via gateways
            q2 = """
            MATCH (h1:Host {uid: $from_uid})-[:HAS_ROUTE]->(r:Route)
            WHERE r.gateway IS NOT NULL
            WITH h1, r.gateway AS gw
            MATCH (ip:IPAddress {address: gw})<-[:HAS_IP|HAS_INTERFACE*1..2]-(router:Host)
                  -[:HAS_INTERFACE|HAS_IP*1..2]->(ip2:IPAddress)
                  -[:IN_NETWORK]->(n:Network)<-[:IN_NETWORK]-(ip3:IPAddress)
                  <-[:HAS_IP|HAS_INTERFACE*1..2]-(h2:Host {uid: $to_uid})
            RETURN h1.hostname AS src, router.hostname AS via_host,
                   h2.hostname AS dst, gw, n.cidr AS network
            """
            for row in db.query(q2, from_uid=from_uid, to_uid=to_uid):
                findings.append(Finding(
                    title=f"Multi-hop path: {row['src']} -> {row['via_host']} -> {row['dst']}",
                    severity="info",
                    detail=f"Via gateway {row['gw']}, network {row['network']}",
                    data=row,
                ))

        if not findings:
            findings.append(Finding(
                title="No path found",
                severity="info",
                detail=f"No network path between {from_uid} and {to_uid}",
            ))

        return findings

    def _all_reachable_pairs(self, db: "TargetDB") -> list[Finding]:
        q = """
        MATCH (h1:Host)-[:HAS_INTERFACE|HAS_IP*1..2]->(ip1:IPAddress)
              -[:IN_NETWORK]->(n:Network)<-[:IN_NETWORK]-(ip2:IPAddress)
              <-[:HAS_IP|HAS_INTERFACE*1..2]-(h2:Host)
        WHERE h1.uid < h2.uid
        RETURN h1.hostname AS host1, h2.hostname AS host2,
               n.cidr AS shared_net,
               ip1.address AS ip1, ip2.address AS ip2
        ORDER BY shared_net
        """
        findings: list[Finding] = []
        for row in db.query(q):
            findings.append(Finding(
                title=f"{row.get('host1') or row.get('ip1')} <-> "
                      f"{row.get('host2') or row.get('ip2')}",
                severity="info",
                detail=f"Shared network: {row['shared_net']}",
                data=row,
            ))
        return findings
