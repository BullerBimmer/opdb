"""
Network segmentation analysis.

Evaluates how well the network is segmented:
  - Which subnets can reach which other subnets (via dual-homed hosts or routes)
  - Cross-boundary services (a host in subnet A serving clients in subnet B)
  - Flat network detection (everything on one /16)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, TYPE_CHECKING

from . import BaseAnalyzer, Finding

if TYPE_CHECKING:
    from ..db import TargetDB


class SegmentationScoreAnalyzer(BaseAnalyzer):
    name = "segmentation"
    description = "Score network segmentation — find cross-boundary paths and flat networks"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        findings: list[Finding] = []

        # 1. How many subnets vs how many hosts
        q_overview = """
        MATCH (n:Network) WITH count(n) AS net_count
        MATCH (h:Host) WITH net_count, count(h) AS host_count
        RETURN net_count, host_count
        """
        rows = db.query(q_overview)
        if rows:
            r = rows[0]
            net_count = r.get("net_count", 0)
            host_count = r.get("host_count", 0)
            ratio = host_count / net_count if net_count > 0 else host_count

            if net_count <= 1 and host_count > 3:
                findings.append(Finding(
                    title=f"Flat network: {host_count} hosts on {net_count} subnet(s)",
                    severity="high",
                    detail="All hosts appear to be on the same network — no segmentation",
                ))
            else:
                findings.append(Finding(
                    title=f"Network topology: {host_count} hosts across {net_count} subnets "
                          f"(avg {ratio:.1f} hosts/subnet)",
                    severity="info",
                    detail="",
                ))

        # 2. Subnet bridges — hosts connecting two subnets
        q_bridges = """
        MATCH (h:Host)-[:HAS_INTERFACE|HAS_IP*1..2]->(ip:IPAddress)
              -[:IN_NETWORK]->(n:Network)
        WITH h, collect(DISTINCT n.cidr) AS nets
        WHERE size(nets) > 1
        UNWIND nets AS net1
        WITH h, nets, net1
        UNWIND nets AS net2
        WITH h, net1, net2
        WHERE net1 < net2
        RETURN h.hostname AS hostname, h.uid AS uid,
               net1, net2
        """
        bridge_pairs: set[tuple[str, str]] = set()
        for row in db.query(q_bridges):
            pair = (row["net1"], row["net2"])
            bridge_pairs.add(pair)
            findings.append(Finding(
                title=f"Subnet bridge: {row.get('hostname') or row['uid'][:12]} "
                      f"connects {row['net1']} <-> {row['net2']}",
                severity="high",
                detail="This host can be used as a pivot between these networks",
                data=row,
            ))

        # 3. Route-implied connectivity — gateways connecting subnets
        q_routes = """
        MATCH (h:Host)-[:HAS_ROUTE]->(r:Route)
        WHERE r.gateway IS NOT NULL
        MATCH (h)-[:HAS_INTERFACE|HAS_IP*1..2]->(ip:IPAddress)
              -[:IN_NETWORK]->(home_net:Network)
        RETURN h.hostname AS hostname,
               home_net.cidr AS home_network,
               r.destination AS route_dest,
               r.gateway AS gateway
        """
        for row in db.query(q_routes):
            dest = row.get("route_dest", "")
            if dest == "0.0.0.0/0":
                dest = "default (all networks)"
            findings.append(Finding(
                title=f"Route: {row.get('hostname')} in {row['home_network']} "
                      f"-> {dest} via {row['gateway']}",
                severity="info",
                detail="This route implies cross-network reachability",
                data=row,
            ))

        # 4. Segmentation score summary
        if bridge_pairs:
            findings.insert(0, Finding(
                title=f"Segmentation concern: {len(bridge_pairs)} subnet pair(s) "
                      f"bridged by dual-homed hosts",
                severity="high",
                detail="Dual-homed hosts break network isolation. "
                       "Consider firewall rules on these hosts.",
            ))

        return findings


class SubnetMapAnalyzer(BaseAnalyzer):
    name = "subnet-map"
    description = "Full subnet-to-host-to-service map for situational awareness"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (n:Network)<-[:IN_NETWORK]-(ip:IPAddress)
              <-[:HAS_IP|HAS_INTERFACE*1..2]-(h:Host)
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
          WHERE p.state = 'open'
        WITH n.cidr AS net, h.hostname AS hostname, ip.address AS ip,
             collect(DISTINCT p.service + ':' + toString(p.number)) AS services
        ORDER BY net, ip
        RETURN net,
               collect({hostname: hostname, ip: ip, services: services}) AS hosts
        ORDER BY net
        """
        findings: list[Finding] = []
        for row in db.query(q):
            hosts = row.get("hosts", [])
            lines = []
            for h in hosts:
                svcs = [s for s in (h.get("services") or []) if s and s != "null:0"]
                svc_str = f" [{', '.join(svcs)}]" if svcs else ""
                lines.append(f"  {h.get('ip'):16s} {h.get('hostname') or '?'}{svc_str}")
            findings.append(Finding(
                title=f"Subnet {row['net']} ({len(hosts)} host(s))",
                severity="info",
                detail="\n".join(lines),
                data=row,
            ))
        return findings
