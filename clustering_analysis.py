"""
Host clustering — group hosts by fingerprint similarity.

Clusters hosts that share the same OS, service stack, or network role.
Useful for identifying:
  - Server farms / identical deployments
  - Outliers (one host unlike anything else)
  - Role-based groupings (web tier, db tier, jump boxes)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, TYPE_CHECKING

from . import BaseAnalyzer, Finding

if TYPE_CHECKING:
    from ..db import TargetDB


class ServiceClusterAnalyzer(BaseAnalyzer):
    name = "service-clusters"
    description = "Group hosts by identical open-service fingerprint"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (h:Host)
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
          WHERE p.state = 'open'
        WITH h, collect(p.service + ':' + toString(p.number) + '/' + p.protocol) AS svc_list
        WITH h, apoc.coll.sort(svc_list) AS sorted_svcs
        RETURN h.uid AS uid, h.hostname AS hostname, sorted_svcs
        """
        # If apoc isn't available, fall back to a simpler query
        try:
            rows = db.query(q)
        except Exception:
            q_fallback = """
            MATCH (h:Host)
            OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
              WHERE p.state = 'open'
            WITH h, collect(p.service + ':' + toString(p.number)) AS svc_list
            RETURN h.uid AS uid, h.hostname AS hostname, svc_list
            """
            rows = db.query(q_fallback)

        # Group by fingerprint
        clusters: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            svcs = sorted(s for s in (row.get("sorted_svcs") or row.get("svc_list") or []) if s)
            fingerprint = "|".join(svcs) if svcs else "<no-services>"
            clusters[fingerprint].append(row)

        findings: list[Finding] = []

        # Multi-host clusters first
        for fp, hosts in sorted(clusters.items(), key=lambda x: -len(x[1])):
            names = [h.get("hostname") or h["uid"][:12] for h in hosts]
            if len(hosts) > 1:
                findings.append(Finding(
                    title=f"Cluster ({len(hosts)} hosts): {fp}",
                    severity="medium",
                    detail=f"Hosts: {', '.join(names)}",
                    data={"fingerprint": fp, "hosts": hosts},
                ))
            else:
                findings.append(Finding(
                    title=f"Unique: {names[0]} — {fp}",
                    severity="info",
                    detail="No other host shares this service profile",
                    data={"fingerprint": fp, "hosts": hosts},
                ))

        return findings


class OSClusterAnalyzer(BaseAnalyzer):
    name = "os-clusters"
    description = "Group hosts by operating system"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (h:Host)
        WITH coalesce(h.os, 'Unknown') AS os_name,
             collect({uid: h.uid, hostname: h.hostname}) AS hosts
        RETURN os_name, hosts, size(hosts) AS count
        ORDER BY count DESC
        """
        findings: list[Finding] = []
        for row in db.query(q):
            names = [h.get("hostname") or h["uid"][:12] for h in row["hosts"]]
            findings.append(Finding(
                title=f"OS: {row['os_name']} ({row['count']} host(s))",
                severity="info",
                detail=", ".join(names),
                data=row,
            ))
        return findings


class OutlierAnalyzer(BaseAnalyzer):
    name = "outliers"
    description = "Find hosts running unusual or unique services"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        # Find services that appear on only one host
        q = """
        MATCH (h:Host)-[:HAS_PORT]->(p:Port)
        WHERE p.state = 'open' AND p.service IS NOT NULL
        WITH p.service AS service, p.number AS port,
             collect(DISTINCT h.hostname) AS hosts
        WHERE size(hosts) = 1
        RETURN service, port, hosts[0] AS host
        ORDER BY port
        """
        findings: list[Finding] = []
        for row in db.query(q):
            findings.append(Finding(
                title=f"Unique service: {row['service']}:{row['port']} "
                      f"only on {row['host']}",
                severity="low",
                detail="This service appears on no other host — investigate if intentional",
                data=row,
            ))
        return findings
