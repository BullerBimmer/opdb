"""
Layered views over the targeting graph.

The raw graph stores everything — interfaces, IPs, MACs, routes, ports,
banners, etc.  That level of detail is essential for deep-dive analysis but
makes the big picture unreadable.

This module provides three zoom levels that *project* the same underlying
data at different abstraction layers:

    STRATEGIC   Host ←→ Host via Network.  Pure connectivity.
                "Who can talk to whom?"

    TACTICAL    Host (interface) ←→ Network ←→ Host (interface),
                with key services and credentials attached.
                "How do they connect, and what's exposed?"

    TECHNICAL   Full detail — every IP, MAC, route entry, port,
                banner, version.  The raw graph.
                "Give me everything."

Each view is a set of Cypher queries that return a consistent schema
the CLI and (future) UI can render without knowing which layer is active.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .db import TargetDB


class ViewLevel(str, Enum):
    STRATEGIC = "strategic"
    TACTICAL = "tactical"
    TECHNICAL = "technical"


# ── Strategic ────────────────────────────────────────────────────────────────
# Collapse the entire Interface→IP→Network chain into direct Host↔Network
# edges.  Ports, routes, MACs are hidden.

_STRATEGIC_OVERVIEW = """
MATCH (h:Host)
OPTIONAL MATCH (h)-[:HAS_INTERFACE|HAS_IP*1..2]->(ip:IPAddress)
      -[:IN_NETWORK]->(n:Network)
WITH h, collect(DISTINCT n {.cidr, .name}) AS networks
RETURN h.uid        AS uid,
       h.hostname   AS hostname,
       h.status     AS status,
       networks
ORDER BY h.hostname
"""

_STRATEGIC_CONNECTIVITY = """
MATCH (h1:Host)-[:HAS_INTERFACE|HAS_IP*1..2]->(:IPAddress)
      -[:IN_NETWORK]->(n:Network)<-[:IN_NETWORK]-(:IPAddress)
      <-[:HAS_IP|HAS_INTERFACE*1..2]-(h2:Host)
WHERE h1.uid < h2.uid
WITH h1, h2, collect(DISTINCT n.cidr) AS shared_nets
RETURN h1.hostname AS host_a,
       h2.hostname AS host_b,
       shared_nets,
       size(shared_nets) AS link_count
ORDER BY link_count DESC
"""

# ── Tactical ─────────────────────────────────────────────────────────────────
# Show the interface-level detail: which interface on which host connects to
# which network, plus a summary of open high-value services.

_TACTICAL_HOST = """
MATCH (h:Host {uid: $uid})
OPTIONAL MATCH (h)-[:HAS_INTERFACE]->(i:Interface)-[:HAS_IP]->(ip:IPAddress)
WITH h, i, ip
OPTIONAL MATCH (ip)-[:IN_NETWORK]->(n:Network)
WITH h,
     collect(DISTINCT {
       iface: i.name, mac: i.mac,
       ip: ip.address, cidr: ip.cidr,
       network: n.cidr, network_name: n.name
     }) AS connections
OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
  WHERE p.state = 'open'
WITH h, connections,
     collect(DISTINCT {
       port: p.number, proto: p.protocol,
       service: p.service, product: p.product, version: p.version
     }) AS services
OPTIONAL MATCH (c:Credential)-[:FOR_HOST]->(h)
WITH h, connections, services,
     collect(DISTINCT {
       username: c.username, type: c.cred_type, domain: c.domain
     }) AS creds
RETURN h {.uid, .hostname, .os, .status, .tags, .notes} AS host,
       connections, services, creds
"""

_TACTICAL_NETWORK = """
MATCH (n:Network {cidr: $cidr})
OPTIONAL MATCH (ip:IPAddress)-[:IN_NETWORK]->(n)
OPTIONAL MATCH (ip)<-[:HAS_IP]-(i:Interface)<-[:HAS_INTERFACE]-(h:Host)
OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
  WHERE p.state = 'open'
WITH n, h, i, ip,
     collect(DISTINCT p.service + ':' + toString(p.number)) AS services
RETURN n {.cidr, .name, .vlan, .description} AS network,
       collect(DISTINCT {
         hostname: h.hostname, uid: h.uid,
         iface: i.name, ip: ip.address,
         services: services
       }) AS hosts
"""

_TACTICAL_OVERVIEW = """
MATCH (h:Host)
OPTIONAL MATCH (h)-[:HAS_INTERFACE]->(i:Interface)-[:HAS_IP]->(ip:IPAddress)
      -[:IN_NETWORK]->(n:Network)
OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
  WHERE p.state = 'open'
WITH h, n,
     collect(DISTINCT {iface: i.name, ip: ip.address}) AS ifaces,
     collect(DISTINCT p.service) AS services
RETURN h.uid        AS uid,
       h.hostname   AS hostname,
       h.status     AS status,
       n.cidr       AS network,
       ifaces,
       [s IN services WHERE s IS NOT NULL] AS services
ORDER BY network, h.hostname
"""

# ── Technical ────────────────────────────────────────────────────────────────
# Everything.  Full raw detail for a single host.

_TECHNICAL_HOST = """
MATCH (h:Host {uid: $uid})
OPTIONAL MATCH (h)-[:HAS_INTERFACE]->(i:Interface)-[:HAS_IP]->(ip:IPAddress)
OPTIONAL MATCH (ip)-[:IN_NETWORK]->(n:Network)
WITH h, collect(DISTINCT {
  iface_uid: i.uid, iface: i.name, mac: i.mac,
  ip: ip.address, ip_version: ip.version, cidr: ip.cidr,
  network: n.cidr, network_name: n.name, network_vlan: n.vlan,
  ip_first_seen: ip.first_seen, ip_last_seen: ip.last_seen
}) AS interfaces
OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
WITH h, interfaces, collect(DISTINCT {
  port: p.number, proto: p.protocol, state: p.state,
  service: p.service, product: p.product, version: p.version,
  banner: p.banner,
  first_seen: p.first_seen, last_seen: p.last_seen
}) AS ports
OPTIONAL MATCH (h)-[:HAS_ROUTE]->(r:Route)
WITH h, interfaces, ports, collect(DISTINCT {
  destination: r.destination, gateway: r.gateway,
  interface: r.interface_name, metric: r.metric, flags: r.flags
}) AS routes
OPTIONAL MATCH (c:Credential)-[:FOR_HOST]->(h)
WITH h, interfaces, ports, routes, collect(DISTINCT {
  uid: c.uid, username: c.username, type: c.cred_type,
  domain: c.domain, realm: c.realm, source: c.source, valid: c.valid
}) AS creds
OPTIONAL MATCH (s:ScanEvent)-[:PRODUCED]->(h)
WITH h, interfaces, ports, routes, creds, collect(DISTINCT {
  scan_type: s.scan_type, timestamp: s.timestamp,
  source_file: s.source_file, summary: s.summary
}) AS scans
RETURN h {.*} AS host,
       interfaces, ports, routes, creds, scans
"""


class GraphView:
    """Query the graph through a specific abstraction layer."""

    def __init__(self, db: "TargetDB", level: ViewLevel = ViewLevel.TACTICAL):
        self.db = db
        self.level = level

    # ── Overview (all hosts) ─────────────────────────────────────────────

    def overview(self) -> list[dict]:
        """Top-level view of all hosts."""
        if self.level == ViewLevel.STRATEGIC:
            return self.db.query(_STRATEGIC_OVERVIEW)
        elif self.level == ViewLevel.TACTICAL:
            return self.db.query(_TACTICAL_OVERVIEW)
        else:
            # Technical overview = just list hosts, user drills in
            return self.db.query(_STRATEGIC_OVERVIEW)

    def connectivity(self) -> list[dict]:
        """Which hosts can reach which — strategic level always."""
        return self.db.query(_STRATEGIC_CONNECTIVITY)

    # ── Single host detail ───────────────────────────────────────────────

    def host(self, uid: str) -> dict | None:
        """Drill into one host at the current view level."""
        if self.level == ViewLevel.STRATEGIC:
            rows = self.db.query(_STRATEGIC_OVERVIEW + """
            // Not parameterised in the overview, so re-query for one host
            """)
            # Simpler: just return minimal info
            q = """
            MATCH (h:Host {uid: $uid})
            OPTIONAL MATCH (h)-[:HAS_INTERFACE|HAS_IP*1..2]->(ip:IPAddress)
                  -[:IN_NETWORK]->(n:Network)
            RETURN h.hostname AS hostname, h.status AS status,
                   collect(DISTINCT n.cidr) AS networks
            """
            rows = self.db.query(q, uid=uid)
            return rows[0] if rows else None

        elif self.level == ViewLevel.TACTICAL:
            rows = self.db.query(_TACTICAL_HOST, uid=uid)
            return rows[0] if rows else None

        else:  # TECHNICAL
            rows = self.db.query(_TECHNICAL_HOST, uid=uid)
            return rows[0] if rows else None

    # ── Network detail ───────────────────────────────────────────────────

    def network(self, cidr: str) -> dict | None:
        """Drill into one network."""
        if self.level == ViewLevel.STRATEGIC:
            q = """
            MATCH (n:Network {cidr: $cidr})
            OPTIONAL MATCH (ip:IPAddress)-[:IN_NETWORK]->(n)
                   <-[:HAS_IP|HAS_INTERFACE*1..2]-(h:Host)
            RETURN n.cidr AS cidr, n.name AS name,
                   collect(DISTINCT h.hostname) AS hosts
            """
            rows = self.db.query(q, cidr=cidr)
            return rows[0] if rows else None
        else:
            rows = self.db.query(_TACTICAL_NETWORK, cidr=cidr)
            return rows[0] if rows else None
