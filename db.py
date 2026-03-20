"""
Neo4j database layer.

All Cypher lives here.  The public API works with the dataclass models from
``models.py`` so callers never touch raw Cypher.

Design principles
-----------------
* **Merge-on-natural-key** — hosts are matched by hostname *or* IP, IPs by
  address, networks by CIDR, etc.  This lets repeated scans update existing
  nodes instead of creating duplicates.
* **Temporal edges** — every relationship carries ``first_seen`` /
  ``last_seen`` so the graph records *when* a fact was true and naturally
  handles network churn.
* **Scan provenance** — every ingestion creates a ``ScanEvent`` node linked
  to the entities it touched, giving full auditability.
"""

from __future__ import annotations

import dataclasses
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator

from neo4j import GraphDatabase, Driver, Session

from .models import (
    Host, Interface, IPAddress, Network, Port, Credential, Route, ScanEvent,
    HostStatus,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _props(obj: Any) -> dict[str, Any]:
    """Flatten a dataclass to a Neo4j-safe property dict."""
    d: dict[str, Any] = {}
    for f in dataclasses.fields(obj):
        v = getattr(obj, f.name)
        if v is None:
            continue
        if isinstance(v, list):
            d[f.name] = v  # Neo4j handles lists of primitives
        elif isinstance(v, dict):
            # Flatten one level: meta.foo -> meta_foo
            for mk, mv in v.items():
                d[f"{f.name}_{mk}"] = mv
        elif isinstance(v, enum_base):
            d[f.name] = v.value
        else:
            d[f.name] = v
    return d


# Avoid circular import — we just need the base class for Enum detection
import enum as _enum_mod  # noqa: E402
enum_base = _enum_mod.Enum


# ---------------------------------------------------------------------------
# Database wrapper
# ---------------------------------------------------------------------------

class TargetDB:
    """High-level interface to the targeting Neo4j database."""

    def __init__(self, uri: str = "bolt://localhost:7687",
                 user: str = "neo4j", password: str = "neo4j",
                 database: str = "neo4j"):
        self._driver: Driver = GraphDatabase.driver(uri, auth=(user, password))
        self._database = database

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        self._driver.close()

    def __enter__(self) -> "TargetDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _session(self) -> Generator[Session, None, None]:
        with self._driver.session(database=self._database) as s:
            yield s

    # -- schema / constraints ------------------------------------------------

    def ensure_indexes(self) -> None:
        """Create constraints and indexes for performance."""
        stmts = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.uid IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (i:Interface) REQUIRE i.uid IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.uid IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Network) REQUIRE n.uid IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Port) REQUIRE p.uid IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Credential) REQUIRE c.uid IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Route) REQUIRE r.uid IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (s:ScanEvent) REQUIRE s.uid IS UNIQUE",
            "CREATE INDEX IF NOT EXISTS FOR (ip:IPAddress) ON (ip.address)",
            "CREATE INDEX IF NOT EXISTS FOR (n:Network) ON (n.cidr)",
            "CREATE INDEX IF NOT EXISTS FOR (h:Host) ON (h.hostname)",
            "CREATE INDEX IF NOT EXISTS FOR (p:Port) ON (p.number)",
        ]
        with self._session() as session:
            for s in stmts:
                session.run(s)

    # -- raw query -----------------------------------------------------------

    def query(self, cypher: str, **params: Any) -> list[dict]:
        """Run arbitrary Cypher and return list of record dicts."""
        with self._session() as session:
            result = session.run(cypher, **params)
            return [r.data() for r in result]

    # -- merge helpers (upsert) ----------------------------------------------

    def merge_host(self, host: Host, scan_uid: str | None = None) -> str:
        """Merge a Host node.  Matches on hostname if set, else uid."""
        q = """
        MERGE (h:Host {uid: $uid})
        SET h += $props, h.last_seen = $now
        RETURN h.uid AS uid
        """
        # If hostname is known, try to merge on hostname first
        if host.hostname:
            q = """
            MERGE (h:Host {hostname: $hostname})
            ON CREATE SET h += $props
            ON MATCH SET h += $props, h.last_seen = $now
            RETURN h.uid AS uid
            """
        props = _props(host)
        with self._session() as session:
            rec = session.run(q, uid=host.uid, hostname=host.hostname,
                              props=props, now=_now()).single()
            uid = rec["uid"]  # type: ignore[index]
        if scan_uid:
            self._link_scan(scan_uid, "Host", uid)
        return uid

    def merge_interface(self, iface: Interface, host_uid: str,
                        scan_uid: str | None = None) -> str:
        """Merge an Interface and attach it to a Host."""
        q = """
        MATCH (h:Host {uid: $host_uid})
        MERGE (h)-[:HAS_INTERFACE]->(i:Interface {name: $name})
        ON CREATE SET i += $props
        ON MATCH SET i += $props, i.last_seen = $now
        RETURN i.uid AS uid
        """
        # If no name, fall back to uid-based merge
        if not iface.name:
            q = """
            MATCH (h:Host {uid: $host_uid})
            MERGE (i:Interface {uid: $uid})
            ON CREATE SET i += $props
            ON MATCH SET i += $props, i.last_seen = $now
            MERGE (h)-[:HAS_INTERFACE]->(i)
            RETURN i.uid AS uid
            """
        props = _props(iface)
        with self._session() as session:
            rec = session.run(q, host_uid=host_uid, uid=iface.uid,
                              name=iface.name, props=props, now=_now()).single()
            uid = rec["uid"]  # type: ignore[index]
        if scan_uid:
            self._link_scan(scan_uid, "Interface", uid)
        return uid

    def merge_ip(self, ip: IPAddress, interface_uid: str | None = None,
                 host_uid: str | None = None,
                 scan_uid: str | None = None) -> str:
        """Merge an IPAddress.  Optionally link to an Interface or Host."""
        q = """
        MERGE (ip:IPAddress {address: $address})
        ON CREATE SET ip += $props
        ON MATCH SET ip += $props, ip.last_seen = $now
        RETURN ip.uid AS uid
        """
        props = _props(ip)
        with self._session() as session:
            rec = session.run(q, address=ip.address,
                              props=props, now=_now()).single()
            uid = rec["uid"]  # type: ignore[index]

        if interface_uid:
            self._rel("Interface", interface_uid, "HAS_IP", "IPAddress", uid)
        if host_uid:
            self._rel("Host", host_uid, "HAS_IP", "IPAddress", uid)
        if scan_uid:
            self._link_scan(scan_uid, "IPAddress", uid)
        return uid

    def merge_network(self, net: Network,
                      scan_uid: str | None = None) -> str:
        q = """
        MERGE (n:Network {cidr: $cidr})
        ON CREATE SET n += $props
        ON MATCH SET n += $props, n.last_seen = $now
        RETURN n.uid AS uid
        """
        props = _props(net)
        with self._session() as session:
            rec = session.run(q, cidr=net.cidr, props=props,
                              now=_now()).single()
            uid = rec["uid"]  # type: ignore[index]
        if scan_uid:
            self._link_scan(scan_uid, "Network", uid)
        return uid

    def merge_port(self, port: Port, host_uid: str,
                   scan_uid: str | None = None) -> str:
        q = """
        MATCH (h:Host {uid: $host_uid})
        MERGE (h)-[:HAS_PORT]->(p:Port {number: $number, protocol: $protocol})
        ON CREATE SET p += $props
        ON MATCH SET p += $props, p.last_seen = $now
        RETURN p.uid AS uid
        """
        props = _props(port)
        with self._session() as session:
            rec = session.run(q, host_uid=host_uid, number=port.number,
                              protocol=port.protocol.value,
                              props=props, now=_now()).single()
            uid = rec["uid"]  # type: ignore[index]
        if scan_uid:
            self._link_scan(scan_uid, "Port", uid)
        return uid

    def merge_credential(self, cred: Credential, host_uid: str | None = None,
                         port_uid: str | None = None,
                         scan_uid: str | None = None) -> str:
        q = """
        MERGE (c:Credential {uid: $uid})
        ON CREATE SET c += $props
        ON MATCH SET c += $props, c.last_seen = $now
        RETURN c.uid AS uid
        """
        props = _props(cred)
        with self._session() as session:
            rec = session.run(q, uid=cred.uid, props=props,
                              now=_now()).single()
            uid = rec["uid"]  # type: ignore[index]

        if host_uid:
            self._rel("Credential", uid, "FOR_HOST", "Host", host_uid)
        if port_uid:
            self._rel("Credential", uid, "FOR_SERVICE", "Port", port_uid)
        if scan_uid:
            self._link_scan(scan_uid, "Credential", uid)
        return uid

    def merge_route(self, route: Route, host_uid: str,
                    scan_uid: str | None = None) -> str:
        q = """
        MATCH (h:Host {uid: $host_uid})
        MERGE (h)-[:HAS_ROUTE]->(r:Route {destination: $destination})
        ON CREATE SET r += $props
        ON MATCH SET r += $props, r.last_seen = $now
        RETURN r.uid AS uid
        """
        props = _props(route)
        with self._session() as session:
            rec = session.run(q, host_uid=host_uid,
                              destination=route.destination,
                              props=props, now=_now()).single()
            uid = rec["uid"]  # type: ignore[index]
        if scan_uid:
            self._link_scan(scan_uid, "Route", uid)
        return uid

    def create_scan_event(self, scan: ScanEvent) -> str:
        q = """
        CREATE (s:ScanEvent $props)
        RETURN s.uid AS uid
        """
        props = _props(scan)
        with self._session() as session:
            rec = session.run(q, props=props).single()
            return rec["uid"]  # type: ignore[index]

    # -- IP ↔ Network linking -----------------------------------------------

    def link_ip_to_network(self, ip_address: str, network_cidr: str) -> None:
        """Create (IPAddress)-[:IN_NETWORK]->(Network)."""
        q = """
        MATCH (ip:IPAddress {address: $addr})
        MATCH (n:Network {cidr: $cidr})
        MERGE (ip)-[r:IN_NETWORK]->(n)
        ON CREATE SET r.first_seen = $now
        SET r.last_seen = $now
        """
        with self._session() as session:
            session.run(q, addr=ip_address, cidr=network_cidr, now=_now())

    def auto_link_networks(self) -> int:
        """For every IPAddress, find matching Network by CIDR and link them.

        Returns the number of relationships created/updated.
        """
        # This uses APOC if available; otherwise falls back to brute-force
        # matching.  For moderate-size graphs (<100k nodes) the brute-force is
        # fine.
        q = """
        MATCH (ip:IPAddress), (n:Network)
        WHERE ip.address IS NOT NULL AND n.cidr IS NOT NULL
        WITH ip, n,
             split(ip.address, '.') AS octets,
             split(split(n.cidr, '/')[0], '.') AS net_octets,
             toInteger(split(n.cidr, '/')[1]) AS prefix
        WHERE size(octets) = 4 AND size(net_octets) = 4
        WITH ip, n, prefix,
             toInteger(octets[0])*16777216 + toInteger(octets[1])*65536
               + toInteger(octets[2])*256 + toInteger(octets[3]) AS ip_int,
             toInteger(net_octets[0])*16777216 + toInteger(net_octets[1])*65536
               + toInteger(net_octets[2])*256 + toInteger(net_octets[3]) AS net_int
        // build mask  (2^32 - 2^(32-prefix))
        WITH ip, n, ip_int, net_int,
             toInteger(4294967296 - toInteger(round(2.0 ^ (32 - prefix)))) AS mask
        WHERE (ip_int / toInteger(round(2.0 ^ (32 - toInteger(split(n.cidr, '/')[1])))))
            = (net_int / toInteger(round(2.0 ^ (32 - toInteger(split(n.cidr, '/')[1])))))
        MERGE (ip)-[r:IN_NETWORK]->(n)
        ON CREATE SET r.first_seen = datetime()
        SET r.last_seen = datetime()
        RETURN count(r) AS cnt
        """
        with self._session() as session:
            rec = session.run(q).single()
            return rec["cnt"]  # type: ignore[index]

    # -- relationship helpers ------------------------------------------------

    def _rel(self, from_label: str, from_uid: str,
             rel_type: str,
             to_label: str, to_uid: str) -> None:
        q = f"""
        MATCH (a:{from_label} {{uid: $from_uid}})
        MATCH (b:{to_label} {{uid: $to_uid}})
        MERGE (a)-[r:{rel_type}]->(b)
        ON CREATE SET r.first_seen = $now
        SET r.last_seen = $now
        """
        with self._session() as session:
            session.run(q, from_uid=from_uid, to_uid=to_uid, now=_now())

    def _link_scan(self, scan_uid: str, label: str, uid: str) -> None:
        q = f"""
        MATCH (s:ScanEvent {{uid: $scan_uid}})
        MATCH (n:{label} {{uid: $uid}})
        MERGE (s)-[:PRODUCED]->(n)
        """
        with self._session() as session:
            session.run(q, scan_uid=scan_uid, uid=uid)

    # -- materialized view edges ---------------------------------------------

    def materialize_views(self) -> dict[str, int]:
        """Create/refresh summary relationships for graph visualization.

        These are direct edges that collapse multi-hop paths so that
        Neo4j Browser (and any graph UI) can render clean views:

          STRATEGIC:
            (Host)-[:ON_NETWORK {via_ip, via_iface}]->(Network)
            (Host)-[:CAN_REACH {via_net}]->(Host)

          TACTICAL:
            (Host)-[:CONNECTS_VIA {iface, ip, mac}]->(Network)
            (Host)-[:ROUTES_TO {gateway, metric}]->(Network)

        These edges are *derived* — they carry a `_materialized: true`
        property so they can be deleted and rebuilt at any time.
        """
        counts: dict[str, int] = {}

        # Clean old materialized edges first
        cleanup = [
            "MATCH ()-[r:ON_NETWORK]->() WHERE r._materialized = true DELETE r",
            "MATCH ()-[r:CAN_REACH]->() WHERE r._materialized = true DELETE r",
            "MATCH ()-[r:CONNECTS_VIA]->() WHERE r._materialized = true DELETE r",
            "MATCH ()-[r:ROUTES_TO]->() WHERE r._materialized = true DELETE r",
        ]
        with self._session() as session:
            for stmt in cleanup:
                session.run(stmt)

        # -- STRATEGIC: Host -[:ON_NETWORK]-> Network -----------------------
        q_on_net = """
        MATCH (h:Host)-[:HAS_INTERFACE]->(i:Interface)-[:HAS_IP]->(ip:IPAddress)
              -[:IN_NETWORK]->(n:Network)
        WITH h, n, collect(DISTINCT ip.address) AS ips,
             collect(DISTINCT i.name) AS ifaces
        MERGE (h)-[r:ON_NETWORK]->(n)
        SET r._materialized = true,
            r.ips = ips, r.ifaces = ifaces,
            r.last_seen = datetime()
        RETURN count(r) AS cnt
        """
        # Also catch hosts linked to IP directly (from nmap without interface)
        q_on_net_direct = """
        MATCH (h:Host)-[:HAS_IP]->(ip:IPAddress)-[:IN_NETWORK]->(n:Network)
        WHERE NOT exists { (h)-[:ON_NETWORK]->(n) }
        WITH h, n, collect(DISTINCT ip.address) AS ips
        MERGE (h)-[r:ON_NETWORK]->(n)
        SET r._materialized = true,
            r.ips = ips,
            r.last_seen = datetime()
        RETURN count(r) AS cnt
        """
        with self._session() as session:
            r1 = session.run(q_on_net).single()
            r2 = session.run(q_on_net_direct).single()
            counts["on_network"] = (r1["cnt"] if r1 else 0) + (r2["cnt"] if r2 else 0)

        # -- STRATEGIC: Host -[:CAN_REACH]-> Host ---------------------------
        q_reach = """
        MATCH (h1:Host)-[:ON_NETWORK]->(n:Network)<-[:ON_NETWORK]-(h2:Host)
        WHERE h1.uid < h2.uid
        WITH h1, h2, collect(DISTINCT n.cidr) AS shared_nets
        MERGE (h1)-[r:CAN_REACH]->(h2)
        SET r._materialized = true,
            r.via_networks = shared_nets,
            r.last_seen = datetime()
        RETURN count(r) AS cnt
        """
        with self._session() as session:
            rec = session.run(q_reach).single()
            counts["can_reach"] = rec["cnt"] if rec else 0

        # -- TACTICAL: Host -[:CONNECTS_VIA {iface, ip, mac}]-> Network ----
        q_connects = """
        MATCH (h:Host)-[:HAS_INTERFACE]->(i:Interface)-[:HAS_IP]->(ip:IPAddress)
              -[:IN_NETWORK]->(n:Network)
        WITH h, n, i, ip
        MERGE (h)-[r:CONNECTS_VIA {iface: i.name}]->(n)
        SET r._materialized = true,
            r.ip = ip.address, r.mac = i.mac,
            r.cidr = ip.cidr,
            r.last_seen = datetime()
        RETURN count(r) AS cnt
        """
        with self._session() as session:
            rec = session.run(q_connects).single()
            counts["connects_via"] = rec["cnt"] if rec else 0

        # -- TACTICAL: Host -[:ROUTES_TO]-> Network -------------------------
        # Create network nodes for route destinations if they don't exist,
        # then link.
        q_routes = """
        MATCH (h:Host)-[:HAS_ROUTE]->(r:Route)
        WHERE r.destination <> '0.0.0.0/0'
          AND r.destination CONTAINS '/'
        MERGE (n:Network {cidr: r.destination})
        ON CREATE SET n.uid = randomUUID(), n.first_seen = datetime()
        SET n.last_seen = datetime()
        MERGE (h)-[rel:ROUTES_TO]->(n)
        SET rel._materialized = true,
            rel.gateway = r.gateway,
            rel.interface = r.interface_name,
            rel.metric = r.metric,
            rel.last_seen = datetime()
        RETURN count(rel) AS cnt
        """
        with self._session() as session:
            rec = session.run(q_routes).single()
            counts["routes_to"] = rec["cnt"] if rec else 0

        return counts

    # -- delete --------------------------------------------------------------

    def delete_host(self, host_uid: str) -> None:
        """Delete a host and all exclusively-owned children."""
        q = """
        MATCH (h:Host {uid: $uid})
        OPTIONAL MATCH (h)-[:HAS_INTERFACE]->(i:Interface)
        OPTIONAL MATCH (i)-[:HAS_IP]->(ip:IPAddress)
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
        OPTIONAL MATCH (h)-[:HAS_ROUTE]->(r:Route)
        DETACH DELETE h, i, ip, p, r
        """
        with self._session() as session:
            session.run(q, uid=host_uid)

    # -- read helpers --------------------------------------------------------

    def get_all_hosts(self) -> list[dict]:
        q = "MATCH (h:Host) RETURN h ORDER BY h.last_seen DESC"
        with self._session() as session:
            return [dict(r["h"]) for r in session.run(q)]

    def get_host(self, uid: str) -> dict | None:
        q = "MATCH (h:Host {uid: $uid}) RETURN h"
        with self._session() as session:
            rec = session.run(q, uid=uid).single()
            return dict(rec["h"]) if rec else None

    def get_host_detail(self, uid: str) -> dict:
        """Return host with all related nodes."""
        host = self.get_host(uid)
        if not host:
            return {}
        ips_q = """
        MATCH (h:Host {uid: $uid})-[:HAS_INTERFACE]->(i)-[:HAS_IP]->(ip)
        RETURN i, ip
        """
        ports_q = """
        MATCH (h:Host {uid: $uid})-[:HAS_PORT]->(p)
        RETURN p ORDER BY p.number
        """
        routes_q = """
        MATCH (h:Host {uid: $uid})-[:HAS_ROUTE]->(r)
        RETURN r
        """
        creds_q = """
        MATCH (c:Credential)-[:FOR_HOST]->(h:Host {uid: $uid})
        RETURN c
        """
        with self._session() as session:
            interfaces = []
            for r in session.run(ips_q, uid=uid):
                interfaces.append({"interface": dict(r["i"]),
                                   "ip": dict(r["ip"])})
            ports = [dict(r["p"]) for r in session.run(ports_q, uid=uid)]
            routes = [dict(r["r"]) for r in session.run(routes_q, uid=uid)]
            creds = [dict(r["c"]) for r in session.run(creds_q, uid=uid)]

        return {
            "host": host,
            "interfaces": interfaces,
            "ports": ports,
            "routes": routes,
            "credentials": creds,
        }

    def get_all_networks(self) -> list[dict]:
        q = "MATCH (n:Network) RETURN n ORDER BY n.cidr"
        with self._session() as session:
            return [dict(r["n"]) for r in session.run(q)]

    def search(self, term: str) -> list[dict]:
        """Full-text search across hostnames, IPs, service names."""
        q = """
        OPTIONAL MATCH (h:Host)
          WHERE h.hostname CONTAINS $term
        WITH collect(h {.*, _label: 'Host'}) AS hosts
        OPTIONAL MATCH (ip:IPAddress)
          WHERE ip.address CONTAINS $term
        WITH hosts, collect(ip {.*, _label: 'IPAddress'}) AS ips
        OPTIONAL MATCH (p:Port)
          WHERE p.service CONTAINS $term OR p.product CONTAINS $term
        WITH hosts, ips, collect(p {.*, _label: 'Port'}) AS ports
        RETURN hosts + ips + ports AS results
        """
        with self._session() as session:
            rec = session.run(q, term=term).single()
            return rec["results"] if rec else []  # type: ignore[index]

    # -- credential helpers --------------------------------------------------

    def get_all_credentials(self) -> list[dict]:
        q = """
        MATCH (c:Credential)
        OPTIONAL MATCH (c)-[:FOR_HOST]->(h:Host)
        OPTIONAL MATCH (c)-[:FOR_SERVICE]->(p:Port)
        RETURN c, collect(DISTINCT h.hostname) AS hosts,
               collect(DISTINCT p.number) AS ports
        ORDER BY c.last_seen DESC
        """
        with self._session() as session:
            results = []
            for r in session.run(q):
                d = dict(r["c"])
                d["linked_hosts"] = [h for h in r["hosts"] if h]
                d["linked_ports"] = [p for p in r["ports"] if p]
                results.append(d)
            return results

    def get_credential(self, uid: str) -> dict | None:
        q = """
        MATCH (c:Credential {uid: $uid})
        OPTIONAL MATCH (c)-[:FOR_HOST]->(h:Host)
        OPTIONAL MATCH (c)-[:FOR_SERVICE]->(p:Port)<-[:HAS_PORT]-(ph:Host)
        RETURN c,
               collect(DISTINCT {uid: h.uid, hostname: h.hostname}) AS hosts,
               collect(DISTINCT {port: p.number, service: p.service,
                                 host: ph.hostname}) AS services
        """
        with self._session() as session:
            rec = session.run(q, uid=uid).single()
            if not rec:
                return None
            d = dict(rec["c"])
            d["linked_hosts"] = [h for h in rec["hosts"] if h.get("uid")]
            d["linked_services"] = [s for s in rec["services"] if s.get("port")]
            return d

    def link_credential_to_host(self, cred_uid: str, host_uid: str) -> None:
        self._rel("Credential", cred_uid, "FOR_HOST", "Host", host_uid)

    def link_credential_to_port(self, cred_uid: str, port_uid: str) -> None:
        self._rel("Credential", cred_uid, "FOR_SERVICE", "Port", port_uid)

    def set_credential_valid(self, cred_uid: str, valid: bool) -> None:
        q = """
        MATCH (c:Credential {uid: $uid})
        SET c.valid = $valid, c.last_seen = $now
        """
        with self._session() as session:
            session.run(q, uid=cred_uid, valid=valid, now=_now())

    def delete_credential(self, cred_uid: str) -> None:
        q = "MATCH (c:Credential {uid: $uid}) DETACH DELETE c"
        with self._session() as session:
            session.run(q, uid=cred_uid)

    # -- annotation helpers (notes/tags on any node) -------------------------

    def annotate(self, label: str, uid: str, notes: str | None = None,
                 tags: list[str] | None = None) -> None:
        """Add notes and/or tags to any node."""
        parts = [f"MATCH (n:{label} {{uid: $uid}})"]
        params: dict[str, Any] = {"uid": uid, "now": _now()}
        if notes is not None:
            parts.append("SET n.notes = $notes")
            params["notes"] = notes
        if tags is not None:
            parts.append("SET n.tags = $tags")
            params["tags"] = tags
        parts.append("SET n.last_seen = $now")
        q = "\n".join(parts)
        with self._session() as session:
            session.run(q, **params)

    # -- snapshot diff -------------------------------------------------------

    def diff_scans(self, scan_a_uid: str | None = None,
                   scan_b_uid: str | None = None) -> dict:
        """Compare two scans (or the two most recent) and return changes.

        Returns dict with keys: new_hosts, gone_hosts, new_ports, gone_ports,
        new_ips, gone_ips.
        """
        # If no scan UIDs given, pick the two most recent
        if not scan_a_uid or not scan_b_uid:
            q = """
            MATCH (s:ScanEvent)
            RETURN s.uid AS uid, s.timestamp AS ts, s.source_file AS src
            ORDER BY s.timestamp DESC LIMIT 2
            """
            scans = self.query(q)
            if len(scans) < 2:
                return {"error": "Need at least 2 scans to diff"}
            scan_b_uid = scans[0]["uid"]  # newer
            scan_a_uid = scans[1]["uid"]  # older

        result: dict[str, Any] = {
            "scan_old": scan_a_uid,
            "scan_new": scan_b_uid,
        }

        # Hosts in B but not in A (new)
        q_new_hosts = """
        MATCH (sb:ScanEvent {uid: $b})-[:PRODUCED]->(h:Host)
        WHERE NOT exists { (sa:ScanEvent {uid: $a})-[:PRODUCED]->(h) }
        RETURN h.uid AS uid, h.hostname AS hostname, h.status AS status
        """
        result["new_hosts"] = self.query(q_new_hosts, a=scan_a_uid, b=scan_b_uid)

        # Hosts in A but not in B (gone)
        q_gone_hosts = """
        MATCH (sa:ScanEvent {uid: $a})-[:PRODUCED]->(h:Host)
        WHERE NOT exists { (sb:ScanEvent {uid: $b})-[:PRODUCED]->(h) }
        RETURN h.uid AS uid, h.hostname AS hostname, h.status AS status
        """
        result["gone_hosts"] = self.query(q_gone_hosts, a=scan_a_uid, b=scan_b_uid)

        # Ports in B but not in A
        q_new_ports = """
        MATCH (sb:ScanEvent {uid: $b})-[:PRODUCED]->(p:Port)<-[:HAS_PORT]-(h:Host)
        WHERE NOT exists { (sa:ScanEvent {uid: $a})-[:PRODUCED]->(p) }
        RETURN h.hostname AS hostname, p.number AS port,
               p.protocol AS protocol, p.service AS service, p.state AS state
        """
        result["new_ports"] = self.query(q_new_ports, a=scan_a_uid, b=scan_b_uid)

        # Ports in A but not in B
        q_gone_ports = """
        MATCH (sa:ScanEvent {uid: $a})-[:PRODUCED]->(p:Port)<-[:HAS_PORT]-(h:Host)
        WHERE NOT exists { (sb:ScanEvent {uid: $b})-[:PRODUCED]->(p) }
        RETURN h.hostname AS hostname, p.number AS port,
               p.protocol AS protocol, p.service AS service, p.state AS state
        """
        result["gone_ports"] = self.query(q_gone_ports, a=scan_a_uid, b=scan_b_uid)

        # IPs in B but not in A
        q_new_ips = """
        MATCH (sb:ScanEvent {uid: $b})-[:PRODUCED]->(ip:IPAddress)
        WHERE NOT exists { (sa:ScanEvent {uid: $a})-[:PRODUCED]->(ip) }
        RETURN ip.address AS address
        """
        result["new_ips"] = self.query(q_new_ips, a=scan_a_uid, b=scan_b_uid)

        # IPs in A but not in B
        q_gone_ips = """
        MATCH (sa:ScanEvent {uid: $a})-[:PRODUCED]->(ip:IPAddress)
        WHERE NOT exists { (sb:ScanEvent {uid: $b})-[:PRODUCED]->(ip) }
        RETURN ip.address AS address
        """
        result["gone_ips"] = self.query(q_gone_ips, a=scan_a_uid, b=scan_b_uid)

        return result

    # -- export helpers ------------------------------------------------------

    def export_all(self) -> dict:
        """Export the full graph as a JSON-serializable dict."""
        data: dict[str, Any] = {}
        data["hosts"] = self.query(
            "MATCH (h:Host) RETURN h ORDER BY h.hostname")
        data["interfaces"] = self.query(
            "MATCH (h:Host)-[:HAS_INTERFACE]->(i:Interface) "
            "RETURN h.uid AS host_uid, h.hostname AS hostname, i")
        data["ips"] = self.query(
            "MATCH (ip:IPAddress) "
            "OPTIONAL MATCH (i:Interface)-[:HAS_IP]->(ip) "
            "OPTIONAL MATCH (h:Host)-[:HAS_IP]->(ip) "
            "RETURN ip, i.name AS interface, h.hostname AS hostname")
        data["networks"] = self.query(
            "MATCH (n:Network) RETURN n ORDER BY n.cidr")
        data["ports"] = self.query(
            "MATCH (h:Host)-[:HAS_PORT]->(p:Port) "
            "RETURN h.uid AS host_uid, h.hostname AS hostname, p "
            "ORDER BY h.hostname, p.number")
        data["credentials"] = self.query(
            "MATCH (c:Credential) "
            "OPTIONAL MATCH (c)-[:FOR_HOST]->(h:Host) "
            "RETURN c, h.hostname AS for_host")
        data["routes"] = self.query(
            "MATCH (h:Host)-[:HAS_ROUTE]->(r:Route) "
            "RETURN h.hostname AS hostname, r")
        data["scans"] = self.query(
            "MATCH (s:ScanEvent) RETURN s ORDER BY s.timestamp DESC")
        return data

    def get_scan_events(self) -> list[dict]:
        q = """
        MATCH (s:ScanEvent)
        OPTIONAL MATCH (s)-[:PRODUCED]->(n)
        WITH s, count(n) AS node_count
        RETURN s.uid AS uid, s.scan_type AS type,
               s.source_file AS source, s.timestamp AS timestamp,
               node_count
        ORDER BY s.timestamp DESC
        """
        with self._session() as session:
            return [dict(r) for r in session.run(q)]

    # -- stats ---------------------------------------------------------------

    def stats(self) -> dict[str, int]:
        q = """
        OPTIONAL MATCH (h:Host) WITH count(h) AS hosts
        OPTIONAL MATCH (ip:IPAddress) WITH hosts, count(ip) AS ips
        OPTIONAL MATCH (n:Network) WITH hosts, ips, count(n) AS networks
        OPTIONAL MATCH (p:Port) WITH hosts, ips, networks, count(p) AS ports
        OPTIONAL MATCH (c:Credential) WITH hosts, ips, networks, ports, count(c) AS creds
        OPTIONAL MATCH (s:ScanEvent) WITH hosts, ips, networks, ports, creds, count(s) AS scans
        RETURN hosts, ips, networks, ports, creds, scans
        """
        with self._session() as session:
            rec = session.run(q).single()
            return dict(rec) if rec else {}  # type: ignore[arg-type]
