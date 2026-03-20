"""Service / port analyzers."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from . import BaseAnalyzer, Finding

if TYPE_CHECKING:
    from ..db import TargetDB


# Services commonly targeted for exploitation
_HIGH_VALUE_SERVICES = {
    "ssh", "rdp", "smb", "ftp", "telnet", "vnc", "mysql", "mssql",
    "postgresql", "oracle", "redis", "mongodb", "ldap", "kerberos",
    "winrm", "snmp", "nfs", "docker", "kubernetes",
}

_HIGH_VALUE_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443,
    27017,
}


class CommonServiceAnalyzer(BaseAnalyzer):
    name = "common-services"
    description = "Summarise which services/ports appear across the environment"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (h:Host)-[:HAS_PORT]->(p:Port)
        WHERE p.state = 'open'
        WITH p.service AS svc, p.number AS port, p.protocol AS proto,
             collect(DISTINCT h.hostname) AS hosts
        RETURN svc, port, proto, hosts, size(hosts) AS count
        ORDER BY count DESC
        """
        findings: list[Finding] = []
        for row in db.query(q):
            findings.append(Finding(
                title=f"{row['svc'] or 'unknown'}:{row['port']}/{row['proto']} "
                      f"on {row['count']} host(s)",
                severity="info",
                detail=", ".join(str(h) for h in row["hosts"]),
                data=row,
            ))
        return findings


class ExposedServiceAnalyzer(BaseAnalyzer):
    name = "exposed-services"
    description = "Flag high-value / sensitive services that are open"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (h:Host)-[:HAS_PORT]->(p:Port)
        WHERE p.state = 'open'
        RETURN h.uid AS uid, h.hostname AS hostname,
               p.number AS port, p.protocol AS proto,
               p.service AS service, p.product AS product, p.version AS version
        """
        findings: list[Finding] = []
        for row in db.query(q):
            svc = (row.get("service") or "").lower()
            port = row.get("port", 0)
            if svc in _HIGH_VALUE_SERVICES or port in _HIGH_VALUE_PORTS:
                findings.append(Finding(
                    title=f"High-value service: {svc or port}/{row['proto']} "
                          f"on {row.get('hostname') or row['uid']}",
                    severity="medium",
                    detail=f"Product: {row.get('product')} {row.get('version')}",
                    data=row,
                ))
        return findings


class VersionAnalyzer(BaseAnalyzer):
    name = "versions"
    description = "List all detected software versions for vulnerability research"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (h:Host)-[:HAS_PORT]->(p:Port)
        WHERE p.product IS NOT NULL
        RETURN h.hostname AS hostname, h.uid AS uid,
               p.service AS service, p.product AS product,
               p.version AS version, p.number AS port
        ORDER BY p.product, p.version
        """
        findings: list[Finding] = []
        for row in db.query(q):
            findings.append(Finding(
                title=f"{row.get('product')} {row.get('version') or '?'} "
                      f"({row.get('service')}/{row['port']})",
                severity="info",
                detail=f"Host: {row.get('hostname') or row['uid']}",
                data=row,
            ))
        return findings
