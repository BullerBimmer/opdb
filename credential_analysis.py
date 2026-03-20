"""Credential analyzers."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from . import BaseAnalyzer, Finding

if TYPE_CHECKING:
    from ..db import TargetDB


class CredentialReuseAnalyzer(BaseAnalyzer):
    name = "cred-reuse"
    description = "Detect credentials shared across multiple hosts/services"

    def run(self, db: "TargetDB", **kw: Any) -> list[Finding]:
        q = """
        MATCH (c:Credential)-[:FOR_HOST]->(h:Host)
        WITH c.username AS user, c.secret AS secret, c.cred_type AS ctype,
             collect(DISTINCT h.hostname) AS hosts
        WHERE size(hosts) > 1
        RETURN user, ctype, hosts, size(hosts) AS count
        ORDER BY count DESC
        """
        findings: list[Finding] = []
        for row in db.query(q):
            findings.append(Finding(
                title=f"Credential reuse: {row['user']} ({row['ctype']}) "
                      f"on {row['count']} hosts",
                severity="high",
                detail=f"Hosts: {', '.join(str(h) for h in row['hosts'])}",
                data=row,
            ))
        return findings
