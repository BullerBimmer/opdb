"""
CLI interface for tgt_db.

Usage:
    tgtdb [OPTIONS] COMMAND [ARGS]

All commands connect to Neo4j using --uri / --user / --password or
the environment variables TGTDB_URI, TGTDB_USER, TGTDB_PASSWORD.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .db import TargetDB
from .models import (
    Host, IPAddress, Network, Port, Credential, Route,
    HostStatus, CredentialType, Protocol, PortState,
)

console = Console()


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

def _db_options(f):
    """Decorate a Click command with standard DB connection options."""
    f = click.option("--uri", envvar="TGTDB_URI",
                     default="bolt://localhost:7687",
                     help="Neo4j bolt URI")(f)
    f = click.option("--user", envvar="TGTDB_USER", default="neo4j")(f)
    f = click.option("--password", envvar="TGTDB_PASSWORD", default="neo4j")(f)
    f = click.option("--database", envvar="TGTDB_DATABASE",
                     default="neo4j")(f)
    return f


def _get_db(uri: str, user: str, password: str, database: str) -> TargetDB:
    return TargetDB(uri=uri, user=user, password=password, database=database)


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="tgt-db")
def cli():
    """tgt_db — Targeting cyber database."""


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@cli.command()
@_db_options
def init(uri, user, password, database):
    """Initialise DB schema (indexes & constraints)."""
    with _get_db(uri, user, password, database) as db:
        db.ensure_indexes()
    console.print("[green]Schema initialised.[/green]")


# ---------------------------------------------------------------------------
# materialize
# ---------------------------------------------------------------------------

@cli.command()
@_db_options
def materialize(uri, user, password, database):
    """Rebuild materialized view edges for Neo4j Browser visualization.

    Creates direct ON_NETWORK, CAN_REACH, CONNECTS_VIA, and ROUTES_TO
    edges so that strategic and tactical views render with visible edges.
    Run this after any data ingestion.
    """
    with _get_db(uri, user, password, database) as db:
        counts = db.materialize_views()
    table = Table(title="Materialized View Edges")
    table.add_column("Relationship")
    table.add_column("Count", justify="right")
    for k, v in counts.items():
        table.add_row(k, str(v))
    console.print(table)
    console.print("\n[dim]Neo4j Browser queries:[/dim]")
    console.print("  [bold]Strategic:[/bold]  MATCH (h:Host)-[r:ON_NETWORK|CAN_REACH]-(x) RETURN h, r, x")
    console.print("  [bold]Tactical:[/bold]   MATCH (h:Host)-[r:CONNECTS_VIA|ROUTES_TO]-(n:Network) RETURN h, r, n")
    console.print("  [bold]Technical:[/bold]  MATCH (n)-[r]->(m) RETURN n, r, m")


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

@cli.command()
@_db_options
def stats(uri, user, password, database):
    """Show database statistics."""
    with _get_db(uri, user, password, database) as db:
        s = db.stats()
    table = Table(title="Database Statistics")
    table.add_column("Entity")
    table.add_column("Count", justify="right")
    for k, v in s.items():
        table.add_row(k.capitalize(), str(v))
    console.print(table)


# ---------------------------------------------------------------------------
# host commands
# ---------------------------------------------------------------------------

@cli.group()
def host():
    """Manage hosts."""


@host.command("list")
@_db_options
def host_list(uri, user, password, database):
    """List all hosts."""
    with _get_db(uri, user, password, database) as db:
        hosts = db.get_all_hosts()
    table = Table(title="Hosts")
    table.add_column("UID", style="dim", max_width=12)
    table.add_column("Hostname")
    table.add_column("OS")
    table.add_column("Status")
    table.add_column("Last Seen")
    for h in hosts:
        table.add_row(
            h.get("uid", "")[:12],
            h.get("hostname", "—"),
            h.get("os", "—"),
            h.get("status", "?"),
            h.get("last_seen", "?"),
        )
    console.print(table)


@host.command("show")
@click.argument("uid")
@_db_options
def host_show(uid, uri, user, password, database):
    """Show detailed info for a host."""
    with _get_db(uri, user, password, database) as db:
        detail = db.get_host_detail(uid)
    if not detail:
        console.print(f"[red]Host {uid} not found.[/red]")
        return
    console.print(Panel(json.dumps(detail, indent=2, default=str),
                        title=f"Host {uid}"))


@host.command("add")
@click.option("--hostname", required=True)
@click.option("--os", "os_name", default=None)
@click.option("--ip", "ip_addr", default=None, help="Primary IP address")
@click.option("--status", type=click.Choice(["alive", "down", "unknown"]),
              default="unknown")
@click.option("--tags", default="", help="Comma-separated tags")
@click.option("--notes", default=None)
@_db_options
def host_add(hostname, os_name, ip_addr, status, tags, notes,
             uri, user, password, database):
    """Manually add a host."""
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    h = Host(hostname=hostname, os=os_name,
             status=HostStatus(status), tags=tag_list, notes=notes)
    with _get_db(uri, user, password, database) as db:
        uid = db.merge_host(h)
        if ip_addr:
            ip = IPAddress(address=ip_addr)
            db.merge_ip(ip, host_uid=uid)
    console.print(f"[green]Host added:[/green] {uid}")


@host.command("rm")
@click.argument("uid")
@click.confirmation_option(prompt="Delete host and all related data?")
@_db_options
def host_rm(uid, uri, user, password, database):
    """Delete a host."""
    with _get_db(uri, user, password, database) as db:
        db.delete_host(uid)
    console.print(f"[yellow]Host {uid} deleted.[/yellow]")


# ---------------------------------------------------------------------------
# network commands
# ---------------------------------------------------------------------------

@cli.group()
def network():
    """Manage networks."""


@network.command("list")
@_db_options
def network_list(uri, user, password, database):
    """List all networks."""
    with _get_db(uri, user, password, database) as db:
        nets = db.get_all_networks()
    table = Table(title="Networks")
    table.add_column("UID", style="dim", max_width=12)
    table.add_column("CIDR")
    table.add_column("Name")
    table.add_column("VLAN")
    table.add_column("Last Seen")
    for n in nets:
        table.add_row(
            n.get("uid", "")[:12],
            n.get("cidr", "?"),
            n.get("name", "—"),
            str(n.get("vlan", "—")),
            n.get("last_seen", "?"),
        )
    console.print(table)


@network.command("add")
@click.option("--cidr", required=True, help="e.g. 10.0.0.0/24")
@click.option("--name", default=None)
@click.option("--vlan", type=int, default=None)
@click.option("--description", default=None)
@_db_options
def network_add(cidr, name, vlan, description, uri, user, password, database):
    """Manually add a network."""
    net = Network(cidr=cidr, name=name, vlan=vlan, description=description)
    with _get_db(uri, user, password, database) as db:
        uid = db.merge_network(net)
    console.print(f"[green]Network added:[/green] {uid}")


# ---------------------------------------------------------------------------
# credential commands
# ---------------------------------------------------------------------------

@cli.group()
def cred():
    """Manage credentials."""


@cred.command("list")
@_db_options
def cred_list(uri, user, password, database):
    """List all credentials."""
    with _get_db(uri, user, password, database) as db:
        creds = db.get_all_credentials()
    table = Table(title="Credentials")
    table.add_column("UID", style="dim", max_width=12)
    table.add_column("Username")
    table.add_column("Type")
    table.add_column("Domain")
    table.add_column("Valid")
    table.add_column("Hosts")
    table.add_column("Source")
    for c in creds:
        table.add_row(
            c.get("uid", "")[:12],
            c.get("username", "—"),
            c.get("cred_type", "?"),
            c.get("domain", "—"),
            str(c.get("valid", "?")),
            ", ".join(str(h) for h in c.get("linked_hosts", [])) or "—",
            c.get("source", "—"),
        )
    console.print(table)


@cred.command("show")
@click.argument("uid")
@_db_options
def cred_show(uid, uri, user, password, database):
    """Show credential details."""
    with _get_db(uri, user, password, database) as db:
        detail = db.get_credential(uid)
    if not detail:
        console.print(f"[red]Credential {uid} not found.[/red]")
        return
    console.print(Panel(json.dumps(detail, indent=2, default=str),
                        title=f"Credential {uid}"))


@cred.command("link")
@click.argument("cred_uid")
@click.option("--host-uid", default=None, help="Link to a host")
@click.option("--port-uid", default=None, help="Link to a port/service")
@_db_options
def cred_link(cred_uid, host_uid, port_uid, uri, user, password, database):
    """Link a credential to a host or port."""
    with _get_db(uri, user, password, database) as db:
        if host_uid:
            db.link_credential_to_host(cred_uid, host_uid)
            console.print(f"[green]Linked cred {cred_uid[:12]} → host {host_uid[:12]}[/green]")
        if port_uid:
            db.link_credential_to_port(cred_uid, port_uid)
            console.print(f"[green]Linked cred {cred_uid[:12]} → port {port_uid[:12]}[/green]")
    if not host_uid and not port_uid:
        console.print("[yellow]Specify --host-uid or --port-uid[/yellow]")


@cred.command("validate")
@click.argument("uid")
@click.option("--valid/--invalid", default=True)
@_db_options
def cred_validate(uid, valid, uri, user, password, database):
    """Mark a credential as valid or invalid."""
    with _get_db(uri, user, password, database) as db:
        db.set_credential_valid(uid, valid)
    status = "valid" if valid else "invalid"
    console.print(f"[green]Credential {uid[:12]} marked {status}.[/green]")


@cred.command("rm")
@click.argument("uid")
@click.confirmation_option(prompt="Delete this credential?")
@_db_options
def cred_rm(uid, uri, user, password, database):
    """Delete a credential."""
    with _get_db(uri, user, password, database) as db:
        db.delete_credential(uid)
    console.print(f"[yellow]Credential {uid[:12]} deleted.[/yellow]")


@cred.command("add")
@click.option("--username", required=True)
@click.option("--secret", required=True)
@click.option("--type", "cred_type",
              type=click.Choice(["password", "hash", "key", "token", "certificate"]),
              default="password")
@click.option("--domain", default=None)
@click.option("--host-uid", default=None, help="Associate with a host")
@click.option("--source", default=None, help="How it was obtained")
@_db_options
def cred_add(username, secret, cred_type, domain, host_uid, source,
             uri, user, password, database):
    """Add a credential."""
    c = Credential(username=username, secret=secret,
                   cred_type=CredentialType(cred_type),
                   domain=domain, source=source)
    with _get_db(uri, user, password, database) as db:
        uid = db.merge_credential(c, host_uid=host_uid)
    console.print(f"[green]Credential added:[/green] {uid}")


# ---------------------------------------------------------------------------
# ingest (parsers)
# ---------------------------------------------------------------------------

@cli.group()
def ingest():
    """Ingest data from scans and logs."""


@ingest.command("nmap")
@click.argument("xml_file", type=click.Path(exists=True))
@_db_options
def ingest_nmap(xml_file, uri, user, password, database):
    """Import an nmap XML scan."""
    from .parsers import get_parser
    parser = get_parser("nmap")
    with _get_db(uri, user, password, database) as db:
        result = parser.parse(db, xml_file)
    console.print(f"[green]Nmap import done.[/green] "
                  f"Hosts: {result.get('hosts', 0)}, "
                  f"Ports: {result.get('ports', 0)}")


@ingest.command("sysadmin")
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--host-uid", default=None,
              help="Associate with existing host UID")
@_db_options
def ingest_sysadmin(log_file, host_uid, uri, user, password, database):
    """Import sysadmin command output (ip a, ip route, etc.)."""
    from .parsers import get_parser
    parser = get_parser("sysadmin")
    with _get_db(uri, user, password, database) as db:
        result = parser.parse(db, log_file, host_uid=host_uid)
    console.print(f"[green]Sysadmin import done.[/green] "
                  f"Interfaces: {result.get('interfaces', 0)}, "
                  f"IPs: {result.get('ips', 0)}, "
                  f"Routes: {result.get('routes', 0)}")


@ingest.command("list-parsers")
def ingest_list_parsers():
    """List available parsers."""
    from .parsers import REGISTRY
    table = Table(title="Available Parsers")
    table.add_column("Name")
    table.add_column("Description")
    for name, p in REGISTRY.items():
        table.add_row(name, p.description)
    console.print(table)


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

@cli.group()
def analyze():
    """Run analysis on the database."""


@analyze.command("run")
@click.argument("analyzer_name", required=False)
@click.option("--all", "run_all_flag", is_flag=True,
              help="Run all analyzers")
@click.option("--from-uid", default=None, help="Source host UID (for paths)")
@click.option("--to-uid", default=None, help="Target host UID (for paths)")
@click.option("--days", type=int, default=7, help="Stale threshold in days")
@_db_options
def analyze_run(analyzer_name, run_all_flag, from_uid, to_uid, days,
                uri, user, password, database):
    """Run an analyzer (or --all)."""
    from .analysis import get_analyzer, run_all, list_analyzers

    kwargs = {}
    if from_uid:
        kwargs["from_uid"] = from_uid
    if to_uid:
        kwargs["to_uid"] = to_uid
    kwargs["days"] = days

    with _get_db(uri, user, password, database) as db:
        if run_all_flag:
            all_results = run_all(db, **kwargs)
            for name, findings in all_results.items():
                _print_findings(name, findings)
        elif analyzer_name:
            a = get_analyzer(analyzer_name)
            findings = a.run(db, **kwargs)
            _print_findings(analyzer_name, findings)
        else:
            console.print("[yellow]Specify an analyzer name or --all[/yellow]")
            console.print("Available:")
            for name, desc in list_analyzers():
                console.print(f"  {name:20s} {desc}")


@analyze.command("list")
def analyze_list():
    """List available analyzers."""
    from .analysis import list_analyzers
    table = Table(title="Available Analyzers")
    table.add_column("Name")
    table.add_column("Description")
    for name, desc in list_analyzers():
        table.add_row(name, desc)
    console.print(table)


def _print_findings(name: str, findings: list) -> None:
    """Pretty-print findings from an analyzer."""
    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    if not findings:
        console.print(f"  [{name}] No findings.")
        return

    console.print(f"\n[bold]═══ {name} ═══[/bold]")
    for f in findings:
        color = severity_colors.get(f.severity, "white")
        console.print(f"  [{color}][{f.severity.upper()}][/{color}] {f.title}")
        if f.detail:
            console.print(f"         {f.detail}")


# ---------------------------------------------------------------------------
# view (layered views)
# ---------------------------------------------------------------------------

@cli.group()
def view():
    """Browse the graph at different abstraction levels."""


@view.command("overview")
@click.option("--level", "-l",
              type=click.Choice(["strategic", "tactical", "technical"]),
              default="tactical", help="Zoom level")
@_db_options
def view_overview(level, uri, user, password, database):
    """Show all hosts at the chosen zoom level."""
    from .views import GraphView, ViewLevel
    with _get_db(uri, user, password, database) as db:
        gv = GraphView(db, ViewLevel(level))
        rows = gv.overview()

    if level == "strategic":
        table = Table(title="Strategic Overview — Host ↔ Network")
        table.add_column("Hostname")
        table.add_column("Status")
        table.add_column("Networks")
        for r in rows:
            nets = r.get("networks") or []
            net_str = ", ".join(n.get("cidr", "?") for n in nets) if nets else "—"
            table.add_row(r.get("hostname", "?"), r.get("status", "?"), net_str)
        console.print(table)
    else:
        table = Table(title="Tactical Overview — Host · Interface · Services")
        table.add_column("Hostname")
        table.add_column("Status")
        table.add_column("Network")
        table.add_column("Interfaces")
        table.add_column("Services")
        for r in rows:
            ifaces = r.get("ifaces") or []
            iface_str = ", ".join(
                f"{i.get('iface') or '?'}={i.get('ip') or '?'}"
                for i in ifaces if i.get("ip")
            ) or "—"
            svcs = r.get("services") or []
            svc_str = ", ".join(str(s) for s in svcs) or "—"
            table.add_row(
                r.get("hostname", "?"), r.get("status", "?"),
                r.get("network", "?"), iface_str, svc_str,
            )
        console.print(table)


@view.command("connectivity")
@_db_options
def view_connectivity(uri, user, password, database):
    """Show host-to-host connectivity (strategic)."""
    from .views import GraphView, ViewLevel
    with _get_db(uri, user, password, database) as db:
        gv = GraphView(db, ViewLevel.STRATEGIC)
        rows = gv.connectivity()

    table = Table(title="Host Connectivity")
    table.add_column("Host A")
    table.add_column("Host B")
    table.add_column("Shared Networks")
    for r in rows:
        table.add_row(
            r.get("host_a", "?"), r.get("host_b", "?"),
            ", ".join(r.get("shared_nets", [])),
        )
    console.print(table)


@view.command("host")
@click.argument("uid")
@click.option("--level", "-l",
              type=click.Choice(["strategic", "tactical", "technical"]),
              default="tactical")
@_db_options
def view_host(uid, level, uri, user, password, database):
    """Drill into a single host at the chosen zoom level."""
    from .views import GraphView, ViewLevel
    with _get_db(uri, user, password, database) as db:
        gv = GraphView(db, ViewLevel(level))
        data = gv.host(uid)
    if not data:
        console.print(f"[red]Host {uid} not found.[/red]")
        return
    console.print(Panel(
        json.dumps(data, indent=2, default=str),
        title=f"Host [{level}] {uid}",
    ))


@view.command("network")
@click.argument("cidr")
@click.option("--level", "-l",
              type=click.Choice(["strategic", "tactical", "technical"]),
              default="tactical")
@_db_options
def view_network(cidr, level, uri, user, password, database):
    """Drill into a network/subnet at the chosen zoom level."""
    from .views import GraphView, ViewLevel
    with _get_db(uri, user, password, database) as db:
        gv = GraphView(db, ViewLevel(level))
        data = gv.network(cidr)
    if not data:
        console.print(f"[red]Network {cidr} not found.[/red]")
        return
    console.print(Panel(
        json.dumps(data, indent=2, default=str),
        title=f"Network [{level}] {cidr}",
    ))


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("term")
@_db_options
def search(term, uri, user, password, database):
    """Search hosts, IPs, and services."""
    with _get_db(uri, user, password, database) as db:
        results = db.search(term)
    if not results:
        console.print("[yellow]No results.[/yellow]")
        return
    for r in results:
        label = r.pop("_label", "?")
        console.print(f"  [{label}] {r}")


# ---------------------------------------------------------------------------
# query (raw Cypher)
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("cypher")
@_db_options
def query(cypher, uri, user, password, database):
    """Run raw Cypher and print results as JSON."""
    with _get_db(uri, user, password, database) as db:
        rows = db.query(cypher)
    console.print_json(json.dumps(rows, indent=2, default=str))


# ---------------------------------------------------------------------------
# diff (compare scan snapshots)
# ---------------------------------------------------------------------------

@cli.command("diff")
@click.option("--scan-a", default=None, help="Older scan UID (default: 2nd most recent)")
@click.option("--scan-b", default=None, help="Newer scan UID (default: most recent)")
@_db_options
def diff_scans(scan_a, scan_b, uri, user, password, database):
    """Compare two scans and show what changed.

    Without arguments, compares the two most recent scans.
    """
    with _get_db(uri, user, password, database) as db:
        result = db.diff_scans(scan_a, scan_b)

    if "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        return

    console.print(f"\n[bold]Diff: {result['scan_old'][:12]} → {result['scan_new'][:12]}[/bold]\n")

    sections = [
        ("New Hosts", "new_hosts", "green"),
        ("Gone Hosts", "gone_hosts", "red"),
        ("New Ports", "new_ports", "green"),
        ("Gone Ports", "gone_ports", "red"),
        ("New IPs", "new_ips", "green"),
        ("Gone IPs", "gone_ips", "red"),
    ]
    for title, key, color in sections:
        items = result.get(key, [])
        if items:
            console.print(f"  [{color}]{title} ({len(items)}):[/{color}]")
            for item in items:
                # format depends on what's in the dict
                if "hostname" in item and "port" in item:
                    console.print(f"    {item.get('hostname','?')}  "
                                  f"{item['port']}/{item.get('protocol','?')}  "
                                  f"{item.get('service','')}")
                elif "hostname" in item:
                    console.print(f"    {item.get('hostname') or item.get('uid','?')}  "
                                  f"({item.get('status','')})")
                elif "address" in item:
                    console.print(f"    {item['address']}")
                else:
                    console.print(f"    {item}")
        else:
            console.print(f"  [dim]{title}: none[/dim]")


# ---------------------------------------------------------------------------
# scan (list scan events)
# ---------------------------------------------------------------------------

@cli.command("scans")
@_db_options
def scan_list(uri, user, password, database):
    """List all scan events."""
    with _get_db(uri, user, password, database) as db:
        scans = db.get_scan_events()
    table = Table(title="Scan Events")
    table.add_column("UID", style="dim", max_width=12)
    table.add_column("Type")
    table.add_column("Source")
    table.add_column("Timestamp")
    table.add_column("Nodes", justify="right")
    for s in scans:
        table.add_row(
            str(s.get("uid", ""))[:12],
            s.get("type", "?"),
            str(s.get("source", "—")),
            str(s.get("timestamp", "?")),
            str(s.get("node_count", 0)),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# annotate (notes/tags on any node)
# ---------------------------------------------------------------------------

@cli.command("annotate")
@click.argument("uid")
@click.option("--label", "-l", required=True,
              type=click.Choice(["Host", "Network", "Port", "Credential",
                                 "Interface", "IPAddress"]),
              help="Node type")
@click.option("--notes", "-n", default=None, help="Free-text notes")
@click.option("--tags", "-t", default=None, help="Comma-separated tags")
@_db_options
def annotate(uid, label, notes, tags, uri, user, password, database):
    """Add notes or tags to any node."""
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    with _get_db(uri, user, password, database) as db:
        db.annotate(label, uid, notes=notes, tags=tag_list)
    console.print(f"[green]Annotated {label} {uid[:12]}.[/green]")


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

@cli.command("export")
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]),
              default="json")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file (default: stdout)")
@_db_options
def export_data(fmt, output, uri, user, password, database):
    """Export the full database."""
    with _get_db(uri, user, password, database) as db:
        data = db.export_all()

    if fmt == "json":
        import json as _json
        text = _json.dumps(data, indent=2, default=str)
        if output:
            Path(output).write_text(text)
            console.print(f"[green]Exported to {output}[/green]")
        else:
            console.print_json(text)
    elif fmt == "csv":
        import csv
        import io
        buf = io.StringIO() if not output else open(output, "w", newline="")
        try:
            for section, rows in data.items():
                if not rows:
                    continue
                # Flatten neo4j node dicts
                flat_rows = []
                for row in rows:
                    flat: dict = {}
                    for k, v in row.items():
                        if isinstance(v, dict):
                            for ik, iv in v.items():
                                flat[f"{k}.{ik}"] = iv
                        else:
                            flat[k] = v
                    flat_rows.append(flat)
                if flat_rows:
                    writer = csv.DictWriter(buf,
                                            fieldnames=list(flat_rows[0].keys()))
                    buf.write(f"# {section}\n")
                    writer.writeheader()
                    writer.writerows(flat_rows)
                    buf.write("\n")
            if output:
                console.print(f"[green]Exported to {output}[/green]")
            else:
                console.print(buf.getvalue())
        finally:
            if output:
                buf.close()


if __name__ == "__main__":
    cli()
