# tgt_db — Targeting Cyber Database

A Neo4j-backed targeting database for tracking hosts, networks, IPs, credentials, services, and their relationships. Designed for network reconnaissance and situational awareness.

## Quick Start

```bash
# Start Neo4j
docker compose up -d

# Install tgt_db
pip install -e .

# Initialise schema
export TGTDB_PASSWORD=tgtdb_pass
tgtdb init

# Check it works
tgtdb stats
```

## Architecture

```
tgt_db/
├── models.py              # Dataclass models (Host, IP, Port, Credential, …)
├── db.py                  # Neo4j CRUD layer (merge/upsert semantics)
├── cli.py                 # Click CLI
├── parsers/               # Extensible ingestion parsers
│   ├── nmap_parser.py     #   nmap -oX XML
│   └── sysadmin_parser.py #   ip a, ip route, ifconfig, uname
└── analysis/              # Extensible analysis layer
    ├── network_analysis.py    # dual-homed, shared-subnet, gateways, stale
    ├── service_analysis.py    # common/exposed services, versions
    ├── credential_analysis.py # credential reuse
    └── path_analysis.py       # reachability / path finding
```

### Graph Model

```
(Host)-[:HAS_INTERFACE]->(Interface)-[:HAS_IP]->(IPAddress)-[:IN_NETWORK]->(Network)
(Host)-[:HAS_PORT]->(Port)
(Host)-[:HAS_ROUTE]->(Route)
(Credential)-[:FOR_HOST]->(Host)
(Credential)-[:FOR_SERVICE]->(Port)
(ScanEvent)-[:PRODUCED]->(*)
```

Every node carries `first_seen` / `last_seen` timestamps. Repeated scans **update** existing nodes (merge-on-natural-key) rather than creating duplicates, so the graph naturally tracks network changes over time.

## CLI Reference

### Hosts
```bash
tgtdb host add --hostname webserver1 --ip 10.0.1.5 --os "Ubuntu 22.04" --status alive
tgtdb host list
tgtdb host show <uid>
tgtdb host rm <uid>
```

### Networks
```bash
tgtdb network add --cidr 10.0.1.0/24 --name "DMZ" --vlan 100
tgtdb network list
```

### Credentials
```bash
tgtdb cred add --username admin --secret 'P@ssw0rd' --type password --host-uid <uid>
```

### Ingestion
```bash
# Nmap XML
tgtdb ingest nmap scan_results.xml

# Sysadmin logs (ip a, ip route, uname, hostname output in one file)
tgtdb ingest sysadmin server_info.txt
tgtdb ingest sysadmin server_info.txt --host-uid <uid>   # link to existing host

# List parsers
tgtdb ingest list-parsers
```

### Analysis
```bash
tgtdb analyze list                     # show available analyzers
tgtdb analyze run --all                # run everything
tgtdb analyze run dual-homed           # find pivot hosts
tgtdb analyze run exposed-services     # flag sensitive open ports
tgtdb analyze run cred-reuse           # shared credentials
tgtdb analyze run paths --from-uid X --to-uid Y   # find paths between hosts
tgtdb analyze run stale-hosts --days 14
```

### Raw Cypher
```bash
tgtdb query "MATCH (h:Host)-[:HAS_PORT]->(p:Port) WHERE p.service = 'ssh' RETURN h.hostname, p.number"
```

### Search
```bash
tgtdb search "10.0.1"
tgtdb search "ssh"
```

## Extending

### Adding a parser

1. Create `tgt_db/parsers/my_parser.py`
2. Subclass `BaseParser` and implement `parse(db, source, *, host_uid, scan_uid)`
3. Register in `tgt_db/parsers/__init__.py`:
   ```python
   from .my_parser import MyParser
   REGISTRY["my-parser"] = MyParser()
   ```

### Adding an analyzer

1. Create `tgt_db/analysis/my_analysis.py`
2. Subclass `BaseAnalyzer` and implement `run(db, **kwargs) -> list[Finding]`
3. Register in `tgt_db/analysis/__init__.py`

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TGTDB_URI` | `bolt://localhost:7687` | Neo4j Bolt URI |
| `TGTDB_USER` | `neo4j` | Neo4j username |
| `TGTDB_PASSWORD` | `neo4j` | Neo4j password |
| `TGTDB_DATABASE` | `neo4j` | Neo4j database name |
