"""
Extensible parser framework.

To add a new parser:
  1. Create a module in this package.
  2. Subclass ``BaseParser`` and implement ``parse()``.
  3. Register it in ``REGISTRY``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..db import TargetDB


class BaseParser(ABC):
    """Base class for all data-ingestion parsers."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def parse(self, db: TargetDB, source: str | Path, *,
              host_uid: str | None = None,
              scan_uid: str | None = None) -> dict:
        """Ingest *source* into *db*.

        Parameters
        ----------
        db : TargetDB
            Database handle.
        source : str | Path
            File path or raw text to parse.
        host_uid : str | None
            If this data is known to come from a specific host, pass its uid.
        scan_uid : str | None
            ScanEvent uid for provenance tracking.

        Returns
        -------
        dict
            Summary of what was ingested (counts, warnings, …).
        """
        ...


# Parser registry — import parsers here to auto-register
from .nmap_parser import NmapParser          # noqa: E402
from .sysadmin_parser import SysadminParser  # noqa: E402

REGISTRY: dict[str, BaseParser] = {
    "nmap": NmapParser(),
    "sysadmin": SysadminParser(),
}


def get_parser(name: str) -> BaseParser:
    if name not in REGISTRY:
        raise KeyError(f"Unknown parser '{name}'. Available: {list(REGISTRY)}")
    return REGISTRY[name]


def list_parsers() -> list[str]:
    return list(REGISTRY.keys())
