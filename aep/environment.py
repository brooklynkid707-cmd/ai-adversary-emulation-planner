"""Target-environment model loaded from an env/*.yaml file.

An environment file describes the authorized test environment: the OS mix, the
telemetry/data sources that are actually collected, the SIEM/EDR in use, and
scheduling constraints (blackout windows, change-freeze). The planner uses it
to tailor expected telemetry and to flag detection blind spots where a
technique's data source is not collected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Environment:
    """Authorized test environment constraints."""

    name: str
    os_mix: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    siem: str = "unspecified"
    edr: str = "unspecified"
    blackout_windows: list[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_file(cls, path: Path | str) -> "Environment":
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(
            name=doc.get("name", "unnamed environment"),
            os_mix=list(doc.get("os_mix", [])),
            data_sources=list(doc.get("data_sources", [])),
            siem=doc.get("siem", "unspecified"),
            edr=doc.get("edr", "unspecified"),
            blackout_windows=list(doc.get("blackout_windows", [])),
            notes=doc.get("notes", ""),
        )

    def covers_data_source(self, data_source: str) -> bool:
        """True if the environment collects telemetry for this ATT&CK data source."""
        ds = data_source.lower()
        for have in self.data_sources:
            h = have.lower()
            if h in ds or ds in h:
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "os_mix": self.os_mix,
            "data_sources": self.data_sources,
            "siem": self.siem,
            "edr": self.edr,
            "blackout_windows": self.blackout_windows,
            "notes": self.notes,
        }
