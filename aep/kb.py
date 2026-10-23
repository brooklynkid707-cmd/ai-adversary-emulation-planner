"""Knowledge-base loader and schema validation.

The knowledge base is four committed JSON files under ``data/``:

* ``techniques.json``    - ATT&CK techniques (id, name, tactic, description,
  data sources, common log events).
* ``actor_profiles.json``- six threat-actor archetypes with technique lists.
* ``atomic_map.json``    - technique -> Atomic Red Team test identifiers (ids
  and titles only; never commands or payloads).
* ``detections.json``    - technique -> detection ideas (Sigma titles,
  Splunk/KQL pseudo-logic, owning repo).

This module loads them, exposes typed lookups, and validates the whole KB so a
malformed entry fails a test instead of a plan.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# A well-formed ATT&CK technique id: Txxxx with an optional .NNN sub-technique.
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# An Atomic Red Team test identifier as referenced here, e.g. T1059.001-2.
ATOMIC_RE = re.compile(r"^T\d{4}(\.\d{3})?-\d+$")

CANONICAL_TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]
TACTIC_INDEX = {t: i for i, t in enumerate(CANONICAL_TACTICS)}


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique as stored in the KB."""

    id: str
    name: str
    tactic: str
    description: str
    data_sources: list[str] = field(default_factory=list)
    log_events: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Profile:
    """A threat-actor archetype."""

    id: str
    name: str
    summary: str
    motivation: str
    typical_targets: list[str]
    techniques: list[str]


class KnowledgeBase:
    """In-memory view over the data/ JSON files with validation."""

    def __init__(self, data_dir: Path | str = DATA_DIR) -> None:
        self.data_dir = Path(data_dir)
        tdoc = _read_json(self.data_dir / "techniques.json")
        pdoc = _read_json(self.data_dir / "actor_profiles.json")
        adoc = _read_json(self.data_dir / "atomic_map.json")
        ddoc = _read_json(self.data_dir / "detections.json")

        self.techniques: dict[str, Technique] = {}
        for t in tdoc["techniques"]:
            self.techniques[t["id"]] = Technique(
                id=t["id"], name=t["name"], tactic=t["tactic"],
                description=t["description"],
                data_sources=list(t.get("data_sources", [])),
                log_events=list(t.get("log_events", [])),
            )

        self.profiles: dict[str, Profile] = {}
        for p in pdoc["profiles"]:
            self.profiles[p["id"]] = Profile(
                id=p["id"], name=p["name"], summary=p["summary"],
                motivation=p["motivation"],
                typical_targets=list(p["typical_targets"]),
                techniques=list(p["techniques"]),
            )

        self.atomic: dict[str, list[dict]] = dict(adoc["map"])
        self.detections: dict[str, list[dict]] = dict(ddoc["map"])

    # ------------------------------------------------------------- lookups
    def technique(self, tid: str) -> Technique | None:
        return self.techniques.get(tid)

    def profile(self, pid: str) -> Profile | None:
        return self.profiles.get(pid)

    def atomic_tests(self, tid: str) -> list[dict]:
        return self.atomic.get(tid, [])

    def detection_ideas(self, tid: str) -> list[dict]:
        return self.detections.get(tid, [])

    def tactic_rank(self, tactic: str) -> int:
        return TACTIC_INDEX.get(tactic, len(CANONICAL_TACTICS))

    # -------------------------------------------------------------- validate
    def validate(self) -> list[str]:
        """Return a list of schema problems; empty means the KB is valid."""
        errors: list[str] = []
        ids = set(self.techniques)

        for tid, t in self.techniques.items():
            if not TECHNIQUE_RE.match(tid):
                errors.append(f"technique id not well-formed: {tid!r}")
            if t.tactic not in TACTIC_INDEX:
                errors.append(f"{tid}: unknown tactic {t.tactic!r}")
            if not t.name or not t.description:
                errors.append(f"{tid}: missing name/description")
            if not t.log_events:
                errors.append(f"{tid}: no log_events listed")

        # Every atomic ref must map to a KB technique and be well-formed.
        for tid, tests in self.atomic.items():
            if tid not in ids:
                errors.append(f"atomic map references unknown technique {tid}")
            for test in tests:
                atid = test.get("test_id", "")
                if not ATOMIC_RE.match(atid):
                    errors.append(f"{tid}: malformed atomic id {atid!r}")
                if not atid.startswith(tid + "-"):
                    errors.append(f"atomic {atid!r} does not belong to {tid}")
                if not test.get("title"):
                    errors.append(f"atomic {atid!r} has no title")

        # Every detection ref must map to a KB technique.
        for tid, ideas in self.detections.items():
            if tid not in ids:
                errors.append(f"detections map references unknown technique {tid}")
            for idea in ideas:
                if idea.get("type") not in {"sigma", "splunk", "kql"}:
                    errors.append(f"{tid}: bad detection type {idea.get('type')!r}")
                if not idea.get("title") or not idea.get("logic"):
                    errors.append(f"{tid}: detection idea missing title/logic")

        # Every profile technique must exist in the KB.
        for pid, p in self.profiles.items():
            for tid in p.techniques:
                if tid not in ids:
                    errors.append(f"profile {pid} references unknown technique {tid}")
        return errors


def _read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def load_kb() -> KnowledgeBase:
    """Load and cache the default knowledge base."""
    return KnowledgeBase()
