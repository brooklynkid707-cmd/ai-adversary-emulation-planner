"""Coverage / gap analysis of a plan against deployed detections.

Input: a plan (from :mod:`aep.planner`) and a CSV of deployed SIEM rules that
carry ATT&CK technique ids (the owner's Sentinel/Splunk coverage docs are the
model). Output: per-technique coverage status (covered / partial / gap), a
summary, and an ATT&CK Navigator 4.5 layer JSON scored by coverage so the gaps
are visible on the matrix.

Partial coverage means the plan exercises a sub-technique (``T1059.001``) while
the only deployed rule is for the parent (``T1059``) or a sibling - the SOC
sees *something* but not exactly this behaviour.
"""

from __future__ import annotations

import csv
from pathlib import Path

COLORS = {
    "covered": "#2e7d32",   # green
    "partial": "#f9a825",   # amber
    "gap": "#c62828",       # red
}
SCORES = {"covered": 100, "partial": 50, "gap": 0}


def _parent(tid: str) -> str:
    return tid.split(".", 1)[0]


def load_deployed_rules(csv_path: Path | str) -> list[dict]:
    """Read the deployed-rules CSV.

    Recognised columns (case-insensitive): ``technique`` / ``technique_id`` /
    ``attack_technique``, ``rule`` / ``rule_name`` / ``name``, ``siem`` /
    ``platform``, ``status``. A single rule may list several techniques
    separated by ``;`` / ``,`` / whitespace.
    """
    rows: list[dict] = []
    with Path(csv_path).open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        norm = {k: (k or "").strip().lower() for k in (reader.fieldnames or [])}
        for raw in reader:
            row = {norm.get(k, k): v for k, v in raw.items()}
            tech_field = (row.get("technique") or row.get("technique_id")
                          or row.get("attack_technique") or "")
            techniques = [t.strip().upper() for t in
                          tech_field.replace(";", ",").replace(" ", ",").split(",")
                          if t.strip()]
            rows.append({
                "rule": (row.get("rule") or row.get("rule_name")
                         or row.get("name") or "").strip(),
                "siem": (row.get("siem") or row.get("platform") or "").strip(),
                "status": (row.get("status") or "enabled").strip(),
                "techniques": techniques,
            })
    return rows


def analyze(plan: dict, deployed_rules: list[dict]) -> dict:
    """Compare plan techniques against deployed rules -> gap analysis."""
    enabled = [r for r in deployed_rules
               if r["status"].lower() not in {"disabled", "off", "draft"}]
    deployed_ids: set[str] = set()
    for r in enabled:
        deployed_ids.update(r["techniques"])
    deployed_parents = {_parent(t) for t in deployed_ids}

    # Map technique -> rules that reference it (exact or via parent).
    rules_for: dict[str, list[str]] = {}
    for r in enabled:
        for t in r["techniques"]:
            rules_for.setdefault(t, []).append(r["rule"])
            rules_for.setdefault(_parent(t), []).append(r["rule"])

    results: list[dict] = []
    for tid in plan["technique_ids"]:
        if tid in deployed_ids:
            status = "covered"
        elif _parent(tid) in deployed_parents or tid in deployed_parents:
            status = "partial"
        else:
            status = "gap"
        results.append({
            "technique_id": tid,
            "status": status,
            "deployed_rules": sorted(set(rules_for.get(tid, [])
                                         or rules_for.get(_parent(tid), []))),
        })

    counts = {"covered": 0, "partial": 0, "gap": 0}
    for r in results:
        counts[r["status"]] += 1
    total = len(results) or 1
    # Weighted coverage: partial counts as half.
    pct = round(100 * (counts["covered"] + 0.5 * counts["partial"]) / total, 1)

    return {
        "schema": "aep-coverage/1.0",
        "exercise_name": plan.get("exercise_name"),
        "plan_technique_count": len(results),
        "deployed_rule_count": len(enabled),
        "deployed_technique_count": len(deployed_ids),
        "counts": counts,
        "coverage_pct": pct,
        "results": results,
        "gaps": [r["technique_id"] for r in results if r["status"] == "gap"],
    }


def navigator_layer(plan: dict, coverage: dict,
                    name: str | None = None) -> dict:
    """Build an ATT&CK Navigator 4.5 layer scored by coverage status."""
    status_by_id = {r["technique_id"]: r["status"] for r in coverage["results"]}
    techniques = []
    for tid, status in status_by_id.items():
        techniques.append({
            "techniqueID": tid,
            "score": SCORES[status],
            "color": COLORS[status],
            "comment": f"{status}; rules: "
                       + (", ".join(
                           next(r["deployed_rules"] for r in coverage["results"]
                                if r["technique_id"] == tid)) or "none"),
            "enabled": True,
            "metadata": [{"name": "status", "value": status}],
        })
    return {
        "name": name or f"AEP coverage - {plan.get('exercise_name', 'plan')}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Planned emulation techniques scored by existing detection coverage: "
            "green=covered, amber=partial (parent/sibling only), red=gap."),
        "sorting": 0,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#c62828", "#f9a825", "#2e7d32"],
                     "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "covered", "color": COLORS["covered"]},
            {"label": "partial", "color": COLORS["partial"]},
            {"label": "gap", "color": COLORS["gap"]},
        ],
        "metadata": [
            {"name": "coverage_pct", "value": str(coverage["coverage_pct"])},
            {"name": "gaps", "value": str(coverage["counts"]["gap"])},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
    }
