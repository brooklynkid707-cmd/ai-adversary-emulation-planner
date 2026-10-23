"""Produce a phased, detection-focused emulation plan.

Given a threat-actor profile (or an explicit technique list) and an
:class:`~aep.environment.Environment`, the planner groups the selected
techniques into ATT&CK-ordered phases and, for each technique, emits a
planning record: objective, Atomic Red Team test identifiers, prerequisites,
expected telemetry, a detection checklist, success criteria, rollback/cleanup
notes and a risk rating.

The output is **planning and detection only**. It names Atomic test IDs and
describes what telemetry a defender should see; it never contains commands,
payloads or operational attack instructions.
"""

from __future__ import annotations

import datetime as _dt
from typing import Iterable

from .environment import Environment
from .kb import CANONICAL_TACTICS, KnowledgeBase, Technique

# Phase sequence requested for the plan, in kill-chain order. Discovery,
# command-and-control, reconnaissance and resource-development are included so
# that whole-lifecycle profiles are represented; empty phases are dropped.
PHASE_ORDER = list(CANONICAL_TACTICS)

# Base risk per tactic for an *authorized* test. Impact/credential/defense
# actions carry the most operational risk and need the most care.
_RISK_BY_TACTIC = {
    "reconnaissance": "low",
    "resource-development": "low",
    "initial-access": "medium",
    "execution": "medium",
    "persistence": "medium",
    "privilege-escalation": "high",
    "defense-evasion": "high",
    "credential-access": "high",
    "discovery": "low",
    "lateral-movement": "high",
    "collection": "medium",
    "command-and-control": "medium",
    "exfiltration": "high",
    "impact": "high",
}


def _risk_rating(technique: Technique, observable: bool) -> str:
    base = _RISK_BY_TACTIC.get(technique.tactic, "medium")
    # A blind spot (no telemetry) raises risk: the action happens unseen.
    if not observable and base == "medium":
        return "high"
    return base


def _rollback_note(technique: Technique) -> str:
    """Generic, non-operational cleanup guidance keyed to the tactic."""
    notes = {
        "persistence": "Remove the created account/task/service/registry value; "
                       "confirm no autostart remains.",
        "privilege-escalation": "Revert any token/UAC/GPO change; reboot the test "
                                 "host if elevation artifacts persist.",
        "defense-evasion": "Re-enable any disabled logging/security tooling and "
                           "restore audit policy; re-ingest cleared logs from backup.",
        "credential-access": "Rotate any test credentials touched; purge dumped "
                             "artifacts from disk.",
        "lateral-movement": "Close remote sessions; remove any transferred tooling "
                            "from destination hosts.",
        "collection": "Delete staged/archived data from the test host.",
        "exfiltration": "Delete uploaded test data from the external sink; confirm "
                        "no real data left the environment.",
        "impact": "Restore from the pre-test snapshot; verify encrypted/stopped "
                 "resources are recovered before resuming operations.",
        "command-and-control": "Tear down the test C2 listener; remove downloaded "
                              "tooling.",
    }
    return notes.get(technique.tactic,
                     "Remove any artifacts created by the test; confirm the host "
                     "is back to its pre-test state.")


def _detection_checklist(kb: KnowledgeBase, technique: Technique,
                         env: Environment) -> list[dict]:
    """Per-technique detection checklist, annotated with coverage status."""
    items: list[dict] = []
    for idea in kb.detection_ideas(technique.id):
        items.append({
            "type": idea["type"],
            "title": idea["title"],
            "logic": idea["logic"],
            "source_repo": idea.get("repo"),
            "status": "planned",
        })
    if not items:
        # No pre-built detection in the KB: flag it as a coverage gap to build.
        items.append({
            "type": "gap",
            "title": f"No prebuilt detection for {technique.id} - author one",
            "logic": f"Build a rule over {', '.join(technique.log_events)}",
            "source_repo": None,
            "status": "to-build",
        })
    return items


def _expected_telemetry(technique: Technique, env: Environment) -> dict:
    observed = [ds for ds in technique.data_sources if env.covers_data_source(ds)]
    blind = [ds for ds in technique.data_sources if not env.covers_data_source(ds)]
    return {
        "log_events": technique.log_events,
        "data_sources": technique.data_sources,
        "collected_here": observed,
        "blind_spots": blind,
        "observable": bool(observed) or not technique.data_sources,
    }


def _plan_technique(kb: KnowledgeBase, technique: Technique,
                    env: Environment) -> dict:
    telemetry = _expected_telemetry(technique, env)
    atomics = kb.atomic_tests(technique.id)
    checklist = _detection_checklist(kb, technique, env)
    return {
        "technique_id": technique.id,
        "technique_name": technique.name,
        "tactic": technique.tactic,
        "objective": f"Emulate {technique.name} ({technique.id}) and confirm the "
                     f"SOC can detect it.",
        "atomic_test_ids": [a["test_id"] for a in atomics],
        "atomic_tests": atomics,
        "prerequisites": _prerequisites(technique, env),
        "expected_telemetry": telemetry,
        "detection_checklist": checklist,
        "success_criteria": [
            f"Atomic test(s) {', '.join(a['test_id'] for a in atomics) or '(manual)'} "
            f"execute in the lab without error.",
            "Expected telemetry is present in "
            f"{env.siem} within the agreed detection window.",
            ("At least one detection in the checklist fires an alert."
             if any(i["status"] == "planned" for i in checklist)
             else "Coverage gap confirmed: no alert fires (finding to remediate)."),
        ],
        "rollback": _rollback_note(technique),
        "risk_rating": _risk_rating(technique, telemetry["observable"]),
    }


def _prerequisites(technique: Technique, env: Environment) -> list[str]:
    reqs = ["Written authorization for this host/technique is on file (see ROE)."]
    if technique.tactic in {"impact", "credential-access", "defense-evasion"}:
        reqs.append("A clean pre-test snapshot/backup of the target host exists.")
    if technique.tactic in {"lateral-movement", "initial-access"}:
        reqs.append("A designated non-production target host is available.")
    reqs.append(f"Telemetry for {', '.join(technique.data_sources) or 'this technique'} "
                "is being collected (or the gap is accepted and noted).")
    return reqs


def select_techniques(kb: KnowledgeBase, *, profile_id: str | None = None,
                      technique_ids: Iterable[str] | None = None) -> list[str]:
    """Resolve the technique list from a profile id and/or explicit ids."""
    selected: list[str] = []
    if profile_id:
        profile = kb.profile(profile_id)
        if profile is None:
            raise ValueError(f"unknown profile: {profile_id!r} "
                             f"(have {sorted(kb.profiles)})")
        selected.extend(profile.techniques)
    if technique_ids:
        selected.extend(technique_ids)
    if not selected:
        raise ValueError("no techniques selected: pass a profile or technique ids")
    # De-duplicate, keep order, and drop anything not in the KB.
    seen: set[str] = set()
    out: list[str] = []
    for tid in selected:
        if tid in seen:
            continue
        seen.add(tid)
        if kb.technique(tid) is not None:
            out.append(tid)
    return out


def build_plan(kb: KnowledgeBase, env: Environment, *,
               profile_id: str | None = None,
               technique_ids: Iterable[str] | None = None,
               exercise_name: str | None = None) -> dict:
    """Build the full phased emulation plan as a serialisable dict."""
    tids = select_techniques(kb, profile_id=profile_id, technique_ids=technique_ids)

    by_phase: dict[str, list[dict]] = {p: [] for p in PHASE_ORDER}
    for tid in tids:
        technique = kb.technique(tid)
        assert technique is not None
        by_phase[technique.tactic].append(_plan_technique(kb, technique, env))

    phases = []
    for phase in PHASE_ORDER:
        entries = by_phase[phase]
        if not entries:
            continue
        phases.append({
            "phase": phase,
            "phase_rank": kb.tactic_rank(phase),
            "techniques": entries,
        })

    profile = kb.profile(profile_id) if profile_id else None
    name = exercise_name or (
        f"Purple-team emulation - {profile.name}" if profile
        else "Purple-team emulation - custom technique set")

    return {
        "schema": "aep-plan/1.0",
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exercise_name": name,
        "profile": profile_id,
        "profile_name": profile.name if profile else None,
        "environment": env.to_dict(),
        "technique_count": len(tids),
        "technique_ids": tids,
        "phase_count": len(phases),
        "phases": phases,
        "disclaimer": (
            "Planning and detection only. This plan references public Atomic Red "
            "Team test identifiers and expected telemetry; it contains no exploit "
            "code, payloads or operational attack instructions. Authorized testing "
            "of the owner's own systems only - see SCOPE.md and the ROE."),
    }


def plan_phase_ranks(plan: dict) -> list[int]:
    """Return the phase ranks in plan order (used by tests for ordering)."""
    return [p["phase_rank"] for p in plan["phases"]]
