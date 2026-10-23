"""Planner tests: phase ordering, record completeness, env awareness."""

from __future__ import annotations

import pytest

from aep.planner import (PHASE_ORDER, build_plan, plan_phase_ranks,
                         select_techniques)


def test_phases_in_canonical_order(plan):
    ranks = plan_phase_ranks(plan)
    assert ranks == sorted(ranks), "phases not in kill-chain order"
    # Ranks must be strictly increasing (no duplicate phase blocks).
    assert len(ranks) == len(set(ranks))


def test_phase_names_are_canonical(plan):
    for p in plan["phases"]:
        assert p["phase"] in PHASE_ORDER


def test_every_technique_record_is_complete(plan):
    required = {"technique_id", "technique_name", "tactic", "objective",
                "atomic_test_ids", "prerequisites", "expected_telemetry",
                "detection_checklist", "success_criteria", "rollback",
                "risk_rating"}
    for phase in plan["phases"]:
        for t in phase["techniques"]:
            assert required <= set(t), f"{t['technique_id']} missing fields"
            assert t["risk_rating"] in {"low", "medium", "high"}
            assert t["success_criteria"]
            assert t["rollback"]


def test_impact_is_high_risk(plan):
    impact = [p for p in plan["phases"] if p["phase"] == "impact"]
    assert impact
    for t in impact[0]["techniques"]:
        assert t["risk_rating"] == "high"


def test_blind_spot_flagged(kb, env):
    # Module/WMI not collected in the test env -> T1574.002 (Module) is a blind spot.
    plan = build_plan(kb, env, technique_ids=["T1574.002"])
    tele = plan["phases"][0]["techniques"][0]["expected_telemetry"]
    assert "Module" in tele["data_sources"]
    assert tele["blind_spots"], "expected a blind spot for uncollected data source"


def test_select_techniques_dedups(kb):
    tids = select_techniques(kb, technique_ids=["T1059.001", "T1059.001", "T1486"])
    assert tids == ["T1059.001", "T1486"]


def test_unknown_profile_raises(kb, env):
    with pytest.raises(ValueError):
        build_plan(kb, env, profile_id="does-not-exist")


def test_empty_selection_raises(kb, env):
    with pytest.raises(ValueError):
        build_plan(kb, env)


def test_atomic_ids_present_for_known_technique(kb, env):
    plan = build_plan(kb, env, technique_ids=["T1059.001"])
    rec = plan["phases"][0]["techniques"][0]
    assert rec["atomic_test_ids"]
    assert all(a.startswith("T1059.001-") for a in rec["atomic_test_ids"])
