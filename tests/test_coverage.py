"""Coverage math and Navigator layer tests."""

from __future__ import annotations

import json

from aep.coverage import analyze, load_deployed_rules, navigator_layer


def _rules_csv(tmp_path, body: str):
    f = tmp_path / "rules.csv"
    f.write_text("rule_name,technique_id,siem,status\n" + body, encoding="utf-8")
    return f


def test_exact_partial_and_gap(kb, env, tmp_path):
    from aep.planner import build_plan
    plan = build_plan(kb, env, technique_ids=["T1003.001", "T1021.001", "T1486"])
    # Deployed: exact for T1003.001; parent T1021 only (partial for .001);
    # nothing for T1486 (gap).
    csv = _rules_csv(tmp_path,
                     "lsass,T1003.001,Sentinel,enabled\n"
                     "rdp-parent,T1021,Splunk,enabled\n")
    cov = analyze(plan, load_deployed_rules(csv))
    by = {r["technique_id"]: r["status"] for r in cov["results"]}
    assert by["T1003.001"] == "covered"
    assert by["T1021.001"] == "partial"
    assert by["T1486"] == "gap"


def test_coverage_pct_math(kb, env, tmp_path):
    from aep.planner import build_plan
    plan = build_plan(kb, env, technique_ids=["T1003.001", "T1021.001", "T1486"])
    csv = _rules_csv(tmp_path,
                     "lsass,T1003.001,Sentinel,enabled\n"
                     "rdp-parent,T1021,Splunk,enabled\n")
    cov = analyze(plan, load_deployed_rules(csv))
    # 1 covered + 1 partial(0.5) + 1 gap over 3 => (1 + 0.5)/3 = 50.0
    assert cov["coverage_pct"] == 50.0
    assert cov["counts"] == {"covered": 1, "partial": 1, "gap": 1}


def test_disabled_rules_ignored(kb, env, tmp_path):
    from aep.planner import build_plan
    plan = build_plan(kb, env, technique_ids=["T1486"])
    csv = _rules_csv(tmp_path, "ransom,T1486,Splunk,disabled\n")
    cov = analyze(plan, load_deployed_rules(csv))
    assert cov["results"][0]["status"] == "gap"
    assert cov["deployed_rule_count"] == 0


def test_multi_technique_rule(kb, env, tmp_path):
    from aep.planner import build_plan
    plan = build_plan(kb, env, technique_ids=["T1059.001", "T1027"])
    csv = _rules_csv(tmp_path, "enc-ps,T1059.001;T1027,Sentinel,enabled\n")
    cov = analyze(plan, load_deployed_rules(csv))
    assert all(r["status"] == "covered" for r in cov["results"])


def test_navigator_layer_schema(plan, env, tmp_path):
    csv = _rules_csv(tmp_path, "lsass,T1003.001,Sentinel,enabled\n")
    cov = analyze(plan, load_deployed_rules(csv))
    layer = navigator_layer(plan, cov)
    # Round-trips as JSON and has the required Navigator 4.5 fields.
    layer = json.loads(json.dumps(layer))
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert isinstance(layer["techniques"], list) and layer["techniques"]
    for t in layer["techniques"]:
        assert t["techniqueID"].startswith("T")
        assert 0 <= t["score"] <= 100
        assert t["color"].startswith("#")
    # One technique per plan technique.
    assert len(layer["techniques"]) == plan["technique_count"]
