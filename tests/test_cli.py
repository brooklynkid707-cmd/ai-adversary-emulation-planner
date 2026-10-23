"""End-to-end CLI tests for plan -> coverage -> roe -> brief."""

from __future__ import annotations

import json
from pathlib import Path

from aep.cli import main

ENV = str(Path(__file__).resolve().parent.parent / "env" / "hospital.yaml")
RULES = str(Path(__file__).resolve().parent.parent / "env" / "deployed_rules.csv")


def test_cli_full_pipeline(tmp_path, capsys):
    out = tmp_path

    # plan
    rc = main(["plan", "--profile", "ransomware-affiliate", "--env", ENV,
               "--out", str(out)])
    assert rc == 0
    plan_file = out / "ransomware-affiliate-plan.json"
    assert plan_file.exists()
    plan = json.loads(plan_file.read_text())
    assert plan["technique_count"] >= 10

    # coverage
    rc = main(["coverage", "--plan", str(plan_file), "--rules", RULES,
               "--out", str(out)])
    assert rc == 0
    cov_files = list(out.glob("*-coverage.json"))
    nav_files = list(out.glob("*-navigator-layer.json"))
    assert cov_files and nav_files
    cov = json.loads(cov_files[0].read_text())
    assert cov["counts"]["covered"] + cov["counts"]["partial"] + cov["counts"]["gap"] \
        == cov["plan_technique_count"]

    # roe
    rc = main(["roe", "--plan", str(plan_file), "--out", str(out)])
    assert rc == 0
    assert list(out.glob("*-ROE.md"))

    # brief (template, offline)
    rc = main(["brief", "--plan", str(plan_file), "--backend", "template",
               "--out", str(out)])
    assert rc == 0
    brief = json.loads(list(out.glob("*-brief.json"))[0].read_text())
    assert brief["backend"] == "template"


def test_cli_plan_to_json_path(tmp_path):
    dest = tmp_path / "custom.json"
    rc = main(["plan", "--techniques", "T1059.001,T1486", "--env", ENV,
               "--out", str(dest)])
    assert rc == 0
    plan = json.loads(dest.read_text())
    assert plan["technique_ids"] == ["T1059.001", "T1486"]


def test_cli_validate_kb(capsys):
    assert main(["validate-kb"]) == 0
    assert "KB valid" in capsys.readouterr().out


def test_cli_list_profiles(capsys):
    assert main(["list-profiles"]) == 0
    assert "ransomware-affiliate" in capsys.readouterr().out
