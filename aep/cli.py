"""Command-line interface for the adversary emulation planner.

    python -m aep plan     --profile ransomware-affiliate --env env/hospital.yaml --out plans/
    python -m aep coverage --plan plans/x.json --rules env/deployed_rules.csv
    python -m aep roe      --plan plans/x.json --out plans/
    python -m aep brief    --plan plans/x.json --backend template
    python -m aep validate-kb
    python -m aep list-profiles
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__
from .coverage import analyze, load_deployed_rules, navigator_layer
from .environment import Environment
from .kb import load_kb
from .llm_client import LLMClient
from .narrator import narrate
from .planner import build_plan
from .roe import generate_roe


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "plan"


def _load_plan(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_plan(args: argparse.Namespace) -> int:
    kb = load_kb()
    env = Environment.from_file(args.env)
    technique_ids = args.techniques.split(",") if args.techniques else None
    plan = build_plan(kb, env, profile_id=args.profile,
                      technique_ids=technique_ids, exercise_name=args.name)

    out = Path(args.out)
    if out.suffix == ".json":
        dest = out
    else:
        out.mkdir(parents=True, exist_ok=True)
        dest = out / f"{_slug(args.profile or 'custom')}-plan.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")

    print(f"plan: {plan['exercise_name']}")
    print(f"techniques: {plan['technique_count']}   phases: {plan['phase_count']}")
    for p in plan["phases"]:
        tids = ", ".join(t["technique_id"] for t in p["techniques"])
        print(f"  {p['phase']:<22} {len(p['techniques']):>2}  {tids}")
    print(f"wrote {dest}")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    plan = _load_plan(args.plan)
    rules = load_deployed_rules(args.rules)
    cov = analyze(plan, rules)
    layer = navigator_layer(plan, cov)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base = _slug(plan.get("exercise_name", "plan"))
    (out / f"{base}-coverage.json").write_text(
        json.dumps(cov, indent=2) + "\n", encoding="utf-8")
    (out / f"{base}-navigator-layer.json").write_text(
        json.dumps(layer, indent=2) + "\n", encoding="utf-8")

    c = cov["counts"]
    print(f"deployed rules: {cov['deployed_rule_count']}   "
          f"plan techniques: {cov['plan_technique_count']}")
    print(f"coverage: {cov['coverage_pct']}%   "
          f"covered={c['covered']} partial={c['partial']} gap={c['gap']}")
    print("")
    print(f"{'technique':<12} {'status':<9} rules")
    print("-" * 60)
    for r in cov["results"]:
        rules_txt = ", ".join(r["deployed_rules"]) or "-"
        print(f"{r['technique_id']:<12} {r['status']:<9} {rules_txt}")
    if cov["gaps"]:
        print("")
        print(f"GAPS ({len(cov['gaps'])}): {', '.join(cov['gaps'])}")
    print("")
    print(f"wrote {out / (base + '-coverage.json')}")
    print(f"wrote {out / (base + '-navigator-layer.json')}")
    return 0


def cmd_roe(args: argparse.Namespace) -> int:
    plan = _load_plan(args.plan)
    text = generate_roe(plan, authorized_by=args.authorized_by, window=args.window)
    out = Path(args.out)
    if out.suffix == ".md":
        dest = out
    else:
        out.mkdir(parents=True, exist_ok=True)
        dest = out / f"{_slug(plan.get('exercise_name', 'plan'))}-ROE.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text + "\n", encoding="utf-8")
    print(f"wrote {dest} ({len(text.splitlines())} lines)")
    return 0


def cmd_brief(args: argparse.Namespace) -> int:
    plan = _load_plan(args.plan)
    client = LLMClient() if args.backend == "llm" else None
    narration = narrate(plan, backend=args.backend, client=client)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base = _slug(plan.get("exercise_name", "plan"))
    (out / f"{base}-brief.json").write_text(
        json.dumps(narration, indent=2) + "\n", encoding="utf-8")

    print(f"backend: {narration['backend']}")
    if narration.get("fallback_reason"):
        print(f"fallback reason: {narration['fallback_reason']}")
    print("")
    print("EXECUTIVE BRIEF")
    print("-" * 60)
    print(narration["executive_brief"])
    print("")
    print("TABLETOP SCENARIO")
    print("-" * 60)
    for i, scene in enumerate(narration["tabletop_scenario"], 1):
        print(f"{i}. {scene['scene']}  [{', '.join(scene['techniques'])}]")
        print(f"   {scene['narrative']}")
    print("")
    print(f"wrote {out / (base + '-brief.json')}")
    return 0


def cmd_validate_kb(args: argparse.Namespace) -> int:
    kb = load_kb()
    errors = kb.validate()
    if errors:
        for e in errors:
            print(f"ERROR: {e}")
        print(f"\n{len(errors)} problem(s) found")
        return 1
    print(f"KB valid: {len(kb.techniques)} techniques, {len(kb.profiles)} profiles, "
          f"{sum(len(v) for v in kb.atomic.values())} atomic tests, "
          f"{sum(len(v) for v in kb.detections.values())} detection ideas")
    return 0


def cmd_list_profiles(args: argparse.Namespace) -> int:
    kb = load_kb()
    for pid, p in kb.profiles.items():
        print(f"{pid:<24} {p.name}")
        print(f"{'':<24} {len(p.techniques)} techniques; motivation: {p.motivation}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aep", description="AI-Assisted Adversary Emulation Planner "
                                "(planning and detection only).")
    parser.add_argument("--version", action="version", version=f"aep {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plan", help="build a phased emulation plan")
    p.add_argument("--profile", help="threat-actor profile id")
    p.add_argument("--techniques", help="comma-separated technique ids")
    p.add_argument("--env", required=True, help="environment yaml file")
    p.add_argument("--name", help="exercise name override")
    p.add_argument("--out", default="plans/", help="output file or directory")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("coverage", help="gap analysis + Navigator layer")
    p.add_argument("--plan", required=True)
    p.add_argument("--rules", required=True, help="deployed-rules CSV")
    p.add_argument("--out", default="plans/", help="output directory")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("roe", help="generate rules-of-engagement document")
    p.add_argument("--plan", required=True)
    p.add_argument("--authorized-by", default="____________________")
    p.add_argument("--window", default="____________________")
    p.add_argument("--out", default="plans/")
    p.set_defaults(func=cmd_roe)

    p = sub.add_parser("brief", help="executive brief + tabletop scenario")
    p.add_argument("--plan", required=True)
    p.add_argument("--backend", choices=["template", "llm"], default="template")
    p.add_argument("--out", default="plans/")
    p.set_defaults(func=cmd_brief)

    sub.add_parser("validate-kb", help="validate the knowledge base") \
        .set_defaults(func=cmd_validate_kb)
    sub.add_parser("list-profiles", help="list threat-actor profiles") \
        .set_defaults(func=cmd_list_profiles)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
