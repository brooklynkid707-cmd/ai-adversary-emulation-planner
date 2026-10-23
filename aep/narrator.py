"""Turn a plan into an executive brief and a tabletop scenario script.

Two backends:

* ``template`` (default) - deterministic, offline. No network, no key.
* ``llm`` - optional, via :class:`aep.llm_client.LLMClient`. The model is held
  to a strict JSON contract and may only cite ATT&CK technique ids that are in
  the plan. Any citation that is not in the plan, or any malformed response,
  causes a fall back to the template backend (never a raw-model passthrough).

This keeps the AI on a short leash: it rewrites planning content into prose but
cannot invent techniques, and it cannot smuggle in operational attack detail
because only the plan's technique ids are accepted as references.
"""

from __future__ import annotations

import json
import re

from .llm_client import LLMClient, LLMNotConfigured

CITATION_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

_SYSTEM_PROMPT = (
    "You are a purple-team report writer. You rewrite an authorized, "
    "detection-focused emulation plan into an executive brief and a tabletop "
    "scenario. You MUST NOT invent techniques, commands, payloads or attack "
    "instructions. You may only cite ATT&CK technique ids that appear in the "
    "ALLOWED list. Respond with a single JSON object and nothing else, matching: "
    '{"executive_brief": str, "tabletop_scenario": [{"scene": str, '
    '"narrative": str, "inject": str, "soc_expectation": str, '
    '"techniques": [str]}], "citations": [str]}.'
)


def _allowed_ids(plan: dict) -> set[str]:
    return set(plan["technique_ids"])


def validate_narration(obj: dict, allowed: set[str]) -> dict:
    """Validate an LLM narration against the JSON contract and plan citations.

    Raises ``ValueError`` on any contract breach, including a technique id that
    is not in the plan. Returns the object unchanged on success.
    """
    if not isinstance(obj, dict):
        raise ValueError("narration is not a JSON object")
    if not isinstance(obj.get("executive_brief"), str) or not obj["executive_brief"].strip():
        raise ValueError("missing executive_brief")
    scenes = obj.get("tabletop_scenario")
    if not isinstance(scenes, list) or not scenes:
        raise ValueError("tabletop_scenario must be a non-empty list")

    cited: set[str] = set()
    for scene in scenes:
        if not isinstance(scene, dict):
            raise ValueError("scene is not an object")
        for key in ("scene", "narrative"):
            if not isinstance(scene.get(key), str) or not scene[key].strip():
                raise ValueError(f"scene missing {key}")
        for tid in scene.get("techniques", []):
            cited.add(tid)
        # Any technique id mentioned anywhere in the prose must be allowed too.
        for blob in (scene.get("narrative", ""), scene.get("inject", ""),
                     scene.get("soc_expectation", "")):
            cited.update(CITATION_RE.findall(blob))

    cited.update(obj.get("citations", []))
    cited.update(CITATION_RE.findall(obj["executive_brief"]))

    bad = sorted(t for t in cited if t not in allowed)
    if bad:
        raise ValueError(f"narration cites techniques not in the plan: {bad}")
    return obj


def _template_narration(plan: dict) -> dict:
    env = plan["environment"]
    phases = plan["phases"]
    phase_names = [p["phase"] for p in phases]

    brief_lines = [
        f"Exercise: {plan['exercise_name']}.",
        f"This authorized, detection-focused purple-team exercise emulates "
        f"{plan['technique_count']} ATT&CK techniques across "
        f"{plan['phase_count']} phases ({', '.join(phase_names)}) in the "
        f"'{env['name']}' environment ({env['siem']} / {env['edr']}).",
        "The goal is to measure whether the SOC detects each behaviour, not to "
        "cause impact: every step runs a public Atomic Red Team test in a lab, "
        "checks the expected telemetry, and records whether an alert fires.",
    ]
    high = [t["technique_id"] for p in phases for t in p["techniques"]
            if t["risk_rating"] == "high"]
    if high:
        brief_lines.append(
            f"Highest-risk steps requiring a snapshot and extra sign-off: "
            f"{', '.join(sorted(set(high))[:10])}"
            f"{' ...' if len(set(high)) > 10 else ''}.")

    scenes = []
    for p in phases:
        tids = [t["technique_id"] for t in p["techniques"]]
        names = [t["technique_name"] for t in p["techniques"]]
        atomics = [a for t in p["techniques"] for a in t["atomic_test_ids"]]
        scenes.append({
            "scene": p["phase"].replace("-", " ").title(),
            "narrative": (
                f"In the {p['phase'].replace('-', ' ')} phase the emulated actor "
                f"performs: {', '.join(names)}."),
            "inject": (
                f"Run Atomic test(s) {', '.join(atomics) or '(manual step)'} on an "
                f"authorized lab host."),
            "soc_expectation": (
                "Analysts should observe the expected telemetry and triage the "
                "resulting alert(s); note any step that produces no alert as a gap."),
            "techniques": tids,
        })

    citations = list(plan["technique_ids"])
    return {
        "backend": "template",
        "executive_brief": " ".join(brief_lines),
        "tabletop_scenario": scenes,
        "citations": citations,
    }


def _plan_summary_for_llm(plan: dict) -> str:
    """Compact, citation-safe summary handed to the model (no attack detail)."""
    summary = {
        "exercise_name": plan["exercise_name"],
        "environment": {k: plan["environment"][k]
                        for k in ("name", "siem", "edr", "os_mix")},
        "phases": [
            {"phase": p["phase"],
             "techniques": [{"id": t["technique_id"], "name": t["technique_name"]}
                            for t in p["techniques"]]}
            for p in plan["phases"]
        ],
    }
    return json.dumps(summary)


def narrate(plan: dict, *, backend: str = "template",
            client: LLMClient | None = None) -> dict:
    """Produce the narration. Falls back to the template on any LLM problem."""
    if backend == "template":
        return _template_narration(plan)

    if backend != "llm":
        raise ValueError(f"unknown backend: {backend!r}")

    allowed = _allowed_ids(plan)
    client = client or LLMClient()
    try:
        if not client.configured:
            raise LLMNotConfigured("no AISEC_LLM_URL")
        user = ("ALLOWED technique ids: " + ", ".join(sorted(allowed))
                + "\n\nPLAN:\n" + _plan_summary_for_llm(plan))
        raw = client.chat(_SYSTEM_PROMPT, user)
        obj = json.loads(raw)
        validate_narration(obj, allowed)
        obj["backend"] = "llm"
        obj.setdefault("citations", sorted(allowed))
        return obj
    except (LLMNotConfigured, ValueError, KeyError, json.JSONDecodeError,
            OSError) as exc:
        fallback = _template_narration(plan)
        fallback["backend"] = "template (fallback)"
        fallback["fallback_reason"] = str(exc)
        return fallback
