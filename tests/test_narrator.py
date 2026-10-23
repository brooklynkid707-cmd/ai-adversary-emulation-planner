"""Narrator tests: template backend, JSON contract, citation guard, fallback."""

from __future__ import annotations

import json

import pytest

from aep.llm_client import LLMClient
from aep.narrator import narrate, validate_narration


def test_template_backend(plan):
    out = narrate(plan, backend="template")
    assert out["backend"] == "template"
    assert out["executive_brief"]
    assert out["tabletop_scenario"]
    # Every cited technique is in the plan.
    allowed = set(plan["technique_ids"])
    for scene in out["tabletop_scenario"]:
        for tid in scene["techniques"]:
            assert tid in allowed


def test_validate_rejects_out_of_plan_citation(plan):
    allowed = set(plan["technique_ids"])
    bad = {
        "executive_brief": "Brief mentioning T9999.",
        "tabletop_scenario": [{"scene": "s", "narrative": "n", "techniques": []}],
        "citations": ["T9999"],
    }
    with pytest.raises(ValueError, match="not in the plan"):
        validate_narration(bad, allowed)


def test_validate_rejects_inline_out_of_plan(plan):
    allowed = set(plan["technique_ids"])
    bad = {
        "executive_brief": "ok",
        "tabletop_scenario": [{"scene": "s",
                               "narrative": "actor used T0001 here",
                               "techniques": []}],
        "citations": [],
    }
    with pytest.raises(ValueError):
        validate_narration(bad, allowed)


def test_validate_accepts_good_narration(plan):
    allowed = set(plan["technique_ids"])
    good_tid = plan["technique_ids"][0]
    obj = {
        "executive_brief": f"Covers {good_tid}.",
        "tabletop_scenario": [{"scene": "Phase", "narrative": "desc",
                               "techniques": [good_tid]}],
        "citations": [good_tid],
    }
    assert validate_narration(obj, allowed) is obj


def test_validate_rejects_malformed_structure(plan):
    allowed = set(plan["technique_ids"])
    with pytest.raises(ValueError):
        validate_narration({"executive_brief": ""}, allowed)
    with pytest.raises(ValueError):
        validate_narration({"executive_brief": "x",
                            "tabletop_scenario": []}, allowed)


class _FakeClient(LLMClient):
    def __init__(self, payload: str):
        super().__init__(url="http://mock/none")
        self._payload = payload

    @property
    def configured(self) -> bool:
        return True

    def chat(self, system, user, *, temperature=0.0):  # noqa: D401
        return self._payload


def test_llm_backend_accepts_valid_json(plan):
    good_tid = plan["technique_ids"][0]
    payload = json.dumps({
        "executive_brief": f"Brief citing {good_tid}.",
        "tabletop_scenario": [{"scene": "P", "narrative": "n",
                               "techniques": [good_tid]}],
        "citations": [good_tid],
    })
    out = narrate(plan, backend="llm", client=_FakeClient(payload))
    assert out["backend"] == "llm"


def test_llm_backend_falls_back_on_rogue_citation(plan):
    payload = json.dumps({
        "executive_brief": "Brief",
        "tabletop_scenario": [{"scene": "P", "narrative": "n",
                               "techniques": ["T9999"]}],
        "citations": ["T9999"],
    })
    out = narrate(plan, backend="llm", client=_FakeClient(payload))
    assert out["backend"] == "template (fallback)"
    assert "T9999" in out["fallback_reason"]


def test_llm_backend_falls_back_on_garbage(plan):
    out = narrate(plan, backend="llm", client=_FakeClient("not json"))
    assert out["backend"] == "template (fallback)"


def test_llm_backend_falls_back_when_unconfigured(plan, monkeypatch):
    monkeypatch.delenv("AISEC_LLM_URL", raising=False)
    out = narrate(plan, backend="llm")
    assert out["backend"] == "template (fallback)"
