"""Knowledge-base schema and integrity tests."""

from __future__ import annotations

import pytest

from aep.kb import ATOMIC_RE, TECHNIQUE_RE, KnowledgeBase


def test_kb_validates_clean(kb: KnowledgeBase):
    assert kb.validate() == []


def test_enough_techniques_and_tactics(kb: KnowledgeBase):
    assert len(kb.techniques) >= 80
    tactics = {t.tactic for t in kb.techniques.values()}
    # The full enterprise kill chain should be represented.
    assert len(tactics) >= 11


def test_six_profiles(kb: KnowledgeBase):
    assert len(kb.profiles) == 6
    for p in kb.profiles.values():
        assert p.techniques, f"{p.id} has no techniques"


def test_every_technique_id_well_formed(kb: KnowledgeBase):
    for tid in kb.techniques:
        assert TECHNIQUE_RE.match(tid), tid


def test_every_technique_has_log_events(kb: KnowledgeBase):
    for tid, t in kb.techniques.items():
        assert t.log_events, f"{tid} missing log_events"


def test_atomic_refs_map_to_kb_techniques(kb: KnowledgeBase):
    for tid, tests in kb.atomic.items():
        assert kb.technique(tid) is not None, f"atomic ref for unknown {tid}"
        for test in tests:
            assert ATOMIC_RE.match(test["test_id"]), test["test_id"]
            assert test["test_id"].startswith(tid + "-")


def test_detection_refs_map_to_kb_techniques(kb: KnowledgeBase):
    for tid in kb.detections:
        assert kb.technique(tid) is not None, f"detection for unknown {tid}"


def test_profile_techniques_all_known(kb: KnowledgeBase):
    for p in kb.profiles.values():
        for tid in p.techniques:
            assert kb.technique(tid) is not None, f"{p.id} -> {tid}"


def test_validator_detects_bad_atomic(kb: KnowledgeBase, tmp_path, monkeypatch):
    # Corrupt an in-memory copy and confirm validate() flags it.
    bad = KnowledgeBase.__new__(KnowledgeBase)
    bad.data_dir = kb.data_dir
    bad.techniques = dict(kb.techniques)
    bad.profiles = dict(kb.profiles)
    bad.detections = dict(kb.detections)
    bad.atomic = {"T1059.001": [{"test_id": "T1059.001-bad", "title": "x"}]}
    errors = bad.validate()
    assert any("malformed atomic" in e for e in errors)


def test_validator_detects_unknown_profile_technique(kb: KnowledgeBase):
    from aep.kb import Profile
    bad = KnowledgeBase.__new__(KnowledgeBase)
    bad.data_dir = kb.data_dir
    bad.techniques = dict(kb.techniques)
    bad.atomic = {}
    bad.detections = {}
    bad.profiles = {"x": Profile("x", "X", "s", "m", [], ["T0000"])}
    assert any("unknown technique T0000" in e for e in bad.validate())
