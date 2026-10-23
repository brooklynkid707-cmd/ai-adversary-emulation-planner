"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from aep.environment import Environment
from aep.kb import KnowledgeBase, load_kb
from aep.planner import build_plan


@pytest.fixture(scope="session")
def kb() -> KnowledgeBase:
    return load_kb()


@pytest.fixture()
def env(tmp_path):
    f = tmp_path / "env.yaml"
    f.write_text(
        "name: Test Lab\n"
        "os_mix: [Windows Server 2022, Windows 11]\n"
        "data_sources: [Process, Command, Logon Session, File, Network Traffic]\n"
        "siem: Microsoft Sentinel\n"
        "edr: Defender\n"
        "blackout_windows: [Weekdays 09:00-17:00]\n",
        encoding="utf-8",
    )
    return Environment.from_file(f)


@pytest.fixture()
def plan(kb, env) -> dict:
    return build_plan(kb, env, profile_id="ransomware-affiliate")
