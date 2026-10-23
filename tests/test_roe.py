"""Rules-of-engagement document tests."""

from __future__ import annotations

from aep.roe import generate_roe


def test_roe_has_required_sections(plan):
    text = generate_roe(plan, authorized_by="J. Scirica (ticket SEC-42)",
                        window="2026-11-02 to 2026-11-06")
    for heading in ("## 1. Scope", "## 2. Authorization sign-off",
                    "## 3. Blackout windows", "## 4. Kill switch",
                    "## 5. Data handling"):
        assert heading in text


def test_roe_includes_authorization_and_window(plan):
    text = generate_roe(plan, authorized_by="J. Scirica (ticket SEC-42)",
                        window="2026-11-02 to 2026-11-06")
    assert "J. Scirica (ticket SEC-42)" in text
    assert "2026-11-02 to 2026-11-06" in text
    assert "ENDEX" in text  # kill switch keyword


def test_roe_lists_high_risk_techniques(plan):
    text = generate_roe(plan)
    # The ransomware profile includes impact techniques; they must be called out.
    assert "T1486" in text


def test_roe_carries_blackout_from_env(plan):
    text = generate_roe(plan)
    assert "09:00-17:00" in text  # from the test env fixture
