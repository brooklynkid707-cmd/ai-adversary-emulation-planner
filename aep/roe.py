"""Generate a rules-of-engagement (ROE) document for a plan.

The ROE is a Markdown document a test lead signs before a purple-team exercise:
scope, an authorization sign-off block, blackout windows, a kill switch, data
handling and emergency contacts. It is generated from the plan so the
authorized technique list and environment always match what will be executed.
"""

from __future__ import annotations

HIGH_RISK_TACTICS = {"impact", "credential-access", "defense-evasion",
                     "privilege-escalation", "lateral-movement", "exfiltration"}


def _high_risk_techniques(plan: dict) -> list[str]:
    out = []
    for phase in plan["phases"]:
        if phase["phase"] in HIGH_RISK_TACTICS:
            out.extend(t["technique_id"] for t in phase["techniques"])
    return out


def generate_roe(plan: dict, *, authorized_by: str = "____________________",
                 window: str = "____________________") -> str:
    """Render the ROE as Markdown text."""
    env = plan["environment"]
    high = _high_risk_techniques(plan)
    blackout = env.get("blackout_windows") or ["(none specified - define before execution)"]

    lines: list[str] = []
    lines.append(f"# Rules of Engagement - {plan['exercise_name']}")
    lines.append("")
    lines.append(f"- **Generated:** {plan['generated']}")
    lines.append(f"- **Environment:** {env['name']}")
    lines.append(f"- **SIEM / EDR:** {env['siem']} / {env['edr']}")
    lines.append(f"- **Techniques in scope:** {plan['technique_count']} "
                 f"across {plan['phase_count']} phases")
    lines.append("")
    lines.append("> This exercise is **authorized testing of the owner's own "
                 "systems only**. It is detection-focused: Atomic Red Team tests "
                 "are run in a controlled lab to validate telemetry and alerts. "
                 "No production data is exfiltrated; destructive techniques run "
                 "only against disposable, pre-snapshotted hosts.")
    lines.append("")

    lines.append("## 1. Scope")
    lines.append("")
    lines.append("**In scope (authorized targets):**")
    lines.append("")
    lines.append(f"- Operating systems: {', '.join(env['os_mix']) or 'as agreed'}")
    lines.append("- Only the hosts named in the authorization block below.")
    lines.append("- Only the ATT&CK techniques listed in the plan "
                 f"({', '.join(plan['technique_ids'][:12])}"
                 f"{' ...' if len(plan['technique_ids']) > 12 else ''}).")
    lines.append("")
    lines.append("**Out of scope:** production systems not named below, customer "
                 "data, third-party/SaaS tenants, any technique not in the plan, "
                 "and any action with real-world impact outside the lab.")
    lines.append("")

    lines.append("## 2. Authorization sign-off")
    lines.append("")
    lines.append(f"Authorized by (name/role): **{authorized_by}**")
    lines.append("")
    lines.append(f"Authorization reference (RoE id / ticket): ____________________")
    lines.append("")
    lines.append(f"Approved testing window: **{window}**")
    lines.append("")
    lines.append("| Role | Name | Signature | Date |")
    lines.append("|---|---|---|---|")
    lines.append("| System/Data owner | | | |")
    lines.append("| Test lead (red) | | | |")
    lines.append("| SOC lead (blue) | | | |")
    lines.append("| Approving manager | | | |")
    lines.append("")

    lines.append("## 3. Blackout windows")
    lines.append("")
    lines.append("No testing during these periods:")
    lines.append("")
    for b in blackout:
        lines.append(f"- {b}")
    lines.append("")

    lines.append("## 4. Kill switch")
    lines.append("")
    lines.append("- Any participant may call **\"ENDEX\"** (end of exercise) by "
                 "message or phone to halt all activity immediately.")
    lines.append("- On ENDEX: stop all atomic tests, tear down any test C2 "
                 "listener, and begin rollback per each technique's cleanup notes.")
    lines.append("- Trigger ENDEX on any unplanned outage, any sign of real "
                 "attacker activity, or any spill of production/customer data.")
    lines.append("- Emergency contact (24/7): ____________________")
    lines.append("")

    lines.append("## 5. Data handling")
    lines.append("")
    lines.append("- Use only synthetic/test data; never stage, archive or "
                 "exfiltrate real production or customer data.")
    lines.append("- Store evidence (screenshots, logs, alert exports) in the "
                 "engagement's access-controlled folder; retain per policy then "
                 "destroy.")
    lines.append("- Redact credentials and tokens from all evidence.")
    lines.append("- Exfiltration techniques transfer a benign canary file only, "
                 "to a sink controlled by the test team.")
    lines.append("")

    lines.append("## 6. High-risk techniques requiring extra sign-off")
    lines.append("")
    if high:
        lines.append("The following require a clean snapshot/backup and explicit "
                     "per-technique approval before execution:")
        lines.append("")
        for tid in high:
            lines.append(f"- {tid}")
    else:
        lines.append("- None in this plan.")
    lines.append("")

    lines.append("## 7. Rollback and verification")
    lines.append("")
    lines.append("- Each technique in the plan carries cleanup notes; execute them "
                 "immediately after the test step.")
    lines.append("- After ENDEX, confirm every target host is restored to its "
                 "pre-test state and all test artifacts are removed.")
    lines.append("- The SOC confirms which detections fired; gaps become findings, "
                 "not re-tests, without fresh approval.")
    lines.append("")
    return "\n".join(lines)
