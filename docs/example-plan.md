# Example plan walk-through

This follows one exercise end to end: a ransomware-affiliate emulation against
the synthetic hospital environment.

```bash
python -m aep plan     --profile ransomware-affiliate --env env/hospital.yaml --out plans/
python -m aep coverage --plan plans/ransomware-affiliate-plan.json --rules env/deployed_rules.csv --out plans/
python -m aep roe      --plan plans/ransomware-affiliate-plan.json --out plans/
python -m aep brief    --plan plans/ransomware-affiliate-plan.json --backend template --out plans/
```

## 1. The plan

The profile resolves to 30 techniques, grouped into 12 kill-chain phases
(initial-access → impact). Every technique becomes a planning record. Here is
the LSASS-dumping step from the credential-access phase:

```json
{
  "technique_id": "T1003.001",
  "technique_name": "OS Credential Dumping: LSASS Memory",
  "tactic": "credential-access",
  "objective": "Emulate OS Credential Dumping: LSASS Memory (T1003.001) and confirm the SOC can detect it.",
  "atomic_test_ids": ["T1003.001-1", "T1003.001-2"],
  "prerequisites": [
    "Written authorization for this host/technique is on file (see ROE).",
    "A clean pre-test snapshot/backup of the target host exists.",
    "Telemetry for Process, Command is being collected (or the gap is accepted and noted)."
  ],
  "expected_telemetry": {
    "log_events": ["Sysmon 10 (lsass access)", "Security 4688"],
    "collected_here": ["Process", "Command"],
    "blind_spots": [],
    "observable": true
  },
  "detection_checklist": [
    {"type": "kql", "title": "mde-lsass-memory-dump",
     "source_repo": "microsoft-sentinel-detection-engineering", "status": "planned"},
    {"type": "sigma", "title": "LSASS Access by Non-Allowlisted Process",
     "source_repo": "splunk-threat-detection-lab", "status": "planned"}
  ],
  "success_criteria": [
    "Atomic test(s) T1003.001-1, T1003.001-2 execute in the lab without error.",
    "Expected telemetry is present in Microsoft Sentinel within the agreed detection window.",
    "At least one detection in the checklist fires an alert."
  ],
  "rollback": "Rotate any test credentials touched; purge dumped artifacts from disk.",
  "risk_rating": "high"
}
```

Note what the record does **not** contain: no command, no tool invocation, no
payload. It points the tester at the Atomic Red Team identifiers to run and
tells the defender exactly what telemetry and which detection to watch.

## 2. Coverage

Compared against the 20 enabled rules in `env/deployed_rules.csv`:

```
coverage: 48.3%   covered=14 partial=1 gap=15
GAPS (15): T1566.001, T1133, T1569.002, T1548.002, T1134, T1018, T1482,
           T1550.002, T1570, T1560.001, T1005, T1567.002, T1041, T1105, T1489
```

Two findings worth calling out:

- `T1562.001` is **partial** — the only matching rule (`sec-4719-audit-policy-changed`)
  is for the parent behaviour, so the SOC sees audit-policy tampering but not
  security-tool tampering specifically.
- `T1489` (Service Stop) is a **gap** here even though a rule exists, because
  `service-stop-before-impact` is in `draft` status and the coverage engine
  ignores disabled/draft rules.

The command also writes a Navigator layer (`*-navigator-layer.json`) so the
same result can be read off the ATT&CK matrix — see
[`navigator.md`](navigator.md).

## 3. Rules of engagement

`python -m aep roe` renders a sign-off-ready Markdown ROE from the plan: scope,
an authorization table, the blackout windows pulled from the environment file,
an ENDEX kill switch, data-handling rules, and the list of high-risk techniques
(all impact/credential/evasion steps) that need a snapshot and extra approval.

## 4. Brief

`python -m aep brief` produces an executive brief and a per-phase tabletop
scenario script. With `--backend template` it is fully offline and
deterministic; with `--backend llm` (and a configured endpoint) a model rewrites
the prose but may only cite technique ids that are in the plan — any other
citation is rejected and the template output is used instead.
