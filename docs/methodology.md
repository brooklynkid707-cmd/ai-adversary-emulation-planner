# Methodology: threat-informed defense and purple teaming

This planner operationalizes **threat-informed defense**: letting known
adversary behaviour drive which detections a SOC builds and tests, rather than
buying tools and hoping they cover the right things.

## The loop

```
threat intel  ->  emulation plan  ->  controlled test  ->  detection result  ->  gap -> new rule
      ^                                                                                     |
      +-------------------------------------------------------------------------------------+
```

1. **Pick a threat model.** A profile (e.g. "ransomware affiliate targeting
   healthcare") or an explicit technique list defines *what* to emulate. The
   profiles here are archetypes drawn from public reporting patterns, not
   claims about specific named groups.
2. **Plan against the real environment.** The plan is tailored to the OS mix,
   the telemetry actually collected, and the SIEM/EDR in use. Where a
   technique's ATT&CK data source is not collected, the plan flags a *blind
   spot* up front.
3. **Test under rules of engagement.** Each step runs a public **Atomic Red
   Team** test in a lab. Atomic Red Team is a library of small, single-technique
   tests mapped to ATT&CK; this tool references the test *identifiers and
   titles* only (e.g. `T1059.001-2`) and never reproduces their commands.
4. **Measure detection, not compromise.** Success is "the SOC saw it and
   alerted," not "the attack worked." A step that produces no alert is a
   finding, recorded as a coverage gap.
5. **Close gaps.** Gaps feed back into detection engineering (the owner's
   Sentinel and Splunk repos), and the next exercise re-tests them.

## Why purple, not red

A pure red-team engagement measures whether a goal can be reached. A **purple**
exercise optimizes the defender's feedback loop: red and blue work the same
technique list together, so every emulated behaviour is paired with an explicit
question — *did we detect this, and if not, why?* That is why every technique
record in a plan carries an **expected telemetry** block and a **detection
checklist**, and why the coverage command compares the plan to deployed rules.

## Frameworks referenced

- **MITRE ATT&CK (Enterprise)** — the technique taxonomy and the tactic
  (kill-chain) ordering used for the phases.
- **MITRE ATT&CK Navigator** — the layer JSON the coverage command emits.
- **Atomic Red Team** — the test library whose identifiers the plan references.
- **CTID / threat-informed defense** — the idea of prioritizing detections by
  adversary behaviour and measuring coverage as a first-class metric.
- **NIST CSF 2.0 DETECT (DE.CM / DE.AE)** — the function this work serves.

## Safety model

Everything is planning and detection content. The tool is built for
**authorized testing of the owner's own systems**:

- No exploit code, payloads, or operational attack instructions are generated
  or stored — see [`../SCOPE.md`](../SCOPE.md).
- Destructive (impact-tactic) techniques are marked high risk, require a clean
  snapshot, and carry explicit rollback notes.
- The ROE document encodes scope, sign-off, blackout windows, a kill switch and
  data handling before any test runs.
