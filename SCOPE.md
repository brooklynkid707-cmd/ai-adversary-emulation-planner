# Scope, authorization and responsible use

The AI-Assisted Adversary Emulation Planner is a **planning and detection**
tool for purple-team exercises. It helps a defender decide what adversary
behaviour to emulate, in what order, and how to detect it. It is built to
support **authorized testing of systems you own or are contracted in writing to
test**.

## What this tool is NOT

- It does **not** contain, generate or output exploit code, malware, payloads,
  or operational attack instructions.
- It references public **Atomic Red Team** tests by identifier and title only
  (e.g. `T1059.001-2 "PowerShell Encoded Command"`). To actually run a test you
  go to the Atomic Red Team project itself, inside your authorized lab.
- The threat-actor profiles are generic archetypes (`Group A` … `Group F`)
  modelled on public reporting patterns. They make no claims about specific
  named real-world groups.

## Authorized use only

Running adversary techniques — even for testing — against systems you do not
own or lack written permission to test is illegal in most jurisdictions (for
example the US Computer Fraud and Abuse Act and the UK Computer Misuse Act) and
violates provider acceptable-use policies. Before any execution:

1. Obtain written authorization naming the hosts, the techniques, the testing
   window and an emergency contact.
2. Generate and sign a rules-of-engagement document (`python -m aep roe`).
3. Run only against isolated, non-production lab hosts with a clean snapshot.

## How the tool keeps testing safe

1. **Planning only.** The data files hold technique metadata, telemetry, atomic
   *identifiers* and detection ideas — never commands. The validator
   (`python -m aep validate-kb`) enforces the schema.
2. **High-risk steps are flagged.** Impact, credential-access, defense-evasion,
   privilege-escalation, lateral-movement and exfiltration techniques are rated
   high risk, require a pre-test snapshot, and carry rollback/cleanup notes.
3. **Rollback is built into every step.** Each technique record includes
   cleanup guidance; the ROE adds an ENDEX kill switch and a restore step.
4. **Data handling.** Exfiltration techniques are planned around a benign
   canary file to a tester-controlled sink; real production/customer data is
   never staged or transferred. Evidence is stored access-controlled and
   redacted.
5. **The LLM is kept in check.** The optional narrator may only cite technique
   ids that are already in the plan; any other citation is rejected and the
   deterministic template output is used instead. The model never sees or
   emits attack commands.

## Reporting

Findings from an exercise (detection gaps) are remediation items for the
detection-engineering backlog — not a licence to re-test without fresh
authorization.
