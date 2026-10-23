# Using the ATT&CK Navigator layer

`python -m aep coverage` writes `<exercise>-navigator-layer.json`, an
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) 4.5 layer
scoring each planned technique by how well existing detections cover it.

## Loading it

1. Open the ATT&CK Navigator (hosted or self-run).
2. **Open Existing Layer -> Upload from local** and choose the generated file.
3. Each planned technique is coloured:
   - **green (score 100)** — covered: an enabled deployed rule maps to this exact
     technique id.
   - **amber (score 50)** — partial: only a parent/sibling rule exists
     (e.g. a `T1021` rule while the plan exercises `T1021.001`).
   - **red (score 0)** — gap: no enabled rule maps to it.

## What the comment on each cell tells you

The `comment` field lists the deployed rule names that matched, so you can jump
from the matrix straight to the rule that should fire (or confirm none does).
Layer `metadata` carries the headline `coverage_pct` and the gap count.

## Reading it in an exercise

- Before the test: the layer is your coverage hypothesis. Red cells are where
  you expect no alert.
- After the test: annotate reality. A green cell whose rule did **not** fire is
  a worse finding than a red cell — it means a detection exists but failed.
- Over time: diff layers between exercises to show coverage improving as gap
  findings are turned into rules in the detection repos.

## Relationship to the coverage JSON

`<exercise>-coverage.json` is the machine-readable gap analysis (counts,
per-technique status, the `gaps` list). The Navigator layer is the same data
rendered for the matrix. Use the JSON for CI/metrics and the layer for
communication.
