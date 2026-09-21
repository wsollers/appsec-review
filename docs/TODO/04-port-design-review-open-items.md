# 04 -- Port the six open "must address" items out of design-review-2026-09-11.md

Goal: `docs/design-review-2026-09-11.md` is disposed (chunk 02) but six of its "must address before
first run" items are tracked nowhere else. Put them where open work lives before the file goes.

## Inputs
- `docs/design-review-2026-09-11.md` -- the six unchecked items: lane-09 verifiers see only cited
  artifact spans; seccomp / Windows Hyper-V isolation profile; L3 SVF/IR/CPG substrate note;
  `VERIFIED_PRIMITIVE` stranding final confirmation (§23.1); §19 recall / false-positive budget /
  holdout split criteria; ledger anchoring (§8.2, needs the orchestrator).
- `docs/design-parity/design-parity-completion-plan.md` Workstreams A/F/G.

## Steps
1. Add each item as an unchecked line in the matching workstream of the completion plan, with the
   design-v3 section reference and one sentence of context. If it belongs to an existing batch id
   in `appsec-review-process/TODO.md`, cross-reference that id instead of duplicating.
2. Note in `docs/REORG-2026-09-21.md` §2 that the port is done so chunk 02 may remove the file.

## Done when
All six appear in the completion plan (or TODO.md batch) and nothing else in the review doc is
untracked.

## Touches
`docs/design-parity/design-parity-completion-plan.md`, possibly `appsec-review-process/TODO.md`.
