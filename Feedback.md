# Feedback

## [P2] The accepted gate decisions are contradicted by stale proposal state

ADR-0010 now says all G1-G10 decisions were accepted, and the JSON appends a `gate_decisions` object, but the machine-readable proposal still states that it represents recommendations for “each open human gate” and that “nothing here is decided until the gates ... are answered” (`docs/proposals/vendor-prepass/job-nodes.proposal.json:6`). The same stale state remains in the threat-workbench producer comment (`threat-workbench-producers.proposal.yaml:11`) and the adopted G6 behavior is still labeled `RECOMMENDED` in both proposal JSON files (`job-nodes.proposal.json:847`, `legacy-step-map.proposal.json:722,746`).

This fails the packet's acceptance condition that the ADR and fixtures agree and leaves downstream implementers with two conflicting authorities inside the same machine-readable artifact. Update the fixture basis/comments/behavior text to say the choices are the recorded decisions, and describe `02-mobile-applicability` strictly as a rejected/option-only alternative rather than an open recommendation.

## Validation

- Both proposal JSON files parse successfully.
- `validate_design_parity.py`: PASS (existing readiness gaps reported).
- `qualify_phase1.py --check-contracts`: PASS.
- `git diff --check`: PASS.
- Full pytest collection requires `PHASE1_TEST_DATA` and the `dagster` package, which are absent in this host environment.
