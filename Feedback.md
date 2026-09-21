# Review Feedback for PR #30 (V02)

Reviewed at head `e93e004`. One documentation finding; **no P1 and no data/code defect was found** —
the list of what was attacked and held is below, so the fix can be small.

## [P2] `docs/build-discovery-integration.md` now says "51" above a hand-written job table with 41 rows

The PR changed line 3 ("exposes 51 lifecycle and registry jobs") and line ~165 ("the 51-node
lifecycle view"). The table directly beneath, under `## Registered lifecycle jobs`, was not
extended: none of the nine new nodes is in it (`02-evidence-index` was already missing on `main`).
The PR body says the docs that hard-coded 42 were updated to 51; this file now states 51 and lists
41, and it is the one hand-maintained copy of the node set the PR did not extend — the
two-sources-of-truth shape this PR otherwise removes.

Reproduction (from the repo root at the PR head):

```bash
for j in $(python3 -c "import json;print(' '.join(x['id'] if isinstance(x,dict) else x for x in json.load(open('appsec-review-process/job-graph.json'))['jobs']))"); do
  grep -q "\`$j\`" docs/build-discovery-integration.md || echo "MISSING $j"; done
```

Observed: `MISSING` for `02-evidence-index`, `02-secrets-inventory`, `02-iac-config-scan`,
`02-container-image-inventory`, `02-sbom-inventory`, `02-sca-vulnerability-match`,
`02-license-scan`, `02-dependency-lifecycle`, `02-binary-hardening`, `02-mobile-sast`.

Why the suite missed it: `test_generated_views_name_every_new_node_and_are_current` covers only the
four generated views; nothing ties this table to the graph.

Fix direction: either add the ten rows (`Worker blocked` / `Missing`; `02-evidence-index` per its
real state), or — better — replace the table with a pointer to the generated
`design-parity-readiness.md`. Regression: every `job-graph.json` job id appears in that section, or
the section holds no job table.

## Heads-up for the merge order (not a defect of this PR)

- Draft PR #33 (B15) makes `blocked_op` reference a module global `NOT_IMPLEMENTED`; this PR's
  `test_vendor_prepass_graph.py` (~`:431-464`) execs `blocked_op` in a hand-built namespace without
  it → 9 `NameError`s on the merged tree. Reported on #33; whichever merges second must fix it.
- After #30 + #31 the nine parity rows still say validator dispatch is pending, and
  `test_vendor_prepass_graph.py:~384` pins `"validate_job_output.py" in blocker` — the promised
  follow-up has to change that test too.

## Probes that held

- Generated views regenerated on a scratch copy are byte-identical (`diff -r` empty);
  `validate_design_parity.py` PASS (51 jobs), `phase1.py graph --check` 0, `--check-contracts` PASS
  (92 records, 51 jobs).
- Independent script (not the PR's test): for all nine nodes, graph `required_artifacts` == contract
  record `required_files` == the merged verifier modules' policy tables; job ids and dependencies
  match the V04/V05/V07 modules; exactly four nodes may skip and that agrees across the assembly
  edges, the fixture and the modules.
- 18 consistent mutations (views regenerated each time so a stale view could not be the detector) —
  dropped/duplicated/optional edges, skip reason added/removed/misplaced/unregistered, swapped
  contract, dropped or reordered dependency, extra 03→node edge, popped artifact, `implemented:
  true`, template set, readiness/next_prerequisite flipped — all caught by the focused suite.
- `dagster_workflow.py` builds the lifecycle ops data-driven from the graph (read, not run: no
  Dagster on the host). No code or test depends on 42.
- `e93e004` decides nothing new: its ADR/fixture edits equal the three merged contracts'
  `required_files`. TODO/task-series status edits match merged-PR history.
- #30 + #31 merged in a scratch tree: no conflicts, validators pass, 307 affected tests OK, full
  suite shows only the 8 known host errors.

## Not covered

Live Dagster load and the `qualify_*` reruns claimed in the body; the in-container 872 figure;
Windows.
