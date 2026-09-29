# Brief M: report completion and small correctness items (branch `report-complete`) - CLOUD agent

Independent small items that stand between "runs" and "trustworthy report". Commit each separately.

## M1. Verify the CVSS 4.0 lookup table (correctness gate)
`cvss4.py` carries a pinned lookup table (ADR-0020). Obtain FIRST's reference `cvss_lookup.js` (FIRSTdotorg
cvss-v4-calculator repository, pin the commit) and compare programmatically, entry by entry. If the network blocks it,
say so and instead add the published CVSS v4.0 example vectors as tests. Any mismatch is a bug: fix and add a
regression test. Add `data/` provenance note (source URL, commit, date) next to the table.
## M2. Report shows the workbench outputs
`10-synthesis-report` closed report schema: add sections for `data_classes`, `privacy_threats`, `deployment_zones`
(and `attack-trees` summary) produced by `03-threat-model-dfd-stride`. Update schema, renderer, tests, fixture output.
## M3. Job 03 metadata matches the job that runs (controller authorises this edit)
`job-graph.json` `required_artifacts` for 03 must list `attack-trees.mmd`, `dfd.mmd`, `ranked-threat-scenarios.json`,
`intercom-transcript.jsonl`; the registry template model and `threat_model_core.py` `worker_kind` must describe the
persona-cell workbench job, not `deterministic-python`. Regenerate catalogs/manifests
(`python3 docs/processes/job_catalog.py`, `python3 appsec-review-process/validate_design_parity.py --write-generated-views`,
then `--check-generated-views`). Never hand-edit generated views.
## M4. ADR-0023 decision 9 vs code
The ADR names a `review_flags` entry `reachability-conflict`; `claim_ledger.py` records a review obligation instead.
Align the ADR text to the code (code is tested and in use). Say so in the ADR implementation line.
## M5. Reachability entry points beyond `main` (design first)
ADR-0020 open item. Read `reachability.py`. Write a short design note (`docs/reachability-entry-points.md`): what
sources are trustworthy (exported symbols, framework route/handler registrations, argv/socket/file-read sinks from
source-SAST tags), how each maps to the CPG, and what stays `unknown`. Implement ONLY the smallest deterministic
piece that is clearly correct (for example CPG exported-symbol entry points behind a tunable, default off). If nothing
is clearly correct, deliver the note alone. Never assert `unreachable` through an unmodelled entry point.

## You own
`cvss4.py` (+ data note), `synthesis_report_presentation.py` and its report schema/tests, `job-graph.json` entry for 03
and its registry template/worker_kind, `reachability.py` (M5 only), ADR-0023 wording. Do NOT touch persona files
(brief J), `execution_state.py`/`launch_job.py` (brief I), `claim_ledger.py`.
## Acceptance
Tests for each item; parity and generated-view checks pass; baseline failures in 00-common.md unchanged.
