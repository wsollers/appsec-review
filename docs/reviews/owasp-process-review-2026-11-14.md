---
title: "OWASP control-assessment process review, 2026-11-14"
kind: "review"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_owasp_control_assessment"]
---
# OWASP control-assessment process review (2026-11-14)

Independent review of `job_owasp_control_assessment` as it stands on `origin/main`
`1a154efbfab2b633a62495898017044635043dcd` (fetched 2026-11-14, worktree branch `owasp-review`).
At the end of the review `origin/main` had advanced to `810d837cd9a40609ebe3f909dbbf035f7932e65d`
(one T-152 commit touching no OWASP path). No code was changed. Run evidence comes from smoke-cpp run `2026-11-14-0003` on this host; the
answer key was not read. Line numbers refer to the reviewed commit.

**Important caveat for the run evidence.** The run started at 08:50 UTC from the main checkout at
`515300d5`, which contains the two contract fixes (`1f40f7aa`, `055bf1f6`) but **not** the T-146
subject-selection enhancement (`fdb85e69`, `afc7c1b8`, `441f5836` are not ancestors of `515300d5`).
The run's gap text (`evidence cap reached; at least 124 further accepted records omitted`) is the
pre-T-146 wording. Observations below therefore show the pre-enhancement evidence binding on a
real target; the code review covers the enhanced code.

## Findings

Severity vocabulary: **defect** (wrong behaviour), **contract gap** (violates
`docs/architecture/job-interchange.md` or AGENTS.md discipline), **doc drift**, **improvement**.

### F1 — defect: finding packages cannot fit the configured model input budget

- Files: `src/appsec_review/owasp_workbench/engine.py:387-389,402` (every row's package copies the
  whole component evidence list, bounded only by `max_evidence_per_component`);
  `src/appsec_review/owasp_workbench/assessment.py:181,195,207-222` (all packages of a batch are
  serialised into one request; when the 4-chars-per-token estimate exceeds `max_input_tokens`
  the investigation ends with status `input_budget` and no model call).
- Evidence: run `2026-11-14-0003`, `artifacts/owasp-workbench/finding-packages.json` (1,524,133
  bytes for 4 packages). Per batch: `batch-a0d5eb3c…` 1 package, 389,000 bytes, about 97,250
  estimated tokens; `batch-b440889f…` 1 package, 389,292 bytes, about 97,300 tokens;
  `batch-fa57ef8c…` 2 packages, 777,691 bytes, about 194,400 tokens. Every package carried 60
  evidence references with excerpts. The configured budget is 24,000 input tokens
  (`appsec-review.toml:2700`). No batch reached a model here only because no obligation was
  supported; with a Python component the same shape (60 subjects, excerpts up to 16,000
  characters, repeated once per row, up to 12 rows per batch) would have produced
  `cannot_verify` with gap `worker: input_budget` for every row and zero model calls, which
  `tests/test_owasp_assessment_job.py:500-513` treats as the correct outcome of budget exhaustion.
- Proposed fix: give each package only the evidence its obligations bind (`evidence_ids`),
  serialise shared evidence once per batch, and refuse at package assembly (not at the model call)
  when the serialised request cannot fit the selected profile.

### F2 — contract gap: batches with no supported obligation are dispatched and reported as failed workers

- Files: `engine.py:324-326` (`partition_work` dispatches every applicable/conditional row);
  `assessment.py:409-414,488-490` (`run_batch` returns `terminal_state: "failed"` when `ready` is
  empty because the worker status is `missing_evidence`); `job.py:211-216,241-244,343` (the cell
  logs `OWASP_WORKER_STARTED` with the model profile, counts the batch as failed, and publishes
  `failed_batches_by_cell`).
- Evidence: run `2026-11-14-0003`: 3 batches, 3 `OWASP_WORKER_STARTED` events naming
  `claude-haiku-5-5`, 3 `OWASP_WORKER_COMPLETED` events with `terminal_status: "failed"` and
  `model_calls: 0`; result `failed_batches_by_cell {"cell_01": 1, "cell_02": 1, "cell_03": 1}`.
  The operations doc (`docs/operations/owasp-control-assessment.md:140-141`) tells operators that
  cell failure is a scoped gap; here nothing failed, the component had no recognisable Python
  subject.
- Proposed fix: partition only rows with at least one `supported` obligation, and record the rest
  under `non_dispatch_dispositions` with a payload reason, keeping `failed` for actual worker or
  provider failures.

### F3 — contract gap: the declared contract mirrors the tags manifest, not what the job reads

- Files: `src/appsec_review/jobs/job_owasp_control_assessment/datasets.py:39-330` (26 producers,
  about 110 input requirements); `src/appsec_review/owasp_workbench/evidence.py:21-24,107-109` (the
  resolver keeps only shards whose index is in `UPSTREAM_INDEXES` and whose producer is in
  `CONTRACT.consumes`, silently dropping the rest); `src/appsec_review/retrieval/core.py:388-389`
  (`accept_manifest` opens and records every embedded shard through `observe_shard`);
  `tests/test_consumes_parity.py:57-66` (cements the mirror).
- Evidence: run claim `upstream_handoffs` pins 26 producers; the tags manifest embeds
  `debug_symbols`, `history` and `binary` indices (`data/indices/`), none of which is in
  `UPSTREAM_INDEXES`, yet their shards are opened, read-receipted and declared as consumed. The
  1f40f7aa fix was necessary to stop `load_inputs` refusing, but it widened `CONSUMES` (and the
  review topology) to producers the job never uses, which is the availability/supply/read/citation
  conflation AGENTS.md asks to avoid.
- Proposed fix: let `accept_manifest`/`RetrievalCore` take a producer and index selection so only
  shards the resolver will use are opened and receipted, then shrink the contract to those
  producers and replace the parity test with a "declares what it opens" test.

### F4 — contract gap: terminal statuses are literals and gaps are free text

- Files: `job.py:125,244,285,292,383` (string literals `"COMPLETED_WITH_GAPS"`/`"SUCCEEDED"`
  rather than `interchange.ProducerStatus` members); `job.py:124,349,376` (unit `gaps` are
  free-text strings); `job.py:412-415` (no `strict_gaps=True`); `tests/test_gap_contract.py:19`
  (the job sits in the legacy free-text list).
- Evidence: run handoff validates (the literals are valid members), but the attempt outcome holds
  six generic `producer_reported_gap` records with reason `producer status: COMPLETED_WITH_GAPS;
  coverage disposition: None`, while the 614 named gaps live only in the result payload.
- Proposed fix: emit `ProducerStatus` values, publish named gaps as `interchange.producer_gap`
  records, set `strict_gaps=True`, and remove the job from the legacy list.

### F5 — contract gap: the fingerprinted guidance bundle is not the one a model receives

- Files: `job.py:183-191` (`build_packages` composes a bundle whose task carries the full
  obligations and pins it on every package); `job.py:302-304,330-332` (its hash feeds the
  finding-package shard fingerprint and the global fingerprint);
  `assessment.py:110-124,153-156,207-209` (`investigate` composes a second bundle with
  `proof_obligations: [VERSION]`, sends that one, and keys the reuse receipt on it).
- Evidence: run `2026-11-14-0003` pinned the package-time bundles only (no investigation ran); in
  a run with model calls the bundle a worker saw is discoverable only through `OWASP_MODEL_ATTEMPT`
  events and receipts, never through the published shard fingerprints.
- Proposed fix: compose once per batch and role in `build_packages`, carry the pinned identity into
  `investigate`, and fingerprint shards with the identities actually sent.

### F6 — improvement: an unreviewed or disputed adverse verdict still becomes a lead

- Files: `assessment.py:440-441,455,479` (`satisfied` needs reviewer agreement; `not_satisfied`
  does not; `lead_eligible = bool(observations)`); `src/appsec_review/indexing/products.py:1189-1194`
  (eligible when `verification_status` is any of `independently_assessed`, `dissent`, `pending`,
  `unresolved`); `src/appsec_review/review/lead_families.py:677-699` (emits an `owasp_control`
  lead).
- Evidence: code path only; the run produced no adverse verdict. The asymmetry is conservative in
  the security direction and the doc calls leads provisional, but a worker answer whose blinded
  reviewer disagreed, or whose reviewer failed (`pending`), reaches package assembly with the same
  standing as an independently assessed one; the model's `severity`/`ship_blocking` choices ride
  along in `observations`.
- Proposed fix: either require `independently_assessed` for `production_eligible`, or carry the
  disposition into the lead so ranking can down-weight `dissent`/`pending` leads.

### F7 — doc drift: registry role text does not describe the task the job gives the role

- Files: `pipeline/guidance/registry.json` roles `independent_reviewer` ("Independently review
  elevated or ship-blocking proposed claims.") and `control_assessor` ("…return observations with
  citations."); `assessment.py:113-117` (the reviewer is blinded and asked to assess the
  obligations afresh with no claims supplied; both return the turn contract, not observations).
- Proposed fix: reword both role records to the blinded fresh-assessment task and the turn
  contract.

### F8 — doc drift: settings table and parser description

- Files: `docs/operations/owasp-control-assessment.md:48` says the closed parser rejects missing
  keys; `src/appsec_review/config/owasp.py:36-40` makes `max_discovery_files` and
  `max_discovery_bytes` optional with defaults. `docs/operations/owasp-control-assessment.md:71`
  describes `parser_versions` as versioned fingerprint inputs; no key exists for
  `owasp-proof-obligations/2` or `owasp-complete-source-subjects/1`, and no code checks that the
  TOML values (`evidence_binding = "2"`, `result_validator = "3"`, …) match the constants
  `EVIDENCE_RULE`, `RESULT_RULE`, `SELECTION_RULE`, `VERSION`.
- Proposed fix: mark the two keys optional in the table, add the two missing versions, and assert
  TOML/constant parity in `_validate_config` or a unit test.

### F9 — doc drift: artifact listing

- Files: `docs/operations/owasp-control-assessment.md:104-105` lists "selection, classification,
  applicability, batches, model results, independent review, join, publication and metrics".
- Evidence: the run's `artifacts/owasp-workbench/` holds `standards-manifest.json`,
  `selection.json`, `component-classifications.json`, `applicability.json`,
  `validation-work.json`, `finding-packages.json`, `verified-results.json`,
  `control-results.json`, `owasp-workbench-result.json`; model results live under
  `steps/validation/tasks/cell_0N/result.json` and `data/indexes/owasp/receipts/`.
- Proposed fix: list the file names and where cell results and receipts live.

### F10 — improvement: `not_assessed` rows are projected into every review package

- Files: `src/appsec_review/jobs/job_review_data_indexing/job.py` precompute `control_evidence`;
  `src/appsec_review/review/lead_families.py:666-676`.
- Evidence: run `2026-11-14-0003`: `control_evidence` has 277 facts and 273 relations, all for
  rows whose status is `not_assessed` (273) or `cannot_verify` (4). Each of the 562 hunt and 562
  lead packages carries 5 `precomputed_fact` context entries whose payload says "no reviewed
  versioned proof procedure for this selected control" and whose `workbench_reference.query` is
  `query_owasp_workbench family=control-result`. That is context budget spent on rows with no
  information for a C/C++ target.
- Proposed fix: project only dispatched or lead-eligible rows into package context; keep the
  unresolved rows in the coverage ledger.

### F11 — doc drift: the workbench query tool is advertised to workers who cannot call it

- Files: `src/appsec_review/review/capability.py:36-37,47` (`query_owasp_workbench` is excluded
  from `IN_PROCESS_TOOLS`); `datasets.py:27` (route string names it); every `workbench_reference`
  in packages names it; `docs/architecture/owasp-control-workbench.md` says consumers re-open the
  authority.
- Evidence: 0 `query_owasp_workbench` retrievals in 1,226 review cells; retrievals used were
  `query_syntax` 703, `query_observations` 205, `query_codeql` 91, `query_build_security` 76,
  `query_precomputed` 23, `query_hotspots` 20, `query_artifacts` 14, `query_code_graph` 12,
  `query_debug_symbols` 9, `query_ci_configuration` 2. The application resolves control records
  through `load_control_assessment`, not the model.
- Proposed fix: document the workbench as application-side, and route package references through
  `query_precomputed query_set=control_evidence` only.

### F12 — improvement: verification pool and serial review

- Files: `job.py:247-270` (one `independent_review` unit reviews all batches serially, building a
  new `EvidenceResolver` and re-accepting the manifest per batch at line 263);
  `src/appsec_review/orchestration/dagster/adapter.py:139-140` (`verification` and `join` map to
  pool `owasp_verification = 2`).
- Proposed fix: partition verification into cells like validation, or set the pool to 1 and build
  the resolver once.

### F13 — improvement: private retrieval API use

- Files: `evidence.py:134` (`self.core._database(...)`).
- Proposed fix: expose a public `RetrievalCore.payload(identity, shard)` and use it.

## What the recent enhancement changed (behaviour)

Commits since 2026-11-01 touching the job, by behaviour, not title:

- **Complete-subject selection (fdb85e69, afc7c1b8, 441f5836, T-146 slice A).** Evidence binding
  moved from "first `max_source_lines` lines of each file" to parsing accepted Python files once
  (`subject_selection.parse_subjects`) and selecting complete functions or a complete module as
  subjects, preferring subjects that accepted syntax/graph index locations point at. Discovery is
  bounded per component by the new `max_discovery_files` (512) and `max_discovery_bytes` (8 MiB)
  settings; supported (`.py`) files are ordered before unsupported ones so other languages do not
  starve the four procedures; every omission is a named gap with a count. HTTP-route subjects keep
  the whole module when it fits (so middleware/guard context is visible) and a route function cut
  from an oversized module cannot establish an authorization obligation
  (`assessment.py:373-376`). Evidence binding rule became `owasp-evidence-binding/2`, acceptance
  `owasp-assessment-acceptance/3`, obligations `owasp-proof-obligations/2`; the resolver records a
  `source_subject` with `complete` and `outside_lines`.
- **Graph-derived routing context (6457fbf2, 1007ba46).** Security tagging now derives capability
  tags from accepted graph sites with a `declared`/`invoked` basis; `characterize_components`
  maps `func:*` capability tags to component roles (`engine.py:29-46,137-146`) while recording that
  tags route context and prove nothing. Packages and the package view carry the OWASP
  `workbench_reference` and the actionability fields consumed downstream.
- **Contract repairs (1f40f7aa, 055bf1f6).** The contract declares every producer the tags
  manifest can embed; `debug_symbol_indexing` publishes `producer.job`. See F3 for the cost.
- **Unchanged.** The five procedures (four Python static, one MASVS runtime placeholder), the
  blinded reviewer design, the turn contract and `validate_final`, the deterministic join, the
  shard families and the receipts keying.

## Code versus documentation and typed configuration

- `appsec-review.toml:2675-2720` matches the operations table defaults (`asvs_level 2`,
  `masvs_profile L2`, `max_*` bounds, `reviewer_profile = "reviewer"`, worker and reviewer both
  `claude-cli`/`claude-haiku-5-5`/`medium`/24000/6000/120 s/1 retry); the parser bounds in
  `config/owasp.py:66-78` match the "Allowed" column. Profiles `profiles/prod.toml`,
  `profiles/copilot-prod.toml`, `profiles/copilot-dev.toml` override only the two model profiles,
  consistent with "enabled by default across all shipped profiles".
- `_validate_config` (`job.py:61-78`) enforces topology order against the TOML steps/tasks, the
  enabled gate, complete catalogs in assessment mode and a supported provider for both selected
  profiles. `masvs_profile` is validated to `L1`/`L2` and both select all 24 MASVS controls, as
  documented.
- Mismatches: F7, F8, F9, F11 above. The architecture doc's "exactly four reviewed Python static
  procedures" is correct; `PROCEDURES` has a fifth, `MASVS-NETWORK-1`, which the doc describes
  separately as always `cannot_verify`.
- Unverified: the doc's claim that worker and reviewer requests emit standard model start and
  terminal events (`docs/operations/owasp-control-assessment.md:119-121`) could not be checked on
  this run because no model call happened; code path `assessment.py:234` wraps `infer` in
  `recorded`.

## Contract and dataset discipline

- **Reads.** The job reads upstream only through the claim-pinned context manifest
  (`resolve_context_manifest`, `job.py:103-106`) and `accept_manifest`/`RetrievalCore`, which pass
  every opened shard through `observe_shard` against the claim's `upstream_handoffs` and the typed
  contract (`runtime/inputs.py:348-373`). No `latest.json` is read. The job never calls
  `accepted_upstream` for a producer handoff directly; the manifest path is the read boundary. The
  target snapshot check at `job.py:97-99` ties accepted evidence to the authenticated target.
- **Producers of embedded shards.** Every producer the tags manifest embeds is declared (F3 shows
  the cost of how). The job's own published manifest (`owasp-index-manifest/1`) binds
  `accepted_upstream_manifest` (path, sha256, target snapshot) and `configuration_sha256`
  (`indexes.py:63-91`), and review data indexing refuses a manifest not bound to the accepted
  handoff (`job_review_data_indexing/job.py:173-177`).
- **Dataset declarations.** `DATASETS` (`datasets.py:14-32`) claims receipts, the six shard
  families plus manifests and `accepted.json`, and the attempt's `artifacts/owasp-workbench/*.json`.
  Run `2026-11-14-0003`: review data indexing's audit `PASSED`, 0 violations, 0 warnings, 0
  unaccounted files, 18 OWASP inventory rows.
- **Terminal status.** Values are `ProducerStatus` members but are written as literals, and gaps
  are free text (F4).

## Worker side

- **What the control assessor is asked.** Governing rules, the role record, the persona fragment
  sections (Viewpoint, Effective controls, False positives, Evidence by predicate, Hand-offs) for the
  control domain, the task "Investigate the named obligations using only accepted evidence and
  bounded expansion. Return the task's structured turn contract; unknown is not a failure.", the
  `effective-control-verification` runtime skill, and the structured task input: cleaned packages
  (control text, component roles and evidence, `evidence_references` with excerpts, proof
  obligations with invariant, prerequisites, criteria and static limits), the turn contract
  (`retrieve` or `final`), capability limits and remaining budget (`assessment.py:180-215`).
- **What the independent reviewer is asked.** The same, with the task "Independently assess the
  underlying named obligations and accepted evidence. No previous worker conclusion is supplied."
  and the `predicate-verification` skill; a fresh request context, no transcript
  (`assessment.py:415-418`).
- **Bounded evidence.** Only accepted-index entities the resolver materialised for the component
  (`component_evidence`, `evidence.py:381-487`), capped by `max_evidence_per_component`,
  `max_source_lines` and a 16,000-character excerpt, with secrets redacted. Expansion requests must
  name an identity already in the batch's evidence (`assessment.py:316-322`) and are capped by
  `max_queries`; each turn is capped by `max_turns` and the profile timeout.
- **Verdict validation.** `validate_final` (`assessment.py:63-107`) requires exactly the dispatched
  rows and supported obligations, a closed field set, bounded strings, at most 12 citations and 4
  hypotheses, and a closed severity vocabulary. `accept_obligations` (`assessment.py:342-398`)
  re-resolves every citation against the accepted manifest, binds it to the obligation's named AST
  subject, rejects truncated, redacted, ambiguous or incomplete subjects, downgrades any
  `satisfied`/`not_satisfied` with assumptions, evidence requests or missing resolving citations to
  `cannot_verify`, and forces `cannot_verify` for runtime obligations. `run_batch` requires the
  blinded reviewer to agree before a `satisfied` stands (`assessment.py:440-441`).
- **Can an answer widen its authority?** Not on scope: unknown rows, obligations, actions,
  identities and fields are rejected, and `validate_final` of a cached receipt is re-run on
  reuse. The remaining lever is F6: an adverse verdict and its model-chosen hypothesis severity
  survive reviewer dissent or absence into lead production, labelled provisional.

## Run `2026-11-14-0003` observations

Source revision: main checkout at `515300d5` (contract fixes present, T-146 absent). Target
snapshot `50399744…`; smoke-cpp. Attempt `attempt_0001`, `COMPLETED_WITH_GAPS`, accepted.

| Item | Value |
|---|---|
| Duration (status.json) | 119,631 ms |
| Step durations | standards 5.9 s, characterization 17.1 s, applicability 0.7 s, batching 5.8 s, validation 6.1 s, verification 4.5 s, join 0.8 s, publication 7.5 s |
| Components | 1 (`component:0001`), roles `[]`, confidence `low` |
| Selected rows | 277 (249 ASVS L2 + 24 MASVS + 4 ASVS conditional) |
| Applicability | 273 `unsupported_missing_evidence`, 4 `conditional` (V1.2.4, V6.2.1, V8.2.1, V8.3.1) |
| Control status | 273 `not_assessed`, 4 `cannot_verify` |
| Verification status | 273 `not_required`, 4 `pending` |
| Batches | 3, all `terminal_state: failed` (no supported obligation), 0 admitted-cap exclusions |
| Model calls / attempts / retrievals / reuse | 0 / 0 / 0 / 0 |
| Input retrieval metrics | attempts 122, denials 0, missing 0, truncations 34 |
| Shards published | 10 (standards 1, component-classification 1, applicability 1, control-result 1, validation-work 3, finding-package 3) |
| Gaps in result | 614 (mostly upstream shard limitations echoed per component, plus "reviewed site recognition supports only Python source" for every file) |
| Lead-eligible rows | 0 |
| OWASP pipeline events | 3 `OWASP_WORKER_STARTED`, 3 `OWASP_WORKER_COMPLETED`, 1 `OWASP_VERIFICATION_COMPLETED`, 1 `OWASP_ASSESSMENT_RECORDED` |
| Downstream | `control_evidence` 277 facts, 273 relations; 0 `owasp_control` leads; 5 OWASP facts in each of 562 hunt and 562 lead packages |
| `query_owasp_workbench` retrievals in review cells | 0 of 1,226 cells (tool not grantable to cells) |

## The value question

- **Do assessments cite resolving source lines?** In this run nothing was assessed, so no. The
  four `cannot_verify` rows carry 60 whole-file `source_file` references each (pre-T-146 binding)
  whose only content is the file's first 120 lines, and gaps naming every non-Python file. Nothing
  restates scanner facts either; the OWASP output for a C/C++ target is coverage accounting only.
- **By design,** a result that does assess cites `owasp-evidence-reference/1` records bound to a
  named AST subject with file, hash, line span and byte columns (`obligations.py:384-395`), which
  is a resolving source line, plus the obligation's invariant and criteria. That is the right
  shape for a developer; it exists only for four ASVS controls in Python.
- **What would make it actionable:**
  1. Procedures for the languages the targets are written in (the smoke targets are C/C++, Go,
     Java, JavaScript, PHP, Python, Ruby, Rust, C#); today only Python has recognisers.
  2. F1 and F2, so a supported subject actually reaches a model within budget and "no subject" is
     not reported as a failed worker.
  3. A developer-facing projection per adverse or satisfied row: control id and text, subject
     `path:lines`, verdict, the one-paragraph rationale, the cited lines, the reviewer's agreement
     or dissent, and the gaps, rather than the 277-row ledger.
  4. Keep `not_assessed` rows out of package context (F10) and in a coverage summary that states
     per control family and language why nothing was assessed.

## Focused unit tests

Command (worktree `~/projects/appsec-review-owasp-review`, venv `.venv`, HEAD `1a154efb`):

```
.venv/bin/python -m pytest tests/test_owasp_assessment_job.py tests/test_owasp_catalog_integrity.py \
  tests/test_owasp_downstream.py tests/test_owasp_evidence_binding.py tests/test_owasp_indexes.py \
  tests/test_owasp_proof_procedures.py tests/test_owasp_telemetry.py tests/test_owasp_workbench.py \
  tests/unit/job_owasp_control_assessment tests/test_consumes_parity.py \
  -q -p no:cacheprovider --basetemp=test/tmp/owasp-review -n 4
```

Result: **505 passed, 40 failed, 5 errors**, 5 warnings, elapsed 864.96 s (14:24). 67 cases ran
over 10 s; the slowest were `test_owasp_assessment_job.py` end-to-end cases (55.8 s, 52.4 s,
47.5 s, 43.6 s, 41.8 s, 35.9 s, 32.7 s, …). Junit: `test/tmp/owasp-review-junit.xml`; log:
`test/tmp/owasp-review-pytest.log` (worktree-local, not committed).

This branch changes no code, so every failure is pre-existing on `1a154efb`. Grouped by error
line:

| Count | Error line | Where | Likely attribution |
|---:|---|---|---|
| 27 + 5 errors | `ValueError: OWASP manifest is not bound to its accepted producer handoff` | `tests/test_owasp_downstream.py` (via `job_review_data_indexing/job.py:177`) | stale fixture: the downstream fixture publishes a workbench manifest without listing it in an accepted OWASP handoff |
| 3 | `AttributeError: 'types.SimpleNamespace' object has no attribute 'cell_id'` | `tests/test_owasp_telemetry.py::test_review_guard_reports_real_dispatch_and_checks_budget_first[*]` | stale fixture: the request stub predates `cell_id` on model requests |
| 3 | `IntegrityError: review execution contract failed: AttributeError` | `tests/test_owasp_telemetry.py::test_review_cell_terminal_metrics_cover_reuse_and_not_launched[*]` | same stub |
| 2 | `assert 'unresolved' == 'independently_assessed'` | `tests/test_owasp_assessment_job.py:156` (`test_real_job_calls_worker_and_blinded_reviewer_over_accepted_tagged_evidence`, `test_partial_resume_reuses_worker_but_performs_missing_independent_review`) | expectation drift after T-146: fixture excerpts are whole-file spans, so `accept_obligations` now rejects them as incomplete subjects and the row stays `cannot_verify` |
| 1 | `assert 'cannot_verify' == 'satisfied'` | `tests/test_owasp_assessment_job.py:263` | same cause |
| 1 | `assert 'truncated' in 'ValueError: incomplete, redacted or ambiguous evidence cannot establish an obligation'` | `tests/test_owasp_proof_procedures.py:412` | message changed with `owasp-assessment-acceptance/3` |
| 2 | `AssertionError: {'validation.cell_04': 'Traceback … ValueError: scripted malformed response'}` | `tests/test_owasp_assessment_job.py:135` (`test_provider_and_output_failure_are_named_gaps_not_results[error1]`, `test_qualification_is_explicit_and_never_eligible`) | needs attribution: a transport raising a bare `ValueError` escapes `investigate`'s `except (ModelOutputError, ProviderError, TimeoutError, …)` (`assessment.py:255`) and fails the cell instead of becoming a named gap. Either the test should raise `ModelOutputError`, or the seam should classify unexpected transport exceptions |
| 1 | `assert False` (no routing record matched) | `tests/test_owasp_evidence_binding.py:424` | not attributed |
| 5 more | assorted (`test_configured_source_cap_survives_publication_and_projection`, `test_independent_disagreement_stays_visible_and_provisional`, `test_authentic_unrelated_evidence_cannot_prove_the_named_subject`, …) | `tests/test_owasp_assessment_job.py` | most likely the T-146 fixture drift above; not individually confirmed |

The merge base is the reviewed commit itself, so no second run was needed for attribution. The
`tests/unit/job_owasp_control_assessment/` cases (T-146 units) and `tests/test_consumes_parity.py`
all passed. The 45 failing cases mean the end-to-end OWASP tests on `main` do not currently
establish the job's behaviour; fixing the fixtures is the first repair this review recommends.

## Not verified

- Model start/terminal telemetry for worker and reviewer requests (no model call in the run).
- Behaviour of the T-146 subject selection on a real Python target (no such run on this host).
- Lead production from a `dissent`/`pending` adverse verdict (code path only).
