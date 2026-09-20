# Continuation prompt — G02 OWASP control workbench decision

Continue from branch `codex/g02-owasp-workbench-decision`.

This is a documentation/proposal-only G02 task. Do not edit runtime code, schemas, registry records,
graph/parity surfaces, generated views, tests, validators, Dockerfiles, launchers, or `TODO.md`.

## Task

Review and refine the OWASP control workbench proposal:

- `docs/decisions/ADR-0009-owasp-control-workbench.md`
- `docs/proposals/owasp-workbench/input-sources.proposal.yaml`
- `docs/proposals/owasp-workbench/workcells.proposal.yaml`
- `docs/proposals/owasp-workbench/task-series.md`

The intended pattern is: use gathered intel to decide if checks are needed, batch similar controls,
dispatch validator personas with explicit tools/evidence, and join into a validated applicability
and control-status model.

## Read first

1. `AGENTS.md`
2. `docs/agent-reader.md`
3. `appsec-review-process/TODO.md` — G02 and S03
4. `docs/design-parity-completion-plan.md` — G2
5. `docs/design-v3.md`
6. `docs/standards-checklist-validation-proposal.md`
7. `docs/persona-catalog.md`
8. `docs/intelligence-sources-and-jobs.md`
9. `appsec-review-process/04-asvs-masvs/prompt.md`
10. `appsec-review-process/04-asvs-masvs/config.md`
11. `appsec-review-process/04-asvs-masvs/subprompts.md`
12. `appsec-review-process/registry/job-templates/04-owasp-validation-worklist.json`
13. `appsec-review-process/registry/personas/owasp-validator.json`

## Exclusive file boundary

You may change only:

- `docs/decisions/ADR-0009-owasp-control-workbench.md`;
- files under `docs/proposals/owasp-workbench/`;
- this continuation prompt, only to append a final checkpoint.

## Acceptance

- Proposal remains non-runnable and proposal-only.
- OWASP standards/version/profile decisions are explicit or recorded as human gates.
- Applicability and control statuses are defined.
- Control work is batched by component/domain/evidence mode.
- Validator personas cannot publish findings/severity/compliance certification.
- Static-only evidence cannot satisfy dynamic/runtime controls.

## Verification

Run:

```text
python -c "import pathlib, yaml; [yaml.safe_load(path.read_text(encoding='utf-8')) for path in pathlib.Path('docs/proposals/owasp-workbench').glob('*.yaml')]; print('yaml ok')"
python -B appsec-review-process/validate_design_parity.py
python -B appsec-review-process/qualify_phase1.py --check-contracts
git diff --check
```

Commit on a dedicated branch and report branch, commit, files changed, validation results, and
remaining human gates.

## Final checkpoint — 2026-09-19

- Branch/base: `codex/g02-owasp-workbench-decision` from `90cebf1`.
- Scope remained documentation/proposal-only; no runtime, schema, registry, graph/parity, generated
  view, test, validator, Dockerfile, launcher, or `TODO.md` file was changed.
- Refined ADR-0009 and the proposal packet to define standards/profile/version selection gates,
  accepted raw-versus-derived intel lineage, evidence-backed applicability triage, deterministic
  checklist partitioning, bounded batch defaults, persona/tool/handoff boundaries, structured
  intercom, static/dynamic/manual evidence rules, the control-status taxonomy, dynamic-test request
  contents, wait-all failure accounting, and the final joined matrix/gaps/requests/report structure.
- Kept the packet proposal-only and non-runnable. A checklist gap cannot become a finding, severity,
  exploitability, runtime observation, remediation claim, or compliance certification.
- The supplied OWASP comparison location remained the literal placeholder `<OWASP_REPO_URL>`.
  Accordingly, the packet records only the user/repository-described partitioning idea and does not
  claim inspection of a specific upstream revision.
- Verification passed: proposal YAML load, design-parity validation, Phase 1 contract
  qualification, and `git diff --check`. Design-parity still reports the expected planned gaps,
  including the unapproved OWASP decision and unimplemented S03 worker surfaces.
- Remaining human gate: approve exact standard/test/crosswalk versions and storage/license policy,
  ASVS profile/level and tailoring authority, enabled optional families, applicability override and
  rescope authority, evidence/status and batch policy, dynamic/manual authorization authority, and
  report/finding-promotion policy before implementation.

## Final checkpoint — source snapshots and NVD feed decision — 2026-09-19

- User approved the current stable source policy and repository-root `data/` snapshot layout.
- Pinned for the first materialization task: ASVS 5.0.0, MASVS 2.1.0, MASTG 2.0.0, OWASP Top
  10:2025, API Security Top 10:2023, GenAI LLM Top 10:2026, and a dated/hash-addressed OpenCRE
  export. Exact upstream tags/commits are recorded in ADR-0009 and the input-sources proposal.
- Defined immutable `data/reference/` snapshots with raw/normalized content, license/usage text,
  hashes, extraction lineage, counts, and validation receipts. Engagements copy and pin the exact
  manifest into run-owned data and never follow a moving upstream or shared pointer.
- Defined proposal-only NVD JSON/API 2.0 asynchronous synchronization beneath `data/feeds/nvd/`:
  scheduler singleton plus exclusive lease/heartbeat writer lock, attempt staging, immutable
  snapshots, atomic `current.json` publication, coordinator-only stale-lock recovery, explicit
  staleness, and per-run snapshot pinning. NVD remains enrichment rather than target-match,
  reachability, exploitability, severity, or finding proof.
- No reference payloads or runtime downloader were added because this branch remains constrained to
  the documentation/proposal-only allowed files. Materializing `data/reference/` and implementing
  the NVD publisher are explicit follow-on implementation tasks T02A and T02B.
- Verification passed: proposal YAML load, design-parity validation, Phase 1 contract
  qualification, and `git diff --check`.
- Remaining decisions: ASVS profile/level and tailoring authority, component applicability for
  approved context families/mobile platforms, applicability override and rescope authority,
  evidence/status and batch policy, dynamic/manual authorization, report/finding-promotion policy,
  and NVD freshness/block-versus-gap policy.

## Implementation checkpoint — immutable references and NVD publisher — 2026-09-19

- Materialized and verified the approved OWASP/OpenCRE source set under `data/reference/` as
  content-addressed raw and normalized snapshots with exact source lock, hashes, counts, license
  lineage, and offline validation.
- Implemented the NVD JSON/API 2.0 publisher under `data/feeds/nvd/`: yearly-feed bootstrap,
  bounded last-modified API deltas, content-addressed blobs, immutable manifest chains, atomic
  last-good publication, and failed-attempt retention.
- Added a default two-hour UTC Dagster schedule, scheduler singleton tag, OS advisory writer lock,
  visible lease/heartbeat, and expired-lease recovery receipt. The API key remains an external
  deployment secret.
- NVD remains enrichment only. The publisher does not establish product matching, reachability,
  exploitability, severity, findings, or compliance, and it does not decide the outstanding
  per-engagement freshness/block policy.
- The workbench validator lifecycle remains unimplemented and blocked on the remaining T01 policy
  decisions before T03-T14 may proceed.

## Policy checkpoint — 2026-09-20

- Approved ASVS 5.0.0 L2 as the baseline; any departure remains a new named selection decision.
- Authorized one assigned applicability reviewer to make justified, cited, append-only row-level
  overrides and bounded rescope decisions within the approved engagement scope. Selection/profile,
  target-boundary, tool, or permission expansion still returns to the selection owner.
- Kept tunable bounded batches with defaults of 12 rows, five components, one primary evidence
  mode, and one primary validator role; each batch must record effective versioned limits.
- Disabled dynamic execution. The proposal retains an inert launcher/handoff boundary that can
  validate, deduplicate, and queue request artifacts only; launch attempts fail closed without
  contacting a target.
- Allowed structurally valid stale NVD snapshots with explicit age, freshness gap, and limitation;
  hash, lineage, structural, or missing-snapshot failures still block the affected input.
- Remaining gates are per-engagement optional-family/mobile scope, departures from L2 and profile
  tailoring, manual-observation authorization, remaining evidence/status policy, and report and
  finding-promotion policy. The workbench remains proposal-only and non-runnable.
- The next bounded implementation task is T03 accepted-intel lane-in; it does not require dynamic
  execution or a finding/report promotion decision.

## Implementation checkpoint — T03 accepted-intel lane-in — 2026-09-20

- Implemented the standalone offline lane-in worker and closed schemas for its request, run-owned
  artifact references, accepted input manifest, and gap output.
- The worker verifies ASVS L2 selection and exact OWASP/OpenCRE snapshot bytes; embeds the approved
  selection and manifests; accepts only hash-checked imports or accepted producer attempts; and
  rechecks upstream identity before atomic publication.
- Derived intelligence cannot be canonical evidence. Search/index artifacts are locator-only and
  stale indexes fail closed. Missing lineage, tampered artifacts/pointers, and non-L2 ASVS fail.
- Optional NVD input verifies the pinned manifest/blob chain. Valid stale NVD is retained with age,
  limitation, and `nvd-stale-accepted` gap.
- Dynamic execution, manual observation, network access, and target mutation remain disabled. No
  validator, dynamic launcher, registry/graph/parity surface, or generated view was activated.
- T04 applicability modeling is the next bounded implementation task. Reporting/finding promotion
  remains gated.

## Implementation checkpoint — T04 applicability model — 2026-09-20

- Implemented a standalone offline applicability worker and closed schemas for its request,
  citations, signals, decisions, override chain, complete matrix, applicable-control projection,
  and visible gaps.
- The worker verifies the accepted T03 pointer and artifact plus the exact selected ASVS/MASVS
  reference snapshots, then independently enumerates every selected control/component target.
  Caller-supplied target omission cannot reduce the matrix.
- Deterministic rules use exact-control, domain, then all-controls precedence. Missing or conflicting
  rules remain `cannot_determine`; no result is silently dropped.
- Technical `not_applicable` requires cited positive exclusion and adequate canonical evidence.
  `out_of_scope` is a distinct selection-owner decision. The signal vocabulary intentionally has no
  generic absence signal.
- Only the assigned applicability reviewer may add justified, cited, append-only row overrides.
  Invalidated prior decisions require bounded rescope actions, and override chains must preserve
  prior-status continuity.
- Outputs are published together as a locked immutable attempt and rechecked before publication.
  The worker makes no control-satisfaction, finding, severity, exploitability, certification, or
  runtime claim.
- No validator dispatch, batching, dynamic launcher, registry/graph/parity surface, generated view,
  or report promotion was activated. T05 control partitioning and batching is next.

## Implementation checkpoint — T05 control partitioning and batching — 2026-09-20

- Implemented the standalone offline T05 batcher, closed request/worklist/batch schemas, a tracked
  versioned default limits configuration, and its qualification fixture.
- The worker validates the complete accepted T04 artifact set, re-verifies every control row against
  its pinned standards snapshot, and permits linked MASTG tests only when the pinned test record
  names the assigned MASVS control.
- Deterministic proof routing uses exact obligation, control, domain, then family fallback, with
  component-specific routes taking precedence. Missing routes block; equal-specificity conflicts
  fail rather than selecting by input order.
- Batches preserve component group/trust role, domain, evidence/authorization boundary,
  tool/persona, standard/profile, and linked-test-family separation. The qualified default remains
  12 control-target rows and five components, with one primary evidence mode and validator role.
- Mixed-mode controls become obligation fragments in separate batches while retaining exactly one
  worklist assignment and a required later join. No fragment may independently issue the final
  control status.
- Every T04 row is accounted exactly once as a validator assignment, technical N/A, scope exclusion,
  or unresolved applicability gap. IDs and ordering are deterministic and accepted attempts are
  immutable and reusable only after full artifact validation.
- All batches explicitly remain non-dispatchable and execution-unauthorized. Dynamic routing is
  request-drafting only; manual observation, validator dispatch, control assessment, findings,
  registry/graph/parity changes, and report promotion remain inactive. T06 handoff/tool contracts
  are next.

## Implementation checkpoint — T06 through T08 offline boundaries — 2026-09-20

- T06 publishes immutable, deterministic, non-dispatchable validator handoffs with exact T03–T05
  lineage, closed tool/action contracts, hashes, and inert dynamic-request authoring.
- T07 validates supplied candidate assessment results against one exact newest T06 member, enforces
  exact fragment/obligation coverage and evidence sufficiency, and publishes immutable batch results.
- T08 validates supplied structured-intercom candidates against one exact newest T06 handoff and,
  when referenced, the exact newest T07 pointer/result/hash. Pre-result messages need no T07.
- T08 publishes locked immutable ledger snapshots and deterministic JSONL with pinned prior
  attempt/ledger/head/sequence state. Rejected/blocked attempts do not replace the accepted ledger;
  exact replay requires complete revalidation.
- Intercom is communication/provenance only. Challenges are proposals, locators are hints,
  crosswalk notices are routing metadata, dissent cannot replace a result, assistance cannot
  transfer authority, and inert dynamic candidates cannot authorize execution.
- No Dagster, lifecycle graph, registry, parity manifest, generated view, persona dispatch, target
  inspection, result join, T09 lifecycle, dynamic/manual execution, finding, or `TODO.md` surface
  was activated. T09 is the next dependency-ordered task.

## Implementation checkpoint — T09 dynamic/manual request lifecycle — 2026-09-20

- Implemented the standalone offline T09 request validator and immutable lifecycle ledger with
  closed publication, request-version, transition-authority, ledger, validation, and disabled-
  execution receipt schemas.
- Each request preserves exact T03–T06 lineage and proof-obligation identity. Optional T07 results
  and T08 messages are independently pinned and revalidated, but remain neither evidence nor
  transition authority.
- Deterministic request identity protects control, component, environment, identity/data, safety,
  and required-authority dimensions. Compatible exact requests deduplicate; cross-batch sources
  retain independent result authority.
- Baseline publication is limited to inert proposed, owner-canceled, and policy-blocked states.
  Authorized, executed, ingested, or reassessed records require a separately supplied exact state
  artifact from its newest accepted run-owned producer and still do not mean T09
  authorized/performed work or changed T07.
- Manual-observation requests are blocked. Execute/launch operations write only an immutable
  `dynamic_execution_disabled` receipt recording no contact, mutation, execution, or observation.
- Request versions and publication attempts are append-only and hash chained. Stale heads, skipped
  or reversed transitions, rewritten history, conflicting protected identities, circular T09
  authority, lost updates, secrets, unnecessary personal data, and prompt-injected scope/permission
  expansion fail closed without replacing accepted state.
- No Dagster, lifecycle graph, registry, parity manifest, generated view, persona dispatch, target
  access, assessment update, result join, finding promotion, or `TODO.md` surface was activated.
  T10 dispatch, wait-all, and failure accounting is next and remains dependency-gated.
