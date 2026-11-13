---
title: "Development package 04 - Consistent worker guidance and artifact contracts"
kind: "task"
subsystem: "review inference and guidance"
status: "historical"
jobs: []
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Development package 04 - Consistent worker guidance and artifact contracts

## Authorization and assignment

User authorization, quoted verbatim: "I agree with 1,2,3,4,5 and the mcp / skill recomendations. please create a detailed instruction prompt for each  to implement them on independent working trees. They should be fully covered with unit tests. There should be intergration and acceptance tests (but do not run them due to time constraints). when complete and tested the code should be merged back to local main. These tasks can run as top level independent chats and do not need to be monitored or supervised. Ensure all of these are included in their respective development package. Run those chats/tasks/workers on the Model GPT 6 Astra High 1M context window."

Implement recommendation 4: complete effective prompt contracts for every dispatched worker, a generated Capability & Artifact Card, and realistic offline prompt-competence tests. Save this whole development package in docs/tasks/2026-11-06-worker-prompt-contracts.md before implementation and append a completion/verification/local-main record. Work as an independent top-level autopilot session; do not rely on a parent supervisor. Any necessary bounded subagents must also use GPT-6 Astra/high/long-context. No live model calls, deployments, remote pushes or PRs.

## Base/environment

wsollers/appsec-review, reviewed at 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5. Verify ancestry and read current files plus AGENTS.md and .claude/skills/multi-session-coordination/SKILL.md. Use an isolated Linux/WSL Linux-filesystem worktree and own venv; Ubuntu-22.04 is available. Do not test in the Windows primary checkout. Canonical configured local main is F:\XBOX-Repositories\appsec-review; integration must reach that main through the permitted existing local procedure, not merely a companion mirror.

## Ownership

Own guidance/, pipeline/guidance and pipeline/prompt-fragments and related runtime skills; guidance-loader functions for specialized jobs; model-facing request/card rendering in inference/request.py; new prompt evaluation cases/harness extensions and prompt tests. Source paths are under src/appsec_review unless otherwise stated. Package 03 owns provider mechanics, retries, budgets, review-cell execution and specialized model loops. In shared files, edit guidance functions/request construction only and preserve their calling interfaces. Prefer a shared renderer seam rather than rewriting the execution loop. Package 05 owns longitudinal quality aggregation, not your per-case competence harness. Package 06 owns repository-development skills under .claude, not runtime skills. 02 owns global testing configuration and dependencies. Do not depend on unpublished APIs from those packages.

## Verified facts - avoid implementing nonexistent gaps

- Main review personas are detailed. api_web and deployment_operations map to rich personas; dependency_repository_investigator and native_dependency_analyst also load substantive files outside their short registry entries. Preserve these mappings.
- Cells already expose exact tool parameter schemas, initial capability limits, remaining_queries, remaining_turns and final_required. Standardize/reuse this rather than creating a competing budget counter.
- The independent scorer is deterministic code with evidence-bound factors; do not add an LLM scoring rubric or tools to it.
- Review cells are tool-free model transports with application-mediated retrieval, not direct MCP clients. OWASP direct workbench retrieval is intentionally MCP-only; accepted control_evidence projections reach cells. Missing evidence never proves safety or vulnerability.
- Dependency repository resolution currently pins persona/role/task/skill but omits the common governing-rules file, repeating restrictions elsewhere. Specialized guidance publication formats differ. Consolidate faithfully.

## Required implementation

1. Inventory every actually dispatched model worker and document its effective role, viewpoint, task schema, governing rules, selected procedures, retrieval capability, evidence contract, missing-evidence behavior and bundle identity. Test completeness of effective contracts, not that every registry entry has a separate Markdown file. Non-dispatched/deterministic roles must be identified as such.
2. Use one common governed bundle publication/verification mechanism with explicit job-selected sections and versioned compatibility. All workers must receive shared governing rules through the same authenticated assembly contract. Preserve old immutable bundles; do not rewrite their bytes. Remove unnecessary duplicated policy prose where a generated block is authoritative, but retain useful examples and role-specific responsibilities.
3. Generate a bounded Capability & Artifact Card from trusted admitted state. Include only that worker's available and unavailable datasets, producer and accepted identities, allowed retrieval operations and exact schemas, citation format, evidence authority (direct/context/provisional), relevant scope and missing/truncated coverage, plus current limits/remaining budgets when available. Do not enumerate the whole run or grant access through prose. No target-owned guidance, private outputs, hidden opposing reasoning, credentials, raw protected artifacts, or irrelevant dataset metadata should leak.
4. Make citation contracts consistent: cell-local labels or admitted logical identities for review roles; the exact permitted reference format for specialized workers. Do not globally replace labels with filesystem paths. Ground citation shape in output schemas and validators; ensure good/bad examples actually match each contract.
5. Strengthen genuinely thin specialized guidance only where an evidenced gap exists: build reproducibility/abstention, component-local version identity, ambiguous evidence and failed producers. Preserve concise prompt budgets and domain-specific false-positive conditions; do not inflate every persona or create another swarm.
6. Extend prompt evaluation beyond one no-tool turn. Add deterministic scripted multi-turn cases exercising retrieval selection, paging/truncation, denial recovery, remaining budget/final turn, missing artifacts, wrong citations, misleading untrusted text, false-positive controls and justified abstention. Use production bundle assembly and authorization boundaries. Model-quality claims require later live acceptance; scripted unit fixtures must not be represented as live efficacy.
7. Correct directly related documentation contradictions, including root AGENTS.md's deferred-signing language versus implemented launch enforcement, without changing signing policy. Keep repository-agent and runtime-worker guidance separation intact. Do not add the package-06 development skills here.

## Unit tests to implement and RUN

Every effective worker family must have a real assembled prompt test and bounded positive/negative examples. Cover registry migrations, rich dependency personas, forbidden authority widening, unlisted tools, optional/missing datasets, out-of-scope references, selected-skill-only hash changes, common governing-rule inclusion, immutable legacy bundle compatibility, deterministic card order/hash and byte limits, denied raw artifacts, no hidden-role reasoning, valid/invalid citations, exact schemas, existing remaining-budget fields, and each multi-turn competence case. Reuse tests/test_guidance_compose.py, test_guidance_procedures.py, test_guidance_examples.py, test_review_guidance_execution.py and skill-separation tests where appropriate. Do not fake the composition/authorization being tested.

## Integration/acceptance tests to WRITE but NOT RUN

Create tests that wire accepted producer shards into actual worker-card assembly and application-mediated retrieval across review, dependency, build and remediation families. Add acceptance fixtures for benign/vulnerable/incomplete cases across multiple domains, and an opt-in live-provider evaluation entrypoint with explicit model/config/corpus identities and quality metrics. Keep integration/acceptance/live separate from normal unit collection. Do not execute these tests, models or a review run; document exact future manual commands and limitations.

## Completion and integration

Run the smallest comprehensive affected unit selection in your isolated Linux environment with a unique basetemp under test/tmp. Record exact source revision, commands, elapsed times, outcomes and coverage gaps. Commit the complete implementation/tests/docs/package. Incorporate current local main into your worktree before landing and rerun directly affected units after conflict resolution.
You own merging this package into actual local main. All six packages must use the existing serialized integration procedure/lock; if none exists, use an OS-backed advisory appsec-independent-main-integration.lock in the canonical main Git common directory. Final main changes are single-owner operations; do not disturb active freezes, dirty main or another integration owner. Do not use destructive reset, force-checkout, ours/theirs wholesale conflict resolution, remote push or a periodic merge monitor. Verify the ready SHA is an ancestor of the resulting canonical local main. Final report names both SHAs, unit results, and integration/acceptance tests NOT RUN. Preserve ready work and state an exact blocker if safe integration cannot be completed; do not ask the originating chat to monitor you.

## Execution record

- Base ancestry verified: HEAD equals `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`.
- Dedicated Ubuntu-22.04 Linux-filesystem worktree:
  `/home/wsollers/copilot-worktrees/worker-contracts-d23ca33f`, with its own `.venv`.
- Branch: `william-sollers-xbox-worker-prompt-contracts`.
- Package saved before implementation. Runtime and development guidance remain separate.
- Initial `python3 -m venv .venv` failed because the default Python 3.10 lacks ensurepip and
  is older than the project's Python >=3.11 requirement; use the existing Linux uv/Python 3.12.
- Integration limitation to resolve: this worktree session may not directly read or write the
  canonical main checkout. Use an existing permitted integration owner/procedure, or preserve the
  ready commit and report that exact blocker without claiming a companion mirror is canonical main.

## Implementation completion

Implemented the [effective worker inventory](../architecture/worker-prompt-contracts.md), common
versioned selected-section publication, read-only legacy compatibility, and generated bounded
Capability & Artifact Cards. Dependency repository resolution, build planning/repair and
post-build workers now include the common governing rules. Native plan and metadata output
contracts are separately pinned while retaining first-use snapshots. Rich persona mappings,
deterministic scoring and application-mediated retrieval are preserved.

Added realistic scripted multi-turn competence cases using real accepted indexes, composition,
authorization, retrieval and citation expansion. Model scripts are test fixtures, not live
quality evidence. Added manual cross-family integration and opt-in acceptance/live entrypoints;
none was run. Corrected the obsolete signing and runtime-procedure documentation without
changing signing policy.

Two related existing test inventories needed repair rather than weakened admission:
the dependency API assertion omitted already-dispatched curation/metadata stages, and the OWASP
repin fixture replaced a complete handoff with an incomplete/stale artifact/result binding.
The latter now regenerates complete synthetic producer accounting through `write_fixture_handoff`;
real admission and citation validators are not faked.

## Development verification

Environment: private Linux `.venv`, Python 3.12.15; editable import resolved inside the isolated
worktree. Only missing dependencies were installed (`uv pip install --python .venv/bin/python
-e .[test]`). The initial system Python 3.10 venv failure and one shell-quoting failure preceded
successful environment setup; neither executed tests or product models.

Development runs below used HEAD `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5` with the evolving
package working diff. They are diagnostic results, not claims about a frozen revision. Final
immutable-revision evidence is recorded separately after the implementation commit and incorporation
of current canonical main. Times are pytest-reported elapsed seconds.

| Run | Selected unit scope | Basetemp under `test/tmp/` | Result | Seconds |
| --- | --- | --- | --- | --- |
| G1 | guidance compose/procedures/examples, review guidance execution, skill separation | `pkg04-guidance-first` | 122 passed, 12 migration failures, 13 pre-dispatch fixture errors | 103.61 |
| G2 | G1 without review guidance execution | `pkg04-guidance-migration` | 109 passed | 7.75 |
| S1 | native inference runtime, remediation models, PoC writer, review request, Anthropic and CLI inference | `pkg04-specialized-first` | 108 passed, 6 migration failures, 2 provider/parser failures | 13.26 |
| C1 | new worker/card units, native runtime, remediation models, PoC writer, build guidance publication | `pkg04-contracts-first` | 156 passed, 3 assertion-migration failures | 18.84 |
| C2 | C1 plus review cell units | `pkg04-contracts-second` | 197 passed | 18.15 |
| U1 | complete guidance/card/competence/cell selection below | `pkg04-unit-union` | 346 passed | 43.03 |
| O1 | native curation/metadata and focused dependency, post-build and repair validators | `pkg04-output-contracts` | 173 passed, 1 outdated dependency inventory assertion | 6.58 |
| R1 | new worker/card units, remediation models and dependency inventory/resolution | `pkg04-render-final` | 86 passed | 5.70 |
| W1 | OWASP telemetry and evidence binding | `pkg04-owasp-contracts` | 37 passed, 57 fixture-admission failures | 13.14 |
| W2 | OWASP binding, stopping at three failures | `pkg04-owasp-binding-fixed` | 3 failures; partial repin correctly rejected stale producer result | 2.18 |
| W3 | OWASP binding with complete producer republishing | `pkg04-owasp-republication` | 64 passed | 42.27 |
| Agent | new competence units only | `pkg04-competence` | 28 passed; earlier 24/28-case iterations also passed after fixture assembly corrections | 21.83 |

Exact U1 command (the smaller runs above select the corresponding listed files/cases with their
recorded unique `--basetemp`; failures were investigated before narrowing):

```sh
.venv/bin/python -m pytest -q tests/test_worker_prompt_contracts.py tests/test_capability_artifact_cards.py tests/review/test_prompt_competence.py tests/test_guidance_compose.py tests/test_guidance_procedures.py tests/test_guidance_examples.py tests/test_skill_separation.py tests/test_prompt_numeric_reasoning.py tests/test_native_inference_runtime.py tests/test_remediation_models.py tests/test_poc_writer.py tests/test_review_model_request.py tests/review/test_cells.py --basetemp=test/tmp/pkg04-unit-union --tb=short
```

O1:

```sh
.venv/bin/python -m pytest -q tests/test_native_component_curation.py tests/test_native_metadata_investigation.py tests/test_dependency_intelligence.py::test_native_inference_is_injectable_and_pins_registered_guidance tests/test_dependency_intelligence.py::test_guidance_and_job_public_api_are_registered tests/test_post_build_security_assessment.py::test_inference_is_observation_until_evidence_validation_confirms_or_refutes tests/test_post_build_security_assessment.py::test_bounded_inference_records_tokens_and_validates_observations tests/test_project_build.py::test_image_repair_accepts_only_bounded_apt_package_sets tests/test_project_build.py::test_image_repair_environment_is_a_typed_family_allowlist tests/test_project_build.py::test_image_repair_dependency_restores_use_the_family_manager_on_accepted_manifests tests/test_project_build.py::test_image_repair_package_manager_selects_only_a_pinned_lockless_node_manager --basetemp=test/tmp/pkg04-output-contracts --tb=short
```

W3:

```sh
.venv/bin/python -m pytest -q tests/test_owasp_evidence_binding.py --basetemp=test/tmp/pkg04-owasp-republication --tb=short --maxfail=3
```

### Named gaps and ownership

- The 13 `test_review_guidance_execution.py` cases using `test_team_handler.prepared` failed
  before dispatch because the synthetic handoff froze configuration before the test configuration
  existed. Package 03 owns the fixture's complete configuration/upstream-handoff repair and its
  scripted lead-triage support. Package 04 leaves that fixture unchanged instead of duplicating
  unpublished work. The independent new competence/cell tests exercise actual authorization.
- `test_anthropic_parse_failure_retains_bounded_raw_response` and
  `test_anthropic_normalizes_only_unambiguous_missing_plan_schema` exposed provider/parser
  failures. Package 03 explicitly owns those fixes. Package 04 changes only rendering wrappers;
  it does not claim these parser tests passed.
- The competence corpus is synthetic and verifier-focused (native, authorization, deployment).
  No live efficacy, graph-retrieval quality, exploit confirmation or runtime remediation success
  is established. Missing acceptance/live execution is not evidence of safety.

### Manual tests: written, NOT RUN

Only AST syntax and documented path existence were checked for these entrypoints; no manual
test, provider, deployment or review run was executed.

```sh
.venv/bin/python -m pytest tests/integration/test_worker_prompt_contracts.py --basetemp=test/tmp/pkg04-manual-integration -q
.venv/bin/python -m tests.acceptance.test_prompt_competence --live --config appsec-review.toml --profile dev --provider claude-cli --model claude-haiku-5-5 --cases tests/fixtures/review_guidance/competence_cases.json --output runs/competence-live-YYYYMMDD-unique
```

The live arguments assert configured provider/model identities. Use the actual configured pair,
an intentionally approved live run, and a fresh output directory. The integration suite covers
producer/retrieval/card wiring, not end-to-end compiler execution or an accepted remediation.

## Local-main integration procedure

Canonical owner: session `f9628e8e-873f-4f72-8aca-3069fb9fe4af`, operating
`F:\XBOX-Repositories\appsec-review`. Its existing serialized procedure now uses the exclusive
`appsec-independent-main-integration.lock` in the canonical Git common directory. The earlier
build-topology hold was released. Do not establish a competing owner or lock.

Canonical history was imported read-only through a local Git bundle from the assigned app
worktree; no canonical checkout files were read or written by this session. The unpublished
implementation was rebased without conflicts onto
`0d2c6d7b8830436bda7eed3e2c66f89c6525a17d` (Package 02 plus its landing record).
No remote push or PR is authorized.

## Frozen post-rebase verification

Exact implementation revision: **`91fecdd2f875aa5ad89ae05340c671f1a7af2f21`**.
Private editable import:
`/home/wsollers/copilot-worktrees/worker-contracts-d23ca33f/src/appsec_review/__init__.py`.

**619 passed in 95.87 seconds.** Slowest individual test: 4.21 seconds (skill-separation source
scan). The next four were 3.60, 2.79, 2.48 and 2.46 seconds. No unit exceeded ten seconds.
This is the comprehensive affected selection, not a full repository or live-quality result:

```sh
.venv/bin/python -m pytest -q tests/test_worker_prompt_contracts.py tests/test_capability_artifact_cards.py tests/review/test_prompt_competence.py tests/test_guidance_compose.py tests/test_guidance_procedures.py tests/test_guidance_examples.py tests/test_skill_separation.py tests/test_prompt_numeric_reasoning.py tests/test_native_inference_runtime.py tests/test_remediation_models.py tests/test_poc_writer.py tests/test_review_model_request.py tests/review/test_cells.py tests/test_native_component_curation.py tests/test_native_metadata_investigation.py tests/test_dependency_intelligence.py::test_native_inference_is_injectable_and_pins_registered_guidance tests/test_dependency_intelligence.py::test_guidance_and_job_public_api_are_registered tests/test_dependency_intelligence.py::test_model_resolution_is_validated_and_never_exact tests/test_post_build_security_assessment.py::test_inference_is_observation_until_evidence_validation_confirms_or_refutes tests/test_post_build_security_assessment.py::test_bounded_inference_records_tokens_and_validates_observations tests/test_project_build.py::test_image_repair_accepts_only_bounded_apt_package_sets tests/test_project_build.py::test_image_repair_environment_is_a_typed_family_allowlist tests/test_project_build.py::test_image_repair_dependency_restores_use_the_family_manager_on_accepted_manifests tests/test_project_build.py::test_image_repair_package_manager_selects_only_a_pinned_lockless_node_manager tests/test_target_analysis_plan.py::test_guidance_bundles_are_group_scoped_immutable_and_reusable tests/test_owasp_telemetry.py tests/test_owasp_evidence_binding.py --basetemp=test/tmp/pkg04-post-rebase --tb=short --durations=5
```

Committed portable files and the final Linux working files are LF. Initial UNC file creation
produced CRLF in seven new portable files; `.gitattributes` correctly staged LF. Those working
files were normalized to the committed LF bytes before rebasing and before the frozen-revision
test run. Byte-pinned JSON fixtures were already LF and were not normalized. `git diff --check`
and changed-file `git ls-files --eol` were inspected.

Documentation command:

```sh
.venv/bin/python -m pytest -q tests/test_documentation.py --basetemp=test/tmp/pkg04-documentation --tb=short
```

The repository-wide link check failed in **0.87 seconds** on two existing links from
`docs/architecture/build-environments-and-execution-capture.md` into the intentionally absent
`targets/appsec-multi-vuln` checkout (`support/project-matrix.json` and `README.md`). Package 04
does not clone or alter a user target to satisfy documentation checks. Changed-document links
are checked separately. These missing target links are not caused by the worker-contract change.
The earlier named package-03 fixture/parser gaps remain explicit, not counted among the 619 passes.

<details>
<summary>Exact diagnostic commands for the development verification table</summary>

```sh
# G1
.venv/bin/python -m pytest -q tests/test_guidance_compose.py tests/test_guidance_procedures.py tests/test_guidance_examples.py tests/test_review_guidance_execution.py tests/test_skill_separation.py --basetemp=test/tmp/pkg04-guidance-first --tb=short
# G2
.venv/bin/python -m pytest -q tests/test_guidance_compose.py tests/test_guidance_procedures.py tests/test_guidance_examples.py tests/test_skill_separation.py --basetemp=test/tmp/pkg04-guidance-migration --tb=short
# S1
.venv/bin/python -m pytest -q tests/test_native_inference_runtime.py tests/test_remediation_models.py tests/test_poc_writer.py tests/test_review_model_request.py tests/test_anthropic_inference.py tests/test_claude_cli_inference.py --basetemp=test/tmp/pkg04-specialized-first --tb=short
# C1
.venv/bin/python -m pytest -q tests/test_worker_prompt_contracts.py tests/test_capability_artifact_cards.py tests/test_native_inference_runtime.py tests/test_remediation_models.py tests/test_poc_writer.py tests/test_target_analysis_plan.py::test_guidance_bundles_are_group_scoped_immutable_and_reusable --basetemp=test/tmp/pkg04-contracts-first --tb=short
# C2
.venv/bin/python -m pytest -q tests/test_worker_prompt_contracts.py tests/test_capability_artifact_cards.py tests/test_native_inference_runtime.py tests/test_remediation_models.py tests/test_poc_writer.py tests/test_target_analysis_plan.py::test_guidance_bundles_are_group_scoped_immutable_and_reusable tests/review/test_cells.py --basetemp=test/tmp/pkg04-contracts-second --tb=short
# R1
.venv/bin/python -m pytest -q tests/test_capability_artifact_cards.py tests/test_worker_prompt_contracts.py tests/test_remediation_models.py tests/test_dependency_intelligence.py::test_guidance_and_job_public_api_are_registered tests/test_dependency_intelligence.py::test_model_resolution_is_validated_and_never_exact --basetemp=test/tmp/pkg04-render-final --tb=short
# W1
.venv/bin/python -m pytest -q tests/test_owasp_telemetry.py tests/test_owasp_evidence_binding.py --basetemp=test/tmp/pkg04-owasp-contracts --tb=short
# W2
.venv/bin/python -m pytest -q tests/test_owasp_evidence_binding.py --basetemp=test/tmp/pkg04-owasp-binding-fixed --tb=short --maxfail=3
# Agent (same selector throughout its bounded implementation iterations)
.venv/bin/python -m pytest tests/review/test_prompt_competence.py --basetemp=test/tmp/pkg04-competence -q --tb=short
```

</details>

Only this verification record changes after the frozen implementation test. The integration
owner receives its final ready SHA/tree, the full changed-path list, local bundle and the evidence
above, and must append the observed canonical-main ancestry/landing record below.

### Current-main combined-tree revalidation

Canonical main advanced while verification was in progress, incorporating Package 06. The
unpublished package was rebased again, without conflicts, onto
**`1a627f23d904c0c86233c92b1ad6e2ef7d0e07a6`**. Neither root agent guidance nor the loaded
multi-session coordination skill changed across that main update.

Exact combined revision tested: **`b6964e2e053914391916af755cb0990d530af6e7`**.
The exact 619-case command above was repeated with the sole argument change
`--basetemp=test/tmp/pkg04-current-main`. Result: **619 passed in 93.11 seconds**.
Slowest individual call was **4.05 seconds**; the next slowest call was 3.22 seconds.
This includes actual accepted-shard card assembly, all specialized workers, offline multi-turn
competence, evidence citation re-resolution, and existing cell behavior.

Changed Markdown files were checked using the repository documentation test's `LINK` parser,
restricted to `git diff --name-only canonical/main...HEAD`: **all local links resolved**, in
0.011 seconds. The two repository-wide absent-target links remain the already recorded gap.
No integration, acceptance, live-provider or review-run validation was executed.

The final handoff adds only this record to the tested combined revision. Disposable package-owned
test directories are removed after verification; no user target, other checkout, image, service,
private output, or shared development environment is removed.

### Local-main landing outcome

Landed by the canonical Windows local-main integration owner (`F:\XBOX-Repositories\appsec-review`)
through its serialized gate.

- Ready commit: **`825627981a1c5bebbe1cc7cd64b9155c3be385ec`** (tree
  `083aa0d450363622902e534747964c44664b1dc2`). It was fetched from the package's local bundle
  `worker-contracts-ready.bundle` (sha256
  `0b4eaab8bd401b97f8778c612cc496290a4ef403134bb2f197d696bbe0612d1d`). The bundle verified, has
  prerequisite `1a627f23d904c0c86233c92b1ad6e2ef7d0e07a6`, and contains three linear commits with
  no merges, each carrying the Copilot co-author trailer.
- Pre-landing checks:
  - `git diff --check` against the base was clean.
  - None of the changed paths contain CR bytes.
  - All 44 changed paths match the handed-off list.
  - None of them overlap the single main-side commit since the base (`a79fe222`). That commit
    only appended a Package 06 documentation record.
- Canonical main before landing: `a79fe222e95d57fb336c7b18c557509089e52672`, a descendant of the
  ready commit's base. Landing was therefore an ordinary non-fast-forward merge.
- Gate:
  - An exclusive OS-backed handle (FileShare.None) was held on
    `appsec-independent-main-integration.lock` in the canonical Git common directory across the
    checks, the merge and the post-merge verification. It was released in `finally`.
  - Inside the lock: the branch was `main` at `a79fe222`; the tracked and untracked status was
    clean; there was no rebase, merge, cherry-pick, revert, bisect or index/HEAD lock in progress;
    and there was no active source freeze or competing owner. Hooks were disabled for the merge.
- Merge commit: **`5887bec4cfc919249300c3af410a77894e0968d8`** ("Merge worker-prompt-contracts
  (82562798)", Copilot co-author trailer), with parents `a79fe222` and `82562798`.
  - Tree `ab63a82dda1af46b8e82f64bf64e49651f20be0c`, identical to the `git merge-tree
    --write-tree` prediction. There were no conflicts.
  - `git merge-base --is-ancestor 825627981a1c5bebbe1cc7cd64b9155c3be385ec main` exits 0, and the
    checkout was clean after the merge.
- No tests were executed by the integration owner. The package's recorded unit evidence (619 passed
  on `b6964e2e`) covers the package code. The merged tree adds only Package 06 documentation
  records relative to that revision's base. Integration, acceptance, live-provider and review-run
  validation were NOT RUN. Nothing was pushed and no pull request was opened.
- This record is a documentation-only commit on top of the merge. Package 03 retains ownership of
  its provider/execution changes when they are later combined.