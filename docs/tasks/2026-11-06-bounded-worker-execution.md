# Development package 03 - shared bounded worker execution

User authorization, quoted verbatim: "I agree with 1,2,3,4,5 and the mcp / skill recomendations. please create a detailed instruction prompt for each  to implement them on independent working trees. They should be fully covered with unit tests. There should be intergration and acceptance tests (but do not run them due to time constraints). when complete and tested the code should be merged back to local main. These tasks can run as top level independent chats and do not need to be monitored or supervised. Ensure all of these are included in their respective development package. Run those chats/tasks/workers on the Model GPT 6 Astra High 1M context window."

Implement recommendation 3: consolidate model execution mechanics and fix demonstrated retry, usage, and replay inconsistencies. Save this complete package before implementation in docs/tasks/2026-11-06-bounded-worker-execution.md and append the implementation/verification/integration record. Work autonomously in this detached top-level session without reporting to the originating chat. GPT-6 Astra/high/long-context applies to necessary bounded subagents too. No remote pushes, PRs, actual model calls, live reviews, or deployments.

## Environment/base

Repository wsollers/appsec-review; reviewed baseline 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5. Verify ancestry, inspect current code, and follow AGENTS.md and .claude/skills/multi-session-coordination/SKILL.md. Use an isolated Linux/WSL Linux-filesystem worktree and its own environment; Ubuntu-22.04 is available. Never run tests in the shared Windows primary checkout. Canonical configured local main is F:\XBOX-Repositories\appsec-review; final integration must reach it via the permitted local procedure, not stop at a mirror's main.

## Ownership

Own inference dispatch/recording and new shared execution mechanics; review/cells.py execution/retry logic; review/budget.py and the _Guard/_run dispatch/budget portions of jobs/job_inference_security_review/teams.py; model execution loops in PoC, remediation, build planning/repair, native dependency inference and OWASP. Own associated unit and newly written integration/acceptance tests. All source paths are under src/appsec_review. Package 04 owns guidance assembly, persona/role/skill content, model-facing card rendering and guidance-loader functions in the same job files. Do not edit its guidance bodies or widen capabilities. Package 05 owns observability event aggregation/reporting; reuse the current common event API and preserve compatibility. Package 01 owns runtime graph/repair and CLI; 02 owns pyproject/global test configuration. Integrate narrowly by function when a file is shared. No dependency on an unpublished sibling API.

## Required behavior and boundaries

- Extract a small shared execution mechanism, not a universal autonomous agent framework. Preserve each job's distinct authority, allowed retrieval, blind inputs, output validation, missing-evidence behavior and repair policy. PoC's private readers need a capability contract, not automatic public MCP exposure. Deterministic scoring and attack-chain helpers must not become LLM workers.
- Inventory actual model loops first. Share deadline/cancellation handling, typed transport and schema failures, retry/backoff scheduling, response/turn bounds, usage accounting and immutable receipts. Migrate every genuine in-scope caller, not just review/cells.py, while preserving public calling interfaces where possible. Keep provider-specific authentication/SDK behavior at transport boundaries.
- The verified review retry backoff setting is parsed but unused. Implement cancellation-aware bounded backoff, distinguish transient transport failure from invalid output, and preserve first-error mode's no-retry semantics. Unexpected application/contract bugs must not silently become ordinary provider gaps; retain explicit error evidence.
- Fix recording/replay exception semantics: inference/recording.py currently recreates most errors as RuntimeError subclasses. Use a closed versioned error envelope that preserves timeout/cancellation/provider/schema categories and required bounded fields. Never import arbitrary exception classes or execute recorded commands. Preserve safe compatibility with prior recordings or reject unsupported semantics explicitly.
- Correct usage handling. Missing/invalid token usage is unknown, never zero actual usage. Distinguish actual usage, estimates/reservations, cache tokens, and replayed usage. Implement atomic in-flight budget reservations/settlement so concurrent launch admission follows documented bounds. Release reservations on failures/cancellation and reconcile abandoned ownership conservatively. Preserve actual spend even when a provider overshoots; do not label a soft launch limit a hard billed-cost guarantee.
- Add explicit active execution timing suitable for repair pauses while retaining cumulative usage and prior immutable receipts. Do not reset spent tokens or quietly reinterpret historical wall-clock runs. Define versioned budget timing/resume semantics and compatibility; use existing run/attempt evidence, and coordinate through public contracts rather than adding a competing runtime state machine.
- Share common correlated model-call telemetry with all migrated callers using the existing event facilities. Include request/guidance/attempt identities, retries and reason, timeout/cancel category, reported provider/model, and usage availability. Raw prompts, raw outputs, source text and secrets do not enter general telemetry. Fix subprocess.TimeoutExpired classification at the owned transport boundary without racing package 05's reporting code.
- Retain current blue-only memo semantics and blind verifier/judge independence. Garnet failures remain optional-cache misses with visible diagnostics. Do not add Rust or replace the cache service.

## Unit tests to implement and RUN

Cover each migrated caller with deterministic scripted Infer/retrieval boundaries and real shared-loop behavior. Cover final/retrieve turns, malformed output, authorized versus denied retrieval, repeated denials, no-evidence results, output and transcript bounds, max-turn final behavior, configured backoff timing with fake clock/sleeper, cancellation during wait/call/teardown, first-error no-retry, provider failure versus programming/integrity error, typed recorded timeouts and repeated identical requests, replay misses and malformed envelopes, no raw-content telemetry, missing/negative/noninteger usage, replay-not-billed accounting, concurrent reservations, provider overrun settlement, crash/abandoned reservations, paused timing versus cumulative cost, old budget state, memo reuse and independent-verifier isolation. Use thread/process unit fixtures only as bounded offline tests; no external services. Include existing tests/review/test_budget.py, result-cache, cell and relevant provider/recording tests in the focused selection.

## Integration/acceptance to WRITE, NOT RUN

Create explicit integration tests wiring several real job adapters through the shared engine with external provider/retrieval services replaced only at their actual boundaries. Add acceptance scenarios for an interrupted review, repair pause/resume, transient failures, malformed provider replies, cache outage and usage exhaustion with stable findings/gaps and truthful costs. Put suites under tests/integration and tests/acceptance, excluded from implicit unit collection; document future commands/prerequisites. Do not execute them, live models, Docker builds or a real review run.

## Completion and local-main merge

Document the stable execution API and migration/compatibility decisions, update directly related docs, and retain all behavior with focused regressions. Run smallest directly affected unit commands in your own Linux environment with unique test/tmp basetemp. Record exact revision, commands, elapsed times, results and honest remaining gaps. Commit all code/tests/docs and this package. Update your branch from current local main as needed and rerun the affected units on the combined tree.

You are the designated integration owner for your package. Use the repository's existing local integration procedure and common lock; if absent, all six packages use an OS-backed advisory appsec-independent-main-integration.lock in the canonical main Git common directory. Serialize final main updates only. Respect another integration owner, dirty main, source freezes, and semantic ownership conflicts; never reset/force-checkout, blindly choose ours/theirs, or push. Safely merge into actual local main and verify your ready SHA is its ancestor. Record main SHA and explicitly list integration/acceptance NOT RUN. If safe landing cannot be completed, preserve ready commits and report the exact blocker in this standalone chat, not to the origin.

## Implementation record

### Starting state

- Baseline and starting HEAD: `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`; ancestry verified.
- Assigned branch: `william-sollers-xbox-bounded-worker-execution`.
- Isolated Ubuntu-22.04 worktree: `/home/wsollers/appsec-package03-8b2ffebc`;
  private Git common directory: `/home/wsollers/.appsec-package03-8b2ffebc.git`.
- A local Git bundle transferred the verified source history because a Windows worktree's
  absolute `.git` pointer is not usable directly by Linux Git. No remote fetch or push occurred.
- Package saved before source implementation. Execution/dispatch edits are separate from package
  04's guidance and request-card edits; only result usage metadata may overlap `inference/request.py`.
- Integration and acceptance tests, model calls, live reviews, Docker builds, and deployments
  are not authorized execution gates for this package.

### Inventory and shared contract decisions

Genuine dispatches are review cells, lead severity triage, PoC writer, remediation writer/reviewer,
target-analysis bounded feedback, project-build image repair, native repository resolution,
native SBOM curate/plan/metadata, post-build model assessment, and OWASP workbench assessment.
Runtime registry recording and planning sanitization wrap transports; they are not extra workers.
The C++ tool named Infer, deterministic scoring, and attack-chain construction are not model loops.

1. Keep `Infer`, `ModelRequest`, and `ReviewModelRequest` calling interfaces. Add only result-level
   `usage_source` and `usage_unavailable_reason`; request rendering remains package 04's property.
2. Centralize mechanics in `inference.execution`: a bounded execution owns one monotonic deadline,
   physical-call bound, input/output/transcript byte bounds, normalized usage and immutable
   per-dispatch receipts. Local adapters retain their own semantic turn loops and authorization.
3. Use closed `FailureCategory` values: timeout, cancelled, provider, schema, budget, contract.
   Only identified `ProviderError(retryable=True)` failures are transient. Unexpected exceptions
   propagate after evidence capture; cancellation remains `BaseException` control flow.
4. Shared retry scheduling uses configured delays, cooperative cancellation checks, the remaining
   execution deadline, and the existing first-error mode. No independent worker supervision or
   runtime state machine is introduced. Transports must honor the passed timeout and cancellation;
   synchronous Python callbacks cannot safely be preempted by abandoning a thread.
5. Preserve reported input/output/cache tokens independently. Missing, bool, negative and
   noninteger reports are unknown. Replay retains historical reported values with explicit replay
   provenance and contributes no new billable tokens. Reservations are admission liabilities,
   not provider usage and not a hard guarantee of billed cost.
6. Budget v2 will atomically reserve/settle calls, retain partial known spend and unknown usage,
   conservatively reconcile abandoned reservations, and expose explicit active timing ownership.
   Existing v1 budgets retain historical wall-clock semantics and cumulative counters.
7. Use the existing PipelineLog/emit_model_event contract for correlated hash-only call telemetry.
   Do not send prompts, results, source, exception messages, or arbitrary adapter dictionaries into
   common telemetry. Existing specialized receipts remain authoritative semantic evidence.
8. Keep private PoC readers private; use an explicit local capability contract. Blue memo reuse
   and independent verifier/judge isolation remain unchanged.

### Initial verification

At baseline `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`:

- `.venv/bin/python -m pytest tests/review/test_budget.py --basetemp=test/tmp/package03-baseline -q`
  first failed before collection because this new checkout had no environment (exit 127).
- Restored the missing environment with `uv venv --python 3.12 .venv` and
  `uv pip install --python .venv/bin/python -e '.[test]'`; verified `appsec_review.__file__`
  resolves inside this Linux worktree.
- The same focused budget command passed: **17 passed**, pytest 10.10 s, wall 11.07 s.
  This baseline selection is not evidence of integration, acceptance, or live behavior.

Shared-contract revision `0a01ca073807d6559d3a9d81163c27c237cf49bc` preserves the provider calling
interfaces. Before committing it,
`tests/test_inference.py tests/test_claude_cli_inference.py --basetemp=test/tmp/package03-contract -q`
via `.venv/bin/python -m pytest` passed **16 tests** (pytest 7.93 s, wall 8.45 s).

On that revision plus the shared execution implementation,
`.venv/bin/python -m pytest tests/test_bounded_execution.py --basetemp=test/tmp/package03-engine -q`
passed **20 tests** (pytest 1.33 s, wall 1.80 s). These cover cancellation checkpoints, fake-clock
backoff, first-error refusal, deadlines, bounds, immutable correlated receipts, reported/replay
usage and propagation of unexpected contract failures.

### Review-cell and triage migration

Review cells now share one execution deadline across turns, retries and configured backoff.
Receipt reuse stays fingerprint-bound; the executor version is bumped to `/3` so old behavior
is not silently reused. Prior receipt bytes are retained. Per-turn missing usage is null;
aggregate actual usage becomes unknown when any contributing provider call is unknown.
Replay preserves reported values separately and adds no new spend. Unexpected model-boundary
and integrity exceptions are retained and re-raised instead of being relabeled provider gaps.
The existing blue-only memo gate and verifier/judge blind request construction are untouched.
Lead triage uses the same execution mechanics, still permits only one schema repair, and grants
no retrieval or additional authority.

Focused commands on `2c77d7c809d95a734bda86954ea78a315d77ac1f` plus these owned changes:

| Pytest selectors (all prefixed `.venv/bin/python -m pytest`) | Basetemp | Result | Wall time |
| --- | --- | --- | --- |
| `tests/review/test_cells.py tests/review/test_bounded_cells.py tests/review/test_result_cache.py -q` | `test/tmp/package03-cells` | 80 passed | 4.01 s |
| `tests/review/test_lead_triage.py tests/review/test_bounded_cells.py -q` | `test/tmp/package03-triage` | 28 passed | 1.96 s |
| Same selection, after adding triage contract/replay/first-error cases | `test/tmp/package03-triage-expanded` | 33 passed | 2.17 s |
| `tests/test_bounded_execution.py tests/review/test_cells.py tests/review/test_bounded_cells.py tests/review/test_result_cache.py tests/review/test_lead_triage.py -q` | `test/tmp/package03-review-core` | 118 passed | 4.26 s |

The model call context preserves run/job/attempt/step/task correlation and optional typed
package/lane/batch/build-unit/case IDs. Callers with legacy `ModelRequest` can pass the exact
pinned guidance digest as `Execution(guidance_sha256=...)`; otherwise its existing summary pin
or the exact guidance-content digest is recorded. Failure codes distinguish execution deadline
exhaustion from byte/token limits. No arbitrary correlation dictionary is forwarded.

### Integrated implementation chunks

The bounded subagents used GPT-6 Astra, high reasoning and long context, each in its own
Linux-filesystem worktree/environment. No nested agents, remote operations or live validations
were commissioned.

- Shared engine: `2c77d7c809d95a734bda86954ea78a315d77ac1f`.
- Review/triage core: `7631fe91639ffd109f7a02ceb6d20c52c20e3e72`.
- Atomic budget/timing: `d2d3b93b376550f683110172749b8c1977bf0150`, branch `package03-budget`,
  only `review/budget.py` and its two focused unit files. Imported into this package by exact SHA.
- Transport/recording: `521262be87d6fb62e7cbd8bd460783e5c59bd0e7`, branch `package03-transport`,
  only the five owned inference modules and four provider/recording unit files.
- Specialized adapters: `c2075ab3b89d036cc283fcc4be0775ac686b111d`, branch `package03-adapters`,
  nine owned execution adapters and five focused unit files. Guidance-loader bodies and request
  rendering were not changed by that chunk.

The parent wired atomic accounting before physical-call telemetry, including undispatched
cancellation settlement. New review runs select active timing; imported wall-clock runs retain
their semantics. A normal cell execution closes only its own invocation owner against its
verified receipt. Interrupted/uncertain owners require positive cessation evidence and explicit
reconciliation. A budget-exhausted resume may revalidate existing receipts and reconstruct prior
claims, but cannot dispatch new model work. It does not erase prior findings merely because the
new-call budget is exhausted.

The new receipt directory and canonical run-wide budget are declared in inventory/datasets;
this is a necessary output-contract update, not an expansion of retrieval authority. PoC private
readers declare a local capability contract, without public MCP exposure. `recording-root.json`
must accompany copied v2 recordings; the PoC replay fixture was updated accordingly. A focused
cell test exercises a recorded timeout and identical retry through actual replay and the shared
engine, including zero new billing for the replayed failure.

#### Budget chunk verification

Root: `/home/wsollers/appsec-package03-budget-8b2ffebc`. Commands used the checkout's own
`.venv/bin/python -m pytest`, with `--basetemp=test/tmp/package03-budget -q` and
`/usr/bin/time -f 'wall_seconds=%e'` when timed.

- **B1**: `tests/review/test_budget.py`
- **B2**: `tests/review/test_budget.py tests/review/test_budget_reservations.py`
- **B3**: `tests/review/test_budget_reservations.py`

| Command | Result | Wall seconds |
| --- | --- | --- |
| B1 | Missing `.venv/bin/python`, exit 127, no collection | Not measured |
| B1 after isolated dependency restoration | 17 passed | 19.44 |
| B2 | 81 passed | 31.54 |
| B3 | `NameError: replay` in a misplaced guard; aggregate output truncated | Not captured |
| B3 `-x --tb=short` | 1 failed, same misplaced guard | 1.43 |
| B2 `--tb=short` after correction and added cases | 100 passed | 28.69 |
| B3 `-k 'identity_collision or corrupted_receipts or directory_without or import_sources'` | 11 passed, 78 deselected | 1.79 |
| B3 `-k 'timing_option or legacy_import_never or active_execution'` | 3 passed, 87 deselected | 1.98 |
| B2 at ready `d2d3b93b376550f683110172749b8c1977bf0150` | 107 passed; pytest 16.53 s | 17.02 |

The first two rows used pristine contract revision `0a01ca073807d6559d3a9d81163c27c237cf49bc`;
intermediate rows used that HEAD plus evolving owned changes. Uncaptured timing/counts are
explicit record gaps, not estimates.

#### Transport chunk verification

Root: `/home/wsollers/appsec-package03-transport-8b2ffebc`. Final command:

```text
/usr/bin/time -p .venv/bin/python -m pytest tests/test_model_recording.py tests/test_inference.py tests/test_claude_cli_inference.py tests/test_copilot_inference.py tests/test_anthropic_inference.py tests/test_inference_transport_failures.py --basetemp=test/tmp/package03-transport -q
```

| Invocation | Result | Wall seconds |
| --- | --- | --- |
| Initial selection, before the new failure-test file existed | Missing environment, exit 127 | 0.00 |
| Same baseline selection after restoration | 22 passed, 12 skipped, 3 failed | 11.03 |
| Final selection during implementation | 6 circular-import collection errors | 2.16 |
| Same selection after fixing cold imports | 178 passed | 13.55 |
| Same selection with additional coverage | 181 passed | 13.78 |
| Same selection with additional coverage | 205 passed | 13.57 |
| Same selection with additional coverage | 214 passed | 14.72 |
| Exact ready `521262be87d6fb62e7cbd8bd460783e5c59bd0e7` | 216 passed, no skips; pytest 10.21 s | 10.85 |

Baseline failures were stale Anthropic planning-v3 sanitization/v2 omission expectations and an
incomplete nested-model profile walker. The assertions now target the correct boundary and all
configured models. Optional SDK tests use deterministic fake SDK modules rather than skipping
coverage or contacting the SDK service.

#### Specialized adapter verification

Root: `/home/wsollers/appsec-package03-adapters-8b2ffebc`. All commands used
`/usr/bin/time -f elapsed=%e .venv/bin/python -m pytest`, plus
`--basetemp=test/tmp/package03-adapters -q`. Selector aliases:

- **P**: `tests/test_poc_writer.py`
- **R**: `tests/test_remediation_models.py`
- **N**: `tests/test_native_inference_runtime.py`
- **F**: `tests/test_build_topology_feedback.py`
- **X**: `tests/test_bounded_worker_adapters.py`
- **D**: `tests/test_dependency_intelligence.py`
- **O**: `tests/test_owasp_evidence_binding.py`
- **S**: `tests/test_post_build_security_assessment.py`
- **J**: `tests/test_project_build.py`

| Selectors / additional flags | Result | Wall seconds |
| --- | --- | --- |
| P | Missing environment, exit 127; restored private environment | 0.00 |
| P R N F | 152 passed, 8 failed; corrected clock initialization and first-error expectations | 34.79 |
| X F | 145 passed, 2 failed; corrected new first-error tests to expect cancellation control flow | 28.81 |
| S D O | Pre-existing topology/OWASP fixture failures; aggregate console output truncated | Not captured |
| `D::test_guidance_and_job_public_api_are_registered` O `--tb=short -x` | 1 failed: stale topology expectation omits `resolution.curate_components` | 1.59 |
| O `--tb=short -x` | 1 failed before dispatch: `repin` drops `size_bytes`; package 04 owns it | 2.86 |
| X P R N F `--tb=short` | 254 passed, 1 failed; new fixture landed exactly on, not above, the output bound | 29.62 |
| X P R N F `--tb=short` after correcting that fixture | 256 passed | 38.35 |
| D `-k 'model_resolution or native_inference' --tb=short` | 2 passed, 24 deselected | 1.82 |
| S `--tb=short` | 20 passed | 17.02 |
| J `-k 'repair or repeated_preparation' --tb=short` | 5 passed, 6 failed, 33 deselected; unrelated existing `profile=None`/unenforced-target fixture expectations | 90.21 |
| X R N `--tb=short` | 173 passed | 21.25 |
| X P R N F `--tb=short` at ready `c2075ab3b89d036cc283fcc4be0775ac686b111d` | 267 passed; pytest 35.29 s | 35.93 |

The unchanged project preparation/reuse functions were compared against the base; model planning
completed without model gaps. No target-policy weakening or speculative fixture rewrite was
performed. The missing aggregate timing/output is retained as a verification-record gap.

#### Parent integration regressions

Commands below are `.venv/bin/python -m pytest <selectors> --basetemp=<listed path> -q`
under `/home/wsollers/appsec-package03-8b2ffebc`, timed with `/usr/bin/time`.

| Selectors | Basetemp under `test/tmp/` | Result | Wall seconds |
| --- | --- | --- | --- |
| Core/cells/cache/triage selection above | `package03-review-commit` | 120 passed | 4.12 |
| Same selection after accounting hooks | `package03-accounting-boundary` | 123 passed | 3.52 |
| `tests/review/test_execution_budget_wiring.py` | `package03-budget-wiring` | 5 passed, 1 failed; undispatched settlement must pass `usage=None` | 2.65 |
| Wiring file plus `tests/review/test_team_handler.py --durations=5` | `package03-teams` | 46 passed, 13 fixture setup errors: frozen configuration mismatch | 96.73 |
| Wiring file after correction | `package03-budget-wiring-fixed` | 6 passed | 2.52 |
| Wiring file plus team blind-verifier and budget cases | `package03-team-prerequisites` | 1 passed, 5 failed (wall-clock timing must not switch); 2 upstream-origin fixture errors | 8.84 |
| Same selection after timing compatibility correction | `package03-active-budget` | 6 passed, 2 fixture errors: scripted provider did not implement triage | 10.93 |
| Team blind-verifier and budget cases `--tb=short` | `package03-team-fixture-fixed` | 1 passed, 1 failed: test tried changing a persisted run's budget limits | 16.04 |
| Five team cases listed below `--tb=short --durations=5` | `package03-team-focused` | 5 passed | 46.37 |
| `tests/test_bounded_execution.py tests/review/test_bounded_cells.py tests/review/test_execution_budget_wiring.py` plus exhausted-team resume case, `--tb=short` | `package03-resume-regressions` | 50 passed | 15.60 |

The five focused team selectors are:

```text
tests/review/test_team_handler.py::test_blue_cells_never_see_each_other_and_the_verifier_is_blind
tests/review/test_team_handler.py::test_a_distinct_verifier_profile_is_recorded_without_changing_independence
tests/review/test_team_handler.py::test_provider_and_schema_failures_are_typed_gaps_with_terminal_records
tests/review/test_team_handler.py::test_budgets_end_cells_not_launched_or_timed_out_and_are_never_retried
tests/review/test_team_handler.py::test_rerunning_a_team_reuses_every_succeeded_cell
```

The resume selector is
`tests/review/test_team_handler.py::test_resuming_exhausted_team_reconstructs_prior_claims_without_new_calls`.
The last regression selection ran after integrating the three exact ready commits above, plus
the parent's working-tree changes. The exact final source revision is recorded by the subsequent
code-freeze/final validation entry rather than assigning a pre-commit SHA to uncommitted changes.

Fixture repairs were scoped to affected checks: write config before frozen handoffs, include
the real upstream jobs, supply the accepted upstream identity, and give the scripted Infer a
valid unresolved triage answer instead of relying on swallowed assertions. Separate limit
variants use independent unit budget scenarios; the product still rejects mutated run limits.
The team fixture uses zero retry delay because fake-clock cell tests cover the real configured
delay and deadline behavior. No assertions were weakened and production backoff is not bypassed.

Slow checks are explicit: the earlier profile-allocation cases took 10.41-10.97 s of call time
each, and one final blind-verifier case had 5.63 s setup plus 5.07 s call time. They were not
reclassified or assigned larger timeouts; later selections exclude unrelated profile sweeps.

### Manual suites: written, NOT RUN

Only syntax parsing with `ast.parse` was performed on the new files; no import, collection,
fixture, test or provider was executed from these suites.

```text
.venv/bin/python -m pytest tests/integration/test_bounded_worker_execution.py --basetemp=test/tmp/manual-bounded-integration -q
.venv/bin/python -m pytest tests/acceptance/test_bounded_worker_execution.py --basetemp=test/tmp/manual-bounded-acceptance -q
```

Prerequisites: an isolated Linux checkout and its own editable `.[test]` environment. These
component-level manual suites script the actual external Infer/retrieval/Garnet boundaries;
they do not need provider credentials, Docker or external services. They exercise real
adapter validation and accounting, not an alternative execution loop. They are not a substitute
for full-graph/live acceptance, which remains separately user-owned and unrun.

The integration suite composes review, triage and remediation adapters with common receipts and
telemetry while retaining different authority and output validators. Acceptance scenarios cover
interruption, positively verified cessation, repair pause/resume, immutable prior receipts,
transient/schema failures, cache outage, verifier memo exclusion and unknown-usage exhaustion.
`tests/conftest.py` already excludes `tests/integration` and `tests/acceptance` from implicit
unit collection; this package does not alter that global configuration.
