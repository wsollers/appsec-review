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
