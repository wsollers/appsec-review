---
title: "Remediation planning and bounded validation"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_remediation_planning", "job_remediation_validation"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Remediation planning and bounded validation

Status: producers `6278e580`, central wiring `b702eb7` and follow-up `e769645f`, 2026-10-28. Planning and validation
are real registered jobs, enabled in new configurations by the user's rollout decision.
The shared reader now verifies review `/3` and nested chain/package bindings (`18eae9f`).
The `dd9c9ad` integration introduced gate/report `/2` certification of these exact attachments.
The gate remains `/2`; current report `/4` preserves their bindings while representing unknown
domain metrics explicitly ([report contract](final-report.md#domain-coverage-and-unknown-measurements-t-5088)).
The owner-reported historical `039b24e4` all-lane check passes native and manual outcomes with
offline model/compiler/renderer boundary doubles; it is not live compiler/runtime reproduction.
The separate remediation Linux suite at `68915bb7` reports 256 passed / zero skips. Focused
consumer compatibility and remaining manual/current-main validation are recorded in the
[acceptance ledger](../reviews/evidence-completion-documentation-inventory.md#acceptance-ledger);
neither result establishes a full-repository clean verdict or a fixed finding.
Existing frozen configurations are not rewritten or silently enabled by new defaults.

These jobs attach proposals/checks to immutable accepted findings. They do not edit the user
target, alter adjudication/severity/shipment, apply a release fix, or execute a PoC/regression test.
The [completion design](../architecture/evidence-completion-and-remediation.md) is the behavioral
contract; [strict artifact schemas](../schemas/remediation/README.md) define exact fields.

## Inputs, units and retained outcomes

| Job | Units / accepted inputs | Outputs |
| --- | --- | --- |
| `job_remediation_planning` | `load.verify_inputs -> assess.propose -> acceptance.publish_handoff`; shared accepted review, exactly its confirmed partition, counted evidence relations and accepted native build workspace custody. | `remediation-planning/1` summary and `remediation-planning-handoff/1`; per-finding plan, inert patch, source context and writer receipt. |
| `job_remediation_validation` | `load.verify_inputs -> assess.validate -> acceptance.publish_handoff`; same accepted review plus exact accepted planning handoff and native build custody. | `remediation-validations/1` summary and `remediation-validation-handoff/1`; per-item validation/check artifacts and cleanup receipts. |

Every confirmed intake item has exactly one terminal row, including work beyond `max_candidates`;
supported findings never enter planning, even if a PoC compiled. Rows carry
`finding: {claim_id, finding_package_id, sha256}`, status, artifact ref or null, reason and gaps.
Summaries use `schema`, `run_id`, `upstream`, `items`, `gaps`; the handoff binds summary hash,
item count, gaps and terminal status. Empty scope is `SKIPPED_NA`; accounted gaps produce
`COMPLETED_WITH_GAPS`. Invalid hashes, cross-review bindings, mutated accepted source and failed
scratch cleanup fail integrity validation rather than returning an empty successful result.

Source resolution joins indexed evidence to hash-verified run-owned native build workspaces.
It never falls back to the user target. Although graph ordering can place planning after PoC,
this slice consumes no PoC context and records `poc_handoff: null`. Missing native custody is
an explicit gap; non-native/architectural work must retain a manual-design or insufficient-evidence
outcome rather than invent a validated native patch.

## Exact patches and assurance

`remediation-exact-patch/1` is inert JSON, not shell or a fuzzy unified diff. Each file has an exact
accepted `before_sha256` or explicit new-file absence proof, then ordered nonoverlapping UTF-8
byte edits with `start`, `end`, `old`, `new`. All baselines/old bytes are checked before writes.
Existing files must be admitted evidence-related source; new files are limited to related source
directories. Bounds, canonical paths, case collisions, symlinks/junctions and undeclared edits are
checked. Only disposable baseline/patched run-owned copies are changed.

Planning statuses are `proposal_generated`, `manual_design_required`, `insufficient_evidence`,
`capped`. A generated proposal includes violated/corrected invariants, evidence ids, compatibility/
interface effects, residual risks, deployment prerequisites, scope limits, validation checks and a
separate safe regression specification. A manual-design outcome is not a patch success.

Validation records seven independent dimensions: `patch_applicability`, `policy`,
`semantic_review`, `static_checks`, `build`, `regression_compile`, `runtime_regression`.
Fresh-conversation semantic review does not receive the planner's rationale and remains
analyst-assessed, not deterministic proof or automatically model-distinct verification.
Static checks cover exact edit scope, UTF-8/no NUL and no newly added merge markers.

Only `native_syntax` is commissioned initially. It derives allowlisted `-fsyntax-only` argv from
one exact accepted C/C++ translation unit, and uses the same pinned offline image and arguments
for baseline and patched source. It does not invoke a build system, linker, generated test or
PoC. Compiler response files, executable tool-loading/unsupported options, implicit Clang
configuration, unsafe build changes and escaping paths are refused. Accepted facts that cannot
commission a pinned `BuildProfile` yield `manual_validation_required` with
`accepted_build_profile_uncommissioned`, not fabricated build coverage. Header/new-file/multi-unit
changes are outside that adapter's claimed coverage.

Compiler exit `1` is an expected negative syntax-check result, including under first-error
execution safety: baseline rejection is inconclusive; patched rejection rejects the proposal.
It is not a successful compile. Under that policy, timeouts, abnormal exits, transport/cleanup
failures and explicit review cancellation keep their stop semantics; validation never catches `ReviewStopped`.
The shared build executor's default remains exit `0` only.

The adapter retains bounded stdout/stderr and outcome receipts in the protected, host-only
`assess/tasks/validate/<item>/compiler-execution/<container>/` directory, alongside rather than
inside `scratch/`. The build-comparison artifact hash-binds each attempted phase's three files.
Receipt storage is never mounted into the compiler. Both complete source manifests are still
compared after compilation, including every `.appsec-*` file; there is no path-name exemption.
Scratch cleanup does not delete retained execution evidence.

| Validation status | Meaning |
| --- | --- |
| `build_checked` | Baseline and patched selected syntax checks passed after prior checks. Not a full rebuild or a verified vulnerability fix. |
| `static_checked` | Selected static/semantic checks only; for example no adapter commissioned or safe replay unavailable. |
| `rejected` | Exact-patch/static policy, semantic contradiction or patched syntax check failed. |
| `inconclusive` | Semantic assessment unavailable/unresolved or baseline syntax failed. A broken baseline cannot establish patch success. |
| `manual_validation_required` | No patch/source/build coverage, candidate cap, unsafe replay/build mutation, uncommissioned pinned build profile or unsupported change scope. |

Regression specifications are retained, but generated regression functions are not commissioned;
`regression_compile` is explicitly not performed. `runtime_regression` is always
`not_performed_by_policy`. All assurance keeps `runtime_verified: false`, `result_id: null`.
Neither these statuses nor a dossier may label the finding `fixed`, `resolved` or reproduced.
Every created scratch copy is removed in `finally`, with an attempt-owned cleanup receipt.

## Configuration and operation

Typed settings are in [`config/remediation.py`](../../src/appsec_review/config/remediation.py);
the authoritative tables are [`appsec-review.toml`](../../appsec-review.toml). Validation cannot
be enabled when planning is disabled. Provider/model/reasoning/turn/query/time budgets remain
central; runtime profiles may override only the allowlisted writer/reviewer model fields.

`job_remediation_planning/model.py::guidance` closes role-to-job scope: `remediation_writer` belongs
only to planning, `remediation_reviewer` only to validation. Each role requires a registered
bounded responsibility and validated procedure text; governing rules use the shared validated
loader. The immutable role bundle identity includes job/role, registry version, responsibility
and exact file hashes, retained in the common selected-section `/4` format with `bundle.json`
and `prompt.md` under `data/guidance/<sha256>/`. Historical layouts remain immutable and readable.
Receipts pin that digest; host/repository-agent instructions and target guidance are not loaded
as worker guidance. These are provenance records, not dossier raw-prompt payloads.

| Settings | Current defaults |
| --- | --- |
| Both `.settings.enabled` | `true` for new configurations; never retroactively changes frozen runs. |
| Shared `.bounds` | 16 candidates, 10000 packages, 8 source files / 64000 source bytes, 4 patch files / 64000 patch bytes, 262144 bytes/file, 32 edits/list items, 4000 text chars, 100000 workspace files / 1073741824 bytes. |
| Planning `.writer` | 64000 input / 32000 output tokens, 6 turns, 4 queries, 600 seconds. |
| Validation `.reviewer` | 64000 input / 8000 output tokens, 2 turns, 0 queries, 600 seconds. |
| Validation adapters / execution bounds | `["native_syntax"]` (or `[]` for selected static checks only), 120 seconds/command, 65536 retained diagnostic bytes. |

The registered target-independent `run <job> --run-id <id> --upstream-from-run` surface binds
accepted upstream job handoffs. Do not treat it as an old-run migration or bypass pending
consumer acceptance. For final publication, use the implemented gate-certified snapshot,
not later mutable `latest.json` discovery.

Summaries are artifact-only/internal; source contexts, patches, model/semantic/compiler receipts
are protected/sensitive attempt artifacts. Public reports receive sanitized statuses and bound
references, not these payloads. [Dossiers](dossier-publication.md) use a closed protected projection.

## Telemetry and metrics

`REMEDIATION_PLANNING_INPUTS_VERIFIED`, `REMEDIATION_PLANNING_CANDIDATE_COMPLETED`,
`REMEDIATION_PLANNING_PUBLISHED`, and `REMEDIATION_MODEL_COMPLETED` record planning work.
Validation emits corresponding `REMEDIATION_VALIDATION_*` input/candidate/publication events plus
`REMEDIATION_VALIDATION_ADAPTER_COMPLETED`. Read per-event counters/outcomes/durations in
`completion.lanes.remediation_planning` and `.remediation_validation`, not sums of overlapping
candidate/stage totals. Counts are attempted work, including retries, not accepted finding counts.

Events carry bounded counts/statuses/error classes and correlation, never patch/source/PoC/prompt
content. Follow-up `e769645f` preserves each unknown input/output token total as null if any turn's
corresponding measurement is missing; genuine measured zeros remain zero. `usage_unavailable`
and `usage_unavailable_count` distinguish unavailable turns. No completed turns produce null
totals, flag `true`, count `0` and reason `no_completed_turns`; missing provider readings use
`provider_usage_missing`. This is not a measured zero-token invocation or a complete cost bill.
See [metrics operations](metrics.md) for unknown-usage and integrity/coverage limits.


## Tuning and whole-job recovery: `job_remediation_planning`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.bounds.max_candidates` | `16` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_edits` | `32` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_file_bytes` | `262144` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_list_items` | `32` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_packages` | `10000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_patch_bytes` | `64000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_patch_files` | `4` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_source_bytes` | `64000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_source_files` | `8` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_text_chars` | `4000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_workspace_bytes` | `1073741824` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_workspace_files` | `100000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.writer.max_input_tokens` | `64000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.writer.max_output_tokens` | `32000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.writer.max_queries` | `4` | coverage | integer >=0; exact parser/cross-field bounds? |
| `settings.writer.max_turns` | `6` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.writer.timeout_seconds` | `600` | coverage | positive integer; exact parser/cross-field bounds? |

? The [executing job/parser](../../src/appsec_review/config/remediation.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `settings.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.writer.provider` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.writer.model` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.writer.reasoning` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `steps.load.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.assess.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.acceptance.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.


## Tuning and whole-job recovery: `job_remediation_validation`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.bounds.max_candidates` | `16` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_edits` | `32` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_file_bytes` | `262144` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_list_items` | `32` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_packages` | `10000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_patch_bytes` | `64000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_patch_files` | `4` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_source_bytes` | `64000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_source_files` | `8` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_text_chars` | `4000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_workspace_bytes` | `1073741824` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.bounds.max_workspace_files` | `100000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.command_timeout_seconds` | `120` | execution | positive integer; exact parser/cross-field bounds? |
| `settings.output_bytes` | `65536` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.reviewer.max_input_tokens` | `64000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.reviewer.max_output_tokens` | `8000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.reviewer.max_queries` | `0` | coverage | integer >=0; exact parser/cross-field bounds? |
| `settings.reviewer.max_turns` | `2` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.reviewer.timeout_seconds` | `600` | coverage | positive integer; exact parser/cross-field bounds? |

? The [executing job/parser](../../src/appsec_review/config/remediation.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `settings.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.reviewer.provider` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.reviewer.model` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.reviewer.reasoning` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `steps.load.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.assess.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.acceptance.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
