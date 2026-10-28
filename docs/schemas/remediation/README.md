# Remediation artifact contracts

These are protected, attempt-owned attachments to immutable confirmed findings, not findings,
release decisions, applied target changes, or runtime proof.

`job_remediation_planning.build_job(infer=..., builds_factory=..., core_factory=...,
repository_root=...)` exposes `load.verify_inputs`, `assess.propose`, and
`acceptance.publish_handoff`. It uses the shared `jobs.accepted_review.load_accepted_review`
verifier and admits exactly the confirmed `remediation_intake` partition. Supported findings,
including supported findings with compile-checked PoCs, never enter planning.

`job_remediation_validation.build_job(infer=..., executor_factory=..., builds_factory=...,
repository_root=...)` exposes `load.verify_inputs`, `assess.validate`, and
`acceptance.publish_handoff`. The executor factory receives `(UnitContext, BuildProfile)`;
the build factory receives the run root and returns the existing `AcceptedBuilds` interface.

Both summaries contain exactly `schema`, `run_id`, `upstream`, `items`, and `gaps`.
The handoff binds `artifact`, `item_count`, `gaps`, and `terminal_status`. Every confirmed
candidate has one outcome, including candidates exceeding the configured work cap.
Validation additionally binds the accepted planning job handoff in `upstream.planning_handoff`.

The planner joins bounded accepted index locations to hash-verified native build workspace
bytes. It never falls back to the user target checkout. Unsupported languages, unavailable
source custody, architecture changes and cross-build proposals retain explicit manual design
or validation outcomes. Optional PoC context is not consumed by this first implementation;
`poc_handoff` is explicitly null. Planning does not require PoC success.

`remediation-exact-patch/1` is an inert JSON patch, not a command or fuzzy unified diff.
Each file declares an accepted baseline hash or a new-file absence proof, followed by ordered,
nonoverlapping UTF-8 byte-range replacements with exact original text. Existing edits must name
source files admitted through evidence; new files are restricted to a related source directory.
The validator verifies every baseline before writing any patch file into its disposable copy.
No target commit, deployment, build-script execution, generated test execution or PoC execution
is available.

Validation reports seven separate check dimensions. Semantic review uses a distinct model
conversation without the planner's rationale and remains analyst-assessed. The commissioned
`native_syntax` adapter covers a patch to one exact accepted translation unit and derives an
allowlisted `-fsyntax-only` command from accepted compiler
facts and uses the same pinned offline image and argv before and after the patch. It disables
Clang implicit configs and refuses response files, executable tool loading, unsupported flags,
untrusted build-configuration changes and escaping paths. Header, new-file and multi-translation-unit
patches require manual validation rather than claiming compiler coverage they did not receive.
This is selected translation-unit
syntax assurance, **not** a full rebuild or a verified vulnerability fix. Baseline failure is
`inconclusive`; patched failure is `rejected`; unavailable replay after static checks is
`static_checked`. No safe native adapter or a cross-build change requires manual validation.
Regression specifications are retained separately; generated regression functions are not
commissioned in this slice. `runtime_regression` is always `not_performed_by_policy`.

Every scratch copy is bounded and removed in a `finally` path, including failed checks.
Attempt-owned cleanup receipts record whether a copy existed and was removed. Integrity
failures and cleanup failures prevent publication. Retrying creates new attempt-owned artifacts
and cannot overwrite bytes reachable from an earlier accepted handoff.

## Central configuration integration

The parsers are `config.remediation.RemediationPlanningSettings.from_mapping` and
`RemediationValidationSettings.from_mapping`. The central config loader, registry, launch graph,
profile/model checks, guidance registry and input matrix must register these jobs together.
The new role fragments are `remediation_writer` and `remediation_reviewer`; no runtime skill is
loaded. The local assembler calls shared `governing_rules`, `load_registry`, and fragment
validation, requires the registered bounded responsibility, and checks its closed role-to-job
allowlist against the actual job context. `remediation_writer` belongs only to planning;
`remediation_reviewer` belongs only to validation. Tool mentions and conflicting policy are
rejected before dispatch. The pinned bundle identifies the job, role, registry version,
responsibility, and exact governing/role file hashes.

The user selected automatic planning and bounded nonexecuting validation for **new
reviews**; existing runs retain their frozen configuration. The corresponding central tables are:

```toml
[jobs.job_remediation_planning]
name = "remediation_planning"
workers = 1
[jobs.job_remediation_planning.settings]
enabled = true
[jobs.job_remediation_planning.settings.bounds]
max_candidates = 16
max_packages = 10000
max_source_files = 8
max_source_bytes = 64000
max_patch_files = 4
max_patch_bytes = 64000
max_file_bytes = 262144
max_edits = 32
max_list_items = 32
max_text_chars = 4000
max_workspace_files = 100000
max_workspace_bytes = 1073741824
[jobs.job_remediation_planning.settings.writer]
provider = "claude-cli"
model = "claude-haiku-5-5"
reasoning = "high"
max_input_tokens = 64000
max_output_tokens = 16000
max_turns = 6
max_queries = 4
timeout_seconds = 600
[jobs.job_remediation_planning.steps.load.tasks.verify_inputs]
workers = 1
[jobs.job_remediation_planning.steps.assess.tasks.propose]
workers = 1
[jobs.job_remediation_planning.steps.acceptance.tasks.publish_handoff]
workers = 1

[jobs.job_remediation_validation]
name = "remediation_validation"
workers = 1
[jobs.job_remediation_validation.settings]
enabled = true
adapters = ["native_syntax"]
command_timeout_seconds = 120
output_bytes = 65536
[jobs.job_remediation_validation.settings.bounds]
max_candidates = 16
max_packages = 10000
max_source_files = 8
max_source_bytes = 64000
max_patch_files = 4
max_patch_bytes = 64000
max_file_bytes = 262144
max_edits = 32
max_list_items = 32
max_text_chars = 4000
max_workspace_files = 100000
max_workspace_bytes = 1073741824
[jobs.job_remediation_validation.settings.reviewer]
provider = "claude-cli"
model = "claude-haiku-5-5"
reasoning = "high"
max_input_tokens = 64000
max_output_tokens = 8000
max_turns = 2
max_queries = 0
timeout_seconds = 600
[jobs.job_remediation_validation.steps.load.tasks.verify_inputs]
workers = 1
[jobs.job_remediation_validation.steps.assess.tasks.validate]
workers = 1
[jobs.job_remediation_validation.steps.acceptance.tasks.publish_handoff]
workers = 1
```

Step-level `workers` may be explicitly set to one by the central integrator; model turns and
patch checks are deliberately serial and bounded in this slice. Enable validation only with
planning enabled. Consumers must read the accepted summaries and referenced bytes, never
reconstruct mutable file paths or treat `build_checked` as `fixed` or `resolved`.

## Metadata-only telemetry

The jobs emit `REMEDIATION_PLANNING_INPUTS_VERIFIED`,
`REMEDIATION_VALIDATION_INPUTS_VERIFIED`, `REMEDIATION_MODEL_COMPLETED`,
`REMEDIATION_PLANNING_CANDIDATE_COMPLETED`, `REMEDIATION_VALIDATION_CANDIDATE_COMPLETED`,
`REMEDIATION_VALIDATION_ADAPTER_COMPLETED`, and the two corresponding `*_PUBLISHED` events.
Admission, omitted/confirmed candidates, finite outcomes, gaps, durations, adapter failures and
timeouts, and output byte counts are bounded metadata. Claim/cell IDs are correlation fields,
not metric labels; source, prompts, patches, model answers and reason prose are not emitted.
Model token aggregates preserve `null` whenever that dimension is missing from any completed
turn, and for attempts without a completed turn. Genuine reported zero usage remains zero.
`usage_unavailable`, `usage_unavailable_count` (completed turns missing either dimension),
and `usage_unavailable_reason` (`provider_usage_missing`, `no_completed_turns`, or null)
distinguish unavailable usage from measured usage.
