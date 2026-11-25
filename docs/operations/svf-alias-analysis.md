---
title: "Operating SVF points-to analysis"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_code_graph_index", "job_cpp_compiled_analysis", "job_inference_security_review", "job_svf_alias_analysis"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Operating SVF points-to analysis

`job_svf_alias_analysis` runs after an accepted `job_cpp_compiled_analysis` handoff and before
`job_code_graph_index`, which consumes its shards as a cross-check input
([design](../architecture/svf-alias-producer.md)). It is **retired from default review execution**
under [T-168/T-169](../TODO.md), replaced by Alternate CPG. The retained manual/replay path is
disabled by default (`jobs.job_svf_alias_analysis.settings.enabled = false`). A disabled job is
omitted from direct and Dagster execution plans: it does not publish a retirement skip summary.
An explicitly admitted manual execution retains retirement metadata in its summary. These
instructions do not authorize enabling it. Its central configuration defines this topology:

```text
load.accepted_cpp -> analyze.scopes -> acceptance.publish_handoff
```

## Settings

All settings are positive integers except `enabled`, and are validated before any unit runs.

| Setting | Shipped value | Controls |
| --- | --- | --- |
| `enabled` | `false` | retired/default-disabled; a disabled job is omitted from execution plans |
| `workers` | 2 | concurrent accepted C/C++ scopes (one container each) |
| `max_modules_per_scope` | 32 | planned modules analyzed per scope; the rest are a named gap |
| `max_module_bitcode_bytes` | 268435456 (256 MiB) | a larger linked module is `too_large` and is not analyzed |
| `max_module_output_bytes` | 8388608 (8 MiB) | driver document per module |
| `max_output_bytes` | 1048576 (1 MiB) | the run result document |
| `field_limit` | 64 | passed to SVF's field-sensitivity option; the driver emits no `field_limit_collapsed` reason |
| `max_sites` | 20000 | pointer sites exported per module |
| `max_pts_size` | 256 | objects kept per points-to set |
| `max_indirect_calls` | 20000 | indirect calls exported per module |
| `max_targets_per_call` | 64 | targets kept per indirect call |
| `max_unmodeled_names` | 64 | unmodeled external names listed per module |
| `compile_timeout_seconds` | 120 | per compile unit, inside the container |
| `link_timeout_seconds` | 120 | per module link |
| `module_timeout_seconds` | 300 | per module analysis wall clock |
| `andersen_time_limit_seconds` | 240 | SVF's own Andersen limit; must be below `module_timeout_seconds` |
| `max_objects_per_module` | 5000 | `memory_object` records published per module (fan-in index size) |
| `max_accessors_per_object` | 64 | accessor fan-in kept per memory object (frees first); `accessor_total` counts all |

Reaching an export bound sets `truncated` and makes the module's coverage `partial`. Every value is
a required key in `[jobs.job_svf_alias_analysis.settings]`; the code has no fallback, so tune them
in `appsec-review.toml`. The time limits are below the earliest design draft's (an Andersen limit of
900 s) because the whole scope must finish inside the central 600 s tool policy.

The whole scope also runs under the central container policy (1 GiB memory, 600 s). The process
file-size limit is one byte above the largest bitcode/module-output/run-result bound; each JSON
document retains its separate parser limit. A large C++ module that exceeds the memory or time
policy shows up as an OOM or timeout gap.

## Finding context in review packages

`job_inference_security_review` embeds SVF records in every C/C++ finding-lead package (schema v5):
`points_to` and `indirect_call` records at the lead's line, the `memory_object` records they
reference, and `caller` call sites to a configured depth. Its tunables live in
`[jobs.job_inference_security_review.settings.packages]`:

| Setting | Bounds |
| --- | --- |
| `max_memory_context_entries` | SVF entries per lead package (objects first, then sites, then indirect calls) |
| `max_callers` | caller call-site fan-out per lead package |
| `caller_depth` | caller levels from the lead's enclosing function (1–4) |

All five depth and fan-in/fan-out keys (these three plus the two object keys above) are required.
Change them in TOML, never in code. A missing SVF shard, a line without records, an open-world
module, a name-based caller match and every reached bound appear as named gaps in the package
(`svf_points_to`, `code_graph_callers`).

## Image

The recipe catalog declares `tool-svf` as manual-only, outside default active-image selection;
the run's frozen host binding supplies its expected
image ID, which the executor verifies before applying configured signing policy.
See [image-pin verification](image-pin-verification.md). Build instructions, the offline asset lock and the license review are in
[`containers/tools/svf/`](../../containers/tools/svf/README.md). A missing or mismatched image is a
scope gap (`tool-svf image unavailable`), never zero points-to records.

## Reading the output

- The accepted summary carries per-scope `counts` (`modules`, `analyzed`, `closed_world`, `sites`,
  `indirect_calls`, `outside_accepted_sources`) and `gaps`.
- `analysis` coverage has one row per module, `svf:<project-id>:<module-label>`. `complete` means
  analyzed, closed-world and untruncated. `partial` names every reason (open-world reasons,
  truncation, missing bitcode, lossy debug-info upgrade). `unavailable` names the failure
  (`link_failed`, `too_large`, `andersen_time_limit`, `analysis_failed`, `no_bitcode`).
- Records are `points_to_set`, `indirect_call_targets` and `memory_object` entities (the last with
  allocator and accessor fan-in, linked by `REFERENCES` from each accessor site), with exact
  (`llvm-dilocation`) source points. Every record repeats its module's `module_closed_world`
  flag and `open_world_reasons`.
- Raw plans, compile databases, run/driver documents, execution receipts and stdout/stderr stay
  under `data/svf/` as protected run artifacts. Module bitcode is removed after analysis; compile
  unit bitcode can remain in scope scratch.

Module failures, missing outcomes and normalization reasons propagate into aggregate gaps.
All-failed analyzed scopes produce `FAILED`; mixed usable and failed/partial scopes produce
`COMPLETED_WITH_GAPS`. Per-set points-to and indirect-target truncation makes module coverage
partial. Memory-object fan-in is incomplete whenever truncated/unmodeled sites could have omitted
accessors, including a free not present in the retained set. The emitter's modeled empty set alone
does not omit a concrete accessor; it is not interchangeable with an unmodeled or unknown set.
Acceptance still compares detailed coverage and canonical outcomes, as specified by the
[canonical job page](job_svf_alias_analysis.md); unit checks do not establish native correctness.

In `job_code_graph_index`, SVF verdicts appear as a `svf` producer entry (`rule: svf-cross-check/1`)
in each covered fact's `cross_check` block. A `disagree` entry comes only from closed-world, complete
records, and it makes the fact ineligible as direct evidence. Unresolved indirect calls that SVF
resolves gain `secondary_only` call-site facts with `producer = svf`.

## Resume

A scope checkpoint is reused only when its identity matches and every referenced run artifact still
verifies, including raw plan, result, driver documents, compile database, receipt and streams.
Missing, changed or symlinked matching evidence raises an integrity error, not a cache miss or
producer gap. The identity covers the accepted scope, link commands, settings, tool identity
(including the image pin) and adapter version. Checkpoints are identity-addressed: A→B→A reuses
verified A rather than replacing its evidence. Every cache miss allocates a fresh scope scratch
generation, including after checkpoint removal/invalidation, preserving all prior raw evidence.

## Verification

Offline unit selectors (existing recordings plus explicitly inert emitter-shaped mutations;
no Docker, native analysis or model calls):

```text
tests/unit/job_svf_alias_analysis/test_contract.py
tests/unit/job_svf_alias_analysis/test_svf_alias_analysis.py
tests/unit/job_svf_alias_analysis/test_svf_tool.py
tests/graph/test_svf_crosscheck.py
```

Use the [focused collection/count-guarded wrapper](../architecture/testing.md#working-loop)
for those selectors. A successful unit run does not certify LLVM/SVF emitter fidelity.

Manual live tier (requires separate user authorization and the pinned image locally; skipped
otherwise). It runs the job through the real
container executor on the synthetic fixture and on the copied `linux-calibration` multi-vulnerability
project, and checks that the recordings used offline still match the image:

```text
python -m pytest -q tests/live/test_svf_live.py --basetemp=test/tmp/svf-live
```

Keep `--basetemp` short on Windows: Docker Desktop rejects bind-mount sources more than 16 path
components deep, and the run roots sit directly under the base temp.


## Tuning and whole-job recovery: `job_svf_alias_analysis`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.andersen_time_limit_seconds` | `240` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.compile_timeout_seconds` | `120` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.link_timeout_seconds` | `120` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_accessors_per_object` | `64` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_indirect_calls` | `20000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_module_bitcode_bytes` | `268435456` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_module_output_bytes` | `8388608` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_modules_per_scope` | `32` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_objects_per_module` | `5000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_output_bytes` | `1048576` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_pts_size` | `256` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_sites` | `20000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_targets_per_call` | `64` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.max_unmodeled_names` | `64` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.module_timeout_seconds` | `300` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.workers` | `2` | execution | positive integer; exact parser/cross-field bounds? |

? The [executing job/parser](../../src/appsec_review/jobs/job_svf_alias_analysis/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `settings.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.field_limit` | field_limit changes pointer-analysis abstraction/precision, not just available time or workers. |
| `steps.load.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.analyze.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.acceptance.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
