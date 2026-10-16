# Operating SVF points-to analysis

`job_svf_alias_analysis` runs after an accepted `job_cpp_compiled_analysis` handoff and before
`job_code_graph_index`, which consumes its shards as a cross-check input
([design](../architecture/svf-alias-producer.md)). It is **opt-in**:
`jobs.job_svf_alias_analysis.settings.enabled = false` by default, and a disabled job is omitted from
direct and Dagster execution plans. Its central configuration must define this exact topology:

```text
load.accepted_cpp -> analyze.scopes -> acceptance.publish_handoff
```

## Settings

All settings are positive integers except `enabled`, and are validated before any unit runs.

| Setting | Bounds |
| --- | --- |
| `workers` | concurrent accepted C/C++ scopes (one container each) |
| `max_modules_per_scope` | planned modules analyzed per scope; the rest are a named gap |
| `max_module_bitcode_bytes` | a larger linked module is `too_large` and is not analyzed |
| `max_module_output_bytes`, `max_output_bytes` | driver document per module, and the run result |
| `field_limit` | SVF's field-sensitivity limit; wider structs merge fields (`field_limit_collapsed`) |
| `max_sites`, `max_pts_size`, `max_indirect_calls`, `max_targets_per_call`, `max_unmodeled_names` | driver export bounds; reaching one sets `truncated` and makes the module's coverage `partial` |
| `compile_timeout_seconds`, `link_timeout_seconds`, `module_timeout_seconds` | per compile unit, per link, and per analysis wall clock inside the container |
| `andersen_time_limit_seconds` | SVF's own Andersen limit; must be below `module_timeout_seconds` |
| `max_objects_per_module` | `memory_object` records published per module; the rest are a named coverage reason |
| `max_accessors_per_object` | accessor fan-in kept per memory object (frees first); `accessor_total` counts all |

The whole scope also runs under the central container policy (1 GiB memory, 600 s). A large C++
module that exceeds it shows up as an OOM or timeout gap.

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

The catalog entry `tool-svf` is pinned by `image_id`, and the executor refuses any other local
image. Build instructions, the offline asset lock and the license review are in
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
- Raw plans, compile databases, driver documents and execution receipts stay under `data/svf/` as
  protected run artifacts. Bitcode is deleted after each module is analyzed.

In `job_code_graph_index`, SVF verdicts appear as a `svf` producer entry (`rule: svf-cross-check/1`)
in each covered fact's `cross_check` block. A `disagree` entry comes only from closed-world, complete
records, and it makes the fact ineligible as direct evidence. Unresolved indirect calls that SVF
resolves gain `secondary_only` call-site facts with `producer = svf`.

## Resume

A scope checkpoint is reused only when its identity matches and every referenced run artifact still
verifies. The identity covers the accepted scope, link commands, settings, tool identity
(including the image pin) and adapter version. Any change produces a new immutable shard.

## Verification

Offline suites (recorded real tool output, no Docker):

```text
python -m pytest -q tests/test_svf_alias_analysis.py tests/test_svf_tool.py tests/graph/test_svf_crosscheck.py --basetemp=test/tmp/svf
```

Live tier (requires the pinned image locally; skipped otherwise). It runs the job through the real
container executor on the synthetic fixture and on the copied `linux-calibration` multi-vulnerability
project, and checks that the recordings used offline still match the image:

```text
python -m pytest -q tests/live/test_svf_live.py --basetemp=test/tmp/svf-live
```

Keep `--basetemp` short on Windows: Docker Desktop rejects bind-mount sources more than 16 path
components deep, and the run roots sit directly under the base temp.
