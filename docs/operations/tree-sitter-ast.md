---
title: "Tree-sitter AST operations"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_tree_sitter_ast"]
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# Tree-sitter AST operations

Build `appsec-review/tool-tree-sitter:1.0.0` only after acquiring the ignored Linux asset cache as
documented in `containers/tools/tree-sitter/README.md`. The build must use the tracked
`assets.lock.json`, the digest-pinned base, `--pull=false`, `--network none`, and
`--provenance=false`. Record the final local image ID through the host-owned pin workflow,
not in the recipe catalog; see [image-pin verification](image-pin-verification.md).

A rebuilt offline image from this context supports C, C++, C#, Go, Java, JavaScript, Kotlin, PHP,
PowerShell, Python, Ruby, Rust, Shell, TSX, and TypeScript. Shell files use the hash-locked upstream Bash grammar.
Swift and any other cataloged language without a lock remain explicit `UNAVAILABLE`
dispositions; operators must not interpret those gaps as clean coverage.

The standalone `tree_sitter_ast` Dagster job is the manual dispatch path. In the review graph it
runs from admitted intake/catalog inputs, with an admitted language-build lane for generated
sources when available. It does not consume compiled AST/IR, SAST or inference results.
Enabled scheduling follows the typed contracts, not an unconditional claim of independence from
language builds. The [canonical job page](job_tree_sitter_ast.md) supplies the generated input
and placement declarations. CodeQL waits for its accepted handoff before composing the later retrieval
view. Dagster maps accepted scopes concurrently; application receipts, immutable shards, the
accepted handoff, and the central run log remain authoritative.

Generated-source intake reads `build_outcome` for product existence. A built receipt with
provenance gaps does not become `generated_source_build_unsuccessful` just because it contains
no eligible generated sources. Admitted sources from such receipts still pass artifact-indexing
manifest, identity and byte checks before detached publication. Receipt gaps remain visible;
rejected artifacts are never generated-source inputs.

For recovery, inspect scope dispositions in the accepted Tree-sitter artifact and central pipeline
log. Rerunning a partial attempt reuses hash-verified successful scope shards and retries failed or
invalidated scopes. Reuse also requires the same CFG builder algorithm and actual node bound;
changed semantics use a new fingerprint and preserve the old checkpoint bytes. Missing or
mismatched builder metadata under a current fingerprint is rejected, not overwritten.
Do not delete locks, edit accepted pointers, or remove successful shards to
force recovery. An unsupported grammar or bounded parse is a named gap, not clean coverage.

CFG completeness is separate from parsing. Inspect each `cfg-manifest.json` function's
`coverage_status`, `gaps`, `truncated` and `unmodeled_constructs`, together with the scope and
accepted `cfg_partial_functions`, `cfg_truncated_functions` and `cfg_unmodeled_constructs`
counts. The accepted analysis coverage area `cfg:<source_identity>` names partial CFG work
even when the raw file's AST coverage is complete. Node-limit and unsupported-flow gaps make
the scope partial and suppress CFG guard-dominator claims; a bounded prefix is not a clean
function. A `cfg_ast_context_projection` gap instead means context-specific cleanup CFG nodes
cannot be collapsed into unique AST flow edges: use the per-function CFG, not an invented
AST-level path. See the [control-flow semantics](../architecture/tree-sitter-ast.md#intra-procedural-cfg-and-guard-polarity-t-169-t-5211).
The public CFG/guard queries carry these limitations in their existing `coverage_gaps` envelope.
Older CFG payloads without completeness metadata are unknown and yield no guard claims.
Source-line/AST/source-file guard answers contain only guards common across possible execution
contexts; use an explicit CFG `node_id` only when examining that particular context.

For source-only navigation, call `query_syntax` with an accepted `source_file` identity and mode
`definitions`, `calls`, `imports` or `references`; optionally filter an exact written `name`.
Pass a returned AST identity to `read_excerpt`, or as a syntax subject to narrow to that node's
span. Package source-file grants work even without a CodeQL database. The tool reads accepted
`analysis` shards only. Projection coverage is separately partial (explicit syntax subsets) or
unavailable; raw AST parse completeness never means resolved calls or exhaustive symbols.
The host adds projections using existing pinned grammar output, so no grammar/image rebuild or
new asset pin is required. Swift stays unavailable; PowerShell and Shell currently expose raw AST
only. Reusing an old scope fingerprint cannot skip the new projection version.

Live acceptance must verify the frozen host-bound image ID, run with network disabled and the target mounted
read-only, parse the multi-project/multi-language fixture, publish at least one searchable AST shard,
and demonstrate that an injected sibling grammar failure produces `COMPLETED_WITH_GAPS` while the
successful shard remains accepted.

If every runnable scope reports container exit 1, inspect a scope's protected raw stderr. A
`PermissionError` for `/scratch/request.json` indicates a stale producer that did not make the
atomic request readable by the effective application/container UID. Current producers set the scope directory to `0733` and the
completed request to `0644` before starting the network-disabled container. Keeping the owner-write
bit avoids Docker Desktop input/output errors caused by Windows read-only file attributes while the
container user still has read-only access.


## Tuning and whole-job recovery: `job_tree_sitter_ast`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.max_file_bytes` | `2097152` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_files_per_scope` | `128` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_nodes_per_file` | `20000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_nodes_per_scope` | `20000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_source_bytes_per_scope` | `16777216` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.workers` | `8` | coverage | 1..32 |

† The [executing job/parser](../../src/appsec_review/jobs/job_tree_sitter_ast/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.load.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.plan.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.parse.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.parse.tasks.dynamic_scopes.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.acceptance.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
