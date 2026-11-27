---
title: "Analyzer attempt-local scope artifacts"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_clang_static_analysis", "job_cpg_analysis", "job_cpp_symbol_index"]
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# Analyzer attempt-local scope artifacts

Clang static analysis, the C++ symbol index and CPG analysis keep their scope
checkpoints and execution generations beneath the current job attempt:

| Job | Scope directory under the run |
| --- | --- |
| `job_clang_static_analysis` | `data/clang-static/<scope-id>/attempts/<attempt-id>/` |
| `job_cpp_symbol_index` | `data/code-index/clangd/<scope-id>/attempts/<attempt-id>/` |
| `job_cpg_analysis` | `data/code-index/joern/<scope-id>/attempts/<attempt-id>/` |

A new whole-job attempt executes all selected scopes even when settings and
source identities are unchanged. It does not use another attempt's scope
checkpoint or the historical run-wide checkpoint. The existing within-attempt
checkpoint verifier still checks every required artifact and refuses changed
bytes. Its validation rules and existing execution-generation directories are
unchanged.

Accepted originals are not migrated or deleted. Their handoffs continue to
resolve their original execution and index references. New index fingerprints
include the new execution artifacts; none of these changes modifies a raw
configuration hash or introduces a separate recovery store.

This is not a general cache change, authorization to retry, or an operational
settings declaration. CodeQL, Tree-sitter, code-graph indexing and build
iteration paths have separate contracts. Follow the existing
[whole-job recovery workflow](recovery-repair.md) for explicitly authorized
reexecution.
