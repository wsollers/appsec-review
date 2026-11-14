---
title: "Cross-language CodeQL architecture"
kind: "architecture"
subsystem: "code intelligence"
status: "current"
jobs: ["job_codeql_analysis"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Cross-language CodeQL architecture

The configured CodeQL job has three steps; its execution step schedules several internal actions:

1. `plan.inventory` validates the pinned runtime live and partitions accepted target/build scopes.
2. `execution.scopes` preflights runtime declarations, then advances each ready scope through
   database creation/reuse, independently configured query profiles, bounded SARIF normalization
   and optional graph export. These are internal actions, not separate configured job steps.
3. `acceptance.publish_handoff` composes the accepted retrieval manifest and publishes scope,
   query and export dispositions.

The [canonical job page](../operations/job_codeql_analysis.md) links the generated step and dataset
declarations. Scope execution is independent and concurrency-bounded, subject to resource admission
and execution-safety policy; an active fail-stop policy may stop before a scope-local fallback is
published. Identity inputs include target and
file hashes, accepted handoffs, build receipt and protected argv, environment image, dependency
identity, declared CodeQL/extractor/runner/query releases, limits, query profile, database tree,
and normalizer release. Supplied platform trees are not customer-evidence fingerprints.
Query profiles have independent checkpoints and SARIF artifacts; changing
or failing a custom suite does not invalidate the database or erase the default-suite result.

Configuration is frozen per run. A changed query declaration requires a new run; cross-run
database reuse is only the explicitly admitted predecessor path, not an unrestricted cache.
Host-observed runtime IDs and preinstalled declarations belong in the host bindings described by
[image-pin verification](../operations/image-pin-verification.md).

The shared implementation lives in `src/appsec_review/codeql/` and
`src/appsec_review/jobs/job_codeql_analysis/`. Language-specific jobs do not own a second CodeQL
runtime, SARIF normalizer, or retrieval schema.
