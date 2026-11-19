---
title: "Profile-data ingestion"
kind: "architecture"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_artifact_indexing", "job_language_build", "job_profile_data", "job_target_catalog"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Profile-data ingestion

`job_profile_data` turns profile reports already retained by accepted language builds into bounded,
queryable hotspot context. It does not run the target, start a profiler, invoke a converter, or
deserialize an executable or language-native object format.

## Inputs and trust boundary

The job requires an accepted `job_target_catalog` handoff, plus `job_language_build` and
`job_artifact_indexing` handoffs when those producers are enabled. Disabled producers leave named
gaps; without artifact indexing the job verifies the pinned attempt or catalog manifest instead.
All present handoffs must identify the same target snapshot. A candidate must be a
regular, non-symlink, run-owned file in an accepted language-build receipt, have kind
`execution-profile`, and still match its receipt SHA-256. The accepted artifact-index manifest is
verified and becomes the upstream manifest for the profile-data index.

Profile bytes, names, symbols, modules, source names, line numbers, and event names are untrusted
data. Configured limits bound artifact count and bytes, input rows and line bytes, frames per
sample, and normalized rows. Integrity contradictions fail the job. Missing, unsupported,
malformed, truncated, duplicate, or ambiguous producer data becomes an explicit gap.

The text-only parser set is:

| Format | Accepted input | Normalized meaning |
| --- | --- | --- |
| Folded stacks | `frame;frame count` rows | inclusive sample count for each retained frame |
| `perf script` | textual sample headers and indented call chains | one count per symbol/frame and event; optional sampling periods do not weight counts or enter event identities; event qualifiers are retained |
| Callgrind | event declarations, current file/function, and line-position cost rows | event costs distinguished as `self` or `call_inclusive`; call rows retain callee and caller positions separately |
| LLVM sample profile | textual function headers | total samples by function; malformed top-level headers produce partial gaps, while body/inline details remain outside this parser's coverage |

Callgrind `calls=` positions identify the callee; the following cost row identifies the caller's
callsite. Neither side is a verified source citation. Unresolved callees are omitted with an
explicit gap, not reassigned to the caller. Non-line position layouts are unsupported and produce
gaps rather than treating instruction addresses as source lines. Self and inclusive call costs
must not be summed as one undifferentiated event population.
The reserved Callgrind file marker `???`, including compressed file references, becomes a null
source with an `ambiguous_source` gap. Its measured costs remain unlocated same-build context;
ordinary filenames containing question marks are not treated as this exact reserved marker.

Detection incrementally decodes its bounded prefix, so a UTF-8 character crossing that boundary
is not rejected. Parsing still strictly validates the complete admitted text and its line bounds.

Opaque `gmon.out`, pprof protobuf, LLVM `.profraw`, and LLVM `.profdata` inputs are recognized but
not parsed. They produce unsupported-format gaps until a pinned, sandboxed conversion stage is
designed. No pickle, executable, or unsafe native deserialization path is accepted.

## Outputs

Each normalized row retains the build unit, symbol/function, count, event, optional module,
optional source and line, report path and SHA-256, parsed format, and artifact origin
(`accepted-input` or `build-output`). Rows receive a deterministic rank within the build unit by
descending count with stable tie breakers. Callgrind rows also retain `cost_kind` and, for calls,
`callsite_symbol`, `callsite_source`, and `callsite_line`; unknown values remain null.
Byte-identical copies at different report paths retain separate identities and all report origins.
Repeated references to the same path/hash are instead reported as duplicate-input gaps.

The job publishes:

- one immutable `analysis` shard named `profile-data-<build-unit-id>` per accepted build receipt;
- `hotspot` entities for normalized rows and explicit complete, partial, or unavailable coverage;
- a composed, hash-verified retrieval manifest; and
- `appsec-review/profile-data-handoff/1`, with build-unit accounting, report identities, rows,
  parser identities, gaps, upstream handoff hashes, and the manifest identity.

Consumers should use `load_accepted_profile_data()` rather than guessing an attempt or file path.
Local shard fingerprints also bind the normalized rows, report metadata and coverage, preventing
reuse of an old projection after its normalized meaning changes. Unchanged normalized inputs
reuse the same immutable shard, independent of receipt artifact ordering.

The indexed route is `query_engineering_signals signal_family=profile`. Its optional exact path
filter also reads the reported `source` field before pagination, without manufacturing a verified
location. Responses retain shard and coverage gaps even when no rows match. Review-unit context
keeps path-bearing profiles file-specific; only unlocated profiles become same-build context.

## Security interpretation

Hotness has `context_only` semantics. A heavily sampled function may deserve attention because it
has high operational impact, processes more real inputs, or offers more observations to investigate.
That does not mean it is more likely to contain a defect. A hot function can be simple and mature;
a cold error, parser, initialization, recovery, or privilege-transition path can be the critical
security boundary.

Profile rank is therefore a review-prioritization and attack-surface clue, not a finding, severity,
defect probability, proof of reachability under an attacker-controlled input, or evidence that a
cold function is safe. Useful review combines profile context with complexity, taint and call-graph
reachability, unsafe operations, change history, test coverage, static-analysis leads, and maximal
deployment exposure. No numeric security score is changed by this producer.
These reports are observed inputs, not proof that this review executed their workloads.

## Public implementation surface

The implementation is under `appsec_review.jobs.job_profile_data`. `parse_profile()` exposes the
bounded parsers for tests and controlled callers; `ingest_profile_artifacts()` exposes receipt-level
normalization; `detect_profile_format()` reports supported, opaque, unknown, and ambiguous formats;
`build_job()` constructs the generic job; and `load_accepted_profile_data()` verifies the accepted
publication and immutable index graph.
