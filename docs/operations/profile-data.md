---
title: "Operating profile-data ingestion"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_language_build", "job_profile_data"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Operating profile-data ingestion

`job_profile_data` imports execution-profile artifacts retained by accepted builds. It never creates
profile data itself. Arrange for a build or test workflow to emit a supported text report and for
`job_language_build` to catalog it as `execution-profile`.

The configured topology is `load.accepted_inputs`, `normalize.profile_data`,
`index.profile_data`, then `acceptance.publish_handoff`. Central bounds limit accepted artifacts,
bytes per artifact, rows per artifact, bytes per line, and frames per sample. Changing a parser,
normalizer, mapping identity, report hash or target snapshot changes the corresponding shard
identity. Local shard keys also bind normalized rows, report metadata and coverage. Bounds and
admitted inputs participate in run/attempt identity; frozen configuration still forbids bounds-only
same-run edits. See the [canonical job page](job_profile_data.md).
Do not put these values in a target file or prompt. The identity values in the settings
must equal the code constants (`job_profile_data/job.py`); any other value fails configuration
loading rather than invalidating shards.

## Accepted reports

Use one of these interchange formats:

- folded stacks (`*.folded` or `*.stacks`);
- textual `perf script` output (`*.perf-script` or `*.perf.txt`);
- Callgrind output (`callgrind*` or content with an `events:` declaration); or
- LLVM text sample profiles (`*.llvm-sample`, `*.sample.prof`, or `*.prof`).

An accepted receipt may set `profile_format` to `folded-stacks`, `perf-script`, `callgrind`, or
`llvm-sample` when a conventional filename is unavailable. The declared value is still untrusted
and restricted to the closed parser set. Preserve `artifact_origin`: a preexisting deterministic
fixture is `accepted-input`; a report emitted during the accepted build is `build-output`.
Identical bytes at different retained paths remain separately attributed reports, not conflicting
hotspot identities. Neither origin proves that the current review executed a workload.

Perf counts are sample/frame occurrences, not sampling-period sums; event qualifiers remain
part of the event name. Callgrind supports line-position layouts and keeps self costs separate
from inclusive call costs. A call row's reported source/line is the callee's; `callsite_*` fields
retain the caller. Do not sum self and call-inclusive costs into a single total.

Do not rename opaque data to resemble a text report. `gmon.out`, pprof protobuf, `.profraw`, and
`.profdata` require a future pinned conversion workflow and currently produce explicit gaps.

## Results and gaps

The accepted summary is beneath the attempt's `artifacts/profile-data/` directory, while immutable
analysis shards and the composed manifest are beneath `data/indices/`. Use the accepted loader for
programmatic access. A successful parse does not assert that the workload was representative.
For bounded indexed access use `query_engineering_signals signal_family=profile`, optionally with
an exact reported source `path`. Returned profile rows remain artifact-backed context, not verified
source citations. Review units receive located rows only for that source, with unlocated rows
remaining available to the same build. Query responses retain partial/unavailable coverage reasons.

Expected gap prefixes include:

- `missing_profile_data`: an accepted build has no profile artifact;
- `unsupported_profile_format`: opaque, unknown, or undeclared input cannot be parsed safely;
- `malformed_profile`: the selected parser rejected the text;
- `malformed_llvm_header`: valid function totals were retained but a top-level header was omitted;
- `missing_call_cost`: a Callgrind call declaration lacks its following cost row;
- `artifact_byte_bound`, `artifact_count_truncation`, `row_truncation`,
  `profile_row_truncation`, or `frame_truncation`: a configured bound was reached;
- `ambiguous_profile_format`, `ambiguous_profile_identity`, or `ambiguous_symbol`: identity or
  interpretation was not unique.

These are unknown or incomplete coverage, never a clean-security result. A SHA-256 mismatch,
symlink, escaped path, wrong accepted schema, target-snapshot disagreement, or invalid artifact
origin is an integrity failure and prevents publication.

## Review use

Start with high-ranked functions when operational impact or frequently exercised attack surface is
relevant, then cross-check against source complexity, input trust, call paths, static findings,
coverage, churn, and dependency exposure. Always inspect cold security-boundary and exceptional
paths separately. Rank is context only: do not turn it into a vulnerability finding or probability
and do not lower severity or review scope because a function is absent or cold.

For focused parser development verification, run:

```text
python -m pytest -q tests/unit/job_profile_data/test_parsers.py --basetemp=test/tmp/profile-parsers
```

Offline report-to-publication-to-query regressions are in
`tests/unit/job_profile_data/test_semantics.py`; use the bounded unit-test wrapper for combined
selections. Passing units do not establish real profiler or live-review quality.


## Tuning and whole-job recovery: `job_profile_data`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.bounds.max_artifact_bytes` | `33554432` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.bounds.max_artifacts` | `256` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.bounds.max_frames_per_sample` | `256` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.bounds.max_line_bytes` | `65536` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.bounds.max_rows_per_artifact` | `250000` | coverage | positive integer; exact parser/cross-field bounds† |

† The [executing job/parser](../../src/appsec_review/jobs/job_profile_data/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.load.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.normalize.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.index.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.acceptance.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
