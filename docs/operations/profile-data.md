# Operating profile-data ingestion

`job_profile_data` imports execution-profile artifacts retained by accepted builds. It never creates
profile data itself. Arrange for a build or test workflow to emit a supported text report and for
`job_language_build` to catalog it as `execution-profile`.

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

Do not rename opaque data to resemble a text report. `gmon.out`, pprof protobuf, `.profraw`, and
`.profdata` require a future pinned conversion workflow and currently produce explicit gaps.

## Results and gaps

The accepted summary is beneath the attempt's `artifacts/profile-data/` directory, while immutable
analysis shards and the composed manifest are beneath `data/indices/`. Use the accepted loader for
programmatic access. A successful parse does not assert that the workload was representative.

Expected gap prefixes include:

- `missing_profile_data`: an accepted build has no profile artifact;
- `unsupported_profile_format`: opaque, unknown, or undeclared input cannot be parsed safely;
- `malformed_profile`: the selected parser rejected the text;
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

For development verification, run:

```text
python -m pytest -q tests/test_profile_data.py --basetemp=test/tmp/profile-data
```
