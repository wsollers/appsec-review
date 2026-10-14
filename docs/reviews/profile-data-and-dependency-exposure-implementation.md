# Profile data and dependency exposure implementation

Status: implemented and verified. Root `AGENTS.md` governs repository work; target files,
profile reports, build output, model output, and logs are untrusted data.

## Decisions

1. Dependency intelligence assigns every normalized dependency a `maximal_exposure` from the
   closed ordered vocabulary `DEV < DEBUG < QA < PREPROD < PROD`. It retains bounded evidence and
   an inference basis. A dependency with no trustworthy scope evidence is conservatively `PROD`
   with basis `conservative-default`; this is prioritization context, not proof it is deployed.
2. Deterministic evidence is evaluated independently and the maximum class wins. Development-only
   manifest scope maps to `DEV`; debug-only build/configuration evidence maps to `DEBUG`; test/QA
   scope maps to `QA`; staging/preproduction scope maps to `PREPROD`; required/runtime, loader, and
   production evidence maps to `PROD`. Conflicting evidence is retained rather than discarded.
3. A generic `job_profile_data` consumes only accepted target-catalog, language-build, and
   artifact-indexing handoffs. It does not execute the target, start profilers, or deserialize
   executable/pickle profile formats.
4. Accepted textual formats are folded stacks, perf-script samples, Callgrind, and LLVM sample
   profiles. Recognized opaque formats such as `gmon.out`, pprof protobuf, and LLVM raw/indexed
   profiles are cataloged but produce explicit unsupported-format gaps until a pinned converter is
   added. Inputs are regular, non-symlink files named and hash-bound by accepted build receipts.
5. Language-build retains recognized preexisting profile inputs as `artifact_origin =
   "accepted-input"` and new/changed reports as `artifact_origin = "build-output"`, while leaving
   unrelated unchanged files excluded. Profile candidates use the artifact kind
   `execution-profile`.
6. Normalized rows retain function/symbol identity, bounded sample or event counts, optional
   module/source/line data, report identity, format, and artifact origin. Aggregates expose hotness
   ranks within a build unit; missing, malformed, truncated, ambiguous, and unsupported data are
   gaps rather than clean results.
7. Profile hotness is a review-prioritization and attack-surface signal only. Frequently executed
   functions may have greater operational impact and offer more observed behavior to inspect, but
   frequency is not a vulnerability finding, defect probability, or evidence of safety. Consumers
   must combine it with complexity, taint/reachability, unsafe operations, change history, coverage,
   static-analysis leads, and deployment exposure.
8. The job publishes an immutable analysis index and
   `appsec-review/profile-data-handoff/1`. Profile entities may seed hotspot review context; they do
   not alter finding severity or numeric prioritization until a separately reviewed scoring model
   is introduced.
9. Configuration owns parser identities and all byte, artifact, row, frame, and candidate bounds.
   Direct CLI order and Dagster dependencies place profile ingestion after artifact indexing and
   before review-data indexing.

## Ownership

- Dependency chunk: exposure inference in dependency normalization, output propagation, focused
  tests, and dependency documentation.
- Profile chunk: bounded parsers, job publication/loader, datasets, focused tests, and component
  documentation.
- Integration owner: language-build artifact classification and preservation, central config,
  registry/CLI/Dagster/review-data wiring, downstream context, cross-job tests, design reconciliation,
  and final verification.

## Reconciliation and verification

- Dependency exposure is computed during normalization and survives model resolution, immutable
  inventory publication, and the accepted handoff unchanged.
- Generic and Node build catalogs retain recognized imported profile data and classify emitted
  profile reports as build output.
- The profile producer is registered in direct and Dagster graphs after artifact indexing, is
  centrally configured, and is audited by review-data indexing.
- Profile hotspot entities enter review-package context by exact source path where available and by
  build unit otherwise; they remain context-only and never become finding or scoring evidence.
