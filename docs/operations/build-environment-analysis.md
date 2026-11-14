---
title: "Static build-environment analysis"
kind: "operations"
subsystem: "target acquisition and build"
status: "current"
jobs: ["job_build_environment_analysis"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Static build-environment analysis

`job_build_environment_analysis` is default enabled after the accepted target catalog and before
planning in both `wave1_review` and `project_build_review`. It needs no new image, tool, provider,
compiler or target-script execution. Existing application processes must actually load this
source before these semantics apply; this source candidate makes no deployment claim.

The producer reads only accepted-inventory `.sh`, `.bash`, `.bat` and `.cmd` files whose names
identify environment/setup/bootstrap scripts, plus bounded literally sourced/called inventory
members. PowerShell remains a named unsupported gap. It never searches the target for new paths,
evaluates shell syntax or probes a host. Relative sourcing, `$0`, conditions, dynamic syntax and
changed working directory retain uncertainty; a sourced file's defining directory is not its
invocation directory. A literal declaration is advisory, never the effective recipe environment
or native target proof.

`[jobs.job_build_environment_analysis.settings]` centrally bounds 64 scripts, 256 KiB/file,
4096 assignments, source depth four and a 30-second internal deadline. Settings may tighten,
not exceed, these ceilings. Long declaration values are withheld with a named gap.
Credential-bearing URLs and sensitive assignments are redacted before publication or inference.
Literal batch `set "NAME=value"` and `@set "NAME=value"` use the same assignment boundary:
safe bytes and line endings are preserved, sensitive values are withheld from additive evidence
and complete caches, and the original source hash is never rewritten to accept redacted bytes.
Raw script content is not the environment output.

The accepted sensitive artifact is `build-environment.json` beneath the producer's publication
task. It binds the source fingerprint and accepted catalog handoff, redacted declarations,
coverage, bounds and gaps. The planner records the host-authored workflow, expected producer,
mode, reason and exact reference in its signed claim and accepted availability outcome.

| Condition | Planner-visible availability | Lifecycle |
| --- | --- | --- |
| Accepted complete or partial producer | `AVAILABLE` | Coverage and all gaps retained |
| Bounded unsupported input, exhaustion or internal deadline | Partial `AVAILABLE` or typed `UNAVAILABLE` | Atomically `COMPLETED_WITH_GAPS` |
| Explicit `enabled = false` | `DISABLED` | Producer omitted; catalog dependency preserved |
| Deliberate trusted standalone launch without this producer | `ABSENT`, mode `NOT_RUN` | No inference that enabled scheduling happened |
| Valid optional prior evidence with another source | `UNAVAILABLE`, reason `STALE` | No imported declarations |
| Expected current producer missing, unaccepted or wrong-source | Blocking error | No fallback to optional/absent evidence |
| Changed hashes/schema/paths, unexpected bugs, killed/timed-out orchestration or failed publication | Blocking error | Never relabeled as bounded success |

The producer's unit result carries the artifact's bounded gap strings as `producer-gap/1` records
(`producer_reported_gap`, `scope_id` the script path when the gap names one, never retryable: the
analysis is advisory and bounded by design) and the job is strict (`strict_gaps`); the artifact keeps
its own gap strings. A failure of the job's own — the accepted catalog or custody not matching the
claim, an accepted script missing or its bytes changed since the catalog, the reader breaking its byte
contract, the publication over the reader bound — is `BuildEnvironmentAnalysisFailed` in the task
receipt (`error.type`); the attempt fails, no handoff is published, and a resume after the cause is
removed publishes a second attempt. Events: `BUILD_ENVIRONMENT_ANALYSIS_STARTED` (inventory files,
selected scripts, `max_scripts`), `BUILD_ENVIRONMENT_ANALYZED` (availability, coverage, inspected
scripts, declaration and gap counts) and `BUILD_ENVIRONMENT_PUBLISHED` (artifact identity, gap count);
the pipeline never carries script values, redacted or not (job pass 06, 2026-11-08).

Optional prior evidence must pass integrity validation before staleness is considered. An expected
current publication must bind the current accepted catalog. Accepted-plan readers and planner
reuse admission compare these identities again. Disabling this producer does not disable native
recipe/refinement guards, and declared developer settings never replace compiler enforcement.
Optional-prior mode and its exact reference come from the trusted launch metadata, including on
resume; they are not inferred from an old artifact or replaced with expected-current semantics.
An unscheduled producer is supplied explicitly as `environment_mode = "OPTIONAL_PRIOR"` and
`environment_reference = "<accepted handoff SHA-256>"` in host orchestration metadata. A supplied
producer upstream reference may express the same identity; conflicting references, unsupported
modes and attempts to downgrade a scheduled producer block. Without either explicit prior
reference, an unscheduled producer remains `NOT_RUN`, not an inferred previous publication.
After integrity validation, only deliberately optional environment evidence is omitted from
required target-evidence/manifest lineage. Its exact reference and availability remain pinned in
the signed launch contract, accepted plan, evidence/cache identity and reuse comparisons.
Required current producers and all other upstream dependencies remain unchanged. Graph plan
and run propagate the same host orchestration identity on initial and deferred resume paths.

## Verification boundary

The accompanying static-parser, lifecycle, graph-wiring and feedback units are authored but not
run in this source-only session. The exact predecessor V1's 173 independently passed cases are
preserved evidence, not V2 results. The actual-capture R8 replay is separately classified and
requires explicit custody/import/environment admission; no live review or acceptance follows
from the new defaults.
