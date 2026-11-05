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

Optional prior evidence must pass integrity validation before staleness is considered. An expected
current publication must bind the current accepted catalog. Accepted-plan readers and planner
reuse admission compare these identities again. Disabling this producer does not disable native
recipe/refinement guards, and declared developer settings never replace compiler enforcement.

## Verification boundary

The accompanying static-parser, lifecycle, graph-wiring and feedback units are authored but not
run in this source-only session. The exact predecessor V1's 173 independently passed cases are
preserved evidence, not V2 results. The actual-capture R8 replay is separately classified and
requires explicit custody/import/environment admission; no live review or acceptance follows
from the new defaults.
