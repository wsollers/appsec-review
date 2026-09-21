# Build discovery and the full job graph

The Dagster `full_review` job exposes 51 lifecycle and registry jobs as dependency-linked
ops, plus configuration and build discovery. `00-validation` is the shared validation contract,
not a recursively scheduled review job. The graph comes from `appsec-review-process/job-graph.json`.
Every unavailable worker raises `WORKER_NOT_IMPLEMENTED` and records `pre.json` under the
engagement's `data/orchestration/dagster/<dagster_run_id>/<job>/`. Its descendants cannot run.
Registration does not mean that a worker, its persona implementation or its output contract
has been qualified. Missing lane templates remain visible blockers to implementation.

The subsequent [parallel intelligence expansion](parallel-intelligence.md) adds build-gated IR,
binary/CFG and test collection while letting source-only scans and consumers start independently.
The original 26-job integration evidence below remains historical; the new graph has separate
dependency qualification and its new workers remain unimplemented.

The first additional executable integration is **`build_discovery`**. It runs configuration,
intake, a bounded Python build-discovery worker and validated publication. Its scope is discovering
how to build; it does not run CMake, install dependencies, execute target scripts or compile code.

**`build_execution`** is the second additional executable integration, added 2026-09-19, and the
first job in the whole graph permitted to set `target_execution: True`. It depends on `build_discovery`
already having published an accepted branch for the run (checked on disk, not chained as a Dagster
op input, since the two jobs are launched independently). It reuses `build_discovery`'s cited
configure command verbatim, adds an explicit `-G Ninja` generator (the one thing `build_discovery`
deliberately never decides), and runs that single CMake configure step inside the sandboxed
`audit-buildenv-cpp` container (`images/audit-buildenv-common/run.sh`: no network, read-only
workspace, writable scratch). It never runs `cmake --build`, never installs dependencies and never
compiles or links a target. Its only job is to answer, with real evidence instead of citation: does
this target's discovered build actually produce a non-empty `compile_commands.json` under Ninja,
inside this project's isolated container.

## Submit

Create and stage a Linux-owned engagement using [the submission guide](dagster-launching.md), then:

```powershell
python -B appsec-review-process/launch_job.py --run-id <run_id> --job build_discovery --wait
```

The output contains source revision, hashed file/line citations, declared CMake requirements,
options and dependencies, observed documentation/CI build text, candidate build environments and
proposed argument arrays. Source text is recorded as evidence and never used as executable commands.
The initial command planner supports an unambiguous CMake root. Other build systems are inventoried
and reported as unsupported or ambiguous rather than given invented commands.

Outputs are under:

```text
runs/<run_id>/data/jobs/00-workflow-preparation/build_discovery/
  latest.json
  accepted.json
  attempts/<attempt_id>/
    inputs.json
    pre.json
    output.json
    post.json
    status.json
    logs/stdout.log
    logs/stderr.log
```

Pre-processing checks accepted intake, current source identity, file hashes, scope and bounded
evidence size. Post-processing recomputes the expected output, checks freshness and validates
publication. The shared process runner handles nonzero exits, timeouts, cancellation, stream
draining, child cleanup and logging failures. Repeating the launch reuses a valid immutable attempt;
`--force` requests a new one. Recovery uses a new launch with the same engagement ID.

To inspect failure propagation through the whole graph:

```powershell
python -B appsec-review-process/launch_job.py --run-id <run_id> --job full_review --wait
```

This currently reaches the repository-partition supplied-artifact gate and issues an actionable
handoff when no schema-valid result has been supplied. Build discovery remains preserved. The
`02-build-configure` lifecycle node is wired to the same worker as standalone `build_execution`,
but it is not qualified through a real `full_review`: both supplied discovery gates must first
publish accepted results, and the worker still reads the accepted build-discovery plan from disk.
A successful discovery or configure result never claims a successful target build or completed
security review. Use the standalone job for bounded diagnostics while the lifecycle chain remains
unqualified.

## Submit build execution

Once `build_discovery` has published an accepted branch for the run:

```powershell
python -B appsec-review-process/launch_job.py --run-id <run_id> --job build_execution --wait
```

Outputs are under:

```text
runs/<run_id>/data/jobs/00-workflow-preparation/build_execution/
  latest.json
  accepted.json
  attempts/<attempt_id>/
    inputs.json
    status.json
    command.json
    output.json
    build/discovery/compile_commands.json   (present only if the configure step produced one)
    logs/stdout.log
    logs/stderr.log
```

`output.json` records `build_status` (`CONFIGURE_OK` / `CONFIGURE_FAILED` / `CONFIGURE_INCOMPLETE`),
`generator_selected_ninja`, `compile_commands_present`, `compile_commands_entry_count` and
`compile_commands_sha256`. Unlike `build_discovery`, this job cannot be validated by recomputing a
pure function and comparing -- a real container run is not cheap or guaranteed byte-identical to
repeat -- so it manages its own immutable-attempt lifecycle and is validated by hash integrity of
the recorded evidence (see `build_execution.py`'s module docstring). Repeating the launch with an
unchanged upstream fingerprint reuses the existing attempt without re-running the container;
`--force` requests a new one.

A `CONFIGURE_FAILED` or `CONFIGURE_INCOMPLETE` result is not a harness bug by itself -- the
container has no network access, so any dependency Freeciv21's CMake needs at configure time that
isn't already baked into `audit-buildenv-cpp` will fail here, and that failure is exactly the real
signal this job exists to surface. Check `command.json` and `logs/stderr.log` before assuming
otherwise.

## Qualification

```powershell
python -B appsec-review-process/qualify_build_discovery.py --run-id <qualification_owner_run_id>
```

The qualifier stages Freeciv21 and uses the actual Dagster service to check cited build discovery,
both streams, immutable reuse, explicit full-graph failure and recovery. It preserves every launch
and writes its report under the qualification owner's `data/qualification/`.

The 2026-09-19 [live integration report](../appsec-review-process/runs/20260919T130744Z-a09a25/data/qualification/build-9bca14aa/report.json)
passed all five checks. The [verification summary](../appsec-review-process/runs/20260919T130744Z-a09a25/data/verification-summary.json)
records the tested identities and final follow-up checks. The full suites passed 52 host and 56
Linux tests; final discovery/publication changes were covered by nine host and twelve Linux
targeted tests and another actual Freeciv21 service execution. The qualification is a self-review.
Evidence is ignored local run data and requires this workspace or its preserved archive.

See the [Freeciv21 discovery results](../appsec-review-process/runs/20260919T130744Z-a09a25/data/freeciv21-build-discovery.md)
for source citations and proposed commands. The stopped legacy stack's states and mounts were
unchanged. Dagster event and compute-log snapshots were archived into the engagement's `data/`.

`build_execution` has its own qualifier, `qualify_build_execution.py`, added alongside the job
itself on 2026-09-19:

```powershell
python -B appsec-review-process/qualify_build_execution.py --run-id <run_id_with_accepted_build_discovery>
```

It asserts the job's own mechanics unconditionally (real execution recorded, output pinned to the
accepted `build_discovery` fingerprint, non-empty logs, immutable reuse on a second launch) but
does not assert that the real CMake configure step succeeds -- whether `audit-buildenv-cpp` already
resolves Freeciv21's Qt6/Lua/KF6Archive/SQLite3 dependencies is exactly what running it for real
will show. **This job and its qualifier have not been run yet.** They were written and syntax-checked
against the same primitives `build_discovery`/`workflow.py` already use, but neither Docker nor a
Dagster service is reachable from the environment that wrote them, so the actual `CONFIGURE_OK` /
`CONFIGURE_FAILED` outcome, and therefore whether this closes the Ninja/compile_commands.json
question for real, is unverified until `qualify_build_execution.py` is run on a host with Docker and
the Dagster service up. Run the host and Linux test suites (`tests-host-full`, `tests-linux-full`)
plus this qualifier before trusting it the way `build_discovery` is trusted here.

## Registered lifecycle jobs

See the manifest-generated [lifecycle dependency flow](full-review-workflow.mmd). Build discovery
is a supporting workflow op before partition discovery, distinct from the 51-node lifecycle view
and from full developer project discovery.

| Job | Execution readiness | Registry template |
|---|---|---|
| `00-intake` | Intake qualified | Present |
| `02-ossf-scorecard` | Qualified published-results ingestion; explicit fixed-host network permission, or validated not-requested skip | Present |
| `02-repository-partition-discovery` | Validated hand-off gate wired (2026-09-19); blocks with an actionable hand-off until a schema-valid result is supplied | Present |
| `02-dev-project-discovery` | Validated hand-off gate wired (2026-09-19); blocks with an actionable hand-off until a result is supplied | Present |
| `02-devops-project-discovery` | Worker blocked | Present |
| `02-sre-operations-topology` | Worker blocked | Present |
| `02-evidence-assembly` | Worker blocked | Missing |
| `01-component-characterization` | Worker blocked | Missing |
| `03-threat-model-dfd-stride` | Worker blocked | Missing |
| `04-asvs-masvs` | Worker blocked | Missing |
| `05-native-memory` | Worker blocked | Missing |
| `06-cve-reachability` | Worker blocked | Missing |
| `13-fuzz-target-triage` | Worker blocked | Missing |
| `15-deployment-hardening` | Worker blocked | Missing |
| `07-red-team-adversarial` | Worker blocked | Missing |
| `08-blue-team-refutation` | Worker blocked | Missing |
| `09-independent-verification` | Worker blocked | Missing |
| `11-remediation-proposal` | Worker blocked | Missing |
| `12-scoring-prioritization` | Worker blocked | Missing |
| `10-synthesis-report` | Worker blocked | Missing |
| `02-api-collection-intelligence-ingest` | Worker blocked | Present |
| `02-binary-intelligence-ingest` | Worker blocked | Present |
| `02-doc-intelligence-ingest` | Worker blocked | Present |
| `02-standards-source-ingest` | Worker blocked | Present |
| `02-test-intelligence-ingest` | Worker blocked | Present |
| `04-owasp-validation-worklist` | Worker blocked | Present |
| `15-stig-srg-validation-worklist` | Worker blocked | Present |
| `02-build-configure` | Wired to `build_execution.py` (2026-09-19) | Present, unrun in `full_review` |
| `02-native-build` | Worker blocked | Missing |
| `02-source-sast` | Worker blocked | Missing |
| `02-native-sast` | Worker blocked | Missing |
| `02-ir-capture` | Worker blocked | Missing |
| `02-ir-link` | Worker blocked | Missing |
| `02-ir-facts` | Worker blocked | Missing |
| `02-debug-symbol-index` | Worker blocked | Missing |
| `02-binary-triage` | Worker blocked | Missing |
| `02-binary-cfg` | Worker blocked | Missing |
| `02-test-execution` | Worker blocked | Missing |
| `02-test-result-ingest` | Worker blocked | Missing |
| `02-test-coverage-ingest` | Worker blocked | Missing |
| `02-operations-doc-ingest` | Worker blocked | Missing |

## Discovery hand-off gate (02-repository-partition-discovery, 02-dev-project-discovery)

The repository-partition gate now emits the common worker-result envelope and uses the shared
read-only validation/atomic-publication boundary. Its bounded standalone Dagster diagnostic is:

```powershell
python -B appsec-review-process/launch_job.py --run-id <run_id> --job repository_partition_discovery --wait
```

This standalone entrypoint invokes the same supplied-artifact lifecycle worker; it does not perform
automatic analysis. Developer discovery deliberately retains its older supplied-gate runtime.

Added 2026-09-19 to unblock `02-build-configure`'s real declared dependency chain
(`02-build-configure` -> `02-dev-project-discovery` -> `02-repository-partition-discovery`) inside
`full_review`, without inventing an in-Dagster LLM execution model or fabricating repository
analysis. Both jobs' contracts (see `schemas/repository-partition-map.schema.json`) require real
judgment about the specific target's code -- partition boundaries, routing rationale, confidence,
overlap notes -- that a deterministic script cannot honestly produce.

`appsec-review-process/discovery_gate.py` wires both as a validated hand-off gate, following the
project's existing "supplied artifact" precedent (`phase1.validate_supplied`): a human or agent
session does the actual analysis out-of-band and writes a schema-conformant result to
`runs/<run_id>/data/jobs/<job>/supplied/result.json`. The Dagster op accepts it (schema-validated,
recorded as an immutable attempt, same `accepted.json`/`attempts/` shape as every other job root)
if present and valid; otherwise it writes an actionable `handoff.md`/`handoff.json` under that
job's root and fails clearly, instead of `blocked_op`'s generic `WORKER_NOT_IMPLEMENTED`.

This makes the dependency chain resolvable end to end once both results are supplied -- it does
not make `02-build-configure` fire with zero human/agent involvement, and it should not: fabricating
a partition map would put false coverage/confidence claims into a security review. `02-dev-project-
discovery` has no dedicated schema yet, so it is validated structurally (non-empty JSON object)
until one is authored.
