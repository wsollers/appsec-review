# Bounded integration acceptance

This is the operator guide for the explicit acceptance profiles exposed by `run-tests`.
For the producer/consumer design, see [bounded acceptance architecture](../architecture/bounded-acceptance.md).
For revision-specific measurements and remaining work, see the
[implementation record](../reviews/integration-live-test-implementation.md).
These profiles are separate from the existing stepwise corpus and deployed-review acceptance tools.

## What a passing profile means

A profile selects connected application behavior, with exact pytest nodes declared in
[`tests/acceptance_inventory.json`](../../tests/acceptance_inventory.json). Real producers,
validators, accepted handoffs and consumers run; external model/compiler/feed boundaries may
be scripted or recorded as declared by the obligation. This is stronger than independently
passing mocked units, but does not prove that the substituted service or tool currently works.

The inventory records obligations, gap IDs, boundaries, variants, prerequisites, substitutions,
deferrals and node selections. Its catalog snapshots detect added/removed jobs, MCP tools and
provider families/transports. **Catalog membership is not execution evidence.** An obligation
is demonstrated only by a successful recorded execution of all its selected cases on the
identified revision. Deferred features remain unverified.

Acceptance is always strict. Unlike legacy `run-tests` suites, it does not forgive entries in
`scripts/known-failures.txt`. Missing prerequisites, incomplete/unexpected collection, empty
collection, duplicate collected nodes, failure, skip, xfail, xpass, interruption, timeout,
unexecuted requirements and unconfirmed process cleanup cannot make a profile pass.
Parameterized selections must collect and pass every matching parameter case.

## Select and inspect a profile

Use the checkout's own Python 3.11+ virtual environment with its test dependencies installed.
Acceptance refuses a virtual environment borrowed from another checkout. Process cases also
require the pinned Dagster host dependencies, including when those cases are selected by `quick`.
Follow repository host policy: use Linux or a Linux-filesystem WSL checkout by default; native
Windows execution requires explicit permission.

```powershell
.\scripts\run-tests.ps1 -Acceptance quick -Workers 1 -DryRun
.\scripts\run-tests.ps1 -Acceptance signals -Workers 1
.\scripts\run-tests.ps1 -Acceptance review -Workers 1
```

```bash
scripts/run-tests.sh --acceptance quick --workers 1 --dry-run
scripts/run-tests.sh --acceptance signals --workers 1
scripts/run-tests.sh --acceptance review --workers 1
```

Remove `-DryRun` / `--dry-run` to execute the inspected selection. Dry run prints JSON containing
`profile`, `nodes`, `workers`, `deadline_seconds`, `case_deadline_seconds`, `strict` and
`implemented`; it neither establishes prerequisite availability nor demonstrates coverage.

| Hermetic profile | Connected selection | Suite cap |
| --- | --- | --- |
| `quick` | Representative harness/isolation, signals/dependencies, graph/helper, process recovery/MCP, controls/TLS, authentic review and current-report oracle obligations | 720 s |
| `signals` | Accepted intake/catalog/artifact/coverage/profile and dependency/exposure/cache flows | 240 s |
| `graphs` | Source-resolving recorded graph consumers, same-row semantic matching and real local SQLite helper CLI | 180 s |
| `process` | Actual local/Dagster workers, configuration propagation, failure/recovery, durable submission, MCP, record/replay and failure sensor | 360 s |
| `process-linux` | Linux guardian/process-tree and Unix listener/peer-credential obligations | 180 s |
| `process-windows` | Actual PowerShell dispatch with an invocation-owned compiled transport | 60 s |
| `controls` | Configured control-source normalization and actual loopback HTTPS publication/failure preservation | 240 s |
| `review` | Authentic review/gate/PoC planning, empty/corrupt review, current-report oracle, benign/blocked final publication | 600 s |

This table summarizes the inventory, not a promise that every profile has passed. `quick` is
representative, not the union of all hermetic profiles. For example, graph-negative,
record/replay/sensor, benign/blocked and OS-specific cases have additional bounded selections.
Inspect the inventory at the commit under test for the exact selection.

The selectable `tools`, `deployed`, `provider`, `guidance`, `codeql-warm` and `native` profiles
currently have no executable obligations. Actual invocation fails with `profile_not_implemented`;
dry run reports `implemented: false`. Their declared prerequisites and ceilings are reservation
metadata, not working live lanes. They do not download tools, warm CodeQL, fall back to a live
provider, discover credentials or authorize deployment/native access.

## Deadlines and concurrency

- Serial execution is the default and the recommended calibration mode. `--workers 2`
  (`-Workers 2`) is the maximum; it schedules isolated case subprocesses, not `pytest -n auto`.
- An ordinary case has a 60-second hard cap. Explicit obligation exceptions are 15 seconds for
  loopback feed transport, 30 seconds for the helper CLI, and 120 seconds for the heavier
  signals/dependency, controls and review/oracle cases. Profile-level 120-second maxima do not
  silently grant every case that allowance.
- `quick` targets less than ten minutes, with a hard twelve-minute suite ceiling. This is a
  design target pending final integrated public-driver calibration, not an achieved benchmark.
- `--deadline` / `-Deadline` and `--case-deadline` / `-CaseDeadline` can only lower declared
  ceilings. Three seconds are reserved **inside** a supervised process deadline for cleanup.
  Interpreter/plugin startup, fixtures, case execution and owned-process cleanup count toward
  its cap; collection and driver setup also consume the suite budget.
- Legacy suite arguments, arbitrary pytest selections, `--parallel` and `--background` cannot
  be combined with acceptance. Do not bypass the public driver to claim its budget passed.

Storage/process isolation allows hermetic acceptance alongside an ongoing review without using
its run storage or restarting services. It does **not** guarantee zero shared CPU, memory, disk
or I/O contention. Check host load and coordinate before running; use serial execution and
report load-related limitations rather than promising production performance isolation.

## Artifacts and telemetry

Each invocation creates only a unique
`test/tmp/acceptance/acceptance-<uuid>/<profile>/` workspace:

| Path below that workspace | Purpose |
| --- | --- |
| `owner.json` | Invocation, repository, lane and private runs-directory identity |
| `result.json` | Strict suite result, coverage accounting, provenance, budgets and artifact references |
| `driver/` | Production-format `PipelineLog`, `events.jsonl` and acceptance operation spans |
| `runs/` | Real fixture job attempts, accepted handoffs, indices, logs and other run-owned evidence |
| `processes/collection/` | Collection log, pytest outcome, exit/gate records and supervisor result |
| `processes/case-<node-hash>/` | The same per-case records plus private pytest cache/base-temp |
| `home/`, `temporary/`, `dagster/` | Private HOME/profile, TEMP/TMP/TMPDIR and DAGSTER_HOME |

The public command prints `acceptance: PASSED|FAILED; <N> cases; <seconds>s` and the path to
`result.json`. Exit 0 requires all selected obligations to pass with confirmed cleanup;
execution failures return 1, while invalid options/profile/deadline selections return 2.

`appsec-review/acceptance-result/1` records the tested commit, dirty-working-tree flag,
inventory SHA-256, source-file SHA-256 identities, Python versions, selected/collected nodes,
selected/executed/failed/skipped/unexecuted obligations, prerequisites, case outcomes, cleanup
and `coverage_status`. Source identities cover the declared files recorded by the driver;
they are not an attestation of every transitive dependency. A dirty result must not be described
as testing only the named commit.

Each supervised process retains `pytest.log`, `pytest.json` and `supervisor.json`. Preserve
these alongside the result when reporting a failure; read the named node's log instead of
substituting an unrelated green unit result. Cases retain setup/call/teardown phase durations;
the supervisor records elapsed time and cleanup duration. The suite's
`setup_duration_seconds`, when present, ends before supervised collection, not after all fixture
setup. If a prior measurement did not capture setup time, report it as unavailable.

Telemetry reuses production `PipelineLog`, `EventLog` and `operation_span` formats, but **only**
under these test-owned roots, with acceptance namespace/invocation correlation. It is not
copied into production metrics destinations. Operation spans report wall duration and
`os.times()` process CPU deltas. Child CPU and span-attributable peak RSS remain null with
explicit reasons; Linux `/proc/self/io` supplies I/O deltas where available, otherwise I/O is
null with `proc_io_unavailable`. Missing or interrupted measurements keep their unavailable
reason; never reinterpret nulls as zero resource consumption.

## Isolation, supervision and fixture discipline

The driver strips inherited deployment selection, credentials, SDK endpoints and pytest/plugin
overrides, and supplies private home/temp/Dagster paths. The plugin guards Python file access,
mutation, network use and child execution: no repository `targets/`, production `runs/` or
`data/`, no external network (only loopback/owned local sockets), no production service commands,
and no shared Docker cleanup. Redirected scratch roots and paths escaping the invocation are
rejected. The guard catches accidental regressions; it is **not a hostile-code sandbox** or
proof that arbitrary native code cannot access the host.

The supervisor opens the execution gate only after ownership is established. Windows uses a
private kill-on-close Job Object without breakaway. Linux uses a subreaper with verified
process identities and descendant cleanup, including adopted descendants; this path and the
Linux guardian/peer-credential cases have not been executed in the Windows evidence recorded
here. A case that exits with leftover descendants fails even if the assertions passed.
Cleanup kills only the invocation-owned tree, never processes selected by executable name.

For new fixtures:

1. Use `LaneWorkspace` and private `runs_dir`; nested acceptance helpers inherit the outer root.
2. Keep child working directories short on Windows, but still inside the owned root. Deep nested
   fixture paths can exceed Win32/process-tool path limits.
3. Do not launch child `git`. The supervisor resolves HEAD before the guarded test process and
   exports `APPSEC_ACCEPTANCE_TESTED_COMMIT`; use it rather than widening the executable guard.
4. Use application producers and certified validators at real joins. Write framework
   `handoff/2` fixture envelopes through `tests.handoff_fixture.write_fixture_handoff`; do not
   replace unchanged review/gate/report domain contracts to make an integration pass.
5. Add exact inventory nodes, budgets, substitutions and named deferrals. Preserve substantive
   existing unit/job coverage; deleting failing tests does not establish integration adequacy.

## Remaining commissioning

Current results do not authorize or demonstrate actual WSL dispatch, native containers/daemon
compatibility, provider access, cold builds, current CodeQL exports, Lua/native-variant
compatibility or a full language/runtime matrix. The unknown original producer of a recorded
feed is not a real live-computation claim. Positive source-bound OWASP assessment-to-review
integration remains absent; the controls case proves the configured source-evidence path and
its named missing-assessment gap. The pinned Dagster run object lacks `create_timestamp`, so
queue-delay timing is unavailable.

Triage/referral/presentation joins and final integrated calibration are separate pending work
until their own results are recorded. See the implementation record before treating older
focused, nested-plugin or direct pytest timings as public-driver acceptance evidence.
