# System acceptance test (SAT)

One fixture, taken from a fresh clone of the system under test through the whole review cycle, to
SARIF and report generation. Built one stage at a time so each step can be examined and refined
before the next is added. Script: `scripts/system-acceptance-test.sh` (POSIX host);
`scripts/system-acceptance-test.ps1` runs it inside WSL from Windows.

```bash
cd ~/projects/appsec-review
scripts/system-acceptance-test.sh --list                                # stages, and which are built
scripts/system-acceptance-test.sh --through sut-checkout                # new SAT, run to that stage
scripts/system-acceptance-test.sh --resume <sat_id> --through <stage>   # continue an earlier SAT
```

```powershell
.\scripts\system-acceptance-test.ps1 -Distro Ubuntu-24.04 --through sut-checkout
```

Each SAT has an id (UTC timestamp) and a record under
`appsec-review-process/logs/system-acceptance/<sat_id>/` (gitignored): `sat.json` with per-stage
status (`PASS`, `FAIL`, `NOT_IMPLEMENTED`) and evidence, plus one log per stage. A failing stage
stops the SAT; a stage that is not built yet stops it with `NOT_IMPLEMENTED` (exit 3), never a
silent skip. `--resume` skips stages that already passed in that SAT, except `sut-checkout`, which
is re-verified (same HEAD, still clean) because every later stage reads that checkout.

## Stages

| # | Stage | Proves | Built |
|---|---|---|---|
| 1 | `sut-checkout` | Fresh clone at the pinned commit; clean; origin correct; no answer key or defect comments on the reviewed revision | yes |
| 2 | `services` | Dagster services healthy; host code location serving; job list reloaded | yes |
| 3 | `run-create` | `run_process.py --start` creates the run | yes |
| 4 | `stage-inputs` | `stage_artifacts.py` writes a valid manifest (executor platform `posix`) | yes |
| 5 | `intake` | `00-intake` accepted | yes |
| 6 | `partition-discovery` | Hand-off with nothing supplied; partition map supplied and accepted | yes |
| 7 | `dev-project-discovery` | Project discovery supplied and accepted | |
| 8 | `engagement-workflow` | Preparation branches and join published | |
| 9 | `build-configure` | `02-build-configure` through B13 in the pinned build image (needs Phase 3, Phase 4, E01) | |
| 10 | `native-build` | Compile database and build outputs | |
| 11 | `evidence` | Evidence jobs accepted or explicitly skipped | |
| 12 | `evidence-index` | `02-evidence-index` accepted | |
| 13 | `review-lanes` | 01 through 09, 11, 12 | |
| 14 | `sarif` | Accepted SARIF from verified findings | |
| 15 | `report` | Report generated | |

### 1. `sut-checkout`

Starts from nothing. An existing checkout of the fixture is deleted only if it is a clean clone of
the expected origin; anything else (wrong origin, local changes, not a clone) is refused and left
for a person. It then clones through `fixtures/populate-targets.sh` (the single source of the pin)
and checks: HEAD equals the pin, the tree is clean, the origin is right, `docs/VULNERABILITIES.md`
is absent and `src/` has no `VULN`/`CWE-` comments (the answer key stays on the fixture's
`with-vulnerabilities-doc` branch, so the SAT measures detection, not recall of the fixture's notes).
Evidence: fixture, origin, pin, HEAD, tree hash, tracked-file count.

### 2. `services`

Brings up this project's own Compose services and checks that jobs can run. The host code location
runs in the foreground in its own terminal, so this stage checks it and never starts it; start it
first with `orchestrator/dagster/code-location.sh start`.

1. The Docker engine answers `docker version` (else: why, and the recovery steps). If Docker Desktop
   answers while a native `docker` service is also active in the distro, the stage fails: the two
   compete for `/var/run/docker.sock`, which wedged the engine on 2026-09-23.
2. `orchestrator/dagster/.env` exists and, under WSL NAT, `APPSEC_CODE_LOCATION_HOST` equals this WSL
   boot's IP (else: restart the code location, which rewrites it).
3. `docker compose up -d` (idempotent; recreates webserver and daemon when the address changed), then
   postgres, webserver and daemon all `running/healthy` within 240 s.
4. Inside the webserver, the IPv4 answers for `host.docker.internal` include the code location's address
   (Docker Desktop adds its own, often IPv6, host-gateway entry for that name as well).
5. `code-location.sh check` (gRPC health) passes, and `code-location.sh reload` reports `LOADED`.
6. The loaded job list includes the jobs the SAT drives (`phase1_intake`,
   `repository_partition_discovery`, `dev_project_discovery`, `engagement_workflow`, `full_review`),
   and every daemon Dagster marks required is healthy.

Evidence: engine version, service states, code location address, what the webserver resolves, the
loaded job list and the required daemons.

### 3. `run-create`

The security engineer's first command, run the way the jobs run: `code-location.sh run -B
appsec-review-process/run_process.py --start` (the code location's Python and `APPSEC_*` paths).

1. The output names a run id of the form `YYYYMMDDTHHMMSSZ-xxxxxx`.
2. `appsec-review-process/runs/<run_id>/` exists with `data/`, `inputs/` and `outputs/`.
3. `run-status.json` is for this run, `READY`, with nothing completed and `resume_from` equal to the
   first lane of `process-manifest.json` (`00-intake-recovery`); `events.jsonl` holds exactly one
   event, `RUN_CREATED`.
4. `inputs/artifact-manifest.json` is still the unfilled template (stage 4 writes the real one).

The run id is written to `sat.json` (`run_id`); every later stage of this SAT works on that run, and
`--resume` shows it in the header. Evidence: run id and folder, status, creation time, first lane,
lane count, manifest state.

### 4. `stage-inputs`

States what is reviewed and why, through `code-location.sh run -B appsec-review-process/stage_artifacts.py`
on the run from stage 3. The engagement is fixed so every SAT stages the same one; `SAT_BUSINESS_GOAL`,
`SAT_PLATFORM`, `SAT_BUDGET` and `SAT_EXECUTION_ENVIRONMENT` override it for experiments.

| Parameter | SAT value |
|---|---|
| project | the fixture name (`hello-autotools`) |
| target | `fixtures/targets/<fixture>` (absolute host path) |
| business goal | "System acceptance test: full review cycle on the fixture" |
| platform | `Linux` |
| budget | `probe` |
| execution environment | `dagster-read-only-linux` |
| permissions | default, `read-source` only |

Checks on `inputs/artifact-manifest.json` (the intake contract): `orchestration_version` 1, this
run's id, the project, the resolved target path, goal, platforms, budget and execution environment
as given; `executor_platform` `posix`; permissions `read-source` only; whole-tree scope (`**`, no
excludes); no imports, no compile database, no supplied evidence (`pending-evidence`); and
`run-status.json` still `READY`. The eight "Expected before pregather" notes are counted, not
treated as errors: they name legacy pregather outputs that do not exist before anything has run.
Evidence: the staged values, the note count and the manifest's SHA-256.

### 5. `intake`

The first Dagster job: `code-location.sh run -B appsec-review-process/launch_job.py --run-id <run>
--job phase1_intake --wait` (`launch_job.py` submits and monitors; the work runs in the host code
location). The job must end `SUCCESS` within `SAT_JOB_TIMEOUT` (default 900 s); otherwise the stage
fails and prints the Dagster run URL. Then, on disk:

1. `data/jobs/00-intake/whole/accepted.json` is `OK`, was published by the Dagster run just launched,
   and points at the latest attempt; the attempt has `outputs/intake.json`,
   `outputs/build-discovery.md` and `status.json`, and every file still matches the hashes recorded
   at acceptance.
2. `intake.json`: `source_revision` is the pin from stage 1; business goal, platform, budget and
   permissions are as staged; it fingerprinted exactly the clone's tracked files (the clone is clean,
   so all files are tracked); `ready_to_collect` true, `pregather_complete` false, **no findings**;
   `native.build_status` `NOT_EXECUTED` with no commands attempted (intake never runs target code);
   partition discovery and developer project discovery are selected as `required`.
3. The manifest's `accepted_intake` equals the pointer and its `source_identity` names the pin; the
   run's `data/events.jsonl` has the `ACCEPTED` event for the attempt.
4. The checkout is unchanged (same HEAD, still clean).

Evidence: Dagster run, launch and attempt ids, revision and source fingerprint, file count, detected
families, native applicability and strategy, the selected jobs with their applicability, and the
number of recorded limitations. On `hello-autotools` the families are `autotools`, `cpp` and
`deployment` (the Dockerfile), so intake also marks DevOps and SRE discovery `required`.

### 6. `partition-discovery`

`02-repository-partition-discovery` is a supplied-result gate: it validates an analysis written by a
person or agent and never invents one. The stage proves both halves on the SAT's run:

1. **Nothing supplied.** `launch_job.py --job repository_partition_discovery --wait` must end
   `FAILURE`; the gate must have written `handoff.md` and `handoff.json` naming `supplied/result.json`
   and the `repository-partition-map` schema; nothing may be accepted. (Skipped, and recorded as
   skipped, if a result is already supplied, e.g. when the stage is re-run after a later failure.)
2. **Supply.** `fixtures/supply_record.py` installs the fixture's recorded analysis
   (`fixtures/supplied/<fixture>/02-repository-partition-discovery.json`); it refuses a checkout at a
   different commit or with local changes and never overwrites a different supplied result.
3. **Accept.** The gate is launched again and must end `SUCCESS`; `discovery_gate.validate` (the
   project's own validator) must accept the result; the accepted attempt must come from that Dagster
   run; the map's `source_revision` is the checkout's HEAD; its partitions are the record's; the
   `docs` partition is `deferred`; and every source-file citation's SHA-256 is re-computed from the
   checkout and must match (independently of the gate).

Evidence: both Dagster runs, the attempt, each partition's disposition, the primary personas and the
number of citations checked. On `hello-autotools`: `app`, `build`, `tests`, `vendored-cjson` review,
`docs` deferred, 19 citations.
