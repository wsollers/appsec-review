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
| 4 | `stage-inputs` | `stage_artifacts.py` writes a valid manifest (executor platform `posix`) | |
| 5 | `intake` | `00-intake` accepted | |
| 6 | `partition-discovery` | Partition map supplied and accepted | |
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
