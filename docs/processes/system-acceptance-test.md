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
| 3 | `run-create` | `run_process.py --start` creates the run | |
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

1. The Docker engine answers `docker version` (else: the recovery steps, stop).
2. `orchestrator/dagster/.env` exists and, under WSL NAT, `APPSEC_CODE_LOCATION_HOST` equals this WSL
   boot's IP (else: restart the code location, which rewrites it).
3. `docker compose up -d` (idempotent; recreates webserver and daemon when the address changed), then
   postgres, webserver and daemon all `running/healthy` within 240 s.
4. Inside the webserver, `host.docker.internal` resolves to the code location's address.
5. `code-location.sh check` (gRPC health) passes, and `code-location.sh reload` reports `LOADED`.
6. The loaded job list includes the jobs the SAT drives (`phase1_intake`,
   `repository_partition_discovery`, `dev_project_discovery`, `engagement_workflow`, `full_review`),
   and every daemon Dagster marks required is healthy.

Evidence: engine version, service states, code location address, what the webserver resolves, the
loaded job list and the required daemons.
