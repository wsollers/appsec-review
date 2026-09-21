# Linux host baseline, 2026-09-20

First full run of the suites and qualifiers on a **native Linux** host with the live Dagster stack,
taken on branch `claude/linux-host-bringup` (base `732560c`, i.e. `main` without V15) right after the
bring-up fixes in `orchestrator/dagster/` (see that README, "Native Linux host"). It records a state,
including what is broken; it fixes nothing outside the stack configuration.

Host: Ubuntu 24.04, Docker 29.1.3, Compose 2.40.3, runtime containers as uid/gid 1000.
Image `appsec-review-dagster:local` built from this branch (Python 3.12.14, dagster 1.13.21,
libfuzzy2 2.14.1). Target: Freeciv21 `0ce1c60acf1140d6c5c5a5cd6bef2507bd072319`.
Owner/qualification run: `20260920T222922Z-acacfe` (under the ignored `runs/` root).

## Unit suite inside the code-server

`python -B -m unittest discover -s /opt/process/tests -p "test_*.py"`: 822 tests.

| Pass | Result | Cause of the failures |
|---|---|---|
| 1 (before the `data/reference` mount) | 1 failure, 78 errors | `data/reference/` not mounted: every OWASP-workbench suite and `test_reference_snapshots` |
| 2 (this branch) | **1 failure, 59 errors, 1 skip** | below |

Remaining, none caused by this branch:

1. **59 errors, one cause (T05, `owasp_batching.py`).** `_load_batch_config` resolves the request's
   `batch_config.path` (`appsec-review-process/config/owasp-batching/default-v1.json`) against the
   repository root. In the container the tree is `/opt/process`, so `/opt/appsec-review-process/...`
   does not exist and the worker raises "batch config must be a tracked file…". T05 cannot run in
   the code-server, and the T06–T09 suites that build on it fail with it. Options: resolve against
   the process root in code, or mount the tree a second time at `/opt/appsec-review-process`. It is
   a contract question (what a path inside a request means); not decided here.
2. **1 failure, already on `main`:** `test_build_discovery…test_all_registry_jobs_have_lifecycle_nodes`.
   `registry/job-templates/10-critical-findings-sarif.json` (B09, PR #2) has no node in
   `job-graph.json`.

Previously failing in the container and now passing because `docs/` is mounted: the two
`test_evidence_redaction` tests that read `docs/evidence/evidence-redaction.md`.

## Qualifiers

| Qualifier | Result | Notes |
|---|---|---|
| `qualify_phase1.py` (A01–A16) | **A02–A16 PASS; A01 not attempted → `NOT ACCEPTED`** | All 17 steps exit 0 (host tests, code-server tests, live Dagster, restart + restart-check, Freeciv21 intake, reuse, status, handoff, validate, graph); code identity stable. A01 needs a `prompt-vetting.json` review record in the qualification run; a fresh run has none and one was not fabricated. Report: `data/acceptance/q-60ea5f65/acceptance.md` |
| `qualify_evidence_index.py` | PASS | `main`'s worker (pre-V15). V15's own requalification is recorded in PR #25 |
| `qualify_workflow.py` | PASS | real queue, multiprocess branches, branch recovery |
| `qualify_worker_adoption.py` | PASS | |
| `qualify_sarif_adoption.py` | PASS | |
| `qualify_build_discovery.py` | **FAILED at its last assertion** (fixed afterwards, see Corrections) | Build discovery itself was accepted and reused. The qualifier expected `full_review` to be blocked at `02-repository-partition-discovery` by a `WORKER_NOT_IMPLEMENTED` `pre.json`; that node is now `discovery_gate`'s hand-off gate and records a `BLOCKED` attempt with `HANDOFF_ISSUED` under `data/jobs/` instead. Stale qualifier only |
| `qualify_build_execution.py` | **FAILED** | `configure failed inside buildenv: exit 127`: `/opt/images/audit-buildenv-common/run.sh` is absent, and that wrapper does `docker run`, while the code-server deliberately has no Docker socket. This is the B13 pinned-container-adapter gap, not a mount to add |
| `qualify_tooling.py` | `MISSING_IMAGE` | no `audit-buildenv-*` image is built on this host |

Operator errors made while taking the baseline, for whoever repeats it: `qualify_phase1.py` needs a
run created first with `run_process.py --start`; `qualify_build_execution.py --run-id` wants the
*engagement* that holds an accepted build-discovery branch, not the owner run.

## Not covered

Windows. The Codex OWASP lane beyond its unit suites. Any worker that is not implemented
(most of the 42 graph jobs block with `WORKER_NOT_IMPLEMENTED`).

## Corrections (same day, branch `claude/linux-baseline-fixes`)

- The first version of this document said `02-repository-partition-discovery` "now runs" and that
  `job-graph.json`'s `implemented: false` was stale. **That was wrong.** It is a validated hand-off
  gate that does no analysis and blocks until a partition map is supplied; `implemented: false` is
  correct. Only the qualifier's expectation was stale, and it now asserts the hand-off.
- Item 2 above is not a missing graph node. `docs/dagster/critical-findings-sarif-job.md` makes the SARIF
  transform a deliberately standalone registered job; the test exempted only `00-validation`. The
  test now pins both standalone templates, in both directions.
- Item 1 (T05 config path) is fixed by resolving the repository-path identifier against the process
  directory wherever it is mounted; the same pattern in `owasp_validator_handoff.py` (config and
  prompt) was fixed with it.
- After these three fixes, on the same stack: the whole unit suite inside the code-server is
  **857 tests, OK (1 skip)** (was 1 failure + 59 errors), and `qualify_build_discovery.py` is `PASS`
  (owner run `20260920T232243Z-169a47`). Still open from the table above: `qualify_build_execution`
  (B13), `qualify_tooling` (no buildenv images), and A01's prompt-vetting record.
