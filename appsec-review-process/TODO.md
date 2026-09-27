# AppSec Review TODO: run four targets through to a report

Approach: [ADR-0013](../docs/decisions/ADR-0013-run-to-report-first.md). Run `full_review`, fix the
first thing that breaks, re-run, until the target produces its report. Breakage is expected. Process
hardening (qualification rituals, recovery proofs, batch protocol) is out of scope.

The earlier batch backlog and phase plan were removed on 2026-09-27; see git history at `2e98423a`.

## Targets, in order

| # | Target | Source | Pinned commit | What it exercises | Status |
|---|---|---|---|---|---|
| 1 | `hello-autotools` | `github.com/wsollers/hello-autotools` | `632522b` | C/autotools, vendored cJSON, Dockerfile; known answer key on branch `with-vulnerabilities-doc` | NEXT |
| 2 | `appsec-multi-vuln` | `github.com/wsollers/appsec-multi-vuln` | `878d5d6` | C++, C#, Go, Java, JS/TS, PHP, PowerShell, Rust, Bash and six Dockerfiles; answer key in private `appsec-multi-vuln-guide` | TODO |
| 3 | `freeciv21` | `github.com/longturn/freeciv21` | `0ce1c60` | Large CMake/Qt C++ codebase, many build dependencies | TODO |
| 4 | `doom3-bfg` | `github.com/id-Software/DOOM-3-BFG` | `1caba19` | Large Windows-oriented C++ (MSVC/clang-cl, ADR-0003); a Linux build is expected to fail and appear as gaps | TODO |

`fixtures/populate-targets.sh <name>` clones each target at its pinned commit into
`fixtures/targets/<name>`.

A target is **done** when `full_review` publishes its synthesis report. Build failures, unsupported
languages and tools that did not run appear as gaps inside the report; they do not block it.

## Before the first run

`orchestrator/prepare-host.sh` does every host prerequisite and is safe to re-run;
`--check` reports what is missing without changing anything, `--buildenvs` also builds the
per-language build images (expected for appsec-multi-vuln). It covers: offline Grype/OSV snapshots
within the 14-day ceiling (already registered on zarathustra 2026-09-27), the Dagster stack, the
images the B13 registry needs (on zarathustra: `audit-report`, `tool-osv-scanner`,
`tool-microsoft-sbom-tool`, `tool-sbomasm` were missing), B16 registry records, the code location
(started in the background, log `orchestrator/dagster/.host/code-location.log`), the four target
clones and a Claude CLI probe. Machine layouts (zarathustra, hal5000 WSL and Windows) and the
host-local state each one keeps: `docs/processes/host-layouts.md`.

## Running a target

`orchestrator/stage-run.sh <target>` creates and stages the run (the steps in
`docs/report-path/happy-path-operator-guide.md`, with `--max-database-age-seconds 1209600`) and prints
the run id; then:

```bash
python3 appsec-review-process/launch_job.py --run-id "$RUN_ID" --job full_review --wait
```

`python3 orchestrator/run-status.py <run-id> [--failed]` lists every job's latest status and cause.

When a run stops: read the failing op's status/result in `runs/$RUN_ID/data/jobs/<job>/`, fix the
cause, `code-location.sh reload`, and re-launch the same run (accepted upstream attempts are reused).
Start a fresh run only when the fix changes what an upstream job would have produced.

For `hello-autotools`, the test step needs `python3 -B appsec-review-process/test_evidence.py
stage-control "$RUN_ID"` once the native build is accepted (see the operator guide).

## Target notes

- **appsec-multi-vuln.** OSV has only the npm ecosystem registered; other ecosystems (Go, Maven,
  crates.io, NuGet, Packagist, PyPI) need their own snapshots for OSV matching, otherwise they are OSV
  gaps (Grype still matches them). Score the report against `appsec-multi-vuln-guide` afterwards.
- **freeciv21.** Expect the build-plan and build-resolution steps to need Qt and many system
  packages; long runtimes for native analysis, Joern and search indexing.
- **doom3-bfg.** Upstream builds on Windows only. Expect build-resolution/native-build gaps on Linux;
  source SAST, secrets, search and the persona review lanes should still run from source.

## Follow-ups (after hello-autotools reaches a report)

- [ ] **Source SAST Semgrep rules.** `data/source-sast/rules-v1.yml` has only 4 C/C++ rules
      (strcpy, non-literal printf, memcpy, system), so `02-source-sast` always reports the gap
      "Repository-owned C/C++ Semgrep rules do not cover every source-analysis family". Decided
      (William, 2026-09-27): vendor the 16 C rules from `opengrep/opengrep-rules` at
      `f1d2b562b414783763fd02a6ed2736eaed622efa` (LGPL-2.1 + Commons Clause; keep LICENSE and a
      NOTICE naming the commit) under `data/source-sast/`, add a second `--config`, map their rule ids
      in `source_sast.RULE_CATEGORIES`, and extend the closed category enum in
      `schemas/source-sast.schema.json`. Keep our 4 rules. Then narrow the gap text to what is still
      uncovered.
- [ ] **Semgrep/opengrep code signals for partitioning.** The design intended rule-based signals to
      inform partition discovery; nothing does that today (partition discovery is a single persona
      call over the intake file list and file contents). Add a deterministic job before
      `02-repository-partition-discovery` that runs structural rules (entry points and argv parsing,
      socket listen/accept and HTTP routes, file/DB/IPC access, exec/system, crypto,
      deserialization) and publishes per-file/per-directory tags with citations; feed them to
      partition discovery and `01-component-characterization` as an upstream.

## Breakage log

Newest first. One line per breakage: date, target, run id, job, what broke, fix (commit).

| Date | Target | Run | Job | Breakage | Fix |
|---|---|---|---|---|---|
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-build-resolution` | BLOCKED `STALE_GRANT`: build grants bind to the hash of `artifact-manifest.json`, which intake rewrites on acceptance; the controls had been staged before intake | Operator order: run `phase1_intake` before `build_resolution`/`build_configure stage-control` (`stage-run.sh`, operator guide); this run's controls re-staged after intake |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-repository-partition-discovery` | Result rejected: claim-class text check read the model's disclaimer "not asserted as a verified finding" as a finding promotion (negation lookbehind only matched "not a "/"no ") | `validate_job_output`: a promotion phrase counts only without a negation (not/no/never/without/nor) in the 40 characters before it |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `persona-tool-pool-dispatch` | BLOCKED: no pinned `model-versions.json`; the job ran before discovery pinned model identities | `persona_tool_pool_lifecycle._current_inputs` calls `resolve_run_model_versions(run_id)` first, like every other persona worker |
