# Freeciv walk 01 - `job_model_connectivity` (and the walk's standing terms)

This record advances T-057: the job-by-job walk of the Freeciv target requested by the user on
2026-11-11 ("go job by job. Verify everything. ... Lets try freeciv"). It also holds the terms
every later `2026-11-11-freeciv-walk-NN-*.md` record cites: the target, the overlay, the runs, the
four checks and the confirmed expected-gaps list.

**Result: accepted** (run `2026-11-11-0009`, corpus tag `freeciv-b1b0768b-v2`).

> Update 2026-11-12: merging the change-log history feature changed the frozen configuration, so the
> walk restarted as run `2026-11-12-0001` with corpus tag `freeciv-b1b0768b-v3`. This job was run,
> verified with the same independent checks and accepted there with the same numbers as recorded
> below for `2026-11-11-0009`; `0009` and its `-v2` keys are retained and are not the baseline.

## Walk terms

- **Target.** `targets/freeciv`, detached at `b1b0768bfaca9b2fae68f9466defe1e80636e9fa`, whole
  repository, clean. The target is reviewed blind: the answer files and the private answers
  repository are not read, and grading is the user's step after the walk. Agents do not touch the
  target. `stepwise.py accept` needs a Git tag at target HEAD; on the user's instruction the
  coordinating session created the local tag `freeciv-b1b0768b-v1` at that commit, passed as
  `--target-tag` (T-094 records the follow-up: accept by commit).
- **Stack.** Compose project `appsec-review-dagster-wsl`, profile `dev` (`claude-haiku-5-5` through
  the Claude CLI), recording `record`, image
  `sha256:7b71373ad05af149871a29f587ff475c3f4c08c5595535add1814e1190d74a9a`.
- **Overlay.** `test/acceptance/freeciv-b1b0768b/capacity-overlay.toml` (user instruction):
  `review_policy.resources.cpu = 20`, `io_slots = 4`; `memory_mb` stays 10240 and the Dagster pools
  stay at their defaults. The host has 24 cores and 15 GiB in WSL, so memory is the ceiling; if a
  step is killed for memory, `io_slots` drops to 2 and the record says so. Timings are not
  comparable with runs under another overlay.
- **Runs.** A run is bound to its configuration, so each configuration change needed a fresh
  `init`. `2026-11-11-0007`: no overlay, job 1 only. `2026-11-11-0008`: overlay, jobs 1-3 accepted
  under corpus tag `freeciv-b1b0768b-v1`, job 4 stopped on 38 oversized files. `2026-11-11-0009`:
  the walk, after the user's decisions on asset exclusions and the inventory bound and the merge
  of T-080 (walk 04). Earlier runs and the `-v1` keys are retained and are not the baseline.
  Within `0009`, implementation fixes are applied with the documented repair path
  (`stepwise.py recover`, `plan-repair`, `admit-repair`, `recover --plan`); the always-execute
  jobs 1-3 are replayed and re-accepted each time, with a preserved-key comparison.
- **Four checks before every accept.** A: the job consumed what its contract declares from this
  run's accepted handoffs. B: the output agrees with an independent source of truth in the target
  or host. C: every canonical gap (from the handoff's `outcomes.json`, not the check's repeated
  strings) is classified by cause. D: the job is accepted so its next run is a diff.

## Expected gaps (confirmed by the user 2026-11-11: "Yes, as written")

| Gap cause | Why it is expected | What accepting it costs |
| --- | --- | --- |
| No Unity or other engine project | Freeciv is a C codebase; there is no engine project to analyse | nothing |
| `.git` excluded from catalog and source inventory | repository metadata is not target source | nothing |
| PowerShell environment scripts not supported | the environment job does not parse PowerShell | any such script is unanalysed |
| Grype artifact coverage disabled by configuration | the configuration turns it off | **artifact vulnerability scanning is not covered in this walk** |
| No execution-profile artifacts | the target produces none | **prioritization has no hotness signal for this target** |
| Configured source-history and change-context bounds reached | a long history against the configured bound | history beyond the bound is not attributed |

Anything else stops the walk for a decision. Named in advance as not pre-approved: GUI clients or
tools that cannot be built for lack of a toolkit, vendored dependencies treated as first-party
build units, and the fragment build units of T-091. Oversized data files were put to the user and
are not an expected gap: they were resolved by policy exclusion and a higher bound (walk 04).

## What the job did

Resolved every enabled provider/model setting of the run's configuration and probed each distinct
pair. First dispatch `972e90c1-ea5e-4dad-b064-50f0a35a9bdf` (`attempt_0001`, 22.9 s job time,
`init` wall time 2 min 12 s); it has since been replayed after each admitted repair, with a
preserved-key comparison of 0 differences each time.

## Checks

- **A. Inputs.** The contract has no upstream; `claim.json` `upstream_handoffs` is `{}`.
- **B. Independent comparison.** A separate walk of `runs/2026-11-11-0009/data/configuration/resolved.json`
  finds 11 provider/model settings, all `claude-cli` / `claude-haiku-5-5`. The job reports 10
  required and 1 not required (`job_post_build_security_assessment`, model setting disabled):
  11 on both sides. The one distinct pair answered the availability probe; `unavailable` is empty.
  The resolved configuration carries the overlay (`cpu 20, io_slots 4, memory_mb 10240`), the
  inventory bound (12,582,912), the six asset classes, and the release ids: `platform` and
  `validation` declared, `build_toolchain` derived from the host-pinned native build image
  (`sha256:132466e35d67...`, T-080).
- **C. Gaps.** 0 canonical gaps.
- **D. Baseline.** `test/acceptance/freeciv-b1b0768b-v2/job_model_connectivity.json` and its
  provenance; seed `after-job_model_connectivity`.

## Commands

```sh
scripts/stack-restart.sh --code-location-only --target freeciv --overlay freeciv-b1b0768b/capacity-overlay.toml
.venv/bin/python deploy/dagster/bin/stepwise.py init --target /opt/app/targets/freeciv        # 2 min 12 s
.venv/bin/python deploy/dagster/bin/stepwise.py accept --app-run 2026-11-11-0009 \
  --job job_model_connectivity --tag freeciv-b1b0768b-v2 --target-tag freeciv-b1b0768b-v1
```

## Not verified

The probe shows the model answers one request; it does not show the login survives the walk.
`resolve_models/result.json` reports `not_required_count: 0` beside a one-entry `not_required`
list; the count is of pairs not also required, by design (`job_model_connectivity/job.py`).
