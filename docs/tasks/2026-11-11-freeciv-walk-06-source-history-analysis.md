# Freeciv walk 06 - `job_source_history_analysis`

This record advances T-057 and bears on T-097. Terms: [walk terms](../walks/freeciv-b1b0768b.md).

**Result: stopped for decisions, not accepted** (run `2026-11-12-0001`, overlay
`freeciv-b1b0768b/capacity-overlay.toml`, corpus tag `freeciv-b1b0768b-v3`). The job completed
(`SUCCEEDED`, `COMPLETED_WITH_GAPS`, 0 findings, audit clean, check report passed), but gap causes
outside the expected list appeared and one of them points at a possible defect. Nothing was
repaired, saved as a baseline or accepted.

## Run

- Expected duration (charter section 10): unknown (first run on this target and overlay); look at
  30 minutes.
- Dagster run `ad630bf6-36ef-4092-b819-547c0707bba5`, `attempt_0001`, launched 2026-11-12 07:28:49Z.
  `next` wall time 5 min 49.6 s, well inside the mark. Steps: git history about 1 min, GitHub
  enrichment about 2 min, blame, spans and line history about 55 s.
- The first launch (a background process inside the WSL shell) died with the shell and wrote
  nothing; no job started. It was relaunched with the WSL command as the background task.
- Replays: 0.

## Gaps (28 unique, 49 occurrences; from the check report and `attempts/attempt_0001/outcomes.json`)

| Cause | Where | On the expected list? |
| --- | --- | --- |
| `.git` excluded; no target document of kind design, dfd, openapi, postman, threat_model, unit_test | target-files, target-documents (6 kinds) | yes (rows 2, 9, 10) |
| `compile_commands.json` not present | compile-units | yes (row 7) |
| `untracked_path`, `working_tree_divergent`, `head_differs_from_mainline`, `timestamp_anomaly:1` | git-history, bind_snapshot, index_history, publish_handoff | **no** |
| `fix_on_fix_undetermined` | fix-on-fix and downstream | **no** |
| `parse_errors_present`, `parse_errors_in_span`, `preprocessor_branches_not_counted`, `symbol_language_unsupported` | symbol-spans and downstream | **no** |
| `changelog_format_unrecognized` (NEWS 4,993 lines, NEWS-3.2 749 lines), `changelog_mixed_format` (ChangeLog 3,796 lines, ChangeLog-1.0-S3_0 75,924 lines), `changelog_paths_unbound` (24,204 path mentions, 0 matched) | acquire.changelog_history | **no** (T-097's author expected unbound paths; not on the walk list) |
| `deployment_timing_not_acquired`, `pr_timing_not_acquired` | deployment-timing, pull-request-timing | **no** |
| configured history or change-context bounds reached (row 6) | - | not observed |

## Checks

- **A. Inputs.** Not completed. Both reading units report upstream `attempt_0003`, handoff
  `c88c2cbd...`, coverage `complete`. That pointer was not compared with the run's accepted
  pointers in this session. Not verified.
- **B. Independent comparison.** Partial; the result is a finding, not a pass.
  - Target (git, on the host): HEAD `b1b0768b`, clean, not shallow, 31,479 commits reachable from
    HEAD, 6,726 tracked files.
  - `bind_snapshot`: 3,307 eligible files, 1,878 exact, 1,429 divergent, 189 untracked. On the
    host `git ls-files --others` lists 0 files and `git status` is clean.
  - Example `.github/workflows/ci.yml`: the file bytes in the container and on the host agree with
    the sha256 the job records (`bc386e8f...`, 249 lines). The job records blob id `34cbd111...`;
    git at the pin has `b4137ec5...` for the path, and `git hash-object` of the file also gives
    `b4137ec5...`. Blob `34cbd111...` exists in the object store. So the job compares the working
    tree with a revision that is not the pin. The `head_differs_from_mainline` gap names the same
    condition.
  - The target clone holds `main`, `origin/*` branches and 58,798 commits in all
    (`git rev-list --all`), against 31,479 from the pinned HEAD. Whether the history units read the
    pinned HEAD or the mainline tip was not established.
  - Change logs: formats git-log and svn-log, 20,924 entries, 4 files, 2,389 bound files,
    `changelog.json` 9.8 MB. Not compared with the two files; the 24,204 unmatched paths were not
    examined.
  - Not compared: commit counts of the history acquisition, bound ranks, symbol spans.
- **C. Gaps.** Table above. Several causes are not on the list: stop.
- **D. Baseline.** Not saved; the job is not accepted.

## Blindness note

While sizing the question I ran `git log --all -1 -- .github/workflows/ci.yml` and a loop over
`git log --all` for that one file in the target. The output included one commit subject
("CI: Do not install libsdl2-gfx-dev for meson job") that I used for nothing. I looked at no other
commit and searched for no advisory or fix. Whether that commit is later than the pin was not
checked. Reported because the clone contains revisions later than the pin, and the terms put later
upstream revisions off limits.

## Decisions for the user

1. **Is the history read at the pin?** If the job analyses mainline history or compares against the
   mainline tip, its output (blame ages, co-change, fix-on-fix, symbol history) uses revisions
   later than the pin and is not a blind history of this target; the 1,429 divergent and 189
   untracked files would be the symptom. That is a probable defect in the job, not yet sized.
   Options: (a) the walker sizes it read-only and proposes a fix; (b) hand it to a separate
   session; (c) the user confirms it is intended and accepts. Recommendation: (a).
2. **Gap causes to accept or fix.** Which of `fix_on_fix_undetermined`, the parse and symbol gaps
   (C code, preprocessor branches), the change-log gaps (`NEWS` is not a change log; the two
   ChangeLog files report mixed format and bind 0 of 24,204 paths) and the timing gaps join the
   expected list for this walk. Recommendation: decide after 1, since divergent bindings may cause
   several of them.

## Not verified

Check A (accepted pointers), the history, blame and span results, whether the GitHub enrichment
reached the network (the step ran about 2 minutes; not examined), whether any output holds author
names, addresses or message text (T-097 done-when), and bound-file ranks.

## Commands

```sh
.venv/bin/python deploy/dagster/bin/stepwise.py next --app-run 2026-11-12-0001   # 5 min 49.6 s
```

No unit tests were run.

## Defect found and fixed (2026-11-12, after the stop)

**Root cause.** `resolve_git_source` (`sources.py`) took `refs/heads/main` as the snapshot when it
existed and only fell back to `HEAD` otherwise. The target clone is detached at the pin with a
local `main` far ahead. The job bound the working tree to the `main` tip (1,429 divergent, 189
untracked on a clean tree) and `git.py` wrote that commit as the synthetic `HEAD` every history
command starts from, so first-parent history, blame and line history were read from `main`, past
the pin. Pinned revisions did not apply because a direct checkout carries no acquisition pin.

**Fix** `38777f90` (pushed with `251e9345` and `d901bac4`; origin/main at `d901bac4`): `HEAD` is the
snapshot; `main` or `master` only when `HEAD` cannot be resolved (observation
`head_unresolved_using_mainline`); `head_differs_from_mainline` is no longer emitted. Regressions
`test_pinned_detached_head_is_the_snapshot_not_a_newer_main` and
`test_unreadable_head_falls_back_to_the_mainline_tip_and_says_so` failed before. Documented in
`docs/architecture/source-history-analysis.md`.

**Tests.** 3 focused tests, then 11 symbol tests and 8 graph tests passed (the graph tests take 2
to 15 minutes each, far over the 10 s limit; the slowest,
`test_large_message_and_path_bounds_never_yield_complete_history`, 919 s). Before the fixture fixes
the history tests failed for host reasons unrelated to this change: the fixture copied 5.2 GB of
untracked `containers/` per test and patched duplicate release keys, and 19 tests read an image id
the tracked catalog no longer carries (T-051). The history files were not run as one complete set;
the 19 failing tests were rerun in groups and passed. The four other test files that use the new
copy helper did not finish a run; the helper was checked by reading the code only.

## Rerun after the fix (2026-11-12, run `2026-11-12-0001`, `attempt_0002`)

**Result: stopped for decisions, not accepted.** The history now binds to the pin. The gap causes
that remain are still off the expected list (below).

**Time and what was lost.** Rerun itself: Dagster run `d2474825-8fa7-4183-a77a-48335dcf6ffc`,
`SUCCESS`, `COMPLETED_WITH_GAPS`, about 2 minutes of steps (history 1 min). About 25 minutes went
to getting it launched, not to the job:

- `lifecycle.py reload` (3 min 37 s) recreated the services from `deploy/dagster/.env`, whose
  defaults are the multi-vuln target and overlay. The first relaunch failed in its begin step
  (`run is already bound to a different configuration ... overlay cpp-multivuln-v1`). The walk's
  `scripts/stack-restart.sh --code-location-only --target freeciv --overlay
  freeciv-b1b0768b/capacity-overlay.toml` (3 min) restored them. Use that, not a bare `reload`.
- The second relaunch failed with `implementation changed: plan-repair and admit-repair are
  required`. `stepwise.py recover --app-run 2026-11-12-0001` (verifies every recorded dispatch,
  19 of them), `plan-repair` (admissible; job 6 `RUN`, its downstream jobs `INVALIDATE`,
  `job_review_intake` and `job_target_catalog` `REUSE`), `admit-repair` with the plan under `runs/` (the container does not mount
  `test/tmp`), then `next --relaunch` launched. `recover --plan` itself refused ("mismatched
  current attempt/state") because job 6's attempt was complete rather than failed; `next
  --relaunch` did not need it.

**Checks.**

- **A. Inputs. Verified.** The run's reads name `job_review_intake` `attempt_0003`
  (`c88c2cbd...`, complete, 0 gaps) and `job_target_catalog` `attempt_0003` (`7d2e0c7f...`,
  partial, 28 gaps). `sha256sum` of those two `handoff.json` files in the run equals both hashes,
  and they are the attempts the state file lists as accepted.
- **B. Independent comparison. Verified for the items below; not for symbols, blame ranks or
  change logs.** On the host, target HEAD `b1b0768b`, 0 status lines, 6,726 tracked files,
  31,479 commits from HEAD. The job: `snapshot_commit` equals HEAD, `mainline_ref` null, no
  observations; `bind_snapshot` exact, 0 divergent, 0 untracked, 3,496 matched, 6,726 tree entries;
  `ci.yml` blob `b4137ec5...` now equals git. The window anchor 1788413334 equals HEAD's commit time
  (`2026-09-03T10:28:54+05:00`); the job reports 113 changes in the 6-month window and git counts 113
  first-parent commits since the window start. The walk read 20,000 first-parent commits, the
  configured `max_changes = 20000` (31,468 first-parent commits exist); because the log is
  newest-first, the 113 in-window commits are inside it. That bound produced no gap record: the
  history is complete for the window. GitHub enrichment: 114 requests, 113 facts, 0 gaps.
  Not compared: classification, co-change and fix-on-fix outputs, symbol spans, the 50 blamed files'
  ranks, change-log binding.
- **C. Gaps (28 unique, 49 occurrences).** Gone since the stop: `untracked_path`,
  `working_tree_divergent`, `head_differs_from_mainline`, `fix_on_fix_undetermined`. Now:

  | Cause | On the expected list? |
  | --- | --- |
  | `.git` excluded; no target document of six kinds; `compile_commands.json` not present | yes (rows 2, 9, 10, 7) |
  | `blame_bound_reached` (177 candidates, 50 blamed), `line_history_bound_reached` | yes, row 6 (bounds reached) |
  | `line_history_file_too_large` | a size bound; row 6 is about history bounds, so ask |
  | `timestamp_anomaly:1` | no |
  | `parse_errors_present`, `parse_errors_in_span`, `preprocessor_branches_not_counted`, `symbol_language_unsupported` (symbol spans) | no |
  | `changelog_format_unrecognized` (`NEWS` 4,993 lines, `NEWS-3.2` 749), `changelog_mixed_format` (`ChangeLog` 3,796, `ChangeLog-1.0-S3_0` 75,924), `changelog_paths_unbound` (24,204 mentions, 0 matched) | no |
  | `deployment_timing_not_acquired`, `pr_timing_not_acquired` | no |

  The charter stops the walk on any cause not on the list.
- **D. Baseline.** Not saved; not accepted.

**Decisions for the user (replaces decision 1, now answered).** Which of the following join the
expected list for this walk: the symbol and parse gaps (C code with preprocessor branches);
`line_history_file_too_large`; the change-log gaps (`NEWS` is not a change log; both ChangeLog files
are mixed format and bind 0 of 24,204 paths, which may be a defect worth its own look since entries
are 20,924); `timestamp_anomaly:1`; the two timing gaps. Recommendation: accept the timing gaps (no
network source for a local clone), the symbol and parse gaps and the size bound as detection
limits, and fix or size the change-log binding before accepting.

## Commands (rerun)

```sh
.venv/bin/python deploy/dagster/bin/lifecycle.py reload                     # 3 min 37 s; resets target and overlay
scripts/stack-restart.sh --code-location-only --target freeciv --overlay freeciv-b1b0768b/capacity-overlay.toml   # 3 min
.venv/bin/python deploy/dagster/bin/stepwise.py recover --app-run 2026-11-12-0001
docker exec appsec-review-dagster-wsl-code-location-1 python -m appsec_review plan-repair --run-id 2026-11-12-0001 --target /opt/app/targets/freeciv
docker exec appsec-review-dagster-wsl-code-location-1 python -m appsec_review admit-repair --run-id 2026-11-12-0001 --target /opt/app/targets/freeciv --plan /opt/app/runs/walk06-plan.json
.venv/bin/python deploy/dagster/bin/stepwise.py next --app-run 2026-11-12-0001 --relaunch
```

No unit tests were run in this part.
