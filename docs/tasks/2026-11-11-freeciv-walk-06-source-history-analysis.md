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
