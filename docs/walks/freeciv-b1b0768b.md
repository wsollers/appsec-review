# Walk terms: Freeciv at `b1b0768b`

The terms of the job-by-job walk of Freeciv requested by the user on 2026-11-11 ("go job by job.
Verify everything. ... Lets try freeciv"). It advances T-057. The rules common to every walk are in
the [walk charter](../processes/walk-charter.md); the current position is in the
[state file](freeciv-b1b0768b-state.md); each job has a record
`docs/tasks/2026-11-11-freeciv-walk-NN-<job>.md`. This file supersedes the "Walk terms" and
"Expected gaps" sections of [walk record 01](../tasks/2026-11-11-freeciv-walk-01-model-connectivity.md)
as the place a session reads them.

A decision is added here in the user's words, with its date, before the walk acts on it. Nothing
here is changed to fit a result.

## Target

- `targets/freeciv`, cloned by the user from <https://github.com/freeciv/freeciv>, detached at
  `b1b0768bfaca9b2fae68f9466defe1e80636e9fa`, whole repository, clean
  ([test targets](../operations/test-targets.md)).
- **Whole repository on this host** (user, 2026-11-11: "Keep whole repo").
- **Tag exception.** `stepwise.py accept` needs a Git tag at target HEAD. On the user's instruction
  the local tag `freeciv-b1b0768b-v1` was created at the pinned commit and is passed as
  `--target-tag`. It is the only change any session has made or may make under `targets/freeciv`.
  T-094 registers accepting by commit. The `-v2`, `-v3` names in the records are acceptance corpus
  namespaces under `test/acceptance/`, not target tags.
- **Blind.** Off limits for steering, checking or explaining a job: the private
  `appsec-review-answers` repository, `docs/reviews/fix-pair-corpus-candidates.md`,
  everything under `test/acceptance/fix-pairs-candidates/`, and any advisory, fix commit or later
  upstream revision of Freeciv. The pin's rationale in the test-targets table is not a lead to
  follow. Grading is the user's step after the walk.

## Host and stack

- WSL `Ubuntu-24.04`, checkout `~/projects/appsec-review` on `main`; 24 cores, about 15 GiB of
  memory in WSL. Memory is the ceiling; raising the WSL limit is the user's decision.
- Compose project `appsec-review-dagster-wsl`, profile `dev`.
- **Overlay** (user, 2026-11-11: "have the walk session create it and use it"):
  `test/acceptance/freeciv-b1b0768b/capacity-overlay.toml`, `cpu = 20`, `io_slots = 4`,
  `memory_mb` and the pools at their defaults. If a step is killed for memory, `io_slots` drops
  to 2 and the record says so. Timings are not comparable with runs under another overlay.
- The other review host walks `appsec-multi-vuln-c094` in full (user, 2026-11-11: "I will get the
  remote to do full multi-vuln"). Its fixes arrive through `origin/main`; the walker merges them
  when no run is in flight, on the user's request.

## Decisions

| Date | Decision, in the user's words where quoted | Effect |
| --- | --- | --- |
| 2026-11-11 | "Lets stop and refocus, and go job by job. Verify everything." | the four checks before every accept |
| 2026-11-11 | pin: "A pre-fix CVE commit" | the target above |
| 2026-11-11 | expected-gaps list: "Yes, as written" | the first six rows of the table below |
| 2026-11-11 | accept by tag now, by commit later ("I'd do B now and A afterwards") | the tag exception; T-094 |
| 2026-11-11 | Oversized files are not an expected gap. "Exclude Blender, image formats like jpg, png, etc... movies like mp4 mov.... icons... sounds . ttf/open fonts. saves etc" | `[[exclusions.asset_classes]]`: art sources, raster and icon images, video, audio, fonts, game saves; counted and named by class, never a gap. Archives, `.svg`, `.xpm`, `.xml`, `.json`, scripts, build files and `.obj` are never excluded |
| 2026-11-11 | "include PDF. They may just upload a doc instead of having the doc build." | `.pdf` is refused as an excluded suffix |
| 2026-11-11 | "as for the .po translation files i agree that they should be looked at so we will have to raise the limit" | `[inventory] max_file_bytes = 12582912` |
| 2026-11-11 | "change logs SHOULD be used in the history job" | T-097, merged; change logs stay in the inventory |
| 2026-11-11 | Fix build discovery before accepting the catalog (T-091) | done at `051d1842`; the catalog is replayed and checked again |
| 2026-11-11 | Vendored dependencies stay in scope as code | known gap below; T-098 |
| 2026-11-11 | Three catalog gap causes accepted for this walk | rows 7 to 9 of the table below |

Decisions reported to this file by the coordinating session rather than read from the user's own
message are those dated 2026-11-11 for T-091, vendored dependencies and the catalog gap causes;
their wording is in [walk record 05](../tasks/2026-11-11-freeciv-walk-05-target-catalog.md).

## Expected gaps

A gap cause on this list does not stop the walk. Anything else does.

| # | Gap cause | Why it is expected | What accepting it costs |
| --- | --- | --- | --- |
| 1 | No Unity or other engine project | Freeciv is a C codebase | nothing |
| 2 | `.git` excluded from catalog and source inventory | repository metadata is not target source | nothing |
| 3 | PowerShell environment scripts not supported | the environment job does not parse PowerShell | any such script is unanalysed |
| 4 | Grype artifact coverage disabled by configuration | the configuration turns it off | **no artifact vulnerability scanning in this walk** |
| 5 | No execution-profile artifacts | the target produces none | **prioritization has no hotness signal for this target** |
| 6 | Configured source-history and change-context bounds reached | a long history against the configured bound | history beyond the bound is not attributed |
| 7 | `compile_commands.json` not present, before a build | none is tracked; none can exist before the build jobs | nothing at the catalog; a build job that produces none is a different cause and stops the walk |
| 8 | No recognized package manifest; no manifest for dependency extraction | no ecosystem manifest is tracked | **the dependency catalog is empty** although code is vendored under `dependencies/` |
| 9 | No target-supplied design, DFD, OpenAPI, Postman or threat-model document | the target ships none | document-based review has nothing to read; no job produces a DFD or threat model |

**Not on the list, named in advance:** GUI clients or tools that cannot be built for lack of a
toolkit; oversized files (resolved by exclusion and the bound, not by acceptance); the `unit_test`
document kind (Freeciv has no unit-test source of the recognised shape but does have script-level
checks under `tests/` that the rule does not see: not yet accepted by the user).

## Known gaps of this walk

- Vendored third-party code (`dependencies/`: Lua 5.4, tolua 5.2, tinycthread, cvercmp, luasql) is
  not identified as vendored and is reviewed as the project's own code (T-098).
- One cause can be reported once per unit of a job, inflating record counts (T-095).
- Whether any job extracts text from a kept `.pdf` has not been established.

## Fixes the walk is waiting for from elsewhere

- `origin/main` `8aed1992` (other host, job pass 20): Infer observations with project-relative
  paths were dropped. The Freeciv walk reaches the same code at `job_cpp_compiled_analysis`; the
  merge is requested by the user (2026-11-12: "pull remote and compare what changes they have
  made") and is the walker's to do at an idle point. A trial merge was clean at `051d1842`.
