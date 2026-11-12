# Freeciv walk 05 - `job_target_catalog`

This record advances T-057 and bears on T-091. Walk terms, overlay and the expected-gaps list are
in [walk 01](2026-11-11-freeciv-walk-01-model-connectivity.md).

**Result: accepted** (run `2026-11-12-0001`, overlay `freeciv-b1b0768b/capacity-overlay.toml`,
corpus tag `freeciv-b1b0768b-v3`), after three pipeline fixes, the user's decisions on the gap
causes, and the T-091 discovery fix. The sections below are in the order things happened; the
accepted result is under "T-091 fixed, catalog accepted".

## Runs

The catalog first ran on `2026-11-11-0009`, where it exposed the three defects below; each fix was
applied with the documented repair path and the earlier jobs replayed (0 preserved-key differences
every time). Merging the change-log history feature (T-097, `9c84849e`) changed the frozen
configuration, so the walk restarted as `2026-11-12-0001`; jobs 1-4 were verified again with the
same independent checks and accepted there (0 gaps each) under corpus tag `freeciv-b1b0768b-v3`.
The checked catalog attempt is dispatch `c8822670-cdd4-4ad6-89b9-cae475d10f01`, `attempt_0001`,
`SUCCEEDED`, 49.1 s job time (`next` wall time 1 min 53 s).

## Defects found by checking the output against the build files, and fixed

| # | What was wrong | Root cause | Fix and regression |
| --- | --- | --- | --- |
| 1 | The job failed at publication: `shared artifact missing: data/Makefile.am` | `runtime.handoff.collect_artifacts` reads any `path`/`sha256` record whose path starts with `data/` as a file of the run. Freeciv owns a top-level `data/` folder; 77 build-marker and descriptor records were taken for run files | `5e9a026c`: `markers` and `descriptor_package` are source metadata. `tests/test_handoff_interchange.py::test_build_descriptors_under_a_target_data_folder_are_source_metadata_not_run_artifacts` failed before with the live message. T-096 registers removing the prefix guess |
| 2 | The root `meson.build` was listed as demoted, "the descriptor declares no build"; the catalog had 30 autotools units, no meson unit, and 9 "orphaned" C sources | Build discovery read descriptors only up to 64 KiB and skipped larger ones without a record. `meson.build` is 124,522 bytes; `configure.ac` (66,520) and `data/flags/Makefile.am` (66,826) were unread too | `e7174668`: descriptors are read up to 1 MiB and an unread descriptor is a named gap (unknown, not empty). `tests/test_catalog_descriptor_read.py` |
| 3 | The meson unit had 38 build points: 16 were `find_library('z')`-style dependency lookups recorded as libraries the project builds, and the server executable was missing | The meson parser matched `library(` inside `find_library(` and required a string-literal target name; the server is `executable(server_binary_name, ...)` | `a264cf68`: bare target functions only; a variable-named target is kept as a build point with its sources and an `unresolved` record naming the variable and its literal values. `tests/test_meson_build_points.py` failed before on both |

## Checks

- **A. Inputs.** The claim pins `job_review_intake` at handoff `1f88fddd3255...`, which is the
  run's accepted intake pointer. No other upstream is declared or read.
- **B. Independent comparison.**

  | Quantity | Job | Independent source |
  | --- | --- | --- |
  | catalog files | 3,496; 3,085 assets and 137 `.gitignore` excluded; 8 binary candidates | same as the accepted intake and `git ls-files` (walk 04) |
  | language census | C 563, C/C++ headers 640, C++ 69, Shell 45, Python 2, Ruby 1, Other 2,176 | identical recount by suffix over the catalog paths |
  | build marker files | 134 accounted for as unit marker, folded root or demoted marker, none twice | 129 `Makefile.am` + 4 `meson.build` + `configure.ac` tracked in the target; none missing |
  | parallel build systems | meson primary and autotools secondary at the root | the target has both `meson.build` and `configure.ac`/`Makefile.am` at the root |
  | meson targets | 15 executables, 7 static libraries, 1 library | `meson.build` declares exactly 15 `executable(`, 7 `static_library(`, 1 `library(` |
  | meson executables by name | 13 clients and tools by literal name, `tolua`, and `server_binary_name` (`server/civserver.c`; values `freeciv-server`, `freeciv-web`) | the `executable(` calls at `meson.build` lines 1255 to 4347 |
  | orphaned sources | 0 | the nine sources the first attempt called orphaned are named by `meson.build` and, under conditionals, by their `Makefile.am` |
  | units | 31: the two root units and 29 autotools fragment units; 77 folded roots, 25 demoted markers | matches the read-only preview that led to T-091 |

- **C. Gaps.** 28 canonical records, 5 causes; three units of the job repeat most of them.

  | Cause | Records | True of the target? | Classification |
  | --- | ---: | --- | --- |
  | `.git` excluded | 7 | yes | expected list |
  | no accepted target document of kind design, dfd, openapi, postman, threat_model, unit_test | 18 (6 kinds x 3 units) | yes: no tracked file name matches any of these kinds | **not on the list: decision** |
  | `compile_commands.json` not present | 1 | yes: none tracked; none can exist before a build | **not on the list: decision** |
  | no recognized project manifests | 1 | yes: no package manifest of any ecosystem is tracked | **not on the list: decision** |
  | `component:0001`: no manifest for dependency extraction | 1 | follows from the previous cause | **not on the list: decision** |

  The last two have a consequence worth stating: the dependency catalog is empty, although the
  target vendors Lua 5.4, tolua 5.2, tinycthread, cvercmp and luasql under `dependencies/`.
- **D. Baseline.** Not saved; the job is checked, not accepted.

## Decisions for the user

1. **Fragment build units (T-091).** 29 autotools directories are separate build units because
   the root reaches them through a variable or a conditional (`$(SSUBDIRS)`, `$(DSUBDIRS)`,
   `GUI_SUBDIRS +=`): `ai` and four AI modules, five GUI clients, `server`, four tools, five
   vendored dependencies, and nine `data` directories that have no build point at all. Every later
   job that works per build unit (planning, project build, language build, the native lanes) will
   treat each as its own project. Recommendation: fix discovery under T-091 before going on, so
   the catalog yields the two parallel root units with these directories as members; the jobs
   after the catalog are far more expensive to walk twice than this one.
2. **Vendored dependencies as first-party units.** `dependencies/lua-5.4`, `tolua-5.2` (two
   units), `tinycthread` and `cvercmp` are build units like the project's own code, and the
   dependency catalog does not name them. Folding them under T-091 does not settle whether they are
   reviewed as first-party code.
3. **The four gap causes above.** Whether "no design, DFD, OpenAPI, Postman, threat-model or
   unit-test document in the target", "no compile database before a build" and "no package
   manifest" join the expected list.

## The user's answers (2026-11-11, relayed by the coordinating session) and sizing

The walk stays on hold at this job: nothing is launched, fixed or accepted until the user says so.

1. **T-091: agreed that discovery is fixed before going on; not started.** Sizing, read-only:
   - Every variable Freeciv uses in `SUBDIRS` is assigned in the same `Makefile.am`, as literal
     lists under `if`/`else` (`SSUBDIRS`, `DSUBDIRS`, `GUI_SUBDIRS +=`, `module_dirs +=`,
     `CLIENTDATADIRS`, `SERVERDATADIRS = $(SRV_RE_DATADIRS) scenarios`, `RULEDITDIRS`,
     `LUASUBDIR`, `TINYCTHRDIR`, `CLI_INCLUDE`). The fix is in one function,
     `build_points.autotools_build_points`: keep every assignment of a variable (`=` and `+=`,
     all branches) as a union instead of the last one, expand `$(VAR)` references to variables
     assigned in the same file to a bounded depth, record a reference that has no in-file
     assignment as `unresolved`, and apply the same reading to `*_PROGRAMS`, `*_LTLIBRARIES` and
     `*_SOURCES`. The existing folding rule then makes the driven directories members. No change
     to `configure.ac` handling is needed for Freeciv.
   - Files: `src/appsec_review/jobs/build_points.py` (about 60 to 80 lines), cases in
     `tests/test_build_points.py`, the discovery matrix cases for conditional systems (their
     strict `pending` entries that start passing must be removed in the same change), and the
     build-discovery docs. Expected Freeciv result: the two parallel root units, no fragment
     unit, the automake programs and sources under conditionals named. One catalog replay.
   - Alternative, walking with the meson root only and setting the autotools fragments aside:
     of 631 C and C++ sources in the catalog, meson's targets name 588 and the autotools units 510.
     34 are named by autotools only, all vendored: 32 in `dependencies/lua-5.4`, 1 in `luasql`,
     1 in `tinycthread` (meson uses the system libraries for these by default). 9 are named by
     neither build. So a meson-only walk would build and analyse the project's own code and lose
     the bundled Lua, luasql and tinycthread sources from build-backed analysis. It needs a way to
     set units aside, which does not exist today, so it is not free either.
2. **Vendored dependencies: agreed.** They stay in scope as code; "vendored dependencies not
   identified, dependency catalog empty" is a known gap of this walk. T-098 registers the work.
3. **Gap causes: accepted as expected for this walk**: no compile database before a build; no
   package manifest and no manifest for dependency extraction; no target-supplied design, DFD,
   OpenAPI, Postman or threat-model document. **Not yet accepted: `unit_test`.** The kind matches
   only file names such as `test_*.c`, `*.test.js`, `_test.go`, `_spec.rb`. Freeciv has no file of
   that shape, and no `check_PROGRAMS`, `TESTS` or meson `test(`. It does have checks the rule
   does not see: `tests/` holds 18 files, shell scripts that lint the source (`check_macros.sh`,
   `copyright.sh`, `header_guard.sh`, `trailing_spaces.sh`, `va_list.sh`, `fcintl.sh`) and
   ruleset load, save and upgrade checks (`rulesets_*.sh.in`), run from `tests/Makefile.am` and
   `.github/workflows/ci.yml`. So: a true absence of unit-test source, and a detection limit for
   script-level checks.
4. **DFD and threat model.** No job in the graph produces either. The catalog only classifies
   documents the target supplies; `job_document_issue_analysis` analyses supplied documents. The
   producer is deferred work (the F07 threat-model item in the legacy backlog; T-070 slices
   findings by a game threat model and is not that producer).

## T-091 fixed, catalog accepted (2026-11-12)

The user gave the go-ahead ("Yes, fix T-091"; and through the coordinating session: fix, replay,
accept job 5 if it comes back with two units; the unit-test gap is accepted as expected with the
detection limit noted).

**Fix** `051d1842`: in `build_points.autotools_build_points` a `Makefile.am` variable is the union
of every `=` and `+=` assignment across all `if`/`else` branches, and `$(VAR)` of a variable
assigned in the same file is expanded to a bounded depth, for `SUBDIRS` and for the program,
library and source lists. The enclosing conditions are recorded on each drive and build point; a
reference with no in-file assignment is an `unresolved` record of kind `unassigned_variable`.
Regressions `tests/test_automake_conditionals.py` (4 of 5 failed before), discovery case
`121-autotools-conditional-subdirs` with no pending entry; no existing pending entry started
passing. 1,792 passed, 162 xfailed over the discovery matrix, build points, build discovery and
the catalog job (174 s).

**Replay.** `recover`, merge, reload, `plan-repair` (admissible, no refusals, plan `09d64afe...`:
jobs 1-4 re-run, the rest invalidated), `admit-repair`, `recover --plan`. The first replay of job
1 failed: the mounted Claude login had expired (`401 OAuth access token has expired`), which the
job reported as a blocked review. The login was refreshed on the host as the operator notes
prescribe and job 1 re-run. Jobs 1-4 then replayed with 0 preserved-key differences and their
independent checks holding, and were re-accepted.

**Accepted attempt:** dispatch `f66ee316-e9e1-4c73-86ff-c2d7d3c254e3`, `attempt_0002`,
`SUCCEEDED`, 51.4 s job time (`next` wall time 1 min 43 s).

- **A. Inputs.** The claim pins `job_review_intake` at `5be31dccd7f5...`, the run's accepted
  intake pointer.
- **B. Independent comparison.**

  | Quantity | Job | Independent source |
  | --- | --- | --- |
  | build units | 2: `.`/meson (primary, 23 targets) and `.`/autotools (secondary, 93 build points), each naming the other as parallel | the target has one project with two build systems at the root |
  | fragment units, demoted markers, orphaned sources | 0, 0, 0 | - |
  | folded member directories | 131 | - |
  | `Makefile.am` directories driven through `SUBDIRS` | 128 of 128 | 129 tracked `Makefile.am` less the root; none undriven |
  | build marker files | 134 accounted for, none twice | 129 `Makefile.am` + 4 `meson.build` + `configure.ac` |
  | automake libtool libraries | 41 | 41 distinct literal names in `lib_LTLIBRARIES`/`noinst_LTLIBRARIES` across all `Makefile.am`, read by a separate script that does not expand variables; none missing, none extra |
  | automake programs | 15 | 13 literal names in `bin_`/`noinst_`/`check_PROGRAMS`, plus `freeciv-server` and `freeciv-web`, which `server/Makefile.am` names through `$(srvbin)` |
  | conditional drives | 53 of 131 carry a condition (`data` under `MAKE_DATA`, `ai` and `server` under `SRV_LIB`, `client/gui-sdl2` under `CLIENT && CLIENT_GUI_SDL2`, ...) | the `if` blocks of the `Makefile.am` files quoted earlier in this record |
  | `unassigned_variable` records | 0 | every `SUBDIRS` variable is assigned in its own file (sizing above) |
  | meson targets, files, census | unchanged from the earlier check | as above |

  Three driven directories have no `Makefile.am` (`translations/core`, `nations`, `ruledit`):
  `translations/Makefile.am` names them and they carry `meson.build` only.
- **C. Gaps.** 28 canonical records, 5 causes, every one on the confirmed list:

  | Cause | Records | Classification |
  | --- | ---: | --- |
  | `.git` excluded | 7 | expected (original list) |
  | no target-supplied design, DFD, OpenAPI, Postman or threat-model document | 15 | expected for this walk (user, 2026-11-11). No job generates a DFD or threat model; T-107 is reserved for that design |
  | no `unit_test` document | 3 | expected for this walk (user, 2026-11-12). Detection limit: the name rule sees only `test_*.c`-style files; Freeciv's checks are 18 shell scripts under `tests/` run from `tests/Makefile.am` and CI |
  | `compile_commands.json` not present | 1 | expected for this walk: none exists before a build |
  | no package manifest; no manifest for dependency extraction | 2 | expected for this walk. Vendored dependencies are not identified and the dependency catalog is empty (T-098, under T-099) |

- **D. Baseline.** `test/acceptance/freeciv-b1b0768b-v3/job_target_catalog.json` and provenance;
  seed `after-job_target_catalog`.

The remaining `unresolved` records of the autotools unit (34) are make-rule variables such as
`$(AM_V_at)`, `$(TOLUA)` and `$(WINDRES)` in recipes; they predate this change and do not affect
which directories or targets are found.

## Not verified

- The symbol index (15,647 items) and component index were not compared with an independent
  count.
- Autotools build points were not checked target by target. Known limitation, added to T-091:
  `bin_PROGRAMS +=` inside `if` blocks keeps only the last program and `_SOURCES = $(da_sources)`
  names no source.
- The `custom_target` (26) and generated sources of `meson.build` are not build points.
- The read bound for build descriptors is a named constant (1 MiB), not a typed setting.

## Commands

```sh
.venv/bin/python deploy/dagster/bin/stepwise.py recover --app-run 2026-11-11-0009
scripts/stack-restart.sh --code-location-only --target freeciv --overlay freeciv-b1b0768b/capacity-overlay.toml
docker exec appsec-review-dagster-wsl-code-location-1 python -m appsec_review plan-repair --run-id 2026-11-11-0009 --target /opt/app/targets/freeciv
docker exec appsec-review-dagster-wsl-code-location-1 python -m appsec_review admit-repair --run-id 2026-11-11-0009 --target /opt/app/targets/freeciv --plan <plan>
.venv/bin/python deploy/dagster/bin/stepwise.py recover --app-run 2026-11-11-0009 --plan <plan>
.venv/bin/python deploy/dagster/bin/stepwise.py init --target /opt/app/targets/freeciv     # 2026-11-12-0001
.venv/bin/python deploy/dagster/bin/stepwise.py next --app-run 2026-11-12-0001             # catalog: 1 min 53 s
```

Focused unit tests, all on the branch before each merge, `-n 4` to `-n 6`: handoff and catalog
105 passed (92 s); descriptor read, catalog job and build discovery 143 passed (61 s); meson build
points with build discovery and catalog 145 passed (56 s), `tests/test_build_points.py` 35 passed.
Most catalog-job tests take 20 to 95 s each, over the 10 s unit limit; that predates this work.
