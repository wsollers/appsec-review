# Freeciv walk 05 - `job_target_catalog`

This record advances T-057 and bears on T-091. Walk terms, overlay and the expected-gaps list are
in [walk 01](2026-11-11-freeciv-walk-01-model-connectivity.md).

**Result: stopped for decisions** (run `2026-11-12-0001`, overlay
`freeciv-b1b0768b/capacity-overlay.toml`, corpus tag `freeciv-b1b0768b-v3`). After three pipeline
fixes the catalog's output agrees with the target on everything checked. It is not accepted: four
gap causes are not on the expected list, and the fragment build units of T-091 are the user's call.

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
