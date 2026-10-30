# Native build-output discovery and named build-output exclusions

Status: implemented on the native build-output implementation branch; see
[Implementation notes](#implementation-notes) for where the code differs from this design. The
design was agreed with the neighbouring design sessions listed under [Ownership](#ownership). The
line numbers below refer to base commit `38c934d9`.

## Problem

In live review run `2026-10-29-0004`, `artifact_indexing__index__relationships` took about 45
minutes instead of about one. The cause was 8,188 third-party files under `node_modules`
catalogued as build output in the target lane.

The build jobs catalogue output by walking the whole workspace after the build and diffing it
against a SHA-256 snapshot taken before:

- `job_language_build/job.py`: `_snapshot` at 238 and `_catalog` at 286-337.
- `job_sanitizer_build/job.py`: `_catalog` at 144-180.
- `job_project_build/job.py`: `_snapshot` at 159 and `_outputs` at 205.

A catalogued row carries no `scope_role`. `delivery_scope.scope_fields` (35-53) therefore gives it
`ScopeRole.UNKNOWN`, which maps to the `target` lane and to a `delivery_fact_unavailable` gap per
row. Every row then reaches artifact indexing, whose approved throughput design changes batching
only and does not skip or summarise any lane.

The npm case belongs to the installer-record design (see [Ownership](#ownership)). C and C++ have
the same defect and no installer record to fall back on. The following trees are created inside
the workspace during configure or build, and today every catalogued file in them becomes a
target-lane row:

- CMake `FetchContent` trees: `_deps/<name>-src`, `-build` and `-subbuild`.
- `ExternalProject` prefixes.
- vcpkg manifest-mode `vcpkg_installed`.
- Meson wrap subprojects.
- Conan generator output.

The only thing excluded today is CMake probe bookkeeping (`jobs/build_bookkeeping.py`). The
existing `[exclusions]` table (`config/exclusions.py`) applies only to target-file selection, in
`job_review_intake`, `job_target_catalog` and `job_source_history_analysis`. It never applies to
files the build creates.

## Goals

1. Use the build system's own metadata, and the execution capture the pipeline already records,
   to find the build-output directories and the dependency trees, both source and output, that a
   native build creates in the workspace.
2. Classify dependency trees into the `supply_chain` lane, recorded per tree rather than per file.
   Target build output stays in the `target` lane: objects and the binaries and libraries linked
   from target sources.
3. Add one typed, central, TOML-configured build-output exclusion. It is applied and recorded as a
   named exclusion (name, pattern, scope) and is never a silent drop or a coverage gap.
4. Provide one mechanism that the installer-record classifiers (npm, cargo, go, composer, python,
   .NET) also use: one config model, one record path and one pruning walk.

Non-goals: changing artifact indexing, changing target-file selection or the source fingerprint,
dependency identity resolution (that remains `job_dependency_intelligence`), and executing extra
build-tool commands.

## Principles

- **Facts before names.** `delivery_scope.py` states that origin and directory names do not
  establish delivery. A tree is reclassified on a build-system-authored fact, an installer record
  or an observed execution-capture fact. A name heuristic is recorded with
  `basis = "heuristic"` and a confidence level, and always raises a named gap. It is never
  promoted to an accepted fact.
- **Only build-created content is reclassified.** A file that was in the pre-build snapshot is
  accepted target content, including vendored source committed to the repository. This design
  never moves such content to `supply_chain`. Vendored-source identity remains the job of
  [`native-sbom.md`](native-sbom.md). Configured exclusions are the only exception, because they
  are an explicit operator decision.
- **Nothing is dropped silently.** Each non-target decision is recorded once per tree root, with
  its basis, evidence reference, file and byte counts, and examples. A configured exclusion is a
  named exclusion, not a gap. Summarised dependency content raises one aggregated named gap per
  evidence source.
- **The manifest stays complete.** The post-build workspace manifest (`job.py:1270-1273`) still
  hashes every file. Several consumers depend on it:
  - `job_codeql_analysis._workspace_manifest_files` (270-322) requires the manifest to equal a
    full re-walk of the workspace.
  - `job_poc_generation.buildctx.materialize` (243-265) rebuilds from manifest files only.
  - `job_remediation_validation` compares baseline manifests.

  Pruning therefore applies only to catalogue rows. The cost in the failing run came from
  per-file rows, not from hashing.
- **Bounded and deterministic.** Metadata readers have byte, file and entry bounds from config. A
  bound overrun is a named gap, and that tree falls back to per-file target rows. No build tool
  is executed to discover layout.

## Discovery sources

Discovery runs once per build unit, after the build's commands finish and before cataloguing. It
produces `LayoutFacts`: a list of `LayoutRoot(root, role, basis, confidence, name, evidence_ref)`
records, each with its source file pinned by SHA-256 in `layout_sources`. Readers are pure
functions over files in the workspace and over capture rows the job already holds.

| Order | Source | Basis | What it yields | Phase |
|---|---|---|---|---|
| 1 | Recipe `build_dir` (`_deterministic_native_recipe` in `job_project_build/job.py:953`, model recipes) | build-system-fact | The build-output root. Its contents stay target unless a deeper root says otherwise. | 1 |
| 2 | Execution capture: compile and link rows from `reconcile_captured_build` (`job.py:1156`) and resolved file events (`capture_files.resolve_file_events`, `process_directories`) | execution-capture | The source to output mapping for every compiler and linker exec; the writer process of every created file. | 1 |
| 3 | CMake `CMakeCache.txt` in `build_dir` | build-system-fact | `CMAKE_HOME_DIRECTORY`, `CMAKE_CACHEFILE_DIR`, `FETCHCONTENT_BASE_DIR`, every `<PROJECT>_SOURCE_DIR`, `_BINARY_DIR` and `_IS_TOP_LEVEL` that `project()` writes, `FETCHCONTENT_SOURCE_DIR_*`, `VCPKG_INSTALLED_DIR`, `VCPKG_TARGET_TRIPLET`. | 1 |
| 4 | CMake file API reply (`<build_dir>/.cmake/api/v1/reply/`) | build-system-fact | `codemodel-v2`: directory source and build paths, project hierarchy, target `artifacts`, `sources[].isGenerated`. `cmakeFiles-v1`: `isExternal` inputs. | 1 |
| 5 | Meson `meson-info/intro-projects.json`, `intro-targets.json`, `intro-buildoptions.json` | build-system-fact | `subproject_dir`, the subproject names, each target's `subproject` and `filename` outputs. | 1 |
| 6 | `compile_commands.json` (already parsed by `_compile_rows`, `job.py:356`) | build-system-fact (corroboration only) | `file`, `output` and `directory` per translation unit. Used only after the exact-argv match the existing enrichment already requires. | 1 |
| 7 | vcpkg `vcpkg_installed/vcpkg/status` and `vcpkg_installed/vcpkg/info/*.list` | installer-record | The installed root, plus the per-port file ownership the installer writes. | 2 |
| 8 | Static `build.ninja` parse (`build <outs>: <rule> <ins>`, `subninja`, `include`) | build-system-fact | The output to input edges for non-CMake, non-Meson Ninja builds. | 2 |
| 9 | MSBuild `.vcxproj`, `.props`, `Directory.Build.props` `OutDir`, `IntDir` | build-system-fact | The output and intermediate roots. Supported only where the value is literal or uses `$(Configuration)`, `$(Platform)`, `$(ProjectDir)` or `$(SolutionDir)` with values the recipe states. Anything else is a gap. | 3 |
| 10 | Conan generator files (`conan_toolchain.cmake`, `conanbuildinfo.*`, `conaninfo.txt`) | build-system-fact | Generator output in the build directory is classified `build_chain`. Conan's package cache is outside the workspace and is not walked. | 3 |
| 11 | Name heuristic: `_deps`, `subprojects`, `vcpkg_installed`, `external`, `third_party`, `third-party`, `vendor`, `deps`, the same `_VENDOR` set as `job_dependency_intelligence/discovery.py:27` | heuristic | A candidate dependency root, only for build-created trees that no fact above covers. | 1 |

Rejected sources:

- `make -pn`: evaluating a Makefile runs `$(shell …)`.
- `ninja -t targets|inputs|compdb`: each is an extra execution needing capture accounting, and
  the static parse plus capture covers the same edges.
- Bazel: `bazel-*` convenience symlinks point at an output base outside the workspace, and the
  cataloguer already skips symlinks. A `bazel-out` symlink is recorded as a layout note only.

Make has no layout metadata. For Make and other plain builds, discovery relies on source 2,
execution capture, which applies to every native build.

### CMake

- **File API query.** When the recipe's build system is CMake and
  `[build_outputs.discovery] cmake_file_api = true`, the job writes a stateless client query
  before the first configure command:
  `<build_dir>/.cmake/api/v1/query/client-appsec-review/query.json`, requesting `codemodel` v2
  and `cmakeFiles` v1. The pre-build snapshot includes this file, and it is recorded in the
  receipt as a prepared input. When CMake is older than 3.14 or writes no reply, discovery falls
  back to the cache alone and raises the gap `cmake-file-api-reply-missing`.
- **Dependency source roots.** A dependency source root is a project's `_SOURCE_DIR` (cache) or
  codemodel directory source path that is created during the build and either lies under
  `FETCHCONTENT_BASE_DIR` (default `${CMAKE_BINARY_DIR}/_deps`) or is named by
  `FETCHCONTENT_SOURCE_DIR_<NAME>`. Its `_BINARY_DIR`, the matching codemodel build path, is a
  dependency output root, and `<name>-subbuild` is a dependency bookkeeping root. All three take
  the dependency's `project()` name.
- **ExternalProject.** `ExternalProject` prefixes (`<name>-prefix/src/<name>`,
  `src/<name>-build`, `src/<name>-stamp`, `tmp`) are not visible in the codemodel. They are found
  from capture (below) and corroborated by the `-stamp` and `-prefix` layout. With capture they
  are execution-capture facts; without capture they are only a heuristic.
- **In-tree subprojects stay target.** A project added with `add_subdirectory` from inside the
  accepted source tree is a target project, even when `<NAME>_IS_TOP_LEVEL` is false.

### Meson

- The build directory is the directory that holds `meson-info/`.
- A target whose `subproject` is non-null is dependency output when its subproject source
  directory (`<source>/<subproject_dir>/<name>`) was created during the build, for example a
  wrap download or a `packagecache` extract. A committed subproject directory is target content
  and its outputs stay target. The record still carries `subproject: <name>` so reviewers can see
  it.
- Each such target's `filename` entries locate `<build>/subprojects/<name>/`, the dependency
  output root.

### Execution capture

Capture is the only source available for every native build system, and it is the strongest
evidence for content created during the build. For each file the build creates in the workspace,
`resolve_file_events` names the writer pid, and the exec record for that pid gives the writer's
argv and image path.

- **Fetched tree.** A created root counts as fetched when it is written mostly by `git`, `curl`,
  `wget`, `tar`, `unzip`, `cmake -E tar`, `cmake -P` download scripts or `meson subprojects`
  rather than by a compiler, and it contains its own build-system file (`CMakeLists.txt`,
  `meson.build`, `configure`, `Makefile`). It becomes a dependency source root with
  `basis = "execution-capture"` and `confidence = "high"`.
- **Dependency output.** A directory counts as dependency output when every compile row with an
  output under it has all its source inputs inside dependency source roots. It becomes a
  dependency output root with `basis = "execution-capture"` and `confidence = "fact"`, the same
  observation authority the existing provenance uses.
- **Mixed outputs.** When a directory holds outputs of both target and dependency sources, it is
  not reclassified. Its rows stay per file, and each dependency-sourced linked output is tagged
  individually.

Capture is bounded by the existing capture limits. A capture gap
(`capture_complete = False`) disables capture-basis classification for the unit and records the
gap `build-output-capture-incomplete`. Discovery then falls back to the other sources.

### Conflict resolution

1. The deepest registered root wins. A root can also be registered as `per_file`, a visible
   carve-out with a recorded reason.
2. Among bases for the same root, the order is: configured exclusion, then fact-level bases
   (build-system-fact, installer-record, execution-capture), then heuristic.
3. When two fact-level bases disagree, the root stays `per_file` in the target lane and raises
   the gap `build-output-classification-conflict: <root>`. No content is dropped on a conflict.

## Classification model

`jobs/build_output_scope.py` (new) owns the model, the recorder and the walker.

```text
Disposition = "excluded" | "supply_chain" | "evidence" | "per_file"
Basis       = "configured-exclusion" | "build-system-fact" | "installer-record"
              | "execution-capture" | "heuristic"
Confidence  = "fact" | "high" | "medium" | "low"

BuildOutputDispositions.classify_tree(
    root, *, disposition, basis, name, reason, evidence_ref=None, pattern=None,
    scope=None, confidence, scope_role=None, keep=())
BuildOutputDispositions.walk(workspace) -> Iterator[(relative, Decision)]
BuildOutputDispositions.document() -> Mapping   # appsec-review/build-output-dispositions/1
summarized_content_gap(count, unit_noun, files, bytes, evidence_ref, lane) -> str
```

- `walk` replaces the `rglob` loops in the three cataloguers. It is a sorted `os.scandir`
  descent that checks the deepest registered root and the configured rules at each directory.
  - A pruned directory is not descended for hashing. Its files are counted with `stat`, which
    gives `files` and `bytes`, and up to five examples are kept.
  - `keep` paths inside a pruned root are yielded as ordinary rows carrying the root's
    `scope_role`. The npm classifier uses this for its per-package `package.json` anchors and
    native addons. Native `supply_chain` roots, both source and output, keep their linked kinds
    (`executable`, `shared-library`, `static-library`), bounded by `max_kept_per_root`. An overrun raises a
    gap, and the remaining files stay counted.
  - The invariant is catalogue ⊆ workspace manifest, which artifact indexing's
    `_validate_receipts` already requires.
- Build bookkeeping (`build_bookkeeping.bookkeeping_reason`) becomes one decision inside `walk`.
  `BookkeepingExclusions` still records it, and the receipt keeps `excluded_bookkeeping` as an
  unchanged projection.
- The recorder emits no gaps. Callers emit gaps, because each one holds the evidence reference
  and the per-unit aggregate:
  - `summarized_content_gap` produces the shape agreed with the installer-record design:
    `dependency-content-summarized: <N> <unit_noun> (<F> files, <B> bytes) recorded by <ref>
    routed to <lane> review; per-file target review not performed`.
  - Heuristic dispositions also raise `build-output-heuristic: <root> classified <disposition>
    by directory name (<confidence>)`.
  - Configured exclusions never raise a gap.

Mapping to lanes, with lanes always derived through `delivery_scope.scope_fields` and no second
mapping:

| Root role | Disposition | Rows | `scope_role` of rows |
|---|---|---|---|
| Configured exclusion | `excluded` | none | n/a, recorded as a named exclusion |
| Dependency source (fetched, `-src`, wrap, vcpkg include) | `supply_chain` | linked kinds only (`keep`): prebuilt binaries stay visible to supply-chain analysis; sources and headers are counted | `build_dependency` |
| Dependency output (`-build`, `subprojects/<n>`, vcpkg `lib`) | `supply_chain` | linked kinds only (`keep`) | `runtime_dependency` for shared libraries named in a target ELF `DT_NEEDED`, otherwise `build_dependency` |
| Dependency bookkeeping (`-subbuild`, ExternalProject `-stamp` and `tmp`) | `evidence` | none (counted) | n/a |
| Conan generator output | `supply_chain` | none (counted) | n/a |
| Heuristic root, confidence `medium` (name plus a build-created tree that contains a build-system file) | `supply_chain` | linked kinds only | `build_dependency` |
| Heuristic root, confidence `low` (name only) | `per_file` | all, as today | unchanged (target), annotated in the record |
| Target build output (everything else) | none | per file, as today | unchanged |

`runtime_dependency` (lane `supply_chain`, delivery `not_established`) is added to
`config/assurance.py` and `jobs/delivery_scope.py` by the installer-record design. This design
consumes it and does not edit those files. A static archive from a dependency tree is
`build_dependency`, because its code is reviewed inside the target binary that links it.

Heuristics act only from `heuristic_min_confidence` (default `medium`) upward. Below that, the
root is annotated and its files stay per-file target rows.

## Configuration

A new top-level typed table in `appsec-review.toml` is parsed by `config/build_outputs.py` (new)
into a frozen `BuildOutputPolicy` and held on the job config of `job_language_build`,
`job_project_build` and `job_sanitizer_build`. Unknown keys, a misplaced table or an invalid
pattern fail at load. Pattern validation and matching reuse `config/exclusions.py`: `_patterns`
is factored into a public `validate_patterns(value, field)`, and each rule's patterns become
`ExclusionRule(pattern, scope="build_outputs")`. Patterns therefore have exactly the semantics of
`[exclusions]`, applied to the workspace-relative path, which equals the target-relative path.

```toml
[build_outputs]
heuristic_min_confidence = "medium"   # "high" | "medium" | "low" | "off"

[build_outputs.discovery]
cmake_file_api = true
max_layout_sources = 64               # metadata files read per unit
max_layout_source_bytes = 16777216    # per file, matches the compile-database bound
max_layout_roots = 512
max_ninja_edges = 200000
max_kept_per_root = 256

[[build_outputs.exclusions]]
name = "cmake-fetchcontent-subbuild"
reason = "FetchContent download sub-builds are CMake bookkeeping, not dependency or target output"
patterns = ["*-subbuild/"]
families = ["native"]                 # optional; omitted means every family

[[build_outputs.exclusions]]
name = "node-bundler-cache"
reason = "Bundler and loader caches (babel-loader, terser, webpack, Vite dependency pre-bundling) are build bookkeeping, not target output or installer-recorded dependency content"
patterns = ["node_modules/.cache/", "*/node_modules/.cache/",
            "node_modules/.vite/", "*/node_modules/.vite/"]
families = ["node"]
```

- `name` is unique, `[a-z0-9-]+`, and appears in every record and in the policy identity.
- `families` is optional and restricts a rule to the listed build families.
- The shipped defaults are the two rules shown: `cmake-fetchcontent-subbuild` and
  `node-bundler-cache`. The second was added at the user's direction, relayed from the
  dependency output filtering design.
  - A pattern containing `/` is anchored at the workspace root, so each cache needs a root form
    and a `*/` form (`fnmatch`'s `*` crosses `/`) to cover nested workspace packages.
  - `.vite` is matched only under `node_modules`, Vite's default `cacheDir`, so a committed
    top-level `.vite` folder is not excluded by default.
  - A configured exclusion outranks an installer-record root, so these caches are recorded as
    named exclusions even inside a classified `node_modules` tree.
- Operators add rules such as `third_party/prebuilt/` here, never in prompts.
- `job_exclusions` and `JOB_LEVEL_SUPPORT` are unchanged. `[jobs.job_language_build.exclusions]`
  still fails at load, and build-output rules live only under `[build_outputs]`.
- `BuildOutputPolicy.identity` is the SHA-256 of the canonical policy. It enters the
  `job_language_build` checkpoint `_fingerprint` (`job.py:553`) as `"build_outputs"`, and the
  equivalent keys in the project-build and sanitizer fingerprints. `EXECUTOR_IDENTITY` (`job.py:60`)
  is bumped to `/4` because catalogue semantics change. `RECEIPT_SCHEMA` is bumped only if receipt
  validation is closed-key. The implementation checks this and records the result in the change.
- The resolved policy is part of the run's immutable configuration under
  `runs/<run-id>/data/configuration/`, like every other table.

## Receipt and telemetry

Each language-build, sanitizer-build and project-build probe receipt gains
`build_output_dispositions`:

```json
{
  "schema": "appsec-review/build-output-dispositions/1",
  "policy_identity": "<sha256>",
  "layout_sources": [{"kind": "cmake-cache", "path": "build/CMakeCache.txt", "sha256": "…"}],
  "roots": [{
    "root": "build/_deps/fmt-src", "disposition": "supply_chain",
    "basis": "build-system-fact", "confidence": "fact", "name": "fmt",
    "reason": "FetchContent source", "evidence_ref": "build/CMakeCache.txt#fmt_SOURCE_DIR",
    "pattern": null, "scope": null, "scope_role": null,
    "files": 412, "bytes": 3145728, "kept": [], "examples": ["…"]
  }],
  "configured_exclusions": [{"path": "build/_deps/fmt-subbuild", "name": "cmake-fetchcontent-subbuild",
                             "pattern": "*-subbuild/", "scope": "build_outputs", "files": 37}],
  "bookkeeping": {"schema": "appsec-review/build-bookkeeping-exclusions/1", "…": "…"}
}
```

- `configured_exclusions` uses the `{path, pattern, scope}` shape that `cataloging.inventory`
  already uses (77-192), plus `name` and `files`.
- `job_dependency_intelligence` already copies `configured_exclusions` into
  `coverage.configured_exclusions`, and it may later read `roots[].name` as a stronger native
  dependency identity than the `_VENDOR` name heuristic. That is optional and not part of this
  design.
- Each build unit emits one event, `BUILD_OUTPUT_CLASSIFIED`, with the detail keys
  `target_rows`, `supply_chain_trees`, `excluded_trees`, `excluded_files`, `kept_rows`,
  `heuristic_dispositions`, `conflicts`, `layout_sources_read` and `duration_ms`. The same counts
  are added to `LANGUAGE_BUILD_COMPLETED` (`job.py:1343`).
- Classification runs inside `operation_phase("build.output_classify")` from the operation
  telemetry design, accumulating into the existing `unit.execute` span. The name is added to
  `_PHASES` when that change lands. No new span is created.
- Event detail keys avoid `file_count`, `artifact_count`, `size_bytes` and the other names that
  `aggregate_run_metrics` sums into `throughput_totals`.

## Ownership

These splits were agreed by cross-session message during this design:

| Area | Owner |
|---|---|
| `[build_outputs]` config, `BuildOutputPolicy`, `validate_patterns` refactor | **this effort** |
| `jobs/build_output_scope.py`: recorder, walker, gap formatter, receipt field, `EXECUTOR_IDENTITY` and `RECEIPT_SCHEMA` bump | **this effort**; lands first |
| Generic `_catalog` and `_snapshot` integration and the family dispatch hook in `job_language_build/job.py` (`dispositions=` keyword passed to `node.catalog` and `php.catalog`) | **this effort** |
| Native layout readers and capture attribution (C/C++ and native) | **this effort** |
| `job_project_build` and `job_sanitizer_build` cataloguer adoption | **this effort** |
| npm, then php, python, rust and .NET installer-record classifiers (`node.py`, `php.py`, …) | Dependency output filtering design (session `0d7434ef`); rebases on the mechanism chunk |
| `ScopeRole.RUNTIME_DEPENDENCY` in `config/assurance.py` and `jobs/delivery_scope.py` | Dependency output filtering design; independent of this effort, and must land before this effort's integration chunk |
| Artifact indexing batching and throughput | Artifact indexing throughput design (implementation session `0e8bb030`). That design does **not** skip or summarise non-target lanes. This design does not need it to, because pruned trees produce no rows. Lane-aware relationship indexing would be a separate user decision. |
| `operation_phase` and `_PHASES` | Operation telemetry design (session `7dcc7b20`) |
| Native dependency identity (`job_dependency_intelligence`) | Native dependency discovery (merged). No edits here. |

## Implementation breakdown

The chunks follow `.claude/skills/parallel-implementation`. Each chunk owns disjoint files. B and
C can start in parallel with A against the interface signatures above.

| Chunk | Depends on | Files | Focused unit tests |
|---|---|---|---|
| **A. Mechanism** (the npm design calls it chunk N; once committed, send the exact ready SHA to the npm implementation session `bff8bca9-a916-4f1d-9075-a280c9c89357`, whose chunk C (`node.catalog` integration) is blocked on it) | none | new `config/build_outputs.py`; `config/exclusions.py` (`validate_patterns`); `config/loader.py` (policy on the three job configs); `appsec-review.toml` (`[build_outputs]`); new `jobs/build_output_scope.py`; `job_language_build/job.py` (`_catalog` walk, receipt field, `_fingerprint`, `EXECUTOR_IDENTITY`, `dispositions=` dispatch to `node`/`php`) | new `tests/test_build_output_config.py`: shipped defaults load, and `node-bundler-cache` matches `node_modules/.cache/x`, `packages/a/node_modules/.vite/x` and not `.vite/x`; valid table, unknown key, duplicate name, bad pattern, `families` filter, identity stability. New `tests/test_build_output_scope.py`: deepest root wins, `per_file` carve-out, `keep` rows hashed and in the manifest, pruned files stat-counted and not hashed (counted `file_sha256` calls), configured exclusion recorded once with name, pattern and scope and no gap, bookkeeping projection unchanged, conflict raises a gap and keeps rows. Update `tests/test_language_build.py` and `tests/test_build_output_mapping.py` expectations for the new field and identity. |
| **B. Native layout readers** | A's interface only | new `job_language_build/native_layout.py`: `read_cmake_cache`, `write_cmake_file_api_query`, `read_cmake_file_api`, `read_meson_info`, `read_ninja` (static, bounded), `read_vcpkg_installed`, `read_msbuild_dirs` (phase 3), `read_conan_generators` (phase 3) | new `tests/test_native_layout.py`, with synthetic files under `tmp_path`: a cache holding `FETCHCONTENT_BASE_DIR`, `fmt_SOURCE_DIR` and `_IS_TOP_LEVEL`; a minimal codemodel-v2 reply with a target and a `_deps` directory; Meson intro JSON with one subproject; a Ninja file with `subninja`; vcpkg `info/*.list`; bound overruns and malformed JSON as gaps |
| **C. Capture attribution** | A's interface only | new `job_language_build/output_attribution.py`: writer classification from resolved file events, and dependency-output directories from compile rows | new `tests/test_output_attribution.py`: a `git`/`cmake -E tar` writer gives a fetched root; a compiler output from a dependency source gives a dependency output root; mixed directories are not reclassified; incomplete capture disables classification with a gap |
| **D. Native classification integration** | A, B, C, `RUNTIME_DEPENDENCY` | `job_language_build/job.py` `_execute_one`: write the file API query before configure, run discovery and conflict resolution after the commands, `classify_tree` before `_catalog`, gaps, the event, and `operation_phase` once available | new `tests/test_native_build_output_classification.py` (below) |
| **E. Other cataloguers** | A | `job_sanitizer_build/job.py` `_catalog`; `job_project_build/job.py` `_outputs` | extend `tests/test_sanitizer_build.py` and `tests/test_project_build.py`: a configured exclusion is recorded and a dependency root is pruned |
| **F. Docs** | A–E | `docs/operations/language-build.md` (bookkeeping paragraph at about 127-132), `docs/operations/project-build.md`, `docs/operations/sanitizer-build.md`, `docs/architecture/jobs-and-runtime.md`, `docs/architecture/dossier-data-inventory.md`; mark this design implemented | documentation checks only |
| **G. Integration and acceptance tests (written, not run)** | D | new `tests/integration/test_native_build_output_layout.py`: a real CMake build using `FetchContent` from a local `file://` git fixture (no network), and a real Meson build with a wrap subproject from a local `packagecache` | none run. The user owns their execution |

### Required regressions for chunk D

The tests are seconds-scale and drive the real cataloguing code against synthetic workspaces
built under `tmp_path`, without running CMake or Meson:

1. **CMake FetchContent.** The workspace holds:
   - `src/main.c` and `CMakeLists.txt` in the pre-build snapshot;
   - build-created `build/CMakeCache.txt`;
   - a codemodel reply;
   - `build/_deps/fmt-src/` (CMakeLists.txt and 300 headers and sources);
   - `build/_deps/fmt-build/libfmt.a` and objects;
   - `build/_deps/fmt-subbuild/`;
   - `build/app`, `build/CMakeFiles/app.dir/main.c.o`;
   - capture compile rows for both.

   The test asserts:
   - target rows are exactly `build/app` and its object, in the target lane;
   - `libfmt.a` is a `build_dependency` row in the `supply_chain` lane;
   - `fmt-src` is one `supply_chain` root (`files == 300+`, never hashed);
   - `fmt-subbuild` is a named configured exclusion with no gap;
   - there is exactly one `dependency-content-summarized` gap;
   - the manifest still lists every file.
2. **Meson subproject.** The workspace holds a build-created `subprojects/zlib/` (wrap) and
   `builddir/meson-info/intro-*.json`, with the `libz.a` target having `subproject: "zlib"`. The
   test asserts that the subproject source and output are classified `supply_chain` with
   `basis = "build-system-fact"` and that the target executable stays in the target lane. A
   variant with `subprojects/zlib/` already present in the pre-build snapshot keeps it as target
   and annotates `subproject: zlib`.
3. **Heuristic fallback.** A build-created `third_party/foo/` that contains a `CMakeLists.txt` but
   is covered by no metadata or capture gives `basis = "heuristic"`, `confidence = "medium"`,
   `supply_chain`, and a `build-output-heuristic` gap. The name-only variant stays per-file
   target rows.
4. **Bounds.** An oversized `CMakeCache.txt` or reply produces a named gap and per-file
   fallback, never an exception or a drop.
5. **Checkpoint.** Changing `[build_outputs]` changes `_fingerprint`.

### Validation commands (WSL, Linux-filesystem checkout)

```sh
python -m pytest -q --basetemp=test/tmp/native-build-output \
  tests/test_build_output_config.py tests/test_build_output_scope.py \
  tests/test_native_layout.py tests/test_output_attribution.py \
  tests/test_native_build_output_classification.py \
  tests/test_language_build.py tests/test_build_output_mapping.py \
  tests/test_path_exclusions.py tests/test_sanitizer_build.py tests/test_project_build.py
```

The integration test in chunk G is not run by the implementation. Running it, and running the
live review that confirms artifact-indexing time drops on a FetchContent target, are manual
validation owned by the user.

## Expected effect

A FetchContent-heavy native build changes as follows:

- **Before:** every catalogued file under `_deps` becomes its own target-lane row with a
  delivery gap, so artifact indexing does per-file relationship work.
- **After:** each dependency tree is one recorded root with linked-kind anchors bounded by
  `max_kept_per_root`, plus one summarised gap per evidence source. Target output rows are
  unchanged.

The workspace manifest and the source fingerprint are unchanged, so CodeQL, PoC and remediation
consumers are unaffected.

## Implementation notes

Recorded by the implementation where the code refined or deviated from the design above.

### Chunk A (mechanism)

- **Receipt schema.** Receipt validation is open-key: `job_artifact_indexing/job.py`
  `_RECEIPT_SCHEMAS` only allowlists schema names. `RECEIPT_SCHEMA` therefore stays
  `appsec-review/language-build-receipt/1`, and `build_output_dispositions` is an added field.
  `EXECUTOR_IDENTITY` is bumped to `appsec-review/generic-language-build-executor/4`.
- **`classify_tree` gains `keep_linked=False`.** This additive keyword yields a `supply_chain`
  root's linked kinds (`executable`, `shared-library`, `static-library`) as kept rows. Native
  dependency roots pass it, and Conan generator output does not. `keep` remains the explicit
  path list that the npm classifier uses. `classify_tree` returns `False` when
  `max_layout_roots` is exhausted, and the root then stays per-file.
- **`classify_tree` gains `bound_group=None`** (user decision). `max_layout_roots` does not
  limit the number of npm packages. Every root registered with the same `bound_group`, which is a
  workspace directory containing the root, counts once against the bound. The npm classifier
  passes the installer prefix (the `node_modules` directory holding `.package-lock.json`), so one
  prefix uses one of the 512, however many verified packages it records, and no
  `build-output-root-bound-exceeded` gap results. Ungrouped roots keep the 512 bound. A root
  outside its group is a `ValueError`. Root documents carry `bound_group` only when it is set, and
  the sanitizer replay passes it through.
- **A configured exclusion wins over everything beneath it,** including deeper registered roots
  and their `keep` paths. Configured file rules also apply inside classified roots.
- **Rank merging.** For one root, a configured exclusion outranks fact bases, and fact bases
  outrank a heuristic. An equal-rank fact disagreement leaves the root `per_file` and records a
  conflict. Equal-rank heuristics that disagree also fall back to `per_file`.
- **An absent `[build_outputs]` table** gives the discovery defaults with no rules. The shipped
  rules live in `appsec-review.toml`.
- **Gaps.** The recorder still emits no gaps on its own. `named_gaps()` gives callers the
  observed conflict and bound gaps:
  - `build-output-classification-conflict: <root>`
  - `build-output-kept-bound-exceeded: <root> kept <n> linked files; <m> more stay counted only`
  - `build-output-root-bound-exceeded: <n> roots beyond max_layout_roots stay per-file target content`

  The generic `_catalog` appends them.
- **Kept rows** carry `build_output_root` beside `scope_role`.
- **Bookkeeping projection.** `excluded_bookkeeping` keeps its schema and its semantics: a
  reason is recorded only for changed, kind-matched files that the walk yields. Files inside a
  pruned root or a configured exclusion are not bookkeeping-counted. A FetchContent sub-build
  excluded by the shipped rule therefore lowers the CMake bookkeeping counts.
- **Misplaced tables.** `jobs.<id>.build_outputs` and `jobs.<id>.settings.build_outputs` fail at
  load.
- **Unused hook.** `node.catalog` and `php.catalog` accept the `dispositions=` keyword and
  ignore it until the installer-record classifiers use it. Until then, a Node or PHP language-build
  unit applies no `[build_outputs]` rule: the shipped `node-bundler-cache` rule takes effect only in
  project-build probes, and those units' `configured_exclusions`, `roots` and
  `BUILD_OUTPUT_CLASSIFIED` counts (except `target_rows`) are empty.
- **`bookkeeping` document key.** `document()` also carries the `bookkeeping` projection beside
  `schema`, `policy_identity`, `layout_sources`, `roots` and `configured_exclusions`.

### Chunks B and C (layout readers, capture attribution)

- `native_layout.py` reads the CMake cache, the codemodel-v2 reply to the stateless
  `client-appsec-review` query, Meson `meson-info`, static `build.ninja` edges, vcpkg
  `status`, MSBuild project properties and Conan generator output. Each source read is recorded in
  `layout_sources` as `{kind, path, sha256}`. The kinds are `cmake-cache`, `cmake-file-api-index`,
  `cmake-file-api-codemodel`, `meson-info`, `meson-intro-projects`, `meson-intro-targets`, `ninja`,
  `vcpkg-status`, `vcpkg-info`, `msbuild-project` and `conan-generator`.
- **Static `build.ninja` is read only when there is neither a CMake cache nor `meson-info`**
  (`discover` in `native_layout.py`).
- **Reader gaps.** A layout source that exceeds `max_layout_source_bytes`, cannot be read, does not
  parse, or falls beyond `max_layout_sources` is named
  `build-output-layout-source-bound-exceeded`, `-unreadable`, `-malformed` or `-limit`.
- **MSBuild output directories are read but not consumed.** `read_msbuild_dirs` resolves
  `OutDir` and `IntDir` into `LayoutFacts.output_directories` and names unresolved values
  `build-output-msbuild-directory-unresolved`. No caller passes `msbuild_properties` yet, because
  the Linux language build never runs MSBuild. The directories classify nothing until a Windows
  native lane exists.
- Static Ninja edges and capture attribution (`output_attribution.py`) add a root only where no
  fact root already covers it. Linked outputs a dependency produces into a mixed directory are
  tagged per file as `dependency-sourced-output`, not rooted.
- **Heuristic names.** `HEURISTIC_NAMES` in `native_layout.py` is its own set, not
  `job_dependency_intelligence`'s `_VENDOR`. It adds `vendors` and `dependencies` to the names
  in the source table above. A candidate root is a build-created child of a directory whose own
  name matches the set, compared case-insensitively.

### Chunk D (language-build integration)

- **`native_outputs.py`** holds the integration: `register` (discover, attribute, apply the
  heuristic and classify), `tag_and_promote` and `gaps`. It keeps `_execute_one` small.
- **Order.** For native units, `reconcile_captured_build` and `_apply_native_link_metadata` now
  run before cataloguing, so attribution sees reconciled rows. Their results are reused
  afterwards instead of being recomputed.
- **`prepared_inputs`.** The file API query that the job writes before configure is recorded on
  the receipt as `prepared_inputs: [{path, sha256, purpose: "cmake-file-api-query"}]`. It is excluded from the "pre-existing"
  set, so the build tree does not look target-owned.
- **Configured exclusions take precedence.** `register` skips a discovered root that a
  configured `[build_outputs]` directory rule already names (`configured_directory`). The
  FetchContent sub-build therefore appears once, as a configured exclusion, never as a gap.
- **`BUILD_OUTPUT_CLASSIFIED`** is written for every unit of every family that the generic
  executor (`_execute_one`) catalogues, not only native ones. The JVM and WebAssembly adapters
  do not use the walk and write no such event, and neither do the early blocked, platform and
  Node-gap receipts.
  Its keys are `supply_chain_trees`, `excluded_trees`, `excluded_files`, `kept_rows`,
  `heuristic_dispositions`, `conflicts`, `layout_sources_read`, `target_rows` and `duration_ms`.
  `target_rows` counts catalogue rows in the `target` analysis lane, so objects, which take the
  evidence lane, are not counted. The same counts are added to `LANGUAGE_BUILD_COMPLETED`. None of
  the keys is summed by `aggregate_run_metrics`.
- **Follow-up: `operation_phase("build.output_classify")`.** The span telemetry change
  (7dcc7b20) is not on main, so the classification is not yet wrapped in that phase and `_PHASES`
  is unchanged. A `FOLLOW-UP(7dcc7b20)` comment in `job_language_build/job.py` marks the place.
- **Follow-up: `ScopeRole.RUNTIME_DEPENDENCY`.** This role is owned by the dependency output
  filtering work (e9ae8d09), which is not on main. `native_outputs` resolves it with `getattr`.
  Until it lands, a dependency shared library that a target ELF loads stays `build_dependency`,
  which routes to the same `supply_chain` lane. The promotion activates automatically once the
  role exists. A `FOLLOW-UP(runtime_dependency)` comment marks the place.

### Chunk E (other catalogers)

- **Sanitizer build.** `job_sanitizer_build` does not rediscover layout. It replays the accepted
  language receipt's `build_output_dispositions.roots` (all except `per_file` roots) with
  `classify_tree`, then walks with the current `[build_outputs]` policy. The replay does not pass
  `keep_linked`, and the catalogue skips kept rows, so dependency trees are pruned entirely from
  the sanitizer catalogue. It adds
  `build_output_dispositions` to each unit result and `build_outputs_policy` to the summary.
  `excluded_bookkeeping` is the dispositions' bookkeeping projection.
- **Project build.** `job_project_build` `_outputs` walks the dispositions. Native probes call
  `native_outputs.register` with no captures and no file API query, so a probe classifies from
  the CMake cache, Meson introspection, static Ninja (when neither is present), vcpkg and Conan
  records and the name heuristic. The probe receipt gains
  `build_output_dispositions` and `build_output_gaps`. Classification gaps go into
  `build_output_gaps`, not `gaps`, so probe acceptance and repair are unchanged.
  `build_output_gaps` holds the reader, summarised-content and heuristic gaps; the
  `named_gaps()` conflict and bound gaps are not added to it. The
  `[build_outputs]` policy identity joins the probe checkpoint identity. The project
  `EXECUTOR_IDENTITY` is unchanged.

### Chunk G (integration tests)

- `tests/integration/test_native_build_output_layout.py` runs real CMake FetchContent and a real
  Meson wrap through intake, catalog, plan, project build and language build. The pinned native
  image ships neither `git` nor `meson`. FetchContent is therefore parametrised over a local
  tarball `URL`, which runs in the pinned image, and a `file://` `GIT_REPOSITORY` inside the
  target. The git case and the Meson case skip until the image provides those tools.
- No acceptance test is added. The acceptance suite evaluates review findings against answer
  keys and trace parity. Build-output classification has no answer-key defect to score.
