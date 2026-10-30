# Dependency output filtering: design

Status: implemented on branch `william-sollers-xbox-dependency-output-filtering-implementati`
(ready commit `7fac4f7f`), which merges the native build-output disposition mechanism (chunk N,
`13ef1ea9` and `3964a85b`). See [section 7](#7-implementation-status).

Branch: `william-sollers-xbox-dependency-output-filtering-design`, based on `38c934d9`.

## 1. Problem

In live run `2026-10-29-0004`, `artifact_indexing__index__relationships` took 45.2 minutes.
Every earlier run took about one minute. The indexing code had not changed. The input had.

- The run cataloged 8,541 artifacts. 8,188 of them (97%) sit under `node_modules`:
  - 7,101 from `projects/northwinds-v1`;
  - 1,086 from `projects/node-addon/case-087`.
- 8,398 rows have `artifact_origin` `build-output`, scope `unknown`, analysis reason
  `delivery-unknown-candidate-review` and analysis lane `target`.
- `_relationships` builds one shard per artifact and scans every tool invocation for each one
  (`job_artifact_indexing/job.py:597-717`). Its cost therefore grows with the row count.

How the rows get there:

1. The northwinds recipe runs its own `npm install`. A recipe that restores its own dependencies
   does not get the read-only image dependency view (`job_language_build/job.py:947-960`), so
   `node_modules` is written into the workspace that the catalog walks.
2. `node.catalog` walks the whole workspace (`node.py:154-175`). It keeps every file under a
   `node_modules` path even when the file is unchanged (`node.py:325-329`).
3. `scope_fields` gives every row without an explicit role the role `UNKNOWN`, which maps to the
   target lane (`delivery_scope.py:31,39-40`). It also emits one gap per row
   (`delivery_scope.py:56-60`).
4. The only node path that assigns a dependency role is accepted `npm pack` membership
   (`node.py:178-246`), and northwinds did not use it.

npm records exactly what it installed in `node_modules/.package-lock.json`. In northwinds that
file has `lockfileVersion` 3 and lists 259 packages (223 dev, 36 prod). Those packages cover
7,861 files and 127 MB. The target's real build output is `frontend/dist`.

The filtering must follow the rule in `delivery_scope.py:1-5`: origin and directory names do not
establish delivery. Scope comes from installer-authored facts. Content that no fact covers stays
visible.

## 2. Related efforts and file ownership

| Effort | State | Files it owns that matter here |
|---|---|---|
| **Native build output design** (`william-sollers-xbox-native-build-output-design`) | design; split agreed with this session | new `jobs/build_output_scope.py`; `[build_outputs]` TOML table, its parser and loader wiring; `job_language_build/job.py` `_snapshot`/`_catalog`/catalog dispatch hook; `RECEIPT_SCHEMA`/`EXECUTOR_IDENTITY` bump; `job_project_build`, `job_sanitizer_build`; `native_layout.py` |
| **Operation telemetry gaps** (implementation and docs branches) | implementation has uncommitted edits | `job_artifact_indexing/job.py`, `config/loader.py`, observability, retrieval/index.py, storage; docs |
| **Artifact indexing throughput** (sessions 0e8bb030 and dcb2aaa1) | implementation | `job_artifact_indexing/job.py`, `job_artifact_indexing/datasets.py`, `retrieval/index.py`, `storage/shared.py`, `storage/validation.py` |
| `william-sollers-xbox-relationship-indexing-bottleneck` | no commits and no edits | none |

This design changes **none** of the shared hotspots: `job_artifact_indexing/job.py`,
`job_artifact_indexing/datasets.py`, `retrieval/index.py` and `config/loader.py`. Package rows
reuse the existing `package-metadata` kind and the `package_metadata` and `delivery_evidence`
payload fields, which the catalog shard already keeps (`job_artifact_indexing/job.py:495-501`).
They land in the existing `build_artifact` family (`job_artifact_indexing/job.py:58-74`).

## 3. Numbered decisions

### D1. Scope of the first implementation

The first implementation covers npm installs recorded by npm's hidden lockfile, plus the shared
disposition mechanism owned by the native design. The table gives the decision for each
ecosystem.

| Ecosystem | Decision | Evidence |
|---|---|---|
| **npm** | **In scope.** Only this ecosystem was observed inflating the catalog. | Section 1; `node.py:325-329` keeps every `node_modules` file |
| pnpm, yarn classic, yarn berry | Deferred. A `[build_outputs]` rule handles them meanwhile. | `LOCKFILES` (`node.py:21-24`) knows their project lockfiles, but no installer record is parsed. pnpm's real files sit under `node_modules/.pnpm`. |
| C/C++ (FetchContent `_deps`, ExternalProject, vcpkg, Conan, Meson subprojects) | **Owned by Native build output design**, including the configurable exclusion (direction item 4). | Only bookkeeping is excluded today (`build_bookkeeping.py`); the generic `_kind` turns a new `.c`/`.h` file into `generated-source` (`job.py:270`). |
| Go | Deferred. This is the next candidate. Installer record: `vendor/modules.txt`. | `GOMODCACHE` is outside the workspace (`project_images.py:349`; `job_project_build/job.py:315`). A recipe step running `go mod vendor` (`go.py:84-87`) writes `vendor/**.go`, which `_kind` labels `generated-source`. `module_metadata` already locates `modules.txt` (`go.py:200-209`). |
| PHP (Composer) | Deferred. Installer record: `vendor/composer/installed.json`. | Image dependencies use `COMPOSER_VENDOR_DIR` outside the workspace (`project_images.py:358-359`), but a recipe-run `composer install` writes `vendor/`. Every changed `.php` file becomes `generated-source` (`php.py:136-137`). `composer_metadata` already marks prod packages unknown with a gap each (`php.py:91-97`); the follow-up should move them to `RUNTIME_DEPENDENCY` (D4). |
| Rust | Deferred. Installer record: the receipt's `cargo_metadata`, where a package source is a registry or a path. | `CARGO_HOME` is outside (`project_images.py:348`). Committed `vendor/` source is unchanged and skipped (`job.py:316-319`). Registry crates' `target/<profile>/deps` libraries are still cataloged (`rust.py:413-424`). Volume has not been measured. |
| .NET | Deferred. Installer record: `obj/project.assets.json`. | `NUGET_PACKAGES` is outside (`project_images.py:352`). Package assemblies copied into `bin/` are cataloged as `managed-assembly` (`dotnet.py:98-102`). The assets file is already recognized (`dotnet.py:123-124`). |
| Python | Deferred. Installer record: `*.dist-info/RECORD`. | Image dependencies are on `PYTHONPATH=/opt/project-deps` (`project_images.py:360`). An in-workspace `.venv` would add `dist-info` metadata, bytecode and native extensions (`python.py:67-82`). Plain `.py` files are not cataloged. |
| JVM | Deferred. | Caches are outside (`project_images.py:350-351`; `job_project_build/job.py:272-320`). Dependency jars copied into `target/` or `build/` stay cataloged, and in a WAR they really are shipped. That needs its own delivery decision. |

Each deferred ecosystem follows the same contract (D2–D7) in a later change. Until then a
`[build_outputs]` rule can exclude or reclassify its trees.

### D2. Installer-record parser (npm)

New module `src/appsec_review/jobs/job_language_build/node_installed.py`. It is pure and does no
catalog work.

- **Locating records.** An npm prefix is a directory `P` where `P/node_modules/.package-lock.json`
  is a regular file and not a symlink. `node.catalog` finds every such prefix in its walk (at most
  32). npm defines this file location. The parsed record, not the directory name, establishes
  scope.
- **Accepted format.** The file must be a JSON object of at most 64 MiB (`_MAX_METADATA_BYTES`,
  `node.py:72`). `lockfileVersion` must be 2 or 3. The `packages` object may have at most 50,000
  entries.
- **Entries.** For each key `k` in `packages`:
  - Skip the empty key (the root project).
  - Skip entries with `"link": true`. These are workspace links; their targets are target source.
  - Otherwise `k` must be a canonical relative POSIX path in which every `node_modules` segment
    is followed by one package name: a plain name or `@scope/name`.
  - `version` must be a non-empty string.
  - The expected name is `name` when present (aliased installs), otherwise the last package name
    in `k`.
  - Record `resolved`, `integrity`, `dev`, `optional` and `devOptional` when present.
- **Verification.** An entry covers files only if:
  - `P/k` is a real directory, not a symlink;
  - `P/k/package.json` is a regular file of at most 4 MiB that parses to an object;
  - that object's `name` and `version` equal the expected name and the entry's version.
- **Result.** `parse_installed_record(prefix) -> InstalledRecord` returns:
  - the record reference: workspace path, sha256 and size;
  - the verified packages;
  - the unverified packages with a reason: `install-path-missing`, `manifest-missing`,
    `manifest-invalid`, `name-mismatch` or `version-mismatch`.
- **Failure behavior.** Parsing never raises for target-controlled content. If the record is
  missing, unreadable, not JSON, has an unsupported version or exceeds a bound,
  `InstalledRecord.status` is `unavailable` with that reason, and **no** package is covered. The
  catalog then behaves exactly as it does today for that prefix and adds the gap in D6(b). Files
  are never dropped.
- **No other fallbacks.** The project `package-lock.json` describes intent, not what was
  installed, so it is not used. Without verified manifests there is no basis for coverage.

### D3. Package rows: schema and identity

There is one catalog row per verified package, anchored on its installed manifest.

```text
path, workspace_path      P/k/package.json (run-relative and workspace-relative)
sha256, size_bytes        of that package.json
kind                      "package-metadata"            (existing kind; no artifact_kinds change)
build_unit_id, mapping="exact-workspace-path", mapping_confidence=1.0
artifact_origin           "build-output" if changed since the pre-build snapshot, else "accepted-input"
scope_role                "build_dependency" | "runtime_dependency"  (D4)
delivery_evidence         {"kind": "npm-installed-record",
                           "workspace_path": "<P>/node_modules/.package-lock.json",
                           "sha256": "<record sha256>", "entry": "<k>"}
package_metadata          {"format": "package.json", "role": "installed-dependency-package",
                           "ecosystem": "npm", "manager": "npm",
                           "name", "version", "resolved"|null, "integrity"|null,
                           "dev": bool, "optional": bool, "dev_optional": bool,
                           "install_path": "<P>/<k>",
                           "files": int, "bytes": int, "retained_files": int}
```

- **Anchor.** artifact_indexing requires each row to be a real file whose digest matches the
  workspace manifest (`job_artifact_indexing/job.py:321-416`). The anchor is therefore the
  package's own `package.json`, not the shared record file. The native design keeps the manifest
  complete, so the catalog is always a subset of the manifest.
- **Identity.** Canonical identity is unchanged:
  `canonical_artifact_identity(source_fingerprint, build_unit_id, row)` over the anchor path and
  digest. Package rows are unique because install paths are unique.
- **Counts.** `files` and `bytes` count every regular file under the install path, excluding
  nested install paths that have their own entry. The names `files` and `bytes` follow the
  native design's telemetry-safe convention.
- **Record row.** The hidden lockfile gets one row: kind `resolved-dependency-metadata`, with
  `dependency_metadata = {"format": ".package-lock.json", "manager": "npm",
  "role": "installed-dependency-record"}`. Add `.package-lock.json` to
  `_RESOLVED_DEPENDENCY_METADATA` (`node.py:67`). Its default role is `BUILD_CHAIN`, which maps
  to the supply_chain lane (`delivery_scope.py:22,27`).
- **Retained per-file rows.** Files under a covered install path whose `artifact_kind` is
  `native-addon`, `shared-library`, `native-symbols` or `package` keep their own rows. They get
  the package's `scope_role` and a `delivery_evidence` that names the package entry. This keeps
  install-time native code (for example `node-gyp` output in case-087) visible to the
  supply-chain scanners.
- **Summarized files.** All other files under a covered install path produce no row. They are
  recorded through D5 and D6(a).

### D4. Scope roles and lanes

- **Dev packages.** Entries with `dev` or `devOptional` true get `BUILD_DEPENDENCY`
  (`accepted-build-dependency-review`, supply_chain lane). npm omits both under `--omit=dev`.
- **Prod packages.** All other entries get a **new** role,
  `ScopeRole.RUNTIME_DEPENDENCY = "runtime_dependency"`:
  - in `_REASONS` it maps to `("accepted-runtime-dependency-review", "supply_chain")`;
  - its `delivery_status` is `not_established`.
- **Why not `SHIPPED_DEPENDENCY`.** That role means delivery was established. It maps to the
  target lane with `delivered` status (`delivery_scope.py:26,45`). Its only producer is accepted
  pack membership. Being in npm's prod tree is not proof of delivery: bundlers inline it into
  `dist`, and server code needs it at run time.
- **What the supply_chain lane allows.** It admits only `inventory`, `packages`, `syft`, `grype`
  and `osv` (`delivery_scope.py:72-79`), which is the intended analysis.
- **`source_in_scope` is unchanged.** It still returns true for supply_chain rows
  (`delivery_scope.py:82-83`). Package rows are not source-bearing (D8), so this has no effect.
- **Version bumps.** `SCOPE_VERSION` becomes `appsec-review/delivered-scope/2`
  (`config/assurance.py:12`), and `delivery_scope.POLICY_IDENTITY` becomes
  `appsec-review/delivery-propagation/2` (`delivery_scope.py:14`). The role vocabulary changed,
  and a `/1` reader must fail loudly rather than mis-route a row.
  - `SCOPE_VERSION` feeds the review policy identity (`assurance.py:269`), so policy-keyed reuse
    is invalidated once.
  - `POLICY_IDENTITY` feeds `EXECUTOR_IDENTITY` (`job.py:60`).
  - No test or fixture hard-codes `delivered-scope/1`.

### D5. Recording through the shared disposition mechanism

This uses the native design's API. Its final names are owned there and are listed here only for
the contract.

```text
BuildOutputDispositions.classify_tree(root, *, disposition, basis, name, reason,
    evidence_ref=None, pattern=None, confidence, scope_role=None, keep=())
```

- **Verified package.** For each one, `node.catalog` calls `classify_tree(install_path,
  disposition="supply_chain", basis="installer-record", name="npm-installed-package",
  reason="verified against installed manifest", evidence_ref=<record ref + entry>,
  confidence="fact", scope_role=<D4 role>, keep=[anchor, *retained per-file paths])`.
- **Unverified nested package** inside a verified parent: call `classify_tree(install_path,
  disposition="per_file", basis="installer-record", name="npm-unverified-package",
  reason=<D2 reason>, confidence="fact")`. The deepest registered root wins, so its files stay
  per-file rows. This carve-out is visible.
- **Uncovered files.** Files under `node_modules` that no entry covers get no disposition and
  keep today's behavior. Examples are `node_modules/.cache/**` and `node_modules/.vite/**`.
  They are counted in D6(a).
- **Where it is recorded.** Dispositions are published in the receipt under
  `build_output_dispositions` (owned by the native design). `excluded_bookkeeping` stays as a
  compatible projection.
- **Workspace manifest.** It stays complete. Pruning applies only to the catalog. The native
  design confirmed this is needed by `job_codeql_analysis` `_workspace_manifest_files`
  (`job.py:270-322`) and by `job_poc_generation` rebuilds.
- **npm-pack precedence.** Before classifying trees, `node.catalog` computes the set of
  workspace paths that are members of accepted `npm pack` archives. It uses the same fact
  matching and bounds as `_package_delivery`: 256 facts and 4,096 members per archive. Those
  paths go into `keep` and are never summarized. `_package_delivery` then upgrades them to
  `SHIPPED_DEPENDENCY` or `DELIVERABLE` exactly as it does today (`node.py:178-246`). This
  preserves the existing shipped-dependency path for bundled dependencies.
- **Truncation.** Classification happens before the `limit` truncation (`node.py:380-382`), so
  dependency files no longer use up the 10,000-row bound.

### D6. Gaps (exact text)

The recorder emits no gaps. `node.catalog` emits the following. Format (a) uses the native
design's shared formatter `summarized_content_gap` in `build_output_scope.py`.

- **(a) Summary.** One gap per verified record, replacing up to 8,000 per-row unknown gaps:
  `dependency-content-summarized: <N> packages (<F> files, <B> bytes) recorded by <P>/node_modules/.package-lock.json routed to supply_chain review; per-file target review not performed`
  - `F` and `B` exclude retained rows.
  - When uncovered `node_modules` files exist, append exactly
    `; <U> files under node_modules not covered by the installer record remain per-file`.
- **(b) Record unavailable.** One gap per prefix whose `node_modules` exists but whose record is
  unavailable:
  `<P>/node_modules: npm installer record unavailable (<reason>); dependency files cataloged per-file in the target lane`
  - `<reason>` is one of `missing`, `unreadable`, `invalid-json`,
    `unsupported-lockfile-version:<v>`, `bound-exceeded:<bound>` or `entry-invalid:<key>`.
  - An invalid entry makes the whole record unavailable. A partially trusted record is not used.
- **(c) Unverified package.** For each of the first 50 unverified packages:
  `<install_path>: installed package does not match npm installer record (<reason>); cataloged per-file`
  - If there are more, add one final gap: `<n> further unverified npm packages cataloged per-file`.
- **Unchanged gaps.** Per-row `delivery_fact_unavailable` gaps (`delivery_scope.py:56-60`)
  remain for rows that are still `UNKNOWN`. Supply_chain rows produce none.

### D7. Configurable exclusion and dependency roots (direction item 4)

The native design owns this: the top-level `[build_outputs]` table with named
`[[build_outputs.exclusions]]` rules, the typed `BuildOutputPolicy` in the loader, and the
`configured-exclusion` disposition basis. This design adds no TOML setting and no
`LanguageBuildSettings` key, and makes no change to `config/loader.py`. Configured exclusions are
recorded as dispositions, never as gaps. That matches how target-file exclusions are recorded as
`configured_exclusions` (`config/exclusions.py`; `cataloging.py:79,190`).

### D8. Downstream consumers

| Consumer | Change |
|---|---|
| `job_tree_sitter_ast/generated_sources.py` | **No code change.** Summarized files no longer reach it. Package rows are kind `package-metadata` with suffix `.json`, so they fail the source-kind and source-language selection (`generated_sources.py:18,60-70`). Retained binaries are not source either. A unit test pins this. |
| `retrieval/source_resolution.py` | **No change.** It only resolves rows that were selected for source publication. |
| Node build probe / `job_project_build` | **No change.** `_IGNORED` already skips `node_modules` (`job_project_build/job.py:56`). |
| `job_artifact_indexing` | **No code change** (D3). Expected effect: row count drops from about 8,500 to about 650 for this run shape, so relationship shards drop by the same factor. |
| `job_artifact_security_analysis` | **No code change.** It reads roles with `ScopeRole(...)` (`job.py:110`) and gates by `analysis_scope` (`job.py:205,483`), so the new role routes automatically. `_applicable` already enables `packages` for the node family (`job.py:175`). |
| `job_target_catalog` | **No change.** It still uses declaration-based `unknown`/`build_dependency` for `package.json` sections (`job_target_catalog/job.py:233`). Those are declarations, not installer facts. |
| `php.composer_metadata` | **No change now.** It moves to `RUNTIME_DEPENDENCY` with the PHP follow-up (D1). |

### D9. Version and identity bumps

| Constant | From | To | Owner |
|---|---|---|---|
| `config/assurance.py` `SCOPE_VERSION` | `delivered-scope/1` | `delivered-scope/2` | this design, chunk A |
| `jobs/delivery_scope.py` `POLICY_IDENTITY` | `delivery-propagation/1` | `delivery-propagation/2` | this design, chunk A |
| `job_language_build/node.py` `CAPTURE_IDENTITY` | `node-build-capture/2` | `node-build-capture/3` | this design, chunk C |
| `job_language_build/job.py` `RECEIPT_SCHEMA`, `EXECUTOR_IDENTITY` base | — | as the native design decides | native design |

There are no artifact-indexing schema, parser or normalizer bumps, because those payload shapes
are unchanged.

### D10. Bounds

| Bound | Value |
|---|---|
| npm prefixes per build unit | 32 |
| Record size | 64 MiB |
| Packages per record | 50,000 |
| Package manifest size | 4 MiB |
| Unverified-package gaps listed | 50 |

Exceeding the prefix bound produces the gap
`npm installer record discovery bound reached; remaining prefixes cataloged per-file`. Other
bounds follow D6(b).

## 4. Test plan

Unit tests are fast and count-based, and they are run. Integration and acceptance tests are
written but **not run**: the user runs them.

### Unit tests (run)

| File | What it pins |
|---|---|
| `tests/test_delivery_scope_propagation.py` (extend) | `RUNTIME_DEPENDENCY` reason, lane and `not_established` status. `analysis_scope` allows inventory, packages, syft, grype and osv and refuses `native`/`jvm`. `delivery_gap` is None. A `scope_version` of `/1` is rejected. |
| `tests/test_node_installed_dependencies.py` (new) | Parser: v2 and v3 records; scoped, aliased and nested keys; `link` entries skipped; `dev`, `devOptional` and `optional` mapping. Every D6(b) reason. Name and version mismatch. Symlinked install path. Bounds at their limit +1, with the limits monkeypatched small. |
| `tests/test_node_dependency_output_filtering.py` (new) | The count regression in the next section, plus npm-pack precedence. |
| `tests/test_generated_source_pipeline.py` (extend) | A supply_chain `package-metadata` row and a retained `native-addon` row are not selected as generated sources. |
| `tests/test_artifact_security_analysis.py` (extend) | A `runtime_dependency` row is scanned by `packages` and refused by `native`. |

**Count regression** (`tests/test_node_dependency_output_filtering.py`). This is a synthetic
workspace with an empty pre-build snapshot. It must run in under 2 s.

- **Workspace contents:**
  - a root `package.json` with workspaces `backend` and `frontend`;
  - `node_modules/.package-lock.json` (v3) with 40 packages: 30 dev and 10 prod, including one
    scoped package, one nested `a/node_modules/b`, one `link` entry, and one entry whose installed
    manifest has a different version;
  - 25 files per package, so about 1,000 files;
  - one package with `build/Release/addon.node`;
  - `node_modules/.cache/loader/x.js`;
  - `frontend/dist/app.js`, `app.js.map` and `index.html`.
- **Assertions:**
  - exactly 38 package rows (39 non-link entries, minus 1 mismatch): 29 or 30
    `build_dependency` and the rest `runtime_dependency`, with exact numbers set by the fixture;
  - exactly 1 hidden-record row;
  - exactly 1 retained `native-addon` row with its package's role;
  - target-lane rows equal the 3 `frontend/dist` rows, plus the mismatched package's per-file
    rows, plus the 1 `.cache` row;
  - total rows of 70 or fewer;
  - exactly one `dependency-content-summarized:` gap with the exact F and B counts and the
    uncovered-files suffix;
  - exactly one D6(c) gap;
  - no `delivery_fact_unavailable` gap for any covered file.
- **Variant: record removed.** The catalog matches today's per-file behavior (same row count as
  the baseline), with exactly one D6(b) `missing` gap.
- **Variant: npm-pack precedence.** An accepted pack whose archive bundles
  `node_modules/dep/index.js` keeps that file as a `SHIPPED_DEPENDENCY` row even though `dep` is
  also a verified record package.

**Focused commands**, run in WSL from a Linux-filesystem checkout:

```bash
pytest tests/test_delivery_scope_propagation.py --basetemp=test/tmp/dof-scope -q
pytest tests/test_node_installed_dependencies.py tests/test_node_dependency_output_filtering.py \
       tests/test_language_build_node.py --basetemp=test/tmp/dof-node -q
pytest tests/test_generated_source_pipeline.py tests/test_artifact_security_analysis.py \
       --basetemp=test/tmp/dof-consumers -q
```

### Integration tests (write, do not run)

- `tests/integration/test_node_project_builds.py` (extend). For a case whose recipe runs
  `npm install`, assert that:
  - the receipt's catalog has one package row per verified record entry;
  - target-lane rows are bounded by the files under the declared build output directory plus
    uncovered files;
  - `build_output_dispositions` lists the installer-record trees.
- This file keeps its existing `requires_target` marker and its registry-availability skip.

### Acceptance tests (write, do not run)

- New file `tests/acceptance/test_dependency_output_bounds.py`. It is given a completed run root
  through `APPSEC_ACCEPTANCE_RUN_ROOT` and skips when that is unset. For each accepted
  language-build receipt, it asserts that:
  - no row with `scope_role` `unknown` has a `workspace_path` under an install path that
    `build_output_dispositions` records with basis `installer-record`;
  - the artifact-indexing artifact count is at most `target-lane rows + package rows + record
    rows + retained rows`.
- The coordinator should replay it against a fresh northwinds review.

## 5. Implementation chunks and file ownership (parallel-implementation §3)

| Chunk | Files (exclusive owner) | Depends on |
|---|---|---|
| **A. Scope contract** | `config/assurance.py`, `jobs/delivery_scope.py`, `tests/test_delivery_scope_propagation.py`, `tests/test_artifact_security_analysis.py` (scope cases only) | none; can land first and in parallel with the native design |
| **B. npm installer-record parser** | new `jobs/job_language_build/node_installed.py`, new `tests/test_node_installed_dependencies.py` | A (role values) |
| **N. Disposition mechanism** (native design) | `jobs/build_output_scope.py`, `[build_outputs]` config and loader, `job_language_build/job.py`, receipt schema | none |
| **C. node.catalog integration** | `jobs/job_language_build/node.py`, new `tests/test_node_dependency_output_filtering.py`, `tests/test_language_build_node.py` (fixture updates only), `tests/test_generated_source_pipeline.py` (D8 case) | A, B, N |
| **D. Integration and acceptance tests** | `tests/integration/test_node_project_builds.py`, new `tests/acceptance/test_dependency_output_bounds.py` | C |
| **E. Docs** (docs agent) | `docs/operations/artifact-indexing.md` (coverage-gap note), language-build and delivery-scope docs, this file's status line | C; after the telemetry docs branch lands, because that branch also edits `docs/operations/artifact-indexing.md` |

Ordering:

1. A, B and N can proceed together.
2. C rebases on N.
3. Then D, then E.
4. Then the user runs integration, acceptance and a live review.

No chunk edits `job_artifact_indexing/*`, `retrieval/index.py`, `storage/*` or
`config/loader.py`, so there is no ordering constraint with the telemetry or throughput
implementations beyond normal rebases.

## 6. Resolved questions (user decisions, 2026-10-29)

These questions were open in the first draft. The user's answers are now binding decisions.

1. **Prod dependency lane (confirms D4).** Prod dependencies of server-side workspaces, such
   as northwinds `backend`, get supply-chain review only: `RUNTIME_DEPENDENCY` in the
   supply_chain lane. They do not get per-file target review.
2. **Uncovered `node_modules` caches (no change here).** Whether the shipped
   `appsec-review.toml` gets default `[build_outputs]` exclusions for `node_modules/.cache`
   and `node_modules/.vite` is decided by the Native build output design session (D7). The
   coordinator has passed the suggestion on. Until that session adds defaults, these files
   stay per-file in the target lane and are counted in the D6(a) suffix.
3. **Deferred ecosystem order (confirms D1).** npm is implemented now. Go
   `vendor/modules.txt` is next, then Composer, .NET, Rust, pnpm/yarn, Python, and JVM, in that
   order. No Rust or .NET role-mix measurement is required first.
4. **Reuse invalidation (confirms D9).** The one-time loss of policy-keyed reuse caused by
   bumping `SCOPE_VERSION` (to `delivered-scope/2`) and the delivery `POLICY_IDENTITY` (to
   `delivery-propagation/2`) is accepted. The bumps land with chunk A and are not deferred.

There are no open questions.

## 7. Implementation status

The current behavior is documented in
[installed npm dependencies](../operations/language-build.md),
[delivery scope roles](../operations/performance-assurance.md#delivery-scope-roles) and the
[Node retention policy](../operations/artifact-indexing.md#node-retention-policy).

| Decision | Status |
|---|---|
| D1 (npm only) | Implemented. The other ecosystems are deferred in [the TODO](../TODO.md#summarize-installed-dependencies-for-the-remaining-ecosystems). |
| D2 (parser) | Implemented in `node_installed.py`, with the deviations below. |
| D3 (package and record rows) | Implemented. |
| D4 (roles and lanes) | Implemented: `runtime_dependency` and `build_dependency` in the supply_chain lane. |
| D5 (shared disposition recording) | Implemented. `job_language_build/job.py` passes the unit's `BuildOutputDispositions` recorder to `node.catalog`, which registers the D5 roots and takes its rows from `walk()`. The receipt publishes them under `build_output_dispositions`. |
| D6 (gaps) | Implemented with the exact texts in D6; (a) uses `summarized_content_gap`. The catalog also appends the recorder's `named_gaps()`. |
| D7 (configurable exclusions) | Implemented by chunk N: `[build_outputs]` with named `[[build_outputs.exclusions]]` rules, documented in [native build-output discovery](../architecture/native-build-output-discovery.md#configuration). The shipped `node-bundler-cache` rule excludes `node_modules/.cache` and `node_modules/.vite`. |
| D8 (downstream consumers) | Implemented as designed; the D8 tests were added. |
| D9 (version bumps) | Implemented: `delivered-scope/2`, `delivery-propagation/2`, `node-build-capture/3`. Chunk N bumped `EXECUTOR_IDENTITY` to `generic-language-build-executor/4`; `RECEIPT_SCHEMA` stays `language-build-receipt/1` because `build_output_dispositions` is an added field. |
| D10 (bounds) | Implemented. |

**Deviations from this design.**

- The parser signature is `parse_installed_record(workspace, prefix)`, and it returns record
  paths relative to the workspace.
- A prefix is a directory that holds a real (non-symlink) `node_modules` directory, found by a
  separate bounded walk that does not descend into `node_modules`. The record may be absent, so a
  missing record yields the D6(b) `missing` gap.
- Lock keys with no `node_modules` segment are workspace folders. They are skipped and stay
  target source.
- The key grammar is strict. A key with an empty, `.` or `..` segment, or a `node_modules` segment
  that is not followed by exactly one package name, makes the whole record unavailable
  (`entry-invalid:<key>`).
- The count regression has 2 target-lane `frontend/dist` rows (`app.js` and `index.html`), not 3.
  `app.js.map` is a `source-map` row in the evidence lane.
- The D6(b) `missing` gap is suppressed for a nested prefix whose `node_modules` a parent record
  describes.
- If an anchor `package.json` digest differs from the parsed manifest digest, the catalog raises
  `ValueError("installed npm package manifest changed during cataloging")` instead of reporting a
  gap.
- npm-pack precedence is bounded: at most 256 pack facts and 4,096 members per archive.
- The catalog computes coverage from the parser itself. When a caller passes no recorder,
  `node.catalog` creates one with the default policy, which has no exclusions. The recorder's
  `evidence_ref` is the string `<record path>#<entry>`, and the row's `delivery_evidence` keeps the
  record SHA-256.
- `classify_tree` gained `bound_group`, and each verified package passes its outermost
  `node_modules` directory (for example `node_modules` or `backend/node_modules`).
  `max_layout_roots` counts one slot per bound group, so an install tree of any size uses one
  slot. The record's own `node_modules` cannot be the group: a root record describes workspace
  members such as `backend/node_modules/x`, and a root outside its group raises `ValueError`.
- A package that `classify_tree` refuses because the root bound is exhausted stays per-file, gets
  no package row and is left out of D6(a). The recorder names it in
  `build-output-root-bound-exceeded: <n> roots beyond max_layout_roots stay per-file target content`.
- The D5 example of uncovered files no longer applies under the shipped configuration:
  `node-bundler-cache` excludes `node_modules/.cache` and `node_modules/.vite` by name, so their
  files get no rows and are not counted in the D6(a) uncovered suffix.

**Tests.** The unit tests below belong to the implementation. The docs session ran only
documentation checks.

- `tests/test_node_installed_dependencies.py`: 11 tests.
- `tests/test_node_dependency_output_filtering.py`: 8 tests. They cover:
  - the count regression;
  - the removed record;
  - npm-pack precedence;
  - the D5 roots in a real recorder;
  - the shipped `node-bundler-cache` rule;
  - a refused prefix under `max_layout_roots = 1`;
  - more than 512 verified packages under one prefix, all classified with no `build-output-` gap;
  - a nested prefix with no `missing` gap.

  The count regression yields 38 package rows (30 `build_dependency` and 8 `runtime_dependency`),
  1 record row, 1 retained `native-addon` row and a `dependency-content-summarized` gap of 949
  files.
- `tests/test_delivery_scope_propagation.py`: 2 new tests.
- `tests/test_artifact_security_analysis.py`: 1 new test.
- `tests/test_generated_source_pipeline.py`: 1 new test.
- `tests/test_language_build_node.py`: fixture updates.
- Chunk N's own unit tests, including `tests/test_build_output_scope.py`, are listed in the
  [native design](../architecture/native-build-output-discovery.md#implementation-breakdown).

These tests are written but **not run**:

- `_assert_installed_dependency_rows` in `tests/integration/test_node_project_builds.py`.
- `tests/acceptance/test_dependency_output_bounds.py`, 3 tests.

Both read the receipt's `build_output_dispositions` (schema
`appsec-review/build-output-dispositions/1`), which `job.py` now writes. The integration,
acceptance and live review validations remain the user's to run.
