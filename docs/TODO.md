# TODO registry

This is the only TODO file in the repository (`AGENTS.md`, "Deferred work and TODOs"). Every
deferred item has a stable id `T-NNN`, a state, and an observable "done when". Ids are never
reused or renumbered; closing an item changes its state, it does not delete the entry. A task doc
under `docs/tasks/` that works an item names its id in its first paragraph; a `TODO` comment in
code names an id or does not exist.

Entry format:

```
### T-NNN — Imperative title
- **State:** open | in-progress | blocked | done (YYYY-MM-DD, commit or task doc)
- **Area:** build | topology | images | windows | mobile | scanners | codeql | graph | native |
            data | history | evidence | review | binary | testing | pipeline
- **Blocked by:** T-… · **Blocks:** T-…        (either line omitted when empty)
- **Why:** the observed problem, one to three lines
- **Scope:** what changes, bounded
- **Done when:** the test, run or document that proves it
- **Refs:** files, task docs, architecture docs
```

Entries T-001–T-034 are the former prose backlog; they keep their text under "Legacy backlog"
until each is rewritten into the entry format when it is next touched.

## Index

| Id | Title | Area | State |
| --- | --- | --- | --- |
| T-057 | [First end-to-end review run and the break/fix loop](#t-057-first-end-to-end-review-run-and-the-breakfix-loop) | pipeline | in-progress |
| T-058 | [Build drivers live in the shared toolchain base](#t-058-build-drivers-live-in-the-shared-toolchain-base) | images | done (2026-11-08, T-058 entry; measurement owed by the next full build) |
| T-059 | [Register of the retired implementation fleet's goals](#t-059-register-of-the-retired-implementation-fleets-goals) | pipeline | blocked |
| T-035 | [Component layer between catalog and plan](#t-035-component-layer-between-catalog-and-plan) | topology | blocked |
| T-036 | [Build-mode disposition per component at plan time](#t-036-build-mode-disposition-per-component-at-plan-time) | topology | open |
| T-037 | [Recipe provenance: declared, canonical, inferred](#t-037-recipe-provenance-declared-canonical-inferred) | build | open |
| T-038 | [Declared builds: operator build plan file](#t-038-declared-builds-operator-build-plan-file) | build | open |
| T-039 | [Component-root materialization](#t-039-component-root-materialization) | build | open |
| T-040 | [Per-component dispatch and coverage reconciliation](#t-040-per-component-dispatch-and-coverage-reconciliation) | build | open |
| T-041 | [Toolchain runner kinds behind one executor contract](#t-041-toolchain-runner-kinds-behind-one-executor-contract) | windows | open |
| T-042 | [MSVC Windows container image](#t-042-msvc-windows-container-image) | windows | open |
| T-043 | [MSVC compile capture tiers and CodeQL on Windows](#t-043-msvc-compile-capture-tiers-and-codeql-on-windows) | windows | open |
| T-044 | [Unity editor image: operator provisioning runbook and settings](#t-044-unity-editor-image-operator-provisioning-runbook-and-settings) | mobile | open |
| T-045 | [Topology fixture xfail burn-down](#t-045-topology-fixture-xfail-burn-down) | testing | open |
| T-046 | [Barracuda slice target and declaration](#t-046-barracuda-slice-target-and-declaration) | build | open |
| T-047 | [Post-merge unit-test failure triage](#t-047-post-merge-unit-test-failure-triage) | testing | open |
| T-048 | [Rethink unit-test speed](#t-048-rethink-unit-test-speed) | testing | open |
| T-049 | [Supersede the Windows native-analysis VM design for builds](#t-049-supersede-the-windows-native-analysis-vm-design-for-builds) | windows | open |
| T-050 | [Container catalog: deferred acceptance work](#t-050-container-catalog-deferred-acceptance-work) | images | open |
| T-051 | [Host-local image pins: bind the observed image ID into the run](#t-051-host-local-image-pins-bind-the-observed-image-id-into-the-run) | images | done (2026-11-10, docs/tasks/2026-11-10-t051-host-local-pins.md) |
| T-052 | [Decide the home of Docker-engine-touching unit tests](#t-052-decide-the-home-of-docker-engine-touching-unit-tests) | testing | open |
| T-053 | [Decide whether review_intake keeps its own model gate](#t-053-decide-whether-review_intake-keeps-its-own-model-gate) | pipeline | done (2026-11-08, docs/tasks/2026-11-08-job-pass-04-review-intake.md) |
| T-054 | [Declare the inputs binary_evidence_indexing and artifact_indexing actually read](#t-054-declare-the-inputs-binary_evidence_indexing-and-artifact_indexing-actually-read) | pipeline | open |
| T-055 | [Catalog gaps as records so job_target_catalog can be strict](#t-055-catalog-gaps-as-records-so-job_target_catalog-can-be-strict) | topology | open |
| T-056 | [Build discovery test program: build points, total assignment, case matrix](#t-056-build-discovery-test-program-build-points-total-assignment-case-matrix) | topology | open |
| T-001 | [Finish OWASP acceptance beyond bounded static assessment](#t-001-finish-owasp-acceptance-beyond-bounded-static-assessment) | scanners | open |
| T-002 | [Hook up Lua game-security rule scanning](#t-002-hook-up-lua-game-security-rule-scanning) | scanners | open |
| T-003 | [Complete the Linux execution vertical before expanding platforms](#t-003-complete-the-linux-execution-vertical-before-expanding-platforms) | build | open |
| T-004 | [Implement conditional build-capture controls](#t-004-implement-conditional-build-capture-controls) | build | open |
| T-005 | [Scale native acceptance from fixtures to a game-sized build](#t-005-scale-native-acceptance-from-fixtures-to-a-game-sized-build) | build | open |
| T-006 | [Add Windows and large native-build coverage after the Linux acceptance gate](#t-006-add-windows-and-large-native-build-coverage-after-the-linux-acceptance-gate) | windows | open |
| T-007 | [Add Android, iOS, and Unity application coverage](#t-007-add-android-ios-and-unity-application-coverage) | mobile | open |
| T-008 | [Close the SEI CERT rule-pack execution and coverage gaps](#t-008-close-the-sei-cert-rule-pack-execution-and-coverage-gaps) | scanners | open |
| T-009 | [Add `grype_db_sync` to `job_third_party_data_sync`](#t-009-add-grype_db_sync-to-job_third_party_data_sync) | data | open |
| T-010 | [Optimize produced-artifact Grype without reducing coverage](#t-010-optimize-produced-artifact-grype-without-reducing-coverage) | scanners | open |
| T-011 | [Summarize installed dependencies for the remaining ecosystems](#t-011-summarize-installed-dependencies-for-the-remaining-ecosystems) | data | open |
| T-012 | [Follow-ups from the scanner launch reduction](#t-012-follow-ups-from-the-scanner-launch-reduction) | scanners | open |
| T-013 | [Match OSV advisories against the snapshot's own index](#t-013-match-osv-advisories-against-the-snapshots-own-index) | data | open |
| T-014 | [Measure and extend seeded CodeQL neighborhoods](#t-014-measure-and-extend-seeded-codeql-neighborhoods) | codeql | open |
| T-015 | [Validate and measure dataflow-bounded package slices](#t-015-validate-and-measure-dataflow-bounded-package-slices) | codeql | open |
| T-016 | [Measure and extend seeded Clang neighborhoods](#t-016-measure-and-extend-seeded-clang-neighborhoods) | native | open |
| T-017 | [Close the remaining CodeQL platform and accepted-build gaps](#t-017-close-the-remaining-codeql-platform-and-accepted-build-gaps) | codeql | open |
| T-018 | [Make CodeQL database throughput tunable end to end](#t-018-make-codeql-database-throughput-tunable-end-to-end) | codeql | open |
| T-019 | [Define and test the CodeQL checkpoint identity matrix](#t-019-define-and-test-the-codeql-checkpoint-identity-matrix) | codeql | open |
| T-020 | [Graph modes: aliases, slices, type layouts, buffer bounds, sink CFG context](#t-020-graph-modes-aliases-slices-type-layouts-buffer-bounds-sink-cfg-context) | graph | open |
| T-021 | [Joern bounded export and acceptance](#t-021-joern-bounded-export-and-acceptance) | graph | open |
| T-022 | [Evaluate additional Joern language frontends](#t-022-evaluate-additional-joern-language-frontends) | graph | open |
| T-023 | [Scale the clangd symbol index](#t-023-scale-the-clangd-symbol-index) | native | open |
| T-024 | [Replace the Python build-capture tool wrapper with a static Go binary](#t-024-replace-the-python-build-capture-tool-wrapper-with-a-static-go-binary) | build | open |
| T-025 | [Prove and extend the dataflow lane; build the contract and deployment lanes](#t-025-prove-and-extend-the-dataflow-lane-build-the-contract-and-deployment-lanes) | graph | open |
| T-026 | [Acquire dynamic execution evidence](#t-026-acquire-dynamic-execution-evidence) | evidence | open |
| T-027 | [Add Perforce history to source history analysis](#t-027-add-perforce-history-to-source-history-analysis) | history | open |
| T-028 | [Consider following Git submodules in source history analysis](#t-028-consider-following-git-submodules-in-source-history-analysis) | history | open |
| T-029 | [Finish deferred source history signals](#t-029-finish-deferred-source-history-signals) | history | open |
| T-030 | [Extend change-context analysis](#t-030-extend-change-context-analysis) | history | open |
| T-031 | [Narrow review-prioritization approximations](#t-031-narrow-review-prioritization-approximations) | review | open |
| T-032 | [Wire binary decompilation publications into a review](#t-032-wire-binary-decompilation-publications-into-a-review) | binary | open |
| T-033 | [Decide how to assert correctness for large query-set jobs](#t-033-decide-how-to-assert-correctness-for-large-query-set-jobs) | testing | open |
| T-034 | [Host a dependency proxy so builds can run without external egress](#t-034-host-a-dependency-proxy-so-builds-can-run-without-external-egress) | images | open |

## Active entries

### T-057 — First end-to-end review run and the break/fix loop

- **State:** in-progress
- **Area:** pipeline
- **Since:** 2026-11-08 — Phase 0 operator-run and Phase 1 agent-run proceed in parallel
- **Blocks:** T-035, T-036, T-037 (demoted to after the first scored run), T-045
- **Why:** nothing has run end to end since the runtime's typed input contract, strict gap
  records and the mounted-source deployment landed. The job-by-job pass (task docs
  `docs/tasks/2026-11-08-job-pass-NN-*.md`, order and rules in
  `docs/processes/job-pass-checklist.md`) found a run-stopping defect in a job roughly every other
  pass (undeclared intake reads in `job_ci_configuration_analysis` and `job_artifact_indexing`,
  `OPTIONAL_PRIOR` consumption in `job_target_analysis_plan`), and 7 of 46 jobs are done: finishing
  the pass linearly before running would take the better part of a week and still miss what only a
  run shows. The goal is a running system that breaks, is fixed with a focused unit test, and is
  resumed re-running only what the fix invalidates — the loop `recovery-repair.md` designs but
  nobody has driven on a real break.
- **Scope:** four phases.
  0. **Run readiness** (operator, each review host — HAL5000 and WSOLLERS1, both on the engine
     inside their WSL distro — `docs/operations/run-readiness.md`, `scripts/run-readiness.sh`): WSL
     host on the machine's one declared Docker daemon, ext4 checkout, key + committed anchor
     (`deploy/dagster/trusted-keys/`), build + smoke every enabled image, re-pin (own commit) and
     sign, compile the CodeQL packs, stack up on `targets/appsec-multi-vuln-c094`, gate run through
     `job_model_connectivity` and `job_image_pin_verification`. Image enforcement stays disabled for
     the first runs. An image that fails for a reason unrelated to the run is disabled in
     configuration and recorded, not fixed (T-050). **Target identity (resolved 2026-11-08):** the first-run target is
     `targets/appsec-multi-vuln-c094` at tag `appsec-multi-vuln-c094-v1` (`bd69bfe83fec…`, on `main`'s
     ancestry; key verified at the tag and at `main`'s tip). `cpp-multivuln-v1` was a separate local
     corpus (`targets/cpp-multivuln`, `9acaa340…`) that never reached GitHub; its acceptance records
     are historical (`run-readiness.md` step 6, `test-targets.md`).
  1. **Critical-path passes** (agent, in parallel with 0), in dependency order:
     `job_source_history_analysis` first (the plan's contract consumes its handoff, so its typed
     outputs are fixed before the plan's tests pin them), then `job_target_analysis_plan` (the 12
     `OPTIONAL_PRIOR` failures block any graph run; T-035/036/037 context), then T-054 — both
     `job_artifact_indexing` (fails every run under the typed input contract today; the
     `intake_target_root=False` seam exists) and `job_binary_evidence_indexing` (undeclared
     `job_target_catalog/handoff`). Each under the checklist, one commit per job.
  2. **First run**: `stepwise.py init/next/accept` on `targets/appsec-multi-vuln-c094` at tag
     `appsec-multi-vuln-c094-v1`, job by job, until a break.
  3. **The loop**, repeated until `stepwise.py system --tag appsec-multi-vuln-c094-v1` scores: for each break
     `failure-replay` → reproduce in a unit test under the pass checklist for that job (a break *is*
     that job's pass, done when the run needs it, not in catalog order) → fix → `lifecycle.py
     reload` → `plan-repair` / `admit-repair` / `resume` → confirm the plan's REUSE/RUN decisions
     reran only what the fix invalidated. A wrong reuse decision is itself a break with its own fix
     and test. Pass order from here is "whatever the run breaks on next".
  Standing rule: nothing in the loop rebuilds an image (`run-readiness.md`, "What triggers a
  rebuild"); if a step seems to need one, the step is wrong or the change is an image change and
  gets its own commit.
  **Carry-forward from the retired fleet worktrees** (assessment of 2026-11-08; the fleet backlog
  F00–F17 is not revived — anything kept lands through a job pass and this registry): X07's
  production correction — `job_post_build_security_assessment` declares the CPP envelope optional
  but `load_accepted_cpp` reads it unconditionally; make the envelope `REQUIRED`/`REJECT` without
  making the per-scope graph outputs mandatory — goes into that job's pass with runner-produced
  fixtures, not the historical synthetic-publication tests. The six language-build fixture
  corrections on `ceb8ea57` (`tests/test_go_language_build.py`, `test_language_build_node.py`,
  `test_language_build_python.py`, `test_php_language_build.py`, `test_rust_language_build.py`,
  `test_wasm_build.py`; 57+/28−) are hints to read during `job_language_build`'s pass against the
  T-047 baseline, never a diff to apply. X04 (four lines in `tests/handoff_fixture.py`, a handwritten
  publication default) is dropped; its negative controls — legacy or unknown worker identity, active
  workers and uncertain cleanup must refuse repair — are requirements of the repair-admission pass.
  The combined candidate's test-map expansion (whole `tests/test_repair_admission.py` in a shared
  mapping) is not inherited. Everything else in the fleet worktrees is already in `main`'s ancestry
  or was never implemented. Out of scope: Windows build containers (T-041, T-042, T-043, T-049) — the
  first runs are Linux-only and the Windows family follows a working Linux loop; catalog work
  (T-050); unit-suite speed (T-048, measured in job pass 07: `storage.shared.safe_path` dominates
  runner-driven tests) and the baseline triage (T-047) stay the differential baseline, not blockers.
  First measured cycle (WSOLLERS1, 2026-11-10, `job_target_catalog`, run `2026-11-10-0003`):
  **248.25 minutes** from observed content defect to rerun, **253.84 minutes** to verified acceptance.
  Shared-source changes correctly replayed the four predecessors under an admitted plan; guarded
  rewind preserved and re-compared their original keys. The measurement includes a **132.52-minute
  unintended broad test execution**, disclosed and not counted as authorized validation. This is
  one compound cycle toward the required three. See `docs/tasks/2026-11-08-job-pass-05-target-catalog.md`
  and `runs/c094-catalog-cycle-metrics.json` for the exact plan, outcomes and process failure.
  Model-availability normalization follow-up (passes 01 and 04): preserve raw advertised-provider
  inventory as diagnostic evidence outside compared content, including indirect artifact hashes.
  Compared keys must retain configured/checked model identities, availability/results, transport,
  errors/gaps and all other intake evidence. The approved operator-side inventory adjustment is
  a temporary stopgap until that producer/key boundary is corrected, not a permanent equivalence rule.
- **Done when:** (a) Phase 0's gate run accepts on HAL5000; (b) `stepwise.py system --tag
  appsec-multi-vuln-c094-v1` produces a score; (c) the edit → resumed-run turnaround of the loop is measured
  on at least three real breaks and recorded here with the REUSE/RUN decision each produced; (d)
  every job the run exercised has its task doc.
- **Refs:** `docs/operations/run-readiness.md`, `docs/operations/recovery-repair.md`,
  `docs/architecture/deployment-image-and-source-mount.md`, `docs/processes/job-pass-checklist.md`,
  `docs/operations/acceptance-funnel.md`, `docs/operations/signing.md`.

### T-058 — Build drivers live in the shared toolchain base

- **State:** done (2026-11-08, T-058 entry; measurement owed by the next full build)
- **Area:** images
- **Note:** landed before T-057 Phase 0's first `build --all`; the "done when" build measurement
  is still owed by that build's `build.py report`
- **Why:** `buildenv-native-toolchain` (gcc 13.3, clang 18.1, make, pkg-config) is the base of six
  language build environments, but the build *drivers* are installed per language: `audit-buildenv-cpp`
  adds autoconf/automake/libtool/cmake/ninja, `audit-buildenv-php` adds autoconf/automake/libtool,
  `tool-native-cpp` carries its own cmake, and go/python/rust-wasm/typescript have none. A Go
  module with cgo + CMake, a Python package built with scikit-build or meson-python, a Rust crate
  using the `cc`/`cmake` crates, or a node-gyp addon lands in a build environment without the driver
  it needs, and the plan has no single capability table to consult. The same apt layer is also built
  and stored several times.
- **Scope:** (done) the drivers moved into `buildenv-native-toolchain` — autoconf 2.71, automake
  1.16.5, libtool 2.4.7, cmake 3.28.3, ninja-build 1.11.1, meson 1.3.2 (python3 was already there),
  pkg-config — pinned in its `packages.lock`, probed in `check-toolchain.sh` (which every family
  re-runs) and in the catalog `probe_expect`; `cpp` installs nothing of its own any more and `php`
  only PHP and Composer. One image, not a third tier: a separate "build-tools" layer between
  compilers and languages buys only the ability to rebuild compilers without drivers, which never
  happens. **Left alone on inspection:** `tool-native-cpp` keeps its own cmake. It is not a build
  environment but the offline compile-capture tool, built network-free from a locked 263-package
  `.deb` closure (`assets.lock.json`, 316 MB) that also carries bear and the PHP/Python development
  headers; rebasing it on the snapshot-built toolchain would trade that locked closure for
  snapshot-pinned apt — a provenance downgrade for no build-time gain (the closure is a tar extract). **Not** in the shared base: Bazel (a JVM
  binary with a 200 MB+ footprint that fetches rules at build time and needs a vendored repository
  cache to work offline — a per-target decision when a target needs it, T-050), Gradle/Maven
  (already in the JVM environments), language package managers. Separate question, not here:
  `audit-buildenv-java`, `-dotnet` and `-android` build `FROM` ubuntu/temurin directly rather than
  from the toolchain; whether a JVM or .NET target ever needs the native compilers decides that.
- **Done when:** every buildenv that builds `FROM` the toolchain can run `cmake`, `ninja`, `meson`,
  `autoreconf` and `libtool` at the pinned versions; the `cpp`/`php` Dockerfiles install nothing
  the base has; `containers/build.py report` of the next full build shows the critical path
  (`base-ubuntu → buildenv-native-toolchain → slowest buildenv`) no longer than before, and the
  plan's build-mode disposition (T-036) can read one capability set for the toolchain family.
- **Refs:** `containers/buildenv/native-toolchain/`, `containers/catalog.toml`, T-036, T-050,
  `docs/operations/run-readiness.md` ("What triggers a rebuild").

### T-059 — Register of the retired implementation fleet's goals

- **State:** blocked
- **Area:** pipeline
- **Blocked by:** T-057
- **Why:** the "appsec implementation fleet" (coordinated agent sessions, packages F00–F17 plus
  X-repairs, plan and ledger formerly under `docs/plans/appsec-system-improvements/`) was paused on
  2026-11-07 and disposed of on 2026-11-08. Its plan was a second registry; this is the single one.
  The design it implemented is kept at `docs/reviews/appsec-system-review-2026-11-06.md`. The
  reconciliation assessment of 2026-11-08 established what landed and what did not; the carried
  fragments (X07, the six language-build fixtures, X04's negative controls) are in T-057's
  carry-forward list. This entry holds the *goals* that did not land, one line each, so nothing is
  lost and nothing is started before the first run shows which of them matter.
- **Landed (closed, in `main`'s ancestry):** F00 integration docs; F01 publication/inventory
  repairs; F02 typed input and dispatch contracts (+ corrections; its consumption-authority policy
  stands); F05 static deployment/service inventory core; F08 worker competence and stateful
  guidance; F09 Glasswing quality metrics core; X01, X02, X03, X05, X06. F03 (shared readers) is
  closed by decision: `runtime.consume.accepted_upstream` is the one reader; T-054 enforces it.
  F04 (recoverability) became T-057 Phase 3.
- **Scope:** the surviving goals below, each re-cut as job passes with typed inputs, gap records
  and runner-driven tests when taken up; package boundaries are historical. Every row is gated on
  T-057's first scored run.
  - **F06 deployment/exposure jobs** — deployment-topology and imported service-observation
    producers consuming F05's inventory; queryable topology/exposure evidence with freshness/drift;
    build graph and deployment graph kept distinct; live collectors permission-gated.
  - **F07 threat model** — an evidence-backed producer of assets/actors/boundaries/flows/threats/
    obligations/unknowns consuming classification, applicability, deployment and build facts;
    document-candidate routing into independent review; typed missing-evidence requests rather than
    worker self-expansion; target-owned exclusions are untrusted context.
  - **F10 operational telemetry** — per-job lifecycle/failure/metrics are now a checklist requirement
    (done per pass); still open: queue/admission/scheduler/resource wait accounting, supplied/
    retrieved/cited evidence views, offline dashboard rendering, optional bounded OTLP export with
    durable position, cost/yield/marginal-role metrics, no source or secrets in telemetry.
  - **F11 experiment planning** — engine-neutral experiment schemas, planner and admission over
    accepted builds; exact source/build/harness/oracle/corpus/config identity and bounds; the
    compile-only review contract preserved; no arbitrary shell or self-issued consent.
  - **F12 downstream replay and campaigns** — appsec campaign lifecycle over the APS-owned DDNet
    runner; deterministic replay first, then bounded coverage-guided campaigns; persisted inputs,
    corpus snapshots, controls and partial outcomes; reduction with parentage; APS replay delivery
    does not itself authorize campaigns.
  - **F13 Lean/formal evidence bridge** — restricted observed-trace projection, pinned Lean
    execution/result contract, assumption applicability and model-mismatch publication; kernel-only
    checking per `docs/formal-verification/design-review-2026-11-07.md`; the APS Lean model only for
    compatible trace work, not as the source-to-IR correspondence program.
  - **F14 re-adjudication and final publication** — runtime evidence admitted as a new publication
    version, never an edit; original vs repaired builds under one observation contract;
    non-reproduction is not refutation; gate/report/dossier/OpenVEX snapshots.
  - **F15 capability report, skills and MCP** — configured/installed/reachable/compatible/
    commissioned/permitted reported separately; one CLI/runner, MCP only if justified; read-only
    inspection without execution permission; no blanket installs or unrestricted endpoints.
  - **F16 measured optimization** — representative performance fixtures; hash/copy/fsync/index/
    lock/cache costs measured before any hot-path change; a native boundary only if evidence
    supports it (T-048's `safe_path` measurement is the first data point).
  - **F17 closeout** — docs, job/input/output inventories, release closure, test mappings and
    supported-mode claims reconciled; known-failure and skip lists reviewed; implementation,
    commissioning, live efficacy and deferred-by-evidence labelled separately. Largely subsumed by
    T-057's done-when and the `docs-sync` skill.
- **Done when:** after T-057 scores, each surviving goal above is either promoted to its own
  `T-NNN` entry (with the job passes it needs) or struck here with the reason the first run gave;
  this entry then closes.
- **Refs:** `docs/reviews/appsec-system-review-2026-11-06.md`, T-057 (carry-forward list), T-054,
  T-048, `docs/formal-verification/design-review-2026-11-07.md`.

### T-035 — Component layer between catalog and plan

- **State:** blocked
- **Area:** topology
- **Blocked by:** T-056, T-057
- **Note:** design work that does not block a first run; resumes after T-057's first scored run
- **Blocks:** T-036, T-037, T-040, T-045
- **Why:** `job_target_catalog` emits one build unit per marker and one "component" per manifest,
  flat. `compile_build_topology` folds a unit into an owner only on literal CMake/Make evidence, so
  vendored libraries, Cargo/Go/npm workspace members, settings-only Gradle roots and sibling-source
  directories become independent roots that are planned and built standalone (Barracuda: 295
  units, 271 roots). A component — one buildable product with one driver and one materialization
  root — does not exist as a concept.
- **Scope:** introduce components in the plan (root, family, build system, owner reasons); default
  nested units of a compatible family to `contained` unless they have their own configure authority
  and no ancestor driver; parse Cargo `[workspace] members`, `go.work use`, npm `workspaces`
  (`node_workspace()` already computes them) and Gradle `settings.gradle`/`project(':x')` into
  ownership and `requires_product` relations; make `_resolve()` accept Gradle project paths
  containing `:`. *Job pass 05 (2026-11-08) landed the discovery side:* `workspace` facts
  (`manager`, `role`, `root`, `members`) for Cargo, Go and settings-only Gradle roots, the Xcode
  unit, and no manufactured `direct-native` root for a source a sibling descriptor names. The
  compiler now has the facts to fold `role == member` units as `contained`; when it does, remove
  the Gradle root-with-build-file absorption in `discover_build_units` so both Gradle shapes agree.
  Static target proof is no longer load-bearing; T-035 still owns component identity and ownership.
- **Done when:** `tests/test_topology_fixture.py` xfails `ownership-*`, `relation-*` and
  `ownership-gradle-settings` flip to passes with their marks removed; a Barracuda slice plan shows
  tens of components, not hundreds of roots.
- **Refs:** `docs/tasks/2026-11-07-topology-fixture-monorepo.md`,
  `docs/architecture/build-topology-and-iterations.md`, `src/appsec_review/jobs/build_topology.py`.

### T-036 — Build-mode disposition per component at plan time

- **State:** open
- **Area:** topology
- **Blocked by:** T-035
- **Blocks:** T-040
- **Why:** components we cannot or must not build (Unity while `unity.enabled=false`, iOS with no
  macOS executor, PHP sites without `composer.json`, Android without a routed SDK image) surface as
  per-unit BLOCKED gaps inside `job_project_build` instead of a decision in the plan. Downstream
  static and source-only analysis should run on them and the report should name the disposition.
- **Scope:** `build_mode ∈ {compiled, package-only, source-only, skipped_policy, unsupported_platform}`
  on every plan component; `.xcodeproj/project.pbxproj` becomes a discovery marker so iOS is a
  component with a disposition rather than absent; selection-policy rows for `composer`,
  `npm|pnpm|yarn`, `gradle` (by build system, not only `declared_platform`); `job_project_build`
  never sends a non-`compiled` component to an image handler.
  Static target proof is no longer load-bearing; T-036 still owns component build-mode disposition.
- **Done when:** fixture xfails `build-mode-disposition` and `discovery-marker` flip; a plan on the
  fixture publishes with zero BLOCKED image entries for shapes D–G.
- **Refs:** T-035, `appsec-review.toml` `[jobs.job_project_build.settings.build_selection]`.

### T-037 — Recipe provenance: declared, canonical, inferred

- **State:** open
- **Area:** build
- **Blocked by:** T-035
- **Blocks:** T-038, T-041
- **Why:** every build recipe is model-inferred (`ambiguity_reasons` always adds "buildable units
  require inference-derived build recipes"), partitioned 16 units per scope with up to 4 calls
  each. Barracuda spent hours of inference and still had 101 null recipes. Canonical build systems
  have known recipes; the model should be the exception path.
- **Scope:** per component, resolve in order `declared` (T-038) › `canonical` (deterministic
  per build system: cmake -S/-B + --build, make, cargo build --workspace, go build over `go.work`
  use entries, npm run build, composer install/dump-autoload, gradle assemble) › `inferred`;
  record `recipe_provenance` and the declaration hash in the plan; run inference only for
  components still null or marked `infer`; all three pass `validate_build_recipe` and the same
  command policy.
  Static target proof is no longer load-bearing; T-037 still owns declared/canonical/inferred recipe provenance.
- **Done when:** fixture xfail `deterministic-recipe` flips; a Barracuda slice plan has no null
  recipes for cmake/make units and model calls fall by an order of magnitude (recorded in
  `plan["feedback"]`).
- **Refs:** `src/appsec_review/jobs/job_target_analysis_plan/{job,planning}.py`,
  `src/appsec_review/jobs/build_discovery.py::build_recipe_inference_policy`.

### T-038 — Declared builds: operator build plan file

- **State:** open
- **Area:** build
- **Blocked by:** T-037
- **Blocks:** T-046
- **Why:** real targets ship their own build scripts. An operator must be able to say "root X,
  run this script, in this image" and have the pipeline run and capture it without inference.
- **Scope:** an operator-side TOML (never inside the target) passed as `start --build-plan`,
  hashed into the intake handoff and the claim; entries carry `id`, `root` (materialization root),
  `image` (a pinned profile) or `image_id`, `run` argv, `cwd`, optional `products`, allowlisted
  `env`, or just a `mode` disposition; the same block is accepted on
  `[[target_acquisition.systems]].components`. A declaration must name an image: the run never
  builds images. The script runs inside the pinned image with no network under the normal output
  policy. `.bat`/`.cmd`/MSBuild declarations route to the `msvc` profile (T-046) or are recorded
  `unsupported_platform` until it exists. Declared-build failure is an operator fault: no model
  repair; fix the declaration, `plan-repair`, `resume`.
- **Done when:** a declaration for the fixture's `server` and `tools/packer` builds both from the
  repository root with capture, discovery marks their units `covered_by: declared:<id>`, and the
  refinement step reports which covered units compiled.
- **Refs:** T-037, `docs/operations/target-acquisition.md`.

### T-039 — Component-root materialization

- **State:** open
- **Area:** build
- **Blocks:** T-040
- **Why:** `job_language_build._copy_source` (and the probe copy in `job_project_build`) copy only
  the unit's root plus named `dependency_files`. Both documented Barracuda GoogleTest failures are
  `../samples/sample1.cc` missing from a partial workspace; every workspace member and sibling
  include fails the same way, and the repair loop then "repairs" a correct recipe.
  `validate_build_recipe` also requires `source_dir == unit root`, so a recipe cannot even express
  "materialize the repository root".
- **Scope:** materialize the component root (T-035) or, as the first step, the whole accepted
  target, keeping `cwd` at the unit's directory; keep the symlink/escape checks; relax
  `validate_build_recipe` to allow `source_dir` to be an ancestor of the unit root; record the
  materialization root in the receipt.
- **Done when:** fixture xfail `workspace-materialization` flips and
  `test_topology_fixture.py`'s sibling-source compile checks run through the real lane; a Barracuda
  slice builds the vendored gtest from the parent tree.
- **Refs:** `src/appsec_review/jobs/job_language_build/job.py::_copy_source`,
  `src/appsec_review/jobs/job_project_build/job.py::_copy_source`.

### T-040 — Per-component dispatch and coverage reconciliation

- **State:** open
- **Area:** build
- **Blocked by:** T-035, T-036, T-039
- **Why:** `job_project_build` dispatches per unit, so contained units are built standalone and
  the plan's defects are carried forward faithfully. The refinement step already reconciles
  captured compiles back to units; it should be the source of per-unit coverage under a component.
- **Scope:** one dispatch per `compiled` component (root, image, recipe, provenance); sub-units
  never dispatch; after execution, mark each unit under the component `compiled | not-compiled |
  not-applicable` from the capture; coverage and gaps are per component with the per-unit list
  attached.
- **Done when:** a fixture live run (`appsec-review start --target targets/topology-monorepo`)
  dispatches exactly the expected components and `acceptance.topology score` reports no diff.
- **Refs:** T-035, T-039, `docs/architecture/build-topology-and-iterations.md`.

### T-041 — Toolchain runner kinds behind one executor contract

- **State:** open
- **Area:** windows
- **Blocked by:** T-037
- **Blocks:** T-042, T-043
- **Why:** "image" means a Linux Docker image everywhere (`BuildProfile`, `BuildContainerExecutor`,
  pin verification). Windows/MSVC builds need a second runner with the same contract.
- **Scope:** `profiles.<name>.kind = "docker" | "windows-container"` (a `windows-host` PowerShell
  runner only as a fallback where Hyper-V isolation is unavailable), `daemon` selection for the
  Windows container engine (Docker Desktop `desktop-windows` context reached from the Dagster
  container over the WSL-facing address), executor factory keyed on kind,
  `job_image_pin_verification` and `update-image-pins` inspecting the right daemon,
  `guard_action` unchanged.
- **Done when:** pin verification passes against a Windows-daemon image and refuses a drifted one;
  a `WindowsContainerExecutor` fake runs through the language-build lane in unit tests.
- **Refs:** `src/appsec_review/container_runtime/build_executor.py`,
  `src/appsec_review/jobs/job_image_pin_verification/`.

### T-042 — MSVC Windows container image

- **State:** open
- **Area:** windows
- **Blocked by:** T-041
- **Blocks:** T-043
- **Why:** MSVC/MSBuild targets (`.bat`, `.sln`, `.vcxproj`) are a real share of the game
  codebase. Microsoft's Build Tools container pattern (`windowsservercore` + `vs_BuildTools.exe
  --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended`) gives a pinned, disposable
  image under the existing Visual Studio license (never published to a public registry).
- **Scope:** `containers/buildenv/msvc/Dockerfile` built from an offline VS layout (`--layout`,
  `--noWeb`) so component versions are pinned; `containers/catalog.toml` entry with
  `platform = "windows"`; `containers/build.py` support for the Windows daemon and `-m 2GB`;
  `--isolation=hyperv --network none`, `ContainerUser`, `VsDevCmd.bat -arch=x64` entrypoint;
  workspace in/out as single tar streams (no `\wsl$` bind mounts, no per-file bridge copies);
  `WindowsContainerExecutor` with Windows-appropriate flags. Operator prerequisites on the Windows
  side (Docker Desktop in Windows-container mode, Hyper-V, exposed daemon on the WSL-facing
  address, VS layout) go in an operations runbook.
- **Done when:** `audit-buildenv-msvc:local` is pinned on HAL5000, the fixture gains a `.vcxproj`
  shape that builds through the lane, and PDBs reach `job_debug_symbol_indexing` via
  `--compiler-target msvc`.
- **Refs:** T-006 (legacy Windows section; this supersedes its VM-only sequencing),
  `docs/architecture/windows-native-analysis-vm.md` (gates to fold in; see T-049).

### T-043 — MSVC compile capture tiers and CodeQL on Windows

- **State:** open
- **Area:** windows
- **Blocked by:** T-042
- **Why:** no `bear` on Windows; capture quality must be recorded, not assumed.
- **Scope:** tier 1 CMake `-G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` under `cl.exe`; tier 2
  `msbuild -bl` binlog → CL/Link invocations; tier 3 `_CL_=/sourceDependencies <dir>` per-TU JSON
  plus a `cl.exe` PATH shim for arbitrary scripts; receipt field `capture_quality ∈ {complete,
  partial, inventory-only}`; CodeQL Windows CLI in-image tracing the accepted build for
  `job_cpp_compiled_analysis`.
- **Done when:** each tier has a fixture and the refinement step consumes all three.
- **Refs:** T-042, `docs/operations/codeql-analysis.md`.

### T-044 — Unity editor image: operator provisioning runbook and settings

- **State:** open
- **Area:** mobile
- **Why:** `config/unity.py` requires an already provisioned, licensed editor image; the pipeline
  never installs or licenses Unity (correct). Nothing documents how the operator provides it, and
  `[jobs.job_project_build.settings.unity]` holds only `enabled = false`.
- **Scope:** `docs/operations/unity-editor-image.md`: match `m_EditorVersion` from the target's
  `ProjectSettings/ProjectVersion.txt`, pull the GameCI `unityci/editor:ubuntu-<version>-android-3`
  image, activate the operator's license inside it, verify `license_ready`, pin with
  `update-image-pins --write`; a complete settings stanza ready to flip `enabled = true`. Unity stays
  `skipped_policy` (T-036) until then.
- **Done when:** the runbook exists and a Unity fixture (topology shape D) is dispositioned
  `skipped_policy` with `enabled = false` and `compiled` with a declared image in a unit test.
- **Refs:** `src/appsec_review/config/unity.py`, `src/appsec_review/jobs/unity_build.py`, T-007.

### T-045 — Topology fixture xfail burn-down

- **State:** open
- **Area:** testing
- **Blocked by:** T-035, T-036, T-037, T-039
- **Why:** `tests/test_topology_fixture.py` carries 54 strict xfails, each tagged with a reason
  code; they are the executable form of T-035–T-039. A strict xfail that starts passing fails the
  suite, so marks must be removed as behavior lands.
- **Scope:** when a T-item above closes, remove its reason code's marks and update the task doc's
  gap table; add fixture shapes for `.vcxproj` (T-042) and a declared build (T-038).
- **Done when:** zero xfails remain and the live `acceptance.topology score` run is clean.
- **Refs:** `docs/tasks/2026-11-07-topology-fixture-monorepo.md`.

### T-046 — Barracuda slice target and declaration

- **State:** open
- **Area:** build
- **Blocked by:** T-038, T-039
- **Why:** the full Barracuda run takes eight hours per iteration; polyglot-case targets exercise
  lanes, not topology. A slice (`fsh-server/Server`, or the protobuf/gtest subtree plus its
  consumers) reproduces the real failure shapes at a tenth of the size.
- **Scope:** `targets/barracuda-slice` (gitignored, operator-prepared), a `targets/barracuda-slice.build.toml`
  declaring the server build in the `native` image and the website/Unity/iOS dispositions; run with
  `start --target … --build-plan …`.
- **Done when:** the slice plan publishes with components and no sibling-source failures, and the
  declared server build produces compile captures on the first run.
- **Refs:** `docs/architecture/build-topology-and-iterations.md` (historical run 2026-11-04-0003).

### T-047 — Post-merge unit-test failure triage

- **State:** open
- **Area:** testing
- **Why:** the fleet "typed job input contracts" merge (`fe328d76`) introduced ~70 new unit-test
  failures (native SBOM, language_build dotnet, tool_input_support, target_artifact_intake,
  review/test_judge, project_build) with messages such as `required input unavailable:
  job_artifact_indexing/handoff`. Most look like fixtures that build run trees by hand without the
  now-mandatory producers; some may be runtime regressions for buildless components.
- **Scope:** classify each failing test as stale fixture or runtime regression; fix fixtures
  through `consume`/`inputs` helpers, not by relaxing contracts; file any runtime regression as its
  own T-item.
- **Done when:** the differential against `fe328d76`'s baseline shows no failures attributable to
  the merge.
- **Refs:** `docs/tasks/2026-11-07-job-control-schema-standardization.md` (differential method).

### T-048 — Rethink unit-test speed

- **State:** open
- **Area:** testing
- **Why:** the full unit suite is slow enough that live tests are being run instead of it, and it
  carries ~900 environment-dependent failures outside the reference host. Deferred by the owner
  until after the next live test cycle.
- **Scope:** to be defined; candidates include splitting Docker-touching tests out of the unit
  path (see T-052), session-scoped fixtures for run trees, and `pytest-xdist` by default.
- **Measured (job pass 07):** a runner-driven unit test (intake → catalog → one job on a tiny
  synthetic target) costs ~7 s serially; a profile puts about half in `storage.shared.safe_path`
  (≈14.7k calls per run, each a per-component symlink walk) and most of the rest in the handoff's
  reference verification. Every job pass adds ~10 such tests, so this is the lever.
- **Done when:** a scoped decision is recorded here and the unit path runs in minutes on a
  developer host.

### T-049 — Supersede the Windows native-analysis VM design for builds

- **State:** open
- **Area:** windows
- **Blocked by:** T-042
- **Why:** `docs/architecture/windows-native-analysis-vm.md` designs an ephemeral Windows VM with
  legal, provenance, isolation, tooling, capacity, mock-test and live-acceptance gates. The MSVC
  Windows container (T-042) supersedes the VM for builds; the still-valid gates (licensing, no
  target execution, immutable evidence export, verified teardown) must be carried into the new
  design rather than silently dropped.
- **Scope:** decide per gate: carried into T-042, kept for a VM-only capability (e.g. target
  execution for dynamic evidence, T-026), or retired; mark the VM doc superseded for builds.
  (Formerly `docs/windows-native-analysis-todo.md`.)
- **Done when:** the VM doc states its remaining scope and `T-042`'s doc lists the inherited gates.

### T-050 — Container catalog: deferred acceptance work

- **State:** open
- **Area:** images
- **Why:** items carried from the former `containers/TODO.md`.
- **Scope:**
  - GCC counterpart to `audit-buildenv-cpp` (`CC=gcc CXX=g++`, sanitizer runtimes, `-fanalyzer`)
    and a recorded retry on GCC when the clang build fails; needs a second native profile per
    family in `job_project_build`.
  - Decide whether archived `audit-native` capabilities (SVF, CodeChecker) earn a bounded image;
    retire or replace the deferred `audit-native`, `audit-codeql`, `audit-lsp-vendor` entries.
  - Share only explicit LSP payload layers; add language-server fixtures.
  - Binary analysis: a specialized capability only when BLint/Syft/Grype/Trivy fail a job contract;
    no curl-to-shell installers, no duplicated scanners.
  - `tool-ghidra`: close `containers/tools/ghidra/LICENSE.md` open items, one reviewed `base-jdk`,
    pin `image_id`, lint the Dockerfile, add a PE fixture.
  - ScanCode: evaluate a fixed release; compare incremental value with Syft before enabling.
  - Microsoft SBOM Tool / SBOM Assembly: stay replaced by Syft unless a contract proves a gap.
  - Document conversion: complete hashed `.deb` closure for pandoc/poppler; PDF/DOCX fixtures.
  - `tool-report-latex`: call it from a publication job, drop `manual = true`, pin `image_id`,
    add a pdftoppm visual check.
  - Dagster: orchestration is a deployment concern; do not restore its archived image.
- **Done when:** each bullet is either closed or promoted to its own T-item.
- **Refs:** `containers/README.md`, `containers/buildenv/README.md`.

### T-051 — Host-local image pins: bind the observed image ID into the run

- **State:** done (2026-11-10, docs/tasks/2026-11-10-t051-host-local-pins.md)
- **Area:** images
- **Why:** Docker IDs and installed CodeQL runtimes describe one host's daemon, not a portable
  recipe. Committing these observations makes hosts overwrite each other's identity bindings.
- **Scope:** ignored `deploy/dagster/host-pins.toml`, generated by `update-image-pins`, carries observed
  IDs and explicit CodeQL preinstalled runtime declarations. The typed loader applies it before
  validation; gate, signer, preflight and executors consume the effective configuration. Runs freeze
  its bytes and identity. Readiness makes no pin commit; recipe tags and asset payload hashes stay
  committed. Manual build fixtures use host bindings rather than an opt-in temporary re-pin.
  William approved a fresh c094 run after this incompatible cutover; preserve `2026-11-10-0002`,
  its frozen configuration and acceptance evidence. Do not weaken repair admission to reuse it.
- **Done when:** the focused unit differential has no new failures, an updater invocation changes no
  tracked recipe, and a fresh c094 run verifies and freezes this host's exact image bindings.
- **Refs:** `docs/tasks/2026-11-10-t051-host-local-pins.md`,
  `docs/operations/image-pin-verification.md`, `docs/operations/run-readiness.md`.

### T-052 — Decide the home of Docker-engine-touching unit tests

- **State:** open
- **Area:** testing
- **Blocks:** T-048
- **Why:** several unit-collected tests invoke a real Docker engine and skip when it or an image
  is missing, so their outcome depends on host state: `tests/test_banned_functions.py`,
  `tests/test_cpp_cert_rules.py`, `tests/test_cpp_memory_safety_rules.py`,
  `tests/test_dossier_live.py`, `tests/test_lua_game_rules.py`, `tests/test_native_sbom_image.py`,
  `tests/test_poc_live_compile.py`, `tests/test_syntax_retrieval.py`,
  `tests/test_tree_sitter_ast.py`, `tests/reporting/test_pdf_docker.py`, and
  `tests/orchestration/dagster/test_definitions.py::test_wave1_dagster_path_runs_application_graph`
  (whose `skipif` decorates the helper `_missing_catalog_images`, not the test). Tests that only
  assert `docker` argv through fakes are unit tests and out of scope. (Formerly the "Deferred work"
  section of `AGENTS.md`.)
- **Scope:** move them to an explicit integration path or replace the engine with a fake at the
  subprocess boundary. Not a merge or test gate.
- **Done when:** the unit path has no test whose result depends on a running engine.

### T-053 — Decide whether review_intake keeps its own model gate

- **State:** done (2026-11-08, docs/tasks/2026-11-08-job-pass-04-review-intake.md)
- **Area:** pipeline
- **Why:** `job_review_intake.model_preflight` repeats `job_model_connectivity`'s live provider
  check two jobs later, with one difference: an unwired check returns `NOT_APPLICABLE` and the
  intake publishes, where the connectivity gate refuses the claim. Both now call
  `verify_configured_models`, so they cannot drift again, but a review pays two provider
  round-trips and has two places to fail for one question. Found in job pass 01
  (`docs/tasks/2026-11-08-job-pass-01-model-connectivity.md`).
- **Scope:** at the intake audit decide: drop the intake preflight and have intake consume the
  connectivity handoff (it is `propagate_handoff=False` today, so that means a contract input), or
  keep it as a deliberate second check and make its unwired behaviour refuse like the gate.
- **Done when:** one of the two is implemented and `tests/test_model_preflight.py` asserts it.
  Decided: keep it. Intake's handoff must be self-contained to be reusable (pinning the
  always-execute gate would invalidate intake on every dispatch), downstream contracts declare
  intake's `model_preflight` dataset as the cited evidence, and both checks share
  `verify_configured_models`. The unwired behaviour stays `NOT_APPLICABLE`, explicit and tested
  (`tests/test_review_intake.py::test_an_unwired_check_is_recorded_as_not_applicable_not_hidden`).
- **Refs:** `src/appsec_review/jobs/job_review_intake/job.py`, `src/appsec_review/jobs/job_model_connectivity/job.py`.

### T-054 — Declare the inputs binary_evidence_indexing and artifact_indexing actually read

- **State:** open
- **Area:** pipeline
- **Why:** since the fleet "typed job input contracts" merge, `job_binary_evidence_indexing` fails
  at publication with `undeclared consumption by job_binary_evidence_indexing: job_target_catalog/handoff`
  (6 tests in `tests/test_binary_evidence_indexing.py`) and `job_artifact_indexing` fails on the
  prebuilt, buildless path with `undeclared consumption by job_artifact_indexing: job_review_intake/handoff`
  (`tests/test_target_artifact_intake.py`, 2 tests). Both jobs read a producer their `JobContract`
  does not declare. These are runtime regressions for the no-build path, not stale fixtures.
- **Scope:** add the missing `InputRequirement`s to each job's `datasets.py` contract (and
  `schedule_after` where ordering is implied), re-run the two files, and check the other
  post-merge failures for the same signature when their jobs come up in the pass. For
  `job_artifact_indexing` the intake read comes through `load_target_catalog`, which job pass 07 gave
  an `intake_target_root` keyword: a job that does not use `ScanCatalog.target_root` passes `False`
  rather than declaring an input it never reads. Part of T-057 Phase 1.
- **Done when:** the eight tests pass without weakening the undeclared-consumption check.
- **Refs:** T-047, `src/appsec_review/runtime/inputs.py`, `src/appsec_review/runtime/consume.py`.

### T-055 — Catalog gaps as records so job_target_catalog can be strict

- **State:** open
- **Area:** topology
- **Why:** `job_target_catalog` emits free-text and `{path, reason}` gaps from the inventory,
  engine discovery, unsupported-build detection and the four retrieval-index builders
  (`IndexIdentity.gaps` are strings rendered by `_gap_text`), so it stays on the legacy free-text
  list and its failures are untyped `RuntimeError`/`ValueError`s. Found in job pass 05
  (`docs/tasks/2026-11-08-job-pass-05-target-catalog.md`).
- **Scope:** `producer-gap/1` records at every catalog unit (path-scoped via
  `interchange.path_gap_records`), index coverage rows carrying the record ids rather than joined
  text, typed `CatalogError` classes, `strict_gaps=True`, and the job removed from
  `tests/test_gap_contract.py`'s legacy list. The retrieval-index schema (`retrieval-index/2`)
  must keep its shape or bump.
- **Done when:** `tests/test_target_catalog_job.py::test_configured_topology_matches_the_job`
  asserts `strict_gaps` and the legacy list shrinks by one.
- **Refs:** T-035, `src/appsec_review/jobs/job_target_catalog/job.py`, `src/appsec_review/indexing/`.

### T-056 — Build discovery test program: build points, total assignment, case matrix

- **State:** open
- **Area:** topology
- **Blocks:** T-035, T-036, T-039
- **Why:** discovery's atom is a marker file and its fallback atom is a source file; neither is a
  build point (a CMake target, a Make rule, a `.sln` project, a Cargo package, a Gradle module…),
  and a source is never a unit. Build systems nest, run in parallel over the same sources, reach
  across trees and are conditional, across languages; the code has pairwise rules for a few of
  these and no systematic positive/negative tests. Discovery decides what the buildable things are,
  so it must be the most tested piece of the review.
- **Scope:** `docs/plans/build-discovery-test-program-2026-11-08.md`: the discovery contract (a
  total, explainable assignment of every path to a unit's evidence, a source-only scope, context or
  a policy exclusion; named non-units; evidence with file and line; determinism), the
  `test/discovery/cases/<NNN>-<slug>/{tree,expect.json}` fixture layout with strict `pending`
  entries, the case matrix (A single systems and look-alikes, B nesting, C parallel systems, D
  cross-tree, E conditional, F multi-language, G scale/hostile) and the sub-items T-056.1–.7
  (harness; build points; loose sources become source-only scopes; the matrix in three tranches).
  `native_components` from job pass 05 was interim and is retired (2026-11-08). Progress: T-056.1
  done, T-056.2 done (`jobs/build_points.py`, 2026-11-08), T-056.3 done in discovery/catalog; cases
  010–120 written (73 cases) with strict `pending` entries; plan §2.1 (2026-11-08) records the
  contract decisions the first tranche raised — a root that drives members is the unit and the
  members are its build points (`drives`), parallel systems at one root both exist with a
  `capture_authority`, solution family follows the listed projects, generated trees are never
  units, the context/evidence/inert name tables, the fact vocabulary. Decision 1 landed 2026-11-08
  (members fold into the driving root: `.sln` projects, Gradle includes, Cargo/Go/npm workspace
  members, Maven modules, `add_subdirectory`/`FetchContent`/`ExternalProject_Add`, `$(MAKE) -C`,
  `subdir`, `SUBDIRS`; cross-system drives via `invokes:<tool>`/`externalNativeBuild` leave the
  driven unit standing with `driven_by`; `build-systems/4`; vocabulary in plan §2.1 item 11;
  pending 542 → 313). Decision 2 landed 2026-11-08 (Makefiles beside cmake/meson/autotools are
  read: generated → inert, wrapper → context, compiling → parallel unit; `parallel_with`,
  `capture_authority`, `generated_by`; pending → 294). Decision 3 landed 2026-11-08 (solution
  family from the listed projects, listed projects are never markers, `missing_project` unresolved
  kind, CMake build trees inert; pending → 187). Decision 4 landed 2026-11-08 (`installed_trees`:
  node_modules, Cargo/Go/Composer vendor, Pods → context; buildSrc → context; Go testdata → inert;
  pending → 164). Next: the §2.1 items 5–8 rules (context/inert names, roots that are not roots,
  interpreted scopes), then T-056.5/.6 facts.
- **Done when:** every case in the matrix has no `pending` entry and `build-systems.json` carries
  build points with evidence for every unit; the composite monorepo's xfails are re-expressed as
  `pending` entries or closed.
- **Refs:** `docs/plans/build-discovery-test-program-2026-11-08.md`, `src/appsec_review/jobs/build_discovery.py`,
  `docs/tasks/2026-11-08-job-pass-05-target-catalog.md`, T-045.

## Legacy backlog

Former `docs/TODO.md` sections, verbatim, with ids. State: open unless noted.

### T-001 — Finish OWASP acceptance beyond bounded static assessment

- Implemented: complete pinned ASVS/MASVS inventories and MASTG/Top 10 context catalogs,
  independently reviewed inventory/content/license pins; explicit qualification versus assessment;
  configured worker and fresh blinded reviewer calls; four site-bound Python static procedures;
  accepted original-evidence custody and scoped outcomes with named unresolved coverage.
- Implemented in direct and Dagster graphs: accepted classification/prioritization/code graph → security tagging/tag
  cloud → default-enabled OWASP → review data indexing/`control_evidence` → lead/hunt packages →
  red/blue/independent verifier requests. Tags route work; they do not prove controls.
- Verified offline: full-catalog publications, adverse/benign/dissent outcomes, configured caps,
  qualification isolation, projection/lead/package delivery, actual scripted review-role requests,
  original-source retrieval and indirect-proof guards. This is not live-provider efficacy.
- [x] Integrate the same enabled tagging/OWASP chain into direct CLI `start`/`resume`/`plan-resume`,
  including `--force-from` routing and rejection of disabled jobs. OWASP is enabled by default
  across all shipped profiles, with an explicit job-level opt-out.
  This closes the missing chain, not CI/post-build or standalone metadata-sync topology differences.
- [ ] Run authorized live-model efficacy/budget acceptance. Scripted `Infer` doubles establish
  contract behavior, not real-provider analytical quality.
- [ ] Review and implement additional language/control procedures with subject-bound acceptance.
  Complete catalog inventory is not full assessment coverage or compliance certification.
- [ ] Implement separately authorized environment-bound runtime/manual adapters;
  `MASVS-NETWORK-1` stays unsupported even when `dynamic_authorized = true`.
- [ ] Obtain independent exploit confirmation where warranted. Even elevated/ship-blocking OWASP
  hypotheses are provisional; no customer safety certification follows from this stage.

See [the current design](architecture/owasp-control-workbench.md) and
[operating limits](operations/owasp-control-assessment.md).

### T-002 — Hook up Lua game-security rule scanning

- [ ] Integrate `rules/lua-game-security/game-security.yml` into
  `job_evidence_collection`'s existing `source_sast` step using the Semgrep/OpenGrep
  images. The 20-rule pack currently supports standalone scans only.
- [ ] Add typed central configuration, Lua source applicability and accepted dispatch
  selection; verify and hash-pin the rule bundle before mounting it read-only.
  Include source, rule, configuration and tool identities in checkpoint reuse.
- [ ] Normalize and index matches as review leads with resolving source locations,
  not confirmed vulnerabilities. Preserve parser failures, unsupported dialects
  (including Luau extensions), skipped files and timeouts as explicit coverage gaps.
- [ ] Add dispatch, configuration, provenance, normalization and failure/resume tests,
  plus an end-to-end Lua fixture run through the job using both pinned scanners.
  Retain exact-match rule fixtures and verify non-Lua scans remain unchanged.
- [ ] Update the pack README and pipeline operations documentation once the hookup
  is implemented; do not describe standalone fixture coverage as pipeline acceptance.

### T-003 — Complete the Linux execution vertical before expanding platforms

Use `targets/appsec-multi-vuln` as the acceptance target until the generic execution path is
solid, repeatable, and queryable. Do not make the later Windows or large-repository work a
prerequisite for this stage.

The Linux vertical is complete only when:

- accepted static dispatches are consumed as executable `tool + build-unit` shards, while global
  scanners run once and static work remains independent of build probes;
- every successful or reused probe can dispatch a generic real build using the accepted recipe and
  exact derived image, without a repository-specific Dagster graph;
- native, Rust, Go, Java, Node/TypeScript, .NET, Python, PHP, and WASM build units publish explicit
  success, gap, or not-applicable receipts without discarding successful siblings;
- real builds retain bounded protected command provenance for compilers, assemblers, linker
  drivers, linkers, archivers, code generators, transpilers, bundlers, package builders, and
  post-link tools, plus sanitized searchable records and exact input/output identities;
- generated sources, objects, libraries, executables, bytecode, packages, debug data, link maps,
  and statically observed loader dependencies are cataloged without executing target binaries;
- the C++ AST, LLVM IR, Infer, binary, and post-build branches consume the generic native-build
  handoff instead of maintaining a separate project build path or fixed case list;
- compiled-language CodeQL traces the exact accepted clean build, interpreted-language CodeQL uses
  the accepted source snapshot, and both publish bounded database/query/SARIF identities and gaps;
- component dependencies determine build-unit ordering, while unrelated build units and analysis
  branches remain concurrent;
- unchanged recipe, dependency, image, source, tool, and query identities reuse only the valid
  checkpoints they actually cover; and
- unit tests, failure/resume tests, MCP integration tests, and a live Dagster acceptance run prove
  dispatch, execution, provenance capture, indexing, gaps, and selective reuse end to end.

Current status: the generic Linux native/CMake, Rust/Cargo, JVM Java/Kotlin (Maven, Gradle, and direct compiler), Go, manifest-declared Node/JavaScript/TypeScript, manifest-declared PHP/Composer, Linux-capable .NET SDK, and WebAssembly output-family adapters now cover
accepted dispatch validation, real build execution, protected compiler/link provenance, artifact catalogs, dependency ordering,
failure isolation, checkpoint reuse, default-image-first probing, three bounded inference-guided
dependency-image repairs, successful Dockerfile/image reuse, and dynamic C++/post-build
consumption. The Go adapter supports accepted modules/workspaces, vendor mode, package targets,
build tags, and cgo; uses the same syscall-authoritative capture boundary as native, Rust, and
.NET with its own Go-specific reconciliation (`go.capture_invocations`, successful process-exec
events only); and catalogs modules, packages, generated sources, binaries, build IDs, and sanitized
retrieval records. One parameterized contract now checks successful/failed/redacted exec,
envp/connect facts, wrapper reconciliation, malformed input, and cap/loss behavior across the three
`CapturedBuildDescriptor` families (native, Rust, .NET); adding another compiled language must
extend that descriptor contract rather than copy capture orchestration. The .NET adapter
allows declared dependency restore, catalogs MSBuild/Roslyn and
managed/native outputs, and reports Windows-only/.NET Framework units as explicit platform gaps.
The Rust adapter accepts Cargo workspaces/packages and bounded target/profile/features/lock
choices; retains rustc, linker, archiver, build-script, and proc-macro provenance; catalogs Cargo
metadata and resolve edges plus generated sources, rlib/rmeta, native libraries, binaries, and debug
metadata; and publishes sanitized build evidence without executing tests or produced programs.
Its current Docker fixture gate verifies dependency egress, standardized syscall/envp/connect
records, exact-name redaction, gitleaks findings, complete output files, Cargo dependency and
intermediate artifacts, loader facts, default plus security-extended CodeQL profiles, and truthful
zero-result SARIF. Recipe inference is a separate opt-in model gate and never contributes capture
authority. Rust compiler-native AST and IR producers remain unimplemented; tree-sitter and CodeQL
must not be described as substitutes for those missing branches.
The native adapter now uses the same syscall/envp/connect/gitleaks boundary as Rust and .NET.
Successful exec events alone establish tool provenance; compile databases and CMake link records are
exact-match enrichment only. Docker-backed fixture acceptance covers complete streams,
compiler/linker/archiver provenance, compile database, objects, static library, executable, split
debug data, link map, loader facts, Clang AST, LLVM IR, secret removal, and raw-trace cleanup. This
lower-level acceptance has not been promoted to a Dagster run while language work remains batched.
The Node adapter accepts npm, pnpm, and Yarn identities; allows dependency egress while denying application/test
execution; treats lifecycle scripts as sandboxed target code; and catalogs generated code, bundles,
maps, packages, and native addons with protected command/stream evidence and sanitized retrieval.
The PHP adapter accepts `composer.json` with an optional lockfile, prepares dependencies in the pinned derived image with
plugins/scripts disabled, applies explicit sandbox policy to real Composer build work, catalogs
package and dependency metadata, generated autoload/code, archives, and native extensions, and
keeps exact argv and streams out of retrieval-visible evidence.
The WebAssembly adapter consumes accepted Rust, native/Emscripten/WASI, Node/AssemblyScript, WAT,
and explicitly configured producer recipes without duplicating source discovery; catalogs modules,
components, bindings, interface/debug metadata, side modules, packages, and dependency evidence;
and never instantiates produced modules. Focused host tests cover protected stream truncation,
sanitized MCP retrieval, checkpoint reuse, tamper rejection, and sibling failure isolation. The
prior standalone WebAssembly deployment receipt predates integration into `job_language_build`
and is not acceptance evidence for the current tree. A fresh integrated Dagster run
(`d51d396c-4f0f-4386-a503-859b399f1449`, application run `2026-10-08-0081`) completed all 248
orchestration steps and accepted the shared language-build handoff with one native and seven JVM
successes, nine explicit .NET recipe gaps, and truthful non-selection for Go, Node, Python, PHP,
Rust, and WebAssembly. The composed retrieval manifest and an MCP query resolved sanitized JVM
class evidence while retaining the unrelated catalog build shard. Producer-positive fixture and
live-record coverage is tracked per language; a new integrated Dagster run remains required before
the Linux vertical can be closed.
The pinned cross-language CodeQL job and exact `query_codeql` MCP surface are implemented and have
fresh live acceptance on `appsec-multi-vuln`: producer Dagster run
`e596f2f0-3b47-4263-973e-e0bc0362fe5a`, application run `2026-10-09-0007`, and CodeQL attempt
`attempt_0006` completed all seven selected steps. Exact-tree verification run
`0958c6ff-907d-43fc-b82a-004243f3a573` then reused that accepted attempt and also completed all
seven selected steps. Thirty of 37 profile scopes completed real
database and query execution and published 30 normalized observations across Actions, C/C++,
Java/Kotlin, JavaScript/TypeScript, and Python. The seven Go scopes preserve explicit database and
query gaps because their exact accepted recipes download modules without compiling source; C# is
blocked by the accepted build environment, and Rust by missing accepted Cargo locks. PHP and raw
WebAssembly are explicitly not applicable. Static dispatch execution, pinned loader-dependency
parsing, broader MCP integration, and producer-positive live coverage for the remaining
language-build families are still required. Retained Dagster records describe only the revisions
and selected target recipes they captured.

Probe policy must be centrally configurable per build unit as `configure`, `selected-target`, or
`full-build`. This keeps the default test target rigorous without forcing future large repositories
through an unnecessary full probe before every instrumented or traced build.

### T-004 — Implement conditional build-capture controls

The agreed semantics and the 18-row `appsec-multi-vuln` fixture mapping are documented in
[`architecture/build-environments-and-execution-capture.md`](architecture/build-environments-and-execution-capture.md),
using nested corpus commit `7c10536389c3cfb20a27d7a6a78943267ea43b3f`. Current status:

- implemented: independent typed central controls for build execution capture and
  compiler-artifact collection with `required`, `auto`, and `disabled` values;
- implemented: canonical immutable per-run resolution and binding into handoff, job-configuration,
  and resume identities;
- implemented: one deterministic descriptor-backed applicability evaluator and canonical
  `SUCCEEDED`, `SKIPPED_NA`, `SKIPPED_POLICY`, and `GAP` processing dispositions, without another
  syscall parser or reconciliation loop;
- implemented: CodeQL's typed capability model accepts `build`, `source`, `auto`, and `disabled`,
  with one-way load-time normalization of legacy `manual`/`none` values; executor receipts retain
  `manual`/`none` after deterministic capability selection;
- implemented: parameterized schema/path/applicability coverage for every matrix row and focused
  transitions for syntax-only versus material lifecycles, mixed native facts, missing inventory,
  unsupported capability, failed processing, and incomplete evidence; and
- remaining: specialized live Kotlin, Android SDK, Composer lifecycle, phpize, mixed-language
  CodeQL, and WebAssembly toolchain acceptance. Their absence is a validation gap, not a changed
  applicability decision.

Conditional policy dispatch and dispositions are implemented. Do not describe specialized live
toolchain acceptance as complete until the remaining gates above run. Executor-level CodeQL
receipts continue to use `manual`/`none` after the canonical decision selects build/source.

### T-005 — Scale native acceptance from fixtures to a game-sized build

Advance native testing through explicit gates rather than moving directly from the synthetic
multi-language target to a full game project:

1. `appsec-multi-vuln` remains the functional acceptance target for dispatch, failure isolation,
   provenance, indexing, MCP retrieval, and selective resume across supported languages.
2. EASTL is the next native target. Use it to validate template- and header-heavy C++, custom
   allocators and containers, cross-translation-unit relationships, compile-database fidelity,
   static-library outputs, AST/IR scale, compiler-specific flags, and deduplication of findings
   emitted through many template instantiations.
3. The Unreal Engine Lyra sample project is the later game-scale target, after the required Windows
   and Unreal build capabilities are available. Use it to validate project/plugin/module/target
   discovery, UBT/UAT orchestration, generated headers and sources, C# build tooling, shader and
   asset-build provenance, native compiler/linker capture, selective configurations, traced
   CodeQL, large-index retrieval, and bounded resumption.

Externally obtained target and engine source remains under ignored `targets/` storage and is never
committed or copied wholesale into documentation, fixtures, prompts, or indexes. Retain only the
bounded derived evidence permitted by the index contract plus the source revision, acquisition
provenance, applicable capability state, and accepted run-owned artifact identities needed to
reproduce and verify a test.

### T-006 — Add Windows and large native-build coverage after the Linux acceptance gate

Once the Linux vertical above passes against `appsec-multi-vuln`, add a first-class disposable
Windows executor rather than extending Linux recipes with platform-specific exceptions.

The follow-on work should:

- bootstrap an ephemeral Windows image or VM from centrally configured, hash-identified tooling;
- make the Clang/C++ test collector host-portable by isolating the Unix-only `resource` dependency,
  preserving the existing Linux file-size-limit assertions, and adding a Windows regression test
  that proves `tests/test_cpp_index_jobs.py` and the related Clang suites collect and run rather
  than failing during import;
- support MSVC, clang-cl, MSBuild, CMake/Ninja, and UBT/UAT-style modular build orchestration;
- capture `cl`, `clang-cl`, `link`, `lib`, `rc`, `cvtres`, `midl`, shader compilers, code generators,
  signing tools, and other build-time compiler/transpiler actions through the same protected
  provenance contract used on Linux;
- wrap the exact accepted Windows build for compiled-language CodeQL database creation when the
  required pinned assets and runtime capability are available;
- inventory installed compiler, SDK, build-system, extractor, and query-pack versions and hashes
  without copying redistributable tool payloads into this repository or run indexes;
- shard large repositories by component, module, plugin, target, platform, configuration, and
  dependency topology instead of producing project-named horizontal Dagster graphs;
- allow selective target/configuration matrices and centrally bounded concurrency, storage, and
  time budgets; and
- validate the executor with synthetic fixtures first, then representative larger native projects,
  while preserving gaps for unsupported platform or toolchain combinations.

### T-007 — Add Android, iOS, and Unity application coverage

After the Linux execution vertical is accepted, extend the same discovery, recipe, provenance,
artifact, indexing, and gap contracts to mobile applications and Unity projects. Keep source-only
analysis useful before the corresponding platform build executor is available.

Android work should:

- discover Gradle/Android Gradle Plugin projects, modules, variants, manifests, resources, Java,
  Kotlin, JNI/NDK, native libraries, dependency catalogs, signing configuration references, and
  generated sources without retaining signing secrets;
- run selected source scanners, including the existing pinned `tool-mobsfscan` lane, before a build
  is available;
- build accepted variants in a pinned Linux Android SDK/NDK/JDK image, capture Gradle, Java/Kotlin,
  native compiler/linker, resource, DEX, packaging, and signing-tool provenance, and retain APK/AAB,
  mapping, symbol, manifest, SBOM, and native-library artifacts;
- add bounded APK/AAB MobSF artifact analysis when a reviewed full MobSF runtime is available; and
- correlate mobile, JVM, native, dependency, manifest, exported-component, permission, and binary
  observations through shared component and source identities.

iOS work should:

- discover Xcode projects/workspaces, schemes, targets, Swift packages, CocoaPods, Objective-C,
  Swift, C/C++, entitlements, privacy manifests, resources, frameworks, and extensions;
- keep source scanning and configuration assessment available on non-macOS workers;
- use an ephemeral, centrally configured macOS executor for accepted `xcodebuild`, Clang, Swift,
  linker, asset compiler, interface builder, package, archive, and codesign-metadata capture;
- retain bounded IPA/app/framework, symbol, dependency, entitlement, privacy, and signing-metadata
  evidence without retaining signing credentials or executing the application; and
- publish an explicit platform gap when the required macOS/Xcode capability is unavailable.

Unity work should:

- recognize projects from `Assets`, `Packages`, `ProjectSettings`, assembly definitions, package
  manifests, scripting backend, platform targets, plugins, native libraries, and recorded editor
  version;
- statically analyze C#, shaders, scripts, configuration, packages, managed assemblies, native
  plugins, and IL2CPP-generated C++ when those artifacts already exist;
- capture Unity batch-build, compiler, linker, shader compiler, asset pipeline, managed assembly,
  IL2CPP, packaging, and platform-tool invocations through the generic protected provenance model;
- shard evidence by project, assembly, package, scene, plugin, platform, configuration, and build
  target without exposing project assets to inference unnecessarily; and
- require a centrally configured licensed Unity runtime for builds. If that capability is absent,
  publish a named build-coverage gap while continuing source, package, configuration, and available
  artifact analysis.

Acceptance requires synthetic Android, iOS, and Unity fixtures; failure/resume and unavailable-
platform tests; bounded MobSF/MobSFScan integration tests; and live Dagster runs on workers that
actually provide each enabled platform capability.

### T-008 — Close the SEI CERT rule-pack execution and coverage gaps

The pack (`rules/sei-cert/`) validates and evaluates cleanly under Semgrep 1.178.0 and OpenGrep
1.30.2 on fixtures and on `appsec-multi-vuln`, but these remain open:

- build and smoke-test the new `tool-opengrep` image and run one live evidence-collection
  acceptance with both engines; the image definition was validated statically only;
- verify the Sigstore signature that OpenGrep publishes for its release binary;
- verify live resolution of the canonical CERT URLs, which were derived from the official
  repository's content paths;
- run the Dagster definition tests with the new `opengrep_*` evidence tasks;
- re-read the drafted summaries and analysis classes of unimplemented entries against their
  official pages before promoting them, starting with entries flagged `pattern_candidate`;
- add Kotlin and Android-manifest analysis only after an applicable official rule and a capable
  engine exist; both are currently explicit gaps.

### T-009 — Add `grype_db_sync` to `job_third_party_data_sync`

The archived pre-refactor tree was inspected for a reusable Grype database. It contains a Grype
executable archive and image/build records, but no database snapshot with a verifiable database
schema version, listing metadata, content hashes, source provenance, or freshness identity. Those
bytes are therefore not a usable database snapshot and were not copied.

Future work should add an independent `grype_db_sync` step to `job_third_party_data_sync`, alongside
the NVD, OSV, and MITRE branches. It must use Grype's supported database update mechanism, record the
Grype tool/image identity and upstream database schema/build identity, enforce download and
extraction bounds, hash every published file, validate the database with the pinned Grype version,
publish immutably with a last-known-good pointer, and expose a bounded lookup/consumer interface.
The step must fail truthfully when provenance, validation, or freshness cannot be established.

### T-010 — Optimize produced-artifact Grype without reducing coverage

Future artifact Grype work must deduplicate accepted artifacts by content hash and cache only by
artifact hash plus exact Grype image, vulnerability-database digest, and policy identity. It should
reuse hash-verified accepted SBOMs, filter unsupported formats before launch, and use bounded
concurrency with partitioned resumability. Telemetry must report artifact/byte throughput, avoided
launches, and saved work. Acceptance tests must prove that deduplication, filtering, cache reuse,
resume, and sibling failure cannot suppress expected coverage or convert any gap into a clean result.

### T-011 — Summarize installed dependencies for the remaining ecosystems

Only npm installed trees are summarized from the package manager's own installer record (see
[installed npm dependencies](operations/language-build.md)). In other ecosystems, a recipe-run
install that writes dependency files into the workspace still produces per-file target rows.
Extend the same contract one ecosystem at a time. Scope must come only from the installer record,
verified against the installed package. The new rows go to the supply_chain lane as
`runtime_dependency` or `build_dependency`, with named gaps for unavailable records and unverified
packages. Order, from
[the design's deferred ecosystems](reviews/dependency-output-filtering-design.md#d1-scope-of-the-first-implementation):

1. Go (next): `vendor/modules.txt` written by a recipe's `go mod vendor`.
2. PHP Composer: `vendor/composer/installed.json`; also move `composer_metadata` production packages
   from `unknown` to `runtime_dependency`.
3. .NET: `obj/project.assets.json` for package assemblies copied into `bin/`.
4. Rust: the receipt's `cargo_metadata` package sources for registry crates' `target/*/deps`
   libraries; measure the volume first.
5. pnpm and Yarn (classic and berry): their own install state, for example `node_modules/.pnpm`.
6. Python: `*.dist-info/RECORD` for an in-workspace virtual environment.
7. JVM: dependency jars copied into `target/` or `build/`. These need their own delivery decision,
   because in a WAR they really are shipped.

Until then, an operator can name such a tree in a `[[build_outputs.exclusions]]` rule (see
[native build-output discovery](architecture/native-build-output-discovery.md#configuration)). The
walk then counts its files under `configured_exclusions` instead of listing them, so the tree gets
no per-file review and no supply-chain rows.

### T-012 — Follow-ups from the scanner launch reduction

The [scanner launch reduction](reviews/scanner-launch-reduction-design.md#6-resolved-decisions-and-open-questions)
scans each npm installer record once with Syft, Grype and osv-scanner in place of per-package Syft
and Grype launches. Its open questions:

1. Every artifact-security scan logs `CHECKPOINT_MISSED reason=missing_release_identity` when the
   review policy has no release identity for its components, so a retry repeats completed scans.
   On a retry, that costs more than the launches the reduction removed.
2. Root, workspace and unverified-package `package.json` rows still get one Syft and one Grype
   launch each, which finds nothing for the same cataloger reason. They are few per unit.
3. Decide whether target-intake `package-lock.json` inputs should also get
   `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true`. Today only installer-record launches set it.
4. Feeding Grype the Syft SBOM (`sbom:`) instead of a `file:` source would match npm dev entries
   too and save Grype's own cataloging (see
   [Optimize produced-artifact Grype](#optimize-produced-artifact-grype-without-reducing-coverage)).
5. Installer records for the other ecosystems, Go next: see
   [Summarize installed dependencies for the remaining ecosystems](#summarize-installed-dependencies-for-the-remaining-ecosystems).
6. Run scanner launches in parallel.

### T-013 — Match OSV advisories against the snapshot's own index

Match OSV advisories against the snapshot's own index/osv.sqlite so memory scales with a project's
dependencies, not the ecosystem database size. osv-scanner 1.9.2's `--experimental-offline` mode
loads each needed ecosystem's whole `all.zip` into memory: npm.zip is 208 MB compressed, 368 MB of
JSON, 230k advisories, and a single npm project alone was measured peaking at 2.2 GB or more. The
live run 2026-10-16-0004 was OOM-killed at the uniform 1g scanner limit. Evidence collection now
runs one invocation per project and raises only osv-scanner's limit (`osv_memory`, default `3g`),
which bounds the blast radius but still pays the full ecosystem cost per launch. Extracting package
versions with osv-scanner (or the catalog) and looking them up in the indexed snapshot would make
the cost proportional to the dependencies actually present.

### T-014 — Measure and extend seeded CodeQL neighborhoods

Design: `docs/architecture/seeded-codeql-neighborhoods.md`. Remaining after the first
implementation:

- measure seeded versus whole-program export time on a 20k-100k LOC project, and tune the default
  `seed_depth` and `seed_limit` from the numbers;
- measure one batched `codeql database run-queries` over all queries against serial runs;
- make `scripts/compile-codeql-queries.sh` a routine step of the host image procedure after a
  CodeQL image rebuild (it fills the shared compile cache review runs mount, keyed by the declared
  CodeQL release, so no run compiles cold; see `docs/operations/codeql-analysis.md`; the analyze
  query suites ship precompiled `.qlx` and must not be warmed), and make the live
  CodeQL tests opt-in;
- measure the seeded packs for Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Go, C# and Rust
  (they use the same two external predicates, `exportScope` and `exportSeed`);
- profile the slow `job_evidence_collection` tests.

### T-015 — Validate and measure dataflow-bounded package slices

Design: `docs/architecture/dataflow-bounded-slices.md`. Remaining work:

- run the dataflow-bound assertion in `tests/integration/test_code_graph_end_to_end.py`, which has
  not been run yet;
- measure how much package and view context shrinks on a live review compared with the call-depth
  bound, and whether findings are lost (LLMxCPG reports 68–91% less context).

Done: a real compiler, SVF and tree-sitter fixture now drives every strategy end to end
(`tests/review/test_slicing_end_to_end.py`), and the `AcceptedSliceSources` facade has its own tests.
Function spans are resolved from tree-sitter rows, then graph symbol headers, then per-language text
rules, with a named gap when none applies. The view and the manifest are validated at run time
against `docs/schemas/review-package-view.schema.json` and
`docs/schemas/review-package-manifest.schema.json`.

### T-016 — Measure and extend seeded Clang neighborhoods

Design: `docs/architecture/seeded-neighborhoods.md`. The Clang AST/LLVM IR, Clang-Tidy/Static
Analyzer and (enabled-only) CPG producers run from the findings outward and publish through the
`graph` index. Remaining after the first implementation:

- measure seeded versus whole-program wall time on a 20k-100k LOC project, then tune `seeded_bounds`
  and `seed_depth`. The opt-in live tests (`tests/live/test_seeded_clang_live.py`) now run the real
  containers on the 12-unit fixture and on a small defective file (numbers in
  `docs/architecture/seeded-neighborhoods.md` section 12), but not at scale;
- cross-TU callers in translation units that were not replayed appear only as the standing
  `frontier` gap; extend the unit selection if the measurements show it matters;
- `--exclude-regex` is unverified against a live c2cpg at scale;
- `joern-cpg` rows still reach the graph index only as `producer_neighborhood` `cpg` rows, and the
  seeded CPG shard carries the generic `JOERN_GAP` wording (`jobs/job_cpg_analysis/job.py`; asserted
  in `tests/test_joern_tool.py`, which must keep "no CPG coverage is claimed");
- the `JOERN_CPG` call-site input to the graph cross-check is not wired: add it to
  `SECONDARY_KINDS` / `CrossCheckInputs` in `graph/crosscheck.py` (and `assign_secondary`) before
  claiming a third opinion on call sites;
- workflow consumers that should read seeded Clang facts but do not yet. Analyzer-only `sink_site`
  facts (inexact, `analyzer_only`) already flow into hunt-package `unit_context` through the graph
  families; everything else below is unread:
  - `job_review_prioritization` ranking: diagnostic density and guard/dominance facts per file
    (`jobs/job_review_prioritization/semantic.py`, `rules.py`, `scoring.py`, plus a new basis term in
    the basis taxonomy);
  - hunt-unit construction: clangd callers/callees to widen a unit (`review/packages.py` unit
    building, `GraphContext.unit_context`);
  - review scoring: analyzer severity and trace length as a signal (`review/scoring/factors.py`,
    `risk_model.py`);
  - package flow context: `ir_entity` flow rows are not in `_GRAPH_KINDS` or `GRAPH_ROLES`
    (`review/packages.py`), so `GraphContext.lead_context` cannot cite them; this needs the package
    schema extended;
- already wired, with no change: review source-SAST selection reads the `job_clang_static_analysis`
  observation shard (now the seeded subset, with its gaps), and package assembly reads the `graph`
  families per scope.

### T-017 — Close the remaining CodeQL platform and accepted-build gaps

Cross-language CodeQL uses operator-declared releases for supplied offline extractors and query packs, exact protected
compiled-build replay, source/no-build analysis, bounded SARIF normalization, independent
database/query checkpoints, and accepted MCP retrieval. The pinned `audit-buildenv-dotnet` image
now backs the `dotnet` profile, and the accepted .NET fixture run recorded in
[`operations/language-build.md`](operations/language-build.md) created a C# database with both
suites. Remaining work is deliberately narrower: accepted Cargo locks and analyzer prerequisites
for Rust, a pinned Bundler execution lane for Ruby package lifecycles, and Go recipes that perform
the real accepted compilation rather than dependency download alone. Visual Basic, F#, and Swift
remain explicit unsupported-platform gaps (Swift execution is also gated off by
`tools.enable_swift`; see [`operations/swift-execution-policy.md`](operations/swift-execution-policy.md)).
Preserve the
current selective invalidation boundary: query-pack changes must not rebuild Clang AST, LLVM IR,
or an otherwise reusable CodeQL database.

### T-018 — Make CodeQL database throughput tunable end to end

Run `2026-10-16-0004` (WSL host, 24 CPUs, 16 GB shared WSL limit) built 13 of 55 database scopes in
about 20 minutes. `concurrency = 2`, `threads = 2` and `ram_mb = 4096` are already configurable,
but at most two builds overlapped, and only briefly. Gaps of up to 7 minutes passed between
`TOOL_INVOCATION_STARTED` events with no CodeQL container running, apparently preparing the next
scope. That historical observation is not a current resource reservation or a matched benchmark.
The ready-work coordinator now uses `settings.concurrency` for active CodeQL actions, with
correlated preparation and queue/admission spans and cross-process resource reservations.
Database completion releases that scope's query/export work without waiting for every database.
Container memory, host staging, CPU and I/O reservations remain aggregate constraints: the
checked-in 10,240 MiB/one-I/O-slot defaults cannot overlap two ordinary 4,096 MiB actions.
See [performance and assurance](operations/performance-assurance.md) for sizing and custody.

Remaining acceptance: repeated equal-coverage performance measurements, real host enforcement
and eligible-overlap evidence, and separately authorized rollout. Fake scheduler/admission tests
do not establish production headroom. Required derived images also need a commissioned bounded
builder; missing preparation must not be treated as an acceptable coverage reduction.

The registered [native operator](../deploy/dagster/native/README.md) now has fake end-to-end
coverage through supervisor, simulated Dagster child, common launch, restricted broker and
owned-container cleanup. A shared builder/tool sequence covers derived-image visibility,
stopped-container exclusion and next-build admission after removal. Real installed-release
custody, exclusive PostgreSQL ownership, engine/cgroup enforcement and complete persistent
1-CPU/512-MiB baseline fit remain unproved. The prepared 9-CPU/12-GiB/one-I/O-slot contract is
not activated; commissioning and a subsequent strict third-party review are separate decisions.

Latest equal-semantic fixture medians were 23.176 seconds strict and 27.239 seconds managed
(17.529% slower), with unchanged resolving evidence and 99 gaps. The performance goal is unmet,
not a demonstrated gain. Historical overhead and real CodeQL non-regression gates remain
unestablished; later custody/native changes are unbenchmarked. Keep strict as the default and
follow the [rollback contract](operations/performance-assurance.md#metrics-and-comparison)
without restoring supplied-platform scans or rewriting frozen runs.

### T-019 — Define and test the CodeQL checkpoint identity matrix

Maintain the matrix of identity inputs against the derived image, database, query, normalization,
index, and publication checkpoints. It covers declared CodeQL and extractor releases, source
bytes, accepted build recipes and replay commands, compiler/toolchain identities, base and derived
image identities, runtime policy and resource limits, query packs and suites, custom queries,
normalizer versions, and output schemas. For each change, state the smallest affected scope and
whether the expected action is reuse, database rebuild, query-only rerun, renormalization, or
republication.

Separate semantic execution inputs from provenance-only representation. A changed recipe or
target-owned build instructions that resolve to a different compiler, toolchain, filesystem,
runtime policy, or output image must invalidate dependent work. Supplied platform Dockerfiles,
source and image payloads are not fingerprinted: changed platform material requires an updated
operator release declaration, and missing declarations disable reuse rather than trigger hashing.
Provenance-only representation changes retain their original/current attribution without forcing
unrelated databases or queries to rerun.
Back the matrix with table-driven tests that change one dimension at a time and prove both required
invalidation and required reuse across unrelated languages, projects, scopes, and query profiles.

The explicit first-party predecessor path now accepts selected DB-only detached copies into a
new run under both frozen configurations and operator tenant/project authorization. Fake
`JobRunner` execute/finalize acceptance demonstrates new query declarations without new database
launches, then query reuse; mismatched material, source claims and optional handoff run bindings
fail. No prior queries, exports or guidance are imported. Retained real-run imports, performance
gates and deployment remain separately blocked; the fixture result is not live commissioning.

### T-020 — Graph modes: aliases, slices, type layouts, buffer bounds, sink CFG context

Design: [`architecture/graph-alias-slice-layout-modes.md`](architecture/graph-alias-slice-layout-modes.md)
(proposed, not implemented). Chunks G0 to G7 and GC there; G4 depends on the SVF producer chunks S0 to S4
in [`architecture/svf-alias-producer.md`](architecture/svf-alias-producer.md) and on K1.

- G0 contract: five families and modes, vocabularies, identities, `GraphSettings` bounds.
- GC catalog revision 2 (R-UAF `memory_free` sink class, R-OOB-R `memory_read` entries); lands
  after G0 and before G3.
- G1 `Slices.ql` and the `program_slice` normalizer (data, control and summary edges; `on_paths`
  join; `frontier` and `declaration_without_initializer` nodes).
- G2 `TypeLayouts.ql`, `BufferBounds.ql`, the `layouts` branch of `job_cpp_compiled_analysis`
  (`-fdump-record-layouts-simple`) and `graph-cross-check/4`.
- G3 `ControlFlow.ql` as the internal `control_flow` family and `sink_site.result.cfg_context`
  (`graph-normalize/2`); no model-facing CFG mode.
- G4 `aliases` mode over republished `points_to_set` records, source-operand queries in the SVF job.
- G5 retrieval modes, schema mirror, scoped-adapter tests; G6 integration, live counts, docs truth-up.
- G7 `buffer_bound` package context role for lane A memory leads (v5 package schema), after G6's
  live counts.

Catalog and scanner follow-ups from
[`reviews/detector-coverage-checklist.md`](reviews/detector-coverage-checklist.md) not covered by
GC (R-INT `integer_conversion` entries, R-TOCTOU `path_check` and the `toctou_candidate` join,
R-CSA checker names on clang 18, R-CERT pack extraction, R-LIVE recording of the expanded upstream suite and Infer/CSA issue types).

### T-021 — Joern bounded export and acceptance

**Deprecated (2026-10-12).** Joern is off by default (`jobs.job_cpg_analysis.settings.enabled =
false`). CodeQL is the code-graph producer, with Clang/LLVM cross-checks; see "Why Joern is
deprecated" in `docs/architecture/code-graph-precomputation.md`. The items below are kept for
reference only and are not planned.

Done:

- the pinned, reviewed, offline Joern/c2cpg runtime closure (`tool-joern`);
- the independent `job_cpg_analysis`, which runs c2cpg per accepted C/C++ scope over the exact
  accepted compile commands and retains each CPG as hash-identified, run-owned evidence;
- the `noexec` `/tmp` zstd JNI fix in the image.

Also done: the seeded job runs c2cpg on the seeded units only and a bounded `joern-export --repr all
--format neo4jcsv` (`jobs/job_cpg_analysis/export.py`), so the seeded shard carries real function
observations (a live run on the fixture exported 6 functions). The whole-program shard is still
`BLOCKED` with zero observations. Remaining work:

- a bounded whole-program CPG/PDG exporter;
- the index contract and source mapping beyond the seeded `cpg` rows;
- slicing;
- exporter security probes;
- live functional fixtures at scale.

Also resolve the per-tool resource profile
(Joern needs far more than 1 GiB at scale) and license attribution for JARs without embedded
metadata. Do not put the full CPG into MCP responses.

### T-022 — Evaluate additional Joern language frontends

The pinned `v4.0.630` archive is verified whole, but `tool-joern` installs only the core and
`c2cpg`. The other thirteen frontend directories are excluded until a job needs them: `javasrc2cpg`,
`jimple2cpg`, `kotlin2cpg`, `jssrc2cpg`, `pysrc2cpg`, `php2cpg`, `rubysrc2cpg`, `gosrc2cpg`,
`csharpsrc2cpg`, `swiftsrc2cpg`, `rust2cpg`, `abap2cpg`, and `ghidra2cpg`. For each language that a
job will consume:

1. State the job and coverage the frontend serves, and why CodeQL or an existing producer does not
   already cover it.
2. Review the frontend's added JARs and any native AST generator, recording provenance, licenses,
   and advisories in `containers/tools/joern/LICENSE.md`. The native AST generators are
   `astgen-linux`, `SwiftAstGen-linux`, `goastgen-linux`, `dotnetastgen-linux`,
   `rust_ast_gen-linux`, and `abapgen-linux`; `php2cpg` also bundles a PHP parser `.phar`.
3. Prove that native AST generators and any interpreter dependency, such as a PHP runtime, run
   offline as uid 10001 under the read-only, no-network, drop-all policy without writing outside
   scratch.
4. Add the paths to `[closure].include` in `containers/tools/joern/tool.toml`, regenerate
   `inventory.json`, and update `tests/test_joern_tool.py`, which currently asserts that no other
   frontend or ELF binary is installed.
5. Add bounded-export fixtures and keep each language's coverage `unavailable` until they pass.

Do not enable all frontends wholesale: that adds about 2 GB and six unreviewed native binaries.
`ghidra2cpg` is binary analysis and belongs with the binary-analysis decomposition decision, not
source CPG coverage.

### T-023 — Scale the clangd symbol index

Done: the pinned `tool-clangd-indexer` closure, and the independent `job_cpp_symbol_index`. Per
accepted C/C++ scope it runs clangd-indexer over the exact accepted compile commands. It then
normalizes symbols with exact source locations, and aggregated call/reference edges between
accepted symbols, into `analysis` shards with per-scope coverage and verified checkpoints. A live
run against the real image indexed the fixture completely. Remaining work:

- content-keyed, bounded TU batches with per-TU checkpoints, so Unreal-scale scopes fit the tool
  output bound (index output above it is currently a named truncation gap);
- symbols declared only in headers outside the accepted sources (SDK, engine, system) are counted,
  not indexed; decide how header-only symbols are emitted once across scopes;
- mount licensed MSVC and Windows SDK headers read-only for clang-cl commands;
- a reviewed per-tool resource profile for large compilation databases.

Resolve the open items in `containers/tools/clangd-indexer/LICENSE.md` first: confirming the LLVM
source ref, and an advisory match for the LLVM binary.

### T-024 — Replace the Python build-capture tool wrapper with a static Go binary

`containers/build-capture/tool-wrapper.py` runs for every `PATH`-resolved build tool (cc, c++, ld,
ar, ninja, cmake and others). Measured cost, inside the executor's container boundary with
`--seccomp-bpf` capture:

- about 40 ms per call;
- 45 calls added about 1.8 s to a 0.65 s fixture build;
- about +9 s (+49%) on an 18 s zstd build.

At AAA scale (tens of thousands of compiler and linker calls) that is tens of CPU-minutes per
build. The wrapper also forces `python3` into every build image.

1. First confirm the wrapper still earns its place. strace already records every exec's argv,
   resolved executable and environment authoritatively. The wrapper's unique outputs are per-tool
   stdout/stderr and tool-call records, which reconciliation treats as optional secondary
   evidence. It also misses compilers invoked by absolute path, which Unreal's build tool does.
2. If it stays, reimplement it as a static Go binary (`CGO_ENABLED=0`) with byte-identical
   behaviour:
   - call ordinal locking and the call limit;
   - per-call record, stdout/stderr retention and envp redaction;
   - `exec` of the real tool.
3. Build it offline from a pinned Go toolchain image with locked modules (standard library only,
   if possible). Install it through the capture assets; never commit a binary.
4. Keep the tool-call record schema stable, and bump the capture identities so that changed
   captures invalidate build checkpoints.
5. Re-run the capture benchmark (plain, wrapped, captured) and record per-call cost before and
   after.

### T-025 — Prove and extend the dataflow lane; build the contract and deployment lanes

The planned `query_dataflow` tool and `job_dataflow_summary`/`job_reachability_linking` jobs are
superseded by `query_code_graph`, the `job_codeql_analysis` export step and `job_code_graph_index`
([`architecture/code-graph-precomputation.md`](architecture/code-graph-precomputation.md)). For
C/C++ that lane is built end to end: `dataflow_path`, `entry_point`, `guard_fact`, `range_fact` and
`flow_summary` facts reach packages, admissibility and scoring. Remaining:

1. Run the operator live tier on the review host with the pinned CodeQL image:
   `python -m pytest -q tests/live/test_codeql_graph_export_live.py tests/live/test_code_graph_live.py`.
   The native exports under `tests/fixtures/graph/codeql_export/native/exports/` are a live
   recording (real BQRS hashes, cpp pack tree `93b9a8bf`). `test_code_graph_live.py` has no
   recorded run. The native fixture has no sources or sinks, so only the synthetic test proves the
   dataflow families.
2. Export packs, catalog sections and recorded fixtures exist for Java/Kotlin,
   JavaScript/TypeScript, Python, Ruby, Go, C#, Rust and deferred Swift, and every pack except
   Swift is pinned and has compiled and run in the pinned image (per-language status in
   [`architecture/code-graph-precomputation.md`](architecture/code-graph-precomputation.md)
   section 8). Multilingual normalization, native-only secondary scoping and worker neighborhood
   retrieval are wired. Open named gaps:
   - no live result is recorded in the repository for the C# (`dotnet`) and
     JavaScript/TypeScript (`node`) graph-export tiers;
   - Swift is disabled: CodeQL extracts Swift only on macOS, so it needs a macOS executor;
   - PHP has no CodeQL extractor;
   - Rust `known_gaps`: `rust_summarized_body_prunes_remote_flow` and
     `rust_canonicalize_summary_does_not_propagate`; Rust closure calls are `unresolved_indirect`;
   - sinks the packs export but the catalog leaves unclassified (never `direct_eligible`): C/C++
     `RemoteFlowSinkFunction` (deliberate), Swift `PredicateInjectionSink`, Python
     `NoSqlExecution`, Ruby `HttpResponse` and Go `UnmarshalingFunction`;
   - `range_fact` is `not_applicable` for JavaScript/TypeScript, Python, Ruby and Rust, and
     intraprocedural for Java and Go;
   - no live acceptance record of a real target; keep recorded acceptance distinct from live
     acceptance.
3. Implement the contract and deployment lanes planned in
   [`architecture/evidence-sources-and-dataflow-retrieval.md`](architecture/evidence-sources-and-dataflow-retrieval.md).
4. CodeQL execution telemetry caveats: analyze runtimes (by query path) and result counts (by
   rule id) are not joined; compile cache hits report no time; an exception escaping after an
   action's `COMPLETED` event counts that action twice; and a runtime with a runner older than
   `appsec-codeql-runner-89568569` reports no analyze query timings
   ([`operations/codeql-analysis.md`](operations/codeql-analysis.md#execution-telemetry)).

Unresolved indirect calls, unmodeled externals, and path/depth limits must be published as gaps.

### T-026 — Acquire dynamic execution evidence

Hash-verified import is now implemented for LCOV, Cobertura, JaCoCo, and LLVM coverage JSON, and
for textual folded-stack, perf-script, Callgrind, and LLVM sample profiles. Those producers ingest
artifacts already retained by accepted builds; they do not execute tests or profilers. Live
coverage/profile generation, sanitizer logs, fuzz corpora, and IAST traces are not yet available.
Define a separately authorized, isolated execution job before producing them. Positive traces may
support reachability; zero coverage is a gap and never refutes a claim.

### T-027 — Add Perforce history to source history analysis

`job_source_history_analysis` implements local Git and optional GitHub enrichment only. Perforce is
designed in [`architecture/source-history-analysis.md`](architecture/source-history-analysis.md)
but not built. Implement it as a second history source behind the same signals, ranking, `history`
shard, and plan `history_priority` contract:

- export mode first: consume an operator-produced, SHA-256-pinned `p4 -ztag -Mj` bundle with no
  network or credentials in the review;
- then server mode in a pinned `tool-p4` image whose only egress is the configured `P4PORT`, with a
  pinned changelist, configured `ssl:` trust fingerprint, a ticket from an environment-variable
  secret, and target `P4CONFIG`/`P4ENVIRO`/`.p4config` ignored;
- bind every inventory file to `@N` with `p4 fstat -Ol` digests, reporting `ktext`, purged, and
  protections-hidden paths as per-path gaps;
- use `p4 describe -ds` for churn, `p4 fixes` for exact fix classification, and bounded
  `filelog -i` integration following;
- review the Helix Core CLI license before cataloging the image, and add the history identity probe
  inputs (server identity, depot scope, changelist, bundle hash) so resume reruns on any change.

### T-028 — Consider following Git submodules in source history analysis

Submodule gitlinks are currently a `submodule_history_not_followed` gap. Decide whether each
submodule should become an independent history source bound to its gitlink commit, how its signals
roll up into the parent's components, and how its own `.git` (often under the parent's
`.git/modules/`, outside the submodule path) is resolved without leaving the target root.

### T-029 — Finish deferred source history signals

- Exact security-fix classification needs an OSV index of `fixed` Git events keyed by commit id;
  extend the OSV sync index and match walked commits against it.
- Commit subjects are not indexed. Index them only after a gitleaks redaction pass, with a named gap
  when redaction is unavailable.
- Function-level history uses snapshot Tree-sitter spans, so renamed or moved functions keep their
  snapshot identity and deleted functions are not represented. Follow symbol identity across
  history if consumers need it.
- Cognitive complexity does not detect recursion. Add live grammar probes that pin the
  complexity node-type table to the locked Tree-sitter language pack.
- Add an exact-filter `query_history` MCP tool if consumers need more than `find(kind="hotspot")`.
  Blame-to-Tree-sitter function joins also exist in `job_change_context_analysis`.

### T-030 — Extend change-context analysis

`job_change_context_analysis` is implemented; see
[`architecture/change-context-analysis.md`](architecture/change-context-analysis.md). Remaining work:

- Function-level fix-on-fix events: map the parent-side blamed lines through the fix and later
  changes to snapshot function spans instead of reporting the metric unavailable at function scope.
- Function attribution only sees surviving lines in the top blamed files; consider bounded
  `log -L` per function for changes whose lines were later rewritten.
- A deployment-event adapter for common CD systems. GitLab, Gerrit, and Azure DevOps review
  exports are produced by target acquisition (see
  [`operations/target-acquisition.md`](operations/target-acquisition.md)); validate them against
  live servers.
- Component relatedness uses nesting and co-change only; add build-graph or ownership-file
  (`CODEOWNERS`) relatedness when the catalog exposes them.
- Feed the change-context ranking into `job_target_analysis_plan` once the plan can wait on
  Tree-sitter without delaying the build lane.

### T-031 — Narrow review-prioritization approximations

See [`architecture/review-prioritization.md`](architecture/review-prioritization.md).

- Resolve call targets (clangd symbols, CodeQL call graphs) so wrapper, sink, and recursion
  heuristics stop depending on callee names, and so indirect recursion is detected.
- Evaluate build-system include paths, tsconfig `paths`, Composer PSR-4 maps, and Cargo workspaces in
  import resolution, and count implicit same-package references.
- Diff public API and contract declarations between the snapshot and its mainline parent instead of
  combining declarations with the history hotspot.
- Score preprocessor-conditional and macro control flow instead of reporting it as unsupported.
- Add a Python mapping and any further languages the Tree-sitter producer gains.
- Add Semgrep or CodeQL path queries for PHP, which has no CodeQL extractor today.

### T-032 — Wire binary decompilation publications into a review

Done: the pinned `tool-ghidra` image, the `[binary_decompilation]` configuration, the pre-run
`appsec-review binary-decompile` command, the verified publication store with its `current.json`
pointer and `resolve_current` lookup, and the case-083 known-binary efficacy comparison. Reviews now
consume publications: the `binary_evidence.resolve_publications` intake task with per-binary
`required`, `job_binary_evidence_indexing` (bounded `binary` shards served by the existing
retrieval and MCP tools, in the CLI graph and Dagster wave-1 topology), the registered
`binary-evidence` runtime skill with an enforced binary citation rule, PDB inputs with a
`debug_symbols_not_applied` gap, managed-code routing to a named decompiler, and a designed
binary-only target kind. See [`architecture/binary-decompilation.md`](architecture/binary-decompilation.md).

Outstanding, in order:

1. Rebuild `tool-ghidra` (it now ships `AppsecLoadDebugSymbols.java` and the wrapper's
   `--debug-symbols` option) and run a PE fixture live, with and without its PDB. Today the PE and
   PDB path is tested only with a fake Ghidra export; confirm Ghidra's PE loader and PDB analyzer
   accept the staged file and that `program.debug_symbols_loaded` is reported.
2. Measure peak container memory, wall time, publication file count and size, normalizer memory,
   and `job_binary_evidence_indexing` time and index size on a large real binary (tens of thousands
   of functions). Then tune `[binary_decompilation]` (`memory`, `max_heap`, `cpus`,
   `timeout_seconds`, `analysis_timeout_seconds`, `max_functions`, `max_strings`) and
   `[jobs.job_binary_evidence_indexing.settings]`, whose current values are provisional. This needs
   a Docker host and a licensed large binary, so it was not done.
3. Implement the binary-only target kind designed in the architecture page, including the open
   decision on the dangerous-import seed list.
4. Add a managed-code decompiler lane (ILSpy for CIL, jadx or CFR for JVM and Dalvik); today
   managed binaries are routed to a named gap only.

### T-033 — Decide how to assert correctness for large query-set jobs

`docs/processes/acceptance-and-regression-testing.md` makes each job assert that its output is the
correct response to its inputs, through `Unit.output_validators`. Four contract classes carry most
of that: schema, conservation, internal consistency, and cross-job agreement. They caught every
defect found during the 2026-10-15 bring-up without needing an oracle.

**They do not reach jobs whose output is a large, open-ended result set.** `job_codeql_analysis`
runs 117 CERT C++ queries plus the default suites; `job_evidence_collection` drives twenty
scanners. For those, "is this the correct answer?" is a question about each rule's semantics, and
no conservation or consistency property answers it. The strongest contract available today is the
weak one the pipeline already applies: a required producer that returns zero results is a coverage
gap, not a clean classification.

What needs deciding, roughly in order of expected value:

- **Per-rule corpus expectations.** `rules/sei-cert/multivuln.json` already carries
  `expected_findings`, `expected_exclusions` and `known_false_negatives` against a pinned target
  commit. That is a machine-readable oracle for the SEI CERT rule set and should be the model for
  the rest. Decide whether it is authoritative, and extend the same shape to CodeQL's own suites.
- **Rule liveness.** Assert that every enabled rule produces at least one result somewhere across
  the corpus. A rule that never fires is either dead weight or broken, and today nothing notices.
  This is cheap and would have caught the CERT suite yielding nothing at rule granularity.
- **Metamorphic pairs.** For each rule, a vulnerable snippet must yield a result and its fixed
  counterpart must not. Testable without a full oracle, and it pins rule semantics rather than
  aggregate counts. *Partly done (2026-11-02):* per weakness class rather than per rule, the
  `appsec-multi-vuln-c094-v1` key pairs seven defects with seven negative controls (CWE-121, 416, 476,
  190, 134, 78, 798), and CASTLE-C250 adds 150 defects and 100 controls; detector scoring
  (`appsec_review.acceptance.scoring`) reports per-producer TP/FP/FN/TN against them. Still open: pairs
  per enabled rule, and asserting them rather than reporting.
- **The engine's own test framework.** CodeQL ships `codeql test run` with `.qlref`/`.expected`
  files, and the upstream coding-standards repository already uses it. Query semantics probably
  belong there, not in our pipeline, with our contracts asserting only that the suite ran, resolved
  and produced accounted-for output.
- **Result envelopes rather than exact sets.** Where an exact expected set is unmaintainable, assert
  bounds (counts per rule, per family) so drift is visible without pinning every row.

This is a separate layer from the job contract, and both are required. The job contract asks
whether a job produced the declared number of correct outputs for its input. Query unit tests ask
whether a single query returns the correct rows for a known database. Neither substitutes for the
other, and conflating them is how a suite that runs but answers wrongly passes.

### T-034 — Host a dependency proxy so builds can run without external egress

Project, language and CodeQL replay builds currently need external network egress (Docker bridge)
so package managers can fetch dependencies the derived project image did not already restore:
Maven, Gradle, Go modules, npm/pnpm/Yarn, pip, NuGet, Cargo, Composer, Conan and CMake
FetchContent/ExternalProject. Until a proxy exists, every image that builds keeps that egress.
PoC generation and remediation validation rebuilds stay on --network none.

- [ ] Choose and host a caching artifact proxy (for example Artifactory or Nexus) covering those
  ecosystems, with pinned upstreams and an operator-owned allowlist.
- [ ] Point build containers at it through typed central configuration (for example GOPROXY,
  Maven/Gradle mirrors, NPM_CONFIG_REGISTRY, PIP_INDEX_URL, NuGet and Cargo sources, Conan
  remotes) rather than per-recipe settings, and record the proxy identity in build receipts.
- [ ] Then restrict build containers to an isolated network whose only egress is the proxy, and
  report any dependency the proxy could not serve as a named build gap.
