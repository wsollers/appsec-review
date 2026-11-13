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
| T-052 | [Decide the home of Docker-engine-touching unit tests](#t-052-decide-the-home-of-docker-engine-touching-unit-tests) | testing | done (2026-11-12, branch t052-docker-engine-tests; moved to tests/integration and tests/live, see Refs) |
| T-053 | [Decide whether review_intake keeps its own model gate](#t-053-decide-whether-review_intake-keeps-its-own-model-gate) | pipeline | done (2026-11-08, docs/tasks/2026-11-08-job-pass-04-review-intake.md) |
| T-054 | [Declare the inputs binary_evidence_indexing and artifact_indexing actually read](#t-054-declare-the-inputs-binary_evidence_indexing-and-artifact_indexing-actually-read) | pipeline | done (2026-11-11, 962ed773) |
| T-055 | [Catalog gaps as records so job_target_catalog can be strict](#t-055-catalog-gaps-as-records-so-job_target_catalog-can-be-strict) | topology | open |
| T-056 | [Build discovery test program: build points, total assignment, case matrix](#t-056-build-discovery-test-program-build-points-total-assignment-case-matrix) | topology | open |
| T-060 | [Track findings across revisions with a stable identity](#t-060-track-findings-across-revisions-with-a-stable-identity) | review | done (2026-11-11, docs/architecture/finding-metrics.md section 12) |
| T-061 | [Verify a fix by re-checking the prior finding](#t-061-verify-a-fix-by-re-checking-the-prior-finding) | review | in-progress |
| T-062 | [Measure triage effectiveness against answer-key labels](#t-062-measure-triage-effectiveness-against-answer-key-labels) | review | done (2026-11-11, docs/architecture/finding-metrics.md section 12) |
| T-063 | [Score the published review findings by default](#t-063-score-the-published-review-findings-by-default) | testing | done (2026-11-11, docs/architecture/finding-metrics.md section 12) |
| T-064 | [Report severity-banded actionable yield](#t-064-report-severity-banded-actionable-yield) | review | done (2026-11-11, docs/architecture/finding-metrics.md section 12) |
| T-065 | [Feed real runs into the stability experiments](#t-065-feed-real-runs-into-the-stability-experiments) | testing | done (2026-11-11, docs/architecture/finding-metrics.md section 12) |
| T-066 | [Compare quality trends across prompt model and configuration changes](#t-066-compare-quality-trends-across-prompt-model-and-configuration-changes) | testing | done (2026-11-11, docs/architecture/finding-metrics.md section 12) |
| T-067 | [Build a CVE fix-pair corpus and a private holdout](#t-067-build-a-cve-fix-pair-corpus-and-a-private-holdout) | testing | in-progress |
| T-068 | [Measure hunt-lane value and attack-surface coverage](#t-068-measure-hunt-lane-value-and-attack-surface-coverage) | review | done (2026-11-11, docs/architecture/finding-metrics.md section 12) |
| T-069 | [Ingest developer outcomes and audit dismissed leads](#t-069-ingest-developer-outcomes-and-audit-dismissed-leads) | review | done (2026-11-11, docs/architecture/finding-metrics.md section 12) |
| T-070 | [Slice findings by a game threat model](#t-070-slice-findings-by-a-game-threat-model) | review | in-progress |
| T-071 | [Measure model-specific failure rates](#t-071-measure-model-specific-failure-rates) | review | in-progress |
| T-072 | [Ingest crash reports as finding evidence](#t-072-ingest-crash-reports-as-finding-evidence) | evidence | done (2026-11-11, docs/architecture/finding-metrics.md section 12) |
| T-073 | [Derive reviewed units and entry points from a run](#t-073-derive-reviewed-units-and-entry-points-from-a-run) | review | in-progress |
| T-074 | [Wire the fix re-check to the verifier role](#t-074-wire-the-fix-re-check-to-the-verifier-role) | review | open |
| T-075 | [Run crash evidence as a job and a lane A lead family](#t-075-run-crash-evidence-as-a-job-and-a-lane-a-lead-family) | evidence | open |
| T-076 | [Record attacker position owner function and remediation on findings](#t-076-record-attacker-position-owner-function-and-remediation-on-findings) | review | open |
| T-077 | [Derive lead records with stage attribution from a run](#t-077-derive-lead-records-with-stage-attribution-from-a-run) | review | in-progress |
| T-078 | [Check the model login before a review is submitted](#t-078-check-the-model-login-before-a-review-is-submitted) | pipeline | done (2026-11-11, 2f6c5ae1) |
| T-079 | [One guarded command for run recovery](#t-079-one-guarded-command-for-run-recovery) | pipeline | done (2026-11-11, 83c81a60) |
| T-080 | [Derive default release ids and allow an overlay to override them](#t-080-derive-default-release-ids-and-allow-an-overlay-to-override-them) | pipeline | done (2026-11-11, cab4d770) |
| T-081 | [Fix the stepwise system call to review_run submit](#t-081-fix-the-stepwise-system-call-to-review_run-submit) | pipeline | done (2026-11-11, 49fa3e1a) |
| T-082 | [Check the guard order in project_build repair reuse](#t-082-check-the-guard-order-in-project_build-repair-reuse) | build | open |
| T-083 | [Classify the failing judge and budget-clock unit tests](#t-083-classify-the-failing-judge-and-budget-clock-unit-tests) | testing | open |
| T-084 | [Test language-build iteration dispatch with a ready build unit](#t-084-test-language-build-iteration-dispatch-with-a-ready-build-unit) | testing | open |
| T-085 | [Probe the model login before recovery admits a repair](#t-085-probe-the-model-login-before-recovery-admits-a-repair) | pipeline | open |
| T-086 | [Record source ids on un-hunted units and produce entry-point tags](#t-086-record-source-ids-on-un-hunted-units-and-produce-entry-point-tags) | review | open |
| T-087 | [Normalize crash symbols for corroboration](#t-087-normalize-crash-symbols-for-corroboration) | evidence | open |
| T-088 | [Keep a target registry and a read-only verify command](#t-088-keep-a-target-registry-and-a-read-only-verify-command) | testing | open |
| T-089 | [Fetch answer keys from the private answers repository in memory](#t-089-fetch-answer-keys-from-the-private-answers-repository-in-memory) | testing | open |
| T-090 | [Identify known targets and self-grade a completed run](#t-090-identify-known-targets-and-self-grade-a-completed-run) | testing | blocked |
| T-091 | [Resolve conditional automake SUBDIRS in build discovery](#t-091-resolve-conditional-automake-subdirs-in-build-discovery) | topology | done (2026-11-12, walk 05 record) |
| T-092 | [Decide whether a refused build command fails one unit or the whole language build](#t-092-decide-whether-a-refused-build-command-fails-one-unit-or-the-whole-language-build) | build | open |
| T-093 | [Bind generated Make drivers of configure-style builds to their accepted inputs](#t-093-bind-generated-make-drivers-of-configure-style-builds-to-their-accepted-inputs) | build | open |
| T-094 | [Let stepwise accept a target by commit instead of a tag](#t-094-let-stepwise-accept-a-target-by-commit-instead-of-a-tag) | testing | open |
| T-095 | [Report an intake coverage gap once, not once per unit](#t-095-report-an-intake-coverage-gap-once-not-once-per-unit) | pipeline | open |
| T-096 | [Stop inferring run artifacts from a data/ path prefix](#t-096-stop-inferring-run-artifacts-from-a-data-path-prefix) | pipeline | open |
| T-097 | [Use ChangeLog files as a source-history signal](#t-097-use-changelog-files-as-a-source-history-signal) | history | in-progress |
| T-098 | [Identify vendored third-party code in a target](#t-098-identify-vendored-third-party-code-in-a-target) | topology | blocked |
| T-099 | [Build one dependency finder with a common observation record](#t-099-build-one-dependency-finder-with-a-common-observation-record) | topology | open |
| T-100 | [Find dependencies declared in native build systems](#t-100-find-dependencies-declared-in-native-build-systems) | topology | blocked |
| T-101 | [Find dependencies in manifests and lockfiles of every recognised ecosystem](#t-101-find-dependencies-in-manifests-and-lockfiles-of-every-recognised-ecosystem) | data | blocked |
| T-102 | [Find components in built binaries with a cve-bin-tool scan adapter](#t-102-find-components-in-built-binaries-with-a-cve-bin-tool-scan-adapter) | binary | blocked |
| T-103 | [Sync the Trivy databases nightly and add a Trivy SBOM vulnerability adapter](#t-103-sync-the-trivy-databases-nightly-and-add-a-trivy-sbom-vulnerability-adapter) | data | open |
| T-104 | [Look up CPE candidates in the pinned NVD snapshot](#t-104-look-up-cpe-candidates-in-the-pinned-nvd-snapshot) | data | open |
| T-105 | [Match vulnerabilities in one stage over the merged dependency inventory](#t-105-match-vulnerabilities-in-one-stage-over-the-merged-dependency-inventory) | scanners | blocked |
| T-106 | [Restart the nightly data sync and refuse stale feeds at run readiness](#t-106-restart-the-nightly-data-sync-and-refuse-stale-feeds-at-run-readiness) | data | open |
| T-107 | [Generate a data-flow diagram and threat model from accepted run evidence](#t-107-generate-a-data-flow-diagram-and-threat-model-from-accepted-run-evidence) | review | open |
| T-108 | [Publish the static deployment inventory as a job](#t-108-publish-the-static-deployment-inventory-as-a-job) | evidence | open |
| T-109 | [Put a hard ceiling on test runs and enforce the ten-second unit limit](#t-109-put-a-hard-ceiling-on-test-runs-and-enforce-the-ten-second-unit-limit) | testing | open |
| T-110 | [Decide what the walk does with shell environment scripts the bounded reader cannot read](#t-110-decide-what-the-walk-does-with-shell-environment-scripts-the-bounded-reader-cannot-read) | build | open |
| T-111 | [Surface build-descriptor bounds as gap records and size them against real targets](#t-111-surface-build-descriptor-bounds-as-gap-records-and-size-them-against-real-targets) | build | open |
| T-112 | [Record what the analysis-summary trim removed, and do not report truncation under the bounds](#t-112-record-what-the-analysis-summary-trim-removed-and-do-not-report-truncation-under-the-bounds) | build | open |
| T-113 | [Walk every job into tests/unit with code-level tests under the enforced tier](#t-113-walk-every-job-into-testsunit-with-code-level-tests-under-the-enforced-tier) | testing | in-progress |
| T-114 | [Declare the debug-symbol decision dataset with the schema the job writes](#t-114-declare-the-debug-symbol-decision-dataset-with-the-schema-the-job-writes) | binary | open |
| T-115 | [Record code-graph live verification in fixture provenance and test it against the lock](#t-115-record-code-graph-live-verification-in-fixture-provenance-and-test-it-against-the-lock) | graph | open |
| T-116 | [Make the code-graph docs name all eight pinned export packs](#t-116-make-the-code-graph-docs-name-all-eight-pinned-export-packs) | graph | open |
| T-117 | [Fix the stale image_id comments in appsec-review.toml (not during an active walk)](#t-117-fix-the-stale-image_id-comments-in-appsec-reviewtoml-not-during-an-active-walk) | images | open |
| T-118 | [Run and record the JavaScript/TypeScript graph-export live tier](#t-118-run-and-record-the-javascripttypescript-graph-export-live-tier) | codeql | open |
| T-119 | [Run and record the C# graph-export live tier](#t-119-run-and-record-the-c-graph-export-live-tier) | codeql | open |
| T-120 | [Decide the unclassified sink models and whether html_output is the cross-site scripting class](#t-120-decide-the-unclassified-sink-models-and-whether-html_output-is-the-cross-site-scripting-class) | graph | open |
| T-121 | [Fail when a live export carries a CodeQL model with no catalog decision](#t-121-fail-when-a-live-export-carries-a-codeql-model-with-no-catalog-decision) | graph | blocked |
| T-122 | [Replace every hand-authored recording of a pinned language with its live export](#t-122-replace-every-hand-authored-recording-of-a-pinned-language-with-its-live-export) | codeql | blocked |
| T-123 | [Write the code-graph acceptance record from a live run](#t-123-write-the-code-graph-acceptance-record-from-a-live-run) | graph | blocked |
| T-124 | [Close or confirm the Rust remote-flow pruning gap](#t-124-close-or-confirm-the-rust-remote-flow-pruning-gap) | graph | open |
| T-125 | [Close or confirm the Rust canonicalize sanitizer gap](#t-125-close-or-confirm-the-rust-canonicalize-sanitizer-gap) | graph | open |
| T-126 | [Design the multi-producer plan for code-graph and dataflow facts](#t-126-design-the-multi-producer-plan-for-code-graph-and-dataflow-facts) | graph | blocked |
| T-127 | [Inventory the documentation in a disposition ledger](#t-127-inventory-the-documentation-in-a-disposition-ledger) | pipeline | done (2026-11-13, docs/docs-ledger.json) |
| T-128 | [Generate the documentation inventory and enforce frontmatter and links](#t-128-generate-the-documentation-inventory-and-enforce-frontmatter-and-links) | pipeline | open |
| T-129 | [Map tools and datasets to intelligence buckets and availability matrices](#t-129-map-tools-and-datasets-to-intelligence-buckets-and-availability-matrices) | pipeline | blocked |
| T-130 | [Author job operations pages around the generated contracts](#t-130-author-job-operations-pages-around-the-generated-contracts) | pipeline | blocked |
| T-131 | [Document the forward testing contract and its enforcement](#t-131-document-the-forward-testing-contract-and-its-enforcement) | testing | blocked |
| T-132 | [Write current-state subsystem architecture dives](#t-132-write-current-state-subsystem-architecture-dives) | pipeline | blocked |
| T-133 | [Apply approved documentation merges and retirements](#t-133-apply-approved-documentation-merges-and-retirements) | pipeline | blocked |
| T-001 | [Finish OWASP acceptance beyond bounded static assessment](#t-001-finish-owasp-acceptance-beyond-bounded-static-assessment) | scanners | open |
| T-002 | [Hook up Lua game-security rule scanning](#t-002-hook-up-lua-game-security-rule-scanning) | scanners | open |
| T-003 | [Complete the Linux execution vertical before expanding platforms](#t-003-complete-the-linux-execution-vertical-before-expanding-platforms) | build | open |
| T-004 | [Implement conditional build-capture controls](#t-004-implement-conditional-build-capture-controls) | build | open |
| T-005 | [Scale native acceptance from fixtures to a game-sized build](#t-005-scale-native-acceptance-from-fixtures-to-a-game-sized-build) | build | open |
| T-006 | [Add Windows and large native-build coverage after the Linux acceptance gate](#t-006-add-windows-and-large-native-build-coverage-after-the-linux-acceptance-gate) | windows | open |
| T-007 | [Add Android, iOS, and Unity application coverage](#t-007-add-android-ios-and-unity-application-coverage) | mobile | open |
| T-008 | [Close the SEI CERT rule-pack execution and coverage gaps](#t-008-close-the-sei-cert-rule-pack-execution-and-coverage-gaps) | scanners | open |
| T-009 | [Add `grype_db_sync` to `job_third_party_data_sync`](#t-009-add-grype_db_sync-to-job_third_party_data_sync) | data | done (2026-11-12, docs/operations/third-party-data-sync.md) |
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
- **Progress:** 2026-11-11: four stale fixtures repaired (`61a7718a`: the shared fake executor in
  `tests/capture_fakes.py` supplies compiler profiles, default-collection tests, acceptance
  inventory job list, configuration-layer assertions, judge-test fixture). The undeclared-input
  runtime regressions were T-054. Remaining, classified stale and not fixed: about 75 tests that
  build single-job graphs or hand-written run trees in `tests/test_language_build.py`,
  `tests/test_project_build.py`, `tests/test_tool_input_support.py` and
  `tests/test_native_sbom_job.py`. Unclassified judge and budget-clock failures are T-083.
  T-009 validation on 2026-11-12 also reproduced two stale release-insertion fixtures against
  clean base `60e562e0`: `test_configured_disabled_grype_never_calls_runner_and_publishes_gap`
  in `tests/test_artifact_security_analysis.py` and
  `test_job_has_explicit_dispositions_and_reuses_only_successful_tool_checkpoints` in
  `tests/test_evidence_collection_job.py` duplicate existing TOML release keys (lines 113 and 148).
  They fail before scanner behavior and remain unfixed; focused Grype consumer units cover the
  changed cache boundary separately.
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

- **State:** done (2026-11-12, branch t052-docker-engine-tests; moved to tests/integration and tests/live, see Refs)
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
- **Refs:** `tests/integration/test_banned_functions_engines.py`,
  `tests/integration/test_cpp_cert_rules_engines.py`,
  `tests/integration/test_cpp_memory_safety_rules_engines.py`,
  `tests/integration/test_lua_game_rules_engines.py`,
  `tests/integration/test_syntax_retrieval_live.py`, `tests/integration/test_tree_sitter_ast_live.py`,
  `tests/integration/test_dossier_live.py`, `tests/integration/test_poc_live_compile.py`,
  `tests/integration/test_native_sbom_image.py`, `tests/integration/test_pdf_docker.py`,
  `tests/live/test_dagster_wave1_live.py`; the tests skip there, naming the gap, without the engine
  or an image, because faking the engine would prove nothing about the rule packs and images they
  exist to check. `docs/architecture/testing.md` (unit harness, item 7).

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

- **State:** done (2026-11-11, 962ed773)
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
- **Outcome:** `962ed773` (branch commit `d4aabebe`) declared the missing inputs. The scope was
  wider than the title: review `2026-11-11-0002` failed at 13 of 42 jobs on the same signature in
  `job_evidence_collection`, `job_language_build` and `job_build_iteration`, which the commit also
  covers. The undeclared-consumption check is unchanged.
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
  pending → 164). Items 5–8 landed 2026-11-12 (context files owned by the unit of the system that
  reads them, prose and `.filters` inert, `setup.cfg`/`Makefile.am`/doc-only Makefile/tooling-only
  `package.json` look-alikes demoted, `.asmdef`/`pnpm-workspace.yaml`/root `.xcworkspacedata`
  evidence, header prerequisites and meson include dirs bind, unnamed headers follow the first
  point, every interpreted language is a source-only scope; pending → 103). Next: T-056.5/.6
  facts; the remaining matrix-A entries are Unity player targets, Xcode target sources, SwiftPM,
  and node/Python/Composer package sources (T-056.2).
- **Done when:** every case in the matrix has no `pending` entry and `build-systems.json` carries
  build points with evidence for every unit; the composite monorepo's xfails are re-expressed as
  `pending` entries or closed.
- **Refs:** `docs/plans/build-discovery-test-program-2026-11-08.md`, `src/appsec_review/jobs/build_discovery.py`,
  `docs/tasks/2026-11-08-job-pass-05-target-catalog.md`, T-045.

### T-060 — Track findings across revisions with a stable identity

- **State:** done (2026-11-11, docs/architecture/finding-metrics.md section 12)
- **Area:** review
- **Blocks:** T-061
- **Why:** nothing can say whether a previous finding was fixed. The experiments normalizer hashes
  the source revision into `root_cause_id` ("different source revisions remain different
  identities"), and no run reads a prior run's findings, so the same defect at two commits is two
  unrelated findings. Found in the 2026-11-11 metrics critique.
- **Scope:** a revision-independent finding fingerprint (CWE, normalized path, enclosing function,
  source and sink symbols, code-context hash; no commit and no line number) with exact and
  relocated match tiers, and a per-run lifecycle against a named prior run: `new`, `persisting`,
  `regressed`, `not_redetected` (absent, code unchanged), `not_covered` (the unit was not reviewed
  this run) and `fix_candidate` (absent, code changed). Absence alone never yields `fixed`; that
  state belongs to T-061. Per-changelist use reports the findings a change introduced.
- **Done when:** a unit test over two recorded finding sets of one target at two revisions assigns
  every prior finding exactly one lifecycle state, including a moved function and an uncovered
  unit, and the run-metrics summary carries the counts with null, not zero, when no prior run is
  named.
- **Refs:** `src/appsec_review/observability/experiments/contracts.py` (`root_cause_id`),
  `docs/operations/glasswing-experiments.md`, `docs/operations/metrics.md`, T-030.
  Remaining work: T-073.

### T-061 — Verify a fix by re-checking the prior finding

- **State:** in-progress
- **Area:** review
- **Blocked by:** T-067, T-074
- **Why:** open-ended discovery is not repeatable enough to treat a finding's absence as a fix, and
  `docs/operations/metrics.md` already states that no completion metric establishes a fixed finding.
- **Scope:** for each `fix_candidate` and `not_redetected` finding of T-060, one bounded
  verifier task on the new revision that is given the prior claim and its evidence and returns
  `fixed` (the guard or change is cited), `still_present`, or `insufficient_evidence`. Results are
  recorded per finding; counts by state enter the run metrics.
- **Done when:** on the fix-pair corpus of T-067 the post-fix revision yields `fixed` and the
  pre-fix revision `still_present` for the keyed defects, with the miss and false-fix counts
  reported.
- **Refs:** T-060, T-067, `src/appsec_review/jobs/job_remediation_validation/`.
  Remaining work: T-074.

### T-062 — Measure triage effectiveness against answer-key labels

- **State:** done (2026-11-11, docs/architecture/finding-metrics.md section 12)
- **Area:** review
- **Why:** `triage_reduction` measures volume only. `ratio_over_resolved` reaches 1.0 when triage
  dismisses everything, it adds `no_claim_raised` (silence) to `dismissed_by_adjudication`
  (a reasoned refutation), and no run reports how many true leads triage removed. The
  retention and removal formulas exist only in the offline experiments module.
- **Scope:** on a corpus run, label every lane A lead inside a key scope from the answer key and
  add to the section: true-lead retention, false-lead removal, the stage that removed each true
  lead (red no-proposal, blue, judge, verifier), and the share of negative controls that end
  `supported` or `confirmed`. Report the two reduced dispositions as separate ratios and stop
  presenting a combined ratio without the retention figure beside it. Without a key the labelled
  fields are null.
- **Done when:** unit tests over a recorded lane A document and key produce the labelled counts and
  per-stage attribution, and `stepwise.py system` prints them beside the funnel.
- **Refs:** `src/appsec_review/observability/triage_reduction.py`,
  `src/appsec_review/acceptance/funnel.py`, `src/appsec_review/observability/experiments/metrics.py`
  (`_triage`), `docs/operations/metrics.md`.
  Remaining work: T-077.

### T-063 — Score the published review findings by default

- **State:** done (2026-11-11, docs/architecture/finding-metrics.md section 12)
- **Area:** testing
- **Why:** detector scoring treats scanners as the subject and the final findings as an optional
  producer (`--include-review`), although the published findings are the product. The strict
  two-line match undercounts model findings that cite the missing check and not the sink, the
  CASTLE score is a composite with arbitrary weights and a Top-25 bonus that favours web weaknesses,
  and `accuracy` mixes per-report false positives with per-case true negatives.
- **Scope:** `review` scored by default, with an unavailable final report still a named gap; a
  function-scope and weakness-family match for `review` reported beside the strict match; marginal
  contribution computed on true and false positives; the CASTLE score kept only in the
  paper-reference comparison; `accuracy` removed or recomputed on cases. Schema bump of
  `appsec-review/detector-scoring/1`.
- **Done when:** `tests/test_detector_scoring.py` covers the default `review` producer, both match
  rules and the case-based rates, and the `acceptance_trend` adapter reads `review` without a flag.
- **Refs:** `src/appsec_review/acceptance/scoring.py`, `docs/reviews/castle-style-detector-scoring.md`,
  `docs/operations/acceptance-funnel.md`.

### T-064 — Report severity-banded actionable yield

- **State:** done (2026-11-11, docs/architecture/finding-metrics.md section 12)
- **Area:** review
- **Why:** no metric says how many results are worth a developer's time. `finding_states` counts
  `FINDING_TRANSITION` events, so one finding with two transitions is counted twice, and it has no
  severity, CWE or component dimension. Severity bands and ship-block status exist per finding but
  feed no metric, and answer keys carry no expected severity, so over- and under-rating cannot be
  measured.
- **Scope:** a final-state snapshot of published findings, deduplicated by root cause, by severity
  band, ship-block status, CWE family and lane; yield of confirmed high and critical findings per
  run, per reviewed KLOC and per known cost; the unrated (`decision_pending`) share; the duplicate
  rate after clustering. Optional `severity` on `[[defect]]` in `expectations.toml`, with a severity
  agreement count and precision within the high and critical band on corpus runs.
- **Done when:** the run-metrics summary carries the section with null for unavailable inputs, and a
  unit test shows a finding with several transitions counted once.
- **Refs:** `src/appsec_review/observability/telemetry.py` (`finding_states`),
  `src/appsec_review/review/ship_block.py`, `src/appsec_review/review/scoring/risk_model.py`,
  `src/appsec_review/acceptance/scoring.py`.

### T-065 — Feed real runs into the stability experiments

- **State:** done (2026-11-11, docs/architecture/finding-metrics.md section 12)
- **Area:** testing
- **Why:** run-over-run stability, pairwise stability and recurrence are implemented but
  `rebuild` reads only a hand-assembled document; the accepted-artifact adapter is still owed, so
  no real run has a stability figure. Single-run recall on a seven-defect key moves 14 points per
  defect and carries no interval.
- **Scope:** an adapter that builds launch and completion records from an accepted run at the
  candidate, verified and published stages; per-defect detection rate over repeated corpus runs
  with a binomial interval; stability of the high and critical subset; counts of root causes whose
  severity or disposition changes between comparable runs.
- **Done when:** the adapter turns recorded run fixtures into a valid
  `appsec-review/quality-experiment/1` document under unit test, and the operations doc gives the
  manual command for a five-run corpus series. The series itself is user-owned.
- **Refs:** `src/appsec_review/observability/experiments/`, `docs/operations/glasswing-experiments.md`,
  `docs/reviews/appsec-system-review-2026-11-06.md` (section 10).

### T-066 — Compare quality trends across prompt model and configuration changes

- **State:** done (2026-11-11, docs/architecture/finding-metrics.md section 12)
- **Area:** testing
- **Why:** `compare_trends` returns `incomparable` unless corpus, configuration, prompt and model
  identities are all equal, so it cannot answer whether a prompt or model change helped. The
  implementation and model identities are operator-supplied arguments, not read from the run.
- **Scope:** comparability requires the same corpus, key, scorer, role and case count; prompt, model
  and configuration identities become recorded independent variables named in the result.
  Identities are read from the run's frozen configuration and guidance bundle, and a mismatch with
  a supplied value is an error.
- **Done when:** `tests/test_operations_quality.py` compares two trends that differ only in prompt
  identity and reports the changed variable with the metric deltas.
- **Refs:** `src/appsec_review/observability/quality.py`, `docs/operations/quality-and-retention.md`.

### T-067 — Build a CVE fix-pair corpus and a private holdout

- **State:** in-progress
- **Area:** testing
- **Blocks:** T-061
- **Why:** the keyed corpora are seven seeded defects with seven controls and CASTLE-C250, which is
  public single-file C that a model may have memorised. Neither resembles a game codebase or
  exercises fix detection.
- **Scope:** pinned pairs of pre-fix and post-fix commits for published CVEs in open game and
  engine code, each with a key entry on the pre-fix revision and a control on the post-fix
  revision, held outside the target like the existing keys; a second set never used for prompt or
  guidance tuning, with its use recorded. Target acquisition and pinning stay with the user.
- **Done when:** at least ten pairs are keyed, the loader validates them, and a document lists the
  candidate projects and the licence of each.
- **Refs:** `test/acceptance/`, `src/appsec_review/acceptance/scoring.py`,
  `docs/reviews/castle-style-detector-scoring.md`, T-005. Candidates (26 verified pairs, none
  pinned or keyed yet): `docs/reviews/fix-pair-corpus-candidates.md`,
  `test/acceptance/fix-pairs-candidates/pairs.toml`.
  Shortlist and qualifications:
  [`docs/reviews/fix-pair-corpus-shortlist.md`](reviews/fix-pair-corpus-shortlist.md).

### T-068 — Measure hunt-lane value and attack-surface coverage

- **State:** done (2026-11-11, docs/architecture/finding-metrics.md section 12)
- **Area:** review
- **Why:** lane B claims are only counted as excluded from triage reduction, so nothing shows what
  the review found that no scanner flagged, which is the case for running it at all. Finding
  counts also have no denominator: nothing reports how much of the exposed surface was reviewed.
- **Scope:** per run, confirmed and supported hunt-lane findings with no scanner observation at the
  same root cause, by CWE family; and coverage of catalogued entry points (network handlers,
  parsers, RPC handlers, file loaders) as reviewed, not admitted and not built, from existing
  package and admission records. No target scan at metric time.
- **Done when:** both sections are in the run-metrics summary under unit test, with uncovered
  entry points listed by residual-coverage reason.
- **Refs:** `src/appsec_review/observability/triage_reduction.py` (`hunt_lane_claims_excluded`),
  `src/appsec_review/review/packages.py`, `docs/architecture/review-prioritization.md`.
  Remaining work: T-073.

### T-069 — Ingest developer outcomes and audit dismissed leads

- **State:** done (2026-11-11, docs/architecture/finding-metrics.md section 12)
- **Area:** review
- **Why:** on a real target the only ground truth is what the developers do with a finding, and
  nothing records it. Dismissed leads are never sampled, so the miss rate of triage on real code is
  unknown. No metric says whether a finding is complete enough to act on.
- **Scope:** an operator-supplied outcome file keyed by the T-060 fingerprint (fixed, rejected as
  false, accepted risk with expiry, duplicate), admitted as labels; fix rate, rejected rate and
  time to disposition by severity band; a reproducible random sample of dismissed and no-claim
  leads exported for human labelling, with the estimated miss rate and interval; per finding, the
  presence of a resolving entry-to-sink path, stated preconditions, an owner and a validated fix.
- **Done when:** unit tests admit an outcome file and a labelled sample and produce the rates, and
  the final report states actionability completeness per finding.
- **Refs:** T-060, `src/appsec_review/observability/experiments/contracts.py` (labels),
  `docs/operations/final-report.md`.
  Remaining work: T-076.

### T-070 — Slice findings by a game threat model

- **State:** in-progress
- **Area:** review
- **Why:** severity and every metric use a generic application matrix. A game team ranks by
  attacker position and by what it can fix, and no persona, corpus case or key entry covers the
  weaknesses specific to games.
- **Scope:** per finding, recorded attacker position (client to dedicated server, server to client,
  peer to peer, hostile content such as mods, maps, replays and save files, local), ownership
  (first-party, engine, middleware) and build configuration (shipping, development, editor), each
  null when not established; metric slices on those fields; engine and middleware findings routed
  as dependency findings. Corpus cases and review guidance for server trust in client state,
  unvalidated replication RPCs, bitstream length handling and entitlement bypass, through the
  runtime-guidance procedure.
- **Done when:** the fields are in the finding schema and report, the T-064 section slices by them,
  and at least one keyed corpus case exists per named weakness class.
- **Refs:** T-002, T-005, T-026, T-064, `pipeline/prompt-fragments/`,
  `docs/reviews/dependency-output-filtering-design.md`.
  Remaining work: T-076.

### T-071 — Measure model-specific failure rates

- **State:** in-progress
- **Area:** review
- **Why:** failures peculiar to model reviewers are not counted: citations that do not resolve to
  source, target text that addresses the reviewer, and provider-side model change under an
  unchanged configuration.
- **Scope:** per run and role, the share of claim citations that fail to resolve; a corpus case
  whose comments instruct the reviewer, with the outcome recorded; a documented scheduled canary
  series on a fixed corpus and configuration whose detection-rate change flags drift. The canary
  runs are user-owned.
- **Done when:** the citation-resolution rate is in the run-metrics summary under unit test, the
  injection case is keyed, and the operations doc gives the canary command.
- **Refs:** T-065, `src/appsec_review/review/evidence.py`, `pipeline/prompt-fragments/governing-rules.md`.

### T-072 — Ingest crash reports as finding evidence

- **State:** done (2026-11-11, docs/architecture/finding-metrics.md section 12)
- **Area:** evidence
- **Why:** a game team's crash reports are independent evidence that a defect is real and
  reachable, and memory-safety crashes with no finding are the nearest thing to a recall measure
  on a real target. Nothing ingests them.
- **Scope:** `job_crash_evidence_ingestion` over an operator-exported directory, with no network
  access and no raw dump retained: pluggable adapters to `appsec-review/crash-report/1`
  (first tranche `stackwalk_json`, `sanitizer_report`, `sentry_event`; then
  `unreal_crash_context` and raw `minidump` walked in a pinned tool container), build, revision
  and symbol binding tiers against the debug-symbol index, a `crash_report` lead family with a
  deterministic fault-class ordering, crash corroboration of published findings, the list of
  memory-safety buckets with no finding, and the crash metrics. Annotations pass an allowlist and
  user, device and session identifiers are dropped at parse time.
- **Done when:** each first-tranche adapter parses a recorded fixture into bounded records under
  unit test, a fixture run binds a crash to a finding and reports one uncovered bucket, and the
  job passes the job-contract tests. A run against a real crash export is user-owned.
- **Refs:** `docs/architecture/finding-metrics.md` (section 7), T-026, T-060,
  `docs/architecture/debug-symbol-indexing.md`, `src/appsec_review/review/lead_families.py`,
  `docs/operations/sanitizer-build.md`.

### T-073 — Derive reviewed units and entry points from a run

- **State:** in-progress
- **Area:** review
- **Why:** a run records review units by component, not by source file, so the finding snapshot
  cannot say which files a run covered. The operator must supply `reviewed-units/1` and the
  entry-point catalogue by hand; without them an absent finding can only be `not_covered` and
  coverage is "not measured".
- **Scope:** an adapter from accepted run artifacts (catalog path index, review package manifests,
  lane coverage) to the reviewed and unreviewed source files with their content hashes, and to the
  catalogued entry points with `reviewed`, `not_admitted` and `not_built` status. No target scan.
- **Progress:** `observability/findings/coverage_adapter.py` derives reviewed source files and
  entry points from a run (2026-11-11, `a71681a1`). Covered by unit tests only; not yet checked
  against a real run. Entry points are empty on real runs until T-086 gives them a producer.
- **Done when:** `snapshot` needs no `--units` for a run with an accepted catalog, the integration
  test asserts non-null `reviewed_units`, and `scorecard` prints entry-point coverage without an
  operator file.
- **Refs:** T-060, T-068, `src/appsec_review/observability/findings/run_adapter.py`,
  `docs/architecture/finding-metrics.md` (section 12, decision 3).

### T-074 — Wire the fix re-check to the verifier role

- **State:** open
- **Area:** review
- **Blocks:** T-061
- **Why:** `recheck.run_rechecks` takes an injected transport and never calls a model, so no real
  fix has been verified. Absence still cannot become `fixed` on a real target.
- **Scope:** one bounded, no-tool verifier turn per `fix-recheck-request/1`, through the existing
  role bundle and budget (the pattern of `review/evaluation.py`), opt-in with an explicit live flag,
  with the request, response and receipt stored run-owned. Model, budget and timeout settings in the
  central configuration.
- **Done when:** unit tests drive the transport with a recorded response, and a user-requested live
  run on the fix-pair corpus reports `fix_recall` and `false_fix_rate`.
- **Refs:** T-061, T-067, `src/appsec_review/observability/findings/recheck.py`,
  `src/appsec_review/review/evaluation.py`.

### T-075 — Run crash evidence as a job and a lane A lead family

- **State:** open
- **Area:** evidence
- **Why:** crash ingestion is an operator command. Crash buckets do not reach the review as leads,
  the judge does not see corroboration, and raw minidumps must be walked by the operator first.
- **Scope:** `job_crash_evidence_ingestion` under the job-contract checklist (typed settings,
  registry and topology parity, declared datasets, accepted external input identity), a
  `crash_report` lead family fed from `crash.lead_candidates`, corroboration supplied to the judge
  as evidence, a pinned stackwalker tool container for raw `.dmp` files and Crashpad database
  exports, and an `unreal_crash_context` adapter. No network access at run time.
- **Done when:** the job passes the job-contract tests, a fixture run admits a crash lead, and a
  user-requested run over a real export publishes crash evidence.
- **Refs:** T-072, T-026, `src/appsec_review/observability/findings/crash/`,
  `.claude/skills/add-a-job-contract/SKILL.md`.

### T-076 — Record attacker position owner function and remediation on findings

- **State:** open
- **Area:** review
- **Why:** the review does not record a finding's attacker position, owner, enclosing function,
  source and sink symbols or remediation. The scorecard therefore shows them as not established,
  the fingerprint rests on code context alone, and the final report states no actionability.
- **Scope:** those fields on the claim and finding package (closed vocabularies of
  `observability/findings/contracts.py`), carried by `run_adapter`; actionability completeness in
  the final report; corpus cases and runtime guidance for server trust in client state,
  unvalidated replication RPCs, bitstream length handling and entitlement bypass, through the
  runtime-guidance checklist.
- **Done when:** a fixture review publishes the fields, the snapshot fingerprint basis is
  `function_and_code`, the report lists what each finding is missing, and one keyed corpus case
  exists per named weakness class.
- **Refs:** T-069, T-070, T-002, `src/appsec_review/jobs/accepted_review.py`,
  `.claude/skills/add-runtime-guidance/SKILL.md`.

### T-077 — Derive lead records with stage attribution from a run

- **State:** in-progress
- **Area:** review
- **Why:** `triage.effectiveness` needs one record per lane A lead with its disposition and the
  stage that removed it, and labels for them. Both are operator files today, so true-lead retention
  is not printed by `stepwise.py system`.
- **Scope:** an adapter from the lane A lead manifest, lead accounting and claim projection (the
  inputs `triage_reduction` already verifies) and the funnel's stage vocabulary to lead records;
  lead labels from the answer key by scope; the paired figures printed beside the funnel.
- **Progress:** `observability/findings/lead_adapter.py` derives lane A lead records with
  removal-stage attribution from a run, and `scorecard --run` uses it (2026-11-11, `a71681a1`).
  Covered by unit tests only; not yet checked against a real run, and `stepwise.py system` does not
  print the paired figures.
- **Done when:** unit tests build lead records from a recorded lane A document, and
  `stepwise.py system` prints true-lead retention beside false-lead removal for a keyed corpus.
- **Refs:** T-062, `src/appsec_review/observability/triage_reduction.py`,
  `src/appsec_review/acceptance/funnel.py`, `src/appsec_review/observability/findings/triage.py`.

### T-078 — Check the model login before a review is submitted

- **State:** done (2026-11-11, 2f6c5ae1)
- **Area:** pipeline
- **Why:** on 2026-11-11 review `2026-11-11-0001` failed in under a minute at
  `job_model_connectivity` because the mounted Claude CLI token had expired. `stack-start` probes
  the model; `review-start` does not, so the expiry was found only after a run, a submission intent
  and a failed attempt existed, each of which then had to be cleared by hand.
- **Scope:** `review-start` and `review_run.py submit` run the same bounded model probe as
  `stack-start` for the selected profile before recording a submission intent, and refuse with the
  provider's error class and the documented remedy. `--no-probe` opts out, as on `stack-start`.
  No credential is read, stored or printed.
- **Done when:** unit tests of the launcher show an unanswered probe refusing the launch with no
  intent written and no Dagster call, and an answered probe proceeding unchanged.
- **Refs:** `scripts/review-start.sh`, `deploy/dagster/bin/review_run.py`, `scripts/stack-start.sh`,
  `docs/operations/operator-scripts.md`, T-057. The probe answered `ok` on the real stack before the launches of
  `2026-11-11-0005` and `-0006`; the refusal path has been exercised by unit tests only.

### T-079 — One guarded command for run recovery

- **State:** done (2026-11-11, 83c81a60)
- **Area:** pipeline
- **Why:** resuming a failed run takes a reconcile of the terminal submission, a
  `verify-repair-stop` inside the container for each dispatch, `plan-repair`, `admit-repair` and
  `resume`, run in the right order from two environments. On 2026-11-11 a resume was refused twice
  (unreconciled submission, then "Dagster dispatch stop requires verify-repair-stop") and the run
  was abandoned for a fresh one, which is only acceptable when nothing has been accepted yet.
- **Scope:** a `review-recover` operator script that runs the existing steps in order for one
  application run, prints the repair plan and what will be reused, and asks for one confirmation
  before admission and resume. Every existing check still runs and still refuses: no step is
  weakened, skipped or automated past its refusal, a failed step is still not proof a worker
  stopped, and an unreconciled submission still blocks a launch. When no job of the run has an
  accepted handoff the script says so and offers a fresh run instead.
- **Done when:** unit tests with fake Dagster and lifecycle boundaries cover the ordered happy
  path, each refusal stopping the sequence with its reason, the declined confirmation, and the
  nothing-accepted case; the operator guide documents it beside the single-step commands.
- **Refs:** `docs/operations/recovery-repair.md`, `docs/tasks/2026-11-10-t057-repair-loop-safeguards.md`,
  `deploy/dagster/bin/review_run.py`, `deploy/dagster/bin/stepwise.py`, T-057.

### T-080 — Derive default release ids and allow an overlay to override them

- **State:** done (2026-11-11, cab4d770; `build_toolchain` is derived from the host-pinned native build image and the overlay may set release ids; `platform` is still declared, not derived)
- **Area:** pipeline
- **Why:** review `2026-11-11-0003` blocked all 22 build units with "missing release evidence:
  build_toolchain, platform, validation". The three ids are now committed as fixed strings in
  `[review_policy.releases]` so builds can run, but a fixed string does not change when the thing
  it names changes, nothing checks it, and it is the same on every host although build images are
  host-local. The capacity overlay cannot set releases. The documentation also says a missing
  declaration "disables reuse", while `jobs/build_iterations.py` refuses to dispatch any build.
- **Scope:** (1) `[review_policy.releases]` joins the overlay allowlist, with the overlay layer hash
  covering it and unknown keys still refused. (2) Derived defaults when a release is not declared:
  `build_toolchain` from the native build image id in the host pins, and `platform` from the source
  identity the stack measures at reload, if the loader can read it at load time; `validation`
  stays declared. An explicit value in the base file or an overlay always wins, and the resolved
  configuration records for each id whether it was declared or derived and from what. (3) The
  committed strings are removed once the derived defaults exist. (4) The documentation states what
  a missing id does for each consumer: no build dispatch, no image reuse, no CodeQL reuse.
- **Done when:** unit tests cover declared, derived, overlay-overridden and unavailable-source
  cases for each id and the layer hash; a build-iteration test shows a derived `build_toolchain`
  dispatching; `docs/operations/performance-assurance.md` and `language-build.md` agree with the
  code on the effect of a missing id.
- **Refs:** `appsec-review.toml` (`[review_policy.releases]`), `src/appsec_review/jobs/build_iterations.py`,
  `src/appsec_review/config/loader.py`, `src/appsec_review/config/host_pins.py`,
  `docs/operations/performance-assurance.md`, T-051, T-057.

### T-081 — Fix the stepwise system call to review_run submit

- **State:** done (2026-11-11, 49fa3e1a)
- **Area:** pipeline
- **Why:** `deploy/dagster/bin/stepwise.py` calls `review_run.submit(dagster_run_id)` with one
  argument, but `submit(run_id, url, ...)` requires the GraphQL endpoint as well, so that path would
  raise `TypeError` when reached. Found by reading the code on 2026-11-11 while adding the
  pre-launch model check; not observed in a run.
- **Scope:** pass the endpoint the walk already uses, and add a unit test that drives that call
  through the script's fake boundary so a signature change cannot go unnoticed again.
- **Done when:** the unit test fails on the current call and passes with the fix.
- **Refs:** `deploy/dagster/bin/stepwise.py`, `deploy/dagster/bin/review_run.py`, `tests/test_operator_scripts.py`, T-078.

### T-082 — Check the guard order in project_build repair reuse

- **State:** open
- **Area:** build
- **Why:** `_reuse_accepted_repair` in `jobs/job_project_build/job.py` calls a guard that needs
  an image profile before the early return for missing release declarations, so a run without
  release ids may fail in the guard instead of reporting the missing declaration. Found by reading
  the code on 2026-11-11; not observed in a run.
- **Scope:** confirm or refute with a unit test that drives the function without release ids and
  without an image profile; if confirmed, order the early return first.
- **Done when:** the test shows the missing-release outcome for that input, or the entry is closed
  with the reason the order is correct.
- **Refs:** `src/appsec_review/jobs/job_project_build/job.py`, T-080.

### T-083 — Classify the failing judge and budget-clock unit tests

- **State:** open
- **Area:** testing
- **Why:** three unit failures seen on 2026-11-11 are not explained by T-047's fixture groups:
  `tests/review/test_judge.py::test_r5_outcomes_are_unchanged_with_and_without_a_judge_for_the_same_inputs`
  fails, `test_both_assignments_de_shuffle_to_the_same_red_correct_verdict_in_real_cells` in the
  same file fails intermittently, and `tests/review/test_team_handler.py` reports `budget clock
  regressed` under host load.
- **Scope:** reproduce each alone and shuffled; classify as fixture, test-isolation defect,
  timing assumption or product defect; fix the first three kinds and file a product defect as its
  own entry.
- **Done when:** each of the three passes alone, shuffled and under `-n 8` on a loaded host, or has
  its own entry naming the product defect.
- **Refs:** `tests/review/test_judge.py`, `tests/review/test_team_handler.py`, T-047.

### T-084 — Test language-build iteration dispatch with a ready build unit

- **State:** open
- **Area:** testing
- **Why:** review `2026-11-11-0003` failed at language_build finalize on a status word that no
  unit test reached, because no unit test drives `iterations.dispatch` end to end with a build unit
  that is ready to dispatch; the refused path is the only one covered.
- **Scope:** one unit test through the fake executor boundary: a ready unit is dispatched, its
  result is accepted and the job finalizes with a `ProducerStatus` word.
- **Done when:** the test fails when the dispatch result or the terminal status is malformed and
  runs in under 10 seconds.
- **Refs:** `src/appsec_review/jobs/build_iterations.py`, `tests/test_language_build.py`, T-057.

### T-085 — Probe the model login before recovery admits a repair

- **State:** open
- **Area:** pipeline
- **Why:** `review-recover` checks the model login only inside the resume (`review-start`), after
  the repair plan has been admitted. An expired login therefore leaves an admitted plan and no
  resumed run.
- **Scope:** run the existing bounded probe before the confirmation in step 5, with the same
  refusal text and `--no-probe` opt-out; the resume keeps its own probe.
- **Done when:** a unit test shows an unanswered probe refusing before `admit-repair` is called.
- **Refs:** `deploy/dagster/bin/ops.py`, `docs/operations/operator-scripts.md`, T-078, T-079.

### T-086 — Record source ids on un-hunted units and produce entry-point tags

- **State:** open
- **Area:** review
- **Why:** the coverage adapter (T-073) cannot name the source files of manifest `units` rows
  that were not hunted, because those rows carry no `source_ids`, and it finds no entry points on
  real runs, because no job assigns `surface:entry:*` tags.
- **Scope:** record `source_ids` on every manifest unit row; either add a producer for
  `surface:entry:*` tags or decide to read entry points from the code-graph entry-point facts, and
  record the decision.
- **Done when:** on a completed run the adapter reports reviewed and unreviewed files for every
  unit and a non-empty entry-point list for a target that has entry points.
- **Refs:** `src/appsec_review/observability/findings/coverage_adapter.py`, T-073, T-068.

### T-087 — Normalize crash symbols for corroboration

- **State:** open
- **Area:** evidence
- **Why:** crash-report ingestion corroborates a finding by comparing frame symbols with the
  finding's function, and the two are spelled differently (mangled names, template arguments,
  anonymous namespaces, inlined frames), so a true corroboration can be missed.
- **Scope:** one normalization applied to both sides before comparison, with the raw symbol
  retained; cases for Itanium and MSVC mangling, templates and inlined frames.
- **Done when:** unit tests show each case matching and an unrelated symbol with a shared prefix
  not matching.
- **Refs:** `src/appsec_review/observability/findings/`, T-072, T-075.

### T-088 — Keep a target registry and a read-only verify command

- **State:** open
- **Area:** testing
- **Blocks:** T-090
- **Why:** on 2026-11-11 two machines reviewed "c094" and compared results, but one reviewed a
  sparse checkout of `projects/native/case-094` and the other the whole repository.
  `docs/operations/test-targets.md` records remotes and commands but not sparse scope, the
  expected target fingerprint or full commit hashes, and nothing checks a checkout against it.
- **Scope:** one machine-readable registry (name, normalized remote URL without credentials, full
  commit, tag, sparse paths, expected fingerprint where it is host-independent, licence, purpose,
  answers reference as commit and SHA-256 only). A read-only command that compares
  `targets/<name>` with its entry and reports a wrong commit, dirty tree, different sparse scope or
  different fingerprint; it never clones, fetches or edits a target. Different scopes of one
  repository are separate named entries. The table in `test-targets.md` is tested against the
  registry. First establish whether the target fingerprint depends on host paths or line endings.
- **Done when:** unit tests cover a matching checkout and each mismatch on temporary git
  repositories, the registry holds every target in `test-targets.md` plus Freeciv, and the document
  test fails when the two disagree.
- **Refs:** `docs/operations/test-targets.md`, `data/reference/castle/castle-c250.lock.json`
  (precedent), `src/appsec_review/target_acquisition/`, T-057.

### T-089 — Fetch answer keys from the private answers repository in memory

- **State:** open
- **Area:** testing
- **Blocks:** T-090
- **Why:** answer keys are committed inside this repository (`test/acceptance/*/expectations.toml`)
  and sit on every review host, where a model or an agent can read them. The private repository
  `appsec-review-answers` was created on 2026-11-11 to hold them as schema-validated JSON
  (`appsec-review-answers/answer-key/1`); it holds no keys yet.
- **Scope:** a grader-side reader that fetches one key by full commit over the GitHub REST API,
  verifies its SHA-256 against the target registry, validates it against the schema and returns
  it in memory as a `ScoringKey`, writing nothing to disk and logging no key content. The token is
  read from the grading step's environment only. A converter from `expectations.toml` to the JSON
  format, run outside review hosts. Grade output limited to case ids and outcomes. Then the
  existing keys move to the answers repository and are removed here, with the blind-target
  isolation test extended to refuse a committed key. Network access is confined to this reader.
- **Done when:** unit tests drive the reader through a fake HTTP boundary (success, wrong hash,
  schema violation, HTTP failure, no token) and assert that nothing is written and no path or line
  from a key appears in the grade document or logs; `expectations.toml` files are gone from this
  repository.
- **Refs:** `src/appsec_review/acceptance/scoring.py` (`load_scoring_key`),
  `tests/test_blind_target_isolation.py`, `docs/operations/test-targets.md`, T-067, T-088.

### T-090 — Identify known targets and self-grade a completed run

- **State:** blocked
- **Area:** testing
- **Blocked by:** T-088, T-089
- **Why:** grading a corpus run is a manual sequence (answer-key evaluation, funnel, detector
  scoring, finding scorecard), so most runs are never graded and gaps are never compared with
  what is expected. A checkout records its commit and origin, so a run can recognise a known
  target itself.
- **Scope:** an opt-in final step, after the final report is published, that identifies the
  target by commit, sparse scope and clean tree (the normalized origin URL is a secondary check,
  never recorded with credentials), and for a known target fetches its key (T-089) and publishes
  one grade document: found, missed and wrongly reported cases by id; for each miss the funnel
  stage where it stopped; the delta against the last accepted baseline; and gaps outside the
  target's expected-gaps list. For an unknown or dirty target it reports "not a known target" and
  does nothing. It is reported, never a verdict, feeds nothing back into prompts or guidance, and
  records each holdout use.
- **Done when:** unit tests cover a known target, an unknown commit, a dirty tree, a scope
  mismatch and an unavailable key, each with its stated outcome; a fixture run produces a grade
  document that names every delta; the blind-isolation tests still pass.
- **Refs:** `src/appsec_review/acceptance/funnel.py`, `src/appsec_review/observability/findings/scorecard.py`,
  `docs/architecture/finding-metrics.md`, T-062, T-088, T-089.

### T-091 — Resolve conditional automake SUBDIRS in build discovery

- **State:** done (2026-11-12, `docs/tasks/2026-11-11-freeciv-walk-05-target-catalog.md`; automake variables are the union of all assignments, in-file `$(VAR)` is expanded, conditions are recorded on drives and build points; discovery case 121; Freeciv yields the two parallel root units)
- **Area:** topology
- **Why:** a read-only discovery preview of Freeciv at `b1b0768b` (2026-11-11) found 31 build
  units for what is one project with two parallel build systems. The root autotools and meson
  units are recognised as parallel, and 77 directories listed literally in `SUBDIRS` fold into the
  root, but directories reached through a variable or an `if` block stay separate units:
  `$(SSUBDIRS)` (`ai`, `server`), `$(DSUBDIRS)` (`data` and its themes) and `GUI_SUBDIRS +=`
  (the five clients). Nine of those units have no build point at all.
- **Scope:** follow automake variables assigned in the same file, including `+=` and both branches
  of `if`/`else`, when resolving `SUBDIRS`, recording the condition as a fact on the driven member;
  a directory with no build point that is only driven stays a member, not a unit. Cases added to
  the discovery matrix under conditional systems. The same reading is needed for targets and
  sources: in the Freeciv walk (`docs/tasks/2026-11-11-freeciv-walk-05-target-catalog.md`)
  `bin_PROGRAMS +=` inside `if` blocks keeps only the last program, and `_SOURCES = $(da_sources)`
  names no source, so nine sources were unowned by any automake build point.
- **Done when:** discovery cases for variable, appended and conditional `SUBDIRS` have no
  `pending` entry, and the Freeciv tree yields the two parallel root units with the conditional
  directories folded as members.
- **Refs:** T-056, `src/appsec_review/jobs/build_discovery.py`, `src/appsec_review/jobs/build_points.py`,
  `docs/plans/build-discovery-test-program-2026-11-08.md`.

### T-092 — Decide whether a refused build command fails one unit or the whole language build

- **State:** open
- **Area:** build
- **Why:** in review `2026-11-11-0005` the first build iteration (a phpize extension) raised
  `ValueError: native driver is not the unchanged accepted source descriptor` from
  `prepare_recipe_command`. The iteration job failed, `language_build__iterations__dispatch` raised
  `build iteration invocation failed`, and the review ended at 13 of 42 jobs with the other 21 build
  units never attempted. The phpize cause is fixed (`f4ef5296`), but any other command-custody
  refusal still ends the whole run.
- **Scope:** decide and record whether a custody refusal for one unit is a failed build unit with a
  named gap (siblings continue, as a compile failure does) or a run-level stop; implement the
  decision in the iteration controller without weakening the refusal itself.
- **Done when:** a unit test with two ready units, one of which is refused at command
  preparation, shows the decided outcome for the sibling and for the job's terminal status.
- **Refs:** `src/appsec_review/jobs/build_recipe_commands.py`, `src/appsec_review/jobs/build_iterations.py`,
  `src/appsec_review/jobs/job_build_iteration/job.py`, T-057, T-084.

### T-093 — Bind generated Make drivers of configure-style builds to their accepted inputs

- **State:** open
- **Area:** build
- **Why:** the Make driver recheck requires the Makefile to be an unchanged accepted source
  document. `f4ef5296` binds a phpize unit's generated Makefile to its accepted `config.m4`. Any other
  build whose configure phase generates the Makefile (Autotools `configure.ac`/`Makefile.in`, other
  generators) would still be refused with the same message; none has been observed in a run.
- **Scope:** list the build systems the discovery accepts whose build phase runs a generated
  driver; for each, name the accepted inputs the driver is generated from and bind the recheck to
  them, or record that the build system is refused by design.
- **Done when:** `tests/test_build_recipe_commands.py` has a positive and a tampered-input case for
  each such build system, and the refusal for an unaccepted hand-written Makefile is unchanged.
- **Refs:** `src/appsec_review/jobs/build_recipe_commands.py`, `src/appsec_review/jobs/build_discovery.py`,
  `tests/test_build_recipe_commands.py`, T-092, T-091.

### T-094 — Let stepwise accept a target by commit instead of a tag

- **State:** open
- **Area:** testing
- **Why:** `stepwise.py accept` requires a Git tag in the target that resolves to HEAD. Third-party
  targets are pinned at arbitrary commits and agents may not tag a target, so the Freeciv walk
  needed the user to create a local tag (`freeciv-b1b0768b-v1`) on 2026-11-11 before job 1 could
  be accepted.
- **Scope:** an operator-only `accept --target-commit <full sha>` that verifies target HEAD equals
  the commit and the tree is clean, recorded in the acceptance provenance and seed in place of the
  tag; no runtime source change.
- **Done when:** a focused unit test covers match, mismatch, dirty tree and the existing tag path
  unchanged.
- **Refs:** `deploy/dagster/bin/stepwise.py`, `tests/test_stepwise_target_tag.py`, T-088,
  `docs/tasks/2026-11-11-freeciv-walk-01-model-connectivity.md`.

### T-095 — Report an intake coverage gap once, not once per unit

- **State:** open
- **Area:** pipeline
- **Why:** in the Freeciv walk (run `2026-11-11-0008`) `job_review_intake` published 76 canonical
  gap records for 38 oversized files: `prepare_target.validate_target` reports each inventory gap
  and `publish_intake.publish_handoff` reports the same gap again from the published document. A
  tally by record count overstates the job's gaps twofold and every consumer that echoes them.
- **Scope:** one unit owns each inventory coverage gap in the job's `outcomes.json`; the published
  document may still list them. No change to what is a gap.
- **Done when:** a runner-driven intake test with one oversized file shows exactly one canonical
  gap record for it, and the published intake document still names the file.
- **Refs:** `src/appsec_review/jobs/job_review_intake/job.py` (`validate_target`, `publish`),
  `docs/tasks/2026-11-11-freeciv-walk-04-review-intake.md`, T-057.

### T-096 — Stop inferring run artifacts from a data/ path prefix

- **State:** open
- **Area:** pipeline
- **Why:** `runtime.handoff.collect_artifacts` treats any `path`/`sha256` record whose path starts
  with `data/` as a file of the run, unless it sits under a field named in `_SOURCE_DATA_FIELDS`.
  Freeciv owns a top-level `data/` folder, so the catalog's build markers for `data/Makefile.am`
  failed `job_target_catalog` at publication (`shared artifact missing`, run `2026-11-11-0009`).
  `markers` and `descriptor_package` are now exempt, but any other field that carries a
  target-relative record under `data/` fails the same way in whichever job publishes it.
- **Scope:** an artifact reference is declared by its field or by an explicit `run_path`, not
  guessed from the path; list the producers that rely on the prefix guess and convert them, then
  remove the guess. No missing declared artifact may become silently acceptable.
- **Done when:** a runner-driven test publishes a target-relative `data/...` record under an
  arbitrary field without error, and the existing missing-artifact refusals still hold.
- **Refs:** `src/appsec_review/runtime/handoff.py`, `tests/test_handoff_interchange.py`,
  `docs/tasks/2026-11-11-freeciv-walk-05-target-catalog.md`, T-057.

### T-097 — Use ChangeLog files as a source-history signal

- **State:** in-progress
- **Area:** history
- **Why:** a target is not always delivered with Git history (source drop, tarball, shallow or
  squashed clone, Perforce export), and then `job_source_history_analysis` has little or nothing.
  The Freeciv walk on 2026-11-11 found `ChangeLog` and `ChangeLog-1.0-S3_0` left out of the
  inventory for size; the user decided change logs should feed the history job, since a change log
  is weaker than commits but better than nothing.
- **Scope:** built on branch `changelog-history`: the `acquire.changelog_history` unit parses the
  change-log files the accepted catalog lists (GNU ChangeLog, `git log` dumps, `svn log -v`, Keep
  a Changelog), bounded by the typed `changelog` settings; binds named paths to catalog paths only
  exactly or by an unambiguous suffix; drops names, e-mail addresses and message text while
  parsing (the T-029 redaction pass does not exist); publishes `changelog.json`, the accepted
  document's `changelog` section, `history_priority.changelog` in the plan, location-free
  `history_signal` entities and the `changelog-history` coverage row, all marked
  `source: changelog` with a `primary`/`supplement` role and never merged into Git counts; and
  reports every bound, unparsed part and unbound path as a `producer-gap/1` record. Not built,
  and remaining under this id: (1) review prioritization and the `history_context` product do not
  consume change-log signals, because they read SII scores and location-bound signals; (2) a
  change log without file lists ranks no file, and subject-based file or component attribution
  waits for the T-029 redaction pass; (3) change-log entries are not compared with Git commits
  when both exist (a `git log` dump's hashes could be matched to walked commits); (4) per-symbol
  change-log signals stop at the symbol tokens GNU entries name, with no span binding; (5) the
  job stays on the legacy free-text gap list, only this unit emits records; (6) the acceptance
  fixtures under `test/acceptance/*/job_source_history_analysis*` predate the new task and
  settings table and need re-baselining by their owner.
- **Done when:** a real run of the history job on Freeciv (pinned at `b1b0768b`), after the
  inventory bound admits both change logs, publishes a `changelog` section whose format detection,
  entry counts, bound-file ranks and gaps are checked against the two files, with no author name,
  address or message text in any output; and items (1) to (6) are each built or split into their
  own entries.
- **Refs:** `src/appsec_review/jobs/job_source_history_analysis/changelog.py`,
  `src/appsec_review/jobs/job_source_history_analysis/job.py`,
  `tests/test_source_history_changelog.py`, `tests/fixtures/changelog_history/`,
  [`architecture/source-history-analysis.md`](architecture/source-history-analysis.md)
  ("Change-log history"), T-027, T-029, T-047, T-048.

### T-098 — Identify vendored third-party code in a target

- **State:** blocked
- **Area:** topology
- **Blocked by:** T-099
- **Why:** the Freeciv walk (run `2026-11-12-0001`) catalogued the copies of Lua 5.4, tolua 5.2,
  tinycthread, cvercmp and luasql under `dependencies/` as build units like the project's own
  code, while the dependency catalog was empty because the target has no package manifest. Nothing
  says "this directory is third-party code, of this project and version": findings there are not
  marked as upstream defects, known advisories for the vendored version are not looked up, and
  the source inventory flags `vendored` only for directories literally named `vendor`,
  `vendors` or `third_party`. The user decided on 2026-11-11 not to stop the walk for this:
  vendored code stays in scope as code and its non-identification is a known gap of the walk.
- **Scope:** decide and record what identifies a vendored component (directory conventions such as
  `dependencies/`, `third_party/`, `extern/`, a bundled upstream licence, README or version header,
  a build system that offers a system-library alternative for the same directory) and what the
  catalog publishes for it: a component with name, version when stated, evidence and confidence,
  marked vendored, with its sources still reviewed. Feed the dependency catalog and the delivery
  scope from it. No network lookup in the catalog job.
- **Done when:** a catalog test with a bundled upstream library under a conventional directory
  publishes it as a vendored component with its evidence, a directory that merely has that name
  and no upstream evidence is not marked, and the Freeciv catalog names its five vendored
  libraries.
- **Refs:** `src/appsec_review/jobs/cataloging.py`, `src/appsec_review/jobs/job_target_catalog/job.py`,
  `src/appsec_review/jobs/delivery_scope.py`,
  `docs/tasks/2026-11-11-freeciv-walk-05-target-catalog.md`, T-035, T-091.

### T-099 — Build one dependency finder with a common observation record

- **State:** open
- **Area:** topology
- **Blocks:** T-098, T-100, T-101, T-102, T-105
- **Why:** dependencies are found in eight places with different record shapes, three of which never reach the merged inventory; the Freeciv catalog's dependency list was empty (walk 05). There is no one place that says what a dependency observation is or who may produce one.
- **Scope:** define `dependency-observation/1` (name, version, how the version is known, ecosystem, purl, CPE candidates, component root, vendored flag, scope, finder id, resolving evidence); a registry of finders, each a pure function over accepted inputs returning observations and named gaps; move the existing producers behind it without changing behaviour (catalog `package.json`, Syft observations, native discovery); `normalize_dependencies` consumes only the registry's output and `job_dependency_intelligence` stays the single merge and SPDX publisher. Sequencing (user, 2026-11-12): the dependency redesign is worked after the Freeciv walk is through the build and topology jobs, because build and topology come first. The user also asked (same date) that as many tools as possible feed the SBOM and review data.
- **Done when:** catalog, Syft and native observations reach `normalize_dependencies` only through the registry, with unchanged output on the accepted cpp-multivuln baseline.
- **Refs:** `src/appsec_review/jobs/job_dependency_intelligence/`, `src/appsec_review/jobs/job_target_catalog/job.py`, `docs/tasks/2026-11-11-freeciv-walk-05-target-catalog.md`, T-035, T-091, T-011.

### T-100 — Find dependencies declared in native build systems

- **State:** blocked
- **Area:** topology
- **Blocked by:** T-099
- **Why:** a native project declares what it links against in its build files, not in a package manifest: CMake `find_package`, `pkg_check_modules`, `FetchContent`, `ExternalProject_Add` and CPM; Conan; vcpkg; Meson `dependency()` and wraps; autotools `PKG_CHECK_MODULES` and `AC_CHECK_LIB`; Make link lines. None of these is read as a dependency today, although the build-point parsers already see most of the calls.
- **Scope:** one finder per build system behind the T-099 registry, each publishing declared dependencies with their evidence; a `FetchContent` URL or tag yields a version. Declared constraints are not resolved versions and are labelled so. Sequencing (user, 2026-11-12): the dependency redesign is worked after the Freeciv walk is through the build and topology jobs, because build and topology come first.
- **Done when:** a fixture per build system publishes its declared dependencies with evidence, and Freeciv's meson and autotools declarations appear in its dependency catalog.
- **Refs:** `src/appsec_review/jobs/build_points.py`, T-099, T-098.

### T-101 — Find dependencies in manifests and lockfiles of every recognised ecosystem

- **State:** blocked
- **Area:** data
- **Blocked by:** T-099
- **Why:** the catalog recognises Maven, Gradle, NuGet, Cargo, Go, Python, Composer and RubyGems manifests but reports a deferred parser for most of them.
- **Scope:** take manifest and lockfile contents from Syft and osv-scanner extraction rather than writing parsers, as registry finders. User decisions of 2026-11-12 on `dependency-finder-plan.md` (shared session notes): package-manager tools that need network egress to resolve (Maven, npm and the like) are pre-authorized by the user; each use is still declared in typed configuration and recorded in the run. Sequencing (user, 2026-11-12): the dependency redesign is worked after the Freeciv walk is through the build and topology jobs, because build and topology come first.
- **Done when:** no catalog gap reads that the dependency parser is deferred for a manifest type the catalog recognises.
- **Refs:** `src/appsec_review/jobs/job_target_catalog/job.py`, `src/appsec_review/jobs/job_evidence_collection/`, T-099, T-011.

### T-102 — Find components in built binaries with a cve-bin-tool scan adapter

- **State:** blocked
- **Area:** binary
- **Blocked by:** T-099
- **Why:** a statically linked or bundled library leaves no manifest; its version is only in the binary. cve-bin-tool is built nightly but its scanner is still catalogued as deferred.
- **Scope:** a built-binary component finder (cve-bin-tool version-string checkers, Syft binary classifiers, ELF `NEEDED`/SONAME, Go build info) behind the registry, and a cve-bin-tool scan adapter. User decisions of 2026-11-12 on `dependency-finder-plan.md` (shared session notes): (2) the scan adapter runs cve-bin-tool as a separate executable (execute only), and the nightly builder `tools/cve-bin-tool/build_db.py` importing the package in-process inside its own container is accepted as internal use. The catalog entry moves from `deferred` to `enabled` with that decision recorded. Sequencing (user, 2026-11-12): the dependency redesign is worked after the Freeciv walk is through the build and topology jobs, because build and topology come first.
- **Done when:** a fixture binary with a statically linked library of known version yields the component and its CVEs offline.
- **Refs:** `tools/cve-bin-tool/build_db.py`, `containers/catalog.toml`, T-099.

### T-103 — Sync the Trivy databases nightly and add a Trivy SBOM vulnerability adapter

- **State:** open
- **Area:** data
- **Blocks:** T-105
- **Why:** one matcher's database is one view; Trivy's database is not fetched or used.
- **Scope:** a `trivy_db_sync` step in `job_third_party_data_sync` that fetches `trivy-db` and `trivy-java-db`, verifies and publishes them immutably, and a Trivy adapter in SBOM mode. User decisions of 2026-11-12 on `dependency-finder-plan.md` (shared session notes): (1) the nightly sync job may reach the network to fetch the Grype and Trivy databases; scanners stay `network = "none"`. Sequencing (user, 2026-11-12): the dependency redesign is worked after the Freeciv walk is through the build and topology jobs, because build and topology come first.
- **Done when:** the sync publishes a verified Trivy snapshot with a last-known-good pointer, and the adapter matches a fixture SBOM offline against it.
- **Refs:** `src/appsec_review/jobs/job_third_party_data_sync/`, T-009, T-106.

### T-104 — Look up CPE candidates in the pinned NVD snapshot

- **State:** open
- **Area:** data
- **Blocks:** T-105
- **Why:** vendored C and C++ libraries have no package record, so package-based matchers find nothing for them; their vulnerabilities are published against CPE names in NVD.
- **Scope:** a bounded CPE lookup against the NVD snapshot the nightly already publishes, taking CPE candidates from dependency observations. Matches are leads unless the version is resolved or installed. Sequencing (user, 2026-11-12): the dependency redesign is worked after the Freeciv walk is through the build and topology jobs, because build and topology come first.
- **Done when:** a fixture observation with a known vendor, product and version returns its NVD entries from a pinned snapshot, within stated bounds, offline.
- **Refs:** `data/feeds/nvd`, `src/appsec_review/jobs/job_third_party_data_sync/`, T-099, T-098.

### T-105 — Match vulnerabilities in one stage over the merged dependency inventory

- **State:** blocked
- **Area:** scanners
- **Blocked by:** T-009, T-099, T-103, T-104
- **Why:** each matcher scans its own private view (Grype over a Syft SBOM, osv-scanner per project, nothing for native or vendored code), so coverage depends on which tool happened to see a dependency. Grype is off by `tools.disable_grype` and has no database snapshot on this host.
- **Scope:** Grype and Trivy in SBOM mode over the published SPDX, OSV by purl through the index matcher, the CPE lookup, and cve-bin-tool per built binary, all over the merged inventory; every match records the matcher, the database snapshot id and how the version was known. User decisions of 2026-11-12 on `dependency-finder-plan.md` (shared session notes): (3) native-SBOM design decision 2 is lifted: discovered native versions may be matched against vulnerability data, labelled as leads; vendored copies stay leads because they are often patched. Then `disable_grype = false`, and T-010's dedupe becomes a property of the stage. (4) Order agreed: fix the stale nightly (T-106), then the registry with the vendored and native-declaration finders (T-099, T-098, T-100), then the databases into the nightly (T-009, T-103), then this stage. Sequencing (user, 2026-11-12): the dependency redesign is worked after the Freeciv walk is through the build and topology jobs, because build and topology come first.
- **Done when:** one run publishes matches from every enabled matcher over the same inventory with snapshot ids, a declared-version match is labelled a lead, and Grype coverage is no longer a configured-disabled gap.
- **Refs:** `src/appsec_review/jobs/job_evidence_collection/`, `src/appsec_review/jobs/job_artifact_security_analysis/`, `appsec-review.toml` (`[tools]`), T-010, T-013.

### T-106 — Restart the nightly data sync and refuse stale feeds at run readiness

- **State:** open
- **Area:** data
- **Why:** every feed pointer under `data/feeds` is dated 2026-10-16 or 2026-10-18. Dagster shows the schedule `third_party_data_sync_schedule` (cron `0 0 * * *` UTC, default status RUNNING) in instance state STOPPED; its last tick was 2026-10-19 00:00 UTC. Its last two runs failed: 2026-10-19 in step `cve_bin_tool_db_build__build`, 2026-10-18 in `begin`; the last scheduled success was 2026-10-17. So the schedule was stopped explicitly after two failed nights and nothing has synced for 24 days. A review reading these snapshots matches against vulnerability data of mid-October without saying so.
- **Scope:** find and fix the two failures, turn the schedule back on (an operator action on the shared stack), and add a staleness check to run readiness so a review cannot start on feeds older than a configured bound without a named gap. This is the first item of the dependency plan (phase 0).
- **Done when:** the schedule ticks and publishes on this host, and a readiness test with a feed pointer older than the bound yields the named gap.
- **Refs:** `src/appsec_review/jobs/job_third_party_data_sync/`, `src/appsec_review/orchestration/dagster/adapter.py`, `deploy/dagster/bin/ops_readiness.py`, T-057.

### T-107 — Generate a data-flow diagram and threat model from accepted run evidence

- **State:** open
- **Area:** review
- **Why:** no job in the graph produces a data-flow diagram or a threat model; the catalog only classifies documents the target supplies, and Freeciv supplies none (walk 05). The user asked on 2026-11-11 whether the jobs that should create them exist; they do not. This is the F07 row of T-059 re-cut as one job.
- **Scope:** a design for one job, `job_threat_model_generation`, is being written by a separate session on branch `dfd-threat-model` (not merged). This entry holds the id; its scope and done-when are replaced by the design's proposed text when the user approves the design. Nothing is implemented before that.
- **Done when:** the user has approved a design, this entry carries its scope and acceptance, and the job publishes a data-flow diagram and threat model with resolving evidence on a real run.
- **Refs:** T-059 (F07), T-070, `docs/tasks/2026-11-11-freeciv-walk-05-target-catalog.md`, branch `dfd-threat-model`.

### T-108 — Publish the static deployment inventory as a job

- **State:** open
- **Area:** evidence
- **Why:** the `appsec_review.deployment` library extracts listeners, services and relationships from deployment documents, but no job publishes them as an accepted dataset, so a threat model has no deployment facts to build on. This is the static half of the F06 row of T-059.
- **Scope:** proposed by the same design session as T-107 on branch `dfd-threat-model` (not merged): wire the existing library into a job whose output is an accepted dataset. This entry holds the id; its scope and done-when are replaced by the design's proposed text when the user approves it.
- **Done when:** the user has approved the design, and a run publishes the static deployment inventory as an accepted, consumable dataset.
- **Refs:** `src/appsec_review/deployment/`, T-059 (F06), T-107, branch `dfd-threat-model`.

### T-109 — Put a hard ceiling on test runs and enforce the ten-second unit limit

- **State:** open
- **Area:** testing
- **Why:** on 2026-11-11 and 12 two comparison runs of unit files took 26 to 28 minutes and one did not finish in 1,700 s. They were plain `pytest` runs, which have no limit; `scripts/run-tests.sh` has a 300 s total limit but it can be raised by option and is not the only route. The underlying cost is tests filed as unit tests that drive whole job graphs: 17 tests in one affected set took 19 to 98 s each against the 10 s rule of `AGENTS.md`, which nothing enforces. The user asked on 2026-11-12 for the harness to fault when a run exceeds about fifteen minutes.
- **Scope:** (1) a ceiling on a wrapper run that no option can raise past fifteen minutes, ending the run as a failure with the tests still running named; (2) plain multi-file `pytest` refused or warned in favour of the wrapper; (3) the 10 s unit limit enforced: a test over it fails unless it carries an explicit, reasoned time budget, with the current offenders listed and either narrowed or moved to the integration tier. No assertion is weakened to meet a limit.
- **Done when:** a wrapper run over the ceiling exits non-zero naming the unfinished tests; a unit test over 10 s without a declared budget fails; the list of tests over 10 s at the time of the change is empty or each has a recorded disposition.
- **Refs:** `scripts/run-tests.sh`, `deploy/dagster/bin/ops_tests.py`, `tests/conftest.py`, `docs/architecture/testing.md`, `docs/processes/walk-charter.md` (section 10), T-047.

### T-110 — Decide what the walk does with shell environment scripts the bounded reader cannot read

- **State:** open
- **Area:** build
- **Why:** on the Freeciv walk (run `2026-11-12-0002`, job 8 `job_build_environment_analysis`, 2026-11-12) the job stopped the walk on three gap causes not on the expected list: `unresolved_script_context_or_condition` and `unsupported_script_statement` on `platforms/emscripten/emssetup.sh` and `scripts/setup_auth_server.sh`, and `unresolved_declaration_value` on the latter. Both causes were true of the target: the reader (`analyze_environment` in `src/appsec_review/jobs/job_build_environment_analysis/job.py`) selects every `.sh`/`.bash`/`.bat`/`.cmd` whose stem matches `env|setup|setvars|bootstrap`, marks a whole script uncertain on any control flow, `$`, `;`, `|` or `exit`, reports every non-assignment line as unsupported, and publishes only literal assignments of non-uncertain scripts. On Freeciv that gave 64 declarations, 56 `unknown` and 8 `redacted`, 0 `declared`: the one literal, `EMSDK_VER=5.0.4`, was lost to whole-script uncertainty, and the auth-server script is a runtime MySQL setup tool selected only because its stem contains `setup`. The user accepted the causes for that walk as a detection limit (walk terms row 15) and asked for this item so a correct general answer is worked out rather than repeated per walk.
- **Scope:** decide and implement one of: (1) keep the reader as is and make the three causes a standing expected gap with the cost stated once (no known environment value for any script with control flow); (2) narrow uncertainty to the lines under control flow so unconditional literals such as `EMSDK_VER=5.0.4` are published as `declared`; (3) tighten or widen selection (the stem rule admits non-build scripts; `platforms/emscripten/setups/cross-ems.tmpl` and `scripts/ci-build.sh` are not selected). Any change keeps the byte and count bounds, the secret redaction and the "advisory, not retryable" classification; a contract change follows `.claude/skills/add-a-job-contract/SKILL.md`.
- **Done when:** a written decision names which option applies and why; for (2) or (3) a focused regression in `tests/` shows the Freeciv shapes (an unconditional literal before an `if`, a non-literal `$(...)` value, a non-build `*setup*.sh`) producing the intended declarations and gaps, and the walk charter's expected-gaps guidance says whether the causes are expected by default.
- **Refs:** `src/appsec_review/jobs/job_build_environment_analysis/job.py` (`analyze_environment`, `gap_records`), `docs/processes/walk-charter.md` (sections 5 and 6), the Freeciv walk record `docs/tasks/2026-11-12-freeciv-walk-08-build-environment-analysis.md` (host-local, HAL5000), T-057.

### T-111 — Surface build-descriptor bounds as gap records and size them against real targets

- **State:** open
- **Area:** build
- **Why:** on the Freeciv walk (run `2026-11-12-0002`, job 9, 2026-11-12) the plan's evidence bundle held 24 of 130 autotools descriptors and neither `configure.ac` (66,520 B) nor the root `meson.build` (124,522 B, the primary build system's only descriptor, 23 targets), because `build_discovery.descriptor_package` bounds descriptors at 24 files, 65,536 B per file and 262,144 B in all. The strings `descriptor content omitted by byte bound` and `descriptor file-count bound reached` are written only inside `build-targets.json` (job 5) and `build_actions[].descriptor_package.gaps` (job 9); neither job emits a `producer-gap/1` record for them, so the walk's canonical gap check never sees that the model and the topology planned without the main build descriptors. The user accepted this for the Freeciv walk as a detection limit (walk terms row 17).
- **Scope:** (1) emit a producer-gap record per omitted descriptor and per file-count bound reached, in the job that applies the bound, with the path, size and bound as scope; (2) make the three bounds typed configuration of the catalog job rather than function defaults, and size them against the known targets (Freeciv needs at least 128 KiB per file for `meson.build`; the file-count bound should admit a root `configure.ac` and `meson.build` ahead of subdirectory descriptors, which the ordering already does for markers); (3) a focused unit regression with an over-bound root descriptor showing the record and the ordering.
- **Done when:** a catalog run on a target with an over-bound root descriptor shows that descriptor in `outcomes.json` as a gap record; the bounds are in the resolved configuration; the regression passes.
- **Refs:** `src/appsec_review/jobs/build_discovery.py` (`descriptor_package`), `src/appsec_review/jobs/job_target_analysis_plan/planning.py`, walk record `docs/tasks/2026-11-12-freeciv-walk-09-target-analysis-plan.md` (host-local, HAL5000), T-095, T-110.

### T-112 — Record what the analysis-summary trim removed, and do not report truncation under the bounds

- **State:** open
- **Area:** build
- **Why:** job 9 of the Freeciv walk reported `analysis summary was truncated by configured bounds` while the published summary was under both bounds (334 sample items of 2,000; 359,844 of 524,288 bytes). `planning.summarize_catalog` trims by popping build-unit descriptor documents first, then catalog lists, then prefix samples, until the item count and the canonical byte size fit, and records only `truncated: true`; the summary read by the model is smaller than the one the bounds allow, and nothing says what was dropped. The user accepted the gap for the Freeciv walk (walk terms row 19).
- **Scope:** record the trimmed items by kind and count in `bounds`; trim samples before descriptor documents (the documents are the planning evidence, the samples are illustration); report truncation only when the final size or count is at a bound; a focused regression with a summary that needs trimming.
- **Done when:** a trimmed summary names what was removed; a summary that fits is not marked truncated; the regression passes.
- **Refs:** `src/appsec_review/jobs/job_target_analysis_plan/planning.py` (`summarize_catalog`, `trim_one`), walk record 09 (host-local), T-111.

### T-115 — Record code-graph live verification in fixture provenance and test it against the lock

- **State:** open
- **Area:** graph
- **Blocks:** T-122, T-126
- **Why:** per-language live results exist only as prose in `rules/codeql-graph-export/README.md` ("Live verification"). Only `native` and `rust-synthetic` provenance say `recording: live`; Java, Python, Ruby and Go are sentences with no artifact, date, image id or pack hash behind them, and no test holds the README table to the fixtures or the fixtures to the pinned lock.
- **Scope:** add an optional `live_verification` object to the fixture provenance schema (`date`, `codeql_version`, `source_image_id`, `pack_tree_sha256`, `result`, `notes`); fill it for `native` and `rust-synthetic` from their descriptions; leave it absent for hand-authored fixtures until T-118, T-119 and T-122 run. Add a unit test that (a) the README "Live result" column agrees with each fixture's provenance (an absent object means no live result recorded) and (b) a fixture with `live_verification` fails when its `pack_tree_sha256` differs from `export_query_packs.<language>.tree_sha256` or its `codeql_version` differs from `codeql.version` in `containers/tools/codeql/assets.lock.json`.
- **Done when:** `tests/graph/test_export_provenance.py` passes, fails on a README/provenance disagreement, and fails on a lock mismatch (checked by mutating a copy in the test); `tests/graph/test_*_export.py` still pass.
- **Refs:** `tests/fixtures/graph/codeql_export/*/provenance.json`, `rules/codeql-graph-export/README.md`, `containers/tools/codeql/assets.lock.json`, `docs/architecture/code-graph-precomputation.md` section 8.

### T-116 — Make the code-graph docs name all eight pinned export packs

- **State:** open
- **Area:** graph
- **Why:** `docs/architecture/indexing-and-query-reuse.md` (line 509) and `docs/operations/review-data-indexing.md` (line 326) say only C/C++ has a graph export pack. `containers/tools/codeql/assets.lock.json` `export_query_packs` pins cpp, csharp, go, java, javascript, python, ruby and rust, and `appsec-review.toml` configures all eight.
- **Scope:** rewrite the two passages to the per-language table of `code-graph-precomputation.md` section 8 (pinned, live-recorded, hand-authored, deferred). Documentation only; `appsec-review.toml` is not touched here (T-117).
- **Done when:** neither file contains the C/C++-only claim; `docs/docs-sync.json` updated per `.claude/skills/docs-sync/SKILL.md`; documentation checks only, no test run.
- **Refs:** the two files above, `docs/architecture/code-graph-precomputation.md` section 8.

### T-117 — Fix the stale image_id comments in appsec-review.toml (not during an active walk)

- **State:** open
- **Area:** images
- **Why:** `appsec-review.toml` lines 1279-1281 and 1889-1890 say a profile's `image_id` lives in the TOML and the Rust image is "pinned above"; since T-051 ids live only in `deploy/dagster/host-pins.toml`. The loader hashes the raw TOML bytes into `source_sha256` (`src/appsec_review/config/loader.py` line 1504) and `runtime/runner.py` records it in every run's configuration `sources`, so a comment edit changes the frozen configuration identity and, under walk charter rule 7, ends an active run.
- **Scope:** fix the two comments only, when no walk or review run is active on any host that will pull the change; no key changes.
- **Done when:** `.venv/bin/python -c "from appsec_review.config import load_config; load_config('appsec-review.toml')"` succeeds; `tests/test_000_unit_environment_guard.py` and the config loader unit tests pass; the change lands between walks.
- **Refs:** `appsec-review.toml`, `docs/operations/image-pin-verification.md`, `docs/processes/walk-charter.md` rule 7.

### T-118 — Run and record the JavaScript/TypeScript graph-export live tier

- **State:** open
- **Area:** codeql
- **Blocks:** T-122
- **Why:** the `javascript` pack is pinned but no live result is recorded; the README row says "needs Node". On WSOLLERS1 the `node` profile image `audit-buildenv-typescript:local` is built (2026-11-09), host-pinned with a matching id, and `preinstalled_undeclared = "derive"` layers CodeQL onto it on first use. Unblocked on this host; needs only the run.
- **Scope:** run `tests/live/test_codeql_graph_export_javascript_live.py` under the configured 1800 s live default; if the cold derive and compile exceed it, stop and report the measured time, do not declare a `time_budget`. Fix QL or `expected-facts.json` per "Changing the pack or catalog" (re-pin `tree_sha256` and `asset_lock_sha256`, recompile with `scripts/compile-codeql-queries.sh --language javascript`); record the outcome in the fixture's `live_verification` (T-115) or, until it lands, in the README row. Any re-pin of `tree_sha256`, `catalog_sha256` or `asset_lock_sha256` edits `appsec-review.toml`, which changes the frozen configuration identity (the T-117 mechanism); such a change lands only when no walk or review run is active on any host that will pull it, and all re-pins of this entry go in one commit. A live run that passes with no QL or catalog change needs no TOML edit, and the constraint does not apply.
- **Done when:** the live test passes on the pinned image within the default budget; provenance and README agree under T-115's test; `tests/test_codeql_export_runner.py` and `tests/graph/test_javascript_export.py` pass; any re-pins land in one commit between walks.
- **Refs:** `tests/live/test_codeql_graph_export_javascript_live.py`, `tests/fixtures/graph/codeql_export/javascript-synthetic/`, `rules/codeql-graph-export/javascript/`, `containers/buildenv/typescript/README.md`, T-115, T-117.

### T-119 — Run and record the C# graph-export live tier

- **State:** open
- **Area:** codeql
- **Blocks:** T-122
- **Why:** the `csharp` pack is pinned but no live result is recorded. On WSOLLERS1 `audit-buildenv-dotnet:local` is built (2026-11-09), host-pinned with a matching id, and ships SDK 8.0.131 with `Microsoft.AspNetCore.App.Ref`, which the `net8.0` Web SDK fixture needs. Unblocked on this host; needs only the run.
- **Scope:** run `tests/live/test_codeql_graph_export_csharp_live.py` under the 1800 s default; on overrun, stop and report the measured time, do not declare a `time_budget`. Fix QL or expectations per the pack-change procedure (`--language csharp`); record the outcome in `live_verification` (T-115) or, until it lands, in the README row. Any re-pin of `tree_sha256`, `catalog_sha256` or `asset_lock_sha256` edits `appsec-review.toml`, which changes the frozen configuration identity (the T-117 mechanism); such a change lands only when no walk or review run is active on any host that will pull it, and all re-pins of this entry go in one commit. A live run that passes with no QL or catalog change needs no TOML edit, and the constraint does not apply.
- **Done when:** the live test passes on the pinned image within the default budget; provenance and README agree; `tests/test_codeql_export_runner.py` and `tests/graph/test_csharp_export.py` pass; any re-pins land in one commit between walks.
- **Refs:** `tests/live/test_codeql_graph_export_csharp_live.py`, `tests/fixtures/graph/codeql_export/csharp-synthetic/`, `rules/codeql-graph-export/csharp/`, `containers/buildenv/dotnet/Dockerfile`, T-115, T-117.

### T-120 — Decide the unclassified sink models and whether html_output is the cross-site scripting class

- **State:** open
- **Area:** graph
- **Blocks:** T-121, T-122, T-126
- **Why:** five CodeQL sink models are unclassified and never `direct_eligible`: `RemoteFlowSinkFunction` (C/C++), `NoSqlExecution` (Python), `HttpResponse` (Ruby), `UnmarshalingFunction` (Go), `PredicateInjectionSink` (Swift). `SinkClass` already has `html_output`, which the JavaScript catalog maps `ReflectedXss::Sink` onto; the open question is whether `html_output` is the cross-site scripting class or a distinct class is wanted. A catalog change re-pins `catalog_sha256` for all eight languages, and the README procedure then asks for each language's live tier again (T-122).
- **Scope:** a written decision per model: extend `SinkClass` (contract enum, catalog schema, `docs/schemas/retrieval-mcp-tools.json`, goldens), map onto an existing class, or record as deliberately ignored with a reason; one decision on `html_output` versus a distinct class. Apply it in one change with the re-pins; name the live tiers it invalidates. Any re-pin of `tree_sha256`, `catalog_sha256` or `asset_lock_sha256` edits `appsec-review.toml`, which changes the frozen configuration identity (the T-117 mechanism); such a change lands only when no walk or review run is active on any host that will pull it, and all re-pins of this entry go in one commit. A live run that passes with no QL or catalog change needs no TOML edit, and the constraint does not apply.
- **Done when:** the decision is recorded in `code-graph-precomputation.md` section 8; `tests/test_codeql_export_runner.py`, `tests/graph/test_*_export.py` and the catalog tests pass with regenerated goldens; the invalidated-tier list is in the README; any re-pins land in one commit between walks.
- **Refs:** `src/appsec_review/graph/contract.py` (`SinkClass`), `rules/codeql-graph-export/catalog.json`, `catalog.schema.json`, `rules/codeql-graph-export/README.md` ("Catalog semantics"), T-117.

### T-121 — Fail when a live export carries a CodeQL model with no catalog decision

- **State:** blocked
- **Area:** graph
- **Blocked by:** T-120
- **Why:** an exported `sink_sites` or `source_sites` row whose `model` matches no catalog rule silently becomes `unclassified`. Nothing distinguishes a model nobody has looked at from one the catalog deliberately leaves out, so new models arriving with a CodeQL upgrade go unnoticed.
- **Scope:** add an `ignored` list per language to `catalog.json` and `catalog.schema.json`, each entry a `model` plus a `because` reason; a unit test that loads every fixture with `recording: live`, collects the distinct `model` (and `source_type`) values of its `sink_sites` and `source_sites`, and fails on any value that is neither matched by a rule nor listed as ignored.
- **Done when:** `tests/graph/test_catalog_decisions.py` passes on the current live recordings and fails when an ignored entry is removed in a test copy; the five T-120 models are either classified or listed with reasons.
- **Refs:** `rules/codeql-graph-export/catalog.json`, `catalog.schema.json`, `src/appsec_review/graph/catalog.py`, `tests/fixtures/graph/codeql_export/*/provenance.json`.

### T-122 — Replace every hand-authored recording of a pinned language with its live export

- **State:** blocked
- **Area:** codeql
- **Blocked by:** T-115, T-118, T-119, T-120 (all steps); T-124, T-125 (the rust-synthetic refresh step only) · **Blocks:** T-123
- **Why:** six of eight pinned languages (java, python, ruby, go, javascript, csharp) hold hand-authored recordings, which are the author's expectation of the pack, not evidence of it. The T-120 catalog change also invalidates the native and Rust recordings.
- **Scope:** one language per run, one at a time on the host: run that language's live tier, copy the passing `exports/` over the fixture's recording, set `recording: live` and `live_refreshable: true`, fill `live_verification`, regenerate the golden with `APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`, and keep `expected-facts.json` as the semantic floor. Refresh `native` after the catalog change and `rust-synthetic` only after T-124 and T-125 are decided; if the Rust refresh happens first, a later Rust pack change requires one more Rust live run. Fix QL only where a live row shows the pack wrong. Any re-pin of `tree_sha256`, `catalog_sha256` or `asset_lock_sha256` edits `appsec-review.toml`, which changes the frozen configuration identity (the T-117 mechanism); such a change lands only when no walk or review run is active on any host that will pull it, and all re-pins of this entry go in one commit. A live run that passes with no QL or catalog change needs no TOML edit, and the constraint does not apply.
- **Done when:** no fixture of a pinned language has `recording: hand-authored` (only `swift-synthetic` remains); every live tier passes; `tests/graph/test_*_export.py` and T-115's test pass; any re-pins land in one commit between walks.
- **Refs:** `tests/fixtures/graph/codeql_export/*/`, `tests/live/test_codeql_graph_export*_live.py`, `rules/codeql-graph-export/README.md` ("Changing the pack or catalog" step 4), T-117.

### T-123 — Write the code-graph acceptance record from a live run

- **State:** blocked
- **Area:** graph
- **Blocked by:** T-122
- **Why:** `deploy/dagster/verification/code-graph-acceptance.json` has never existed; `code-graph-precomputation.md` (lines 1057 and 1095) and `docs/reviews/code-graph-precomputation-implementation.md` say so. `tests/live/test_code_graph_live.py` writes it only when `APPSEC_CODE_GRAPH_VERIFICATION` is set, and today it builds C/C++ scopes only.
- **Scope:** extend the live test with one seeded scope per pinned language from the existing fixtures (`LIVE_SCOPES` profile and mode per language); run it on `targets/appsec-multi-vuln-c094` for C/C++ (`APPSEC_MULTI_VULN_WORKSPACE`) plus the per-language scopes; write the record to `deploy/dagster/verification/code-graph-acceptance.json` and describe it in that directory's README.
- **Done when:** the record exists and the test asserts, per language, at least one `dataflow_path` of two or more steps, at least one `guard_fact`, and a response from every `query_code_graph` mode (`callers`, `callees`, `sinks`, `entry_points`, `paths`, `guards`, `ranges`, `summary`, `sarif_path`); the architecture doc's "not written" sentences are removed.
- **Refs:** `tests/live/test_code_graph_live.py`, `deploy/dagster/verification/README.md`, `docs/architecture/code-graph-precomputation.md` sections 5.2 and 10 (C9).

### T-124 — Close or confirm the Rust remote-flow pruning gap

- **State:** open
- **Area:** graph
- **Blocks:** T-122
- **Why:** `rust_summarized_body_prunes_remote_flow` keeps four `path_flows` rows unmet in `rust-synthetic/expected-facts.json` `known_gaps` (remote to SQL, command, SSRF, deserialization). The live test fails once CodeQL closes it, but nothing records which option closes it. The option is the user's open decision.
- **Scope:** reproduce against the live recording, then apply the user's chosen option from: (1) a pack-side flow step in `rules/codeql-graph-export/rust/`; (2) a rust-all upgrade past 0.2.21 with a recorded re-check version; (3) CodeQL data-extension model files, if codeql/rust-all 0.2.21 in the pinned 2.27.0 image accepts extensions for Rust; (4) Semgrep/Opengrep taint rules as a fallback producer for these four sink classes, correlated by span. Option 4 has prerequisites that do not exist today: the only `mode: taint` rule in the tree is the Java SEI CERT rule `rules/sei-cert/rules/java/ids07-j.yml`, so Rust taint rules for `sql_query`, `command_execution`, `server_side_request` and `deserialization` must be written per sink class; the scans in `src/appsec_review/jobs/job_evidence_collection/adapters.py` (lines 797 and 803) run without `--dataflow-traces`; and the normalizer keeps only the match span, rule id and metadata, so the trace steps must be kept as ordered steps the way `graph/correlate.py` keeps CodeQL SARIF code flows. Costing these is part of choosing option 4; (5) keep the gap as an accepted limit with the upstream cause named.
- **Done when:** either the four rows move from `known_gaps` to expectations and the Rust live test passes with a refreshed recording, or the gap entry names the chosen option, the upstream cause and the re-check version; `tests/graph/test_rust_export.py` passes.
- **Refs:** `tests/fixtures/graph/codeql_export/rust-synthetic/expected-facts.json`, `tests/live/test_codeql_graph_export_rust_live.py`, `rules/registry.toml` (`graph-export-rust`), `containers/tools/codeql/assets.lock.json` `extractors.rust`.

### T-125 — Close or confirm the Rust canonicalize sanitizer gap

- **State:** open
- **Area:** graph
- **Blocks:** T-122
- **Why:** `rust_canonicalize_summary_does_not_propagate` keeps the `path_sanitizers` row for `canonicalize` unmet, and the Rust catalog has one sanitizer rule. Independent of T-124.
- **Scope:** as T-124 for this gap, with the same five options; review whether the Rust sanitizer list should grow toward the other languages' two to six rules.
- **Done when:** the row is an expectation with a refreshed recording, or the gap names the chosen option, upstream cause and re-check version; `tests/graph/test_rust_export.py` passes.
- **Refs:** same files as T-124; `rules/codeql-graph-export/catalog.json` `rust.sanitizers`.

### T-126 — Design the multi-producer plan for code-graph and dataflow facts

- **State:** blocked
- **Area:** graph
- **Blocked by:** T-115, T-120
- **Why:** CodeQL is the only dataflow producer for every language, and `graph/crosscheck.py` cross-checks `call_site` only, with every secondary shard C/C++ (clangd, LLVM IR, Clang AST). Every other language's facts are `not_covered`, nothing in `inference/`, `review/` or `reporting/` reads cross-check state, so a single-producer fact scores and reports like a corroborated one. PHP has no CodeQL extractor, so its only dataflow producers are Semgrep taint and the Psalm taint findings the evidence-collection adapter already parses; today the tree holds one `mode: taint` rule (`rules/sei-cert/rules/java/ids07-j.yml`). No file mentions SCIP. The producer set should be decided once, as a matrix, not one producer at a time.
- **Scope:** design doc only, `docs/architecture/multi-producer-dataflow.md`: (1) a fact-family by producer by language matrix (CodeQL, SCIP, Semgrep/Opengrep taint, Psalm taint, clangd/LLVM/Clang AST, Tree-sitter) stating for each cell primary, second opinion, or none, with PHP as a taint-primary language; (2) a SCIP-based symbol index as the `call_site` cross-check for managed languages; (3) Semgrep/Opengrep taint rules generated per language from `rules/codeql-graph-export/catalog.json` (its sink APIs with argument index, source APIs and sanitizers, keyed to `SinkClass` and `SourceClass`), hash-locked in `rules/semgrep/rules.lock.json` the way `banned-functions.yml` is generated from `appsec-review.toml`, so CodeQL classification and taint rules share one source of truth; the doc states and costs the three prerequisites (per-language pattern syntax in the generator, `--dataflow-traces` on both engine invocations in `job_evidence_collection/adapters.py` lines 797 and 803, a normalizer that retains `dataflow_trace` as ordered steps) and decides between `dataflow_path` corroboration, which needs all three, and `sink_site` corroboration by span, which pattern matches already give; (4) a producer list and a precision tag on every graph fact (Semgrep CE and Opengrep taint are intraprocedural) and a `single_producer` label from `cross_check.state`, carried into admissibility, score and report so a model can tell a corroborated fact from one to hunt; (5) scan-time and rule-count cost per language. Chunked per `.claude/skills/parallel-implementation/SKILL.md`; no implementation. Swift/Objective-C scope is the user's open decision, recorded not decided.
- **Done when:** the design doc exists with the matrix, decisions, chunks and acceptance per chunk; `docs/agent-reader.md` links it; `docs/architecture/code-graph-precomputation.md` D1 points to it for second producers; implementation items (the rule generator, the trace normalizer, the SCIP job, the fact labels) get their own ids.
- **Refs:** `src/appsec_review/graph/crosscheck.py`, `correlate.py`, `contract.py`, `rules/codeql-graph-export/catalog.json`, `src/appsec_review/rulepacks/banned_functions.py`, `src/appsec_review/jobs/job_evidence_collection/adapters.py`, `docs/architecture/code-graph-precomputation.md` D1 and section 4.1, `docs/reviews/review-protocol-second-opinion-brief.md`, T-120, T-124.

### T-127 — Inventory the documentation in a disposition ledger

- **State:** done (2026-11-13, docs/docs-ledger.json)
- **Area:** pipeline
- **Blocks:** T-128
- **Why:** the documentation mixes current architecture, operations, plans and dated records
  without a complete inventory or an explicit disposition for each file.
- **Scope:** Stage 1 of the documentation program. Create `docs/docs-ledger.json` with schema
  `appsec-review/docs-ledger/1`, covering files under `docs/`, `containers/**/README.md`,
  `scripts/README.md` and `AGENTS.md`. Record path, kind, subsystem, disposition, merge target
  when applicable, a one-sentence reason and the decision-record flag. Survey the delta from
  `docs/docs-sync.json` first, then the remaining documents. Keep `docs/walks/` rows host-local
  with disposition `keep`; their content is not a source of rules. Do not rewrite dated decisions.
  The user clarified on 2026-11-13 that the committed ledger covers tracked files only:
  walk entries stay local and are not portable existence requirements. The delivered ledger
  records 342 paths including itself, its inventory commit and the inventory-only survey;
  it does not claim the cumulative behavior delta has been reconciled.
- **Done when:** `tests/docs/test_docs_ledger.py` rejects a tracked document with no row, a row
  naming a missing file, a merge without a target and retirement of a decision record; the ledger
  covers the stated paths, and the docs-sync record names only a commit actually reconciled.
- **Refs:** `docs/tasks/2026-11-13-docs-program-prompt.md` (Stage 1),
  `.claude/skills/docs-sync/SKILL.md`, `docs/docs-sync.json`, `AGENTS.md`,
  `docs/docs-ledger.json`, `tests/docs/test_docs_ledger.py`.

### T-128 — Generate the documentation inventory and enforce frontmatter and links

- **State:** open
- **Area:** pipeline
- **Blocked by:** T-127
- **Blocks:** T-129
- **Why:** job, task, dataset, retrieval and model-guidance facts are repeated in authored prose
  without a generated home or checks that detect drift.
- **Scope:** Stage 2. Add `scripts/generate-docs.py` and `scripts/generate-docs.sh`, reading the
  central configuration through its loader, container catalog, job `DATASETS` and typed
  contracts, MCP tools and retrieval indices, guidance registry, `tests/job-test-map.json` and
  the bucket map when present. Generate `docs/generated/inventory.json`,
  `docs/generated/guidance.md`, marked job-page blocks with the task tree, tools, contracts,
  datasets, routes, model usage, test files, Dagster placement and Mermaid skeleton, plus
  `docs/README.md` and kind indices. Add authored frontmatter and reconciliation markers.
  Output is deterministic, sorted and LF, without timestamps, with source and do-not-edit
  notices. Do not edit the source TOML, catalog, guidance registry or `DATASETS` tables;
  register source defects in this registry instead.
  The link validator must distinguish links from literal Markdown examples in inline or fenced
  code: Stage 1 found the existing `tests/test_documentation.py` regex treating the program
  prompt's inline `relative/path.md#anchor` example as a missing file, unchanged from `145bcceda`.
- **Done when:** `tests/docs/test_generated_docs.py` detects regeneration differences;
  `tests/docs/test_docs_frontmatter.py` rejects missing or invalid frontmatter;
  `tests/docs/test_docs_links.py` rejects unresolved relative links and anchors; and
  `tests/docs/test_docs_identifiers.py` rejects unknown backticked job, task, dataset, schema
  and gap identifiers in authored prose. Each test is independent and under ten seconds.
- **Refs:** `docs/tasks/2026-11-13-docs-program-prompt.md` (Stage 2),
  `appsec-review.toml`, `containers/catalog.toml`, `src/appsec_review/mcp/schema.py`,
  `pipeline/guidance/registry.json`, `tests/job-test-map.json`, `tests/test_documentation.py`,
  T-117, T-127.

### T-129 — Map tools and datasets to intelligence buckets and availability matrices

- **State:** blocked
- **Area:** pipeline
- **Blocked by:** T-128
- **Blocks:** T-130
- **Why:** no single view connects the tools and datasets to intelligence coverage by language,
  retrieval availability and the review roles that can use it.
- **Scope:** Stage 3. Author `docs/intelligence-buckets.json` with schema
  `appsec-review/intelligence-buckets/1`, at most twelve defined buckets and exactly one bucket
  per catalog tool and dataset. Extend `scripts/generate-docs.py` to emit
  `docs/generated/matrix-tool-bucket.md` and `docs/generated/matrix-bucket-availability.md`
  with JSON counterparts. Join tools, jobs and tasks, languages, image state, producers,
  datasets, stages, retrieval indices, MCP tools and role capabilities. Markdown summaries
  have at most seven columns; each empty availability cell names a gap id. Add newly found
  gaps to `docs/TODO.md` in the same commit, linking existing T-115 through T-126 where relevant.
- **Done when:** `tests/docs/test_intelligence_buckets.py` rejects an unmapped tool or dataset,
  a bucket without a definition and an empty matrix cell without a gap id; every tool and
  dataset has exactly one bucket, and generated outputs pass the Stage 2 drift checks.
- **Refs:** `docs/tasks/2026-11-13-docs-program-prompt.md` (Stage 3),
  `containers/catalog.toml`, `src/appsec_review/mcp/schema.py`,
  `pipeline/guidance/registry.json`, T-128, T-115, T-126.

### T-130 — Author job operations pages around the generated contracts

- **State:** blocked
- **Area:** pipeline
- **Blocked by:** T-129
- **Blocks:** T-131
- **Why:** generated job contracts cannot explain a job's purpose, internal decisions, gap
  behavior or the evidence needed to accept its results.
- **Scope:** Stage 4. Create or revise `docs/operations/<job>.md` in
  `tests/job-test-map.json` order and according to the ledger. Include frontmatter, purpose
  and refused claims, the generated block, gap causes with retryable or advisory classification,
  and the walk charter's four acceptance checks. For jobs with real internal logic, add
  per-step pseudocode, internal Mermaid dataflow and gap edges, and resume/invalidation rules.
  Explain model-backed jobs' role and persona choices through links to generated guidance.
  Link shared mechanisms to one canonical architecture or operations page, creating missing
  pages rather than duplicating facts. Leave the T-113 walk's current job page untouched.
- **Done when:** the job-page set matches the ledger and job map, the Stage 2 tests pass,
  `docs/docs-sync.json` names the reconciled commit, and the current T-113 job page is unchanged.
  Each page's acceptance section describes checks; this work runs no integration, acceptance
  or live validation.
- **Refs:** `docs/tasks/2026-11-13-docs-program-prompt.md` (Stage 4),
  `docs/processes/walk-charter.md`, `tests/job-test-map.json`, `docs/docs-sync.json`,
  `docs/architecture/job-interchange.md`, T-113, T-129.

### T-131 — Document the forward testing contract and its enforcement

- **State:** blocked
- **Area:** testing
- **Blocked by:** T-130
- **Blocks:** T-132
- **Why:** the testing documentation must distinguish the tier contract decided under T-113
  from what current guards and scripts actually enforce.
- **Scope:** Stage 5. Revise `docs/architecture/testing.md` around code-level unit tests with
  canned fixtures, no Docker/tools/models, under ten seconds per test and ten minutes per
  suite; integration's 300 s default; live's 1800 s default; job-map tier selection; per-job
  acceptance with the charter's four checks; and `scripts/run-tests.sh` for long runs.
  Name the existing enforcing test, guard or script beside each rule. Mark unenforced rules
  "stated, not enforced" and register their gaps here, reusing existing ids when applicable.
  Keep the short form in `AGENTS.md` linked to the testing page; add no new agent rules.
- **Done when:** `tests/docs/test_docs_links.py` passes, every enforcement reference names an
  existing file and demonstrates the stated guard, and each unenforced rule names a TODO id.
  Documentation checks do not execute integration, acceptance or live tests.
- **Refs:** `docs/tasks/2026-11-13-docs-program-prompt.md` (Stage 5),
  `docs/architecture/testing.md`, `docs/processes/walk-charter.md`, `tests/job-test-map.json`,
  `tests/conftest.py`, `tests/unit/conftest.py`, `scripts/run-tests.sh`, T-113, T-109, T-130.

### T-132 — Write current-state subsystem architecture dives

- **State:** blocked
- **Area:** pipeline
- **Blocked by:** T-131
- **Blocks:** T-133
- **Why:** subsystem behavior is scattered across plans and implementation records, making
  historical decisions easy to mistake for the current implementation.
- **Scope:** Stage 6. Maintain one current-state page under `docs/architecture/` for each of:
  images and deployment; target acquisition and build; code intelligence; scanners and
  evidence collection; review inference and guidance; runtime interchange; reporting and
  metrics; testing and operations. Each has As built today, dated Decisions linking original
  records, Named gaps by T id, Jobs and pages, and Mermaid Dataflow. Mark superseded plans
  and implementation records historical with a current-page pointer, without rewriting their
  dated decisions. Regenerate `docs/architecture/README.md` from frontmatter.
- **Done when:** all eight subsystems have the required current-state page, historical records
  retain their decisions, and the frontmatter, links, identifiers and generated-index checks pass.
- **Refs:** `docs/tasks/2026-11-13-docs-program-prompt.md` (Stage 6),
  `docs/architecture/`, `docs/docs-sync.json`, T-131, T-115, T-116, T-117, T-118,
  T-119, T-120, T-121, T-122, T-123, T-124, T-125, T-126.

### T-133 — Apply approved documentation merges and retirements

- **State:** blocked
- **Area:** pipeline
- **Blocked by:** T-132
- **Why:** duplicate and obsolete non-decision documents remain after current pages exist;
  removing them must not discard decision history or break navigation.
- **Scope:** Stage 7. Stop for the user's decision before deletions, then apply the ledger's
  approved `merge-into` and `retire` dispositions. Delete only non-decision records whose
  ledger reason supports retirement. Leave a one-line pointer for one release after a merge
  before removing the old page, preserving dated decision records. Reconcile
  `docs/docs-ledger.json`, regenerate the indices and record the final reconciled commit in
  `docs/docs-sync.json`. A rendered static site is optional, ignored, derived from Markdown
  and never committed; no site tooling is required to complete the stage.
- **Done when:** approved dispositions are applied without deleting decision records, the ledger
  has no remaining `retire` or `merge-into` rows, all program docs tests and
  `tests/test_todo_registry.py` pass, and the docs-sync record names the final reconciled commit.
- **Refs:** `docs/tasks/2026-11-13-docs-program-prompt.md` (Stage 7),
  `docs/docs-sync.json`, `AGENTS.md`, T-127, T-132.

## Legacy backlog

Former `docs/TODO.md` sections, verbatim, with ids. State: open unless noted.
  Remaining work: T-075.

### T-113 — Walk every job into tests/unit with code-level tests under the enforced tier

- **State:** in-progress
- **Area:** testing
- **Blocks:** T-048, T-109
- **Why:** the unit path held 18,458 tests in 509 files, among them tests that drive whole job
  graphs in-process (10 to 14 minutes each), launch Docker engines, or depend on host tools; two
  comparison runs took 26 to 28 minutes and a full run did not finish. The tier contract decided on
  2026-11-12: unit tests are code-level with canned fixtures and finish in under ten seconds each,
  the whole unit suite in under ten minutes; integration tests may run Docker, tools and models
  against fixtures; acceptance tests run jobs live on Dagster, one job at a time with per-job
  validation (the stepwise process); the former live tier folds into acceptance.
- **Scope:** per job, in registry order: create `tests/unit/<job_id>/`, move the job's genuine
  code-level tests there (the `tests/unit/conftest.py` guard and the 10 s budget then apply),
  replace every test that ran a job graph, an engine, a model or the network with tests of the
  job's own functions (graph shape, validators, handler wiring, parsers, normalizers, bounds), and
  send the removed graph-level tests to `tests/integration/<job_id>/` or delete them when the
  replacement covers the same claims. Shared packages get `tests/unit/<package>/`; cross-tier
  helpers move to `tests/shared/`. Each job lands as one commit that updates
  `tests/job-test-map.json`. Each job is one fresh session with the brief in
  `docs/processes/test-tier-walk-prompt.md`, in `builtin_registry` order, on local `main`. Done so
  far: job_third_party_data_sync (the 88 s whole-job run replaced by graph, publication,
  cve-bin-tool and OSV feed tests); job_project_build (17 code-level tests kept, 25 graph cases
  moved to `tests/integration/job_project_build/`, new graph, contract, repair and enforcement
  tests); job_language_build (27 unit files, 628 cases: 14 whole code-level files moved in, the
  nine family files split with their graph cases parked under
  `tests/integration/job_language_build/`, the live toolchain and Gradle checks under
  `tests/acceptance/job_language_build/`, new contract, graph, handler-wiring and receipt/path
  tests); job_build_iteration (6 unit files, 46 cases: new contract and job-wiring tests, the
  controller's code-level cases, the four self-contained executor-capture cases and the two
  workspace-resume cases moved in; the replay, CLI, replay-executor and controller-recovery
  suites, whose fixtures publish through JobRunner at 8 to 20 s of setup, parked under
  `tests/integration/job_build_iteration/` with their pre-existing failures named);
  job_artifact_indexing (9 unit files, 171 cases: new contract, graph/validator/loader, identity,
  receipt-validation, target-intake, catalog, member, relation and shard-reuse tests, the batching
  cases of the throughput suite and the `_target_artifacts` provenance cases moved in; the
  `_seed`-based graph suite, the two runner-level throughput cases and the shared input-contract
  suite parked under `tests/integration/job_artifact_indexing/`, where 40 cases already failed at
  HEAD 05ac85ae because the synthetic language-build handoff is no longer admitted; the shard-layout
  oracle test moved to `tests/acceptance/job_artifact_indexing/`);
  job_debug_symbol_indexing (15 unit files, 194 cases: new contract, graph/validator/reader-identity,
  accepted-inputs, decision, probe/privacy, source-resolution, extraction, normalization,
  publication and accepted-loader tests over a real `JobContext` with the upstream readers and the
  symbol reader faked at their boundaries; the workflow, source-bounds, metrics and host-binding
  files moved in whole, the settings and build-image-identity cases moved in from the graph and
  execution suites; the `_seed`-based whole-DAG suite, the fake-engine production-path suite and
  the genuine-fixture end-to-end suite parked under `tests/integration/job_debug_symbol_indexing/`,
  where at HEAD 308d8b75 the two JobRunner cases fail at admission and all six end-to-end cases
  fail on a stale `tools` reader setting; the `target_decision` declaration/schema mismatch found
  by the contract test is T-114); job_model_connectivity (3 unit files, 64 cases:
  contract, graph, validators and step behavior; whole-job and dispatch cases moved to
  `tests/integration/job_model_connectivity/`; full job-package line and branch coverage);
  job_image_pin_verification (7 unit files, 122 cases: contract, graph, configuration,
  host bindings, image inspection and update boundaries; 15 whole-graph cases preserved in
  `tests/integration/job_image_pin_verification/`; full job-package line and branch coverage);
  job_review_intake (5 unit files, 133 cases: contract, configuration, target and binary-evidence
  handling, model discovery; 14 graph cases preserved in `tests/integration/job_review_intake/`;
  full job-package line and branch coverage). The unit manager resumed in registry order;
  job_target_acquisition is blocked on its published `/2` versus declared `/1` schema mismatch.
  Next: job_target_catalog.
  Integration follow-up:
  job_third_party_data_sync has eight files / 24 cases (19 passed, five named prerequisite
  skips): real loopback TLS, NVD range resume and incremental pagination, reference parsers,
  immutable filesystem publication and declared work artifacts. The two existing boundary
  files moved into its folder; no graph cases, acceptance moves or deletions were needed.
  Pinned-tool proof remains incomplete: Grype's local tag differs from the host pin;
  cve-bin-tool lacks an exact configured pin and its observed image is unsigned. The successful
  Grype import also needs a tiny fresh v6 fixture with a provenance sidecar. Synthetic unit
  doubles are not tool recordings; no verified tool-output fixture provenance is claimed.
  A real three-unit KEV executor branch checks HTTP/parser failure receipts, dependent skips
  and unchanged publication; full-job lifecycle and accepted-handoff behavior remain outside
  this bounded folder.
  The wrapper currently requires file selectors, so the integration folder is selected with
  `tests/integration/job_third_party_data_sync/test_*.py`, not a directory argument.
  job_project_build now has four bounded integration test files / 19 cases, separate from
  seven retained graph/target acceptance suites. The three old modules imported by unit tests
  keep only shared helpers at their existing paths; no unit test or unit fixture was edited.
  One redundant graph-shape case was deleted in favor of the published unit graph test.
  At base `bc511ce9cede09ab793a29ff62f12dec8220580f`, the exact four-file selection, guarded
  with `--expect-tests 19`, four workers and shuffle seed `111213`, reported **0 passed,
  19 skipped** in 3.18 s (wrapper total 7.88 s; slowest prerequisite skip 0.765 s; no case
  above 300 s). This is authored coverage, not verified real-tool integration.
  Distinct skip prerequisites: native/C++ pin mismatch (10 cases), shared Rust/WebAssembly
  pin mismatch (2), and Android, .NET, Go, Java, Node, PHP and Python mismatches (1 each):
  nine distinct image identities, ten profiles. Additional prerequisites masked by those
  skips are the capture scanner's `tool-gitleaks` pin mismatch and missing expected-image
  signature (the same three capture cases, not six extra skips), plus missing verified
  compiler-diagnostic provenance (one already-skipped case). Build-image signature envelopes
  themselves verified; no pin, image or signing setting changed.
  No tool-output fixture has verified provenance; synthetic binary/APK/layout inputs remain
  synthetic. Real native enforcement/accepted-handoff parity, shared topology recovery,
  full-family builds and provisioned Unity acceptance remain unrun, and the retained
  acceptance suites' historical assumptions are not revalidated by moving them.
  No model call is required by the current reachable job handlers; the old repair-model
  helper is uncalled. Inventory and scope are in `docs/operations/project-build.md`.
  Integration command:
  `scripts/run-tests.sh --allow-heavy --timeout-seconds 1800 --expect-tests 19 --parallel --test-workers 4 --shuffle-seed 111213 -- tests/integration/job_project_build/test_executor.py tests/integration/job_project_build/test_native_artifacts.py tests/integration/job_project_build/test_capture_boundary.py tests/integration/job_project_build/test_fixture_provenance.py`.
  Report: `test/tmp/reports/tests-custom-20261112-160740-911797-89546.json`
  (matching log, JUnit and timing database retained under `test/tmp/`).
  Required bookkeeping:
  `scripts/run-tests.sh --expect-tests 118 --parallel --test-workers 4 --shuffle-seed 111214 -- tests/test_todo_registry.py tests/test_job_test_selection.py tests/test_pytest_default_collection.py`
  passed all 118 cases in 7.49 s (wrapper total 12.54 s), with no slow tests or skips;
  report `test/tmp/reports/tests-custom-20261112-160859-476787-93832.json`.
  `.venv/bin/ruff check tests/integration/job_project_build tests/integration/test_node_project_builds.py tests/acceptance/job_project_build tests/acceptance/test_unity_workflow.py`
  and `git diff --check` passed. No job unit suite, acceptance, live or Dagster execution
  was run. The only completed gap closure here is tier separation; real-tool validation
  remains blocked by the named prerequisites.
  Follow-up (2026-11-12, superseding those integration prerequisites, not the historical run):
  the tests now use the shared `inspect_image` lookup for each configured tag, verify the
  installed image's existing signature, and freeze its immutable ID for execution. All nine
  installed build images and installed Gitleaks image were already signed. The historical
  Gitleaks signing gap referred to its obsolete configured identity; no keys, signatures or
  production host bindings needed alteration. The existing production pin gate is unchanged.
  All 19 real cases passed with zero skips in 12.39 s (wrapper total 17.54 s, slowest 3.939 s),
  using the same four selectors, `--expect-tests 19`, four workers and shuffle seed `111215`.
  Report: `test/tmp/reports/tests-custom-20261112-185541-501547-7567.json`.
  The compiler diagnostic now has one genuine raw-stderr recording and adjacent provenance
  sidecar under `tests/integration/job_project_build/fixtures/`, produced by the signed
  Clang 18.1.3 image. Replay checks measured image/version, catalog version, input/output
  hashes and parity with the unchanged unit example. Regeneration is explicit through
  `python -m tests.integration.job_project_build.fixture_recording --write`, never automatic
  in tests. No unit-owned test or fixture was edited.
  Final verification with JUnit image/signature properties: the same 19-case command
  (`--shuffle-seed 111215`) passed all cases in 11.81 s (wrapper total 16.53 s, slowest
  3.207 s, no skips); report
  `test/tmp/reports/tests-custom-20261112-185827-369531-18858.json`.
  The three required bookkeeping files, selected exactly as above with `--expect-tests 118`,
  four workers and shuffle seed `111216`, passed all 118 in 6.61 s (wrapper total 11.67 s,
  no skips or slow tests); report
  `test/tmp/reports/tests-custom-20261112-185845-488139-22434.json`.
  Ruff on `tests/integration/job_project_build` and `git diff --check` passed.
  Full-job enforcement, accepted-handoff/resume parity and family/Unity acceptance remain
  outside the authorized integration-only repair. Deliberately synthetic negative binary,
  APK and layout unit inputs remain synthetic; they are not claimed as historical recordings.
- **Done when:** `tests/` has no `test_*.py` outside `tests/unit`, `tests/integration`,
  `tests/acceptance` and `tests/shared`; `scripts/run-tests.sh fast` collects only `tests/unit`
  and finishes in under ten minutes with zero tests over 10 s; every job in the registry has a
  `tests/unit/<job_id>/` folder named in the job-test map.
- **Refs:** `tests/unit/conftest.py`, `tests/unit/test_tier_guard.py`, `tests/time_budgets.py`,
  `docs/architecture/testing.md` ("The tests/unit/ tier", "The test-tier walk"),
  `docs/processes/test-tier-walk-prompt.md`, `docs/processes/integration-tier-walk-prompt.md`,
  `tests/job-test-map.json`.

### T-114 — Declare the debug-symbol decision dataset with the schema the job writes

- **State:** open
- **Area:** binary
- **Why:** `job_debug_symbol_indexing/datasets.py` declares the `target_decision` dataset with schema
  `appsec-review/debug-symbol-decision/1`, while `debug_symbols/contract.py` sets
  `DECISION_SCHEMA = "appsec-review/debug-symbol-decision/2"`, which `_decision` writes into
  `decision.json` and `_read_decision` / `load_accepted_debug_symbols` require. The declaration
  was not bumped when the decision gained its frozen execution plan, so the published document
  never carries its declared schema id (found by the T-113 contract test on 2026-11-13).
- **Scope:** declare `target_decision` with `DECISION_SCHEMA` (or derive the declaration from the
  contract constant), and make `tests/unit/job_debug_symbol_indexing/test_contract.py` assert the
  declared schema for the decision like the other documents instead of the written constant.
- **Done when:** the contract test pins `declared["target_decision"].schema == DECISION_SCHEMA` and
  the `TODO(T-114)` comment in it is gone.
- **Refs:** `src/appsec_review/jobs/job_debug_symbol_indexing/datasets.py`,
  `src/appsec_review/debug_symbols/contract.py`,
  `tests/unit/job_debug_symbol_indexing/test_contract.py`.

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

- **State:** done (2026-11-12, docs/operations/third-party-data-sync.md)
- **Area:** data
- **Blocks:** T-105
- **Why:** the manual publisher did not perform pinned Grype validation or provide a bounded,
  provenance-checked nightly database refresh. Archived bytes lacked usable database provenance.
- **Scope:** independent `grype_db_sync` fetch/import/publish branch, typed limits, verified HTTPS
  acquisition, bounded zstd/tar extraction, supported offline Grype import/status, immutable
  `grype-snapshot/2` publication and existing bounded scanner consumers. Replace the manual
  publisher without enabling scanning or redesigning matching.
- **Done when:** focused offline units establish branch/config/registry parity, resource and
  freshness rejection, pinned-tool validation, file hashes, last-known-good preservation,
  publication provenance and consumer gaps. Actual upstream/Docker/native validation and
  activation remain explicitly unrun; nightly restart is T-106.
- **Refs:** [operations](operations/third-party-data-sync.md#grype-database-cache);
  `src/appsec_review/jobs/job_third_party_data_sync/steps/grype_db_sync/`;
  `tests/test_grype_db_sync.py`; T-105; T-106.

User decision 2026-11-12: the nightly sync may reach the network for database bytes; scanners stay
`network = "none"`. The implementation adds the runtime `zstandard` dependency; deployment requires
a separately authorized Dagster image rebuild, not just source reload. No images, host pins,
deployment, nightly run, acceptance or live review are changed by the implementation task.

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

1. Go: done 2026-11-11 (`71063c16`, unit tests only; no real Go build exercised):
   `vendor/modules.txt` written by a recipe's `go mod vendor`.
2. PHP Composer (next): `vendor/composer/installed.json`; also move `composer_metadata` production packages
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

Update 2026-11-12 (dependency plan): the installed and resolved dependency summaries become finders behind the
registry of T-099, in the order above. Package-manager tools that need network egress to resolve are
pre-authorized by the user (2026-11-12).

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

Progress 2026-11-11: a version matcher against the snapshot index (`src/appsec_review/osv_matching.py`,
default off) exists on branch `wave2-osv` (`5bf3475a`) and is not merged: it bumps the sync-step
output schema `osv-index/1` to `/2`, so its effect on reuse of an accepted third-party sync output
must be checked first. Still open after that merge: wiring the matcher into evidence collection in
place of the per-project osv-scanner launch, and measuring memory against the 2.2 GB baseline.

Update 2026-11-12 (dependency plan): after the merge, the matcher consumes the merged inventory as one matcher of
the stage T-105, and gains non-SemVer orderings and `GIT` ranges.

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
