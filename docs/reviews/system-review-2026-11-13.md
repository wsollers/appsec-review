---
title: "Appsec-review system review, 2026-11-13"
kind: "review"
subsystem: "overview"
status: "current"
jobs: []
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---

# Appsec-review system review, 2026-11-13

- **Commit reviewed (primary anchor):** `f29ee4c688bce7d0d7ca2f1b30a9477a63647ad1` (`main`, 2026-11-13)
- **Post-anchor reconciliation window:** `f29ee4c688..35aa97b3f` (`main`, 2026-11-14; concurrent repair waves and `T-146`–`T-167` / `T-5001` updates explicitly credited inline and in Section 9)
- **Prior baseline compared:** [Appsec-review: system review and downstream verification plan](appsec-system-review-2026-11-06.md) (`967a1072bc19feeb320ce4b44d6c056616c94d7b`, 2026-11-06)
- **Method:** Bottom-up source, configuration, schema, rule-pack, container-catalog, test, and documentation audit across 18 components (`C01`–`C18`) covering all 47 registered jobs in `docs/generated/inventory.json`. Every `critical` finding (21/21 candidates: 20 confirmed, 1 downgraded to `low`) and every `high` finding (91/91 candidates: 90 confirmed, 1 withdrawn) plus a stratified sample of 32 `medium`/`low` findings was re-verified directly against `git show f29ee4c688:<path>`, and all 1,111 repo-relative `path:line` citations were mechanically bounds-checked against `f29ee4c688`.
- **What was not covered:** No integration, acceptance, or live Dagster/container/LLM runs were executed during this review; external answer-key repositories (`appsec-multi-vuln-guide` and `appsec-review-smoke-guide`) were never inspected; the gitignored `old/` archive was not read; files sampled or in-scope not opened are listed in Section 9.
- **Finding totals:** **280 verified active component findings** (`20 critical`, `90 high`, `138 medium`, `32 low`; plus 1 withdrawn on spot-check, `C09-F06`). Collapsing 10 cross-component manifestations onto 8 primary root-cause IDs yields **270 unique deduplicated findings (`20 critical`, `82 high`, `136 medium`, `32 low`)**.

| Component | Scope | Critical | High | Medium | Low | Active | Unique |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `C01` | Runtime core, job interchange and storage | 0 | 3 | 7 | 2 | 12 | 12 |
| `C02` | Configuration, profiles and run selection | 2 | 4 | 8 | 1 | 15 | 14 |
| `C03` | Orchestration, deployment and operator surface | 1 | 4 | 12 | 2 | 19 | 19 |
| `C04` | Container images, signing and supply chain | 1 | 1 | 5 | 1 | 8 | 8 |
| `C05` | Target acquisition, intake, catalog and analysis planning | 0 | 2 | 6 | 3 | 11 | 9 |
| `C06` | Build and execution capture | 2 | 5 | 8 | 1 | 16 | 16 |
| `C07` | Syntax, CodeQL and the code graph | 2 | 8 | 8 | 2 | 20 | 20 |
| `C08` | Native and binary analysis | 3 | 6 | 6 | 1 | 16 | 16 |
| `C09` | Scanners, rule packs, dependencies and advisory feeds | 2 | 10 | 6 | 0 | 18 | 18 |
| `C10` | Context signals | 0 | 3 | 4 | 2 | 9 | 9 |
| `C11` | Evidence indexing, retrieval and review packaging | 1 | 7 | 11 | 1 | 20 | 20 |
| `C12` | Control and threat modelling | 0 | 6 | 9 | 3 | 18 | 18 |
| `C13` | Model execution and worker guidance | 1 | 5 | 9 | 1 | 16 | 16 |
| `C14` | The review protocol | 2 | 6 | 10 | 2 | 20 | 19 |
| `C15` | Evidence completion: proof of concept and remediation | 1 | 4 | 9 | 3 | 17 | 16 |
| `C16` | Publication and reporting | 2 | 6 | 7 | 3 | 18 | 16 |
| `C17` | Observability, metrics and quality measurement | 0 | 5 | 10 | 2 | 17 | 15 |
| `C18` | Tests, acceptance harness and repository process | 0 | 5 | 3 | 2 | 10 | 9 |
| **Total** | **18 components, 47 registered jobs** | **20** | **90 (82 unique)** | **138 (136 unique)** | **32** | **280** | **270** |

---

## 1. Executive judgment

Since the 6 November 2026 review (`967a1072bc`), `appsec-review` has grown real architectural spine: detached Ed25519 signing and verified-byte Python imports (`signing/`), typed `JobContract` consumption with read receipts (`runtime/consume.py`), bounded CodeQL graph exports (`job_codeql_analysis` + `job_code_graph_index`), hardened synthetic `/gitdir` history extraction (`job_source_history_analysis`), content-addressed SQLite retrieval shards (`job_review_data_indexing`), and a multi-role adversarial review protocol (`job_inference_security_review`) backed by a transitive-hash publication gate (`job_final_publication_gate`). Yet on the first two questions that matter—**does it find real security issues, and does it keep evidence honest?**—the system still drops or distorts critical truth at its seams. Published findings are verified syntactically at `file:line` (`review/evidence.py`) without proving that a cited guard fails rather than holds (`C14-F01`, now mid-flight under `T-152`), `job_poc_generation` compiles C/C++ harnesses without ever executing them (`C15-F01`), `job_final_publication_gate` ignores pre-review scanner/build gaps when certifying run completeness (`C16-F01`), and `job_final_report_publication` strips finding statements, CWEs, and `file:line` locators from `final-report.json` (`C16-F04`). Simultaneously, redaction fails in both directions at once: a substring regex in `retrieval/model.py` and `observability/events.py` replaces safe tags and identifiers like `auth_token` and `secret_handling` with `"<redacted>"` (`C11-F01`, `C17-F03`), while `RetrievalCore.read_excerpt` streams unredacted target credentials directly into worker prompts, judge citations, and failure logs (`C13-F01`, `C17-F04`).

On the third question—**does it run reliably on real targets?**—the honest answer at `f29ee4c688` is **not yet across non-trivial polyglot or native C/C++ repositories, and its green lights can be misleading**. Twenty-three of 25 production `container_runtime.catalog.load_catalog()` call sites omit `resolved_config`, leaving `expected_image_id=None` and bypassing `T-051`'s host-pin digest check at container launch (`C04-F01`). In the native C/C++ lane, `job_language_build` mounts `/capture/tools` writable inside the untrusted build container and accepts unauthenticated `/capture/traces` files (`C06-F01`, `C06-F07`), falls back to zero-TU static dispatches that still report `COMPLETED` (`C06-F02`), and hands `job_cpp_compiled_analysis`, `job_clang_static_analysis`, `job_cpp_symbol_index`, and `job_svf_alias_analysis` a broken `.appsec-review-link-commands.json` path (`link_commands=[]`), `ignore_patterns("build", "target")` source exclusions, and unmapped `/workspace` include flags (`C08-F01`–`C08-F04`). Meanwhile, `job_target_analysis_plan` leaves `accepted_artifacts` hardcoded to `()` so `tool-spotbugs` and `tool-blint` are never selected (`C05-F02`), single-model `dev` and `copilot-dev` profiles silently disable verifier model distinctness (`C02-F06`), and `stepwise.py system` can report `SYSTEM OK` when `job_inference_security_review` publishes zero confirmed findings so long as raw deterministic scanners touched the answer-key lines (`C18-F01`).

On the fourth question—**does every piece earn its complexity?**—roughly four-fifths of the 47-job graph earns its keep once its seams are repaired, while **7 jobs and several duplicated passes are carrying uncollected rent**. `job_cpg_analysis` (`C07-F13`), `job_document_issue_analysis` (`C10-F04`), and `job_review_package_assembly` (`C11-F03`) should be retired (`3` jobs), and `job_build_iteration` (`C06-F13`), `job_post_build_security_assessment` (`C08-F11`), `job_change_context_analysis` (`C10-F03`), and `job_review_prioritization` (`C11-F04`) should be merged into their adjacent owners (`4` jobs), cutting the topology from 47 jobs to 40 while eliminating hundreds of sequential per-file `docker run` startups, duplicate `git blame`/Tree-sitter passes, and dead artifacts (`enriched.spdx.json`, `native-sbom-provenance.json`, `cve-bin-tool`, `packages/*.json`). The overarching prescription mirrors and sharpens November 6's conclusion: **do not add new analysis stages; seal the trust, redaction, native-build, warrant, report-schema, and acceptance-gate seams so one end-to-end run means what its receipts claim**.

---

## 2. Top recommendations

Ranked strictly by end-to-end leverage across review honesty, host/supply-chain custody, native/polyglot recall, and regression detection:

1. **Replace dual-broken redaction with structured secret detection across retrieval, worker excerpts, and logs (`C11-F01`, `C13-F01`, `C17-F03`, `C17-F04`)** — *Effort: `M` | Depends on: none.*
   Remove the key-name substring regex `(?i)(authorization|password|passwd|secret|token|api[_-]?key|credential)` from `retrieval/model.py:236,276` and `observability/events.py:21,43` so taxonomy tags (`auth_token`, `secret_handling`), symbol names (`token_count`), and file paths stop turning into `"<redacted>"`, and route `RetrievalCore.read_excerpt` (`retrieval/core.py:694-725`), PoC/remediation source readers, failure recordings, and `EventLog` payloads through `secret_redaction.py`'s value-level credential scrubber. **Why #1:** Today the system simultaneously blinds its own auth/secret capability routing and leaks real target secrets to external LLM providers and run logs.

2. **Finish wiring semantic warrant and guard-polarity verification (`T-152`) and enforce multi-model verifier distinctness (`C14-F01`, `C02-F06`, `C14-F06`)** — *Effort: `M` | Depends on: #1.*
   Complete integration of `review/warrants.py` (`predicate-warrants/1`, landed in `c12d9ef45`) into `review/evidence.py`, challenger/judge prompts, and `job_inference_security_review` acceptance so a cited guard or sanitizer at `file:line` cannot be cited with inverted polarity to confirm a mitigated sink, and fail closed (or downgrade maximum finding confidence below `confirmed`) when `verifier_model_distinct` is `False`. **Why #2:** Syntactic line-existence checks without semantic warrant polarity are the single largest source of plausible-looking false positives in LLM security review.

3. **Make `final-report.json` / `final-report.md` self-contained and make `job_final_publication_gate` honor upstream coverage gaps (`C16-F01`, `C16-F04`, `C16-F05`)** — *Effort: `M` | Depends on: #2.*
   Restore finding statements, CWE IDs, resolved `file:line` evidence locators, warrant summaries, and structured gap descriptions to `appsec-review/final-report/2` (`job_final_report_publication`), feed `job_review_data_indexing`'s `producer-inventory.json` and pre-review `producer-gap/1` ledger into `job_final_publication_gate` so blind runs cannot publish as unqualified clean reviews, and decouple failed optional attachment jobs (`WHEN_ENABLED`) from hard-aborting the gate. **Why #3:** Even accurate review decisions are unusable if the terminal report strips `file:line` locators and certifies blind spots as complete.

4. **Repair acceptance gating (`stepwise.py system`), Hunt-lane funnel attribution, and finding-level precision scoring (`C18-F01`, `C18-F02`, `C18-F03`, `C16-F07`)** — *Effort: `M` | Depends on: #3.*
   Require an accepted `job_final_report_publication` handoff in `acceptance/system.py:final_artifact_problems`, score required defects and `control_violations` against published review findings rather than raw scanner observations, evaluate all 5 funnel stages in `acceptance/funnel.py` via `accepted_handoff` so pure `Lane B` (`hypothesis_hunter`) findings reach `published`, and deduplicate `producer == "review"` reports by `finding_id` in `acceptance/scoring.py`. **Why #4:** Without an honest scoreboard, regressions in `C14`–`C16` pass `SYSTEM OK` unnoticed and multi-line evidence chains are penalized as multiple false positives.

5. **Enforce `resolved_config` host-pin binding in `load_catalog()` and unify pin discovery with `job_image_pin_verification` (`C04-F01`, `C04-F02`)** — *Effort: `M` | Depends on: none.*
   Make `resolved_config` mandatory on production `container_runtime.catalog.load_catalog()` calls (fixing all 23 unpinned call sites and `ContainerExecutor.resolve_image()`), include `preinstalled_runtimes` and `("image", "image_id")` step pairs in `job_image_pin_verification/pins.py`, and remove `"present"` (`expected is None`) from `PASSING`. **Why #5:** Restores fail-closed container digest custody across every scanner, AST, build-secret, indexing, and PDF container launch.

6. **Seal build-capture trust boundaries and eliminate silent zero-TU static fallback (`C06-F01`, `C06-F02`, `C06-F07`, `C03-F01`, `C05-F03`)** — *Effort: `M` | Depends on: #5.*
   Mount `/capture/tools` read-only (`:ro`) in `BuildContainerExecutor`, authenticate or cross-validate compiler wrapper trace records against parent `strace` execve trees (`C06-F07`), emit `COMPLETED_WITH_GAPS` / `PARTIAL` (never clean `COMPLETED`) when `job_language_build` produces zero translation units or falls back to static dispatches, and set `GIT_CONFIG_GLOBAL=/dev/null` + `GIT_CONFIG_NOSYSTEM=1` on host `git` subprocesses while mounting `targets` `:ro` where writes are unnecessary. **Why #6:** Protects the host/build boundary against malicious target repositories and stops zero-TU builds from masquerading as compiled coverage.

7. **Unblock the C/C++ compiled analysis chain (`C08-F01`, `C08-F02`, `C08-F03`, `C08-F04`, `C07-F14`)** — *Effort: `M` | Depends on: #6.*
   Fix `job_cpp_compiled_analysis`'s `.appsec-review-link-commands.json` lookup path (unlocking `job_svf_alias_analysis` whole-program bitcode linking), remove recursive `ignore_patterns("build", "target")` that drops legitimate source trees (e.g., Rust/C++ `src/target/` or `src/build/`), rewrite `-I/workspace/...` compiler flags alongside `directory`/`file` to `/scratch/source`, and mount or extract build-image system/SDK headers for replay in `clang_static_analysis`, `cpp_symbol_index`, and `cpp_compiled_analysis`. **Why #7:** Repairs four downstream C/C++ jobs (`job_cpp_compiled_analysis`, `job_clang_static_analysis`, `job_cpp_symbol_index`, `job_svf_alias_analysis`) from one shared root cause.

8. **Fix `accepted_artifacts` in `job_target_analysis_plan`, close remaining `latest.json` bypasses, and resolve `SKIPPED_NA` control mismatches (`C01-F01`, `C01-F02`, `C05-F01`, `C05-F02`, `C15-F02`, `C16-F08`)** — *Effort: `M` | Depends on: none.*
   Populate `accepted_artifacts` from `job_review_intake` / `job_artifact_indexing` so `tool-spotbugs` and `tool-blint` activate when bytecode/binaries exist; replace direct `latest.json` reads in `job_build_environment_analysis` and `job_openvex_export` with `accepted_upstream`; and reconcile `ProducerStatus.SKIPPED_NA` across `UnitExecutor`/`JobRunner` so zero-eligible-finding runs in `C15` and optional coverage/profile runs in `C10` do not fail or manufacture bogus gaps. **Why #8:** Restores contract integrity across job boundaries and re-enables dormant bytecode/binary scanners.

9. **Retire 3 dead-end jobs and merge 4 redundant jobs (`C07-F13`, `C10-F04`, `C11-F03`, `C06-F13`, `C08-F11`, `C10-F03`, `C11-F04`)** — *Effort: `M` | Depends on: #4, #8.*
   Retire `job_cpg_analysis`, `job_document_issue_analysis`, and `job_review_package_assembly`; merge `job_build_iteration` into `job_language_build`, `job_post_build_security_assessment` into `job_artifact_security_analysis`, `job_change_context_analysis` into `job_source_history_analysis` (batching per-file `git blame` and AST runs into one container pass), and `job_review_prioritization` into `job_review_data_indexing` / `review/ranking.py`. **Why #9:** Eliminates 7 job boundaries, up to 555 sequential per-file `docker run` launches per repository, and hundreds of unused declared `InputRequirement`s.

10. **Fix `job_test_coverage` denominator inflation and `job_profile_data` build-wide hotspot broadcast (`C10-F01`, `C10-F02`)** — *Effort: `S` | Depends on: none.*
    Track per-file `(line_number -> max_hits)` maps in `job_test_coverage` instead of summing `lines_total` across duplicate `<class>` or LCOV sections, and resolve profiler `source` paths against `job_target_catalog` in `job_profile_data` (changing `review/units.py:77` so `location=None` hotspots never broadcast to every review unit in a build). **Why #10:** High-leverage, small-effort fix that stops corrupted context signals from skewing review-unit prioritization.

11. **Expand GitHub Actions CI (`.github/workflows/quality.yml`) to run repository merge gates and affected unit suites (`C18-F05`, `C18-F06`)** — *Effort: `M` | Depends on: none.*
    Add `tests/test_000_unit_environment_guard.py`, `tests/test_skill_separation.py`, `tests/test_todo_registry.py`, `tests/test_gap_contract.py`, `tests/test_time_budgets.py`, `tests/docs/*`, and `tests/job-test-map.json`-mapped unit tests to `.github/workflows/quality.yml`, and scope `tests/unit/conftest.py` monkeypatches strictly to `tests/unit/` items. **Why #11:** Prevents broken merge gates and unmapped regressions from landing on `main`.

12. **Build isolated runtime verification (`T-047`) for PoCs, sanitizer binaries, and remediation re-testing (`C15-F01`, `C15-F04`, `C06-F10`)** — *Effort: `L` | Depends on: #2, #6.*
    Execute generated PoC harnesses and `job_sanitizer_build` ASan/UBSan targets inside networkless, resource-capped ephemeral containers (`ContainerExecutor` / `engine_broker`), require a deterministic crash/oracle differential before elevating a finding to `verified`, and re-run that oracle in `job_remediation_validation` to prove the proposed patch actually neutralizes the defect. **Why #12:** Completes the epistemic loop from plausible static/LLM reasoning to behavioral proof, sequenced after trust-boundary and warrant fixes (`#1`–`#6`).

---

## 3. Cross-cutting themes

### Theme 1: Control-plane contracts bypassed by direct `latest.json`, `attempts/*`, or unpinned helper reads
`appsec-review` invested heavily in `runtime.consume.accepted_upstream`, claim-pinned `upstream_handoffs`, and `host-pins.toml` (`C01`, `C04`), yet callers repeatedly route around them. `job_build_environment_analysis` (`C05-F01` / `C01-F02`) and `job_openvex_export` (`C16-F08`) read `published/latest.json` directly; `job_build_iteration` exchanges unpinned `request.json`/`result.json` files outside DAG handoffs (`C06-F13`); `job_clang_static_analysis` and `job_cpg_analysis` read upstream data through `cpp_index_scopes` / `resolve_context_manifest` without `JobContract` enforcement (`C07-F13`, `C08-F09`); `job_target_acquisition` re-parses raw `appsec-review.toml` instead of `resolved.json` (`C05-F10`); `copilot_sdk.verify()` calls `load_config()` without the active profile or overlay (`C02-F10`, `C02-F15`); `reporting/sources.py:RunReader` and `acceptance/funnel.py` glob `attempts/*` instead of `accepted_handoff` (`C16-F07`, `C18-F02`); and 23 of 25 production `load_catalog()` callers omit `resolved_config`, nullifying `expected_image_id` (`C04-F01`).

### Theme 2: Dual-extreme secret redaction—corrupting safe identifiers while leaking real target secrets
Redaction is broken in opposite directions in two adjacent layers. In `retrieval/model.py:236,276` and `observability/events.py:21,43`, a substring regex (`authorization|password|passwd|secret|token|api[_-]?key|credential`) fires on dictionary values and string fields indiscriminately, replacing security tags (`auth_token`, `secret_handling`), symbol names, and paths with `"<redacted>"` (`C11-F01`, `C17-F03`). Meanwhile, `secret_redaction.py` only wraps `PackageView`, leaving `RetrievalCore.read_excerpt` (`C13-F01`), PoC and remediation file readers (`C15-F07`), inference failure recordings, and `EventLog.write` (`C17-F04`) streaming unredacted target credentials and prompt-injection payloads into external model APIs and run artifacts.

### Theme 3: Epistemic inflation—syntactic citations, compile-only PoCs, and blind gates presented as stronger proof
Across build, analysis, review, and publication, weaker checks are recorded under labels that imply stronger verification:
- `job_language_build` can emit zero compiled translation units via static fallback while reporting `COMPLETED` (`C06-F02`), and `job_codeql_analysis` / `job_code_graph_index` lose interprocedural edges and C++ guard scopes (`C07-F01`–`C07-F03`).
- `job_inference_security_review` checks that cited files, line spans, and entity IDs exist (`review/evidence.py`), not that a cited predicate or guard allows attacker-controlled values through (`C14-F01`; `review/warrants.py` landed in `c12d9ef45` and still awaits `evidence.py`/judge enforcement).
- `job_poc_generation` compiles C/C++ reproducers (`-fsyntax-only` / link check) without running them (`C15-F01`), and `job_remediation_validation` checks syntax/build without re-running the triggering scanner or PoC (`C15-F04`).
- `job_final_publication_gate` validates post-review artifact hashes while ignoring pre-review scanner/build gaps (`C16-F01`), and `job_final_report_publication` strips statements, CWEs, and `file:line` locators from `final-report.json` (`C16-F04`).

### Theme 4: Native C/C++ workspace and toolchain drift across jobs
The C/C++ pipeline spans `job_project_build` -> `job_language_build` -> `job_cpp_compiled_analysis` -> `{job_clang_static_analysis, job_cpp_symbol_index, job_svf_alias_analysis, job_post_build_security_assessment}`. Small path and mount mismatches compound across those hops: `job_cpp_compiled_analysis` looks for `.appsec-review-link-commands.json` at the wrong path (`link_commands=[]`, crippling `job_svf_alias_analysis` in `C08-F01`), strips directories named `build` or `target` at any depth (`C08-F02`), rewrites `directory`/`file` from `/workspace` to `/scratch/source` without rewriting `-I/workspace/...` flags (`C08-F03`), and replays clang/clangd/infer inside tool containers that lack the derived build image's system/SDK headers (`C08-F04`, `C07-F14`).

### Theme 5: Severe container and subprocess startup multiplication
Instead of batching file lists into one hardened container or SQLite pass, several jobs spawn one container or full AST load per file or target: `job_source_history_analysis` and `job_change_context_analysis` launch up to 555 sequential one-file `docker run` invocations per repository while loading whole-repo Tree-sitter JSONL into memory (`C10-F03`); `job_model_connectivity` probes model endpoints with serial timeout multiplication (`C13-F09`); `job_openvex_export` re-hashes large upstream artifacts four times (`C16-F13`); and `job_dossier_publication` renders duplicate LaTeX PDFs for `confirmed_finding` + `poc` (`C16-F12`).

### Theme 6: Status and gap vocabulary friction (`SKIPPED_NA`, `COMPLETED_WITH_GAPS`, and `LEGACY_FREE_TEXT_GAPS`)
Thirty-six of 42 gap-checked jobs still sit on `LEGACY_FREE_TEXT_GAPS` (`strict_gaps=False` in `tests/test_gap_contract.py`, `C01-F08`, `C05-F05`, `C10-F07`, `C18-F07`). Worse, `ProducerStatus.SKIPPED_NA` is inconsistently handled between `UnitExecutor`/`JobRunner` and downstream `InputRequirement` policies (`C01-F01`), causing `job_remediation_planning`/`job_remediation_validation` to fail or misreport when zero findings are eligible (`C15-F02`), `job_final_publication_gate` (`WHEN_ENABLED` + `MissingPolicy.REJECT`) to block when an enabled attachment job fails (`C16-F05`), and `job_test_coverage`/`job_profile_data`/`job_change_context_analysis` to degrade into `COMPLETED_WITH_GAPS` on ordinary targets lacking optional coverage/profile/PR exports (`C10-F06`).

### Theme 7: Orphaned producers, dead datasets, and over-declared `InputRequirement`s
Multiple jobs compute expensive artifacts with zero readers or declare huge input surfaces they never open: `job_cpg_analysis` (`C07-F13`), `job_document_issue_analysis` (`C10-F04`, 142 declared `InputRequirement`s, zero downstream readers), `job_review_package_assembly` (`C11-F03`, `packages/*.json` unread by `job_inference_security_review`), `job_owasp_control_assessment` (`C12-F04`, 104 declared inputs across 21 jobs), `job_dependency_intelligence` (`C09-F10`, `enriched.spdx.json` and `native-sbom-provenance.json` unread), `job_third_party_data_sync` (`C09-F12`, `cve-bin-tool` unread), and `job_sanitizer_build` (`C06-F10`, instrumented binaries never run).

### Theme 8: Profile degradation and acceptance/CI blind spots
Operational convenience profiles and test gates diverge sharply from production assurances: single-model `dev` and `copilot-dev` profiles collapse challenger/judge model separation (`C02-F06`, `C14-F06`); `.github/workflows/quality.yml` runs at most 7 sentinel test files while omitting `tests/docs/*`, `test_todo_registry.py`, `test_skill_separation.py`, and `test_time_budgets.py` (`C18-F05`); and `stepwise.py system` passes `SYSTEM OK` on raw scanner line overlap even if published review findings are empty (`C18-F01`), while `funnel.py` marks pure Hunt-lane (`Lane B`) discoveries as `NOT_REACHED` (`C18-F02`) and `scoring.py` multiplies false positives by the number of `direct_evidence` lines cited (`C18-F03`).

---

## 4. The path of a finding

Tracing two representative vulnerabilities end to end—**(A) an authenticated Python/web SQL or command injection** and **(B) a C/C++ heap buffer overflow across two translation units**—shows exactly where evidence is strengthened, weakened, corrupted, or lost:

1. **Acquisition and intake (`job_target_acquisition` -> `job_review_intake`, `C05`):**
   - *Strengthened:* Commit/archive SHA-256 and detached snapshot manifests pin initial source bytes.
   - *Weakened:* Host `git` subprocesses inherit operator `~/.gitconfig` (`url.<base>.insteadOf`, `core.fsmonitor`, `C03-F01` / `C05-F03`), `[target_acquisition]` ignores `resolved.json` profile overrides (`C05-F10`), and live `--target` checkouts are re-read later without SHA-256 re-verification (`C05-F04`).
2. **Catalog and analysis planning (`job_target_catalog` -> `job_build_environment_analysis` -> `job_target_analysis_plan`, `C05`):**
   - *Strengthened:* Deterministic component ownership (`component_ownership.py`) assigns every first-party file to a partition and delivery scope.
   - *Weakened:* `job_build_environment_analysis` reads mutable `latest.json` directly (`C05-F01`), `job_target_catalog`'s regex `symbol_index` misses `async def` and typed C++ signatures and halts at 50,000 symbols in lexicographic order (`C05-F07`), and `job_target_analysis_plan` hardcodes `accepted_artifacts = ()`, disabling `tool-spotbugs` and `tool-blint` (`C05-F02`).
3. **Build and execution capture (`job_project_build` -> `job_language_build` -> `job_artifact_indexing`, `C06`):**
   - *Class A (Python/web):* Static dispatch succeeds cleanly, though unpinned `load_catalog` skips `tool-gitleaks` digest enforcement during post-build secret disposition (`C04-F01`).
   - *Class B (C/C++):* Untrusted build scripts run with `/capture/tools` mounted writable (`C06-F01`) and can forge regular trace records in `/capture/traces` (`C06-F07`). If native headers/deps fail, `job_language_build` can fall back to zero-TU static dispatch while still reporting `COMPLETED` (`C06-F02`), silently starving compiled C++ analyzers downstream. `job_sanitizer_build` may compile ASan/UBSan binaries, but nothing ever runs them (`C06-F10`).
4. **Static, graph, native, and context producers (`C07`, `C08`, `C09`, `C10`):**
   - *Class A (Python/web):* `job_evidence_collection` (Semgrep/Bandit) and `job_codeql_analysis` emit `observations` shards and bounded graph exports; `job_code_graph_index` projects `entry_point`, `sink_site`, `dataflow_path`, and `guard_fact` shards (`C07`). However, `job_code_graph_index` can drop interprocedural call/guard nuances (`C07-F01`), `job_test_coverage` inflates `lines_total` on multi-class Cobertura XML (`C10-F01`), and `job_profile_data` leaves `location=None` so `review/units.py` attaches unrelated hotspots across the whole build (`C10-F02`).
   - *Class B (C/C++):* `job_cpp_compiled_analysis` misses `.appsec-review-link-commands.json` (`link_commands=[]`), excludes any path segment named `build` or `target` (`C08-F02`), leaves `-I/workspace/...` unmapped (`C08-F03`), and lacks build-image system headers (`C08-F04`). Consequently `job_clang_static_analysis` and `job_cpp_symbol_index` lose translation units, `job_svf_alias_analysis` degrades to single-TU open-world mode (`C08-F01`), and `job_codeql_analysis` `cpp/GraphExport.qll` misses macro/guard shapes (`C07-F03`).
5. **Tagging, Stage 1/2 indexing, and packaging (`job_security_tagging` <-> `job_review_data_indexing`, `C11`):**
   - *Strengthened:* Stage 1/2 indexing correlates scanner hits, symbols, history, advisories (`NVD`/`KEV`/`EPSS`/`OSV`), and OWASP controls into content-addressed SQLite shards.
   - *Corrupted:* When `retrieval/model.py` serializes entities/tags, its substring regex replaces `auth_token`, `secret_handling`, and any identifier matching `token`/`secret`/`key`/`auth` with `"<redacted>"` (`C11-F01`), blinding `Lane A` and `Lane B` unit assembly to authentication and secret-handling tags! Meanwhile `job_review_prioritization`'s `ranking.json` is ignored by `review/ranking.py` (`C11-F04`), and `job_review_package_assembly` writes `packages/*.json` that `job_inference_security_review` never reads (`C11-F03`).
6. **Adversarial inference review (`job_inference_security_review`, `C13`, `C14`):**
   - *Strengthened:* `Lane A` (scanner-seeded triage) and `Lane B` (`hypothesis_hunter` surface/invariant hunting) investigate bounded `PackageView` units, challenged by a skeptic role and adjudicated by a judge role with deterministic `ledger-event/1` records and `decision-audit` trails (`T-150`).
   - *Weakened / leaked:* When workers call MCP `RetrievalCore.read_excerpt` to inspect surrounding lines, raw target secrets and prompt-injection strings bypass `PackageView`'s `secret_redaction.py` (`C13-F01`). Under `dev` or `copilot-dev` profiles, proposer, challenger, and judge share the same model (`verifier_model_distinct=False`, `C02-F06` / `C14-F06`). Crucially, `review/evidence.py` checks only that cited `file:line` spans and entity IDs exist—not that a cited guard predicate actually permits the exploit (`C14-F01`; `review/warrants.py` landed in `c12d9ef45` and awaits `evidence.py` integration).
7. **Evidence completion (`job_poc_generation`, `job_remediation_planning`, `job_remediation_validation`, `C15`):**
   - *Class A (Python/web):* `job_poc_generation` skips non-C/C++ targets or produces non-executed artifacts (`C15-F01`), and `RetryPolicy` treats `attempt.failure=None` on malformed model JSON as non-retryable `CONTRACT` failure (`C13` / `C15-F05`).
   - *Class B (C/C++):* `job_poc_generation` compiles the C/C++ harness to check syntax/linking but never runs it against the target binary (`C15-F01`). `job_remediation_validation` checks that the patched source compiles without re-running the scanner or PoC (`C15-F04`), and if zero findings qualify, `SKIPPED_NA` handling collides with `JobRunner` / downstream policies (`C01-F01`, `C15-F02`).
8. **Gate, publication, and scoring (`job_final_publication_gate` -> `job_final_report_publication` -> `acceptance/*`, `C16`, `C17`, `C18`):**
   - *Strengthened:* `job_final_publication_gate` verifies SHA-256 bindings across accepted review artifacts before `job_final_report_publication` runs (`C16`).
   - *Lost / miscounted:* `job_final_publication_gate` ignores pre-review scanner/build gaps (`C16-F01`). `job_final_report_publication` strips the finding statement, CWE ID, `file:line` locators, and gap descriptions out of `final-report.json` (`C16-F04`). Finally, `stepwise.py system` can pass `SYSTEM OK` on raw scanner hits even if `final-report.json` is empty (`C18-F01`), `acceptance/funnel.py` marks any pure `Lane B` (`hypothesis_hunter`) catch as `NOT_REACHED` (`C18-F02`), and `acceptance/scoring.py` explodes a confirmed finding citing 4 `direct_evidence` lines into 4 `Report` objects—penalizing rich multi-hop evidence as 4 false positives if unmatched (`C18-F03`).

---

## 5. Components

### C01 Runtime core, job interchange and storage

**Active findings:** 12 (`0` critical, `3` high, `7` medium, `2` low).

The runtime core (`interchange`, `runtime/*`, `storage/*`) has a disciplined, well-factored foundation: immutable attempt directories, content-addressed shared evidence receipts, HMAC-authenticated managed custody (`admission.py`), claim-pinned upstream handoff consumption (`consume.py` + `inputs.py`), and explicit `input-reads/1` telemetry that cleanly separates availability, supply, and read. However, several concrete defects and legacy residues undermine that contract in practice: `completion_status` disagrees with `CoverageDisposition` (`COMPLETE`/`CONFIGURED_DISABLED` become `COMPLETED_WITH_GAPS` while `SUCCEEDED` with non-empty `gaps` stays `SUCCEEDED`), two producer jobs still read `latest.json` directly, all 47 job factories wire `UnitExecutor(units).execute` as a dead shadow runtime that writes invalid task receipts if called directly, and `release-dependencies.json` puts nearly the entire repository into every job's release closure so any shared edit invalidates all 47 jobs during repair. Cleaning up those contract mismatches, finishing the `strict_gaps=True` migration across the remaining 38 jobs, and narrowing release closures will make the break/fix loop faster and more trustworthy without altering the core envelope design.

**Strengths to preserve:**
- **Distinct availability, supply, read, and citation accounting (`src/appsec_review/runtime/contracts.py:85-169`, `src/appsec_review/runtime/inputs.py:459-646`, `src/appsec_review/runtime/consume.py:157-177`).** `Job.contract` derives `CONSUMES`, `admit_upstreams` pins upstream handoff SHA-256s in `claim.json`, and `input_read_scope` records `appsec-review/input-reads/1` with `citation_observation: "not_observed"` rather than conflating graph edges with evidence use.
- **Immutable attempt storage and shared computation receipts (`src/appsec_review/storage/shared.py:213-485`, `src/appsec_review/storage/atomic.py:42-94`).** Atomic fsynced writes, read-only `0o444` detachment under `FIRST_PARTY_MANAGED` custody (`src/appsec_review/storage/admission.py:372-405`), and `SharedArtifacts` producer/consumer chains prevent silent in-place overwrite across retries and repairs.
- **Process-generation-bound resource leases and first-error safety broker (`src/appsec_review/runtime/resources.py:55-96,423-536`, `src/appsec_review/runtime/execution_safety.py:86-285,388-451`).** Combining `/proc/<pid>/stat` start-time ticks (`linux_ticks`) with container/build quarantine prevents PID-reuse races from prematurely reclaiming capacity or killing unrelated host processes.
- **Model-free cryptographic re-verification of accepted review state (`src/appsec_review/jobs/accepted_review.py:177-331`, `src/appsec_review/jobs/bound_artifacts.py:28-54`).** Downstream gate and report jobs re-verify ledger hash chains, projection digests, package manifests, score packages, and ship-block summaries before projecting accepted state.
- **Explicit repair admission with non-reusable first-error controller latches (`src/appsec_review/runtime/repair.py:140-265,305-445`).** Recovery distinguishes upstream handoff reuse from mid-attempt checkpoint reuse and refuses to reopen latched first-error controllers in place.

#### C01-F01 `completion_status` disagrees with `ProducerStatus` and ignores `gaps`/`dispositions`, contradicting `handoff.coverage`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: cross-cutting (`JobRunner` / `UnitExecutor` / all 47 jobs)
- **Evidence**: `src/appsec_review/interchange.py:61-81,420-430`; `src/appsec_review/runtime/runner.py:486-487,686-688,926-933`; `src/appsec_review/runtime/units.py:165-167,200-203,217-225`
- **Impact**: Two symmetric misclassifications occur in published handoffs and pipeline events. First, `ProducerStatus` and `classify_producer_status` (`interchange.py:420-430`) classify `"COMPLETE"` and `"COMPLETED"` (when `has_gaps=False`) as `CoverageDisposition.COMPLETE` and `"CONFIGURED_DISABLED"` as `CoverageDisposition.SKIPPED_POLICY`, yet `runner.py:486-487,686-688` and `UnitExecutor.summarize` (`units.py:222-225`) hardcode `{"SUCCEEDED", "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"}`. Any unit returning `"COMPLETE"`, `"COMPLETED"`, or `"CONFIGURED_DISABLED"` forces job `completion_status` to `"COMPLETED_WITH_GAPS"` (`JOB_COMPLETED_WITH_GAPS`) even when `outcomes.coverage` is `{"disposition": "complete", "gap_count": 0}`. Second, `UnitExecutor.summarize` and `runner.py` inspect only `output.get("terminal_status")` and ignore `output.get("gaps")` and `output.get("dispositions")`: a unit returning `terminal_status="SUCCEEDED"` (or `None`) alongside non-empty `gaps` or partial per-scope `dispositions` publishes `handoff["completion_status"] = "SUCCEEDED"` (`JOB_SUCCEEDED`) while `handoff["coverage"]` is `{"disposition": "partial", "gap_count": N}`.
- **Recommendation**: Derive step and job `completion_status` directly from `outcomes["coverage"]` (`CoverageDisposition.COMPLETE | NOT_APPLICABLE | SKIPPED_POLICY` with `gap_count == 0` -> `"SUCCEEDED"`, else `"COMPLETED_WITH_GAPS"`) instead of maintaining a separate hardcoded string set in `runner.py` and `units.py`.
- **Effort**: `S`
- **Already registered**: no

#### C01-F02 Direct `latest.json` reads in producer jobs bypass `accepted_upstream` and claim-pinned `upstream_handoffs`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: `job_build_environment_analysis`, `job_openvex_export`
- **Evidence**: `src/appsec_review/jobs/job_build_environment_analysis/job.py:208,228`; `src/appsec_review/jobs/job_openvex_export/inputs.py:257`; `src/appsec_review/jobs/job_openvex_export/reporting.py:193,218`; `src/appsec_review/runtime/consume.py:157-177`; `AGENTS.md:83`
- **Impact**: Both `job_build_environment_analysis` (reading `data/jobs/job_target_catalog/latest.json` at line 228 and its own `latest.json` at line 208) and `job_openvex_export` (constructing `data/jobs/{job}/latest.json` in `inputs.py:257` and `reporting.py:193,218`) bypass `runtime.consume.accepted_upstream`. Inside an active attempt, reading `latest.json` directly ignores the attempt's `claim.json` `upstream_handoffs` pin—exposing the consumer to concurrent repair/retry pointer updates—and bypasses `observe_handoff` / `input-reads/1` accounting.
- **Recommendation**: Replace direct `latest.json` reads in `job_build_environment_analysis` and `job_openvex_export` with `accepted_upstream` (or intra-attempt unit context for self-state) and add an AST/grep contract test under `tests/` forbidding `latest.json` path literals under `src/appsec_review/jobs/`.
- **Effort**: `S`
- **Already registered**: no

#### C01-F03 `UnitExecutor.execute` is a broken, divergent shadow runtime wired into all 47 `Job` constructors
- **Kind**: `remove`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: cross-cutting (all 47 jobs)
- **Evidence**: `src/appsec_review/runtime/units.py:79-208`; `src/appsec_review/runtime/runner.py:424-953,926`; `src/appsec_review/runtime/handoff.py:293`; `src/appsec_review/runtime/job.py:42-81`
- **Impact**: Every job factory passes `UnitExecutor(units).execute` as `Job.handler`, yet `JobRunner` never calls `Job.handler` or `Job.execute`; it executes units directly and calls only `UnitExecutor.summarize` (`runner.py:926`). Meanwhile, `UnitExecutor.execute` has drifted far out of contract: it writes `status.json` without `result_sha256` (`units.py:160`, which causes `build_outcomes` at `handoff.py:293` to fail with `ValueError("succeeded task receipt requires result_sha256")`), catches and suppresses unit exceptions instead of failing fast (`units.py:181-194`), and omits `admit_upstreams`, `upstream_scope`, `input_read_scope`, `publication_scope`, `unit_scope`, `validate_unit_output`, and `publish_checkpoint`. Any unit test invoking `job.execute(context)` tests a non-production execution path that hides missing input-contract declarations and output-schema violations. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Partially addressed in `5f56d7a20` and `a3d4831c0`, which re-attest reused Stage 1/2 index shards for reusing attempts.]*
- **Recommendation**: Delete `UnitExecutor.execute` (retaining `summarize_units` as a pure function), make `Job.units` the sole execution specification on `Job` (removing `Job.handler` / `Job.execute`), and route lightweight unit tests through `JobRunner` or a thin single-unit harness sharing `JobRunner`'s exact receipt/validation path.
- **Effort**: `M`
- **Already registered**: no

#### C01-F04 Attempt publication updates mutable `latest.json` and `accepted.json` pointers before `published.json`, risking torn state
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: cross-cutting (`JobRunner`)
- **Evidence**: `src/appsec_review/runtime/runner.py:935-937,996-1035`; `src/appsec_review/runtime/consume.py:114-124`; `src/appsec_review/runtime/resume.py:153`
- **Impact**: In `_publish_attempt_scoped`, `runner.py` writes `handoff.json` (line 996), updates `data/indices/accepted.json` (line 1010) and `latest.json` (line 1015), and only afterwards writes `published.json` (line 1025) and emits `JOB_HANDOFF_ACCEPTED` (line 1030). Two inconsistencies follow: (1) if writing `published.json` or the event log raises, `_finalize_attempt` (`runner.py:935-937`) catches the exception and calls `_fail_attempt`, overwriting `status.json` to `"FAILED"` while `latest.json` and `accepted.json` already point at an `"ACCEPTED"` `handoff.json`; and (2) `consume.py:_verified` (`consume.py:114-124`) never calls `verify_publication`, so downstream consumers accept a handoff lacking `published.json` while `ResumePlanner` (`resume.py:153`) and `repair.py` treat it as unpublished.
- **Recommendation**: Write and fsync `published.json` inside the immutable attempt directory *before* atomically flipping `latest.json` and `data/indices/accepted.json`, do not overwrite `status.json` to `"FAILED"` once `published.json` exists, and require `verify_publication` inside `consume.py:_verified`.
- **Effort**: `S`
- **Already registered**: no

#### C01-F05 Global release closure and duplicate `implementation`/`validation` hashes invalidate all 47 jobs on any shared edit
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: cross-cutting (`release.py`, `ResumePlanner`, `repair.py`)
- **Evidence**: `src/appsec_review/runtime/release.py:216-226`; `release-dependencies.json:1-9`; `src/appsec_review/runtime/resume.py:163-169`
- **Impact**: `measure_checkout` (`release.py:224-225`) builds `closure = {"job": code, "common": common, "validators": validators, "scripts": scripts}` and assigns `digest(closure)` identically to both `implementation` and `validation`—making `validation_identity` a pure duplicate of `implementation_identity` across `Job`, `claim.json`, `handoff.json`, and `ResumePlanner`. Because `release-dependencies.json` includes `src/appsec_review/**/*` (except `jobs/job_*` and `development`), `pipeline/**/*`, `rules/**/*`, `containers/**/*`, and `scripts/**/*` (including documentation and test scripts), editing one shared helper, prompt, Semgrep rule, or doc script changes the release digest of all 47 jobs simultaneously, forcing `plan-repair` / `ResumePlanner` to invalidate unaffected upstream jobs during the break/fix loop. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Resolved on `main` in `04afb24c6` (`T-148`/`T-163`), which replaces prefix-only `jobs.<job_id>` hashing with transitive AST import-walk job closures in `runtime/release.py`.]*
- **Recommendation**: Compute per-job Python module import closures (plus explicitly declared schema/rule/guidance/script dependencies per job) for `implementation`, compute `validation` separately from `docs/schemas` + validator modules, and exclude developer-only `scripts/` (such as `docs_matrices.py`, `documentation.py`, `run-tests.*`) from runtime job closures.
- **Effort**: `M`
- **Already registered**: no

#### C01-F06 `strict_gaps` remains disabled on 38 of 47 jobs, is dropped during `verify_outcomes`, and skips 3 converted jobs in tests
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: cross-cutting (`handoff.py` and 38 legacy-gap jobs)
- **Evidence**: `tests/test_gap_contract.py:11-29,39-47`; `src/appsec_review/runtime/handoff.py:200-209,354-356`; `src/appsec_review/runtime/job.py:57`
- **Impact**: Although `AGENTS.md` mandates `producer-gap/1` records, `Job.strict_gaps` still defaults to `False` (`job.py:57`) and 38 of 47 jobs remain in `LEGACY_FREE_TEXT_GAPS`, wrapping arbitrary free-text strings into generic `producer_reported_gap` codes without structured `scope_id` or `retryable` accuracy (`handoff.py:200-209`). Moreover, `verify_outcomes` (`handoff.py:354-356`) calls `build_outcomes(..., strict_gaps=False)` unconditionally, so post-publication verification never re-enforces strictness. Finally, `test_converted_jobs_reject_free_text_gaps` (`tests/test_gap_contract.py:39-47`) hardcodes 6 job names instead of parametrizing `sorted(set(REGISTERED_JOBS) - LEGACY_FREE_TEXT_GAPS)`, leaving 3 already-converted jobs untested against regressions.
- **Recommendation**: Parametrize `test_converted_jobs_reject_free_text_gaps` dynamically over `sorted(set(REGISTERED_JOBS) - LEGACY_FREE_TEXT_GAPS)`, record `strict_gaps` in `outcomes.json` (or flip the global default to `True` once `LEGACY_FREE_TEXT_GAPS` is burned down), and burn down the remaining 38 jobs in grouped passes starting with intake/catalog (`T-055`) and build (`T-111`).
- **Effort**: `M`
- **Already registered**: partial: T-055, T-111

#### C01-F07 `runtime/plan.py` (`plan_jobs`) ignores `graph_dependencies` and chains all jobs linearly while its return value is unused
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: none (`runtime/plan.py`)
- **Evidence**: `src/appsec_review/runtime/plan.py:48-73`; `src/appsec_review/orchestration/dagster/adapter.py:158`; `src/appsec_review/runtime/graph.py:67`
- **Impact**: `plan_jobs` chains every job's `__begin__` sentinel sequentially after `prior_final` of the preceding job in iteration order (`plan.py:55-58`), completely ignoring `Job.contract` and `graph_dependencies`. Neither `GraphRunner` nor Dagster executes `ExecutionPlan`; `orchestration/dagster/adapter.py:158` calls `plan_jobs(jobs, configs.base)` and discards the returned plan solely for its side-effect of checking per-job unit DAG cycles (which `JobRunner._topological_units` already validates). Keeping a misleading linear planner in `runtime/__init__.py` invites callers to mistake iteration order for execution order.
- **Recommendation**: Replace `plan_jobs` with a small `validate_job_units(job)` helper called at `Job` construction or Dagster definition load, and delete `src/appsec_review/runtime/plan.py`.
- **Effort**: `S`
- **Already registered**: no

#### C01-F08 Generic runtime core hardcodes domain-specific imports, step names, and `"data/"` prefix heuristics for 8 jobs
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: cross-cutting (`runner.py`, `resume.py`, `repair.py`, `inputs.py`, `handoff.py`)
- **Evidence**: `src/appsec_review/runtime/runner.py:256-259,405-412,519-526,544-551,788-790,906-913`; `src/appsec_review/runtime/resume.py:67-70,113-131`; `src/appsec_review/runtime/repair.py:345-380`; `src/appsec_review/runtime/inputs.py:424-456`; `src/appsec_review/runtime/handoff.py:43-53,88-96`
- **Impact**: Core runtime modules directly branch on string job IDs and import internals of `job_target_catalog`, `job_target_analysis_plan`, `job_build_environment_analysis`, `job_project_build`, `job_language_build`, `job_build_iteration`, `job_review_data_indexing`, and `job_third_party_data_sync` (for example `runner.py:788` hardcoding `job.job_id == "job_target_analysis_plan"` and `unit.step_id == "plan_finalize"` to write `data/analysis-plan/current.json`, and `handoff.py:88-96` guessing artifact paths from any output string starting with `"data/"`). This tight upward coupling from `runtime/` into `jobs/` makes runtime changes fragile and obscures job side effects.
- **Recommendation**: Move job-specific post-unit/post-handoff hooks, tool-probe resolvers, and repair compatibility checks onto explicit declarative hooks on `Job` / `JobContract`, and require explicit artifact references instead of `"data/"` string-prefix inference (`T-096`).
- **Effort**: `M`
- **Already registered**: partial: T-096

#### C01-F09 `cataloging.inventory` and `JobRunner.claim` hash the entire target source tree up to 4 times during `job_target_catalog`
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: `job_target_catalog`
- **Evidence**: `src/appsec_review/runtime/runner.py:406-412`; `src/appsec_review/jobs/cataloging.py:158-161,199-204,213,234-255`
- **Impact**: When `job_target_catalog` runs, `JobRunner.claim` (`runner.py:410`) first walks and SHA-256 hashes every file in `target_root` via `source_fingerprint(target_root)` (`raw_snapshot`). Inside `cataloging.inventory`, every in-scope source file in `LANGUAGES` is then read as UTF-8 text (line 158), hashed via `sha256_file` for `source_metrics` (line 161), sampled for NUL bytes (line 199), hashed a third time via `sha256_file` for `files` (line 204), and hashed a fourth time when `inventory()` calls `raw_snapshot(root)` at line 213 (`sha256_file` at line 251). On multi-gigabyte C++/Unity repositories, three redundant full-tree SHA-256 passes waste significant wall-clock time and disk I/O before downstream jobs can start.
- **Recommendation**: Stream each target file once during `_walk_files` in `cataloging.inventory`—computing SHA-256, NUL-byte detection, and UTF-8 SLOC in a single read pass while accumulating the `raw_snapshot` digest incrementally—and reuse the claim's verified `raw_snapshot` when `target_root` is read-only.
- **Effort**: `S`
- **Already registered**: no

#### C01-F10 Unscoped `accepted_upstream` skips `verify_handoff_integrity`, and `_read_admission` thrushes its single-slot HMAC cache
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: cross-cutting (`consume.py`, `admission.py`)
- **Evidence**: `src/appsec_review/runtime/consume.py:114-124,157-177`; `src/appsec_review/indexing/store.py:45-51`; `src/appsec_review/storage/admission.py:423-431`
- **Impact**: Inside `JobRunner`, `admit_inputs` invokes `storage.shared.verify_handoff` (`inputs.py:137`), verifying `outcomes.json`, artifact SHA-256s, and managed admission records. Outside `upstream_scope` (CLI inspection, operator tools, standalone callers), `accepted_upstream` falls back to `_verified` (`consume.py:114-124`), which checks only `handoff.json`'s own SHA-256 and structural schema (`decode_handoff`) without calling `verify_handoff_integrity`—returning a handoff even if referenced artifacts or `outcomes.json` were truncated or corrupted unless the caller goes through `indexing.store.accepted_handoff`. Separately, `_read_admission` (`admission.py:423-431`) stores its HMAC verification cache under a single literal key `("admission-authentication", "latest", "")`, so validating `N` distinct upstream handoffs in one `validation_scope` misses and overwrites that slot on every handoff.
- **Recommendation**: Key `_read_admission`'s cache by `("admission-authentication", ref["sha256"], "")` and add an integrity-verified mode (or `verify_publication` + `verify_handoff_integrity` check) to unscoped `accepted_upstream` reads.
- **Effort**: `S`
- **Already registered**: no

#### C01-F11 `DAGSTER_QUEUE_DELAY` conflates upstream DAG execution time with scheduler queue delay
- **Kind**: `weakness`
- **Severity**: `low`
- **Confidence**: `verified`
- **Job**: cross-cutting (`JobRunner`)
- **Evidence**: `src/appsec_review/runtime/runner.py:1049-1071`; `docs/reviews/appsec-system-review-2026-11-06.md:187-194`
- **Impact**: Carried over unfixed from the 2026-11-06 review, `_dagster_queue_delay_ms` computes `int(time.time() * 1000) - created_ms` where `created_ms` is the Dagster run's creation timestamp (`creation_timestamp` / `start_time`), not the timestamp when all upstream dependencies of the current op finished. For late-stage jobs such as `job_inference_security_review` or `job_final_report_publication`, `DAGSTER_QUEUE_DELAY` reports hours of upstream build/CodeQL runtime as "queue delay".
- **Recommendation**: Rename the current metric `run_elapsed_at_claim_ms` and compute true scheduler queue delay from the maximum `completed_at` timestamp among admitted `upstream_handoffs` (falling back to Dagster run creation time only for root jobs with no upstreams).
- **Effort**: `S`
- **Already registered**: partial: T-059

#### C01-F12 `validate_unit_output` omits `dispositions[].coverage_disposition` validation while `job-control.schema.json` allows non-canonical uppercase values
- **Kind**: `defect`
- **Severity**: `low`
- **Confidence**: `verified`
- **Job**: cross-cutting (`interchange.py`, `job-control.schema.json`)
- **Evidence**: `src/appsec_review/interchange.py:526-540`; `src/appsec_review/runtime/handoff.py:157-163,258`; `docs/schemas/job-control.schema.json:31-34,47-55`; `docs/schemas/job-interchange.schema.json:45-47`
- **Impact**: `validate_unit_output` validates top-level `result["coverage_disposition"]` (`interchange.py:526-528`) and `dispositions[i]["terminal_status"]` (`interchange.py:534-538`), but omits any check on `dispositions[i]["coverage_disposition"]`. An invalid per-scope `coverage_disposition` escapes unit validation and only crashes later during attempt finalization in `handoff.py:258` (`_explicit_disposition`). Meanwhile `job-control.schema.json:31-34` permits uppercase `ProducerStatus` tokens (`SKIPPED_NA`, `CONFIGURED_DISABLED`) inside `coverageDisposition`—values that `_explicit_disposition` (`handoff.py:159`, which checks `raw.strip().lower() in _DISPOSITION_VALUES` without `COVERAGE_ALIASES`) actually rejects with `ValueError("unsupported explicit coverage disposition")`!
- **Recommendation**: Validate `dispositions[i].get("coverage_disposition")` in `validate_unit_output`, route `_explicit_disposition` in `handoff.py:157` through `COVERAGE_ALIASES` (or restrict `job-control.schema.json` to the 5 canonical lowercase `CoverageDisposition` values), and add a unit regression covering `"SKIPPED_NA"` / `"CONFIGURED_DISABLED"`.
- **Effort**: `S`
- **Already registered**: no
### C02 Configuration, profiles and run selection

**Active findings:** 15 (`2` critical, `4` high, `8` medium, `1` low).

C02 centralizes configuration loading, profile and capacity-overlay composition, host-pin binding, and per-run resolved configuration snapshots cleanly across all 44 registered jobs, with strong closed-key parsers in its newest subsystems (`inference_review`, `codeql`, `owasp`, `remediation`, `exclusions`, and `assurance`). However, two policy-gate defects directly compromise coverage honesty and policy enforcement: generic `jobs.<id>.settings.enabled = false` omits producers from the graph and silently strips them from the reconciled input matrix instead of recording a policy gap, and `swift_policy.py` misses plural/URI path and language fields while failing open to `False` when run configuration files are missing. Recovery and active-run isolation are also brittle because capacity overlays remain hashed into `resolved_sha256` and `job_config_sha256` (invalidating all 44 jobs' handoffs on a capacity adjustment), while `RunConfigurations.for_tags` and `job_build_iteration` re-read live bind-mounted host files and drop explicit `host_pins`. Finally, `load_config()` leaves 26 of 44 jobs without central settings validation—even skipping six jobs and six sync steps that already define strict `settings.py` validators—so simple configuration mistakes fail only after hours of build and model execution. Fixing the disabled-job coverage accounting, Swift key checks, capacity-hash separation, frozen-run loading, and loader-validator wiring will directly improve finding completeness, coverage honesty, and repair turnaround.

**Strengths to preserve:**
- Layered, deterministic composition order (`appsec-review.toml` -> `profiles/<name>.toml` -> `host-pins.toml` -> capacity overlay -> `compiler_target`) with strict allowlists preventing profiles from silently altering non-model policy or capacity overlays from altering semantic settings (`src/appsec_review/config/loader.py:729-915`).
- Closed-schema validation with cross-field invariants in `inference_review.py`, `codeql.py`, `owasp.py`, `remediation.py`, and `exclusions.py`, including verifier distinctness rules, fail-closed exclusion protection against excluding security-critical paths, and single-source seeded neighborhood propagation from `codeql.export_queries` (`src/appsec_review/config/inference_review.py:422-751`, `src/appsec_review/config/exclusions.py:87-146`, `src/appsec_review/config/seeding.py:55-96`).
- Zero pending jobs (`PENDING_JOBS = frozenset()`) and exact 44-for-44 parity between `[jobs.<id>]` tables in `appsec-review.toml` and `builtin_registry()` (`src/appsec_review/config/loader.py:25-27`, `tests/test_inference_review_config.py:86-90`).
- Descriptor-backed, fail-closed `applicability.py` evaluation that maps disabled or inapplicable capabilities onto explicit `SUCCEEDED` / `SKIPPED_NA` / `SKIPPED_POLICY` / `GAP` dispositions (`src/appsec_review/applicability.py:29-98`).
- Host-local image and CodeQL runtime bindings (`host-pins.toml`) separated from tracked recipe tags while still verified and frozen into each run's `data/configuration/` directory (`src/appsec_review/config/host_pins.py:75-169`, `src/appsec_review/runtime/runner.py:86-112`).

#### C02-F01 Generic `jobs.<id>.settings.enabled = false` omits producers and erases them from the coverage matrix instead of naming a policy gap
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/runtime/selection.py:13-30`, `src/appsec_review/orchestration/topology.py:48-75`, `src/appsec_review/indexing/input_matrix.py:183-204`, `src/appsec_review/config/loader.py:1460-1469`; `job_is_enabled` makes `settings.enabled = false` generic across every non-`WAVE1_REQUIRED` job, `wave1_dependencies` splices disabled jobs out of the graph with no receipt, and `input_matrix.reconcile` filters `disabled` producers out of `INPUT_SOURCES` (`if not producers: continue`).
- **Impact**: Disabling an analyzer via `jobs.<id>.settings.enabled = false` (explicitly tested for `job_codeql_analysis` in `tests/test_job_selection.py:55-68`, and active by default for `job_threat_model_generation`, `job_svf_alias_analysis`, and `job_cpg_analysis`) drops single-producer rows from the reconciled input matrix without a `producer-gap/1` record and marks multi-producer rows `runtime_state: "available"` even when one producer was disabled—hiding missing coverage as clean/absent in contrast to `codeql.execution_mode = "disabled"` or `tools.disable_grype = true`. In addition, `loader.py:1460-1469` checks prerequisites only for `job_openvex_export` and `job_remediation_validation`, so disabling `job_inference_security_review` or `job_final_publication_gate` while `job_poc_generation`, `job_remediation_planning`, `job_dossier_publication`, or `job_final_report_publication` remain enabled passes `load_config()` and crashes late in the run on missing upstream handoffs.
- **Recommendation**: Restrict `jobs.<id>.settings.enabled` in `src/appsec_review/config/loader.py` and `src/appsec_review/runtime/selection.py` to an explicit allowlist of optional jobs, validate enablement against `builtin_contracts()` `consumes` edges in `loader.py`, and retain disabled producers in `src/appsec_review/indexing/input_matrix.py` with `status: "disabled_by_policy"` (`runtime_state: "unavailable"` or `"partial"`) that emits a named policy gap.
- **Effort**: `S`
- **Already registered**: no

#### C02-F02 `swift_policy.py` misses plural and URI path/language keys in `reject_swift_derived` and defaults to `False` when run configuration is absent
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/swift_policy.py:42-69`, `src/appsec_review/jobs/job_evidence_collection/job.py:478`, `src/appsec_review/jobs/job_language_build/job.py:258`, `src/appsec_review/jobs/job_target_analysis_plan/job.py:389`; `_explicit_swift` inspects only singular keys `{"language", "source_language", "producer_language"}` and `{"path", "file", "source", "source_path", "relative_path"}`, preserving the parent key when recursing into sequences, while `swift_enabled_from_run` returns `False` when neither `manifest.json` nor `resolved.json` exists.
- **Impact**: When `tools.enable_swift = false` (the default), records carrying `.swift` or `.swiftpm` entries under real producer fields such as `"paths"`, `"files"`, `"dependency_files"`, `"allowed_paths"`, `"languages"`, `"target_path"`, or `"uri"` pass `reject_swift_derived` undetected and can be published into downstream evidence or build artifacts in violation of the Swift execution policy. Conversely, if a run's `data/configuration/` directory is missing, `swift_enabled_from_run` silently assumes `False` rather than failing closed like `applicability.py:29-38`.
- **Recommendation**: Expand `_explicit_swift` in `src/appsec_review/swift_policy.py` to match plural and URI field names (`paths`, `files`, `dependency_files`, `allowed_paths`, `source_paths`, `relative_paths`, `target_path`, `uri`, `languages`, `source_languages`) and change `swift_enabled_from_run` to raise `ValueError("run configuration manifest is missing")` when `manifest.json` or `resolved.json` is absent.
- **Effort**: `S`
- **Already registered**: no

#### C02-F03 Capacity overlays alter `resolved_sha256` and `job_config_sha256`, breaking run continuation and invalidating all upstream handoffs
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/config/loader.py:888-896, 1099-1105, 1141, 1489-1513`, `src/appsec_review/runtime/runner.py:67-73`, `src/appsec_review/runtime/resume.py:45-58, 107`, `src/appsec_review/runtime/repair.py:55`, `appsec-review.toml:2850-2852, 3004-3005`; while `build_workspaces` is popped from `resolved_document` (`loader.py:1149`) and `semantic_settings_view` strips `teams.review_teams` and `result_cache` from cell fingerprints (`inference_review.py:470-478`), `resolved_document` still serializes `configuration_overlay`, `orchestration.dagster.pools`, `review_policy.resources`, `teams.review_teams`, and `result_cache` into `resolved_sha256`, and `resume.py` hashes raw `job.settings`/`workers` plus global `resolved_config_sha256`.
- **Impact**: Adjusting host capacity mid-review via `APPSEC_REVIEW_CONFIG_OVERLAY` (for example lowering `review_teams`, `io_slots`, or Dagster pool limits after provider throttling or OOM, or toggling Garnet `result_cache`) changes `resolved_sha256` and `job_config_sha256`, causing `JobRunner._bind_configuration` to reject in-place continuation and `ResumePlanner` / `ComputationAdmission` to invalidate all 44 jobs' accepted handoffs despite the TOML contract stating capacity is never fingerprinted. Moreover, checking global `resolved_config_sha256` on every job in `resume.py:107` means fixing a terminal job's setting (`job_final_report_publication`) invalidates `job_project_build`, `job_codeql_analysis`, and `job_inference_security_review`.
- **Recommendation**: Strip non-semantic capacity fields (`configuration_overlay`, `orchestration.dagster.pools`, `review_policy.resources`, `teams.review_teams`, `result_cache`, and worker counts) from `resolved_sha256` and `job_config_sha256` in `src/appsec_review/config/loader.py` and `src/appsec_review/runtime/resume.py` (recording capacity separately in `manifest.json`), and bind resume/repair admission to each job's semantic `job_config_sha256` plus transitive `upstream_handoff_sha256` closure rather than global `resolved_sha256`.
- **Effort**: `M`
- **Already registered**: no

#### C02-F04 `load_config()` skips settings validation for 26 of 44 registered jobs, including 6 jobs and 6 sync steps with existing `settings.py` validators
- **Kind**: `weakness`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/config/loader.py:1170-1455`, `src/appsec_review/jobs/job_poc_generation/settings.py:50-55`, `src/appsec_review/jobs/job_final_publication_gate/settings.py:21-34`, `src/appsec_review/jobs/job_final_report_publication/settings.py:21-33`, `src/appsec_review/jobs/job_sanitizer_build/settings.py:1-55`, `src/appsec_review/jobs/job_change_context_analysis/settings.py:1-60`, `src/appsec_review/jobs/job_source_history_analysis/settings.py:1-60`; `loader.py` validates full settings schemas for only 18 jobs and 1 of 7 `job_third_party_data_sync` steps (`grype_db_sync`), never invoking the strict closed-key validators already implemented in those six job `settings.py` modules or the six remaining feed-sync step modules.
- **Impact**: An operator typo or out-of-bounds value in `[jobs.job_poc_generation.settings]`, `[jobs.job_final_publication_gate.settings]`, or `[jobs.job_final_report_publication.settings]` passes `load_config()`, `job_model_connectivity`, `job_image_pin_verification`, compilation, CodeQL, and hours of model inference before crashing at the end of the pipeline; for the remaining unvalidated jobs (and partial parsers like `CppCompiledAnalysisSettings` at `loader.py:1383`, which checks only `lane`), unknown keys in `appsec-review.toml` are silently ignored.
- **Recommendation**: Wire all existing job and sync-step `settings.py` validators into `src/appsec_review/config/loader.py` immediately, store their normalized views in `typed_settings` and `resolved_document`, and add closed-key schemas for the remaining 20 jobs so unknown or out-of-range settings fail at startup before any job runs.
- **Effort**: `M`
- **Already registered**: no

#### C02-F05 `RunConfigurations.for_tags` and `job_build_iteration` re-read live bind-mounted host files and drop explicit `host_pins`, while `runner.py` omits profile and overlay copies
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: job_build_iteration
- **Evidence**: `src/appsec_review/config/run_selection.py:98-108`, `src/appsec_review/jobs/job_build_iteration/job.py:42-48`, `src/appsec_review/runtime/runner.py:86-99`, `deploy/dagster/compose.yaml:45-51`; `for_tags` calls `load_config(self.base.source_path, profile=profile, overlay=key[1], compiler_target=target.value)` without `host_pins=self.base.host_pins` or a `source_sha256` check against `self.base`, `runner.py` copies only `appsec-review.toml` and `host-pins.toml` (not `profile_path` or `overlay_path`) into `data/configuration/`, and `load_iteration_configuration` reloads `Path(manifest["sources"][0]["path"])` from the live host mount.
- **Impact**: Because `compose.yaml` bind-mounts `appsec-review.toml`, `profiles/`, `test/acceptance/`, and `host-pins.toml` directly from the host checkout, editing host configuration or running `update-image-pins --write` during an active review causes `job_build_iteration` workers to fail mid-build (`"iteration worker configuration differs from its frozen run"`), and causes tagged Dagster runs on a live code-location to silently cache different base/host-pin bytes than untagged runs (or lose explicit `host_pins`).
- **Recommendation**: Freeze `profile.toml` and `overlay.toml` alongside `appsec-review.toml` and `host-pins.toml` in `src/appsec_review/runtime/runner.py`, reconstruct `AppConfig` in `src/appsec_review/jobs/job_build_iteration/job.py` exclusively from `run_root/data/configuration/`, and pass `host_pins=self.base.host_pins` while verifying `source_sha256 == self.base.source_sha256` in `src/appsec_review/config/run_selection.py`.
- **Effort**: `S`
- **Already registered**: no

#### C02-F06 `dev` and `copilot-dev` profiles structurally withhold all `ship_blocking` findings by pairing `require_distinct_model_for_ship_blocking = true` with a same-model verifier
- **Kind**: `weakness`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: job_inference_security_review
- **Evidence**: `appsec-review.toml:2960-2961, 2981-2984, 3001-3002`, `profiles/copilot-dev.toml:27-35`, `src/appsec_review/config/inference_review.py:422-441`, `docs/operations/model-profiles.md:27-57`; both `dev` (`claude-cli` / `sonnet`) and `copilot-dev` (`copilot-sdk` / `claude-sonnet-4.6`) bind `independent_verifier` to `model_profile = "default"`—matching `hypothesis_hunter` and `red_team_analyst`—while keeping `require_distinct_model_for_ship_blocking = true`.
- **Impact**: Every `dev` and `copilot-dev` run has `verifier_distinctness().distinct == False`, so no confirmed critical vulnerability can ever be published as `ship_blocking`; all ship-blocking candidates are downgraded to `ship_blocking_pending_distinct_verification` (`verification_backlog`), and `docs/operations/model-profiles.md` never warns operators of this ceiling.
- **Recommendation**: Either bind `independent_verifier` in `appsec-review.toml` (`dev`) and `profiles/copilot-dev.toml` to a distinct verifier model profile (for example a lightweight cross-family model on `copilot-dev`), or document prominently in `docs/operations/model-profiles.md` and `review-startup.md` that `dev` and `copilot-dev` structurally route all ship-blocking findings to the verification backlog.
- **Effort**: `S`
- **Already registered**: no

#### C02-F07 `loader.py` overwrites `job_project_build.typed_settings` with `None` and discards validated `UnityBuildSettings` and `PlanningFeedbackSettings`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: job_project_build
- **Evidence**: `src/appsec_review/config/loader.py:1170-1175, 1218-1222`, `src/appsec_review/jobs/job_target_analysis_plan/job.py:354`; lines `1170-1175` assign `typed_settings = parse_build_selection(...)` and discard `parse_unity_build_settings(...)`, after which line `1218` (`typed_settings: object | None = None`) unconditionally resets `typed_settings` to `None`, while lines `1221-1222` likewise discard `PlanningFeedbackSettings`.
- **Impact**: `config.job("job_project_build").typed_settings` and `config.job("job_target_analysis_plan").typed_settings` are always `None` at runtime, forcing downstream jobs (`job_target_analysis_plan/job.py:354`) to re-parse raw dictionaries and leaving normalized `unity` and `feedback` defaults unmaterialized in `resolved.json`. Lines `1219-1364` also mix sequential `if job_id == ...` statements before an `elif` chain starting at line `1364`, making accidental fallthrough overwrites easy to introduce.
- **Recommendation**: Consolidate all per-job `typed_settings` parsing into a single `if`/`elif` dispatch block in `src/appsec_review/config/loader.py` after `steps` construction, retain composite typed settings for `job_project_build` (`build_selection` + `unity`) and `job_target_analysis_plan` (`feedback`), and write normalized `unity` and `feedback` views back into `settings`.
- **Effort**: `S`
- **Already registered**: no

#### C02-F08 Mandatory 18-key `[jobs.job_inference_security_review.settings.poc]` table is dead configuration that misleads operators and pollutes semantic fingerprints
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: job_inference_security_review
- **Evidence**: `src/appsec_review/config/inference_review.py:293-312, 470-478, 650-690, 745`, `appsec-review.toml:2998-3000, 3170-3195, 3324-3325`; `parse_inference_review_settings` requires `PocSettings` (`execution_enabled = false`, `cpu_limit`, `memory_mb`, `scratch_mb`, and `eligibility_rules` on `cvss_v4 = ["HIGH", "CRITICAL"]`) and `semantic_settings_view` hashes it, yet no producer or consumer outside config tests ever reads `settings.poc`.
- **Impact**: Actual PoC candidate selection reads `settings.poc_candidates` (`risk_ratings = ["medium", "high", "critical"]`) and actual PoC compile verification reads `[jobs.job_poc_generation.settings]` (`enabled = true`). Keeping `settings.poc` misleads operators into believing PoC verification is disabled (`execution_enabled = false`) or limited to `HIGH`/`CRITICAL`, while any edit to its 18 dead keys invalidates semantic model-cache fingerprints across the run.
- **Recommendation**: Remove `PocSettings` and `settings.poc` from `src/appsec_review/config/inference_review.py`, `appsec-review.toml`, and `tests/test_inference_review_config.py`, keeping `settings.poc_candidates` and `[jobs.job_poc_generation.settings]` as the sole PoC configuration surfaces.
- **Effort**: `S`
- **Already registered**: no

#### C02-F09 `telemetry_report.py` hardcodes a stale `DEFAULT_IMAGE_ID` that bypasses `host-pins.toml` and omits `[reporting]` from `resolved.json` when unconfigured
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/config/telemetry_report.py:13-14, 32-44`, `src/appsec_review/config/loader.py:1095, 1106-1148`, `src/appsec_review/config/host_pins.py:92-95`, `deploy/dagster/host-pins.toml:31`; `telemetry_report.py` defaults to `DEFAULT_IMAGE_ID = "sha256:1dd77c969bba..."` (whereas `host-pins.toml` pins `sha256:3aff3add...`), `apply_host_pins` runs on raw `document` before `parse_telemetry_report`, and `loader.py:1114` populates `resolved_document["reporting"]` only `if "reporting" in document:`.
- **Impact**: Any configuration omitting `[reporting]` or `image_tag` skips host-pin injection, omits `reporting` from `resolved.json`, and binds a stale non-existent Docker image digest. More generally (`loader.py:1106-1148`), omitted top-level sections (`exclusions`, `inventory`, `binary_decompilation`, `target_acquisition`, `banned_functions`, `reporting`) are not normalized into `resolved_document`, forcing `resolved.json` readers such as `job_review_intake/job.py:83-86` to duplicate fallback defaults.
- **Recommendation**: Remove `DEFAULT_IMAGE_ID` from `src/appsec_review/config/telemetry_report.py` (defaulting `image_id` to `""` when unpinned, matching other host-pinned tools), materialize default `reporting.telemetry_report.image_tag` before `apply_host_pins` in `src/appsec_review/config/loader.py`, and unconditionally write normalized views of all top-level parsed sections into `resolved_document`.
- **Effort**: `S`
- **Already registered**: no

#### C02-F10 `copilot_sdk.verify()` reloads unprofiled configuration from `os.environ` and treats disabled jobs' models as required
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: job_model_connectivity
- **Evidence**: `src/appsec_review/inference/copilot_sdk.py:318-329`, `src/appsec_review/jobs/job_review_intake/job.py:139-177`, `src/appsec_review/jobs/job_model_connectivity/job.py:32-47`; `copilot_sdk.verify()` calls `load_config(os.environ.get("APPSEC_REVIEW_CONFIG") or "appsec-review.toml")` without `profile` or `overlay` arguments and enumerates `configured_models(...)` rather than `required_models(...)`.
- **Impact**: Calling `copilot_sdk.verify()` when a Copilot profile was selected via CLI `--profile` or Dagster run tags (without `APPSEC_REVIEW_PROFILE` exported in `os.environ`) loads `dev` (`claude-cli`) and fails with `RuntimeError("no copilot-sdk models configured")`; and when a job or sub-model is disabled (`enabled = false`, such as `job_post_build_security_assessment.settings.model` at `appsec-review.toml:2349`), `configured_models` still requires live provider availability for the disabled model.
- **Recommendation**: Pass optional `config: AppConfig | None = None` and `profile: str | None = None` into `verify()` in `src/appsec_review/inference/copilot_sdk.py` and switch `configured_models` to `required_models` so standalone preflight matches `job_model_connectivity` and `job_review_intake`.
- **Effort**: `S`
- **Already registered**: no

#### C02-F11 `application_paths.py` mishandles `file://` config URIs and silently falls back across repository checkouts
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/application_paths.py:6-28`, `src/appsec_review/config/loader.py:1049-1063`; `load_config()` resolves `file://` URIs through `_config_source`, whereas `application_root()` passes raw `os.environ["APPSEC_REVIEW_CONFIG"]` to `Path(configured).resolve().parent` and falls back to `Path(__file__).resolve().parents[2]` whenever `(candidate / marker).exists()` is false.
- **Impact**: Setting `APPSEC_REVIEW_CONFIG=file:///...` (supported by `load_config()` and tested in `tests/test_config.py:67`) causes `application_root()` to construct a bogus relative `file:/...` path and silently load schemas, prompts, or tool locks from the Python package checkout; likewise, a missing asset beside a custom config silently mixes assets from two checkouts instead of failing closed. The module docstring (`application_paths.py:10-15`) also describes a retired `site-packages` vs `/opt/app` image-copy layout.
- **Recommendation**: Reuse `_config_source` path parsing in `src/appsec_review/application_paths.py`, fail closed with `FileNotFoundError` when `APPSEC_REVIEW_CONFIG` is explicitly set and `(candidate / marker)` is missing, and update the docstring to match the read-only bind-mount layout.
- **Effort**: `S`
- **Already registered**: no

#### C02-F12 Structural job, schedule, and concurrency fields in `loader.py` use permissive `int()`/`bool()` coercions without bounds or closed-key checks
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/config/loader.py:1158-1217, 1448-1455, 1505-1511`; `loader.py` converts `job.workers`, `step.workers`, `task.workers`, `dagster.max_concurrent`, and `dagster.pools.*` with raw `int(...)` and converts `schedule.enabled` with `bool(...)`, without checking `type(v) is int`, positive bounds, valid `executor` values, cron/timezone syntax, or unknown keys on `[jobs.<id>]`, `[jobs.<id>.steps.<step>]`, `[jobs.<id>.steps.<step>.tasks.<task>]`, or `[orchestration.dagster]`.
- **Impact**: Mistyped TOML values such as `workers = false` (`0`), `workers = -1`, `max_concurrent = 0`, `schedule.enabled = "false"` (`True`), or unknown keys under step/task/orchestration tables pass `load_config()` silently and surface later as worker starvation, deadlocks, or ignored operator configuration.
- **Recommendation**: Enforce `type(value) is int and 1 <= value <= MAX_WORKERS` on all worker/concurrency/pool fields, `isinstance(enabled, bool)` plus non-empty cron/timezone validation on `ScheduleConfig`, and closed-key sets on job, step, task, and orchestration tables in `src/appsec_review/config/loader.py`.
- **Effort**: `S`
- **Already registered**: no

#### C02-F13 Operations docs contradict `appsec-review.toml`, `profiles/*.toml`, and `deploy/dagster/` on exploration, PoC defaults, bind-mounts, and profiled jobs
- **Kind**: `doc-drift`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `docs/operations/review-startup.md:67-68, 110, 121, 128`, `docs/operations/model-profiles.md:6, 142-151, 171-186, 228-230`, `profiles/prod.toml:6-8, 89-91`, `profiles/copilot-prod.toml:87-90`, `appsec-review.toml:3324-3325`, `deploy/dagster/Dockerfile:12-16`, `deploy/dagster/compose.yaml:45-51`; the docs claim production disables medium/low exploration, `job_poc_generation` defaults to `enabled = false`, config edits require `scripts/stack-rebuild` because `Dockerfile` copies TOML files into the image, and only five jobs are touched by profiles.
- **Impact**: In reality, both `prod` and `copilot-prod` set `exploration_enabled = true` (`exploration_reserve = 20`), `job_poc_generation` defaults to `enabled = true`, `compose.yaml` bind-mounts `appsec-review.toml` and `profiles/` read-only for `lifecycle.py reload` (rebuilding images for config changes violates `AGENTS.md`), and profiles override eight job surfaces including `job_owasp_control_assessment.settings.models.reviewer`, `job_remediation_planning.settings.writer`, and `job_remediation_validation.settings.reviewer`. Operators following these docs make wrong cost/coverage assumptions and run unnecessary image rebuilds.
- **Recommendation**: Reconcile `docs/operations/review-startup.md`, `docs/operations/model-profiles.md`, `profiles/prod.toml:6-8`, and `src/appsec_review/config/loader.py:732-737` against the actual bind-mount deployment (`lifecycle.py reload`), enabled `prod`/`copilot-prod` exploration, `job_poc_generation.settings.enabled = true`, and the full eight-job profile allowlist.
- **Effort**: `S`
- **Already registered**: no

#### C02-F14 Uncommissioned `native_dagster.py` and `native_engine.py` keep 427 lines of permanently blocked config, and `migration.py` ships test-only scaffolding in `src/`
- **Kind**: `remove`
- **Severity**: `low`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/config/native_dagster.py:41-44, 131-143`, `src/appsec_review/config/native_engine.py:1-283`, `src/appsec_review/migration.py:1-125`, `appsec-review.toml:1210`, `src/appsec_review/config/loader.py:1224-1226`; `reject_uncommissioned_native_execution()` unconditionally raises `RuntimeError` at every entry point, `migration.py` has zero callers outside `tests/test_migration_ledger.py`, and `force_buildability_probe = false` remains in `appsec-review.toml` solely to be rejected if set to any other value.
- **Impact**: Maintaining 427 lines of dead-blocked native configuration (where `native_dagster.py:41-44` also accepts any `[A-Za-z][A-Za-z0-9_-]{0,79}` string for `runtime_profile` instead of `PROFILES`), runtime-packaged test helpers (`migration.py`), and retired TOML keys (`force_buildability_probe`) enlarges the signed Python module surface and test burden with zero contribution to review findings or evidence.
- **Recommendation**: Move `src/appsec_review/migration.py` into `tests/`, delete `force_buildability_probe` from `appsec-review.toml` (keeping only the rejection of legacy `force_buildability_probe` in a closed settings schema), and either gate/retire `native_dagster.py` and `native_engine.py` until native execution has an approved commissioning item or tighten `runtime_profile` validation to `PROFILES`.
- **Effort**: `S`
- **Already registered**: no

#### C02-F15 C02 unit tests miss end-to-end capacity-overlay resume, plural/URI Swift rejection, `typed_settings` retention, and `load_config` validator parity
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: component-wide
- **Evidence**: `tests/test_inference_review_config.py:86, 185-204`, `tests/test_swift_policy.py:48-68`, `tests/test_run_selection.py:1-90`, `tests/test_config.py:1-120`; overlay tests assert `semantic_settings_view` equality without running `JobRunner` / `ResumePlanner`, `test_swift_policy.py` tests only singular `"language"`/`"path"` keys and expects `False` on missing `data/configuration/`, no test checks `job_project_build.typed_settings`, and no test checks `RunConfigurations.for_tags` with `host_pins` or mutated files.
- **Impact**: Because the tests exercise helper views in isolation rather than downstream runtime consumers (`JobRunner`, `ResumePlanner`, `input_matrix`, `job_build_iteration`), critical regressions in capacity-overlay resume (`C02-F03`), Swift policy enforcement (`C02-F02`), dropped `typed_settings` (`C02-F07`), and unhooked `jobs/*/settings.py` validators (`C02-F04`) shipped undetected.
- **Recommendation**: Add focused unit regressions in `tests/test_inference_review_config.py` (capacity-overlay change across `JobRunner` + `ResumePlanner`), `tests/test_swift_policy.py` (plural/URI keys and missing-manifest `ValueError`), `tests/test_config.py` (`typed_settings` non-`None` assertions and parity over all `src/appsec_review/jobs/*/settings.py` modules), and `tests/test_run_selection.py` (`for_tags` preserving `host_pins` and rejecting drifted `source_sha256`).
- **Effort**: `S`
- **Already registered**: no (Deduplicated in headline totals under `C02-F10`: `copilot_sdk.verify()` calling `load_config()` without the active run's `profile` or `overlay`.)
### C03 Orchestration, deployment and operator surface

**Active findings:** 19 (`1` critical, `4` high, `12` medium, `2` low).

C03's core `wave1_review` Dagster topology, tooling-only image with signed bind-mounted code, single-submission journal, and read-only operator MCP server are disciplined and preserve upstream handoff and coverage honesty end to end. Its sharpest risks sit in the operator and deployment seams around that core: `review_run.py` runs unhardened host `git status` directly inside untrusted target checkouts (allowing `.git/config` `core.fsmonitor` execution on the host), switching between Claude and Copilot profiles boots the wrong container image because `.env` pins a single untyped image digest, and the secondary `project_build_review` workflow, `smoke.py`, and `verify.py` have drifted out of parity with `JobContract` and `appsec-review.toml`. Recovery works without weakening evidence provenance, but the fix-reload-resume loop remains slower than necessary because `lifecycle.py reload` recreates `webserver` and `daemon` alongside `code-location`, lacks an active-run guard when called directly, and re-spawns every upstream unit subprocess on Dagster resume even when `claim["reused"]` is true. Cleaning up stale baked-image instructions in `deploy/dagster/README.md` and consolidating six duplicated GraphQL/`.env` helpers in `deploy/dagster/bin/` will remove operator traps at low cost.

**Strengths to preserve:**
- Contract-derived `wave1_review` graph topology (`src/appsec_review/orchestration/topology.py:18-92`, `src/appsec_review/orchestration/dagster/adapter.py:255-296`) projects disabled jobs transparently, propagates only declared upstream handoff SHA-256 pins, and prevents terminal completion or run-metrics publication unless every terminal producer finalized (`COMPLETED_WITH_GAPS` vs `SUCCEEDED`).
- Tooling-only container architecture with read-only source mounts and verified-byte module imports (`deploy/dagster/Dockerfile:16-22`, `deploy/dagster/compose.yaml:68-73`, `deploy/dagster/bin/bootstrap.py:1-58`) avoids rebuilding images for Python changes while failing closed on unsigned edits during an active run.
- Single-submission intent custody (`deploy/dagster/bin/review_run.py:55-125, 156-247`) atomically records and `fsync`s `active.json` with source commit, target commit, profile, overlay, and container image digest before `dagster job launch`, preventing duplicate concurrent dispatches and ambiguous lost-response launches.
- Read-only operator MCP and Dagster reader (`src/appsec_review/mcp/operator.py:1-380`, `src/appsec_review/mcp/dagster.py:1-376`) enforce closed schemas, symlink/FIFO rejection, secret/raw-stream redaction, loopback/HTTPS-only SSRF guards, and explicit `coverage_gaps` instead of silent empty results.
- Live incremental step-failure persistence (`src/appsec_review/orchestration/dagster/error_state.py:63-118`) writes one immutable file per failed step attempt during `STARTED` runs so error context survives mid-run crashes before terminal sensors fire.
- Guarded five-step `review-recover` workflow (`deploy/dagster/bin/ops.py:1221-1334`) sequences dispatch terminality, submission reconciliation, container-side worker-stop verification under `resume.lock`/`admission.lock`, `plan-repair` inspection, and hash-matched `admit-repair` without inventing override authority.

#### C03-F01 Host `git status` on untrusted target checkouts in `review_run.py` permits `.git/config` command execution
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/bin/review_run.py:86-98` and `deploy/dagster/compose.yaml:94-95`, contrasted with `src/appsec_review/target_acquisition/git_source.py:40-57` and `src/appsec_review/jobs/job_source_history_analysis/git.py:39-43, 119-126`. `submission_identity` executes host `git -C <target_path> status --porcelain --untracked-files=all` directly on the target repository without `-c core.fsmonitor=false`, clean-filter overrides, `--no-optional-locks`, or `GIT_CONFIG_*` isolation, while `compose.yaml` mounts `../../targets:/opt/app/targets` writable into `code-location`.
- **Impact**: Reviewing or recovering against a hostile target `.git` directory (or one mutated during a run through the writable `/opt/app/targets` mount) can execute arbitrary commands as the operator on the host via `core.fsmonitor` or index-refresh clean filters before Dagster even launches, and refreshes `<target>/.git/index` in place.
- **Recommendation**: Harden `git_identity` in `deploy/dagster/bin/review_run.py` (and host target `git` calls in `deploy/dagster/bin/stepwise.py:92-97, 394-398`) with `--no-optional-locks -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c filter.lfs.clean= -c filter.lfs.process=` and `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F02 `project_build_review` violates `JobContract` upstream handoffs and schedules internal transaction job `job_build_iteration`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/orchestration/dagster/adapter.py:157-163, 259-260, 280-282, 393-404`; `src/appsec_review/jobs/job_target_analysis_plan/datasets.py:54-56`; `src/appsec_review/jobs/job_build_iteration/datasets.py:50-56`; `src/appsec_review/jobs/job_artifact_security_analysis/datasets.py:44-52`. Each job's `finalize` op emits only `{job.job_id: handoff_sha256}` and `pack_upstream` collects handoffs solely from direct parents in `dependencies[job_id]`, yet `project_build_review` hardcodes a single-parent chain and includes `job_build_iteration` (`DispatchClass.INTERNAL_TRANSACTION`).
- **Impact**: Launching `project_build_review` fails closed in input admission because `job_target_analysis_plan` (when `job_build_environment_analysis` is enabled) is not wired to required `job_target_catalog`, `job_artifact_security_analysis` is not wired to required `job_language_build`, and `job_build_iteration` rejects missing `InputChannel.TRANSACTION` (`build_controller/iteration_request`), producing zero build or binary-security findings.
- **Recommendation**: Remove `project_build_review` (and `ci_configuration_review` at `adapter.py:376-379` if unused) from `src/appsec_review/orchestration/dagster/adapter.py`, or compute subgraph dependencies from `JobContract` (`consumes` + `schedule_after`, restricted to `DispatchClass.REVIEW_GRAPH`) via `src/appsec_review/orchestration/topology.py` and assert contract parity in `tests/orchestration/dagster/test_definitions.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F03 Switching provider families via `stack-restart --profile` boots the wrong container image
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/bin/ops.py:351-367, 709-714`; `deploy/dagster/bin/lifecycle.py:86-96, 117-127`; `deploy/dagster/Dockerfile:65-89`. `lifecycle.py` persists one untyped `APPSEC_REVIEW_DAGSTER_IMAGE=sha256:...` pin in `deploy/dagster/.env`, and `ops.bring_up` skips resolving or building `image_tag(profile)` whenever `APPSEC_REVIEW_DAGSTER_IMAGE` is already present in `.env`.
- **Impact**: When an operator follows `review-start`'s refusal message (`run scripts/stack-restart --profile copilot-prod first`), `stack-restart` keeps the signed Claude `runtime` image digest while switching to `compose.copilot.yaml`; the container lacks `github-copilot-sdk` and `/usr/local/bin/copilot`, failing the model probe and every inference-backed job until the operator manually runs `stack-rebuild --profile copilot-prod`.
- **Recommendation**: Persist provider-specific image pins (`APPSEC_REVIEW_DAGSTER_IMAGE_CLAUDE` and `APPSEC_REVIEW_DAGSTER_IMAGE_COPILOT`) or record the image's provider family alongside `APPSEC_REVIEW_DAGSTER_IMAGE` in `deploy/dagster/bin/lifecycle.py` and `deploy/dagster/bin/ops.py`, and add a cross-provider `stack-restart` test in `tests/test_operator_scripts.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F04 Writable `/opt/app/targets` mount breaks recovery when builds dirty the target and mismatches `APPSEC_REVIEW_SYSTEM`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/compose.yaml:8-10, 94-95`; `deploy/dagster/bin/review_run.py:93-116`; `deploy/dagster/bin/ops.py:1265-1266, 1334`. `compose.yaml` mounts `../../targets:/opt/app/targets` writable with the comment `"builds write their outputs into the checkout"`, whereas `review_run.submission_identity` requires `targets/<name>` to pre-exist on the host as a single clean Git working tree (`git status --porcelain --untracked-files=all`).
- **Impact**: Any build or analysis step that writes untracked files into `/opt/app/targets/<name>` causes `review-recover` (which delegates its final resume step to `cmd_review_start --run-id`) to refuse resumption with `"submission requires unchanged tracked source and a clean target"`, stranding accepted upstream evidence; separately, `APPSEC_REVIEW_SYSTEM` multi-repo acquisition runs cannot be submitted through `review-start` because `targets/<id>` does not exist as a single Git checkout prior to intake.
- **Recommendation**: Mount `../../targets:/opt/app/targets:ro` for pre-cloned target reviews so jobs never dirty the host checkout, and extend `deploy/dagster/bin/review_run.py` and `deploy/dagster/bin/ops.py` to bind `APPSEC_REVIEW_SYSTEM` manifest identity when system acquisition is configured.
- **Effort**: `M (days)`
- **Already registered**: no

#### C03-F05 `verify.py` checks only 14 early/mid Wave 1 jobs and `smoke.py` fails every feed run on `grype_db_sync`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/bin/verify.py:273-295, 429-469`; `deploy/dagster/bin/smoke.py:25, 212-214`; `appsec-review.toml:350-379`. `_verify_wave1_run` hardcodes 14 early/mid jobs for `wave1_review`, and `smoke.FEEDS` lists 6 feeds while `job_third_party_data_sync` publishes 7 snapshots including `grype_db_sync`.
- **Impact**: `verify.py --run-id <wave1-run>` reports a passing `acceptance_run` without inspecting consolidation, indexing, `job_inference_security_review`, PoC, remediation, `job_final_publication_gate`, `job_dossier_publication`, `job_openvex_export`, or `job_final_report_publication` (hiding missing or unverified tail receipts from operator verification), while `smoke.py --mode feeds` unconditionally raises `RuntimeError("missing feed snapshot publications")`.
- **Recommendation**: Derive expected `wave1_review` jobs in `deploy/dagster/bin/verify.py` from `enabled_wave1_dependencies` (matching `_workspace`), derive `FEEDS` in `deploy/dagster/bin/smoke.py` from `appsec-review.toml` `.publish` tasks (or add `"grype_db_sync"`), and test both against `appsec-review.toml`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F06 Per-run `--overlay` Dagster pool limits are recorded in `resolved.json` without governing Dagster execution
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/config/loader.py:898-905`; `src/appsec_review/orchestration/dagster/adapter.py:224, 297-302, 312-345`; `deploy/dagster/bin/ops.py:568-571`. `overlay_capacity_keys` explicitly allows `orchestration.dagster.pools.*` in capacity overlays and `RunConfigurations` writes those values into `runs/<run-id>/data/configuration/resolved.json`, but `_build_dagster_graph` freezes `multiprocess_executor(tag_concurrency_limits=...)` from `code-location`'s startup `base.dagster`.
- **Impact**: Launching `review-start --overlay <file>` with altered `orchestration.dagster.pools.*` executes under the container's startup pool concurrency while recording the overlay's pool limits in run provenance, misleading throughput/OOM triage and allowing unintended concurrency when a tighter pool cap was requested per run.
- **Recommendation**: Have `deploy/dagster/bin/ops.py` (`_review_start`) compare the run's resolved `config.dagster` against the running `code-location`'s startup `config.dagster` and refuse with a `stack-restart --overlay` remedy when `max_concurrent` or `pools` differ (matching the `--target` and `--recording` guards).
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F07 Direct `lifecycle.py reload` and `stop` bypass active-run contention checks
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/bin/lifecycle.py:166-175`; `deploy/dagster/bin/ops.py:229-248, 520-523`; `docs/architecture/deployment-image-and-source-mount.md:105`. `AGENTS.md` and the architecture doc instruct developers to deploy code changes with `lifecycle.py reload`, which runs `docker compose up -d --no-deps --force-recreate --wait code-location webserver daemon` without querying Dagster for active runs.
- **Impact**: Running `lifecycle.py reload` (or `stop`) while a review is `STARTED` or `QUEUED` kills `code-location` mid-step, orphans sibling build/scanner containers spawned via `/var/run/docker.sock`, leaves unfinalized attempt claims, and forces manual container cleanup plus `review-recover`.
- **Recommendation**: Add `guard_active_runs` (with `--force` override) to `reload` and `stop` in `deploy/dagster/bin/lifecycle.py` (sharing the check in `deploy/dagster/bin/host.py`), and recommend `scripts/stack-restart.sh --code-location-only` as the primary operator entrypoint in `docs/architecture/deployment-image-and-source-mount.md`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F08 Fix-reload-resume loop recreates non-worker services and spawns 100+ no-op unit subprocesses on resume
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/bin/lifecycle.py:170-171`; `deploy/dagster/compose.yaml:98-145`; `deploy/dagster/bin/ops.py:1303-1334`; `src/appsec_review/orchestration/dagster/adapter.py:210-285`. `lifecycle.py reload` force-recreates `webserver` and `daemon` alongside `code-location`, `review-recover` runs `plan-repair` twice (`plan-repair` then `admit-repair`) plus a live LLM probe, and Dagster's `multiprocess_executor` still spawns a fresh Python subprocess for every unit op (`<job>__<step>__<task>`) of every already-accepted upstream job even when `begin` sets `claim["reused"] = True`.
- **Impact**: Repairing a late-stage failure (for example in `job_inference_security_review` or `job_final_publication_gate`) incurs ~20-40s of unnecessary `webserver`/`daemon` container recreation and minutes of cold-start Python + signed-module verification across ~80-100 upstream unit ops that immediately return cached reuse results. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Resolved on `main` in `69693d133`, `2c9f26f35`, and `2780018a6`, which write terminal stop receipts and reconcile stale resource leases in live Dagster dispatch.]*
- **Recommendation**: Recreate only `code-location` on `lifecycle.py reload` when `python-modules.json` is mounted via its directory (not single-file inode) into `webserver`/`daemon`, and emit conditional Dagster outputs in `adapter.py` (`make_begin` routing `claim["reused"] == True` directly to `finalize`, bypassing intermediate unit subprocesses).
- **Effort**: `M (days)`
- **Already registered**: no

#### C03-F09 Direct `appsec-review` CLI ignores recorded `profile`/`overlay`, lacks `--overlay`, and misfilters `MANUAL_JOB_IDS`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/cli.py:42, 49-51, 180-191, 200-204`; `deploy/dagster/bin/ops.py:1214-1219, 1261-1262`. `cli._load` restores `compiler_target` from `runs/<run_id>/data/configuration/manifest.json` but ignores `selection.profile` and `selection.overlay` and offers no `--overlay` flag; `cli._review_jobs` excludes only `MANUAL_JOB_IDS = {"job_third_party_data_sync"}` instead of checking `JobContract.dispatch`; and `ops.fresh_start_command` omits `--compiler-target`.
- **Impact**: Direct CLI invocations (`plan-repair`, `admit-repair`, `plan-resume`, `resume`, `failure-replay`, `build-failure-context`) on a `prod` or overlay run silently load `dev`/no-overlay configuration unless callers manually inject env vars like `ops.py` does, causing false config-drift invalidations or admissions; local `appsec-review run` also attempts to schedule `DispatchClass.INTERNAL_TRANSACTION` job `job_build_iteration` as a top-level graph node.
- **Recommendation**: Restore `profile` and `overlay` from `manifest.json["selection"]` in `src/appsec_review/cli.py:_load`, add `--overlay`, replace `MANUAL_JOB_IDS` with `job.contract.dispatch is DispatchClass.REVIEW_GRAPH`, and include `--compiler-target` in `deploy/dagster/bin/ops.py:fresh_start_command`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F10 `review_run.effective_configuration` ignores `profiles/<profile>.toml` and `deploy/dagster/host-pins.toml`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/bin/review_run.py:39-57`; `deploy/dagster/bin/verify.py:488`; `deploy/dagster/bin/stepwise.py:124`. `effective_configuration` loads raw `appsec-review.toml` and deep-merges only `APPSEC_REVIEW_CONFIG_OVERLAY`, omitting `profiles/<profile>.toml` and `deploy/dagster/host-pins.toml`.
- **Impact**: `verify.py` workspace verification and `stepwise.py` target/mask lookups see a partially resolved configuration dictionary that diverges from `appsec_review.config.load_config` whenever a profile or host-pins file modifies job settings or release pins.
- **Recommendation**: Delegate `effective_configuration` in `deploy/dagster/bin/review_run.py` to `appsec_review.config.loader` (including active `profile` and `host-pins.toml`) rather than maintaining a second partial TOML merger.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F11 Terminal `error_state.py` sensor keeps only the 5 newest events, dropping earliest root-cause `STEP_FAILURE`
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/orchestration/dagster/error_state.py:55-60, 121-125`; `appsec-review.toml:14-15`. `record_error_state` queries `get_records_for_run(..., of_types={STEP_FAILURE, PIPELINE_FAILURE, PIPELINE_CANCELED}, limit=5, ascending=False)` and reverses those 5 newest events.
- **Impact**: Under `max_concurrent = 8` (or higher), concurrent branch failures plus `PIPELINE_CANCELED`/`PIPELINE_FAILURE` push the first failing step out of the 5-record window, losing the root-cause failure in `runs/metadata/dagster-error-state/<run_id>.log` whenever the incremental `wave1_step_failure_state` sensor missed ticks (for example across a daemon restart).
- **Recommendation**: Fetch the earliest `STEP_FAILURE` records with `ascending=True` (bounded to e.g. 25) plus the terminal `PIPELINE_FAILURE`/`PIPELINE_CANCELED` event in `src/appsec_review/orchestration/dagster/error_state.py`, and add a >5-failure regression test in `tests/orchestration/dagster/test_error_state.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F12 Operator MCP `read_logs` invalidates cursors on active runs and caps forward scans at 1 MiB; CLI `logs --follow` is $O(N^2)$
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/mcp/operator.py:55, 259-295`; `src/appsec_review/cli.py:293-312`. `operator._identity` includes `st_size` and `st_mtime_ns` in cursor state while scanning from byte 0 up to `MAX_SCAN_BYTES = 1 MiB` (leaving lines `275-276` unreachable dead code), and `cli._cmd_logs` re-reads and parses the entire `pipeline.jsonl` every 0.5s during `--follow`.
- **Impact**: Any telemetry event appended during a live run invalidates outstanding MCP `read_logs` cursors (`"pipeline log changed; restart pagination"`), making entries past the first 1 MiB unreachable via MCP until the run stops; CLI `logs --follow` burns CPU and disk I/O quadratically on long runs.
- **Recommendation**: Anchor `read_logs` cursors to `(st_dev, st_ino)` plus the verified record SHA-256 at the cursor offset so append-only growth preserves pagination, add `since_sequence` / tail support in `src/appsec_review/mcp/operator.py` (deleting dead lines `275-276`), and seek from the last read byte offset in `src/appsec_review/cli.py:_cmd_logs`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F13 `review-recover` admits the repair plan before probing model login, and its unit test locks in the wrong order
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/bin/ops.py:1326-1334`; `tests/test_operator_scripts.py:575-582`. `cmd_review_recover` executes `admit-repair` inside `code-location` before calling `cmd_review_start`, which runs the Claude/Copilot login probe, and `test_review_recover_resume_keeps_every_launch_guard` explicitly asserts `recover_steps(box) == ["verify-stops", "plan-repair", "admit-repair", "model-probe"]`.
- **Impact**: When OAuth credentials expired while preparing a fix, `review-recover` writes an immutable admission receipt under `runs/<run_id>/data/recovery/` and then aborts before launch, forcing a second admission cycle after re-authenticating.
- **Recommendation**: Run `probe_model_login` before `admit-repair` in `deploy/dagster/bin/ops.py:cmd_review_recover`, pass `--no-probe` to the delegated `cmd_review_start` call so the probe runs once, and update `tests/test_operator_scripts.py:575-582`.
- **Effort**: `S (under a day)`
- **Already registered**: T-085 — still open; new finding is that `tests/test_operator_scripts.py:575-582` actively asserts the post-admission probe order

#### C03-F14 `DAGSTER_QUEUE_DELAY` measures elapsed run age instead of step queue wait
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/orchestration/dagster/adapter.py:215-221`. Every job's `begin` op computes `datetime.now(timezone.utc).timestamp() - context.dagster_run.create_timestamp` and writes it as `DAGSTER_QUEUE_DELAY`.
- **Impact**: Downstream jobs (`job_inference_security_review`, `job_final_report_publication`) log the entire upstream run duration (tens of minutes to hours) as queue delay in `pipeline.jsonl`, obscuring genuine Dagster pool starvation and repair-loop latency metrics.
- **Recommendation**: Emit `create_timestamp` queue delay only for root jobs (`not dependencies[job_id]`) and measure downstream scheduling lag from the maximum `completed_at` timestamp of direct upstream handoffs in `src/appsec_review/orchestration/dagster/adapter.py`.
- **Effort**: `S (under a day)`
- **Already registered**: T-059 and prior review C7/F10 — still unfixed at `f29ee4c688bce7d0d7ca2f1b30a9477a63647ad1`

#### C03-F15 `Dockerfile` `runtime-copilot` stage installs floating transitive dependencies without `--no-deps` or lockfile hashes
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/Dockerfile:24-27, 70-73`; `deploy/dagster/requirements.copilot.txt:1-3`. Unlike `runtime` (`pip install --no-deps -r /tmp/requirements.lock.txt`), `runtime-copilot` runs `pip install --no-cache-dir -r /tmp/requirements.copilot.txt` with `pydantic>=2.0` and live dependency resolution enabled.
- **Impact**: Rebuilding the Copilot stack image can pull newer transitive packages (or upgrade `pydantic` over the base lockfile), breaking reproducibility between Claude and Copilot runtime environments and risking subtle SDK serialization regressions.
- **Recommendation**: Generate a locked `deploy/dagster/requirements.copilot.lock.txt` and install it with `pip install --no-cache-dir --no-deps` in `deploy/dagster/Dockerfile:72-73`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F16 `deploy/dagster/README.md` and `run-readiness` docs/output teach an obsolete baked-image model and stale commit count
- **Kind**: `doc-drift`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/README.md:19-22, 107, 169-174, 199-203, 235-241, 262, 332-345, 391, 469-473`; `deploy/dagster/bin/ops_readiness.py:173-177, 242`; `docs/operations/operator-scripts.md:369, 390`. `deploy/dagster/README.md` claims the image bakes in `appsec-review.toml` and `/usr/local/lib/python3.12/site-packages/appsec_review` (`"Rebuild the application image after integrating code"`), contradicts itself on `/opt/app/targets` (`:rw` at line 107 vs `:ro` at line 262), and lists an obsolete Wave 1 graph; `ops_readiness.py` and `operator-scripts.md` say `run-readiness` makes "at most two commits" although `step_pin` writes git-ignored `host-pins.toml` and never commits.
- **Impact**: Operators and agents reading `deploy/dagster/README.md` run full `stack-rebuild` image builds on routine Python edits—wasting minutes per repair iteration and violating `AGENTS.md`—or misread the Wave 1 topology and readiness git history expectations.
- **Recommendation**: Reconcile `deploy/dagster/README.md` with `docs/architecture/deployment-image-and-source-mount.md` and generated topology views, and update `deploy/dagster/bin/ops_readiness.py:242` and `docs/operations/operator-scripts.md:369, 390` to state at most one commit (public trust anchor only).
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F17 PowerShell twins `run-readiness.ps1` and `stack-logs.ps1` have drifted from `ops.py` and `.sh` wrappers
- **Kind**: `defect`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `scripts/run-readiness.ps1:23, 42, 56-60` vs `scripts/lib/common.ps1:118-125` and `scripts/compile-codeql-queries.ps1:50-55`; `scripts/stack-logs.ps1:11` vs `deploy/dagster/bin/ops.py:40-42, 1367`. `run-readiness.ps1` hardcodes `$Distro = 'Ubuntu-24.04'` without `\\wsl.localhost\<distro>` inference and passes `-PrivateKey` without `ConvertTo-WslPath`; `stack-logs.ps1` omits `'result-cache'` from `[ValidateSet(...)]`.
- **Impact**: Operators invoking `scripts/stack-logs.ps1 result-cache` get a PowerShell parameter binding error even though `ops.py` and `stack-logs.sh` support `result-cache`, and `run-readiness.ps1` fails on non-default WSL distro names or Windows `-PrivateKey` paths.
- **Recommendation**: Add `'result-cache'` to `ValidateSet` in `scripts/stack-logs.ps1:11`, use `common.ps1` WSL distro detection and `ConvertTo-WslPath` on `-PrivateKey` in `scripts/run-readiness.ps1`, and assert service-list parity in `tests/test_operator_scripts.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F18 Six `deploy/dagster/bin/` scripts duplicate GraphQL transport, `.env` parsing, and diverging non-terminal status sets
- **Kind**: `remove`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `deploy/dagster/bin/ops.py:39, 102-151, 211-248`; `deploy/dagster/bin/smoke.py:30-66`; `deploy/dagster/bin/verify.py:34-49`; `deploy/dagster/bin/recover_runs.py:61-101`; `deploy/dagster/bin/stepwise.py:99-135`; `deploy/dagster/bin/review_run.py:130-154`. Six scripts maintain copy-pasted `urllib` GraphQL clients and `.env` parsers, and `smoke.py:55` checks only `{"STARTED", "STARTING", "QUEUED"}` while `ops.NON_TERMINAL` (`ops.py:39`) and `recover_runs.ACTIVE_STATUSES` include `NOT_STARTED` and `CANCELING`.
- **Impact**: `smoke.py` can launch destructive smoke checks while a run is `NOT_STARTED` or `CANCELING`, and transport timeout/error-redaction fixes have to be patched in six places (plus standalone regex log scraper `deploy/dagster/bin/run_report.py`, which overlaps `review-status`).
- **Recommendation**: Move one canonical operator GraphQL helper and `NON_TERMINAL` status set into `deploy/dagster/bin/host.py`, delete the duplicate implementations across the six `deploy/dagster/bin/*.py` modules, and either fold `run_report.py` into `ops.py review-status` or delete it if unused.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C03-F19 Unit tests mock away composite-graph contract satisfaction, provider image switches, and `smoke`/`verify` config parity
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/orchestration/dagster/test_definitions.py:437-458`; `tests/test_operator_scripts.py:666-679`; `tests/test_dagster_smoke.py:78-95`; `tests/test_dagster_verify.py:16-66`. `test_definitions.py` inspects only `target_analysis_plan__begin` in `project_build_review` without checking `JobContract` handoff satisfaction; `test_operator_scripts.py` pre-populates a Copilot stack rather than switching from `dev` with a pinned `.env` digest; `test_dagster_smoke.py` mocks `verify.py` output from `smoke.FEEDS` itself; and `test_dagster_verify.py` never exercises `_verify_wave1_run`.
- **Impact**: Four real regressions in C03 (`project_build_review` contract breakage, `stack-restart --profile copilot-*` wrong-image launch, `smoke.FEEDS` missing `grype_db_sync`, and `verify.py`'s 14-job Wave 1 check) all coexist with a green C03 unit test suite.
- **Recommendation**: Add fast unit regressions in `tests/orchestration/dagster/test_definitions.py` (every composite Dagster job's direct parents satisfy `job.contract.consumes` and exclude non-`REVIEW_GRAPH` jobs), `tests/test_operator_scripts.py` (`dev` -> `copilot-prod` `stack-restart` selects the Copilot image), and `tests/test_dagster_smoke.py` / `tests/test_dagster_verify.py` (asserting parity with `appsec-review.toml` and `enabled_wave1_dependencies`).
- **Effort**: `S (under a day)`
- **Already registered**: no
### C04 Container images, signing and supply chain

**Active findings:** 8 (`1` critical, `1` high, `5` medium, `1` low).

C04 provides three supply-chain and isolation boundaries:
1. **Container catalog and build validation** (`containers/catalog.toml`, `containers/runtime-policy.toml`, `containers/build.py`, `containers/tools/shared/safe_extract.py`): 42 audited base, toolchain, and scanner images with digest-pinned `FROM` lines, SHA-256-locked assets, non-root `USER 10001`, `--network=none` build flags, and reviewed extraction inventories (`safe_extract.py`).
2. **Ed25519 signing and verified-byte execution** (`src/appsec_review/signing/`): detached DSSE-style JSON envelopes (<!-- historical:begin -->`appsec-review/signed-statement/1`<!-- historical:end -->) verified via OpenSSL 3 for container image IDs (`images.py`), Python module manifests (`modules.py`) enforced at import time by `VerifiedFinder` (`import_hook.py` / `bootstrap.py` / `sitecustomize_shim.py`), and the shared native C library (`release_lib.py`).
3. **Container launch, build capture, and run-start pin gate** (`src/appsec_review/container_runtime/`, `src/appsec_review/jobs/job_image_pin_verification/`): `job_image_pin_verification` checks active host image tags against `deploy/dagster/host-pins.toml` (`configuration_host_pins`) at run start; `ContainerExecutor` runs read-only, `--network none`, `--cap-drop ALL`, `no-new-privileges` scanner containers; `BuildContainerExecutor` runs offline target builds under `strace --seccomp-bpf -y` + `tool-wrapper.py` capture followed by a fail-closed `tool-gitleaks` disposition scan; and `image_builder_service.py` / `engine_broker.py` broker derived-image builds (rootless BuildKit + `audit-dep-proxy`) and native-isolated Docker invocations over authenticated Unix sockets.

**Strengths to preserve:**
- **Verified-byte Python import hook (`signing/import_hook.py:67-166`, `signing/modules.py:130-217`):** `VerifiedFinder` installs at `sys.meta_path[0]`, loads verified source bytes into memory once (`VerifiedManifest`), blocks symlinked files/ancestors, rejects bytecode `.pyc` trust, blocks native extension loading under `package_root`, and checks already-imported `appsec_review.*` modules during `bootstrap()` (`signing/bootstrap.py:93-128`).
- **Fail-closed post-build secret disposition (`container_runtime/build_executor.py:735-922`):** Captured `strace` traces, `events.jsonl`, `stdout`/`stderr`, response files, and compiler wrapper records are scanned by `tool-gitleaks` before raw `trace*` files are unlinked; if `tool-gitleaks` times out, fails, or produces no report, every retained capture source and `record_argv` is scrubbed to `<redacted: secret scan disposition>` (`build_executor.py:893-917`).
- **Strict compiler-probe parser (`container_runtime/compiler_profiles.py:56-165`):** Treats container probe output as untrusted, enforces byte/line ceilings via `head -c` with explicit `@@overflow` markers rather than silent truncation, and fails closed if `readlink -f` diverges from the step-by-step symlink hop chain.
- **Archive extraction closure verification (`containers/tools/shared/safe_extract.py:206-360`):** Validates both SHA-256 and SHA-512 against `assets.lock.json`, enforces member count, expanded byte limits, and compression ratios, extracts only allowlisted closure prefixes into an empty directory, and checks the deterministic file/JAR/ELF inventory against a committed `--expect-inventory` snapshot.

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_image_pin_verification` | `data/configuration/resolved.json` (`configuration_host_pins`), `containers/catalog.toml`, Docker daemon image inspection + optional Ed25519 signature envelopes (`signing/images.py`) | `image_pin_verification` (`image-pin-verification.json`, `handoff.json`); run-start preflight gate | `C04-F01` / `C04-F02` (23 of 25 runtime `load_catalog` callers omit `resolved_config`, and `configured_pins()` skips `preinstalled_runtimes` while treating `expected=None` as `"present"`) | rework |

#### C04-F01 Launch-time catalog image digest pins (`expected_image_id`) are silently `None` across 22 of 24 production call sites (`T-051` regression)
- **Kind**: `trust-boundary`
- **Severity**: `critical`
- **Confidence**: `high`
- **Job**: none (shared `container_runtime.catalog` across 15+ containerized jobs)
- **Evidence**: `src/appsec_review/container_runtime/catalog.py:80-104`, `src/appsec_review/container_runtime/executor.py:153-163`, `src/appsec_review/container_runtime/build_executor.py:774,824-828`, `src/appsec_review/jobs/job_review_data_indexing/job.py:114-118` (and 15 other job/helper call sites). `T-051` removed every `image_id` from `containers/catalog.toml` and moved host-local image digests into `deploy/dagster/host-pins.toml`, bound at config load time into `resolved_config["configuration_host_pins"]["catalog_images"]`. However, `load_catalog(repository_root, path=None, *, resolved_config=None)` (`catalog.py:80-104`) leaves `resolved_config` optional (`None`). When omitted, `bound_catalog_images(resolved_config)` is skipped and `ToolImage.expected_image_id` is `None` for all 42 catalog images. `ContainerExecutor.resolve_image()` (`executor.py:160`) guards digest enforcement behind `if tool.expected_image_id is not None and image_id != tool.expected_image_id: raise ValueError(...)`. Across `src/appsec_review/`, **17 of 19 production call sites** call `load_catalog(...)` without `resolved_config=` (`build_executor.py:772`, `job_artifact_security_analysis/scanners.py:398`, `job_ci_configuration_analysis/job.py:163`, `job_tree_sitter_ast/job.py:55`, `job_tree_sitter_ast/scope_execution.py:37`, `job_cpp_compiled_analysis/job.py:36`, `jobs/cpp_index_scopes.py:67`, `job_dependency_intelligence/integration.py:100`, `job_evidence_collection/job.py:575`, `job_source_history_analysis/job.py:173`, `job_change_context_analysis/job.py:149`, `job_review_data_indexing/job.py:115`, `binary_decompilation/runner.py:41`, `binary_decompilation/efficacy.py:101`, `debug_symbols/execution.py:322`, `reporting/dossier_render.py:194`, `reporting/telemetry_render.py:182`). Only `job_third_party_data_sync/job.py:103` and `debug_symbols/execution.py:293` pass `resolved_config=`.
- **Impact**: Launch-time digest verification (`image_id == expected_image_id`) is completely bypassed in almost every scanner, AST, indexing, build-secret-scan (`tool-gitleaks`), and reporting container execution. Because `[signing] image_enforcement` defaults to `"disabled"`, any tag retagged or rebuilt after `job_image_pin_verification` (or during resumed/repair execution when `job_image_pin_verification` does not re-run, or when `job_image_pin_verification` itself skips disabled/unlisted tools) runs arbitrary local tag contents without failing closed. Additionally, `job_review_data_indexing/job.py:115` reads `expected = load_catalog(unit.job.repository_root).tool(fts_worker.TOOL_ID).expected_image_id`, which permanently evaluates to `None`.
- **Recommendation**: Require `resolved_config` (or an explicit `allow_unpinned_for_tests: bool = False` keyword-only escape hatch) in `load_catalog`, pass `resolved_config=unit.job.resolved_config` at all 17 runtime call sites (including `BuildContainerExecutor` for `tool-gitleaks`), and make `ContainerExecutor.resolve_image()` fail closed when `tool.expected_image_id is None` unless explicitly running an unpinned build/test helper.
- **Effort**: `M`
- **Already registered**: none (`T-051` is marked `done (2026-11-10)` and explicitly promised `"gate, signer, preflight and executors consume the effective configuration"`)

#### C04-F02 `job_image_pin_verification` misses `preinstalled_runtimes` and `image`-keyed pins, and treats unpinned `"present"` images as `PASSING`
- **Kind**: `trust-boundary`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: `job_image_pin_verification`
- **Evidence**: `src/appsec_review/jobs/job_image_pin_verification/pins.py:22,29-51,75-97`, `src/appsec_review/config/host_pins.py:14-18,88-96`, `src/appsec_review/signing/cli.py:326-352`. `pins.configured_pins()` delegates job-setting pin discovery to `host_pins.image_settings()`, which only recognizes `PIN_PAIRS = (("tag", "image_id"), ("image_tag", "image_id"), ("source_image_tag", "source_image_id"))` and explicitly skips `preinstalled_runtimes` (`if key == "preinstalled_runtimes": continue` at `host_pins.py:93`). By contrast, `signing/cli.py:326-352` (`pinned_images`) had to write a separate recursive walker because `configured_pins()` misses both `preinstalled_runtimes[*].build_image_id` / `runtime_image_id` (`job_codeql_analysis`) and step settings paired as `("image", "image_id")` (such as `job_third_party_data_sync`'s `cve_bin_tool_db_build`). Furthermore, `pins.py:22,79-82` defines `PASSING = frozenset({"matched", "present"})`, where `expected is None` yields `status = "present"`.
- **Impact**: First, `job_image_pin_verification` never checks `preinstalled_runtimes` or `("image", "image_id")` entries at run start, so a missing, drifted, or unsigned CodeQL runtime image or DB-build image passes the run-start pin gate and fails much later inside `job_codeql_analysis` or `job_third_party_data_sync` (or runs unchecked). Second, any catalog tool or job setting lacking a pin in `host-pins.toml` (`expected is None`) resolves to `"present"` and passes `job_image_pin_verification` silently instead of failing closed as unpinned.
- **Recommendation**: Unify pin discovery between `job_image_pin_verification/pins.py`, `config/host_pins.py`, and `signing/cli.py` so `preinstalled_runtimes` and `("image", "image_id")` pairs are verified identically by both the signer and the run-start gate, and remove `"present"` from `PASSING` so an active image without a pinned `image_id` fails closed.
- **Effort**: `M`
- **Already registered**: none

#### C04-F03 `job_image_pin_verification` fails before publishing `outcomes.json` or `handoff.json`, stranding `producer-gap/1` records and contradicting docs
- **Kind**: `contract-mismatch`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_image_pin_verification`
- **Evidence**: `src/appsec_review/jobs/job_image_pin_verification/job.py:114-140`, `docs/operations/image-pin-verification.md:91-95`. When any pin is missing, mismatched, or fails signature verification, `verify_pins` (`job.py:119-139`) builds `producer-gap/1` records via `producer_gap(...)`, embeds them inside `image-pin-verification.json`, writes a `JOB_WARNING` pipeline event, and immediately raises `ImagePinVerificationFailed`. Because `TaskUnit.run` catches `Exception` and fails the job before `publish_immutable_job` executes, no `outcomes.json` or `handoff.json` is ever published on failure, even though `ImagePinVerificationJob` declares `strict_gaps=True` and `docs/operations/image-pin-verification.md:93` states that downstream jobs are blocked when `job_image_pin_verification` fails. Meanwhile `containers/README.md` still describes older `PARTIAL` behavior in places, and `appsec-review.toml` assigns `verification.inspect_images` to the `owasp_verification` worker pool (`docs/operations/job_image_pin_verification.md:27`).
- **Impact**: Raising `ImagePinVerificationFailed` rightly halts downstream execution via Dagster/orchestrator failure, but any consumer or audit tool inspecting `outcomes.json` for `producer-gap/1` records on failed pin runs will find no published envelope—only the uncommitted attempt-local `image-pin-verification.json`. Assigning an infrastructure Docker-inspect step to `owasp_verification` also couples container preflight concurrency to the OWASP verification pool.
- **Recommendation**: Document explicitly across `containers/README.md` and `docs/operations/job_image_pin_verification.md` that `image-pin-verification.json` is an attempt-local diagnostic artifact on `FAILED` runs (since `FAILED` jobs intentionally withhold `handoff.json`), and move `verification.inspect_images` onto a dedicated infrastructure/control worker pool instead of `owasp_verification`.
- **Effort**: `S`
- **Already registered**: none

#### C04-F04 POSIX key-custody checks are missing on `TrustedKeys.load()` and `sign_statement()`
- **Kind**: `trust-boundary`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: none (`signing/core.py`)
- **Evidence**: `src/appsec_review/signing/core.py:682-709,759-775,498-524`. On Windows (`os.name == "nt"`), `TrustedKeys.load()` calls `_check_windows_trusted_keys_acl(directory)` on every load (`core.py:688-689`), and `check_private_key_custody()` verifies restrictive ACLs (`core.py:768-769`). On POSIX, however, `TrustedKeys.load()` performs **zero** ownership or mode checks (`0o022` group/world-writable or symlink checks) on `trusted_keys_dir` or its `*.pem` files (only the separate `native/root_entrypoint.py` checks `trusted_path` when starting the privileged native broker). Likewise, `check_private_key_custody()` is only called by `generate_keypair()`, not by `sign_statement()`, and on POSIX only checks `(st_mode & 0o077) != 0` on the key file itself without checking parent directory mode or symlinks.
- **Impact**: On Linux/WSL deployments (the primary execution host per `AGENTS.md`), when `[signing]` enforcement is enabled without the native root broker—or during host CLI verification/signing—a group- or world-writable `trusted_keys_dir` or `.pem` file, or a `0644` private key copied onto the host, is accepted without error, creating a custody asymmetry relative to Windows.
- **Recommendation**: Enforce POSIX non-symlink, owner-only/non-group-or-world-writable (`(st_mode & 0o022) == 0`) checks on `trusted_keys_dir` and every `.pem` anchor inside `TrustedKeys.load()`, and call `check_private_key_custody(private_key_path)` inside `sign_statement()` on both POSIX and Windows.
- **Effort**: `S`
- **Already registered**: none

#### C04-F05 Native `engine_broker.py` neither verifies image signatures nor receives envelopes from `sign-image --all-pinned`
- **Kind**: `trust-boundary`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: none (`container_runtime/engine_broker.py`, `signing/cli.py`)
- **Evidence**: `src/appsec_review/container_runtime/engine_broker.py:407-417`, `src/appsec_review/signing/cli.py:362-383`, `docs/operations/signing.md:567-584`. `NativeExecutionDriver.image()` (`engine_broker.py:407-417`) inspects the Docker image ID and compares it against `self.settings.images` (the `native_engine.images` allowlist in builder-service config), but never invokes `ImageSignatureVerifier`. Consistently, `signing/cli.py:362-383` (`pinned_builder_service_images`) collects `worker_image_id`, `proxy_image_id`, and `service.images` for `sign-image --all-pinned --builder-service-config`, omitting `service.native_engine.images`.
- **Impact**: Even when `[signing] image_enforcement = "required"` is enabled on the application side and `image_builder_service.py` enforces image signatures on BuildKit worker/proxy/base images, the privileged `engine_broker.py` daemon accepts unsigned images if its allowlist config is drifted, and an operator running `sign-image --all-pinned --builder-service-config` will miss `native_engine.images` entries that aren't duplicated elsewhere. (`docs/operations/signing.md:567-584` documents this omission, but no `docs/TODO.md` item tracks closing it.)
- **Recommendation**: Include `service.native_engine.images` in `pinned_builder_service_images()`, wire `ImageSignatureVerifier` into `NativeExecutionDriver.image()` when `builder_service.signing` is configured, and register a `T-NNN` item in `docs/TODO.md` until landed.
- **Effort**: `S`
- **Already registered**: none (mentioned in `docs/operations/signing.md:567-584`, untracked in `docs/TODO.md`)

#### C04-F06 Plain Docker `BuildContainerExecutor` reserves host CPU/memory in Python without passing `--cpus` or `--memory` to `docker run`
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: none (`container_runtime/image_builder_service.py`)
- **Evidence**: `src/appsec_review/container_runtime/build_executor.py:372-415`. `BuildContainerExecutor._prepare()` (`build_executor.py:372-415`) passes `--pids-limit 512`, `--cap-drop ALL`, and `--security-opt no-new-privileges` to `docker run`, and enters `bounded_execution(cpu="2", memory="4g", ...)` (`build_executor.py:451`) on the Python-side admission ledger. However, `--cpus 2 --memory 4g` is only appended inside `if native_execution_requested():` (`build_executor.py:381-383`). In standard (non-native-broker) Docker execution, `docker run` receives **no** `--cpus` or `--memory` flags at all—unlike `ContainerExecutor` (`executor.py:194`), which always passes `--cpus <tool.cpus> --memory <tool.memory>`.
- **Impact**: On standard Docker hosts, an untrusted target build (`mvn`, `cargo`, `npm`, `cmake`, `clang++`) can consume 100% of host CPU cores and exhaust host RAM despite the Python admission ledger believing each build container is bounded to 2 CPUs and 4 GiB.
- **Recommendation**: Pass explicit `--cpus` and `--memory` flags unconditionally in `BuildContainerExecutor._prepare()` (matching the values passed to `bounded_execution`), configurable via typed build profile/executor settings.
- **Effort**: `S`
- **Already registered**: none

#### C04-F07 `containers/build.py` Dockerfile policy validator checks `USER 10001` anywhere in file, misses multiline `curl | sh`, and hardcodes `audited=42`
- **Kind**: `trust-boundary`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: none (`container_runtime/build_executor.py`)
- **Evidence**: `containers/build.py:92-94,116-143,1162`. `validate_dockerfile_text()` (`containers/build.py:124-126`) enforces `"final non-root USER 10001 is required"` using `re.search(r"(?m)^USER\s+10001(?::10001)?\s*$", text)`. Because `re.search` matches anywhere in the file, a multi-stage Dockerfile with `USER 10001` in stage 1 and `USER root` (or no `USER`) in the final stage—or `USER 10001` followed later by `USER 0`—passes static validation. Similarly, `_REMOTE_PIPE_RE` and `_UNPINNED_INSTALL_RE` (`build.py:47-55`) scan line-by-line or without collapsing `\\\n` continuations, missing multiline `curl ...\n  | sh` or `pip install \\\n foo`. Finally, `build.py:92-94` and `build.py:1162` hardcode `if len(audited) != 42:` (`audited=42`).
- **Impact**: Static catalog validation (`python3 containers/build.py --validate`) can false-pass a Dockerfile whose final stage runs as `root` or pipes remote scripts across backslash-continued lines, and adding or retiring any audited image breaks `build.py` until magic constants at two lines are edited.
- **Recommendation**: Collapse Dockerfile backslash line continuations before regex scanning, parse the last stage's effective last `USER` instruction to verify it is `10001` (`10001:10001`), and move any expected catalog count assertion into `runtime-policy.toml` (or test assertions) rather than hardcoding `42` in `build.py`.
- **Effort**: `S`
- **Already registered**: none

#### C04-F08 `tool-wrapper.py` creates world-writable (`0777`/`0666`) directories and records inside the active build container
- **Kind**: `trust-boundary`
- **Severity**: `low`
- **Confidence**: `high`
- **Job**: none (`containers/*`, `signing/core.py`)
- **Evidence**: `containers/build-capture/tool-wrapper.py:72-108`, `src/appsec_review/container_runtime/build_executor.py:559-560,670-683`. During captured builds, `build_executor.py:560` sets `capture_root.chmod(0o733)` and `tool-wrapper.py:73,97-107` sets `chmod(0o777)` on `tool-calls` and `call_root` and `chmod(0o666)` on `stdout`, `stderr`, and `record.json` so compiler subprocesses inside the container can write tool-call records. After the container exits, `_take_tool_call_ownership()` (`build_executor.py:670-683`) replaces the tree with `0o700`/`0o600` host copies. However, *during* the build, every subsequent untrusted build step (e.g., a test script, proc-macro, `build.rs`, or `setup.py` invoked by the build) runs as the same container UID with full write access to `0777`/`0666` prior `tool-calls/*` records, and `_take_tool_call_ownership()` calls `shutil.copytree(tool_root, staging)` without `symlinks=True` (default `symlinks=False` follows symlinks inside `tool-calls/`!).
- **Impact**: A malicious build script inside the container can overwrite earlier `tool-calls/*/record.json` entries to forge compiler flags in wrapper records (though kernel `strace` `events.jsonl` remains separate) or plant a symlink inside `tool-calls/` pointing at `/etc/passwd` or a host-mounted workspace file that `shutil.copytree(..., symlinks=False)` dereferences on the host as the application user!
- **Recommendation**: Reject symlinks (and special files/FIFOs) inside `tool-calls` before copying on the host (never call `shutil.copytree` with `symlinks=False` on container-writable directories—a FIFO will hang the host worker indefinitely and a symlink can disclose host paths!), and tighten `tool-wrapper.py` permissions to `0o700`/`0o600` since the container runs under a single numeric UID (`runtime_user`).
- **Effort**: `S`
- **Already registered**: none (note: the FIFO/symlink hazard in `_take_tool_call_ownership` makes fixing the host copy check especially worthwhile)
### C05 Target acquisition, intake, catalog and analysis planning

**Active findings:** 11 (`0` critical, `2` high, `6` medium, `3` low).

C05 owns target materialization (`target_acquisition/`, `job_target_acquisition`), run intake (`job_review_intake`), deterministic repository partitioning, component/build/Unity discovery and initial retrieval indexing (`job_target_catalog`, `jobs/{cataloging,component_ownership,delivery_scope,build_discovery,discovery_assignment,engine_discovery}.py`), static developer-script inspection (`job_build_environment_analysis`), and deterministic-plus-bounded-feedback analysis planning (`job_target_analysis_plan`). Acquisition custody, Perforce/review-export pinning, path-assignment coverage, and <!-- historical:begin -->`proposal/3`<!-- historical:end --> feedback bounds are carefully engineered. The sharpest defects are at job seams: `job_build_environment_analysis.load_environment` reads mutable `latest.json` files directly instead of claim-pinned upstream handoffs; `job_target_analysis_plan` leaves `accepted_artifacts` permanently empty (`()`), causing `accepted-analysis-plan.json` to mark `tool-spotbugs` and `tool-blint` non-selected even when pre-built artifacts exist; `git` acquisition still loads operator global Git configuration (`url.<base>.insteadOf`); and `job_target_catalog` re-reads target files without SHA-256 verification when building `source` and `analysis` SQLite shards.

**Strengths to preserve:**
- **Custody-hardened target materialization (`src/appsec_review/target_acquisition/git_source.py:92-198`, `archive_source.py:78-174`, `p4_source.py:85-160`):** Git, archive, and Perforce acquisition enforce SHA-256/commit pinning, symlink and path-escape refusal, bounded extraction sizes, and detached provenance receipts before any downstream scanner touches target bytes.
- **Complete, deterministic path-ownership partitioning (`src/appsec_review/jobs/component_ownership.py:42-138`, `discovery_assignment.py:31-118`):** Every cataloged target path is deterministically assigned to a component/partition with explicit delivery-scope classification (`first_party`, `third_party`, `generated`, `test`, `fixture`) rather than ad hoc per-scanner directory globs.
- **Bounded model feedback in analysis planning (`src/appsec_review/jobs/job_target_analysis_plan/planning.py:118-246`, `job.py:440-520`):** `target-analysis-proposal/3` keeps deterministic discovery authoritative and restricts LLM proposals to closed-vocabulary adjustments that cannot invent uncataloged paths or weaken security policy.

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_target_acquisition` | `data/configuration/appsec-review.toml` (`[target_acquisition]`, bypassing `resolved.json`), external/pinned Git, archive, or Perforce sources | Materialized target checkouts under `targets/` + provenance manifests (`target-acquisition/1`) | `C05-F03` (inherits operator `~/.gitconfig` `url.<base>.insteadOf`) and `C05-F10` (ignores `resolved.json` profile overrides) | rework |
| `job_review_intake` | `job_target_acquisition` (optional), operator `--target` snapshot, `data/configuration/resolved.json` | `review_intake` (`intake.json`, target snapshot manifest, `binary_evidence`, configured model inventory) | Coupled to raw `--target` mutation window when run outside immutable snapshot custody (`C05-F04`) | keep |
| `job_target_catalog` | `job_review_intake` (`accepted_upstream`), target tree bytes | `source-catalog`, `repository-partitions`, `components`, `build_units`, `dependency-catalog/1`, initial `source`, `analysis`, and `documents` SQLite shards | `C05-F04` (re-reads target files without SHA-256 verification), `C05-F07` (7-keyword line-prefix regex symbol index), `C05-F08` (Node-only dependency parser) | rework |
| `job_build_environment_analysis` | Direct `latest.json` reads of `job_target_catalog` and `job_review_intake` (`job.py:216,234`, bypassing `accepted_upstream`), developer build scripts/Makefiles/Dockerfiles | <!-- historical:begin -->`build-environment/1`<!-- historical:end --> (`build-environment.json`) consumed by `job_target_analysis_plan` and `job_post_build_security_assessment` | `C05-F01` (reads mutable `latest.json` directly without claim pins or read receipts) | rework |
| `job_target_analysis_plan` | `job_target_catalog`, `job_source_history_analysis`, `job_build_environment_analysis` (schedules after `job_ci_configuration_analysis` without reading it), optional model `target-analysis-proposal/3` | `accepted-analysis-plan.json` (<!-- historical:begin -->`target-analysis-plan/3`<!-- historical:end -->) driving Wave 1–2 build and scanner selection | `C05-F02` (`accepted_artifacts` hardcoded `()`, disabling `tool-spotbugs` and `tool-blint`) and `C05-F06` (unused `job_ci_configuration_analysis` barrier) | rework |

#### C05-F01 `load_environment` reads mutable `latest.json` pointers directly, bypassing `accepted_upstream` and read receipts
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: `job_build_environment_analysis`, `job_target_analysis_plan`
- **Evidence**: `src/appsec_review/jobs/job_build_environment_analysis/job.py:216`, `src/appsec_review/jobs/job_build_environment_analysis/job.py:234`, `src/appsec_review/jobs/job_target_analysis_plan/job.py:166`, `src/appsec_review/jobs/job_target_analysis_plan/job.py:287`. `job_build_environment_analysis.job.load_environment` resolves `data/jobs/job_build_environment_analysis/latest.json` (`line 216`) and `data/jobs/job_target_catalog/latest.json` (`line 234`) directly via `safe_path` instead of `runtime.consume.accepted_upstream`. Both `job_target_analysis_plan` execution (`job_target_analysis_plan/job.py:287`) and downstream `load_accepted_plan` verification (`job_target_analysis_plan/job.py:166`) call this helper.
- **Impact**: Consuming `job_build_environment_analysis` emits no `runtime.consume` read receipt against `job_target_analysis_plan`'s admitted `upstream_handoffs`, violating the control-layer consumption contract (`AGENTS.md`). Furthermore, if `job_target_catalog` or `job_build_environment_analysis` publishes a newer attempt on resume while a consumer calls `load_accepted_plan`, `load_environment` compares against mutable `latest.json` rather than the claim-pinned handoff SHA-256, rejecting a valid accepted plan or reading unpinned state.
- **Recommendation**: Route `load_environment` through `runtime.consume.accepted_upstream(run_root, "job_build_environment_analysis")` (and pin the catalog handoff SHA-256 recorded in the accepted environment artifact rather than re-reading `job_target_catalog/latest.json`), while preserving `OPTIONAL_PRIOR` reference verification against immutable attempt handoffs.
- **Effort**: `S`
- **Already registered**: `none` (Deduplicated in headline totals under `C01-F02`: Direct `latest.json` read bypassing `accepted_upstream` and read receipts (`job_build_environment_analysis`).)

#### C05-F02 `_accepted_catalog` leaves `accepted_artifacts` permanently empty, making `tool-spotbugs` and `tool-blint` non-selected in every analysis plan
- **Kind**: `coverage-gap`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: `job_target_analysis_plan`
- **Evidence**: `src/appsec_review/jobs/job_target_analysis_plan/job.py:145`, `src/appsec_review/jobs/job_target_analysis_plan/datasets.py:64`, `src/appsec_review/jobs/job_target_analysis_plan/planning.py:182-183`, `src/appsec_review/jobs/job_target_analysis_plan/planning.py:293-295`, `src/appsec_review/jobs/job_target_catalog/job.py:165-182`. `job_target_analysis_plan` declares `InputContract("target_artifact_intake", "job_target_catalog", "appsec-review/target-artifact-intake/1")` (`datasets.py:64`), which `job_target_catalog` populates under `partition["target_artifacts"]` (`job_target_catalog/job.py:165-182`). However, `_accepted_catalog` (`job_target_analysis_plan/job.py:145`) computes `"accepted_artifacts": tuple(item for item in targets.get("targets", ()) if item.get("artifact_kind") == "built")` over `build-targets.json`, whose entries are `discover_build_inventory` units that never set `"artifact_kind": "built"`.
- **Impact**: `catalog["accepted_artifacts"]` is `()` for every target. Consequently, `planning._scanner_scope` (`planning.py:182-183`) always returns `()` for `tool-spotbugs` and `tool-blint`, recording both under `scanner_non_selections` (`"no catalog inputs match scanner scope"`), and leaves `build_topology.targets` and `build_topology.link_outputs` (`planning.py:293-295`) permanently empty—even on binary/archive targets where `job_artifact_indexing` and `job_artifact_security_analysis` later scan `partition["target_artifacts"]` directly, contradicting the accepted analysis plan.
- **Recommendation**: Populate `accepted_artifacts` in `_accepted_catalog` from `partition.get("target_artifacts", ())` (normalizing `target_relative_path` to `path` for `_scanner_scope` and `validate_plan`) or remove pre-build binary scanners from source-catalog planning so the accepted plan matches actual Wave 2 execution.
- **Effort**: `M`
- **Already registered**: `none`

#### C05-F03 `Git` subprocess environment blocks system config (`GIT_CONFIG_NOSYSTEM=1`) but still loads operator global Git config (`~/.gitconfig`)
- **Kind**: `trust-boundary`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_target_acquisition`
- **Evidence**: `src/appsec_review/target_acquisition/git_source.py:48-51`, `src/appsec_review/target_acquisition/safety.py:182-186`, `docs/operations/target-acquisition.md:175-181`. `safety.base_environment` (`safety.py:182-186`) preserves `HOME`, `USERPROFILE`, and `XDG_CONFIG_HOME`, while `Git._env` (`git_source.py:48-51`) sets `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_COUNT` overrides without setting `GIT_CONFIG_GLOBAL` to an empty file or isolated credential-only config.
- **Impact**: Host-level `~/.gitconfig` / `$XDG_CONFIG_HOME/git/config` rules remain active during `acquire_target`. In particular, `url.<other>.insteadOf` rewrites happen inside `git fetch` *after* `check_git_url` validated the configured `spec.url`, allowing silent redirection to another HTTPS/SSH remote (or a `file://` path when `allow_local_sources=True`) while `manifest.json` records the original `spec.url`, and global `filter.*` clean/smudge drivers other than `filter.lfs.*` remain inherited.
- **Recommendation**: Point `GIT_CONFIG_GLOBAL` to `os.devnull` (or a minimal run-owned config carrying only explicit credential-helper entries when configured) so host URL rewrites and non-LFS filters cannot alter acquisition provenance.
- **Effort**: `S`
- **Already registered**: `none` (Deduplicated in headline totals under `C03-F01`: Host `git` subprocesses inheriting operator `~/.gitconfig` (`url.<base>.insteadOf`, `core.fsmonitor`) without `GIT_CONFIG_GLOBAL=/dev/null`.)

#### C05-F04 `job_target_catalog` re-reads target files without SHA-256 verification in `dependencies`, `path_index`, and `symbol_index`
- **Kind**: `trust-boundary`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_target_catalog`
- **Evidence**: `src/appsec_review/jobs/job_target_catalog/job.py:318-321`, `src/appsec_review/jobs/job_target_catalog/job.py:356-369`, `src/appsec_review/jobs/job_target_catalog/job.py:394-414`. While `partition_repository` (`job.py:157-163`), `descriptor_reader` (`job.py:92-104`), and `document_index` (`job.py:508-514`) enforce `safe_path` custody and verify `sha256 == item["sha256"]` on read, `dependencies` (`job.py:318-321`), `path_index` (`job.py:356-369`), and `symbol_index` (`job.py:394-414`) open `_target(unit) / item["path"]` directly via `read_text` without symlink/custody re-checks or digest verification against `item["sha256"]` / `component["manifest_sha256"]`.
- **Impact**: If a target checkout mutates during `job_target_catalog` (for example on an unverified `--target` directory), `source` and `analysis` SQLite shards bind mutated file text and line/byte spans to the earlier `SourceLocation(file_sha256=item["sha256"], end_byte=item["size_bytes"])` without failing closed or recording a custody error.
- **Recommendation**: Read all target files in `dependencies`, `path_index`, and `symbol_index` through a single custody helper (`safe_path`, `is_symlink` check, byte cap, and `hashlib.sha256(raw).hexdigest() == expected_sha256`) matching `document_index`.
- **Effort**: `S`
- **Already registered**: `none`

#### C05-F05 `job_target_catalog` and `job_target_analysis_plan` still emit unstructured free-text gaps (`strict_gaps=False`), and `publish_catalog_handoff` crashes if a partition gap is a string
- **Kind**: `contract-mismatch`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_target_catalog`, `job_target_analysis_plan`
- **Evidence**: `src/appsec_review/jobs/job_target_catalog/job.py:61-65`, `src/appsec_review/jobs/job_target_catalog/job.py:488`, `src/appsec_review/jobs/job_target_catalog/job.py:648-653`, `src/appsec_review/jobs/job_target_analysis_plan/job.py:302-303`, `src/appsec_review/jobs/job_target_analysis_plan/job.py:637`, `tests/test_gap_contract.py:31`. Both `job_target_catalog` and `job_target_analysis_plan` remain on `LEGACY_FREE_TEXT_GAPS` (`strict_gaps=False`) and emit raw strings (`"compile_commands.json not present"`, `"symbol index bound reached"`, `"analysis summary was truncated by configured bounds"`, `"build environment: ..."`). Inside `job_target_catalog`, `_gap_text` (`line 61`) accepts either `Mapping` or `str` entries in `partition["gaps"]`, whereas `publish_catalog_handoff` (`line 488`) unconditionally indexes `item["path"]` and `item["reason"]` and flattens structured partition gap dicts back into free text.
- **Impact**: Downstream prioritization, gate accounting, and walk gap classification lose structured `reason_code`, `scope_id`, and `retryable` metadata across both foundational planning jobs, and any string gap appended to `partition["gaps"]` raises `TypeError` at `job_target_catalog/job.py:488`. (`T-055` tracks `job_target_catalog`, while `job_target_analysis_plan` has no corresponding conversion entry.)
- **Recommendation**: Convert both `job_target_catalog` (`T-055`) and `job_target_analysis_plan` to emit `interchange.producer_gap` (`producer-gap/1`) records and enable `strict_gaps=True`.
- **Effort**: `M`
- **Already registered**: `T-055` (covers `job_target_catalog` only; `job_target_analysis_plan` is unregistered)

#### C05-F06 `job_target_analysis_plan` schedules after `job_ci_configuration_analysis` without consuming any CI output
- **Kind**: `scale-risk`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_target_analysis_plan`
- **Evidence**: `src/appsec_review/jobs/job_target_analysis_plan/datasets.py:58-77`, `src/appsec_review/jobs/job_target_analysis_plan/job.py:280-292`. `job_target_analysis_plan/datasets.py:58` sets `schedule_after=('job_ci_configuration_analysis', 'job_source_history_analysis', 'job_build_environment_analysis')`, yet `CONTRACT.inputs` (`lines 59-72`) declares inputs only from `job_target_catalog`, `job_source_history_analysis`, and `job_build_environment_analysis`, and neither `job.py` nor `planning.py` reads any `job_ci_configuration_analysis` handoff or artifact.
- **Impact**: Every review graph serializes `job_target_analysis_plan` (and all downstream Wave 1/build jobs gated on the plan) behind `job_ci_configuration_analysis` for zero consumed data—or conversely, CI-discovered build commands, matrix flags, and container images never reach recipe inference despite the scheduling edge implying they do.
- **Recommendation**: Either drop `'job_ci_configuration_analysis'` from `job_target_analysis_plan`'s `schedule_after` so planning starts as soon as catalog, history, and build-environment finish, or wire bounded advisory CI build-step facts into `CONTRACT.inputs` and recipe context.
- **Effort**: `S`
- **Already registered**: `none`

#### C05-F07 `job_target_catalog` declaration symbol index uses a 7-keyword line-prefix regex and truncates at 50,000 symbols in path order
- **Kind**: `coverage-gap`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_target_catalog`
- **Evidence**: `src/appsec_review/jobs/job_target_catalog/job.py:386-418`. `symbol_index` (`job.py:386`) scans every language with `re.compile(r"^\s*(?:def|class|function|func|interface|struct|enum)\s+([A-Za-z_$][\w$]*)")` and halts the entire loop once `len(symbols) >= 50_000` (`lines 411-418`).
- **Impact**: Declarations with leading modifiers or return types (`async def`, `export class`, `public class`, `pub fn`, `fn`, C/C++/Java/C# typed functions/methods) are never indexed in the initial `analysis` SQLite shard, keyword occurrences inside multiline strings or block comments produce bogus `SYMBOL` entities, and repositories exceeding 50,000 matches lose all declarations in lexicographically later directories (for example `src/` after `crates/` or `apps/`).
- **Recommendation**: Either narrow `job_target_catalog`'s `analysis` shard explicitly to manifest/plan metadata and leave symbol indexing to `job_tree_sitter_ast` and `job_cpp_symbol_index`, or require language-aware patterns that account for common declaration modifiers without silent lexicographic starvation.
- **Effort**: `M`
- **Already registered**: `none`

#### C05-F08 `job_target_catalog` dependency catalog parses only `package.json` and defers all other ecosystems
- **Kind**: `coverage-gap`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_target_catalog`
- **Evidence**: `src/appsec_review/jobs/job_target_catalog/job.py:319-338`, `src/appsec_review/jobs/cataloging.py:21-38`. `component_discovery.catalog_dependencies` (`job_target_catalog/job.py:319-338`) parses only `package.json` (`dependencies` and `devDependencies`); for every other recognized project manifest (`pyproject.toml`, `Cargo.toml`, `go.mod`, `pom.xml`, `build.gradle`, `Gemfile`, `composer.json`, `.csproj`, `.vcxproj`), it emits `"{manifest}: dependency parser deferred for this manifest type"`. Even for `package.json`, `optionalDependencies` and `peerDependencies` are ignored.
- **Impact**: `dependency-catalog/1` (`dependencies.json`) in `job_target_catalog` is empty for every non-Node component and omits `optionalDependencies`/`peerDependencies` for Node components, leaving initial catalog dependency metadata incomplete whenever downstream jobs or operators inspect catalog-level dependencies before Wave 2 `job_dependency_intelligence`.
- **Recommendation**: Either retire `component_discovery.catalog_dependencies` in favor of `job_dependency_intelligence` (avoiding duplicate partial parsers) or parse direct manifest declarations across the catalog's supported `MANIFEST_ECOSYSTEMS`.
- **Effort**: `M`
- **Already registered**: `none`

#### C05-F09 `config/target_acquisition.py` validates Git URLs with `allow_local=True` unconditionally, deferring local-URL refusal to runtime
- **Kind**: `weakness`
- **Severity**: `low`
- **Confidence**: `high`
- **Job**: `job_target_acquisition`
- **Evidence**: `src/appsec_review/config/target_acquisition.py:239-245`, `src/appsec_review/config/target_acquisition.py:309-319`. `_source_url` (`config/target_acquisition.py:239-245`) invokes `check_git_url(value, allow_local=True)` while parsing `[[target_acquisition.systems.components]]` (`line 316`), ignoring `allow_local_sources` (default `False` on `TargetAcquisitionSettings`). Similarly, `_HTTP_URL` (`line 292`) accepts `http://127.0.0.1` / `https://localhost` at config load even when `allow_local_sources = False`.
- **Impact**: Invalid `file://`, bare local path, or loopback URLs under default `allow_local_sources = False` pass `load_config` / preflight configuration parsing and fail only later when `job_target_acquisition` executes `acquire_target`.
- **Recommendation**: Parse scalar settings (`allow_local_sources`) before `systems` in `parse_target_acquisition` and pass `allow_local=allow_local_sources` into `check_git_url` and `check_http_url` during config validation.
- **Effort**: `S`
- **Already registered**: `none`

#### C05-F10 `job_target_acquisition` re-parses raw `data/configuration/appsec-review.toml` instead of `resolved.json`
- **Kind**: `weakness`
- **Severity**: `low`
- **Confidence**: `high`
- **Job**: `job_target_acquisition`
- **Evidence**: `src/appsec_review/jobs/job_target_acquisition/job.py:72-77`, `src/appsec_review/config/loader.py:555-610`. `_settings(unit)` in `job_target_acquisition/job.py:72-77` reads `unit.job.run_root / "data" / "configuration" / "appsec-review.toml"` directly via `tomllib.loads` and calls `parse_target_acquisition(raw.get("target_acquisition"), repository_root)` rather than reading `resolved.json`.
- **Impact**: Any `[target_acquisition]` override supplied by a configuration profile or future capacity overlay (such as `max_parallel_components`) in `resolved.json` is silently ignored by `job_target_acquisition`, which executes against the base TOML file instead of the run's resolved configuration.
- **Recommendation**: Load `[target_acquisition]` from `data/configuration/resolved.json` (with hash check against the run's configuration manifest) instead of re-parsing the base `appsec-review.toml`.
- **Effort**: `S`
- **Already registered**: `none`

#### C05-F11 `cataloging.inventory` hashes every retained source file up to three times across separate full-file passes
- **Kind**: `scale-risk`
- **Severity**: `low`
- **Confidence**: `high`
- **Job**: `job_target_analysis_plan`
- **Evidence**: `src/appsec_review/jobs/cataloging.py:163-167`, `src/appsec_review/jobs/cataloging.py:213`, `src/appsec_review/jobs/cataloging.py:242-259`. During a single `cataloging.inventory(root)` call, every in-scope source file is read in full via `read_text` (`line 163`) and hashed with `sha256_file(path)` (`line 166`) for `source_metrics`, hashed a second time with `sha256_file(path)` (`line 213`) for `files`, and hashed a third time inside `raw_snapshot(root)` (`lines 222, 259`).
- **Impact**: On large targets approaching `Bounds` (`10,000` files / `256 MiB` retained plus unretained files in `raw_snapshot`), `partition_repository` performs up to 4x redundant disk reads and 3x redundant SHA-256 computations per file, and any mid-walk file modification can record inconsistent `sha256` values between `source_metrics`, `files`, and `snapshot`.
- **Recommendation**: Read/hash each regular file once during the single `_walk_files` pass, feeding the same `(size, digest, sample/bytes)` into `raw_snapshot`, `source_metrics`, `artifact_candidates`, and `files`.
- **Effort**: `S`
- **Already registered**: `none`
### C06 Build and execution capture

**Active findings:** 16 (`2` critical, `5` high, `8` medium, `1` low).

C06 has a strong core design—pinned immutable toolchain images, `strace`-backed compiler/linker execution capture, hash-verified receipts, and explicit build-output scope classification—that anchors compiled downstream evidence in C07, C08, and C09. However, the container isolation boundary around untrusted target builds is broken in two critical ways: a writable `/capture` bind mount run under the host worker UID permits host-file exfiltration via symlinks, host-worker FIFO hangs, and capture forgery (`C06-F01`), while iterative `job_language_build` runs every non-native family (`go`, `dotnet`, `python`, `php`, `java`, `node`, `rust`, `wasm`) with live `--network bridge` egress and uncapped host CPU/memory (`C06-F02`). Half-completed refactoring from probe/rebuild to iterative execution also left `job_project_build` stripping planned `system_packages` to `[]` while leaving its entire 300-line model image-repair pipeline unreachable (`C06-F04`), and left `job_language_build` tests exercising a dead `"legacy"` mode instead of `"iterative"` mode (`C06-F15`). Finally, two concrete producer/consumer bugs hurt review results directly: failed JVM or WASM builds retain partial `artifacts` that crash `job_artifact_indexing` for the whole run (`C06-F05`), and `job_language_build` drops all JVM retrieval-index shards from its manifest while populating `NULL` capture/secret fields in the `build` index (`C06-F06`). Fixing `/capture` custody, restoring `--network none` and resource limits, reconnecting or deleting the dead image-repair path, and repairing the artifact/index handoff invariants are the highest-leverage improvements.

**Strengths to preserve:**
- Hash-pinned toolchain images with lockfile-verified offline downloads and post-install `check-toolchain.sh` assertions (`containers/buildenv/native-toolchain/Dockerfile:1-95`, `containers/buildenv/native-toolchain/check-toolchain.sh:1-42`, `containers/buildenv/java/assets.lock.json:1-30`).
- Standardized `strace` + wrapper execution capture with response-file expansion, compiler/linker database extraction, and fail-closed SHA-256 verification on receipt consumption and checkpoint reuse (`src/appsec_review/container_runtime/build_capture.py:218-625`, `src/appsec_review/jobs/job_language_build/job.py:768-868`).
- Explicit first-party vs vendored/test/generated output scope attribution (`BuildOutputPolicy`) and build-bookkeeping exclusion so CMake/Cargo/Gradle internals are never mistaken for target binaries (`src/appsec_review/jobs/build_output_scope.py:1-190`, `src/appsec_review/jobs/build_bookkeeping.py:1-120`).
- Detached JVM instrumentation mounts (`/appsec-jvm`, `/appsec-jvm-evidence`) with post-run JDK symlink-mirror cleanup that records `javac`/`kotlinc`/`kapt` invocations without polluting `/workspace` (`src/appsec_review/jobs/job_language_build/jvm.py:242-354`, `src/appsec_review/jobs/job_language_build/jvm.py:521-532`).
- Explicit upstream build-failure propagation in `job_language_build.upstream_build_failure_receipt`, which turns a failed `job_project_build` image preparation into a `BLOCKED` unit receipt with a named gap rather than silently treating the language lane as `NOT_APPLICABLE` (`src/appsec_review/jobs/job_language_build/job.py:735-755`).
- Clean consolidation of WebAssembly builds into `job_language_build/wasm.py` with zero residual <!-- historical:begin -->`job_wasm_build`<!-- historical:end --> references in code, configuration, or `docs/operations/wasm-build.md` (`src/appsec_review/jobs/job_language_build/wasm.py:1-510`, `docs/operations/wasm-build.md:1-95`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_project_build` | `job_target_analysis_plan` (`load_accepted_plan` via `accepted_upstream`) | `build-dispatches.json`, derived project images, static-workflow dispatches, Unity probe receipts | `C06-F04` (derived project image builds and static fallback dispatches mask missing build prerequisites) | rework |
| `job_language_build` | `job_project_build` (`accepted_upstream`), `job_review_intake` (manifest chain), out-of-band `job_build_iteration` `result.json` | `language-builds.json`, per-unit receipts, `compile_commands.json` / link DBs, captured traces, workspace artifacts, `build` SQLite shard | `C06-F01` / `C06-F02` / `C06-F07` (writable `/capture/tools` & unauthenticated `/capture/traces`, plus zero-TU static fallback reported as clean build) | rework |
| `job_build_iteration` | Out-of-band `request.json` under `data/build/iterations/attempts/<id>/` (bypasses `accepted_upstream`) | Per-attempt `result.json` read directly by `job_language_build` (`build_iterations.py:1142`) | `C06-F13` (not a true DAG job; communicates via unpinned scratch paths outside `accepted_upstream`) | merge |
| `job_sanitizer_build` | `job_language_build` (`accepted_upstream`) | `sanitizer-builds.json`, ASan/UBSan ELF workspaces, `runtime-evidence.json` (read only by `job_review_data_indexing`; zero execution or PoC consumers) | `C06-F10` (builds instrumented binaries that nothing in the pipeline executes) | rework |
| `job_artifact_indexing` | `job_language_build` (`accepted_upstream`), `job_review_intake` (`accepted_upstream`) | `artifact-index.json`, `artifacts-intake` and `artifacts-build` SQLite retrieval shards | `C06-F05` (incomplete provenance linkage between multi-unit build outputs and indexed artifacts) | rework |

#### C06-F01 Writable `/capture` mount under host UID permits host-file exfiltration, worker hang, and trace forgery
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/container_runtime/identity.py:11-21`, `src/appsec_review/container_runtime/build_executor.py:558-595`, `src/appsec_review/container_runtime/build_executor.py:701-716`, `src/appsec_review/container_runtime/build_capture.py:555-566`, `containers/build-capture/tool-wrapper.py:70-76`; `execute_captured` mounts `capture_root` (`0o733`) read-write at `/capture` inside a container running as the host worker's `uid:gid` (`container_user_spec`), leaves `APPSEC_CAPTURE_ROOT=/capture` in child `os.environ`, then runs `shutil.copytree(tool_root, staging)` on the host with default `symlinks=False` and opens `capture_root.glob("trace*")` without symlink or `S_ISREG` checks.
- **Impact**: A hostile target `Makefile`, `build.rs`, `setup.py`, Gradle script, or `npm` build script can (1) plant symlinks under `/capture/tool-calls/<id>/` to host paths (`~/.ssh/id_ed25519`, signing keys, cloud tokens) that `_take_tool_call_ownership` dereferences on the host and copies into run-owned artifacts, (2) create a FIFO `/capture/trace.99999` that blocks the host worker indefinitely in `record_strace_files` outside container timeouts, and (3) overwrite `/capture/tool-wrapper.py` or delete/forge `/capture/trace.*` before `recorder.finish()` hashes them, forging compiler-execution provenance. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Partially addressed in `43ac5c7fe`, which skips symlinks and non-regular files (FIFOs/devices) before reading `/capture/traces`; writable `/capture/tools` wrapper mounts and forged regular trace files (`C06-F07`) remain open.]*
- **Recommendation**: Mount `build-driver.sh` and `tool-wrapper.py` from a separate read-only bind mount; run untrusted build processes under a distinct container UID (or userns remap) from the `strace` supervisor, or replace `shutil.copytree(..., symlinks=False)` in `src/appsec_review/container_runtime/build_executor.py` and `path.open` in `src/appsec_review/container_runtime/build_capture.py` with `O_NOFOLLOW` + `stat.S_ISREG` rejection that deletes/quarantines non-regular entries and fails capture closed.
- **Effort**: `M (days)`
- **Already registered**: no

#### C06-F02 Iterative non-native builds run with live `--network bridge` egress and uncapped host CPU/memory
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_language_build`
- **Evidence**: `src/appsec_review/jobs/job_language_build/job.py:1001-1005`, `src/appsec_review/jobs/job_language_build/job.py:1176-1180`, `src/appsec_review/container_runtime/build_executor.py:394-397`; both `_production_iteration` and `_execute_one` construct `BuildContainerExecutor(..., network="none" if family == "native" else "bridge")`, and `build_executor.py` emits `--cpus 2 --memory 4g` only when `native_execution_requested()` is true while plain Docker runs uncapped.
- **Impact**: Every `go`, `dotnet`, `python`, `php`, `java` (including `android`), `node`, `rust`, and `wasm` build in production iterative mode executes target-controlled build scripts (`build.rs`, proc-macros, `setup.py`, Gradle/Maven plugins, MSBuild tasks, `npm run build`) with live internet egress—even when `[jobs.job_language_build.settings.{go,python,rust}] offline = true` and `recipe["network_required"] == False`—allowing source exfiltration and unpinned remote fetches, while a hostile or runaway compiler can exhaust host RAM/CPU and OOM-kill sibling workers. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Partially mitigated in `8e5cd496c` (Wave 1b typed build failure causes and contiguous file-backed ELF segment mapping); silent zero-TU static fallback remains open.]*
- **Recommendation**: In `src/appsec_review/jobs/job_language_build/job.py`, default `network="none"` for all families unless both the family policy and accepted recipe explicitly permit build-time egress (currently only online `node`/`php` until `T-007` lands), and in `src/appsec_review/container_runtime/build_executor.py` pass configured `--cpus` and `--memory` flags unconditionally on `docker run`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-007` registers routing allowed dependency restores through an egress proxy, assuming build containers already default to `--network none`; new here is that all non-native `job_language_build` executions currently get unconditional `--network bridge` and uncapped host memory/CPU.

#### C06-F03 `job_project_build` executes target Gradle, Maven, and MSBuild code with network egress outside execution capture
- **Kind**: `weakness`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_project_build`
- **Evidence**: `src/appsec_review/container_runtime/project_images.py:262-270`, `src/appsec_review/container_runtime/project_images.py:307-316`, `src/appsec_review/container_runtime/project_images.py:368-378`; `ProjectImageResolver` runs `gradle --no-daemon dependencies`, `mvn -B -DskipTests clean dependency:go-offline`, and `dotnet restore` inside `docker buildx build --network default` against target-owned `build.gradle(.kts)`, `pom.xml`, and `.csproj` files.
- **Impact**: Evaluating `build.gradle(.kts)`, Maven `clean` lifecycle plugins, or MSBuild `.targets` executes arbitrary target-supplied code with live internet access during image assembly, with no `strace` capture, no `gitleaks` scan, and full write access to the derived image filesystem cached across build units.
- **Recommendation**: Restrict `project_images.py` restores to declarative lockfile/manifest fetchers that do not evaluate target code (`npm ci --ignore-scripts`, `go mod download`, `cargo fetch --locked`, `pip download --only-binary=:all:` where possible), pass `--ignore-scripts` / `-p:EnableDefaultItems=false` where supported, and record an explicit provenance warning or block untraced Gradle script evaluation until `T-007` isolates restore traffic.
- **Effort**: `M (days)`
- **Already registered**: `T-007` covers proxy-mediating egress during image builds, not untraced arbitrary code execution in Gradle/Maven/MSBuild during `docker buildx`.

#### C06-F04 `job_project_build` strips `system_packages` to `[]` while its entire model image-repair pipeline is dead code
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_project_build`
- **Evidence**: `src/appsec_review/jobs/job_project_build/job.py:719-923`, `src/appsec_review/jobs/job_project_build/job.py:1179-1210`, `src/appsec_review/jobs/job_project_build/job.py:1400-1455`; `plan.load_recipes` overwrites every recipe's `"system_packages": []` and stashes planned packages in `"package_hints"`, which is read only by `_infer_repair` (`line 730`), yet `probe_handler` never calls `_probe_with_repairs` or `_probe_one`, and `build_job(..., infer=None)` never passes `infer` into any unit.
- **Impact**: Native, Python C-extension, Rust `-sys`, and PHP `phpize` targets that need `apt` development headers (`libssl-dev`, `zlib1g-dev`, etc.) already identified by `job_target_analysis_plan` have those packages stripped before image build, and because `_probe_with_repairs` (~320 lines plus `repair.py` model proposals and `build-image-repair` guidance) is unreachable, those builds fail deterministically in `job_language_build`, forfeiting compiled analysis coverage.
- **Recommendation**: Preserve validated `selected.get("system_packages", ())` in `plan.load_recipes` (`src/appsec_review/jobs/job_project_build/job.py:1202`) when within the `repair.py` allowlist, and either wire bounded image repair into `job_build_iteration` failure recovery or delete the unreachable `_probe_one` / `_probe_with_repairs` / `_infer_repair` functions in `job_project_build/job.py`, `[jobs.job_project_build.settings.model]` in `appsec-review.toml`, and `pipeline/skills/build-image-repair/SKILL.md`.
- **Effort**: `M (days)`
- **Already registered**: `T-038`–`T-041` (`done`) migrated execution to iterative `job_language_build`; new is that `plan.load_recipes` still zeroes `system_packages` expecting the now-dead `_probe_with_repairs` loop to restore them.

#### C06-F05 Failed JVM and WASM builds publish non-empty `artifacts`, crashing `job_artifact_indexing` for the whole run
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_language_build`
- **Evidence**: `src/appsec_review/jobs/job_language_build/jvm.py:830-833`, `src/appsec_review/jobs/job_language_build/jvm.py:893-909`, `src/appsec_review/jobs/job_language_build/wasm.py:447-470`, `src/appsec_review/jobs/job_artifact_indexing/job.py:433-437`; unlike `_execute_one` (`job_language_build/job.py:1522-1528`) and `unity_build.py:604`, `execute_jvm_one` and `wasm.execute_wasm_one` keep partial `artifacts` in the receipt when `status == "FAILED"`, causing `job_artifact_indexing._validate_receipts` to raise `ArtifactIndexIntegrityError("non-successful build receipt publishes artifacts")`.
- **Impact**: Any multi-module Maven/Gradle build that compiles one subproject before failing on another, or any multi-step WASM recipe that writes intermediate outputs before a later command fails, aborts `job_artifact_indexing` completely and starves `job_artifact_security_analysis`, `job_dependency_intelligence`, `job_debug_symbol_indexing`, `job_test_coverage`, and `job_profile_data` across every healthy build unit in the repository.
- **Recommendation**: Clear `artifacts = []` (while preserving `workspace_manifest` and command logs for diagnostics) when `status != "SUCCEEDED"` in `src/appsec_review/jobs/job_language_build/jvm.py:893` and `src/appsec_review/jobs/job_language_build/wasm.py:447`, matching `job_language_build/job.py:1522-1528`, and add a cross-job receipt-contract test.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C06-F06 `job_language_build` orphans all JVM retrieval-index shards and writes `NULL` capture/secret/stream metadata into `build` index rows
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_language_build`
- **Evidence**: `src/appsec_review/jobs/job_language_build/jvm.py:591-670`, `src/appsec_review/jobs/job_language_build/jvm.py:918-920`, `src/appsec_review/jobs/job_language_build/job.py:806-831`, `src/appsec_review/jobs/job_language_build/job.py:1701-1782`; `jvm._index` writes `data/indices/build/<fp>-jvm-<unit>.sqlite` (`jvm_build_actions`) and stores its `IndexIdentity` on `receipt["retrieval_index"]`, which `_publish_build_index` ignores when writing `data/indices/manifests/language-build-<attempt>.json`, while `_publish_build_index` reads nonexistent keys `capture.get("complete")` and `capture.get("secret_findings")` (actual key is `"secret_scan"`) and mismatches JVM/WASM stream byte-count keys (`captured_bytes`/`total_bytes` vs `retained_byte_count`/`byte_count` in `jvm.py:227`).
- **Impact**: Every JVM compiler invocation (`javac`/`kotlinc`/`kapt`) and Gradle `declared_compilations` SQLite shard is orphaned on disk and invisible to manifest-driven retrieval in C11/triage workers, and every captured command in the main `build` shard records `complete=None`, `secret_findings_sha256=None`, `secret_finding_count=None`, and `None` JVM/WASM stream byte counts.
- **Recommendation**: Append verified `IndexIdentity(**receipt["retrieval_index"]["identity"])` entries for succeeded JVM receipts in `_publish_build_index` (`src/appsec_review/jobs/job_language_build/job.py:1770-1777`), read `capture["secret_scan"]` and `not capture["events"]["capped"]` in `job.py:1746-1750`, and standardize stream identity field names across `job.py`, `jvm.py`, and `wasm.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C06-F07 Conservative CMake and external-library blockers in `build_topology.py` prevent building ordinary C/C++ repositories
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/build_topology.py:218-221`, `src/appsec_review/jobs/build_topology.py:296-302`, `src/appsec_review/jobs/build_topology.py:1837-1843`; `build_topology.py` emits `blocking=True` gaps (`unresolved_declaration`) on any CMake `include(...)`, `add_custom_command`, `add_custom_target`, or non-literal target argument, and `refine_build_topology` turns any unresolved `target_link_libraries` symbol (including standard toolchain libraries like `m`, `pthread`, `dl`, or `OpenSSL::SSL` already installed in `buildenv-cpp`) into `required_external_interface_unresolved:<lib>`, blocking dispatch.
- **Impact**: Nearly all non-toy C/C++ repositories use `include(GNUInstallDirs)`, `add_custom_command` (e.g., protobuf/lex/yacc/version headers), or link system libraries; blocking them before configure prevents `compile_commands.json` and ELF generation and eliminates CodeQL C/C++, Clang Static Analyzer, SVF, DWARF, and binary hardening findings.
- **Recommendation**: Downgrade CMake `include(...)`, `add_custom_command`, `add_custom_target`, and external library links to non-blocking advisory topology gaps (`blocking=False`) in `src/appsec_review/jobs/build_topology.py` so the traced container configure/build (which already records `cmake` file-API and `strace` enforcement proofs) determines actual buildability.
- **Effort**: `M (days)`
- **Already registered**: `T-036`–`T-043` (`done`) introduced static topology gating; new is that its blocking rules reject standard CMake idioms (`include`, `add_custom_command`, `-lm`/`-lpthread`) before CMake can resolve them.

#### C06-F08 Mismatched artifact `LogicalIdentity` keys between `job_language_build` and `job_artifact_indexing` break cross-index joins
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_artifact_indexing`
- **Evidence**: `src/appsec_review/jobs/job_language_build/job.py:1754-1761`, `src/appsec_review/jobs/job_language_build/jvm.py:648-652`, `src/appsec_review/jobs/job_artifact_indexing/job.py:101-110`; `job_language_build` derives artifact `LogicalIdentity` from `(LIBRARY|EXECUTABLE|EVIDENCE_ARTIFACT, {"build_unit_id", "path", "sha256"})` (or `"unit"` in `jvm.py`), whereas `job_artifact_indexing.canonical_artifact_identity` derives from `(artifact_family(kind), {"build_unit_id", "workspace_path", "sha256", "format"})`.
- **Impact**: The exact same produced binary or archive receives two or three distinct `LogicalIdentity` hashes across `build` and `artifacts` shards, so retrieval queries joining a binary's C08 security findings (`canonical_artifact_identity`) back to its C06 compiler command/flags in `build` never match.
- **Recommendation**: Import and call `canonical_artifact_identity` from `appsec_review.jobs.job_artifact_indexing.job` (or move it to `appsec_review.jobs.artifact_kinds`) inside `src/appsec_review/jobs/job_language_build/job.py:1754` and `src/appsec_review/jobs/job_language_build/jvm.py:648`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-049` tracks adopting `canonical_artifact_identity` in downstream C08 analyzers, not the intra-C06 mismatch between `job_language_build` and `job_artifact_indexing`.

#### C06-F09 Full-workspace SHA-256 hashing and object-store copying on every iteration node causes quadratic I/O on large builds
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_language_build`
- **Evidence**: `src/appsec_review/jobs/build_workspace.py:55`, `src/appsec_review/jobs/build_workspace.py:621-635`, `src/appsec_review/jobs/build_workspace.py:1081-1125`; `WorkspaceWriter._capture()` walks `target` and `install`, SHA-256 hashes every file, and calls `put_file` on initial materialization and after every committed build node, subject to a hard `MAX_WORKSPACE_ENTRIES = 200_000` ceiling.
- **Impact**: Multi-unit C++, Rust (`target/`), Gradle, or monorepo builds with tens of thousands of intermediate files re-hash and copy gigabytes of unchanged files on every node transition—risking `WorkspaceError` above 200,000 files and multiplying build wall-clock time without adding new evidence.
- **Recommendation**: Carry forward parent checkpoint `(relative_path, size_bytes, mtime_ns, inode, sha256)` entries in `src/appsec_review/jobs/build_workspace.py:_capture` so unchanged files skip re-hashing and `put_file`, and hard-link immutable blobs on `restore()` when `shared/objects` and `workspaces/` share a filesystem.
- **Effort**: `M (days)`
- **Already registered**: `T-044` (`done`) added post-run retention pruning of unreferenced blobs; new is that per-node `_capture()` still performs full-tree re-hashing and copying during the run.

#### C06-F10 `job_sanitizer_build` is enabled by default with zero downstream consumers and cannot verify static-library or stripped native builds
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_sanitizer_build`
- **Evidence**: `appsec-review.toml:1442-1456`, `src/appsec_review/jobs/job_sanitizer_build/job.py:10-13`, `src/appsec_review/jobs/job_sanitizer_build/job.py:32-36`, `src/appsec_review/jobs/job_sanitizer_build/job.py:318-321`, `src/appsec_review/jobs/job_sanitizer_build/evidence.py:28-55`; `job_sanitizer_build` is `enabled = true` by default (`max_units = 8`, `command_timeout_seconds = 600`), runs `executor.execute(...)` without execution capture, inspects only ELF symbol tables on `executable`, `shared-library`, and `object` kinds (skipping `static-library` `.a` archives and reporting `no_symbol_tables` on `-s`/stripped builds), imports private helpers from `job_language_build.job` and `job_codeql_analysis.planning`, and has zero consumers outside `job_review_data_indexing`.
- **Impact**: Every native review run pays for up to eight full container rebuilds whose outputs produce zero findings or PoC evidence today, while targets that only build `.a` libraries (if objects were cleaned) or strip linked binaries emit noisy `COMPLETED_WITH_GAPS` sanitizer gaps even when `-fsanitize=address,undefined` was honored by the compiler.
- **Recommendation**: Set `[jobs.job_sanitizer_build] enabled = false` in `appsec-review.toml` until the `T-082` dynamic PoC/fuzzing consumer lands; move `replay_commands` and shared workspace helpers out of `job_codeql_analysis` and private `job_language_build.job` symbols into `jobs/build_recipe_replay.py`; and inspect `.a` archive members (or run `execute_captured` to verify compiler flags directly) in `src/appsec_review/jobs/job_sanitizer_build/evidence.py`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-082` registers building a downstream <!-- historical:begin -->`job_poc_verification`<!-- historical:end --> consumer; new is that `job_sanitizer_build` is already `enabled = true` on every default run for zero report benefit, couples laterally into `job_codeql_analysis`, and misses `.a`/stripped builds.

#### C06-F11 `protected-commands/*.json` bypass secret scanning and retain unredacted environment variables on disk
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_language_build`
- **Evidence**: `appsec-review.toml:51`, `src/appsec_review/jobs/job_language_build/job.py:1244-1251`, `src/appsec_review/jobs/job_language_build/jvm.py:786-790`, `src/appsec_review/jobs/job_language_build/wasm.py:372-377`, `src/appsec_review/container_runtime/build_executor.py:756-845`; `job_language_build` writes full `{"argv", "environment"}` records to `protected-commands/` outside `capture_root` before invoking `execute_captured`, so when `_scan_capture_secrets` finds credentials in `invocation.json` and redacts `/capture/tool-calls/*/record.json`, `protected-commands/*.json` remains unredacted on disk.
- **Impact**: Target-embedded tokens or registry/build credentials passed via recipe `environment` or `argv` remain stored in cleartext under `runs/<run-id>/.../protected-commands/` even when `tool-gitleaks` flags the invocation and redacts the corresponding capture directory.
- **Recommendation**: Redact or omit `environment` values matching secret patterns (or feed `protected-commands/*.json` through the same `_scan_capture_secrets` disposition in `src/appsec_review/jobs/job_language_build/job.py`, `jvm.py`, and `wasm.py`), and set `capture_envp = false` (recording variable names + value hashes) unless debugging is requested.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C06-F12 Triple build-descriptor parser duplication and dead `"legacy"` execution paths inflate maintenance and hide bugs
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/build_topology.py:124-336`, `src/appsec_review/jobs/build_topology.py:919-960`, `src/appsec_review/jobs/build_points.py:1-999`, `src/appsec_review/jobs/job_language_build/job.py:1810-2090`; `build_topology.py` defines `compile_build_topology` twice in the same file (lines `124` and `919`, aliasing the v1 compiler as `_compile_graph1` and immediately re-parsing documents in v2), `build_points.py` implements a third set of CMake/Make/MSBuild/Gradle/`package.json`/Unity regex parsers, and `job_language_build` retains per-family `load.<family>`/`execute.<family>` `"legacy"` units even though `job_project_build` hardcodes `"execution_mode": "iterative"` (`job_project_build/job.py:1171`) and `iteration_controller` rejects non-iterative dispatches (`job_language_build/job.py:1783`).
- **Impact**: Parser behavior diverges across `build_points.py` and `build_topology.py` v1/v2, while keeping the unreachable `"legacy"` `job_language_build` execution graph misled unit tests into testing `"legacy"` instead of `"iterative"` mode (`C06-F15`).
- **Recommendation**: Delete the `"legacy"` `load.<family>`/`execute.<family>` execution branch in `src/appsec_review/jobs/job_language_build/job.py`, collapse `_compile_graph1` into the single `build-topology/2` compiler in `src/appsec_review/jobs/build_topology.py`, and share one set of build-file declaration extractors between `build_points.py` and `build_topology.py`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C06-F13 `job_build_iteration` spawns a cold `dagster job execute` subprocess per build node and bypasses `accepted_upstream`
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_build_iteration`
- **Evidence**: `src/appsec_review/jobs/job_build_iteration/job.py:86-152`, `src/appsec_review/jobs/build_iterations.py:1095-1155`; in production (`executor_factory is None`), `iterations.dispatch` calls `invoke_registered_iteration`, spawning a fresh `python -m dagster job execute ... -j job_build_iteration` subprocess for every topological build node sequentially and reading the child's `result.json` directly from disk rather than consuming a published handoff via `runtime.consume.accepted_upstream`.
- **Impact**: Multi-node repositories pay full Python + Dagster + code-location + signed-module bootstrap latency per build node sequentially, and `job_build_iteration`'s receipt consumption sits outside the standard `accepted_upstream` read-receipt contract enforced across C01.
- **Recommendation**: Merge `job_build_iteration`'s four lightweight bookkeeping units directly into `job_language_build`'s iteration loop (`src/appsec_review/jobs/job_language_build/job.py` and `src/appsec_review/jobs/build_iterations.py`) while retaining the per-node immutable checkpoint files and audit events—eliminating both the subprocess cold-start tax and the out-of-band `result.json` read.
- **Effort**: `M (days)`
- **Already registered**: Prior review (`docs/reviews/appsec-system-review-2026-11-06.md`, P0 finding) and `T-136` (`done`) fixed `job_build_iteration` failing at startup; new is that the `T-136` fix spawns a full `dagster job execute` CLI subprocess per node and reads `result.json` outside `accepted_upstream`.

#### C06-F14 Android App Bundle (`.aab`) outputs are dropped by `jvm.py` and `jvm` index entities misclassify `.apk`/`.dex`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_language_build`
- **Evidence**: `src/appsec_review/jobs/artifact_kinds.py:28-30`, `src/appsec_review/jobs/job_language_build/jvm.py:45-51`, `src/appsec_review/jobs/job_language_build/jvm.py:648-652`; `artifact_kinds.py` defines `"android-apk"`, `"android-aab"`, and `"dex"`, and `containers/buildenv/android/Dockerfile` builds a dedicated Android SDK/NDK toolchain image, but `jvm._KIND_BY_SUFFIX` omits `".aab": "android-aab"` (`_artifact_kind` returns `None`) and `jvm._index` classifies only `{"jar", "war", "ear"}` as `EntityKind.LIBRARY`.
- **Impact**: Android Gradle builds using `bundleRelease`/`bundleDebug` succeed in `buildenv-android` while `job_language_build/jvm.py` silently drops all produced `.aab` bundles from `artifacts`, hiding them from `job_artifact_indexing` and downstream mobile/package analysis.
- **Recommendation**: Add `".aab": "android-aab"` to `_KIND_BY_SUFFIX` in `src/appsec_review/jobs/job_language_build/jvm.py:50` and align artifact entity kinds with `artifact_kinds.artifact_family` (`C06-F08`).
- **Effort**: `S (under a day)`
- **Already registered**: `T-092` and `T-093` register Android security rule packs and manifest/DEX analyzers; new is that `jvm.py` already executes Android builds via `buildenv-android` yet drops `.aab` outputs on the floor.

#### C06-F15 Unit tests exercise dead `"legacy"` `job_language_build` mode and isolated repair helpers, missing live integration seams
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/unit/job_language_build/test_job_graph.py:330-355`, `tests/unit/job_language_build/test_job_graph.py:418-425`, `tests/unit/job_project_build/test_repair.py:1-160`; `test_job_graph.py` drives family execution via `"execution_mode": "legacy"` and monkeypatches `_publish_build_index` (`line 340`), while `test_repair.py` tests `repair.py` functions directly without running `job_project_build.build_job()`.
- **Impact**: Testing the dead `"legacy"` mode and mocking `_publish_build_index` allowed critical regressions in the live `"iterative"` pipeline—including `network="bridge"` on JVM/non-native iterative builds (`C06-F02`), stripped `system_packages` (`C06-F04`), failed JVM/WASM receipts crashing `job_artifact_indexing` (`C06-F05`), and orphaned JVM index shards + `NULL` capture fields (`C06-F06`)—to ship with green unit tests.
- **Recommendation**: Rewrite `tests/unit/job_language_build/test_job_graph.py` around `"execution_mode": "iterative"` with real `_publish_build_index` verification, add a cross-job test feeding failed multi-module JVM and WASM receipts into `job_artifact_indexing`, and add a `job_project_build` test asserting planned `system_packages` survive `plan.load_recipes`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C06-F16 Architecture docs, operations runbooks, and `appsec-review.toml` contradict executed isolation and repair behavior
- **Kind**: `doc-drift`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `docs/architecture/build-environments-and-execution-capture.md:107-125`, `docs/operations/project-build.md:1-120`, `docs/operations/language-build.md:1-110`, `docs/operations/sanitizer-build.md:45-58`, `appsec-review.toml:1235-1248`, `appsec-review.toml:1275-1340`; the docs and TOML state that build containers run offline (`--network none`) with `--cpus 2 --memory 4g` and that `job_project_build` runs up to `repair_attempts = 5` model-guided image repairs, whereas code runs non-native builds on `--network bridge` without `--cpus`/`--memory` (`C06-F02`) and never invokes image repair (`C06-F04`).
- **Impact**: Operators and reviewers auditing `appsec-review.toml` or `docs/operations/*.md` get a false assurance that target builds are network-isolated, memory-capped, and self-repairing on missing `apt` headers; the documented isolation model is right and the code is wrong on `C06-F02`, while the docs/TOML are stale on `C06-F04`.
- **Recommendation**: After fixing `C06-F02` and resolving `C06-F04`, reconcile `docs/operations/project-build.md`, `docs/operations/language-build.md`, `docs/operations/sanitizer-build.md`, `docs/architecture/build-environments-and-execution-capture.md`, and `appsec-review.toml` with the actual runtime behavior.
- **Effort**: `S (under a day)`
- **Already registered**: no
### C07 Syntax, CodeQL and the code graph

**Active findings:** 20 (`2` critical, `8` high, `8` medium, `2` low).

C07 has a sound spine: four active jobs turn target bytes, traced compiler commands, and CodeQL databases into hash-verified SQLite shards (`analysis`, `observations`, `graph`) that downstream prioritization, security tagging, threat modeling, review slicing, and analyst MCP tools genuinely read. That spine is currently undercut by three high-leverage defects that corrupt corroboration, drop real taint paths, or starve syntax and graph coverage on realistic repositories. First, `graph/crosscheck.py` fabricates `agree` verdicts across unrelated callers in `CLANG_AST`/`LLVM_IR` while suppressing `CLANGD` overload/namespace disagreements into `partial`, and `scopes.py` starves sibling C/C++ build units of secondary cross-check shards. Second, `job_tree_sitter_ast` sets `max_nodes_per_scope = 20000` across 128-file scopes (truncating ~85-90% of files to zero AST nodes), `retrieval/graph.py` `Mode.PATHS` misses cross-file paths when queried by `SOURCE_FILE`, and `cpp/GraphExport.qll` drops bare-name-colliding model sinks and `sprintf` output-buffer taint. Third, `job_codeql_analysis` stamps unverified `tree_sha256` hashes onto `graph-fact/1`, discards its export precompile cache under shipped `"undeclared"` releases (compiling every pack twice per scope), omits `job_clang_static_analysis` from seeded-mode manifests, and keeps deprecated `job_cpg_analysis` alive for zero unique review value.

**Strengths to preserve:**
- Closed, byte-exact `graph-fact/1` normalization with deterministic `LogicalIdentity` hashing, UTF-8/UTF-16 column conversion against verified target bytes, and fail-closed `admissibility.direct_eligible` rules (`src/appsec_review/graph/contract.py:249-301`, `src/appsec_review/graph/normalize.py:216-309`).
- Bounded BQRS decoding in `codeql_runner.py` that inspects `bqrs info` for true total row counts before decoding `--rows <limit>`, recording exact truncation gaps rather than silently clipping results (`containers/tools/codeql/codeql_runner.py:499-534`).
- Capability-safe `query_syntax` and `query_code_graph` retrieval adapters with HMAC-bound pagination cursors, strict response-byte caps, and read-only SQLite `immutable=1` connections (`src/appsec_review/retrieval/syntax.py:118-235`, `src/appsec_review/retrieval/graph.py:265-395`).
- Ready-queue CodeQL work coordinator (`run_ready_work`) that overlaps database creation, SARIF queries, normalization, and graph export across scopes under shared CPU/RAM admission (`src/appsec_review/codeql/scheduler.py:102-204`).
- Honest seeded-mode coverage accounting in `apply_seeded_coverage` and `database_card`, which downgrades every seeded graph shard from `complete` to `partial` with an explicit `seeded_neighborhood` gap (`src/appsec_review/jobs/job_code_graph_index/scopes.py:200-272`).
- Workspace symlink validation in `_stage_manifest_workspace` that rejects escaping, absolute, cyclic, and unpinned symlinks before staging materialized build trees into CodeQL containers (`src/appsec_review/jobs/job_codeql_analysis/job.py:438-553`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_tree_sitter_ast` | `job_target_catalog` (`accepted_upstream`), optional `job_language_build` generated sources, target bytes | `analysis` SQLite shards (`ast_node`, `evidence_artifact`), JSONL AST node shards, generated-source backing metadata | `C07-F04` (per-scope container/JSONL overhead and incomplete cross-language construct coverage) | rework |
| `job_codeql_analysis` | `job_target_catalog`, `job_language_build`, optional upstream `observations` shards (`seeded` mode, omitting `job_clang_static_analysis`), target bytes | Per-scope CodeQL databases, raw SARIF + `observations` SQLite shards, bounded `codeql_graph_export` JSONs + `export-manifest.json` | `C07-F02` / `C07-F03` (zero-TU buildless/trap degradation and C++ `GraphExport.qll` scope/guard blind spots) | rework |
| `job_code_graph_index` | `job_codeql_analysis`, optional `job_review_prioritization`, `job_cpp_symbol_index`, `job_cpp_compiled_analysis`, `job_svf_alias_analysis`, `job_cpg_analysis`, `job_evidence_collection`, `job_clang_static_analysis` | 7 per-(scope, family) `graph` SQLite shards (`call_site`+`symbol`, `sink_site`, `entry_point`, `flow_summary`, `dataflow_path`, `guard_fact`, `range_fact`), `codeql_database` card shard, `producer_neighborhood` shard | `C07-F01` (drops interprocedural/cross-file edges and guard polarity fidelity during bounded projection) | rework |
| `job_cpp_symbol_index` | `job_cpp_compiled_analysis` (`accepted_upstream`; declares but never reads `job_target_catalog` and `job_evidence_collection`), target bytes | Per-scope `analysis` SQLite shards (`clangd-<case_id>`, `symbol` declarations/definitions and `CALLS` relations) | `C07-F14` (inherits broken `/workspace` compile-command paths and over-declares unread inputs) | rework |
| `job_cpg_analysis` | `job_cpp_compiled_analysis` (`accepted_upstream`); in `seeded` mode reads `observations` via `resolve_context_manifest` without `accepted_upstream`; shipped `enabled = false` | Disabled-gap `analysis` shards by default; when enabled, `BLOCKED` `cpg.bin` in `whole_program` mode or edge-less `cpg_method` summaries in `seeded` mode | `C07-F13` (disabled by default, fails in `whole_program` mode, and emits zero graph edges in `seeded` mode) | retire |

#### C07-F01 Cross-check rules fabricate `agree` across unrelated callers and downgrade C++ overload/namespace mismatches to `partial`
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_code_graph_index`
- **Evidence**: `src/appsec_review/graph/crosscheck.py:207-252`, `src/appsec_review/graph/crosscheck.py:375-384`, `src/appsec_review/graph/crosscheck.py:446-548`. `_clang_ast_verdicts` indexes `CallExpr` nodes by file path only (`nodes[path]`, lines 522-534) without enclosing caller or span, stamping any CodeQL `call_site` in `path` as `AGREE` (lines 539-542) if *any* function in that file calls the same unqualified tail name; `_llvm_ir_verdicts` keys IR edges only by `(caller_file_path, caller_tail_name, callee_tail_name)` (lines 456-475); and `_Symbols.match` (lines 232-239) treats any two C++ functions sharing an unqualified tail name (`A::open` vs `B::open`, or `f(int)` vs `f(char*)`) as `"ambiguous"`, so `clangd` span checks emit `PARTIAL` (`direct_eligible = True`, line 375) instead of `DISAGREE`.
- **Impact**: Uncompiled `#ifdef` callers, wrong overload candidates, and speculative indirect/virtual call edges in multi-function C/C++ files receive false compiler corroboration (`cross_check.state = "agree"`) or escape `cross_check_disagree` ineligibility, polluting call-graph traversal and admissibility gates.
- **Recommendation**: Require `CLANG_AST` `CallExpr` line/byte containment inside the CodeQL call span (or enclosing function span), include mangled/signature identity or source line in `LLVM_IR` matching, and compare `qualified_name`/`scope` + `signature` from `job_cpp_symbol_index` (`src/appsec_review/jobs/job_cpp_symbol_index/job.py:188-193`) in `src/appsec_review/graph/crosscheck.py` so distinct C++ namespaces/overloads at the same call span produce `DISAGREE`.
- **Effort**: `M (days)`
- **Already registered**: `T-126` registers single-producer coverage outside C/C++ (and overlooks that `svf_crosscheck.py` already covers `guard_fact`/`dataflow_path`), but assumes existing C/C++ `call_site` cross-checks are sound; these false-`agree` and suppressed-`disagree` defects are new.

#### C07-F02 Unverified export-pack hashes stamp unmeasured SHA-256 provenance onto `graph-fact/1` and crash checkpoint reuse on pack re-pins
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_codeql_analysis`
- **Evidence**: `src/appsec_review/jobs/job_codeql_analysis/job.py:88-90`, `src/appsec_review/jobs/job_codeql_analysis/job.py:955-984`, `src/appsec_review/jobs/job_codeql_analysis/job.py:1096-1102`, `containers/tools/codeql/codeql_runner.py:412-417`, `containers/tools/codeql/codeql_runner.py:515-518`, `src/appsec_review/graph/normalize.py:534`. `_verify_export_sources` binds `digest` without reading it (`job.py:964`) and `_verify_export_pack` checks only `path.is_file()`, yet `codeql_runner.py:516-518` copies `entry["tree_sha256"]` from `assets.lock.json` into `export-manifest.json` and `normalize.py:534` stamps that unverified `export_pack_sha256` onto every `graph-fact/1`; meanwhile `_export_identity` (`job.py:88-90,982-984`) strips `*_sha256`, so updating `tree_sha256` under shipped `"undeclared"` releases reuses a stale `export-checkpoint.json` and crashes `_verify_export_manifest` (`job.py:1100-1102`) with `FrameworkIntegrityError`.
- **Impact**: Modified or drifted `rules/codeql-graph-export/<lang>` packs and `catalog.json` produce run artifacts stamped with stale cryptographic hashes while docs claim fail-closed hash verification, and following the documented pack re-pin workflow (`T-118`..`T-122`) crashes checkpoint reuse unless `releases.export_<lang>` is also bumped.
- **Recommendation**: Either compute actual tree/file SHA-256 over the staged export pack and `columns.json` when writing `export-manifest.json` (recording `export_pack_release` separately from measured bytes) or restore hash checks in `containers/tools/codeql/codeql_runner.py` and `src/appsec_review/jobs/job_code_graph_index/job.py:111-123`, and align `_export_identity` with `_verify_export_manifest` so pack updates invalidate rather than crash.
- **Effort**: `S (under a day)`
- **Already registered**: `T-118`..`T-122` reference re-pinning `tree_sha256` and `catalog_sha256`; new is that those hashes are no longer verified against staged files yet are still stamped onto `graph-fact/1` and enforced asymmetrically in `_verify_export_manifest`.

#### C07-F03 C/C++ and Swift `GraphExport.qll` drop member/namespaced model sinks on bare-name collisions and miss `sprintf` output-buffer taint
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_codeql_analysis`
- **Evidence**: `rules/codeql-graph-export/cpp/GraphExport.qll:246-306`, `rules/codeql-graph-export/swift/GraphExport.qll:238-285`. Unlike the Python/JS/Java/Go/Rust/C# packs (which negate `apiCallSink(call, ...)` including declaring module/type), `rules/codeql-graph-export/cpp/GraphExport.qll:263` writes `not apiSinkArgument(call.getTarget().getName(), _)`, suppressing `modelCallSink` for any C++ method or namespaced function sharing a bare name with the 20 C API entries (`open`, `system`, `read`, `memcpy`, `strcpy`, `fopen`, `unlink`, `rand`) even when `hasGlobalOrStdName` is false; `swift/GraphExport.qll:239,277` ignores `declaredIn` in `apiCallSink`, turning framework sinks named `allocate`/`dataTask` into `unclassified` `"api"` rows; and `rules/codeql-graph-export/cpp/GraphExport.qll:269,302-306` binds `sprintf`/`snprintf`/`vsprintf` via `ArrayFunction.hasArrayOutput(0)` (`operand = buf`) where `sinkNode` matches only pre-call `n.asExpr() = operand` / `n.asIndirectExpr() = operand`.
- **Impact**: Real C++ command/SQL/path/memory sinks on member methods (e.g., `db.open(user)`, `runner.system(cmd)`) and `sprintf(buf, "%s", tainted)` buffer overflows with constant format strings are omitted from `sink_sites` and `dataflow_path`.
- **Recommendation**: Change `rules/codeql-graph-export/cpp/GraphExport.qll:263` to `not apiCallSink(call, _, _)`, check `declaredIn` inside `rules/codeql-graph-export/swift/GraphExport.qll:238-241`, and add `sprintf`/`snprintf`/`vsprintf`/`strcat`/`strncat` format/source argument indices to `apiSinkArgument` (or include `DataFlow::PostUpdateNode` on `ArrayFunction` output arguments in `sinkNode`).
- **Effort**: `S (under a day)`
- **Already registered**: no (`T-120` covers five unclassified `catalog.json` model names, not QL sink suppression or `sprintf` taint-node binding).

#### C07-F04 `job_tree_sitter_ast` sets `max_nodes_per_scope = 20000` equal to `max_nodes_per_file`, truncating ~85-90% of files in full scopes
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_tree_sitter_ast`
- **Evidence**: `appsec-review.toml:955-958`, `src/appsec_review/jobs/job_tree_sitter_ast/model.py:48,80-90`, `containers/tools/tree-sitter/parser.py:72-97`. `plan_scopes` packs up to `128` files (`16 MiB`) into one scope, while `parser.py:92` counts every CST node including unnamed punctuation tokens against `maximum_scope_nodes = 20000` (identical to `max_nodes_per_file = 20000`); once ~10-15 normal source files consume 20,000 CST tokens, `parser.py:75-83` still parses every remaining file in full and discards all its nodes as `TRUNCATED` (`scope_node_limit`).
- **Impact**: On any component with more than ~15 files per language, alphabetically later files receive zero AST nodes in `analysis` shards, breaking `query_syntax`, Tree-sitter review-package slicing (`src/appsec_review/review/slicing/strategies/tree_sitter.py:132-160`), symbol-to-syntax links (`src/appsec_review/indexing/links.py:310-377`), and threat-model syntax interaction candidates (`src/appsec_review/threat_model/lanes/interactions.py:124-132`).
- **Recommendation**: Raise `max_nodes_per_scope` in `appsec-review.toml:958` and `src/appsec_review/jobs/job_tree_sitter_ast/model.py:48` to match scope sizing (e.g., `1_000_000` or `max_files_per_scope = 16` with `max_nodes_per_scope = 320_000`), and skip calling `parser.parse(data)` in `containers/tools/tree-sitter/parser.py:75` once `scope_nodes >= maximum_scope_nodes`.
- **Effort**: `S (under a day)`
- **Already registered**: no.

#### C07-F05 Multi-build-unit C/C++ repositories lose `clangd`, `svf`, `clang-ast`, and `llvm-ir` cross-checks on sibling CodeQL scopes
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_code_graph_index`
- **Evidence**: `src/appsec_review/jobs/job_code_graph_index/scopes.py:340-360`, `src/appsec_review/jobs/cpp_index_scopes.py:165-199`, `src/appsec_review/jobs/job_codeql_analysis/planning.py:196-225`. `job_codeql_analysis` emits one scope per `build_unit_id`, whereas `job_cpp_symbol_index`, `job_svf_alias_analysis`, and `job_cpp_compiled_analysis` emit shards per C/C++ `case_id` (`project_root`); `assign_secondary` (`scopes.py:354-360`) assigns each secondary shard exclusively to `winner = overlap[0][1]` and withholds it from all sibling C/C++ CodeQL scopes.
- **Impact**: In CMake/Make/Meson repositories defining multiple libraries or binaries under one project root, all C/C++ CodeQL scopes except one receive zero secondary shards (`not_covered` / `producer_not_run`), losing `clangd` contradiction checks, `svf` indirect-call/alias refinement, and `producer_neighborhood` flow/diagnostic context.
- **Recommendation**: Update `assign_secondary` in `src/appsec_review/jobs/job_code_graph_index/scopes.py:340-360` to attach each secondary shard to *every* C/C++ CodeQL scope whose `scope_paths` overlap `paths` (filtering `secondary_only` emission in `crosscheck.py` and `producers.py` to `scope_paths`, which `crosscheck.py:329-331` already does via `sources`).
- **Effort**: `S (under a day)`
- **Already registered**: no.

#### C07-F06 `job_codeql_analysis` drops `job_clang_static_analysis` seeds, hard-requires optional C++/artifact handoffs, and over-serializes Wave 1
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_codeql_analysis`
- **Evidence**: `src/appsec_review/jobs/job_codeql_analysis/datasets.py:67-93`, `src/appsec_review/jobs/job_codeql_analysis/datasets.py:220`, `src/appsec_review/jobs/job_codeql_analysis/job.py:1029-1035`, `src/appsec_review/jobs/job_codeql_analysis/job.py:1568-1584`. `datasets.py` declares `job_clang_static_analysis` in `CONTRACT.inputs` and `schedule_after`, yet `plan.inventory` (`job.py:1575-1577`) omits `"job_clang_static_analysis"` (plus `"job_debug_symbol_indexing"` and `"job_svf_alias_analysis"`) when collecting `upstream_manifests`, so `_seed_plan` (`job.py:1031-1033`) never extracts seeds from Clang Static Analyzer / `clang-tidy` observations; meanwhile `job.py:1568-1571` calls `_accepted_handoff_identity(..., required=True)` on `OPTIONAL` inputs `job_artifact_indexing` and `job_cpp_compiled_analysis`, and `datasets.py:220` blocks CodeQL behind 9 Wave-1 jobs (`job_svf_alias_analysis`, `job_cpg_analysis`, `job_cpp_symbol_index`, `job_tree_sitter_ast`, `job_change_context_analysis`, etc.) that CodeQL never reads.
- **Impact**: Default `seeded` C/C++ CodeQL misses neighborhoods around `clang-analyzer`/`clang-tidy` findings, selective/non-C++ standalone runs fail if `job_cpp_compiled_analysis` or `job_artifact_indexing` has no handoff, and Wave-1 critical-path wall time increases because the slowest job waits on unrelated producers.
- **Recommendation**: Add `"job_clang_static_analysis"` to the optional manifest loop in `src/appsec_review/jobs/job_codeql_analysis/job.py:1575-1577`, switch `job_artifact_indexing` and `job_cpp_compiled_analysis` at lines 1568-1571 to `_optional_accepted_handoff_identity`, and trim `schedule_after` in `src/appsec_review/jobs/job_codeql_analysis/datasets.py:220` to actual inputs (`job_language_build`, `job_evidence_collection`, `job_clang_static_analysis`, `job_artifact_security_analysis`, `job_cpp_compiled_analysis`, `job_artifact_indexing`), letting `job_code_graph_index` and `job_review_data_indexing` compose sibling manifests.
- **Effort**: `S (under a day)`
- **Already registered**: `T-014` tracks seeded CodeQL language rollout; the missing `job_clang_static_analysis` manifest wiring, `required=True` crash on optional handoffs, and Wave-1 over-serialization are new.

#### C07-F07 `query_code_graph(mode="paths")` with a `SOURCE_FILE` subject returns only paths whose sink is in that file
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_code_graph_index`
- **Evidence**: `src/appsec_review/retrieval/graph.py:208-218`, `src/appsec_review/graph/normalize.py:1118-1120`. `normalize.py:1118` stores every `dataflow_path` entity's single `locations` row at `sink.location`; in `retrieval/graph.py:216-218`, `_subject_clause` for `Mode.PATHS` when `subject.kind is EntityKind.SOURCE_FILE` filters solely on `l.path = ?`, unlike `EntityKind.SYMBOL` (lines 210-215) which joins both `FLOWS_FROM` and `FLOWS_TO` endpoints.
- **Impact**: Querying `query_code_graph(mode="paths", subject=<source_file_id>)` on an ingress/controller file whose tainted input flows to a SQL, command, or memory sink in another file returns zero paths without a gap, hiding cross-file vulnerabilities from review workers.
- **Recommendation**: Update `_subject_clause` for `(Mode.PATHS, EntityKind.SOURCE_FILE)` in `src/appsec_review/retrieval/graph.py:216-218` to match `l.path = ?` OR `EXISTS (SELECT 1 FROM relations r JOIN locations sl ON sl.entity_id = r.target_id WHERE r.source_id = e.identity AND r.kind IN ('FLOWS_FROM', 'FLOWS_TO') AND sl.path = ?)`.
- **Effort**: `S (under a day)`
- **Already registered**: no.

#### C07-F08 Shipped `"undeclared"` releases discard precompiled CodeQL export caches and compile every export pack twice per scope
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_codeql_analysis`
- **Evidence**: `src/appsec_review/codeql/runtime.py:429-432`, `src/appsec_review/jobs/job_codeql_analysis/job.py:1187-1228`, `containers/tools/codeql/codeql_runner.py:489-492`, `appsec-review.toml:690-700`. When `[review_policy.releases]` entries are `"undeclared"` (the shipped default), `CodeQLExecutor._compile_cache` returns `None` (`runtime.py:430-431`) and `cacheable` is `False` (`job.py:1194`); `_precompile_export_pack` still runs `executor.execute("compile", ...)` inside an ephemeral `--rm` container whose tmpfs `HOME` (`/tmp/codeql-home`) is destroyed on exit, and `codeql_runner.py:490` immediately compiles the entire export pack a second time from scratch inside `executor.execute("export", ...)` under the export timeout (`1800s`, 2 threads / 4 GiB RAM), repeating both cold compiles `2 * N` times across `N` scopes.
- **Impact**: Doubles cold QL compilation work on single scopes, multiplies it `2N`-fold on multi-scope targets, and charges cold compilation directly against the `1800s` export evaluation budget—risking `CodeQL graph export timed out` gaps on default runs.
- **Recommendation**: Mount a run-scoped Docker compile-cache volume (keyed by `run_id`, `image.image_id`, and `language`) in `src/appsec_review/codeql/runtime.py:429-445` and cache `key` in `_PRECOMPILED` within the run (`src/appsec_review/jobs/job_codeql_analysis/job.py:1193-1228`) even when cross-run `[review_policy.releases]` are undeclared.
- **Effort**: `S (under a day)`
- **Already registered**: `T-018` and `T-118`/`T-119` note slow cold export compiles, but do not identify this double-compile / throwaway-container bug as the cause.

#### C07-F09 Language and suffix gaps drop `.jsx`/`.mjs`/`.cjs`/`.mts`/`.cts`/`.kts`, Shell/PowerShell syntax projections, and Python/Kotlin/Swift prioritization coverage
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/cataloging.py:12-17`, `src/appsec_review/jobs/job_tree_sitter_ast/generated_sources.py:18-19`, `src/appsec_review/jobs/job_tree_sitter_ast/projection.py:9-43`, `src/appsec_review/jobs/job_codeql_analysis/planning.py:19-29`, `src/appsec_review/jobs/job_review_prioritization/semantic.py:25-27`. `cataloging.LANGUAGES` omits `.jsx`, `.mjs`, `.cjs`, `.mts`, `.cts`, `.kts`, `.pyi`, and `.c++` even though `generated_sources.py` and `codeql_analysis/planning.py` support them, leaving first-party files with those suffixes `language = None`; `projection.py:9-43` has no `bash` (`Shell`) or `powershell` (`PowerShell`) entries in `DEFINITIONS`, `CALLS`, or `IMPORTS` despite `job_tree_sitter_ast` parsing both; and `job_review_prioritization/semantic.py:25-27` omits `Python`, `Kotlin`, and `Swift` from `CODEQL_LANGUAGES` (and `Python` from `SCORED_LANGUAGES` at `job_review_prioritization/job.py:67-69`).
- **Impact**: ES-module JavaScript/TypeScript (`.mjs`, `.mts`, `.jsx`) and `.kts` files are skipped by both Tree-sitter and buildless CodeQL; `query_syntax` returns empty results (`syntax_projection_unavailable`) on every Shell/PowerShell script; and prioritization omits Python/Kotlin when checking missing CodeQL semantic coverage.
- **Recommendation**: Add `.jsx`/`.mjs`/`.cjs`/`.mts`/`.cts`/`.kts`/`.pyi`/`.c++` to `src/appsec_review/jobs/cataloging.py:12-17`, add `bash` and `powershell` node mappings (`function_definition`, `command`, `command_name`) to `src/appsec_review/jobs/job_tree_sitter_ast/projection.py`, and add `"Python": "python"`, `"Kotlin": "java"`, and `"Swift": "swift"` to `CODEQL_LANGUAGES` in `src/appsec_review/jobs/job_review_prioritization/semantic.py:25-27`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-126` covers PHP/Swift dataflow gaps; these suffix, projection, and `CODEQL_LANGUAGES` omissions are new.

#### C07-F10 Python and Ruby `GraphExport.qll` exclude module-level and class-body code in `seeded` mode
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_codeql_analysis`
- **Evidence**: `rules/codeql-graph-export/python/GraphExport.qll:75-77`, `rules/codeql-graph-export/python/GraphExport.qll:154-167`, `rules/codeql-graph-export/ruby/GraphExport.qll:69-70`, `rules/codeql-graph-export/ruby/GraphExport.qll:136-163` (contrast `rules/codeql-graph-export/javascript/GraphExport.qll:81-155`, which includes `TopLevel` in `SourceFunction`). Both packs restrict `SourceFunction` to `Function` / `MethodBase`; under `export_queries.mode = "seeded"` (`appsec-review.toml:693`), `nodeFunction(n)` fails for module-level statements, class bodies, and Sinatra/Rails DSL blocks, so `seedFunction` resolves zero seeds there and `exportedNode(n)` blocks taint paths crossing module scope.
- **Impact**: Seeded Python and Ruby exports silently miss scanner seeds and `dataflow_path` flows in script entry points, WSGI/ASGI wiring, Rails initializers, and Sinatra route blocks.
- **Recommendation**: Extend `SourceFunction` in `rules/codeql-graph-export/python/GraphExport.qll` (`Module` / `Class` scopes) and `rules/codeql-graph-export/ruby/GraphExport.qll` (`Toplevel` / `ModuleBase`, matching `javascript/GraphExport.qll`) before enabling seeded mode on Python/Ruby.
- **Effort**: `M (days)`
- **Already registered**: `T-014` plans seeded rollout beyond C/C++; this QL defect blocks accurate Python/Ruby seeded exports and is not recorded in `T-014`.

#### C07-F11 `TRUNCATED` Tree-sitter files report `"partial"` syntax-projection coverage instead of `"unavailable"` and lose `source_file` locations
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_tree_sitter_ast`
- **Evidence**: `src/appsec_review/jobs/job_tree_sitter_ast/normalize.py:66-69`, `src/appsec_review/jobs/job_tree_sitter_ast/normalize.py:124-149`, `src/appsec_review/jobs/job_tree_sitter_ast/normalize.py:172-182`, `src/appsec_review/retrieval/syntax.py:72-97`. When `record["status"] == "TRUNCATED"` (`file_byte_limit` or `scope_node_limit`), `parser.py:70,79` emits zero AST nodes, leaving `source_locations.get(path)` `None` (`evidence_artifact` loses its file `SourceLocation` at `normalize.py:139`), yet `normalize.py:66-68,175-182` records `syntax-projection:{source_id}` as `"partial"` rather than `"unavailable"`.
- **Impact**: `query_syntax` on a truncated file with zero indexed nodes reports a generic partial gap instead of `"syntax_unavailable: ... (TRUNCATED)"`, overstating coverage and severing `evidence_artifact` location resolution.
- **Recommendation**: Map `status == "TRUNCATED"` (or `not record.get("nodes")`) to `"unavailable"` in `src/appsec_review/jobs/job_tree_sitter_ast/normalize.py:66-68,175-182`, and synthesize a file-span `SourceLocation` from `scope.files` when `nodes` is empty so `evidence_artifact` retains its `path` and `file_sha256`.
- **Effort**: `S (under a day)`
- **Already registered**: no.

#### C07-F12 Host concurrency setting `job_tree_sitter_ast.settings.workers` changes semantic generated-source intake bounds
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_tree_sitter_ast`
- **Evidence**: `src/appsec_review/jobs/job_tree_sitter_ast/job.py:71-76`. `discover_generated_sources` sets `max_files=max(1, settings.workers) * settings.max_files_per_scope` and `max_bytes=max(1, settings.workers) * settings.max_scope_bytes`.
- **Impact**: Tuning `workers` for host CPU capacity changes which generated protobuf/gRPC/OpenAPI/Thrift files enter the accepted AST handoff and `job_review_prioritization`, breaking cross-host determinism of review scope.
- **Recommendation**: Replace the `settings.workers * ...` multiplier in `src/appsec_review/jobs/job_tree_sitter_ast/job.py:71-76` with explicit deterministic TOML settings (`max_generated_files`, `max_generated_bytes`).
- **Effort**: `S (under a day)`
- **Already registered**: no.

#### C07-F13 Retire deprecated `job_cpg_analysis`, unwired `Producer.JOERN_CPG`, and obsolete `T-022`
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_cpg_analysis`
- **Evidence**: `appsec-review.toml:991-1028`, `src/appsec_review/jobs/job_cpg_analysis/job.py:141-291`, `src/appsec_review/jobs/job_cpg_analysis/export.py:39-42`, `src/appsec_review/graph/contract.py:92-99`, `src/appsec_review/jobs/job_code_graph_index/producers.py:217-244`, `docs/TODO.md` (`T-021`, `T-022`). Shipped `enabled = false`, `job_cpg_analysis` still executes three steps on every C/C++ run to publish disabled-gap shards while `job_codeql_analysis` and `job_code_graph_index` wait on it; whole-program mode emits zero observations (`JOERN_GAP`), seeded mode emits name-matched calls with `NO_CALL_EDGES_GAP`/`NO_CFG_GAP`, `Producer.JOERN_CPG` is never produced by `crosscheck.py`, and `T-022` ("Add additional Joern language frontends") remains `open` despite `T-021` being marked Deprecated under `docs/architecture/code-graph-precomputation.md` §12.5.
- **Impact**: Adds dead Wave-1 DAG dependencies, unused `tool-joern` maintenance surface, redundant manifest shards, and contradictory backlog/docs without contributing a single unique finding or corroboration edge beyond CodeQL + clangd + Clang AST + LLVM IR + SVF.
- **Recommendation**: Delete `src/appsec_review/jobs/job_cpg_analysis/`, `Producer.JOERN_CPG` in `src/appsec_review/graph/contract.py`, the Joern branches in `src/appsec_review/jobs/job_code_graph_index/{datasets.py,scopes.py,producers.py}` and `src/appsec_review/indexing/input_matrix.py`, and close `T-021`/`T-022` in `docs/TODO.md` as superseded.
- **Effort**: `M (days)`
- **Already registered**: `T-021` (Deprecated), `T-022` (`open`), and `T-016` note Joern's status; new is that `T-022` contradicts `T-021` and §12.5's sunset condition is already satisfied on C/C++, warranting outright removal.

#### C07-F14 `job_cpp_symbol_index` discards partial scopes on non-zero `clangd-indexer` exits, buffers unbounded stdout in RAM, and hashes target files three times
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_cpp_symbol_index`
- **Evidence**: `src/appsec_review/jobs/job_cpp_symbol_index/job.py:73-77`, `src/appsec_review/jobs/job_cpp_symbol_index/job.py:104-121`, `src/appsec_review/jobs/job_cpp_symbol_index/job.py:265-275`, `src/appsec_review/jobs/job_cpp_symbol_index/clangd_yaml.py:122-128`, `src/appsec_review/jobs/cpp_index_scopes.py:17-20,187-192`. `job.py:109` marks the entire scope `unavailable` (`0` symbols) whenever `clangd-indexer --executor=all-TUs` exits non-zero on a single broken TU; `job.py:113-116` decodes all `stdout.bin` into memory and `clangd_yaml.py:124` runs `text.splitlines()` before enforcing `max_documents_per_scope = 250000` (with no `file_size_limit_bytes`); and `accepted_cpp_scopes` hashes every file in both `load` and `index` while `_accepted_location` (`job.py:75`) hashes `unit.job.target_root / target_path` a third time (contradicting `cpp_index_scopes.py:17-20`).
- **Impact**: One failing TU wipes out all `clangd` symbol/call cross-checks for a C/C++ project, header-heavy builds trigger large Python memory allocations while parsing YAML stdout, and target files are re-read from the checkout unnecessarily.
- **Recommendation**: Stream `stdout.bin` line-by-line in `src/appsec_review/jobs/job_cpp_symbol_index/clangd_yaml.py` with `file_size_limit_bytes` set on the container request, salvage valid YAML documents emitted before a non-zero exit as `"partial"` coverage with a named gap, and reuse the verified `files[target_path]` SHA-256 from `accepted_cpp_scopes` instead of reading `target_root` in `_accepted_location`.
- **Effort**: `M (days)`
- **Already registered**: `T-023` covers per-TU invocation, header-only symbols, and MSVC flags; the non-zero exit wipeout, unbounded in-memory YAML split, and triple hashing / `TargetAccess.CHECKOUT` violation are new.

#### C07-F15 `job_code_graph_index` processes all scopes serially and scans secondary SQLite shards twice in memory
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_code_graph_index`
- **Evidence**: `src/appsec_review/jobs/job_code_graph_index/job.py:180-221`, `src/appsec_review/graph/analyzers.py:160-200`, `src/appsec_review/graph/crosscheck.py:446-548`, `src/appsec_review/jobs/job_code_graph_index/producers.py:217-263`. `normalize_scopes`, `crosscheck_scopes`, and `correlate_scopes` iterate sequentially over scopes with no worker pool; `analyzers.py:163` loads full `entities` and `relations` tables into Python memory via `fetchall()`, and `producers.build` re-opens and re-scans the same `clangd`, `llvm-ir`, and `clang-ast` SQLite shards that `crosscheck.py` just loaded.
- **Impact**: Polyglot or multi-binary repositories with tens of scopes and up to `200,000` facts per family suffer a single-threaded normalization bottleneck and duplicate multi-hundred-MiB SQLite resident sets between CodeQL completion and `job_security_tagging`.
- **Recommendation**: Push entity-kind filters (`WHERE e.kind IN (...)`) into SQL in `src/appsec_review/graph/analyzers.py:160-175`, share loaded `SecondaryShard` handles (or run `producers.build` alongside `crosscheck`), and bound scope parallelism with a small `ThreadPoolExecutor` in `src/appsec_review/jobs/job_code_graph_index/job.py`.
- **Effort**: `M (days)`
- **Already registered**: no.

#### C07-F16 SARIF-to-graph correlation (`graph/correlate.py`) breaks when SARIF endpoints land on macros/parameters or outside `Paths.ql` shortest-`k` (`k=4`)
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_code_graph_index`
- **Evidence**: `src/appsec_review/graph/correlate.py:72-97`, `src/appsec_review/graph/correlate.py:232-279`, `src/appsec_review/graph/normalize.py:1006-1037`. `_best_endpoint` (`correlate.py:78-97`) requires strict byte-span overlap/containment in the exact same file between SARIF threadFlow endpoints and exported `entry_point`/`sink_site` spans, failing with `source_unmatched`/`sink_unmatched` (`broken`) when standard CodeQL SARIF queries report a callee formal parameter, wrapper call, or macro site while `GraphExport.qll` exports the call argument (or when `seeded` mode excluded the SARIF endpoint's function).
- **Impact**: Valid CodeQL SARIF taint findings fail `sarif_path` bridging (`query_code_graph(mode="sarif_path")` returns empty with `sarif_correlation_broken`) and downgrade the entire scope's `dataflow_path` shard coverage to `"partial"`.
- **Recommendation**: Add a fallback endpoint match in `src/appsec_review/graph/correlate.py:78-97` using enclosing function symbol + matching `threadFlow` intermediate step span (recording `exact=False`, `state="partial"` rather than `"broken"`), and automatically include CodeQL SARIF endpoint locations when running `export` after `query` or document why `export` runs concurrently.
- **Effort**: `M (days)`
- **Already registered**: no.

#### C07-F17 CodeQL database execution copies multi-GiB database trees into scratch per query profile and export
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_codeql_analysis`
- **Evidence**: `src/appsec_review/codeql/predecessor.py:165-177`, `src/appsec_review/jobs/job_codeql_analysis/job.py:867-868`, `src/appsec_review/jobs/job_codeql_analysis/job.py:1171-1172`. `_adopt_predecessor_database` `shutil.copytree`s the predecessor database into `data/codeql/scopes/<scope>/database`, and then `_query_one` (`job.py:868`) and `_export_one` (`job.py:1172`) each `shutil.copytree` the entire database directory again into disposable `scratch/query-database` and `scratch/export/database` trees before running `codeql database run-queries`.
- **Impact**: For a 3 GiB C++ or Java database with default + custom query profiles plus graph export, a single scope writes 9-12 GiB of temporary copies, causing severe disk I/O contention and host storage pressure during concurrent scope execution.
- **Recommendation**: Copy only the mutable CodeQL database metadata/results skeleton or hardlink immutable `db-<lang>/default/*.trap.gz` and `src.zip` blobs (`shutil.copytree(..., copy_function=os.link)` with fallback to `shutil.copy2`, keeping the container user non-owner or read-only on `src.zip`/TRAP files) in `src/appsec_review/jobs/job_codeql_analysis/job.py:868,1172` and `src/appsec_review/codeql/predecessor.py:173`.
- **Effort**: `M (days)`
- **Already registered**: `T-019` covers live matrix testing of predecessor reuse; the multi-copy `shutil.copytree` I/O amplification across `_query_one`, `_export_one`, and `predecessor.py` is new.

#### C07-F18 Dead legacy code, unused `CONTRACT.inputs`, unrecorded seeded-CPG shard reads, and legacy free-text gaps across C07
- **Kind**: `remove`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/job_codeql_analysis/job.py:1244-1271` (dead `_export_scopes` reading removed `"database.scopes"`), `src/appsec_review/jobs/job_code_graph_index/scopes.py:92-98` (`LEGACY_EXPORT_OUTPUT`), `src/appsec_review/graph/settings.py:61-72` (uncalled `catalog_pins`), `src/appsec_review/jobs/job_cpp_symbol_index/datasets.py:55-76` (declares `job_evidence_collection` and `job_target_catalog` inputs never read by `accepted_cpp_scopes`), `src/appsec_review/jobs/job_cpg_analysis/seeded.py:59` (reads `observations` shards via `resolve_context_manifest` without `accepted_upstream`), and `tests/test_gap_contract.py:12-28` (all 5 C07 jobs still on `LEGACY_FREE_TEXT_GAPS`, `strict_gaps=False`).
- **Impact**: Dead migration shims keep obsolete unit tests green against unused code paths, `job_cpp_symbol_index` over-declares upstream consumption (`CONSUMES`), and C07 gap strings bypass `producer-gap/1` schema validation.
- **Recommendation**: Remove `_export_scopes`, `LEGACY_EXPORT_OUTPUT`, `catalog_pins`, and unused `job_evidence_collection`/`job_target_catalog` entries in `job_cpp_symbol_index/datasets.py`, and migrate the four retained C07 jobs to `producer_gap` (`strict_gaps=True`).
- **Effort**: `M (days)`
- **Already registered**: `T-113` covers moving unit test files under `tests/unit/<job_id>/`; the dead code, contract-input drift, and `strict_gaps=False` backlog in C07 are not registered.

#### C07-F19 Documentation drift across `cross-language-codeql.md`, `code-graph-index.md`, `codeql-analysis.md`, and `cpp-index-jobs.md`
- **Kind**: `doc-drift`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `docs/architecture/cross-language-codeql.md:14-20` documents a removed 4-stage pipeline (`plan` -> `database` -> `analyze` -> `acceptance`) with no mention of `execution.scopes` (`codeql/scheduler.py`) or graph export (`appsec-review.toml:677-686`); `docs/operations/cpp-index-jobs.md:95` vs `117` states both `enabled = false` and "Whole-program CPG generation is the default" (TOML line `1005` sets `mode = "seeded"`, `enabled = false`); `docs/operations/code-graph-index.md:16-18,37`, `docs/operations/codeql-analysis.md:38`, and `rules/codeql-graph-export/README.md:148-151` claim runtime SHA-256 verification of `catalog.json` and export packs that `tests/test_codeql_export_step.py:445-457` explicitly forbids.
- **Impact**: Misleads operators and agents debugging CodeQL scheduling, checkpoint reuse, pack/catalog pinning, or C/C++ index defaults.
- **Recommendation**: Update `docs/architecture/cross-language-codeql.md` to the 3-stage `plan` -> `execute` (`execution.scopes`) -> `acceptance` architecture, reconcile the pack/catalog verification docs with the C07-F02 fix, and remove or correct the CPG section in `docs/operations/cpp-index-jobs.md`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-116` covers C/C++-only wording in two non-C07 docs; these four C07 doc-vs-code contradictions are new.

#### C07-F20 Unit tests target dead `_export_scopes` and single-function/single-file fixtures that hide C07-F01, C07-F04, C07-F05, and C07-F07
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/test_codeql_export_step.py:92,193-260` exercises dead `_export_scopes` (`database.scopes`) in 6 of 7 export tests rather than `execution.scopes`; `tests/graph/test_crosscheck.py:16-24,148-153` places one caller function (`process`) in `src/net.c`, masking caller-blind `CLANG_AST` and overload-blind `CLANGD` bugs (C07-F01); `tests/test_code_graph_index_job.py:175-204` tests two scopes where only one has a secondary shard, missing `assign_secondary` starvation across sibling build units (C07-F05); and `tests/test_retrieval_code_graph.py:80-126` puts all functions in a single `src/net.c` file, masking cross-file `Mode.PATHS` failure on `SOURCE_FILE` subjects (C07-F07).
- **Impact**: All C07 unit suites pass while critical/high multi-function, multi-file, and multi-build-unit defects reach live reviews undetected.
- **Recommendation**: Port `tests/test_codeql_export_step.py` onto `execution.scopes`, and add multi-caller/overload cases to `tests/graph/test_crosscheck.py`, multi-build-unit C++ shard sharing to `tests/test_code_graph_index_job.py`, a 25-file scope node-budget test to `tests/test_tree_sitter_ast.py`, and cross-file `SOURCE_FILE` `Mode.PATHS` assertions to `tests/test_retrieval_code_graph.py`.
- **Effort**: `M (days)`
- **Already registered**: `T-113` (test directory layout) and `T-115`/`T-122` (hand-authored QL export fixtures); these concrete behavioral test blind spots are new.
### C08 Native and binary analysis

**Active findings:** 16 (`3` critical, `6` high, `6` medium, `1` low).

C08 spans the seven native, artifact, symbol, and binary producers (`job_cpp_compiled_analysis`, `job_clang_static_analysis`, `job_svf_alias_analysis`, `job_artifact_security_analysis`, `job_post_build_security_assessment`, `job_debug_symbol_indexing`, and `job_binary_evidence_indexing`). Several subsystems—particularly Ghidra publication/indexing, dyadic u64 debug-symbol interval indexing, and SVF epistemic admissibility (`agree`/`partial`/`disagree` gated on closed-world modules)—are carefully engineered, deterministic, and sound. However, three broken upstream/staging seams in `job_cpp_compiled_analysis` silently cripple real C/C++ builds: link commands from `job_language_build` are never loaded (preventing multi-TU SVF modules and all closed-world SVF verdicts in production), root-level C/C++ builds rewrite `/workspace/build` `-I` include paths to `/scratch/source/build`, and `shutil.ignore_patterns(".git", "build", "target")` strips any nested `target/` or `build/` source directory at arbitrary depth. Across the component, ELF/PE hardening is inspected redundantly in three jobs, `job_post_build_security_assessment` runs a per-case LLM step whose validator prevents it from contributing any finding beyond the deterministic table, and all seven jobs remain on `LEGACY_FREE_TEXT_GAPS`.

**Strengths to preserve:**
- Sound epistemic modeling in SVF cross-checking: Andersen may-alias can only confirm (`agree`) or cast doubt (`partial`), while `disagree` requires every consulted SVF row to come from a complete, closed-world linked module (`src/appsec_review/graph/svf_crosscheck.py:8-18`, `src/appsec_review/graph/svf_crosscheck.py:152-194`).
- Unsigned 64-bit dyadic interval cover in `debug_symbol_index.py` avoids SQLite signed-integer overflow and bounds address range point queries to 65 exact prefix probes (`src/appsec_review/retrieval/debug_symbol_index.py:24-35`, `src/appsec_review/retrieval/debug_symbol_index.py:78-89`).
- Checksum-verified DWARF/PDB source binding in `job_debug_symbol_indexing`: unverified recorded paths are hashed rather than promoted to source locations, preventing binary debug info from forging source authority (`src/appsec_review/jobs/job_debug_symbol_indexing/job.py:362-454`).
- Clean separation between pre-run heavyweight Ghidra decompilation (`binary_decompilation/runner.py`) and fast, deterministic, hash-verified run-time shard indexing (`src/appsec_review/jobs/job_binary_evidence_indexing/job.py:328-408`, `src/appsec_review/binary_decompilation/publication.py:83-155`).
- Per-toolchain hardening expectation table (`FAMILY_EXPECTATIONS`) prevents reporting Go's default non-PIE static executable or Rust's default lack of C stack canaries as false hardening regressions (`src/appsec_review/jobs/job_post_build_security_assessment/hardening.py:67-121`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_cpp_compiled_analysis` | `job_language_build`, optional `job_target_analysis_plan` + `job_evidence_collection` (`seeding.seed_plan`) | `cpp_build_graph`, `clang_ast`, `llvm_ir`, `infer_observations`, `binary_symbols`, `cpp_blocked_branches` shards + `data/cpp/projects/*` | `C08-F01`–`C08-F06` (wrong `.appsec-review-link-commands.json` path, `ignore_patterns("build", "target")`, `/workspace` -> `/scratch/source` `-I` bug, missing build-image headers) | rework |
| `job_clang_static_analysis` | `job_cpp_compiled_analysis` (`data/cpp/projects/*`), `job_evidence_collection` + `job_target_catalog` (seeded mode) | `observations` shards (`clang-static-*`, `clang-static-coverage-*`) | `C08-F03`, `C08-F04`, `C08-F09` (inherits broken `-I` paths and missing headers; bypasses `JobContract` via `cpp_index_scopes`) | rework |
| `job_svf_alias_analysis` | `job_cpp_compiled_analysis` (`data/cpp/projects/*`) | `analysis` shards (`svf-cpp-scope-*`, `points_to_set`, `indirect_call_targets`, `memory_object`) | `C08-F01` (always receives `link_commands=[]`, forcing single-TU open-world mode and disabling closed-world `DISAGREE` verdicts) | rework |
| `job_artifact_security_analysis` | `job_artifact_indexing`, `job_language_build` | `observations` shard (`artifact-security`) across `inventory`, `native`, `jvm`, `packages`, `wasm`, `blint`, `syft`, `grype`, `osv`, `spotbugs` | `C08-F12` (`ScannerAdapter.identity` hardcoded `"undeclared"`; overlaps `job_post_build_security_assessment` on ELF/PE hardening) | rework |
| `job_post_build_security_assessment` | `job_cpp_compiled_analysis` (optional), `job_language_build`, `job_project_build`, `job_build_environment_analysis` | `build_security` index shards + case assessment JSON | `C08-F07`, `C08-F08`, `C08-F11` (basename-only output matching, bogus ELF gap on Go/Rust builds, zero-net-information LLM unit) | merge |
| `job_debug_symbol_indexing` | `job_artifact_indexing`, `job_language_build` | `debug_symbols` shards (`symbols-clang_dwarf` or `symbols-msvc_pdb`) | `C08-F10` (`target_decision` `/1` vs `/2` mismatch, resolved post-anchor in `9c41d5e45`) and free-text gaps | rework |
| `job_binary_evidence_indexing` | `job_review_intake` (`binary_evidence`), `job_target_catalog`, frozen Ghidra publications under `data/binary-decompilation/` | `binary` shards (`binary_function`, `binary_call_site`, `binary_import`, `binary_string`) + detached pseudo-C | `C08-F15` (PE+PDB live container path unvalidated end-to-end under `T-032`; legacy free-text gaps) | keep |

#### C08-F01 Broken link-command handoff leaves `link_commands` empty in production and forces SVF into single-TU open-world fallback
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified`
- **Job**: `job_cpp_compiled_analysis`, `job_svf_alias_analysis`
- **Evidence**: `src/appsec_review/jobs/job_language_build/job.py:1498-1502`, `src/appsec_review/jobs/job_language_build/job.py:1546-1547`, `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:1043-1057`, `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:1130-1134`, `src/appsec_review/jobs/job_svf_alias_analysis/planning.py:72-75`
- **Impact**: `job_language_build` moved `link-commands.json` outside the container-owned build tree to `root / "link-commands.json"` and records it in `receipt["link_database"]`, but `job_cpp_compiled_analysis` never copies or reads `receipt["link_database"]` and still probes `root / "build" / ".appsec-review-link-commands.json"`, which nothing in `src/` or `containers/` writes. Consequently `link_commands` is always `[]` on real builds: `cpp_build_graph` emits zero `LINKS_INTO` relations, and `job_svf_alias_analysis` degrades every C/C++ scope to single-TU open-world modules (`no_link_commands`), losing cross-TU points-to/indirect-call resolution and making closed-world `DISAGREE` verdicts in `svf_crosscheck.py` unreachable.
- **Recommendation**: Verify and load `compiled["build_receipt"]["link_database"]` directly in `job_cpp_compiled_analysis` `catalog()` (with path/SHA-256 verification matching `native_compile_database`) instead of probing `.appsec-review-link-commands.json`.
- **Effort**: `S`
- **Already registered**: none

#### C08-F02 Recursive `ignore_patterns(".git", "build", "target")` strips valid C/C++ source directories and invalidates compile databases
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified`
- **Job**: `job_cpp_compiled_analysis`
- **Evidence**: `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:1042`, `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:331-334`, `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:1115-1121`
- **Impact**: `shutil.ignore_patterns(".git", "build", "target")` matches directory and file basenames at every depth of `target_source`, silently omitting legitimate source/header directories such as `src/target/`, `include/target/`, or `tools/build/` from `case_root / "source"` and `source-mapping.json`. When `normalize_compile_db` encounters any translation unit under those directories, it raises `ValueError("compile database source is not in the accepted case mapping")`, marking the entire C/C++ project `INVALID_COMPILE_DATABASE` and blocking AST, IR, Infer, binary symbols, `job_clang_static_analysis`, `job_svf_alias_analysis`, `job_cpp_symbol_index`, `job_cpg_analysis`, and `job_post_build_security_assessment`.
- **Recommendation**: Copy accepted source files from the target's VCS/catalog file list (or ignore only VCS dirs `.git`/`.hg`/`.svn` plus the exact resolved `build_dir` path, matching `job_language_build._copy_source`).
- **Effort**: `S`
- **Already registered**: none

#### C08-F03 `_sanitize_arguments` rewrites `/workspace/<build_dir>` include flags to `/scratch/source/<build_dir>` for root-level C/C++ units
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified`
- **Job**: `job_cpp_compiled_analysis`, `job_clang_static_analysis`, `job_svf_alias_analysis`
- **Evidence**: `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:173-179`, `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:219-222`, `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:1042-1047`
- **Impact**: When a C/C++ unit is rooted at `"."`, `workspace_root(".")` returns `"/workspace"`. `_sanitize_arguments` executes `mapped.replace("/workspace", "/scratch/source")` without first mapping the build directory (`/workspace/<build_dir>`) to `"/scratch/build"`. Every `-I/workspace/build/...` flag for generated headers (`config.h`, `.pb.h`, `.inc`, CMake configure_file outputs) is rewritten to `/scratch/source/build/...` (which does not exist because `build` is staged at `/scratch/build`), causing Clang AST, LLVM IR, Infer, clang-tidy, Clang Static Analyzer, and SVF bitcode compilation to fail with missing-header errors.
- **Recommendation**: Pass `build_dir` from `receipt["recipe"]["build_dir"]` into `normalize_compile_db` / `_sanitize_arguments` and replace `/workspace/<build_dir>` (and boundary-checked prefixes, not raw substring `.replace`) with `/scratch/build` before mapping `/workspace` to `/scratch/source`.
- **Effort**: `S`
- **Already registered**: none

#### C08-F04 Native replay containers ignore the project's derived build image and fail on build-installed headers
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: `job_cpp_compiled_analysis`, `job_clang_static_analysis`, `job_svf_alias_analysis`
- **Evidence**: `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:113-141`, `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:367-373`, `src/appsec_review/jobs/cpp_index_scopes.py:217-247`, `src/appsec_review/debug_symbols/execution.py:114-120`
- **Impact**: Unlike `job_debug_symbol_indexing` (which runs inside `self.build_image` from `job_language_build` first and falls back to the catalog tool image), `job_cpp_compiled_analysis`, `job_clang_static_analysis`, and `job_svf_alias_analysis` replay compile commands solely inside static catalog images (`tool-native-cpp`, `tool-infer`, `tool-clang-static-analysis`, `tool-svf`). System/third-party `-dev` headers installed into `/usr/include` or `/usr/local/include` when `job_project_build` synthesized the target's build image are absent during replay, causing translation units to fail and `replay_failures` to trigger `safety.fail("replay contains failed compilation commands")`.
- **Recommendation**: Export a sysroot/header overlay from the accepted `job_language_build` container image (or mount read-only `/usr/include` + `/usr/local/include` from the build image) into the replay containers, or record missing-system-header TUs as scoped `producer-gap/1` coverage gaps rather than aborting replay via `safety.fail`.
- **Effort**: `M`
- **Already registered**: none

#### C08-F05 Unseeded `_ir_index` bypasses `llvm_ir.parse_module` and `clang_cfg`, dropping CFGs, dominators, def-use chains, and real line numbers
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: `job_cpp_compiled_analysis`
- **Evidence**: `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:660-710`, `src/appsec_review/jobs/job_cpp_compiled_analysis/seeded.py:252-330`, `src/appsec_review/jobs/job_cpp_compiled_analysis/llvm_ir.py:148-260`
- **Impact**: When `seeded=False` (the default whole-program mode for smaller C/C++ targets or unseeded runs), `_ir_index` never calls `llvm_ir.parse_module` or `clang_cfg.parse_cfgs`. Instead it scans `.ll` files with two regexes (`_IR_ENTITY`, `_IR_CALL`), leaves mangled linkage symbols un-demangled, emits zero CFG blocks/dominators/def-use/indirect-call payloads, ignores `.cfg` outputs, and stamps every function's `SourceLocation` at line 1 of the `.cpp` file with `ambiguous=True`—making whole-program `llvm_ir` shards strictly inferior to seeded ones and unusable for line-level slicing.
- **Recommendation**: Unify `_ir_index` onto `llvm_ir.parse_module` + `clang_cfg.parse_cfgs` in both unseeded and seeded modes so every `llvm_ir` shard carries `DISubprogram` source spans, demangled names, CFGs, dominators, and def-use facts.
- **Effort**: `M`
- **Already registered**: none

#### C08-F06 `_run_tool` mounts `target_root` (or `repository_root` fallback) into `tool-native-cpp` despite `/scratch`-only contract
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: `job_cpp_compiled_analysis`
- **Evidence**: `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:113-117`, `src/appsec_review/jobs/cpp_index_scopes.py:225-226`
- **Impact**: `cpp_index_scopes.execute_scope_tool` passes `target_root=None` because C/C++ analyzers must read only hash-pinned `case_root` inputs at `/scratch`. In contrast, `job_cpp_compiled_analysis._run_tool` passes `target_root=unit.job.target_root or unit.job.repository_root`, mounting the raw checkout at `/target` and—if `target_root` is unset—bind-mounting the `appsec-review` repository itself into the tool container.
- **Recommendation**: Pass `target_root=None` in `job_cpp_compiled_analysis._run_tool` so `tool-native-cpp` and `tool-infer` cannot read unpinned paths outside `/scratch`.
- **Effort**: `S`
- **Already registered**: none

#### C08-F07 `job_post_build_security_assessment` matches build actions to produced binaries by basename only while claiming `relationships_exact: True`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: `job_post_build_security_assessment`
- **Evidence**: `src/appsec_review/jobs/job_post_build_security_assessment/job.py:421-436`
- **Impact**: `provenance()` builds `by_output = {PurePosixPath(value).name: action for action in raw_actions for value in action["declared_outputs"]}`. Any multi-directory C/C++ build with colliding object or library basenames (`src/a/util.o` and `src/b/util.o`) silently overwrites earlier actions in `by_output`, misattributing `linked_artifact_ids` and `output_hashes` to the last action while unconditionally stamping `"relationships_exact": True`.
- **Recommendation**: Match artifacts against build-root-normalized relative output paths first and fall back to basename only when unique across the build case; set `relationships_exact=False` whenever basename fallback or ambiguity occurs.
- **Effort**: `S`
- **Already registered**: none

#### C08-F08 Every Go and Rust ELF binary triggers a bogus `COMPLETED_WITH_GAPS` in `job_post_build_security_assessment`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: `job_post_build_security_assessment`
- **Evidence**: `src/appsec_review/jobs/job_post_build_security_assessment/job.py:456-477`
- **Impact**: For `family-*` cases (`source == "language-build"`, covering Go, Rust, and .NET AOT), `inspection()` checks `_case_root(unit, case_id) / "analysis" / "binary" / "records.json"`, which is only produced by `job_cpp_compiled_analysis` for `cpp-*` cases. Whenever `record.get("format") == "ELF"` and `pinned_records` is empty, line 475 appends `"pinned nm/readelf observation was unavailable for this ELF artifact"`, even though `inspect_binary()` already parsed the ELF headers, dynamic tags, notes, and symbol tables directly in Python (`assessment.py:293-436`). Every Go or Rust ELF build therefore degrades `job_post_build_security_assessment` to `COMPLETED_WITH_GAPS`.
- **Recommendation**: Require `analysis/binary/records.json` only when `project.get("source") == "cpp"` (or drop the redundant `nm`/`readelf` check now that `inspect_binary` inspects ELF sections/symbols directly).
- **Effort**: `S`
- **Already registered**: none

#### C08-F09 `cpp_index_scopes.load_accepted_cpp` bypasses `JobContract` validation and reads internal unit state plus `protected` case material
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified`
- **Job**: `job_clang_static_analysis`, `job_svf_alias_analysis`, `job_cpp_compiled_analysis`
- **Evidence**: `src/appsec_review/jobs/cpp_index_scopes.py:54-80`, `src/appsec_review/jobs/job_cpp_compiled_analysis/datasets.py:39-44`, `src/appsec_review/jobs/job_clang_static_analysis/datasets.py:42-92`, `src/appsec_review/jobs/job_svf_alias_analysis/datasets.py:43-93`
- **Impact**: `load_accepted_cpp` calls `accepted_upstream(run_root, "job_cpp_compiled_analysis")` without passing the consumer's `JobContract`, reads `handoff["resolving_paths"]["result"]` -> `result["outputs"]["catalog.projects"]["projects"]` (internal unit-executor state rather than a published dataset artifact), and directly reads `data/cpp/projects/<case_id>`—which `job_cpp_compiled_analysis/datasets.py` declares as `protected("cpp_case_material", ...)`. Simultaneously, `job_clang_static_analysis` and `job_svf_alias_analysis` over-declare 21 `InputRequirement` rows (including `infer_observations`, `binary_symbols`, `declaration_symbols`, `target_documents`) that neither job ever reads.
- **Recommendation**: Publish a dedicated `artifact_only` scope-handoff manifest from `job_cpp_compiled_analysis` for downstream replay consumers, pass `contract=CONTRACT` into `accepted_upstream` across C08 loaders, and prune `CONTRACT.inputs` to datasets actually read.
- **Effort**: `M`
- **Already registered**: none

#### C08-F10 `job_debug_symbol_indexing` `target_decision` dataset schema declaration (`appsec-review/debug-symbol-decision/1`) disagrees with written schema (`appsec-review/debug-symbol-decision/2`)
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: `job_debug_symbol_indexing`
- **Evidence**: `src/appsec_review/jobs/job_debug_symbol_indexing/datasets.py:16-18`, `src/appsec_review/jobs/job_debug_symbol_indexing/job.py:251-278`, `src/appsec_review/jobs/job_debug_symbol_indexing/job.py:282-292`
- **Impact**: `datasets.py` declares `target_decision` with schema `appsec-review/debug-symbol-decision/1`, while `DECISION_SCHEMA` written to `decision.json` and enforced on read is `appsec-review/debug-symbol-decision/2`. Schema-conformance checks between `DATASETS` and published artifacts fail unless special-cased. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Resolved on `main` in `9c41d5e45` (Wave 1a, closing `T-114` by aligning `debug_symbol_indexing` `target_decision` schema version).]*
- **Recommendation**: Update `target_decision` in `job_debug_symbol_indexing/datasets.py` to import and reference `DECISION_SCHEMA` (`appsec-review/debug-symbol-decision/2`).
- **Effort**: `S`
- **Already registered**: T-114

#### C08-F11 Redundant 3-way binary hardening inspection and zero-net-information LLM call in `job_post_build_security_assessment`
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: `job_post_build_security_assessment`, `job_artifact_security_analysis`, `job_cpp_compiled_analysis`
- **Evidence**: `src/appsec_review/jobs/job_post_build_security_assessment/job.py:570-687`, `src/appsec_review/jobs/job_post_build_security_assessment/assessment.py:798-837`, `src/appsec_review/jobs/job_artifact_security_analysis/job.py:32-45`
- **Impact**: Binary hardening (PIE, RELRO, BIND_NOW, NX, CET/PAC, stack canary, FORTIFY, PE DynamicBase/NXCompat/GuardCF/SafeSEH/GS) is inspected three times: `job_cpp_compiled_analysis` (`binary.symbols` `readelf`/`nm`), `job_artifact_security_analysis` (`native` builtin + `blint`), and `job_post_build_security_assessment`. Worse, `job_post_build_security_assessment` runs an LLM call (`inference.native_units`) per build case whose validator (`validate_inference`, `assessment.py:798-837`) rejects any observation without a matching `deterministic_checks` `check_id` and overwrites `validation_status` strictly from `related["status"]` (`FAIL` -> `CONFIRMED`, `PASS` -> `REFUTED`). The LLM cannot surface any new check, adds latency/token cost, and degrades the job to `COMPLETED_WITH_GAPS` whenever model inference is unavailable or unconfigured.
- **Recommendation**: Remove the `inference.native_units` LLM unit from `job_post_build_security_assessment` (making build-flag-vs-binary hardening assessment purely deterministic) and consolidate raw ELF/PE header parsing with `job_artifact_security_analysis`'s builtin `native` inspector.
- **Effort**: `M`
- **Already registered**: none

#### C08-F12 `ScannerAdapter.identity` hardcodes `"undeclared"` across all five container scanners in `job_artifact_security_analysis`
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: `job_artifact_security_analysis`
- **Evidence**: `src/appsec_review/jobs/job_artifact_security_analysis/scanners.py:106-108`, `src/appsec_review/jobs/job_artifact_security_analysis/scanners.py:178`, `src/appsec_review/jobs/job_artifact_security_analysis/job.py:362-365`
- **Impact**: `ScannerAdapter.identity` is a `@property` returning `"undeclared"` for `blint`, `syft`, `grype`, `osv`, and `spotbugs`. Changes to adapter argv construction or output parsing in `scanners.py` do not bump `ADAPTERS[capability].identity`, risking stale checkpoint reuse unless `PARSER_IDENTITY` is manually bumped.
- **Recommendation**: Give each `ScannerAdapter` an explicit versioned adapter string (e.g., `"blint-adapter/2"`, `"osv-adapter/2"`) tied to its flag and parser contract.
- **Effort**: `S`
- **Already registered**: none

#### C08-F13 SVF `accessor_class` recognizes only standard libc/C++ deallocators, missing custom/framework free wrappers in `memory_object` records
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: `job_svf_alias_analysis`
- **Evidence**: `src/appsec_review/jobs/job_svf_alias_analysis/job.py:29`, `src/appsec_review/jobs/job_svf_alias_analysis/job.py:226-231`
- **Impact**: `accessor_class` labels a `call_arg` accessor as `"free"` only when the callee is in `{"free", "cfree", "realloc", "reallocarray"}` or starts with `_ZdlPv`/`_ZdaPv`. Custom C/C++ deallocators (`g_free`, `OPENSSL_free`, `CRYPTO_free`, `sqlite3_free`, `av_free`, `xmlFree`, arena/pool destroys) are labeled `"pass"`, hiding lifecycle deallocation sites from downstream UAF reasoning in `memory_context.py`.
- **Recommendation**: Extend deallocator classification using SVF's `extapi.bc` free-like summaries or a configurable deallocator pattern/table shared with `[banned_functions]` / CPG lifecycle models.
- **Effort**: `S`
- **Already registered**: none

#### C08-F14 `svf_crosscheck.function_tail` strips template arguments and scopes, causing false `AGREE` collisions on overloaded/namespaced indirect targets
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: `job_svf_alias_analysis` (cross-check consumer in `graph/svf_crosscheck.py`)
- **Evidence**: `src/appsec_review/graph/svf_crosscheck.py:42-60`, `src/appsec_review/graph/svf_crosscheck.py:141-155`
- **Impact**: `function_tail` reduces both CodeQL's `callee.display` and SVF's demangled target names to bare unqualified identifiers (`a::Handler::run(int)` and `b::Other::run(char*)` both become `"run"`). If SVF resolves an indirect call only to `b::Other::run`, `_call_verdict` still emits `CrossCheckState.AGREE` for CodeQL's edge to `a::Handler::run`.
- **Recommendation**: Compare qualified namespace/class + function name (falling back to bare tail only for `extern "C"` / C symbols without `::`), and record `PARTIAL` rather than `AGREE` when only the unqualified tail matches across distinct scopes.
- **Effort**: `S`
- **Already registered**: none

#### C08-F15 All seven C08 jobs remain on `LEGACY_FREE_TEXT_GAPS` with `strict_gaps=False`
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified`
- **Job**: `job_cpp_compiled_analysis`, `job_clang_static_analysis`, `job_svf_alias_analysis`, `job_artifact_security_analysis`, `job_post_build_security_assessment`, `job_debug_symbol_indexing`, `job_binary_evidence_indexing`
- **Evidence**: `tests/test_gap_contract.py:11-29`
- **Impact**: Every job in C08 emits ad-hoc `list[str]` gaps (`f"{artifact_id}: {gap}"`, `"tool-svf timed out"`, `"native_binary_unavailable"`) rather than validated `producer-gap/1` records, forcing downstream coverage aggregation to parse or display unstructured strings without machine-readable reason codes, scope paths, or retryability classifications.
- **Recommendation**: Migrate the C08 jobs onto `interchange.producer_gap` (`producer-gap/1`) with `strict_gaps=True`, prioritizing `job_debug_symbol_indexing` and `job_binary_evidence_indexing` whose internal gap codes are already closed vocabularies.
- **Effort**: `M`
- **Already registered**: none

#### C08-F16 Unseeded `native.py` `ast_filter` regex skips global/free C++ template and macro-declared functions when dumping Clang AST JSON
- **Kind**: `weakness`
- **Severity**: `low`
- **Confidence**: `verified`
- **Job**: `job_cpp_compiled_analysis`
- **Evidence**: `containers/tools/native-cpp/native.py:19-22`, `containers/tools/native-cpp/native.py:102-128`
- **Impact**: In unseeded mode (`filters` empty), `native.py` passes `-Xclang -ast-dump-filter -Xclang <filter>` using `ast_filter(source)`. If a C/C++ file defines at least one namespace, `ast_filter` filters solely by namespace names and drops all top-level `extern "C"` or global functions in the same TU; if there are no namespaces and multiple functions without a >=3-char common prefix (e.g., `parse_header` and ` decode_body`), `ast_filter` picks only `functions[0]` (`decode_body`) and silently omits every other function in the file from the Clang AST dump!
- **Recommendation**: Pass one `-ast-dump-filter` invocation per discovered function/namespace (bounded, just like seeded `filters`), or filter by source file path inside a lightweight AST consumer instead of `-ast-dump-filter` substring matching.
- **Effort**: `S`
- **Already registered**: none
### C09 Scanners, rule packs, dependencies and advisory feeds

**Active findings:** 18 (`2` critical, `10` high, `6` medium, `0` low) plus 1 withdrawn on spot-check (`C09-F06`).

C09's artifact-custody spine—hash-verified feed snapshots (`publication.py`), provenance-pinned feed receipts (`feed_provenance.py`), and native-report selectors on scanner observations—is well engineered and preserves traceable evidence when scanners fire cleanly. However, deterministic static coverage is undermined by false-clean dispositions and rule-pack defects: Rust and Ruby pass SAST with zero rules and no gap, scanners honor target-controlled inline suppressions, `[banned_functions]` floods C/C++ scans into a 5,000-record arrival-order truncation cap across both Semgrep and OpenGrep, and `security.yml` plus `generic-secrets.toml` ship tiny custom rule sets while leaving 117 CERT C++ CodeQL queries and ~180 built-in Gitleaks rules inactive. In `job_dependency_intelligence`, per-link-command `@command/*` localities multiply `-l<lib>` flags into duplicate native candidates and uncapped `gpt-5.4` calls, path substrings and unmerged Syft/manifest keys corrupt `maximal_exposure` to `PROD`, and `enriched.spdx.json` (including all Unity packages) is never read by any downstream scanner or job. Offline OSV inventory matching remains disabled by default, supports only 4 of 8 synced ecosystems when enabled, and falls back to unversioned bare-name SQL queries across unrelated language ecosystems for un-PURLed native and manifest dependencies. Finally, `job_third_party_data_sync` follows unvalidated HTTP redirects on unpinned feeds, never prunes snapshots, and runs an unverified live `docker build` + `pip install` for a ~530 MB `cve-bin-tool` database that has zero consumers.

**Strengths to preserve:**
- Atomic, content-addressed feed snapshot publication and fail-closed `verify_current` validation of pointer, manifest SHA-256, and every file's size and digest (`src/appsec_review/jobs/job_third_party_data_sync/publication.py:216-392`).
- Run-owned external feed provenance (`require_verified_feed`) recording <!-- historical:begin -->`external-feed-snapshot-proof/1`<!-- historical:end --> receipts, freshness bounds, and producing-run lineage (`src/appsec_review/storage/feed_provenance.py:134-187`).
- Mandatory native-report byte retention (`NativeResultReference` plus JSON-pointer/XML selectors) ensuring no scanner observation is published without a resolving run-owned artifact (`src/appsec_review/jobs/job_evidence_collection/job.py:772-789`, `src/appsec_review/jobs/job_evidence_collection/evidence.py:159-189`).
- Structured scanner disposition accounting (`SUCCEEDED`, `PARTIAL`, `BLOCKED`, `SKIPPED_NA`, `FAILED`) with `producer-gap/1` records and `unsupported_source_coverage` checks (`src/appsec_review/jobs/job_evidence_collection/job.py:1013-1127,1214-1248`).
- SEI CERT rule-pack schema validator and positive/negative fixture evaluation harness across both Semgrep and OpenGrep (`src/appsec_review/rulepacks/sei_cert/validate.py:67-214`, `src/appsec_review/rulepacks/sei_cert/evaluate.py:45-169`).
- Offline OSV container mounting (`--experimental-offline --experimental-no-resolve`) paired with per-lockfile ecosystem completeness checks (`src/appsec_review/osv_offline.py:15-67`, `src/appsec_review/tool_inputs.py:137-206`).
- Pure-Python SemVer 2.0.0 range evaluator (`osv_matching.py`) that drops proven `not_affected`/`withdrawn` advisories while keeping unparseable ranges as named `undecided` gaps (`src/appsec_review/osv_matching.py:62-214`).
- Hard separation keeping OpenSSF Scorecard data `context_only = True` / `security_finding = False` behind `_NoRedirect` HTTPS transport, and marking LLM-inferred repositories `exact_repository_identity = False` (`src/appsec_review/jobs/job_dependency_intelligence/scorecard.py:34-40,115-164`, `src/appsec_review/jobs/job_dependency_intelligence/resolution.py:293-336`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_evidence_collection` | `job_target_catalog`, `job_target_analysis_plan`, `job_artifact_indexing` (dropped when `enable_swift=False`), `job_third_party_data_sync` (`osv`, optional `grype`) | Per-tool normalized static/secret/IaC/SBOM/advisory envelopes, retained raw reports, `syft` SPDX SBOM, `tool_*` SQLite shards | `C09-F01` / `C09-F02` (silent per-tool suppression/truncation and dropped `artifact_indexing` input when `enable_swift=False`) | rework |
| `job_dependency_intelligence` | `job_target_catalog`, `job_evidence_collection` (`tool-syft` SPDX SBOM), `job_artifact_indexing`, target native/Unity metadata, cached/live OpenSSF Scorecard API | `dependency_context` SQLite shard (consumed by `job_review_data_indexing`); `enriched.spdx.json` and `native-sbom-provenance.json` (unconsumed) | `C09-F10` (two flagship SPDX enrichment outputs have zero downstream consumers; transitive reachability absent) | rework |
| `job_third_party_data_sync` | External HTTPS feeds (NVD, OSV, Grype, MITRE, CISA KEV, FIRST EPSS) and local `nvd_sync` snapshot | Hash-verified snapshots under `data/feeds/{nvd,osv,grype,mitre,kev,epss,cve-bin-tool}/` (`cve-bin-tool` unconsumed) | `C09-F12` (`cve_bin_tool_db_build` builds an unconsumed DB while feed staleness/offline semantics degrade silently) | rework |

#### C09-F01 Rust and Ruby source files pass SAST with zero rules and no coverage gap
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_evidence_collection`
- **Evidence**: `src/appsec_review/tool_inputs.py:34-36`; `src/appsec_review/jobs/job_evidence_collection/adapters.py:418-423,471-476`; `src/appsec_review/jobs/job_evidence_collection/job.py:1214-1228`. `SOURCE_SUFFIXES` assigns `.rs` and `.rb` to `tool-semgrep`, preventing `unsupported_source_coverage` from emitting a gap, while zero rules in `rules/semgrep/*.yml` or `rules/sei-cert/rules/` target `rust` or `ruby` and `semgrep_skip_not_applicable` classifies `"no rules for language"` skips as `SKIPPED_NA` (`not_applicable_inputs`) instead of `gaps`.
- **Impact**: Rust and Ruby repositories complete `job_evidence_collection` with `terminal_status = "SUCCEEDED"`, zero SAST rules executed, and zero coverage gap recorded—violating the core invariant that unanalyzed code is a named gap, never clean.
- **Recommendation**: Remove `.rs` and `.rb` from `tool-semgrep` in `src/appsec_review/tool_inputs.py` (or classify zero-rule language skips as `producer-gap/1` in `src/appsec_review/jobs/job_evidence_collection/adapters.py`) until concrete Rust and Ruby rules are added to `rules/semgrep/security.yml` and `rules/semgrep/review-signals.yml`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-142` was marked `done` (2026-11-12) after adding a smoke-doc note, leaving this false-clean runtime defect unfixed.

#### C09-F02 Target-controlled inline suppressions silently hide scanner findings
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_evidence_collection`
- **Evidence**: `src/appsec_review/jobs/job_evidence_collection/adapters.py:249,298,792-806`. `_cppcheck_args` explicitly passes `--inline-suppr`; `tool-semgrep` and `tool-opengrep` omit `--disable-nosem`; `tool-gosec` omits `-nosec`; and `tool-gitleaks` scans `/target` without disabling target-owned `.gitleaksignore` or inline `gitleaks:allow` directives.
- **Impact**: Untrusted target comments and ignore files (`# nosemgrep`, `// cppcheck-suppress`, `// #nosec`, `gitleaks:allow`, `.gitleaksignore`) act as instructions that suppress real vulnerabilities and secrets inside scanner containers before JSON/XML output is written, leaving no observation, correlation candidate, or gap receipt.
- **Recommendation**: Remove `--inline-suppr` from `_cppcheck_args`, add `--disable-nosem` to `tool-semgrep` and `tool-opengrep`, add `-nosec` to `_gosec_args`, and pass `--gitleaks-ignore-path` pointing to an empty run-owned file (plus strip/forbid `gitleaks:allow` or audit ignored items) in `src/appsec_review/jobs/job_evidence_collection/adapters.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C09-F03 Ubiquitous `[banned_functions]` calls overflow arrival-order truncation caps and duplicate Semgrep/OpenGrep work
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_evidence_collection`
- **Evidence**: `appsec-review.toml:3689-3724`; `src/appsec_review/jobs/job_evidence_collection/evidence.py:22,55,100-156`; `src/appsec_review/jobs/job_evidence_collection/job.py:260-262`; `src/appsec_review/jobs/job_evidence_collection/adapters.py:798-806`. `[banned_functions]` puts `strlen` in `warning` (`MEDIUM`) and `malloc`, `calloc`, `realloc`, `free`, `memcpy`, `memmove`, `memset`, `memcmp`, `strcmp`, `strncmp`, `printf`, `fprintf`, `snprintf`, `atoi`, and `getenv` in `review` (`INFO`); `normalize_observations` truncates at `max_records = 5_000` in arrival order without severity ranking; and both `tool-semgrep` and `tool-opengrep` run `SEI_CERT_MOUNT`, `review-signals.yml`, and `banned-functions.yml`.
- **Impact**: Any nontrivial C/C++ target easily exceeds 5,000 routine `free`/`memcpy`/`strlen`/`printf` matches, silently truncating later `HIGH`/`ERROR` security and SEI CERT findings while burning two full container scans to emit 100% duplicate observations across Semgrep and OpenGrep.
- **Recommendation**: Remove standard memory/string/formatting primitives (`malloc`/`free`/`memcpy`/`memset`/`memcmp`/`strlen`/`strcmp`/`snprintf`/`printf`) from `[banned_functions]` in `appsec-review.toml` (regenerating `rules/semgrep/banned-functions.yml`), sort by severity before capping in `src/appsec_review/jobs/job_evidence_collection/evidence.py`, and restrict `tool-opengrep` in `job.py`/`adapters.py` to rules not already executed by `tool-semgrep` (or remove redundant OpenGrep execution).
- **Effort**: `S (under a day)`
- **Already registered**: `T-011` covers banned-function parity across languages; the `max_records = 5_000` severity-blind truncation drop and Semgrep/OpenGrep duplication are new and high-urgency.

#### C09-F04 Cppcheck compile-database sanitizer strips all build flags, forces C++ mode on C files, and suppresses the missing-context gap
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_evidence_collection`
- **Evidence**: `src/appsec_review/jobs/job_evidence_collection/job.py:283-312,466-468`; `src/appsec_review/jobs/job_evidence_collection/adapters.py:233-252`. `_sanitize_compile_database` rewrites every entry in `compile_commands.json` to `arguments: ["c++", f"/target/{relative}"]`, discarding all `-I`, `-D`, and `-std` flags and forcing C++ parsing on `.c` files, while `_cppcheck` reports `coverage_kind = "cpp_compile_database"` and omits the missing-build-context gap emitted in source mode.
- **Impact**: Conditional `#ifdef` branches, header macros, and C-specific semantics are misparsed or skipped without recording the missing-flags gap, and headers/sources absent from `compile_commands.json` go unscanned while `coverage_scope` claims all cataloged C/C++ `selection.files`.
- **Recommendation**: Preserve safe, path-validated `-I` (under `/target`), `-D`, `-U`, and `-std=` arguments with C vs C++ driver selection in `src/appsec_review/jobs/job_evidence_collection/job.py`, record a `producer-gap/1` for any stripped flags or cataloged C/C++ files absent from `compile_commands.json`, and scope `coverage_scope` to actually analyzed translation units.
- **Effort**: `M (days)`
- **Already registered**: no

#### C09-F05 Rule-pack lock verification was removed while docs, dead helpers, and checkpoint rules assume hash gating
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_evidence_collection`
- **Evidence**: `src/appsec_review/jobs/job_evidence_collection/job.py:42,239-250,259-280,396-397,417-420,967-971`; `appsec-review.toml:91-95`; `docs/operations/static-analysis.md:33`; `docs/architecture/sei-cert-rule-pack.md:26,154-157`; `rules/semgrep/README.md:20-21`; `rules/gitleaks/README.md:14-15`. Marking every rule mount `supplied_platform=True` excluded rule packs from `_extra_identity(mounts)` and left `verify_pack` (`job.py:42`) and `_banned_function_drift` (`job.py:239-250`) uncalled; meanwhile `[review_policy.releases]` is empty by default so every tool checkpoint misses on recovery, whereas overlays setting `rules_tool-*` silently reuse stale checkpoints when rule files change.
- **Impact**: Drifted or modified rule packs (`rules/sei-cert`, `rules/semgrep`, `rules/gitleaks`, `rules/pmd`, `banned-functions.yml`) run unverified, recovery runs re-execute every scanner container by default, overlays risk silent stale-checkpoint reuse because six docs/READMEs falsely state lock files gate execution and checkpoints, and `rules/sei-cert` is omitted from `rules/registry.toml:3-46`.
- **Recommendation**: Call `verify_pack`, `_banned_function_drift`, and a unified lock verifier (`rules/registry.toml`) inside `_prerequisites` in `src/appsec_review/jobs/job_evidence_collection/job.py`, fold verified lock digests into `_rule_pack_identity` so checkpoints stay sound without manual release bumps, delete dead symbols if unused, and reconcile the six docs/READMEs.
- **Effort**: `M (days)`
- **Already registered**: `T-012` registers unifying lock file formats; the complete removal of runtime lock verification, dead `_banned_function_drift`/`verify_pack` code, default checkpoint misses, and contradicting docs are new.

#### C09-F06 [Withdrawn on spot-check] Custom `--config` on Gitleaks disables ~180 built-in secret detectors
- **Kind**: `doc-drift`
- **Severity**: `withdrawn` (excluded from active severity counts)
- **Confidence**: `high`
- **Job**: `job_evidence_collection`
- **Evidence**: Withdrawn during Section 7 spot-check against `f29ee4c688bce7d0d7ca2f1b30a9477a63647ad1`: `rules/gitleaks/generic-secrets.toml:13-14` explicitly sets `[extend]` with `useDefault = true`, so upstream Gitleaks default rules are preserved alongside the repository's custom generic rules. Retained as a placeholder ID so `C09-F07`–`C09-F19` numbering remains stable; excluded from severity totals.
- **Impact**: None; upstream Gitleaks default rules remain active.
- **Recommendation**: None required; keep `[extend] useDefault = true` covered by unit tests.
- **Effort**: `S`
- **Already registered**: none

#### C09-F07 Semgrep `security.yml` has only 3 rules while 117 CERT C++ CodeQL queries and 20 Lua rules are unwired
- **Kind**: `missing`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `rules/semgrep/security.yml:1-20`; `rules/cpp-cert/bundle-lock.json:1-25`; `rules/sei-cert/COVERAGE.md:107`; `rules/lua-game-security/game-security.yml:1-35`; `src/appsec_review/tool_inputs.py:13-37`. `rules/semgrep/security.yml` contains only 3 rules total (Python `eval`, JS/TS `eval`, Bash `${$X}`), leaving SQLi, XSS, SSRF, XXE, path traversal, and deserialization without concrete Semgrep vulnerability rules (`review-signals.yml` emits `INFO` sink leads only and has zero C# XXE/deserialization patterns); meanwhile `rules/cpp-cert/codeql/cert/` (117 queries relied on by `COVERAGE.md:107` for 64 `REQUIRES_CODEQL` rules) and `rules/lua-game-security/` (20 tested Lua rules; `.lua` absent from `SOURCE_SUFFIXES`) have zero runtime callers.
- **Impact**: Non-CodeQL languages and source-only runs lack concrete SAST detections beyond `INFO` sink leads, 64 CERT C++ rules marked covered via CodeQL never execute, and Lua game scripts are reported as unsupported source gaps despite an in-tree tested rule pack.
- **Recommendation**: Wire `rules/lua-game-security/game-security.yml` into `tool-semgrep` (`job_evidence_collection/job.py`, `adapters.py`, `tool_inputs.py`, `rules/registry.toml`), coordinate with C07 to execute or retire `rules/cpp-cert/codeql/cert/`, and expand `rules/semgrep/security.yml` with high-precision taint/sink rules for web/API languages.
- **Effort**: `L (weeks)`
- **Already registered**: `T-008`..`T-011` and `appsec-system-review-2026-11-06.md` noted small Semgrep/CERT packs; the 117 unwired `rules/cpp-cert` CodeQL queries claimed by `COVERAGE.md` and the unwired 20-rule Lua pack are new.

#### C09-F08 Offline OSV inventory matching defaults to disabled, covers 4 of 8 ecosystems, and cross-matches un-PURLed packages by bare name
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `appsec-review.toml:343-344,2505`; `src/appsec_review/osv_matching.py:54`; `src/appsec_review/indexing/products.py:305-316,356-383`. `jobs.job_review_data_indexing.settings.osv_version_matching` defaults to `"disabled"` even though `osv_matching.py` is merged on `main`; `osv_matching.py:54` (`_ECOSYSTEMS`) supports only `npm`, `crates.io`, `Go`, and `NuGet` (excluding synced `PyPI`, `Maven`, `Packagist`, and `RubyGems`); and any dependency entity without a mapped PURL (`declared` manifest rows, `pkg:conan/*`, `pkg:generic/*`, and native C/C++ libraries) falls back to `ecosystem = None` (`"name-only"`), querying `WHERE p.name=? COLLATE NOCASE` across all 8 language ecosystems without version matching.
- **Impact**: Default runs emit false-positive advisory leads for every historical OSV vulnerability ever published for a package name; even with `osv_version_matching = "enabled"`, Python/Java/PHP/Ruby advisories remain undecided, and native C/C++ libraries (`curl`, `zlib`, `ssl`, `fmt`, `m`, `c`) match unrelated npm/PyPI/RubyGems/crates.io packages of the same name while exhausting `max_pairs`.
- **Recommendation**: Implement PEP 440 (`PyPI`), Maven, Composer (`Packagist`), and Gem (`RubyGems`) comparators in `src/appsec_review/osv_matching.py` (or `packaging.version` for PyPI), forbid cross-ecosystem `name-only` SQL matches for native/known-domain dependencies in `src/appsec_review/indexing/products.py`, and enable `osv_version_matching` in `appsec-review.toml`.
- **Effort**: `M (days)`
- **Already registered**: `T-013` tracks enabling `osv_version_matching`, but its Scope text is stale (`osv_matching.py` is already on `main`), and both the 4-missing-ecosystems gap and the cross-ecosystem `name-only` native/manifest collision are new.

#### C09-F09 `enriched.spdx.json` and Unity package intelligence are write-only dead ends never scanned or indexed
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_dependency_intelligence`
- **Evidence**: `src/appsec_review/jobs/job_dependency_intelligence/job.py:372-415`; `src/appsec_review/jobs/job_dependency_intelligence/integration.py:130-217`; `src/appsec_review/jobs/job_dependency_intelligence/unity.py:41-215`; `src/appsec_review/jobs/job_evidence_collection/job.py:322-357`. `publication.publish_sbom` writes `enriched.spdx.json` (`sbom_enriched`) and `native-sbom-provenance.json` containing curated native C/C++ libraries and Unity `packages-lock.json`/`manifest.json` packages, and six downstream `datasets.py` files declare `native_sbom_provenance`, yet zero runtime modules outside `job_dependency_intelligence` read either file and `publish_context` omits Unity packages from `dependency_context`.
- **Impact**: Unity UPM/Git/registry dependencies receive zero OSV, Grype, Scorecard, or review-index coverage, and curated native C/C++ packages added to `enriched.spdx.json` are never scanned by `tool-grype` (which runs earlier in `job_evidence_collection` on `tool-syft`'s baseline SBOM and is disabled by default).
- **Recommendation**: Emit Unity dependencies into `dependency_context` (`EntityKind.DEPENDENCY_PACKAGE` with `pkg:npm` or Unity/Git identity) in `src/appsec_review/jobs/job_dependency_intelligence/job.py`, and either scan `enriched.spdx.json` in a post-enrichment vulnerability step or remove dead `native_sbom_provenance` `InputRequirement` declarations from the six non-reading downstream jobs.
- **Effort**: `M (days)`
- **Already registered**: no

#### C09-F10 Per-link-command `@command/<hash>` locality multiplies `-l<lib>` flags into duplicate native candidates and uncapped `gpt-5.4` calls
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_dependency_intelligence`
- **Evidence**: `src/appsec_review/jobs/job_dependency_intelligence/discovery.py:319,400`; `src/appsec_review/jobs/job_dependency_intelligence/curation.py:227-229,296-304`; `src/appsec_review/jobs/job_dependency_intelligence/resolution.py:204,218-219`; `src/appsec_review/jobs/job_dependency_intelligence/job.py:303-312`; `src/appsec_review/jobs/job_dependency_intelligence/inference.py:26-88`; `src/appsec_review/jobs/job_dependency_intelligence/investigation.py:803-828`. `discovery.py` hashes each command's `evidence_source` (including `/commands/<index>`) into `package_root = "@command/<sha256>"`, creating `K` separate localities across `K` link commands for every `-lz`/`-lssl`/`-lpthread`/`-lm`; `infer_repositories` then runs a fresh LLM `Execution` per unresolved normalized entry (up to `dependency_limit = 500`) with no job-wide call cap, no deduplication by `native_name`, and no retained model receipts, while `investigate_native_metadata` unconditionally fires 2 sequential `gpt-5.4` calls per physical native root even when deterministic `discovery.py` already corroborated `identity`, `release`, and `upstream`.
- **Impact**: Native C/C++ builds with dozens of link targets emit hundreds of duplicate SPDX/index entities and trigger hundreds of redundant `gpt-5.4` calls (stalling runs for tens of minutes and inflating model spend without improving repository or version accuracy).
- **Recommendation**: Key command-only link flags by `(root_id, "@link-flag/" + canonical_lib_name)` in `src/appsec_review/jobs/job_dependency_intelligence/discovery.py`, filter POSIX/toolchain runtime libraries (`c`, `m`, `dl`, `pthread`, `rt`, `gcc_s`, `stdc++`) deterministically before LLM calls, skip `investigate_native_metadata` when `discovery.py` already resolved `identity` + `release` + `upstream`, and wrap `infer_repositories` in a shared bounded `Execution` deduplicated by `(root_id, native_name)`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C09-F11 Path-substring `PROD` matching and split manifest/Syft keys corrupt `maximal_exposure`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_dependency_intelligence`
- **Evidence**: `src/appsec_review/jobs/job_dependency_intelligence/resolution.py:19-40,174-185,202,216-226,258`. `infer_maximal_exposure` matches `"path"` and `"location"` substrings against `_EXPOSURE_TERMS["PROD"]` (`"release"`, `"implementation"`, `"dependency"`, `"dependencies"`) and selects `max(...)`, while `normalize_dependencies` keys manifest declarations without `purl` as `"name:<name>@<constraint>"` and `tool-syft` entries as `"purl:pkg:..."`.
- **Impact**: Any dev/test dependency stored under paths containing `dependency`, `dependencies`, `release`, or `implementation` is misclassified as `PROD`, and manifest scopes (`devDependencies`, `testImplementation`) never merge onto PURL-backed Syft lockfile entries (which default to `PROD`), emitting duplicate entities and defeating `DEP-A` non-prod triage suppression.
- **Recommendation**: Remove `"path"` from `_EXPOSURE_FIELDS` (and remove generic nouns `"dependency"`/`"dependencies"` from `_EXPOSURE_TERMS["PROD"]`) in `src/appsec_review/jobs/job_dependency_intelligence/resolution.py`, and join `declared` manifest observations onto `sbom` entries by `(ecosystem, normalized_name)` within the same component root while keeping `entry["version"]` pinned to the resolved lockfile version rather than the manifest constraint.
- **Effort**: `M (days)`
- **Already registered**: `T-149` / `2026-11-13-dependency-intelligence-review.md` D6 covers Syft lockfile scope propagation; the `_EXPOSURE_TERMS["PROD"]` path-substring bug and duplicate unmerged manifest/Syft entities are new.

#### C09-F12 Feed HTTP clients follow unvalidated redirects across hosts/schemes, leave 3 feeds unpinned, and never prune snapshots
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_third_party_data_sync`
- **Evidence**: `src/appsec_review/jobs/job_third_party_data_sync/publication.py:33-54,216-308`; `src/appsec_review/jobs/job_third_party_data_sync/steps/nvd_sync/feed.py:124,165`; `appsec-review.toml:416-419,446-475`. `HttpDownloader` checks `scheme == "https"` and `hostname in allowed_hosts` only on the initial URL while `urllib.request.urlopen` follows 30x redirects (`allow_redirects = True` for `osv_sync`, `mitre_sync`, `kev_sync`, `epss_sync`), `HttpNvdClient` enforces no `allowed_hosts` check at all while following redirects, `mitre_sync.sources.cwe`, `kev_sync`, and `epss_sync` carry no content pin, and neither `publish_snapshot` nor `NvdPublisher` prunes superseded snapshots.
- **Impact**: Any 30x redirect from an allowed feed endpoint bypasses `allowed_hosts` and HTTPS enforcement (allowing unpinned CWE/KEV/EPSS/NVD poisoning or SSRF during sync), while `data/feeds/` accumulates multi-gigabyte snapshots unboundedly (already 29 snapshot directories / 623 files on disk).
- **Recommendation**: Install a custom `HTTPRedirectHandler` in `publication.py:HttpDownloader` and `steps/nvd_sync/feed.py:HttpNvdClient` that re-validates `https` and `allowed_hosts` on every hop (matching `scorecard.py:_NoRedirect`), add `allowed_hosts` to `NvdSettings`, and add bounded snapshot retention keeping `current.json` plus snapshots referenced by active runs.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C09-F13 `cve_bin_tool_db_build` runs live `docker build` + unpinned `pip install`, skips image verification, embeds `time.time()`, and has zero consumers
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_third_party_data_sync`
- **Evidence**: `src/appsec_review/jobs/job_third_party_data_sync/steps/cve_bin_tool_db_build/database.py:114-131`; `tools/cve-bin-tool/Dockerfile:1-10`; `tools/cve-bin-tool/build_db.py:51`; `appsec-review.toml:436-443`. With `image_id` unset, `DockerBuildRunner` executes `docker build` at runtime running `pip install --no-cache-dir "cve-bin-tool==3.4"` from live PyPI without `--require-hashes`, skips `_verify_pinned_image` whenever `built_here` is `True` (`database.py:130-131`), writes wall-clock `time.time()` into `version_map.db` (`build_db.py:51`), and publishes a ~530 MB SQLite copy per NVD update that no job reads.
- **Impact**: Every scheduled sync risks non-reproducible or supply-chain-tampered Python wheel installation inside a job run, produces a non-deterministic SQLite digest for identical NVD snapshots, and wastes ~530 MB per NVD snapshot for an unconsumed feed.
- **Recommendation**: Disable or remove `cve_bin_tool_db_build` from `job_third_party_data_sync` until `T-102` has an active consumer; when retained, move the image into `containers/tools/` with hash-locked wheels (`T-106`), never bypass `_verify_pinned_image`, and replace `time.time()` in `tools/cve-bin-tool/build_db.py:51` with the NVD snapshot timestamp.
- **Effort**: `M (days)`
- **Already registered**: `T-106` and `T-102` register prebuilt image onboarding and binary CVE consumption; skipping `_verify_pinned_image` when `built_here=True`, wall-clock non-determinism in `build_db.py:51`, and wasted ~530 MB per sync are new.

#### C09-F14 Inline `_RULES` prompt in `curation.py` bypasses registered hash-pinned guidance bundles
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_dependency_intelligence`
- **Evidence**: `src/appsec_review/jobs/job_dependency_intelligence/curation.py:29-39,258-261`. `curate_native_inventory` hardcodes a 13-sentence model instruction string `_RULES` in Python source and places it inside user-message `payload["rules"]` alongside target-controlled path/symbol strings, even though `publish_native_guidance` (`native_inference_runtime.py:72-93`) already loads a registered procedure bundle.
- **Impact**: Prompt instructions live in Python code outside `pipeline/guidance/registry.json` and `runs/<run-id>/data/guidance/<bundle-sha256>/`, weakening prompt-provenance auditing and blurring the boundary between governing instructions and untrusted target data in the user turn.
- **Recommendation**: Move `_RULES` out of `src/appsec_review/jobs/job_dependency_intelligence/curation.py` into the registered `native_dependency_curation` runtime skill/task prompt under `pipeline/` and keep `payload` strictly data-only.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C09-F15 `job_dependency_intelligence` serializes behind `job_cpp_compiled_analysis` despite reading zero datasets from it
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_dependency_intelligence`
- **Evidence**: `src/appsec_review/jobs/job_dependency_intelligence/datasets.py:57-88`; `src/appsec_review/jobs/job_dependency_intelligence/integration.py:52-77`. `CONTRACT` declares 9 `InputRequirement` entries from `job_cpp_compiled_analysis` and sets `schedule_after=('job_cpp_compiled_analysis', 'job_evidence_collection', 'job_artifact_indexing', 'job_target_catalog')`, whereas `collect_inputs` calls `accepted_upstream` only on `job_target_catalog`, `job_evidence_collection`, and `job_artifact_indexing` (`job_evidence_collection/datasets.py:45-77` similarly declares 9 unread upstream datasets).
- **Impact**: Every run blocks `job_dependency_intelligence` (and downstream `job_review_data_indexing`) behind heavyweight C++ compilation, LLVM IR, SVF, and Ghidra analysis for an upstream producer it never reads, slowing end-to-end review turnaround and overstating upstream consumption in contracts.
- **Recommendation**: Remove the 9 `job_cpp_compiled_analysis` `InputRequirement` rows and `'job_cpp_compiled_analysis'` from `schedule_after` in `src/appsec_review/jobs/job_dependency_intelligence/datasets.py`, and prune the 9 unread `InputRequirement` rows in `src/appsec_review/jobs/job_evidence_collection/datasets.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C09-F16 `job_evidence_collection` drops `target_artifacts` when constructing `ScanCatalog` in the default (`enable_swift=False`) path
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_evidence_collection`
- **Evidence**: `src/appsec_review/jobs/job_evidence_collection/job.py:107-125,196-206,1304-1308`. `load_target_catalog` populates `target_artifacts`, `target_artifact_inventory_available`, and `target_artifact_gaps` from `job_artifact_indexing`, but when `unit.job.tools.enable_swift` is `False` (default), `handler` rebuilds `ScanCatalog(...)` with only the first 10 positional arguments, silently resetting `target_artifacts=()`, `target_artifact_inventory_available=False`, and `target_artifact_gaps=()`.
- **Impact**: Any scanner applicability check or gap accounting inspecting `catalog.target_artifacts` or `catalog.target_artifact_gaps` sees an empty artifact inventory on every default run.
- **Recommendation**: Use `dataclasses.replace(catalog, files=..., components=..., build_files=...)` at `src/appsec_review/jobs/job_evidence_collection/job.py:1304-1308` instead of positional `ScanCatalog(...)` reconstruction.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C09-F17 PMD `RuntimeCommandExecution` fires at `HIGH` on every `.exec()` method call in Java while missing `ProcessBuilder` and `TLSv1.1`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_evidence_collection`
- **Evidence**: `rules/pmd/java-security.xml:19-46`; `src/appsec_review/jobs/job_evidence_collection/adapters.py:345-351`. `RuntimeCommandExecution` uses the untyped XPath `//MethodCall[@MethodName = 'exec']` at priority 2 (`HIGH`), and `LegacyTlsProtocol` matches `'SSL' | 'SSLv3' | 'TLSv1'` without `'TLSv1.1'`.
- **Impact**: Every Java method named `exec` on non-process objects (query DSLs, command runners, Netty/Redis/Docker clients) generates a false-positive `HIGH` command-injection observation, while `new ProcessBuilder(...)` command execution and `SSLContext.getInstance("TLSv1.1")` go undetected.
- **Recommendation**: Constrain `RuntimeCommandExecution` in `rules/pmd/java-security.xml` with PMD `pmd-java:typeIs('java.lang.Runtime')` plus `//ConstructorCall[pmd-java:typeIs('java.lang.ProcessBuilder')]`, add `'TLSv1.1'` to `LegacyTlsProtocol`, and update `rules/pmd/rules.lock.json`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C09-F18 Partitioned `osv-scanner` runs drop up to 7 sibling lockfiles on a single parse error and mount all 8 ecosystem zips per slice
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_evidence_collection`
- **Evidence**: `src/appsec_review/jobs/job_evidence_collection/job.py:495-531,722-748`; `src/appsec_review/osv_offline.py:15-50`; `appsec-review.toml:2515-2516`. `_plan_invocations` batches up to `osv_max_lockfiles_per_invocation = 8` lockfiles per `osv-scanner` container and mounts all 8 ecosystem `all.zip` archives (`~241 MB` compressed, requiring `osv_memory = "6g"`) into every invocation regardless of which ecosystems those lockfiles use.
- **Impact**: One malformed or unsupported lockfile in an 8-file batch fails the entire container invocation and discards vulnerability findings for the other 7 valid lockfiles in that batch, while multi-project monorepos repeatedly unpack all 8 OSV zip archives in every container.
- **Recommendation**: Mount only the ecosystem `all.zip` files required by `invocation.selection.files` in `src/appsec_review/osv_offline.py` and retry failed multi-lockfile `osv-scanner` batches per-lockfile in `src/appsec_review/jobs/job_evidence_collection/job.py` so one bad lockfile only gaps itself.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C09-F19 Custom Semgrep, PMD, and Gitleaks rule packs lack positive/negative fixture tests, and sync/dependency tests miss redirect and merge paths
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `rules/semgrep/README.md:1-22`; `rules/pmd/README.md:1-19`; `rules/gitleaks/README.md:1-16`; `tests/test_dependency_intelligence.py:25-54`; `tests/unit/job_third_party_data_sync/test_publication.py:1-125`. Unlike `rules/sei-cert/`, none of `rules/semgrep/`, `rules/pmd/`, or `rules/gitleaks/` has positive/negative rule fixtures; `tests/test_dependency_intelligence.py:25-54` exercises dead `native.py:parse_native_candidates` rather than multi-command `discovery.py` `@command/*` deduplication or manifest-plus-Syft PURL merging; and `job_third_party_data_sync` unit tests mock `HttpDownloader` without exercising 30x cross-host/downgrade redirects.
- **Impact**: Broken or severely incomplete rules (C09-F01, C09-F06, C09-F17), `@command/*` native fan-out (C09-F10), exposure/merge bugs (C09-F11), and redirect bypasses (C09-F12) pass CI undetected.
- **Recommendation**: Add positive/negative fixture suites for `rules/semgrep/`, `rules/pmd/`, and `rules/gitleaks/`, replace `parse_native_candidates` tests in `tests/test_dependency_intelligence.py` with multi-command `discovery.py` and manifest+Syft merge regressions, and add local redirect-hop unit tests for `HttpDownloader` and `HttpNvdClient`.
- **Effort**: `M (days)`
- **Already registered**: no
### C10 Context signals

**Active findings:** 9 (`0` critical, `3` high, `4` medium, `2` low).

C10 covers the six context, CI-configuration, engineering-signal, and document-candidate jobs (`job_source_history_analysis`, `job_change_context_analysis`, `job_ci_configuration_analysis`, `job_test_coverage`, `job_profile_data`, and `job_document_issue_analysis`) plus target-document extraction (`indexing/target_documents.py`, `indexing/document_interfaces.py`, `document_issues.py`). Trust-boundary discipline against hostile target metadata is unusually strong: `GitRunner` synthesizes a clean bare `/gitdir` that neutralizes target `.git/config`, hooks, filter drivers, and replace refs; author identities and commit prose stay in `protected` storage while retrieval shards receive only pseudonyms and closed labels; YAML/XML declaration parsers forbid external entities, anchors, aliases, and custom tags; and every context lane carries explicit non-evidence authority (`ROUTING_CONTEXT` / `context_only`). However, C10 suffers from severe execution and seam defects: `job_source_history_analysis` and `job_change_context_analysis` launch up to 555 sequential one-file `docker run` containers per repository while duplicating `git blame`, `fix_on_fix`, and `tool-tree-sitter` AST parsing; `job_test_coverage` multiplies `lines_total` on multi-class Cobertura files; `job_profile_data` leaves `source` paths unbound (`location=None`), causing `review/units.py` to attach every `hotspot` row in a build unit to every review unit in that build; `job_document_issue_analysis` is an unconsumed leaf that maps only single-line JS `app.get(...)` routes and declares 142 unused `InputRequirement`s with zero unit tests; and normal builds/offline runs force `job_test_coverage`, `job_profile_data`, and `job_change_context_analysis` into perpetual `COMPLETED_WITH_GAPS`.

**Strengths to preserve:**
- **Hardened synthetic Git execution and PII separation (`src/appsec_review/jobs/job_source_history_analysis/git.py:89-151`, `job.py:132-167`, `job_change_context_analysis/sources.py:45-68`):** `GitRunner` constructs an isolated bare `/gitdir` pointing `GIT_OBJECT_DIRECTORY` at `/target/<git_dir>/objects` with `core.hooksPath=/dev/null`, `core.attributesFile=/dev/null`, `GIT_NO_REPLACE_OBJECTS=1`, and `RLIMIT_FSIZE`, defeating hostile target `.git/config`, hooks, smudge/clean filters, mailmaps, and refs. Raw logs stay in `protected` datasets (`raw_git_history`), chunk-verified via `_VerifiedReader`, while operator exports are SHA-256-pinned and refused if placed inside `target_root`.
- **Snapshot-anchored, clock-free history windows and redirect-free GitHub pagination (`src/appsec_review/jobs/job_source_history_analysis/window.py:12-26`, `signals.py:40-90`, `github.py:32-39, 134-174`):** Windows anchor strictly to the mainline snapshot commit's committer timestamp (never `datetime.now()`), out-of-order Git commit times are monotonically clamped (`min(claimed, previous_time)`), and `GitHubClient` disables HTTP redirects, caps responses at 4 MiB, and validates `Link` headers to stay on the configured API host, path prefix, `per_page`, and `page + 1`.
- **Safe, bounded specification and CI parsing (`src/appsec_review/indexing/document_interfaces.py:39-70`, `src/appsec_review/jobs/job_test_coverage/parsers.py:55-64`, `src/appsec_review/jobs/job_ci_configuration_analysis/job.py:194-265`):** YAML composition enforces depth/event bounds and rejects aliases, anchors, duplicate keys, and custom tags; XML coverage parsers reject `<!DOCTYPE` and `<!ENTITY` before `ElementTree.fromstring`; and CI external linters (`zizmor --offline`, `checkov`, `actionlint`) run networkless per-provider branches where one tool failure becomes a `producer-gap/1` record without aborting sibling branches.
- **Explicit epistemic authority boundaries (`src/appsec_review/document_issues.py:72-128`, `src/appsec_review/jobs/job_source_history_analysis/changelog.py:30-35`):** History, change-context, test-coverage, profile-data, and changelog outputs consistently label themselves prioritization context rather than vulnerability proof, and `document_issues.verify_document_issue_ledger` (`document_issues.py:213-214`) fails closed if unreviewed candidates appear in `findings`.

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_source_history_analysis` | `job_target_catalog`, `job_review_intake`, target `.git` object store or pinned operator Git/GitHub exports | `protected` `raw_git_history`, `history` SQLite shard (`source-history-signals/2`), pseudonymous churn/hotspot/changelog context | `C10-F03` (up to 300+ sequential per-file `docker run` invocations for blame and AST complexity) | rework |
| `job_change_context_analysis` | `job_target_catalog`, `job_source_history_analysis`, `job_tree_sitter_ast` (loads whole-repo AST JSONL into RAM), target `.git` | `change_context` SQLite shard and diff/PR/blame context | `C10-F03` / `C10-F06` (duplicates `git blame`, `fix_on_fix`, and `tool-tree-sitter` runs; emits gaps when optional PR exports are absent) | merge |
| `job_ci_configuration_analysis` | `job_target_catalog`, target CI workflow files (`.github/workflows`, GitLab, Azure Pipelines, Jenkins, CircleCI) | `ci_trust` SQLite shard + normalized `zizmor`, `actionlint`, `checkov`, and static CI trust signals | `C10-F08` (drops top-level `actionlint` column spans, skips malformed JSONL lines, mislabels workflow keys as `kind="job"`) | rework |
| `job_test_coverage` | `job_target_catalog`, `job_language_build`, `job_artifact_indexing` (Cobertura, JaCoCo, LCOV, Go coverprofiles) | `coverage` SQLite shard (`file_coverage`) | `C10-F01` / `C10-F06` (multiplies `lines_total` on multi-class Cobertura/multi-run LCOV; forces `COMPLETED_WITH_GAPS` on normal builds without coverage reports) | rework |
| `job_profile_data` | `job_target_catalog`, `job_language_build`, `job_artifact_indexing` (pprof, collapsed stacks, perf/JSON profiles) | `profile` SQLite shard (`hotspot` entities) | `C10-F02` (`location=None` on profiler `source` paths causes `review/units.py` to broadcast every hotspot to every review unit in the build) | rework |
| `job_document_issue_analysis` | Declares 142 `InputRequirement`s; actually reads `job_review_package_assembly` (`document_hunt` packages) and `job_target_catalog` | `document-issue-ledger.json` (read by zero pipeline jobs; checked only by `acceptance/system.py:72`) | `C10-F04` (unconsumed terminal leaf matching only single-line JS `app.get(...)` routes, with zero unit tests) | retire |

#### C10-F01 `job_test_coverage` inflates denominators and counts on multi-class Cobertura XML, multi-section LCOV, and overlapping build-unit coverage reports
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: `job_test_coverage`
- **Evidence**: `src/appsec_review/jobs/job_test_coverage/parsers.py:67-71, 142-171`, `src/appsec_review/jobs/job_test_coverage/job.py:243-266, 395-398`. `parsers._merge` (`parsers.py:67-71`) merges duplicate `source_path` entries inside a report by summing `CoverageTotals` (`lines_total + other.lines_total`, `lines_covered + other.lines_covered`, etc.) rather than taking a line-number union. In `_cobertura` (`parsers.py:142-171`), Python (`coverage.py`), Java, and C# (`coverlet`) Cobertura exports emit one `<class filename="pkg/a.py">` element per class in the same source file; `lines_by_number` deduplicates only within a single `<class>` element and appends a `FileCoverage` per `<class>`, after which `_merge` sums `lines_total` across every class in the file (a 4-class file gets up to 4× its real `lines_total` or distorted coverage rates). Concatenated LCOV traces (`SF:` sections from unit + integration suites) similarly double `lines_total`. Across multiple coverage artifacts in one build unit (`job.py:243-266`), `ingest_coverage_artifacts` records `overlapping_coverage_reports` and still appends duplicate bound rows and sums both into `unit["totals"]` and handoff `totals`.
- **Impact**: File and build-unit `lines_total`, `lines_covered`, and `lines_rate` values indexed into `coverage_cell` entities and attached to review packages are mathematically wrong for standard multi-class Cobertura XML and multi-suite LCOV reports.
- **Recommendation**: Group `<class>` elements by `filename` *before* deduplicating `lines_by_number`, `branches_by_number`, and `(method_name, signature)` in `_cobertura`; union `(line_number -> max_hits)` across repeated `SF:` blocks in `_lcov`; and avoid summing overlapping multi-artifact file totals into a single denominator when `overlapping_coverage_reports` fires.
- **Effort**: `S`
- **Already registered**: none

#### C10-F02 `job_profile_data` leaves profiler `source` paths unbound (`location=None`) and `review/units.py` attaches every `hotspot` row in a build unit to every review unit in that build
- **Kind**: `contract-mismatch`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: `job_profile_data`
- **Evidence**: `src/appsec_review/jobs/job_profile_data/job.py:213-226, 271-283, 315-322`, `src/appsec_review/jobs/job_profile_data/parsers.py:85-100`, `src/appsec_review/review/units.py:69-84`. Unlike `job_test_coverage.bind_coverage_paths`, `job_profile_data` checks only the `job_target_catalog` handoff SHA/fingerprint (`job.py:271-278`) and never loads catalog file paths/hashes or binds profiler `row["source"]` (e.g., `/workspace/src/main.c` or build-root-relative `src/main.c`) to accepted repo-relative paths, indexing every `EntityKind.HOTSPOT` record with `location=None` (`job.py:319-321`). Downstream in `review/units.py:78-84`, `_engineering_context` indexes `by_path[payload["source"]]` (which misses whenever the profiler emitted an absolute or subproject-relative path) and—missing the `if aggregate` check used for `test_coverage` at `units.py:69-74`—appends *every* `hotspot` row with `payload["build_unit_id"]` (set on 100% of rows at `job.py:214`, up to `250,000` rows/artifact) into `by_build[build_unit_id]`. In addition, `parse_folded_stacks` (`parsers.py:98-99`) increments `counts[frame] += count` for every occurrence of a recursive frame in a single stack (`foo;foo 10` adds `20` to `foo`), and `ingest_profile_artifacts` (`job.py:220-226`) ranks incompatible event domains (e.g., Callgrind `Ir` instruction counts vs. sampling stack counts) in a single `hotness_rank` sorted by raw `-count`.
- **Impact**: Whenever execution profiles exist, every review unit in that `build_unit_id` receives all profile rows of the entire build unit in `inference_context`, crowding out file-specific context and triggering package context-cap truncation gaps, while path-exact lookups fail on real build paths.
- **Recommendation**: Bind `row["source"]` against accepted `job_target_catalog` paths/hashes (reusing `bind_coverage_paths`'s exact/build-root/unique-suffix rules) to populate `SourceLocation`, deduplicate frames per stack in `parse_folded_stacks`, rank within `(report_format, event)` or normalize shares before cross-report ranking, and restrict `by_build` in `review/units.py:83-84` to a bounded unit summary (or top-K unmapped build hotspots) rather than every row.
- **Effort**: `M`
- **Already registered**: none

#### C10-F03 Up to 555 sequential per-file `docker run` invocations per repository and duplicated Git/AST work across `job_source_history_analysis` and `job_change_context_analysis`
- **Kind**: `scale-risk`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: `job_source_history_analysis`, `job_change_context_analysis`
- **Evidence**: `src/appsec_review/jobs/job_source_history_analysis/job.py:779-783, 828-831, 926-966`, `src/appsec_review/jobs/job_change_context_analysis/job.py:397-430, 483-507`, `src/appsec_review/jobs/job_change_context_analysis/attribution.py:16-32, 69-125`. Every step in both jobs runs with `workers = 1`. Per source repository, `job_source_history_analysis` runs sequential per-file containers in `blame` (`<=50` `git blame`, `job.py:779-783`), `line_history` (`<=50` `git log -p -U0`, `job.py:828-831`), and `symbol_spans` (`<=200` `tool-tree-sitter` containers, invoking `docker run` once per file at `job.py:926-966` even though `tool-tree-sitter` natively accepts multi-file requests per language scope and `job_tree_sitter_ast` immediately re-parses the whole repo). Next, `job_change_context_analysis` spawns up to `50` *additional* sequential `git blame` containers on the same top files (`job.py:424-429`) and up to `200` (`2 * fix_on_fix_max_checks`) sequential `git diff` + `git blame` containers (`job.py:490-505`) to compute a second, divergent `fix_on_fix` implementation (`job_source_history_analysis` already computed `fix_on_fix` in `lines.py`). Meanwhile, `job_change_context_analysis.attribute_lines` (`job.py:399-407`) materializes every Tree-sitter node JSONL shard across the entire repository into one `list[bytes]` in RAM and runs an O(N_functions × N_nodes) scan (`attribution.py:92-119`) using a hardcoded `FUNCTION_TYPES` table (`attribution.py:16-32`) that omits JS/TS `arrow_function`/`function_expression`, Rust `closure_expression`, and Ruby `method` (already supported by `job_source_history_analysis/symbols.py:29-56`).
- **Impact**: On medium/large repositories, two `ROUTING_CONTEXT` jobs spend several minutes in Docker container startup overhead alone (~555 sequential `docker run` calls), risk host OOM when reading all repo AST node shards into a single list, and publish inconsistent `fix_on_fix` counts and function spans for the same file.
- **Recommendation**: Batch `tool-tree-sitter` requests by language in `symbol_spans` (or schedule `symbol_spans` after `job_tree_sitter_ast` / share its shards), batch `git blame` / `git log` invocations inside one `tool-git` container driver script, share the accepted blame/line-history/symbol-span artifacts with `job_change_context_analysis` instead of re-running Git and re-implementing `fix_on_fix` and AST span extraction, and stream per-file AST records instead of loading all shards into RAM.
- **Effort**: `M`
- **Already registered**: none

#### C10-F04 `job_document_issue_analysis` is an unconsumed terminal leaf with regex-only JS route matching, 142 unused `InputRequirement`s, and zero unit tests
- **Kind**: `dead-weight`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_document_issue_analysis`
- **Evidence**: `src/appsec_review/jobs/job_document_issue_analysis/job.py:26-29, 66-85, 118-123`, `src/appsec_review/jobs/job_document_issue_analysis/datasets.py:22-305`, `src/appsec_review/document_issues.py:21, 145-178`, `src/appsec_review/acceptance/system.py:28`, `tests/job-test-map.json`. `job_document_issue_analysis` runs after `job_review_package_assembly`, has zero downstream consumers in the review/gate/dossier graph (only `acceptance/system.py:28` checks its ledger), never passes red/blue/verifier reviews to `adjudicate()` (`document_issues.py:175`, leaving `supported: 0` and `findings: []` unconditionally), and always emits `UNADJUDICATED_GAP` (`"finding publication is not implemented"`, `terminal_status: "COMPLETED_WITH_GAPS"`). Its source mapper (`document_issues.py:21`) scans files solely with `_ROUTE = r"\b(?:app|router|server)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]"`, which fails on Python (`@app.get`/`path()`), Java (`@GetMapping`), Go (`HandleFunc`), C# (`[HttpGet]`), Rust, Ruby, JS template literals, multi-line registrations, and all DFD boundary `document_hunt` packages (`subject` not starting with `"route:"`). Meanwhile `datasets.py:22-305` declares 142 `InputRequirement`s across 25 upstream jobs while `job.py:66-85` never calls `accepted_upstream` and reads `job_review_package_assembly`'s internal `result.json` directly, and `tests/job-test-map.json` maps `"unit": []` for the job.
- **Impact**: Document-to-implementation drift candidates never reach `job_inference_security_review` or final findings, non-Express targets always report `unmapped`, any upstream schema bump breaks `job_document_issue_analysis/datasets.py` (as seen with `debug-symbol-decision`), and `select-job-tests` selects zero unit tests when editing the job.
- **Recommendation**: Either wire `document_hunt` packages directly into `job_inference_security_review` (retiring `job_document_issue_analysis` as a separate stub leaf, or moving route/symbol resolution upstream into `document_context` / `job_review_package_assembly` using indexed AST/route facts across languages), trim `CONTRACT.inputs` to the actual `job_target_catalog` + `job_review_package_assembly` inputs read via `accepted_upstream(..., contract=CONTRACT)`, and register focused unit tests in `tests/job-test-map.json`.
- **Effort**: `M`
- **Already registered**: `T-059` (item 6)

#### C10-F05 `target_documents.py` OpenAPI 3 JSON parser diverges from YAML/Swagger 2, failing on compact JSON and dropping `security_state` / `security_schemes` (while YAML drops `parameters`)
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_target_catalog`, `job_document_issue_analysis`
- **Evidence**: `src/appsec_review/indexing/target_documents.py:157-172, 217-256`, `src/appsec_review/indexing/document_interfaces.py:155-173`. OpenAPI YAML and Swagger 2.0 JSON call `structured_operations()` (`target_documents.py:161, 219`), which computes `security_state` (`required` / `optional` / `none` / `unspecified`), `security_schemes`, `protocol`, and `operation_id` (`document_interfaces.py:161-172`), whereas `_child(value, "parameters")` is validated at line 163-165 and never included in the returned dict. Conversely, OpenAPI 3 JSON (`target_documents.py:229-256`) bypasses both `structured_operations()` and `json_member_spans()` in favor of naive line scanning (`value.lstrip().startswith(json.dumps(route) + ":")` and indentation comparison), which fails with `unresolved_span` on minified/single-line `openapi.json` or `"route" :` spacing and omits `security_state`, `security_schemes`, `protocol`, and `operation_id` from emitted records.
- **Impact**: Declared authentication/security requirements vanish from OpenAPI 3 JSON specs (the most common machine-generated OpenAPI artifact), minified `openapi.json` specs produce zero operations, and YAML OpenAPI 3 specs lose declared parameter lists.
- **Recommendation**: Route OpenAPI 3 JSON through `structured_operations()` (or `json_member_spans()` + shared field extraction) so JSON and YAML OpenAPI 3 emit identical `security_state`, `security_schemes`, `parameters`, `responses`, `request_body`, `protocol`, and `operation_id` fields and resolve spans on arbitrary valid JSON formatting.
- **Effort**: `S`
- **Already registered**: none

#### C10-F06 `job_test_coverage`, `job_profile_data`, and `job_change_context_analysis` treat normal target builds and operator-disabled optional exports as coverage gaps
- **Kind**: `contract-mismatch`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_test_coverage`, `job_profile_data`, `job_change_context_analysis`
- **Evidence**: `src/appsec_review/jobs/job_test_coverage/job.py:256-258, 410-411`, `src/appsec_review/jobs/job_profile_data/job.py:168, 355-356`, `src/appsec_review/jobs/job_change_context_analysis/sources.py:48-49`, `src/appsec_review/jobs/job_change_context_analysis/job.py:324-376, 642-648, 864`. `job_language_build` captures compilation without executing target test suites or profilers, yet `job_test_coverage` emits `missing_applicable_coverage` (`job.py:257-258`) and `job_profile_data` emits `missing_profile_data` (`job.py:168`) for every build receipt without pre-existing coverage/profile artifacts, returning `COMPLETED_WITH_GAPS` instead of `NOT_APPLICABLE`. Similarly, `job_change_context_analysis` appends operator-unconfigured optional export reasons (`deployment_disabled`, `organization_disabled`, `time_zone_not_configured`, `review_records_unavailable:github_enrichment_disabled`) into `all_gaps()` (`job.py:642-648`), forcing every default local run to `PARTIAL` (`COMPLETED_WITH_GAPS`)—in contrast to `job_source_history_analysis`, which records `UNAVAILABLE_SIGNALS` in its document and index coverage table without turning unconfigured optional feeds into job-level gaps.
- **Impact**: Every normal offline review run reports `COMPLETED_WITH_GAPS` on at least four C10 jobs (`job_test_coverage`, `job_profile_data`, `job_change_context_analysis`, `job_document_issue_analysis`), desensitizing operators and walk gates (`AGENTS.md` stop-on-unexpected-gap rule) to genuine parser or tool failures.
- **Recommendation**: Return `NOT_APPLICABLE` when zero coverage/profile candidates exist across all build units (retaining `missing_*` only in the retrieval coverage table as `"unavailable"`), and separate `unavailable_signals` / `SKIPPED_POLICY` optional feeds from failure/truncation `gaps` in `job_change_context_analysis`.
- **Effort**: `S`
- **Already registered**: none

#### C10-F07 Control-layer bypasses, internal `result.json` / `resolved.json` coupling, legacy free-text gaps, and `implementation_identity=None` across 5 of 6 C10 jobs
- **Kind**: `contract-mismatch`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: `job_source_history_analysis`, `job_change_context_analysis`, `job_ci_configuration_analysis`, `job_test_coverage`, `job_profile_data`, `job_document_issue_analysis`
- **Evidence**: `src/appsec_review/jobs/job_change_context_analysis/job.py:83-105, 224-275, 899-905`, `src/appsec_review/jobs/job_source_history_analysis/job.py:1669-1675`, `src/appsec_review/jobs/job_test_coverage/job.py:353-355, 419-423`, `src/appsec_review/jobs/job_profile_data/job.py:310-312, 365-369`, `src/appsec_review/jobs/job_document_issue_analysis/job.py:66-85, 125-128`. Only `job_ci_configuration_analysis` sets `strict_gaps=True`; the other five C10 jobs remain on `LEGACY_FREE_TEXT_GAPS` (including `job_source_history_analysis`, where `acquire.changelog_history` emits `producer-gap/1` dicts while sibling units emit bare strings). `job_change_context_analysis` reads `job_source_history_analysis`'s internal unit <!-- historical:begin -->`result.json`<!-- historical:end --> (`outputs["resolve_sources.resolve_history_source"]`, `outputs["acquire.git_history"]["raw_log"]`) and reads `data/configuration/resolved.json` directly (`_resolved_job_settings`, `job.py:83-105`) to copy `job_source_history_analysis`'s `bulk_change_file_threshold`; `job_document_issue_analysis` reads `job_review_package_assembly`'s internal <!-- historical:begin -->`result.json`<!-- historical:end --> (`job.py:66-76`). None of those five jobs pass `contract=CONTRACT` to `accepted_upstream`, all over-declare unused `InputRequirement`s (`job_review_intake` preflight/binary datasets, unused catalog shards), `job_test_coverage`/`job_profile_data`/`job_change_context_analysis` set `implementation_identity=None`, and at `f29ee4c688` `job_test_coverage/job.py:353-354` and `job_profile_data/job.py:310-311` reused existing `.sqlite` files via `file_sha256(path)` without `IndexBuilder.attest_existing()`. *(Post-`f29ee4c688` note: commit `53fa08ec5` added `attest_existing()` to `job_test_coverage` and `job_profile_data`.)*
- **Impact**: Internal unit renames in upstream jobs silently break downstream readers, `CONSUMES` / `JobContract.inputs` overstate actual read dependencies (inflating repair invalidation blast radius), and free-text gaps lack structured `producer-gap/1` cause codes for automated walk triage.
- **Recommendation**: Migrate the remaining five C10 jobs to `strict_gaps=True` (`producer-gap/1`), expose required fields (`bulk_change_file_threshold`, package manifest directory, protected raw-log artifact) on published handoff schemas rather than reading internal `result.json` or `resolved.json`, route all reads through `accepted_upstream(..., contract=CONTRACT)`, and prune unused `InputRequirement`s.
- **Effort**: `M`
- **Already registered**: none

#### C10-F08 `job_ci_configuration_analysis` drops `actionlint` column spans, silently skips malformed JSONL lines, and mislabels workflow keys as `job` hierarchy nodes
- **Kind**: `defect`
- **Severity**: `low`
- **Confidence**: `high`
- **Job**: `job_ci_configuration_analysis`
- **Evidence**: `src/appsec_review/jobs/job_ci_configuration_analysis/job.py:282-322`, `src/appsec_review/jobs/job_ci_configuration_analysis/static_rules.py:56-77`. `actionlint -format '{{json .}}'` emits top-level `line`, `column`, and `end_column` integers (no nested `location` object), yet `_generic_external_records` (`job.py:303-312`) reads `line` from `item.get("line")` while reading `col` and `end_col` exclusively from `loc` (`item.get("location")`), collapsing all `actionlint` columns to `1` and preventing `correlation_key` (`job.py:338-347`) from correlating identical findings across `actionlint` and `zizmor`/`ci-schema`. In `_parse_json_or_jsonl` (`job.py:286-291`), unparseable lines in JSONL fallback are silently skipped via `continue` instead of raising `_CiOutputParseError`. Finally, `static_rules.hierarchy()` (`static_rules.py:67-70`) classifies every YAML mapping key at `indent <= 4` on non-Azure YAML providers—including `on:`, `permissions:`, `env:`, `concurrency:`, and `defaults:`—as `kind = "job"`.
- **Impact**: `actionlint` observations have degraded column precision and fail exact-span deduplication, truncated JSONL linter output can silently drop records without a parse gap, and workflow-level findings receive misleading `hierarchy.job` names (e.g., `job="permissions"`).
- **Recommendation**: Fall back to `item.get("column")` / `item.get("end_column")` in `_generic_external_records`, raise `_CiOutputParseError` on malformed JSONL lines, and track the parent top-level section (`jobs:` vs. workflow metadata keys) in `static_rules.hierarchy()` using bounded `yaml.SafeLoader` node spans.
- **Effort**: `S`
- **Already registered**: none

#### C10-F09 Keep-a-Changelog Markdown parser treats backticked prose tokens containing `.` or `/` as unbound file paths
- **Kind**: `weakness`
- **Severity**: `low`
- **Confidence**: `high`
- **Job**: `job_source_history_analysis`
- **Evidence**: `src/appsec_review/jobs/job_source_history_analysis/changelog.py:431-435`, `src/appsec_review/jobs/job_source_history_analysis/job.py:1148-1154`. `_markdown_text` (`changelog.py:432-434`) treats every inline backtick span matching `[A-Za-z0-9_.+~/-]{1,512}` with `.` or `/` as a path mention. Version numbers (`` `1.4.2` ``, `` `v2.0.0` ``), dotted identifiers/settings (`` `auth.timeout` ``), and MIME types (`` `application/json` ``) are ubiquitous in `CHANGELOG.md` bullets, fail `PathBinder.bind` as `unmatched`, and trigger `changelog_paths_unbound` `producer-gap/1` records (`job.py:1148-1154`), marking `acquire.changelog_history` `PARTIAL`.
- **Impact**: Clean repositories with standard Markdown changelogs emit noisy `changelog_paths_unbound` gap records proportional to version/identifier mentions rather than genuine unresolved path references.
- **Recommendation**: Require Markdown inline-code candidates to have either a `/` path separator (excluding MIME/URL-like tokens without known file suffixes or catalog directory prefixes) or a recognized source/config filename extension before counting them as path mentions.
- **Effort**: `S`
- **Already registered**: none
### C11 Evidence indexing, retrieval and review packaging

**Active findings:** 20 (`1` critical, `7` high, `11` medium, `1` low).

C11 provides a sound, hash-verified SQLite shard substrate, source-digest-bound span resolution, and a deterministic `review-package/6` dataflow-sliced packaging pipeline (`src/appsec_review/review/packages.py`), but an over-broad substring regex in `sanitize_producer_data` (`src/appsec_review/retrieval/model.py:270`) corrupts payloads across all 19 index kinds by replacing security tags, rule IDs, file paths, and AST identifiers containing `token`, `secret`, `password`, `credential`, `authorization`, or `api_key` with `"<redacted>"`. That sanitization bug silently drops `query_precomputed(path=...)` results on authentication and secret files without recording a coverage gap, collapses 16 taxonomy tags into one bucket, and causes Tree-sitter slicing and symbol-less call matching to join unrelated functions on `"<redacted>" == "<redacted>"`. The component also carries two parallel review-package and capability stacks: `job_review_package_assembly` (`src/appsec_review/review_packages.py`, schema v3) crashes with `ValueError` on clean targets or scopes with >=12 `metric_vector`s while blocking `job_inference_security_review` via an unused `InputRequirement`, and `src/appsec_review/mcp/capability.py` (`ScopedRetrievalMcpAdapter`) is dead production code that fails on v6 packages yet still backs six retrieval test suites instead of `src/appsec_review/review/capability.py` (`CellCapability`). Finally, `job_review_prioritization` loads all of `syntax-facts.json` into memory five times without resource reservations, scores Ruby with zero heuristic rules while reporting `feature_coverage = 1.0`, and publishes `priority` shards that `src/appsec_review/review/ranking.py` ignores when selecting Lane B hunt packages.

**Strengths to preserve:**
- Hash-verified, read-only SQLite index manifests (`mode=ro&immutable=1`) with lineage cycle checks, shard digest verification before database open, and explicit `coverage` tables (`src/appsec_review/retrieval/index.py:345-415`, `src/appsec_review/indexing/store.py:76-85`).
- `LogicalIdentity` canonical SHA-256 derivation and `SourceLocation` byte/line invariants that prevent collisions and path traversal across all 19 index kinds (`src/appsec_review/retrieval/model.py:72-186`).
- Source-byte resolution in `read_source_bytes` that enforces SHA-256 and target-snapshot checks and refuses to fall back to target files for run-generated sources (`src/appsec_review/retrieval/source_resolution.py:42-98`).
- `review-package/6` assembly and membership auditing in `assemble_packages`, which preserves every admitted lead across 10 scanner families, bounds unknown-severity triage with two-sided severity provenance, and verifies Lane A/Lane B completeness (`src/appsec_review/review/packages.py:1590-1715`, `src/appsec_review/review/lead_triage.py:242-358`).
- Composable dataflow slicing (`Precision.COMPILER` LLVM IR/SVF -> `SYNTAX` Tree-sitter -> `LEXICAL` window) that keeps slices anchored to verified source spans and merges overlapping budgets deterministically (`src/appsec_review/review/slicing/compose.py:48-132`, `src/appsec_review/review/package_view.py:154-225`).
- Strict JSON-RPC framing in `mcp/stdio.py` that rejects duplicate JSON keys, `NaN`/`Infinity`, oversized frames, and unknown tool arguments before touching `RetrievalCore` (`src/appsec_review/mcp/stdio.py:148-198`, `src/appsec_review/mcp/schema.py:44-118`).
- Complete producer-inventory reconciliation in `indexing/inventory.py` and `indexing/input_matrix.py`, ensuring every registered producer handoff is accounted for as indexed, artifact-only, or a named gap (`src/appsec_review/indexing/inventory.py:45-138`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_review_data_indexing` | Accepted handoffs + SQLite shards from all Wave 1–3 producers + third-party feeds (`nvd`, `kev`, `epss`, `osv`, `mitre`, `cve_bin_tool`) | Combined `index-manifest/1`, 14 `precomputed` SQLite shards (`scanner_correlation`, `symbol_links`, `review_package`, etc.), `producer-inventory.json`, `fts-validation.json` | `C11-F01` (blanket substring regex replaces safe tags/identifiers containing `token`/`secret`/`key`/`auth` with `"<redacted>"`) | rework |
| `job_review_prioritization` | `job_target_catalog`, `job_tree_sitter_ast`, optional `job_evidence_collection`, `job_codeql_analysis`, `job_source_history_analysis` | `priority` SQLite shard (`priority_item`, `review_signal`), `ranking.json`, `review-prioritization.json` (ignored by `review/ranking.py`) | `C11-F04` (ranking output is bypassed by `job_inference_security_review`'s own `review/ranking.py` scorer) | merge |
| `job_security_tagging` | `data/reference/taxonomy/*.json`, `job_target_catalog`, `job_review_data_indexing` Stage 1 manifest, producer handoff gaps | `tags` SQLite shard (`tag_assignment`), `tag-cloud.json`, Stage 2 `tags-*.json` manifest | `C11-F01` / `C11-F06` (`auth_token` and `secret_handling` taxonomy tags are destroyed by `retrieval/model.py` redaction) | rework |
| `job_review_package_assembly` | `job_review_data_indexing` final `index-manifest/1` | Legacy `packages/*.json` and `package-assembly.json` (never read by `job_inference_security_review`; read only by `job_document_issue_analysis`) | `C11-F03` (redundant materialization pass superseded by `job_review_data_indexing`'s `review_package` shard and `review/packages.py`) | retire |

#### C11-F01 `sanitize_producer_data` replaces security tags, paths, rule IDs, and AST identifiers with `"<redacted>"`
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/retrieval/model.py:227-273` and `src/appsec_review/retrieval/index.py:239`; `sanitize_producer_data` checks dict keys by whole segments (`model.py:242-247`) but line `270` replaces any string value matching `(?i)(authorization|password|passwd|secret|token|api[_-]?key|credential)` anywhere with `"<redacted>"` when writing `payload_json` to SQLite and again in `RetrievalCore._safe_payload` (`src/appsec_review/retrieval/core.py:523`).
- **Impact**: Sixteen official tags in `data/reference/taxonomy/vocabulary.json` (`func:authn:password`, `func:authn:api-key`, `func:session:csrf-token`, `func:crypto:password-hash`, `data:credential`, `data:session-token`, etc.) become `"<redacted>"` in `tags` shards, collapsing OWASP control and review routing into `tag_subjects["<redacted>"]` (`src/appsec_review/owasp_workbench/evidence.py:130`, `src/appsec_review/review/packages.py:1170`). `precomputed_fact.payload["subject_path"]` for files like `src/auth/token.py` becomes `"<redacted>"`, so `RetrievalCore.query_precomputed(path=...)` (`src/appsec_review/retrieval/core.py:1278`) silently returns zero facts with no coverage gap; non-`secret` rule IDs (`hardcoded-password`, `csrf-token-missing`, `missing-authorization`) become `"<redacted>"` (`src/appsec_review/review/lead_families.py:569-574` only works around `family == "secret"`); and `qualified_name` / `syntax.written_name` for functions like `verify_token` and `hash_password` become `"<redacted>"`, causing `TreeSitterReferences` (`src/appsec_review/review/slicing/strategies/tree_sitter.py:127,168-190`) and symbol-less call matching (`src/appsec_review/review/packages.py:438,894,1417`) to falsely join unrelated functions.
- **Recommendation**: In `src/appsec_review/retrieval/model.py`, remove blanket substring redaction on arbitrary string values at line `270`; retain dict-key segment redaction (`_SECRET_SEGMENTS`), CLI `--flag=value` list redaction, and structured credential-value redaction (`redact_message` in `src/appsec_review/review/lead_families.py`), leaving schema-typed identifiers (`tag`, `rule_id`, `subject_path`, `qualified_name`, `written_name`) intact.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F02 `job_review_prioritization` scores Ruby with zero heuristic rules while reporting `feature_coverage = 1.0`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_review_prioritization`
- **Evidence**: `src/appsec_review/jobs/job_review_prioritization/job.py:67-76,567-598` and `src/appsec_review/jobs/job_review_prioritization/rules.py:22`; `"ruby"` is listed in `SCORED_LANGUAGES` and `languages.py:124`, but `rules.ALL` omits `"ruby"`, and `heuristics.py` has no Ruby extractor branches.
- **Impact**: Every Ruby file and method receives `0` (not `None`) across all 10 heuristic signal features plus `suppression_density`, so `scoring.rank` (`src/appsec_review/jobs/job_review_prioritization/scoring.py:55-68`) assigns Ruby `0.0` percentile across ~68% of total feature weight under the default `normalization_population = "run"` (`appsec-review.toml:985`) while publishing `missing_features = []`, `feature_coverage = 1.0`, and zero gaps—hiding missing Ruby signal coverage as clean and burying Ruby attack surface in `job_target_analysis_plan` and `query_hotspots`.
- **Recommendation**: Either add Ruby rule tables in `src/appsec_review/jobs/job_review_prioritization/rules.py` and `heuristics.py` (Rails routes, `params`/`cookies`, `Marshal.load`/`YAML.load`/`Kernel.system`/`send`, RuboCop/Brakeman suppressions), or emit `None` for unimplemented heuristic features on languages absent from `rules.ALL` in `src/appsec_review/jobs/job_review_prioritization/job.py:567-598` with a named gap so `scoring.rank` redistributes weights honestly.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F03 Legacy `job_review_package_assembly` crashes on >=12 metric scopes or clean targets and blocks `job_inference_security_review`, which never reads it
- **Kind**: `remove`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_review_package_assembly`
- **Evidence**: `src/appsec_review/review_packages.py:249-250,372-373,394-395,410-411`, `src/appsec_review/jobs/job_inference_security_review/datasets.py:219-224`, and `src/appsec_review/jobs/job_inference_security_review/job.py:345-415`; `assemble_review_packages` raises `ValueError` when `not facts and not document_facts` or `len(metrics) > 200` (18 metrics per `metric_vector` in `src/appsec_review/indexing/metrics.py:85-115` means 12 file+function scopes in one 20-lead `hunt` partition produces `216 > 200`), while `job_inference_security_review` declares `job_review_package_assembly` in `CONTRACT.inputs` yet never reads it, calling `review.packages.assemble_packages` (`review-package/6`) instead.
- **Impact**: Any target with zero SAST/document leads or a 20-lead component partition spanning >=6 functions across >=6 files fails `job_review_package_assembly` with an uncaught `ValueError`, blocking `job_inference_security_review` in Dagster even though only `job_document_issue_analysis` (`src/appsec_review/jobs/job_document_issue_analysis/job.py:67`) reads v3 `document_hunt` packages into an unadjudicated side ledger.
- **Recommendation**: Remove the unused `job_review_package_assembly` `InputRequirement`s from `src/appsec_review/jobs/job_inference_security_review/datasets.py` immediately; fold `document_hunt` context into `src/appsec_review/jobs/job_document_issue_analysis/` (or `review/packages.py`) and retire `job_review_package_assembly` and `src/appsec_review/review_packages.py`.
- **Effort**: `M (days)`
- **Already registered**: `docs/reviews/2026-11-13-threat-driven-hunting-review.md` noted duplicate v3/v6 package assemblers; new here are the `len(metrics) > 200` (~12 scopes) and empty-fact `ValueError` crashes in `review_packages.py` and the unused `InputRequirement` in `job_inference_security_review/datasets.py` that makes those crashes block the main review.

#### C11-F04 `job_review_prioritization` loads `syntax-facts.json` into memory five times without resource reservations
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_review_prioritization`
- **Evidence**: `src/appsec_review/jobs/job_review_prioritization/streaming.py:1-10` and `src/appsec_review/jobs/job_review_prioritization/job.py:428,434,456,540,650,916,953-954`; `extract.syntax_metrics` streams `syntax-facts.json` under a 4,096 MB `syntax_metrics_reservation` to avoid OOM, but `syntax_doc` (`job.py:428`) calls `read_json` on the entire file in `dependency_graph`, `semantic_evidence`, `score`, `index_priority`, and `publish` without any `ResourceAdmission` reservation.
- **Impact**: `extract.dependency_graph` and `extract.semantic_evidence` have identical upstream dependencies (`("extract.syntax_metrics",)`, `job.py:953-954`) and run concurrently, materializing two full in-memory copies of `syntax-facts.json` at once on large C/C++ or monorepo targets and reintroducing the exact OOM failure `streaming.py` was written to prevent; `publish` (`job.py:916,938`) reloads the entire multi-hundred-MB artifact solely to read `syntax["by_language"]`.
- **Recommendation**: Emit `by_language` in `extract.syntax_metrics`'s small unit output dict (`src/appsec_review/jobs/job_review_prioritization/job.py:422-425`) so `publish` never reads `syntax-facts.json`, stream per-file records through `iter_syntax_files` (`streaming.py`) in `dependency_graph`, `semantic_evidence`, `score`, and `index_priority`, and gate any remaining parse under `ResourceAdmission`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C11-F05 `RetrievalCore._envelope` enters an infinite pagination loop when the first row exceeds `max_response_bytes`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/retrieval/core.py:538-544`; when `len(canonical_json(response)) > self.limits.max_response_bytes` and `response["results"]` has one item (or the first item alone pushes the response over budget), `response["results"].pop()` empties `results` and sets `next_cursor = self._cursor(offset + len(response["results"]), request_hash)`, which equals `self._cursor(offset, request_hash)`.
- **Impact**: A review worker or operator following `pagination.next_cursor` receives `results = []` and the identical cursor forever until its tool-call budget expires, stranding every subsequent row at `offset + 1..N` whenever a single precomputed or graph record plus shard-manifest envelope exceeds the response byte budget (`65,536` bytes for workers in `src/appsec_review/review/capability.py:44`).
- **Recommendation**: In `src/appsec_review/retrieval/core.py:538-549`, when popping the first row (`len(response["results"]) == 0` while input `results` was non-empty), advance `next_cursor` to `offset + 1` (only when more rows exist or `len(results) > 1`) and append an explicit gap naming the skipped oversized entity identity so pagination always makes forward progress.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F06 `RetrievalCore._safe_payload` strips nested `"path"` keys, erasing cross-file taint-step and subject paths
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/retrieval/core.py:517-521`; `_safe_payload` filters every mapping at every depth with `if not denied.fullmatch(str(key)) and str(key) != "path"`, deleting all nested `"path"` keys inside entity payloads returned by `RetrievalCore`.
- **Impact**: Multi-file `dataflow_path` entities returned by `query_code_graph` / `find` lose `steps[i]["location"]["path"]` while keeping `start_line`, so review workers cannot tell which file intermediate taint steps belong to; `tag_assignment` entities lose `payload["subject"]["path"]`, and `memory_object` entities lose `payload["accessors"][i]["path"]`.
- **Recommendation**: In `src/appsec_review/retrieval/core.py:517-521`, rely on `_DENIED_PAYLOAD_KEYS` (`target_root`, `run_root`, `stdout_path`, etc.) and reject `"path"` only when its string value is an absolute or `..`-traversing filesystem path rather than a normalized repo-relative POSIX path.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F07 `read_excerpt` and `expand` return unredacted secret lines that `package_view` deliberately redacted
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/review/package_view.py:181,319` and `src/appsec_review/review/lead_triage.py:288` apply `redact_source_line` to source lines overlapping `secret` leads, whereas `RetrievalCore.read_excerpt` (`src/appsec_review/retrieval/core.py:694-730`) and `RetrievalCore.read_source_lines` (`core.py:732-758`, backing `CellCapability` `expand` at `src/appsec_review/review/capability.py:143,219-235`) return raw UTF-8 target lines without redaction.
- **Impact**: Every `secret`-family lead package grants its worker `read_excerpt` and `expand` over the lead's `source_file`; as soon as a red, blue, or verifier worker calls either tool on that file, raw private keys, API tokens, or passwords are sent to the model provider and persisted in worker transcripts, defeating `package_view` redaction.
- **Recommendation**: Pass the run's accepted secret-observation `(path, file_sha256, line)` set (or apply `redact_source_line` in `CellCapability` / `RetrievalCore` for worker-scoped calls) so `read_excerpt` and `read_source_lines` redact secret-bearing lines consistently with `package_view.py`.
- **Effort**: `S (under a day)`
- **Already registered**: `docs/reviews/lead-coverage-audit.md` noted `read_excerpt` lacked secret redaction; new here is the `review-package/6` asymmetry where `package_view.py` redacts secret lines while `CellCapability` simultaneously grants `expand` and `read_excerpt` on the same file, leaking the raw secret on the first tool call.

#### C11-F08 `seeding/units.py` drops high-severity seeds via alphabetical `unit_limit` truncation and runs unbudgeted 1 MB file probes
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/seeding/units.py:72-88,139-143` and `src/appsec_review/seeding/plan.py:36-45`; `_Scanner.direct` increments `self.reads` against `include_scan_files` only once per source file (`lines 74-77`) and then calls `self.read_text(candidate)` (which reads up to 1 MB per probe with no existence cache) for every `(include_name, include_dir)` pair (`lines 83-87`), and `select_units` resorts `selected` by `(relative_source(rows[index]), index)` (`line 142`) before slicing `selected[:unit_limit]` (`line 145`).
- **Impact**: On C/C++ repositories with more seeded translation units than `unit_limit`, sorting alphabetically before truncation lets low/info seeds in `a_*.c` evict critical memory-corruption seeds in `src/z_*.c` from Clang AST, LLVM IR, and SVF analysis, depriving `review/slicing` of `Precision.COMPILER` slices on the highest-risk leads; meanwhile header resolution performs `O(files * includes * include_dirs)` uncached disk reads during seeding.
- **Recommendation**: In `src/appsec_review/seeding/units.py`, preserve seed-priority order (`Seed.key` orders by severity rank first in `src/appsec_review/seeding/record.py:42-48`) when applying `selected[:unit_limit]` before sorting chosen units for deterministic execution, and memoize candidate existence (or pass the accepted `source_file` path set) in `_Scanner.direct`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F09 `mcp/capability.py` (`ScopedRetrievalMcpAdapter`) is dead production code that fails on v6 packages while backing six test suites
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/mcp/capability.py:72-86,89-250` vs `src/appsec_review/review/capability.py:35-255` and `src/appsec_review/mcp/stdio.py:137-146`; `ScopedRetrievalMcpAdapter` and `issue_capability` have zero callers in `src/appsec_review/`, and `issue_capability` (`mcp/capability.py:82`) indexes `package["retrieval"]["max_response_bytes"]`, which `review-package/6` (`src/appsec_review/review/packages.py:1373-1376`) removed.
- **Impact**: `issue_capability` raises `KeyError` on any real v6 package and lacks `CellCapability`'s `_PATH_LIKE`, `_REGEX_LIKE`, `_SQL_LIKE`, `FORBIDDEN_PARAMETERS`, `expand`, and locator-tool checks, yet six test suites (`test_review_package_capability.py`, `test_syntax_retrieval.py`, `test_debug_symbol_retrieval.py`, `test_codeql_neighborhood_tools.py`, `test_seeded_neighborhoods_end_to_end.py`, `test_operator_worker_boundaries.py`) validate worker isolation against this dead class instead of `CellCapability`.
- **Recommendation**: Delete `ScopedRetrievalMcpAdapter` and `issue_capability` from `src/appsec_review/mcp/capability.py` (keeping only shared cursor/token helpers if still needed) and migrate those six test files to `CellCapability` in `src/appsec_review/review/capability.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F10 Lane B hunt ranking (`review/ranking.py`) ignores `job_review_prioritization`'s `priority` index
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/review/ranking.py:55-120` and `src/appsec_review/review/packages.py:1665-1675`; `rank_units` ranks Lane B hunt units using a local weighted sum of `lead_density`, `boundary_exposure`, `privilege_concentration`, `churn`, `tag_density`, and `coverage_deficits` without reading `priority_item` or `review_signal` entities from `job_review_prioritization`'s `priority` shards.
- **Impact**: `job_review_prioritization` runs a six-unit pipeline computing cyclomatic/cognitive complexity, import-graph coupling/instability, inline suppressions, and cross-checked semantic taint paths, yet none of those rankings influence which 25 hunt units (`hunt_max_units = 25` in `appsec-review.toml`) actually get reviewed in `job_inference_security_review`; complex, coupling-central, heavily suppressed modules with zero scanner leads are systematically outranked by noisy scanner-dense units.
- **Recommendation**: Feed `priority` shard file/function scores, suppression density, and `semantic_path` counts into `src/appsec_review/review/ranking.py` (or replace the duplicate local heuristic weights with `priority` signals plus coverage deficits) and validate hunt-unit recall on labelled targets.
- **Effort**: `M (days)`
- **Already registered**: `T-155` registers fair hunt allocation across strata; new here is that `review/ranking.py` completely ignores `job_review_prioritization`'s `priority` index, duplicating prioritization poorly.

#### C11-F11 Infer categories classify as `"other"`, dropping Infer leads from `scanner_correlation` enrichment and audit
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_review_data_indexing`
- **Evidence**: `src/appsec_review/retrieval/observations.py:50-57`, `src/appsec_review/indexing/sast.py:114-117`, and `src/appsec_review/review/lead_families.py:157,440,563-580`; `_CLASS_BY_CATEGORY` omits Infer's `"memory_corruption"`, `"concurrency"`, and `"resource_management"` categories so `classify(payload)` returns `"other"`.
- **Impact**: Although `producer_decision("job_native_static_analysis", "tool-infer")` rescues Infer into `source_sast` inside `lead_families.py:440`, `build_scanner_correlation` (`indexing/sast.py:115`) skips every Infer finding (`observation_class != "source_sast"`), so Infer leads receive empty correlation state (`state = {}`)—losing inline-suppression matching, same-line CWE deduplication against Clang/Cppcheck/CodeQL, `flow_ids` linkage, and the `sast_classified` integrity check (`lead_families.py:563,578`).
- **Recommendation**: Add `"memory_corruption": "source_sast"`, `"concurrency": "source_sast"`, and `"resource_management": "source_sast"` to `_CLASS_BY_CATEGORY` in `src/appsec_review/retrieval/observations.py:50-57`.
- **Effort**: `S (under a day)`
- **Already registered**: `docs/reviews/lead-coverage-audit.md` noted `_CLASS_BY_CATEGORY` mapped Infer categories to `"other"`; new here is that `lead_families.py` later added `producer_decision` without updating `_CLASS_BY_CATEGORY`, leaving `indexing/sast.py` correlation and `sast_classified` integrity checks bypassed for Infer.

#### C11-F12 `_purl_osv_identity` misclassifies unversioned scoped npm PURLs as `malformed-purl`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_review_data_indexing`
- **Evidence**: `src/appsec_review/indexing/products.py:318-339`; line `330` executes `path = path.rsplit("@", 1)[0]` unconditionally before URL-decoding, unlike `_resolved_version` (`products.py:348-349`), which guards `separator and path and "/" not in tail`.
- **Impact**: An unversioned scoped npm PURL with a literal `@` (`pkg:npm/@babel/core`, emitted by lockfile/manifest parsers when version is unresolved) splits on the leading `@` to `path = ""`, returning `(None, fallback_name, "malformed-purl")` instead of `("npm", "@babel/core", "purl-ecosystem-and-name")`, dropping the `"npm"` ecosystem filter and falling back to noisy cross-ecosystem `name-only` OSV advisory matching.
- **Recommendation**: In `src/appsec_review/indexing/products.py:329-331`, strip `@version` only when `rpartition("@")` finds `"@"` with a non-empty prefix and `"/" not in tail` (matching `_resolved_version`).
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F13 `package-manifest.json` counts admitted and KEV leads by `reported_severity` instead of `effective_severity`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/review/packages.py:1595,1612,1686-1692`; `admitted_leads` (`line 1595`) and `audit_membership` (`line 1612`) admit and audit leads using `lead.effective_severity`, whereas `admitted_counts` and `kev_admitted` (`lines 1686-1692`) tally `lead.reported_severity`.
- **Impact**: Whenever `lead_triage` resolves an `"unknown"`-severity lead to `"critical"`/`"high"`/`"medium"`/`"low"`, `package-manifest.json`'s `counts.admitted` leaves that lead in `"unknown"` (or drops it completely from `counts.admitted` when `"unknown"` is excluded from `admit_severities`), causing `counts.admitted` to disagree with `audit.lane_a.by_family` and misstate severity distribution to downstream reporting and operators.
- **Recommendation**: Replace `lead.reported_severity` with `lead.effective_severity` in `admitted_counts` and `kev_admitted` at `src/appsec_review/review/packages.py:1686-1692` (or publish both `admitted_by_effective` and `admitted_by_reported`).
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F14 `AcceptedSliceSources.ir_flows` suffix-matches relative paths, merging LLVM IR flows from wrong files
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/review/slicing/sources.py:42-44,113`; `_same_path` returns `True` when `found == path or found.endswith("/" + path)`, and `ir_flows(path)` uses `_same_path` against already-normalized repo-relative paths in `analysis` shards.
- **Impact**: In any C/C++ repository with duplicate relative suffixes (for example root `util.c` and `src/sub/util.c`, or `a/handler.c` and `vendor/a/handler.c`), `ir_flows("util.c")` merges `src/sub/util.c`'s LLVM IR def-use line numbers into `util.c`'s `Precision.COMPILER` slice, feeding irrelevant source lines of `util.c` to the review worker under compiler-precision provenance and crowding out real slice lines under the line budget.
- **Recommendation**: Require exact normalized repo-relative path equality (`found == path`) and matching `file_sha256` when available in `src/appsec_review/review/slicing/sources.py:42-44,105-124`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F15 Hardcoded `cyclomatic_mean=None` forces 100% of `history_context` `metric_vector` facts into `"partial"` coverage
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_review_data_indexing`
- **Evidence**: `src/appsec_review/jobs/job_review_prioritization/complexity.py:368`, `src/appsec_review/jobs/job_review_prioritization/job.py:565-580`, and `src/appsec_review/indexing/metrics.py:106-116`; `complexity.py` already computes per-file `cyclomatic_average`, `job.py` omits it from `priority_item.features`, and `indexing/metrics.py` unconditionally appends `metric("cyclomatic_mean", ..., None, ..., gap="cyclomatic_mean_not_produced_by_prioritization")` on both file and function items.
- **Impact**: Every single `metric_vector` fact in every run has `unavailable = ["cyclomatic_mean_not_produced_by_prioritization"]` and `coverage_status = "partial"` (even for function items where a mean over one function equals its cyclomatic complexity), polluting `query_precomputed("history_context")` coverage gaps on 100% of runs and obscuring real history or parser gaps.
- **Recommendation**: Export `cyclomatic_average` on file `priority_item.features` in `src/appsec_review/jobs/job_review_prioritization/job.py:567-575` and populate `cyclomatic_mean` in `src/appsec_review/indexing/metrics.py:106-112` (using `cyclomatic` for function scope and `cyclomatic_average` for file scope).
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F16 `fts.image_validation` spawns three uncached containers per run for an unread receipt and aborts all validation on one row
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_review_data_indexing`
- **Evidence**: `src/appsec_review/indexing/fts_worker.py:45-78,130-171`, `src/appsec_review/jobs/job_review_data_indexing/job.py:194-224`, and `appsec-review.toml:998`; `validate_shards` runs three Docker invocations (`probe`, `build`, `verify`) on every indexing run (`fts_image_validation = "advisory"`) with no `SharedArtifacts` cache for `fts-validation.json` (which has zero readers in `src/`), and `export_documents` (`fts_worker.py:49-65`) aborts the entire export when any single entity matches `_SENSITIVE_VALUE` or exceeds `max_text_bytes`.
- **Impact**: Runtime `RetrievalCore.search` queries the host-built SQLite `search_fts` tables via Python's `sqlite3` (`src/appsec_review/retrieval/core.py:610-655`), never the container's throwaway `search.sqlite`; running three containers per run wastes wall-clock time, while any target containing one sensitive-looking token or >64 KB document skips validation of all remaining shards—contradicting `docs/operations/review-data-indexing.md:107-110`.
- **Recommendation**: Default `fts_image_validation` to `"disabled"` in `appsec-review.toml` (moving FTS5 container parity to an integration test on the `fts-indexer` image) or cache `fts-validation.json` by shard-digest tuple in `SharedArtifacts` and skip/redact offending rows individually instead of aborting the whole export.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F17 `job_security_tagging` ignores `job_dependency_intelligence` packages, emits unconditional `STANDING_GAPS`, and has stale operations docs
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_security_tagging`
- **Evidence**: `src/appsec_review/jobs/job_security_tagging/producers.py:438-450`, `src/appsec_review/jobs/job_security_tagging/job.py:39-43,374-389`, and `docs/operations/security-tagging.md:62-63`; `package-capability` rules (`pkg-jwt`, `pkg-password-hash`, `pkg-crypto`) inspect only `tool_observation` rows in `observations` (`syft`/`osv_scanner`) and never `dependency_package` entities in `job_dependency_intelligence`'s `dependencies` shard, `STANDING_GAPS` is unconditionally prepended on every run, and the operations doc says `invoked` capability detection is unimplemented despite `collect_graph_facts` (`producers.py:306-405`).
- **Impact**: Declared capability tags (`func:authn:jwt`, `func:crypto:password-hash`, etc.) are missed whenever `job_dependency_intelligence` resolves packages that have no `observations` row (for example clean lockfiles when Syft is skipped or emits inventory summaries without `payload["package"]`), weakening `job_owasp_control_assessment` applicability; unconditional `STANDING_GAPS` forces `COMPLETED_WITH_GAPS` on 100% of runs so operators cannot distinguish real tagging failures from permanent roadmap notes.
- **Recommendation**: Match `package_rules` against `dependency_package` entities from `dependencies` shards in `src/appsec_review/jobs/job_security_tagging/producers.py`, emit gap records only when an applicable input or scope is actually encountered in `job.py:374-389`, and update `docs/operations/security-tagging.md:62-63`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-031`/`T-055` cover MITRE feed crosswalk; the `dependency_package` omission, unconditional `STANDING_GAPS` masking real gaps, and `docs/operations/security-tagging.md` drift are new.

#### C11-F18 `review/lead_triage.py` rule-table lookup fails whenever non-`secret` `rule_id` is redacted or prefixed
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/review/lead_triage.py:135-178` and `src/appsec_review/review/lead_families.py:569-575`; `rule_table_decision` looks up exact `(lead.scanner, lead.rule_id)` keys in `RULE_SEVERITY_TABLE`, while `lead_families.py` only restores `row["name"]` when `rule_id == "<redacted>"` for `family == "secret"`.
- **Impact**: Any unknown-severity `source_sast`, `ci_rule`, `post_build_hardening`, or `artifact_scanner` observation whose rule ID contains `password`, `secret`, `token`, `credential`, `authorization`, or `api_key` arrives at `lead_triage` with `rule_id == "<redacted>"`, misses deterministic rule/CWE triage, and triggers unnecessary LLM triage calls (or remains `unresolved` when LLM triage is unavailable).
- **Recommendation**: Alongside fixing `sanitize_producer_data` (C11-F01), fall back to `row["name"]` / `native_id` when `rule_id == "<redacted>"` across all families in `src/appsec_review/review/lead_families.py:569-575`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C11-F19 All four C11 jobs remain on legacy free-text gaps and run-scoped consumption instead of `producer-gap/1` and unit-pinned receipts
- **Kind**: `weakness`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/test_gap_contract.py:21-24`, `src/appsec_review/jobs/job_review_prioritization/job.py:145,534,931`, `src/appsec_review/jobs/job_review_prioritization/inputs.py:19-25`, and `src/appsec_review/indexing/store.py:35-48`; all four C11 jobs set `strict_gaps=False` on `LEGACY_FREE_TEXT_GAPS`, `job_review_prioritization` uses internal `"PARTIAL"` sub-statuses, and `accepted_upstream` is called with `run_root` rather than `unit`.
- **Impact**: Downstream coverage aggregation (`job_final_publication_gate` and `indexing/inventory.py`) receives unstructured free-text gap strings without machine-typed `gap_code`, `scope`, or `remediation` fields from C11 jobs, and read receipts are recorded at run scope rather than bound to individual unit claims.
- **Recommendation**: Migrate `job_review_prioritization`, `job_review_data_indexing`, `job_security_tagging`, and (if not retired per C11-F03) `job_review_package_assembly` to `interchange.producer_gap` with `strict_gaps=True`, remove them from `LEGACY_FREE_TEXT_GAPS` in `tests/test_gap_contract.py`, and pass `unit` through `accepted_upstream`.
- **Effort**: `M (days)`
- **Already registered**: `T-073` and `T-147` cover parts of interchange/applicability standardization; C11's remaining four entries in `LEGACY_FREE_TEXT_GAPS` are the concrete local slice.

#### C11-F20 Test mapping omits `job_review_package_assembly`, exercises dead `ScopedRetrievalMcpAdapter`, and misses `sanitize_producer_data` regressions
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/job-test-map.json:161-166`, `tests/review/test_packages.py:1-60`, and `tests/test_review_package_capability.py:1-55`; `job-test-map.json` maps `job_review_package_assembly` exclusively to `tests/review/test_packages.py` (which tests `review.packages` v6 and never imports `job_review_package_assembly` or `review_packages.py`), `test_review_package_capability.py` tests dead `ScopedRetrievalMcpAdapter` instead of `CellCapability`, and no unit test indexes real `vocabulary.json` tags (`func:authn:password`, `data:credential`) or `token`/`secret` file paths through `IndexBuilder` + `RetrievalCore`.
- **Impact**: Targeted job tests for `job_review_package_assembly` run zero lines of `job_review_package_assembly` or `review_packages.py` (missing the >200-metric and empty-fact crashes in C11-F03), worker capability regressions in `CellCapability` can slip past six retrieval test files, and `sanitize_producer_data`'s `"<redacted>"` corruption (C11-F01) went undetected despite high unit-test counts.
- **Recommendation**: Add round-trip unit regressions over `IndexBuilder` + `RetrievalCore` + `assemble_packages` with `vocabulary.json` tags and `src/auth/token.py` paths, point `test_review_package_capability.py` at `CellCapability`, and either map `job_review_package_assembly` to a real test of `review_packages.py` or remove the job per C11-F03.
- **Effort**: `S (under a day)`
- **Already registered**: no
### C12 Control and threat modelling

**Active findings:** 18 (`0` critical, `6` high, `9` medium, `3` low).

C12 contains two producers and one unscheduled library at sharply uneven maturity: `job_owasp_control_assessment` runs by default on every review, `job_threat_model_generation` is deterministic and schema-sound but disabled in every profile, and `deployment/` is a standalone static parser library with no job or consumer. `job_owasp_control_assessment` currently degrades default non-Python and clean-unit reviews: it assesses only four narrow Python source controls (rejecting every HTTP route file over 120 lines after spending two LLM calls, and marking controls `satisfied` when common SQL, password, or route forms go unrecognized), yet publishing any row unlocks run-wide `control_gap` hunting that diverts one-third of round-0 hunt cells across every package. `job_threat_model_generation` is already wired into `job_inference_security_review` via `review/behavior.py` despite stale docs saying it has no consumer, but enabling it today yields zero processes, flows, or threats on Python, JS/TS, JVM, .NET, and PHP targets because `lanes/structure.py` only accepts native/Rust/Go executable build-point kinds and `lanes/interactions.py` applies C/C++-only callee rules across all languages. Even on C/C++ targets where threat models populate, `assemble._flow` silently caps flow evidence at eight sites and `review/behavior.py` projects only opaque hash IDs (`flow_id`, `boundary_ids`, `threat_ids`), so STRIDE threat questions and verification obligations never reach review workers. Meanwhile, the listener, reverse-proxy, container-exposure, and privilege-boundary facts that both threat modelling and hunting need remain stranded in `deployment/`—whose parsers abort valid `postgresql.conf`, `nginx.conf`, and OCI descriptors as `malformed` and omit Dockerfiles, Ingresses, volumes, and privilege flags.

**Strengths to preserve:**
- Blinded independent-reviewer verification and fail-closed evidence-span resolution in `owasp_workbench`: `reviewer_package` strips worker rationales/dispositions, `EvidenceResolver.verify` enforces exact snapshot and line-span custody before any citation is accepted, and worker/reviewer disagreement fails closed to `cannot_verify` with `dissent` (`src/appsec_review/owasp_workbench/assessment.py:137-150`, `src/appsec_review/owasp_workbench/evidence.py:217-256`, `src/appsec_review/owasp_workbench/assessment.py:422-436`).
- Qualification/fixture mode cannot masquerade as customer evidence: `validate_config` rejects fixture catalogs in `assessment` mode, and `lead_eligible` requires `assessment` mode, `not_satisfied` status, `independently_assessed` verification, and accepted citations (`src/appsec_review/jobs/job_owasp_control_assessment/job.py:76-78`, `src/appsec_review/owasp_workbench/assessment.py:444-447`).
- `threat_model` is 100% deterministic, zero-LLM, fail-closed on cross-reference integrity, and enforces `strict_gaps=True` (`producer-gap/1`) with honest `UNMITIGATED_EVIDENCE_ABSENT` status rather than treating missing mitigation evidence as clean (`src/appsec_review/threat_model/validate.py:66-195`, `src/appsec_review/jobs/job_threat_model_generation/job.py:448-451`, `src/appsec_review/threat_model/threats.py:124-149`).
- `threat_model/render.py` escapes Mermaid labels, strips control characters, and isolates untrusted target strings from diagram syntax (`src/appsec_review/threat_model/render.py:21-38`).
- `deployment/` enforces YAML alias-expansion caps (`_NoAliasSafeLoader`), regex/byte bounds, path-confinement checks (`relative_to`), and line-anchored `EvidenceRef` provenance on every extracted listener, upstream, image, and configuration claim (`src/appsec_review/deployment/parsing.py:31-42`, `src/appsec_review/deployment/inventory.py:45-64`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_owasp_control_assessment` | Declares 104 inputs across 21 jobs (`datasets.py:37-275`); reads accepted upstream shards (`evidence.py:375-492`) + `RetrievalCore` source files (with raw `target_root` fallback) | `owasp_control_results` (`owasp-workbench-result.json`) and `owasp_workbench_indexes`, consumed by `job_review_data_indexing` and `mcp/owasp.py` | `C12-F01`–`C12-F03` (omits `infer=infer` in `builtin_registry`, raw `target_root` fallback, incomplete `fingerprint_inputs` across `models`) | rework |
| `job_threat_model_generation` | Reads 13 inputs across `job_target_catalog`, `job_language_build`, `job_tree_sitter_ast`, `job_code_graph_index`, plus legacy unregistered names in `threat_model/index_view.py:79-121` | `threat_model_summary`, `generated_dfd`, `generated_threat_model`, `generated_model_evidence`, Mermaid/Markdown renders (read by `job_inference_security_review` when enabled) | `C12-F05`, `C12-F06` (stale upstream job names in `index_view.py`, weak grounding between DFD trust boundaries and Hunt-lane generation) | rework |

#### C12-F01 Narrow Python AST recognizers mark controls `satisfied` while missing common unsafe constructs in the same component
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `src/appsec_review/owasp_workbench/obligations.py:293-341`; `_sql_call` requires `ast.Attribute` calls in `_QUERY_METHODS` with string/literal/`ast.Assign` first arguments, `_password_comparison` only matches `ast.Compare` nodes that already call `len(password)` inside nine hardcoded function names, and `_route` requires `args[0]` to be a string literal starting with `"/"`. `src/appsec_review/owasp_workbench/assessment.py:415-445` and `src/appsec_review/review/packages.py:1161-1167` then publish `control_status = "satisfied"` for the component and project it into review packages whenever recognized obligations pass.
- **Impact**: Components containing one recognized safe site alongside unrecognized unsafe sites in the very same file—such as `session.execute(sqlalchemy.text(f"SELECT ..."))`, bare `execute(...)`, `query: str = f"SELECT ..."` (`ast.AnnAssign`), `def register(username, password):` with no `len()` check at all, FastAPI `@router.post("")` on a prefixed `APIRouter`, keyword `path="/admin"`, or Django `path(...)`—are published as `control_status: "satisfied"` with zero obligation gaps, suppressing `owasp_control` leads and feeding `"satisfied"` `control_context` to `blue_team_refuter`.
- **Recommendation**: In `src/appsec_review/owasp_workbench/obligations.py`, widen `_sql_call` to unwrap `text(...)`/call wrappers, bare query functions, and `ast.AnnAssign` (recording an explicit unmodeled-call obligation gap when dynamic SQL-like calls cannot be statically resolved); change `V6.2.1` to bind on password-accepting functions and fail when no length check exists; and widen `_route` to handle empty-string sub-routes, keyword `path=`, and `add_api_route`/`path(...)` registrations.
- **Effort**: `M (days)`
- **Already registered**: `T-001` registers adding procedures beyond the initial four Python controls; new here is that the four existing Python procedures mark components `satisfied` on incomplete intra-file recognition.

#### C12-F02 Run-wide `control_evidence` availability diverts one-third of round-0 hunt cells onto `control_gap` when no adverse control exists
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `src/appsec_review/owasp_workbench/evidence.py:421-425` and `src/appsec_review/indexing/products.py:1286-1340` index `cannot_verify`/`not_assessed` rows into the `control_evidence` query set even when zero controls were assessed (for example on C/C++, Rust, Go, Java, JS/TS, or C# targets). `src/appsec_review/jobs/job_inference_security_review/job.py:187,259`, `src/appsec_review/jobs/job_inference_security_review/teams.py:767-771`, and `src/appsec_review/guidance/routing.py:188,217-226` then advertise `"owasp_workbench"` in `available_sources` for every hunt package, causing `hunt_panel` to assign one of the three round-0 hunter cells to `pipeline/guidance/tasks/inference-security-review/control_gap.md:8-11`.
- **Impact**: On every default review of a non-Python repository—and on Python packages whose controls were `satisfied` or `cannot_verify`—one-third of round-0 hunting budget is instructed to exploit a failed or missing OWASP control in the unit when none exists, displacing `persona_sweep` coverage across the entire target.
- **Recommendation**: Gate `"owasp_workbench"` in per-package `available_sources` (`src/appsec_review/jobs/job_inference_security_review/teams.py` and `src/appsec_review/guidance/routing.py`) on the package actually carrying non-empty adverse (`not_satisfied` or unresolved applicable) `control_context`, rather than run-wide presence of the `control_evidence` query set.
- **Effort**: `S (under a day)`
- **Already registered**: `docs/reviews/appsec-system-review-2026-11-06.md` §5 noted low OWASP ROI on default runs; new here is the exact `run_sources -> hunt_panel -> control_gap` misrouting that actively degrades round-0 hunting on non-Python and clean packages.

#### C12-F03 Python HTTP route controls (`V8.2.1`, `V8.3.1`) spend worker and reviewer LLM calls on files over 120 lines and then deterministically reject the output
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `src/appsec_review/owasp_workbench/subject_selection.py:61-82` drops the `"module"` subject whenever a file exceeds `max_source_lines` (default `120` in `appsec-review.toml:2680`) or `16000` characters and emits `"function"` subjects instead, which `src/appsec_review/owasp_workbench/obligations.py:478-493` marks `supported = True` for `V8.2.1` and `V8.3.1`. `src/appsec_review/owasp_workbench/assessment.py:394-403` executes both `control_assessor` and `independent_reviewer` model calls before calling `accept_obligations` (`src/appsec_review/owasp_workbench/assessment.py:368-371`), which unconditionally raises `ValueError("complete function does not resolve external authorization policy...")` whenever `source_subject["kind"] != "module"`.
- **Impact**: Every Python route module longer than 120 lines cannot ever produce a `satisfied` or `not_satisfied` result or an `owasp_control` lead for `V8.2.1`/`V8.3.1`, yet still burns two full LLM invocations per batch only to discard their answers as `cannot_verify`.
- **Recommendation**: In `src/appsec_review/owasp_workbench/obligations.py:478-493`, mark `V8.2.1`/`V8.3.1` obligations on `"function"` subjects `supported = False` with the module-policy gap before batching so zero LLM calls are wasted, or carry module-level router/middleware preamble alongside each route function subject within bounded line budgets.
- **Effort**: `S (under a day)`
- **Already registered**: no (introduced by `T-146` subject-complete selection).

#### C12-F04 `build_applicability` forces `test_development_only` and mobile-mismatched components `applicable` in `assessment` mode while empty catalog `component_roles` break `qualification` mode
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `src/appsec_review/owasp_workbench/acquisition.py:177,189` writes `"component_roles": []` on every ASVS and MASVS control in `data/reference/owasp/catalogs/*.json`, so `matched = roles.intersection(...)` in `src/appsec_review/owasp_workbench/engine.py:259-272` is always empty for classified components in `qualification` mode (making every row `not_applicable`). Conversely, in `assessment` mode, `src/appsec_review/owasp_workbench/engine.py:280-297` unconditionally overwrites `outcome` to `"applicable" if roles else "conditional"` for all four supported ASVS controls—clobbering the earlier `roles == {"test_development_only"}` (`line 264`) and `not family_match` (`line 261`) exclusions.
- **Impact**: Test and fixture directories classified exclusively as `test_development_only` (`engine.py:114-116`) are assessed against production ASVS controls and can emit `lead_eligible = True` `owasp_control` leads into `job_inference_security_review`, while `qualification` mode silently marks real catalog controls `not_applicable` whenever a component has a role.
- **Recommendation**: In `src/appsec_review/owasp_workbench/engine.py:280-297`, preserve `outcome == "not_applicable"` from `not family_match` and `roles == {"test_development_only"}` before applying procedure support checks, and populate chapter-level `component_roles` in `src/appsec_review/owasp_workbench/acquisition.py` (or treat empty `control.component_roles` as family-wide rather than matching nothing).
- **Effort**: `S (under a day)`
- **Already registered**: no.

#### C12-F05 `job_threat_model_generation` is disabled in all profiles and produces zero processes, flows, or threats on non-native targets if enabled
- **Kind**: `missing`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_threat_model_generation`
- **Evidence**: `appsec-review.toml:1076` sets `enabled = false` (with no override in `profiles/*.toml`), causing `src/appsec_review/review/behavior.py:209-212` to record a `behavior_model` missing gap on every review. If enabled, `src/appsec_review/threat_model/lanes/structure.py:67-76,239-250` only creates `Process` nodes for native/Rust/Go build-point kinds (`executable`, `bin`, `main_package`, `program`, `test`, `test_program`), ignoring `package`, `script`, `workspace_member`, `project`, `module`, `assembly`, `extension`, and `wasm_module` emitted by `src/appsec_review/jobs/build_points.py:818-960,1237-1255` (and `src/appsec_review/jobs/job_threat_model_generation/datasets.py:65-72` omits `jvm_build_actions`), so `src/appsec_review/threat_model/assemble.py:330-335` drops every interaction as `flow_endpoint_unresolved`.
- **Impact**: Default and production reviews receive no DFD or STRIDE threat context at all, and turning `enabled = true` today yields zero processes, zero data flows, and zero candidate threats on Python, JS/TS, Java/Kotlin, C#/.NET, and PHP repositories.
- **Recommendation**: Map service/application build-point kinds (`package`, `script`, `workspace_member`, `project`, `assembly`, `wasm_module`) and `job_language_build/jvm_build_actions` into `Process` / `CodeUnit` nodes in `src/appsec_review/threat_model/lanes/structure.py` and `src/appsec_review/jobs/job_threat_model_generation/datasets.py` before enabling the job by default.
- **Effort**: `M (days)`
- **Already registered**: `T-107` notes remaining lanes and real-run acceptance before flipping `enabled = true`; new here is the concrete build-point kind mismatch (`structure.py` vs `build_points.py`) and missing `jvm_build_actions` input that cause zero processes/threats on non-native languages.

#### C12-F06 `assemble._flow` and `review/behavior.py` silently drop >8 operations per flow and strip STRIDE threat questions and obligations to unresolvable IDs
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_threat_model_generation`
- **Evidence**: `src/appsec_review/threat_model/assemble.py:254-263` merges all sites of `(process, peer, interaction)` into a single `Flow` whose `evidence` tuple is truncated to `max_evidence_refs_per_element = 8` (`appsec-review.toml:1084`, `src/appsec_review/threat_model/contract.py:552-559`) without emitting a gap, and `src/appsec_review/review/behavior.py:169-185` joins `operations` solely through `dfd["flows"][*]["evidence"]` while ignoring `model["entry_points"]`. For matched operations, `src/appsec_review/review/behavior.py:189-192` and `src/appsec_review/review/package_view.py:473,587` project only `flow_id`, `boundary_ids`, and `threat_ids` (`dfd-*`, `bnd-*`, `thr-*`), while `dfd.json` and `threat-model.json` are `artifact_only` (`src/appsec_review/jobs/job_threat_model_generation/datasets.py:29-50`) with no retrieval index or worker tool.
- **Impact**: Any process with more than eight handlers or call sites of the same interaction silently loses `model_context` on the 9th+ operation with no gap, and even on matched operations review hunters receive only opaque hash IDs—never the STRIDE category, boundary kind, threat `question`, or `obligations` from `data/reference/threat-model/threat-templates.json`—making threat-model output inert for guiding hunt hypotheses.
- **Recommendation**: Join operations in `src/appsec_review/review/behavior.py` using `model["entry_points"]` and `evidence.json` (or retain per-site refs before `merge_evidence` truncation), and project compact threat descriptors (`stride`, `boundary_kind`, `question`, `obligations`) directly into `model_context` in `src/appsec_review/review/behavior.py:189-195` and `src/appsec_review/review/package_view.py:473,587`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-151` plans operation-bound behavioural obligations; new here is the silent 8-ref `flow.evidence` join truncation and the unresolvable opaque IDs currently projected by `T-146`'s `review/behavior.py`.

#### C12-F07 `lanes/interactions.py` bypasses `Reference.languages_for_callee`, matching C/C++ POSIX/Win32 callee rules against ASTs of every language
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_threat_model_generation`
- **Evidence**: Every one of the 46 `callees` entries in `data/reference/threat-model/interaction-catalog.json:163-662` declares `"languages": ["c", "cpp"]`, and `src/appsec_review/threat_model/reference.py:119-120` defines `languages_for_callee(callee)`, but `src/appsec_review/threat_model/lanes/interactions.py:216-226` calls `reference.callee_rule(callee)` without checking the `syntax_ast_units` row's language (`languages_for_callee` has zero callers in `src/`).
- **Impact**: Generic method/function names such as `open`, `read`, `write`, `connect`, `send`, `recv`, `listen`, `accept`, `getenv`, and `system` in Python, JS/TS, Java, Go, or Rust ASTs are misclassified as C/C++ POSIX socket/process/file interactions, producing false DFD peers, entry points, and STRIDE threats on multi-language targets while genuine framework APIs in those languages remain unmodeled.
- **Recommendation**: Carry the normalized file/unit language in `src/appsec_review/threat_model/index_view.py` (`ast_calls_by_unit`) and enforce `unit_language in reference.languages_for_callee(callee)` in `src/appsec_review/threat_model/lanes/interactions.py:218`, then add language-tagged catalog rules for Python/JS/Go/Java/Rust network, DB, and exec sinks.
- **Effort**: `S (under a day)`
- **Already registered**: `T-107` notes expanding lanes generally; new here is the dead `languages_for_callee` guard causing cross-language false matches right now.

#### C12-F08 Default and `copilot-dev` profiles run identical worker and reviewer models while publishing `independently_assessed` verification status
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `appsec-review.toml:2694-2712` configures both `[jobs.job_owasp_control_assessment.settings.model]` and `[jobs.job_owasp_control_assessment.settings.models.reviewer]` as `provider = "claude-cli"`, `model = "claude-haiku-5-5"` (and `profiles/copilot-dev.toml:15-20` sets both to `copilot-cli` / `claude-haiku-5.5`), yet `src/appsec_review/owasp_workbench/assessment.py:415-417` sets `verification = "independently_assessed"` whenever worker and reviewer statuses match without checking model or provider distinctness. In addition, `src/appsec_review/jobs/job_owasp_control_assessment/job.py:309` passes only `settings["model"]` to `fingerprint_inputs` (`src/appsec_review/owasp_workbench/engine.py:617-625`), omitting `settings["models"][reviewer_profile]`.
- **Impact**: In default and `copilot-dev` runs, correlated self-agreement by the exact same model unlocks `independently_assessed` status and `lead_eligible = True` promotion (`assessment.py:444-447`), overstating verification independence; changing only `models.reviewer` also fails to change `model_identity` inside shard fingerprints.
- **Recommendation**: Check `(worker_profile["provider"], worker_profile["model"]) != (reviewer_profile["provider"], reviewer_profile["model"])` in `src/appsec_review/owasp_workbench/assessment.py:415-417` before emitting `"independently_assessed"` (downgrading same-model agreement to `"single_model_reviewed"` with `lead_eligible = False`), and include `reviewer_profile` in `fingerprint_inputs` in `src/appsec_review/jobs/job_owasp_control_assessment/job.py:309`.
- **Effort**: `S (under a day)`
- **Already registered**: `docs/reviews/appsec-system-review-2026-11-06.md` §4 item 5 noted model diversity across review lanes (`prod.toml` and `copilot-prod.toml` were updated); new here is that default/`copilot-dev` still label identical-model OWASP checks `independently_assessed` and `fingerprint_inputs` omits `models.reviewer`.

#### C12-F09 `deployment/` parsers reject valid `postgresql.conf`, `nginx.conf`, and OCI image descriptors as `malformed`, discarding entire files
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: Three strict regex/URL checks in `src/appsec_review/deployment/` raise `ParseError` and discard all facts from the document (`src/appsec_review/deployment/inventory.py:92-97`): (1) `src/appsec_review/deployment/configuration.py:221-225` rejects any PostgreSQL setting name failing `r"[a-z_]+"` before checking `if name not in supported:` (`line 234`), failing on standard mixed-case/digit/dotted GUCs (`TimeZone`, `DateStyle`, `krb5_server_keyfile`, `pg_stat_statements.track`); (2) `src/appsec_review/deployment/configuration.py:26-35,169` raises `ParseError("unsupported_endpoint")` on valid Nginx `listen [::];`, and `urlsplit("http://unix:/run/app.sock:/").port` (`line 177`) raises `ValueError` -> `ParseError("invalid_proxy")`; (3) `src/appsec_review/deployment/descriptors.py:29-34` forbids valid OCI repository names containing `--` or `__`.
- **Impact**: Once `T-108` wires `deployment/` into a producer job, real-world `postgresql.conf`, dual-stack/Unix-socket `nginx.conf`, and multi-document Kubernetes/Compose manifests using `--` or `__` image names will fail whole-file parsing as `malformed`, dropping all listener, TLS, auth, and upstream topology claims from those files.
- **Recommendation**: In `src/appsec_review/deployment/configuration.py`, accept `[A-Za-z_][A-Za-z0-9_.]*` (case-folded) before filtering `supported`, default portless `[::]` listeners to `80`/`443` (`ssl`), and record an `unsupported_proxy` gap on `http://unix:...` before reading `parsed.port`; in `src/appsec_review/deployment/descriptors.py:30`, align the OCI repository separator pattern with the OCI Distribution Spec (`(?:[._]|__|[-]+)`).
- **Effort**: `S (under a day)`
- **Already registered**: `T-108` registers wrapping `deployment/` into a job; new here are concrete parser bugs in `deployment/` that will reject valid configs when `T-108` lands.

#### C12-F10 Deployment and trust-boundary extraction lacks Dockerfiles, Ingresses, privilege flags, and host mounts, and uses a non-standard `Gap` record
- **Kind**: `missing`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/deployment/catalog.py:45-64` and `src/appsec_review/deployment/descriptors.py:101-147,171-258` inspect only Compose services (`image`, `ports`), Kubernetes `Pod`/`Deployment`/`StatefulSet`/`DaemonSet`/`Service`, and `nginx.conf`/`redis.conf`/`postgresql.conf`, while `src/appsec_review/deployment/model.py:124-136` defines a custom `Gap` dataclass lacking `producer-gap/1` fields (`gap_id`, `unit_id`, `scope_id`, `retryable`, `evidence_refs`). Neither `deployment/` nor `threat_model/` extracts `Dockerfile`/`Containerfile` (`USER`, `EXPOSE`, `ENTRYPOINT`), Kubernetes `Ingress`/`NetworkPolicy`/`Job`/`CronJob`, or container/Compose privilege and boundary fields (`privileged`, `hostNetwork`, `hostPID`, `allowPrivilegeEscalation`, `capabilities`, `securityContext`, `network_mode: host`, `volumes`/`hostPath`).
- **Impact**: Both `job_threat_model_generation` (`BoundaryKind.DEPLOYMENT_EXPOSURE` and `BoundaryKind.PRIVILEGE` in `docs/architecture/dfd-and-threat-model-generation.md:277-297`) and `job_inference_security_review` lack target-grounded facts on whether a service is internet-routed via Ingress, runs as root/privileged, shares the host network/PID namespace, or mounts sensitive host paths; `deployment.model.Gap` also cannot publish under `strict_gaps=True`.
- **Recommendation**: Extend `src/appsec_review/deployment/` with `Dockerfile`/`Ingress` and Compose/Kubernetes security-context/network/volume extractors, and emit `interchange.producer_gap` (`producer-gap/1`) records at the job adapter boundary when implementing `T-108`.
- **Effort**: `M (days)`
- **Already registered**: `T-108` registers creating a deployment inventory job and threat-model lane; new here are the missing Dockerfile/Ingress/privilege/mount extractors and the `producer-gap/1` schema mismatch in `deployment/model.py`.

#### C12-F11 `job_owasp_control_assessment` declares 104 upstream inputs across 21 jobs plus `TargetAccess.CHECKOUT` and scans all manifest shards twice for unused categories
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `src/appsec_review/jobs/job_owasp_control_assessment/datasets.py:37-275` declares 104 `InputRequirement`s across 21 upstream jobs—including C++-only `clang_ast`, `llvm_ir`, `svf_alias_sets`, `cpg_binary`, `build_workspaces`, and `raw_git_history`—plus `target_access = TargetAccess.CHECKOUT` (`line 273`). `src/appsec_review/owasp_workbench/evidence.py:293-303,375-402,467-492` then iterates every entity across all shards twice (`_index_hints` and `_component_evidence`) to materialize `scanner_observation` and `static_fact` items that `src/appsec_review/owasp_workbench/obligations.py:356` immediately ignores (`rule.evidence_mode != "static_source" or evidence.get("category") != "source"`), and falls back to reading raw `target_root` files (`evidence.py:298-302`).
- **Impact**: The default-enabled OWASP job sits behind nearly the entire analysis graph (including heavy native/build producers it never uses), holds unnecessary raw checkout access (`TargetAccess.CHECKOUT`), and performs redundant full-manifest shard scans on every non-Python repository.
- **Recommendation**: Trim `src/appsec_review/jobs/job_owasp_control_assessment/datasets.py` to the inputs actually read (`job_target_catalog`, <!-- historical:begin -->`job_source_normalization`<!-- historical:end -->, `job_security_tagging`, and `RetrievalCore` source custody), drop `TargetAccess.CHECKOUT` (along with the raw `target_root` fallback in `evidence.py:298-302`), and short-circuit `accepted_inputs` when no component contains `.py` source files.
- **Effort**: `S (under a day)`
- **Already registered**: `docs/reviews/appsec-system-review-2026-11-06.md` §5 noted OWASP runtime cost vs value; new here is the 104-input C++/protected-dataset over-declaration, unnecessary `TargetAccess.CHECKOUT`, and dead `scanner_observation`/`static_fact` shard scan.

#### C12-F12 `control_evidence` points review consumers at `query_owasp_workbench` while `IN_PROCESS_TOOLS` denies that tool to every review cell
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `src/appsec_review/indexing/products.py:1309,1314-1317` strips `obligations`, `observations`, and `disagreements` from `control_evidence` rows and embeds `"workbench_reference": {..., "query": "query_owasp_workbench family=control-result"}`, while `pipeline/guidance/registry.json:21-25` grants `query_precomputed` to `hypothesis_hunter` and `src/appsec_review/review/capability.py:47` explicitly excludes `"query_owasp_workbench"` from `IN_PROCESS_TOOLS`. Meanwhile, package-level `other_context` is first in `TRIM_ORDER` (`src/appsec_review/review/package_view.py:46`), so inline `control_context` is the first section dropped under prompt budget pressure.
- **Impact**: When inline `other_context` is trimmed or a hunter queries `query_precomputed(query_set="control_evidence")` for obligation details and follows the returned `query_owasp_workbench` instruction, `capability.authorize` rejects the call with `AuthorityDenied`, wasting a bounded tool turn and emitting a spurious `REVIEW_AUTHORITY_DENIED` security event.
- **Recommendation**: Remove the uncallable `"query": "query_owasp_workbench ..."` hint from `src/appsec_review/indexing/products.py:1309` and retain compact obligation/citation summaries directly in `control_evidence` rows so `query_precomputed` is self-contained inside `IN_PROCESS_TOOLS`.
- **Effort**: `S (under a day)`
- **Already registered**: no.

#### C12-F13 `OwaspSettings` drops half of `[jobs.job_owasp_control_assessment.settings]`, omits startup validation of `parser_versions`, and leaves three registered runtime skills unloaded
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `src/appsec_review/config/owasp.py:30-80` validates `parser_versions` only as a non-empty `str -> str` mapping (`lines 67-69`) and drops eight settings (`asvs_level`, `masvs_profile`, `max_batch_size`, `max_components_per_batch`, `max_components`, `dynamic_authorized`, `parser_versions`, `standards`) from `OwaspSettings`, while `src/appsec_review/jobs/job_owasp_control_assessment/job.py:130,310` indexes `settings["parser_versions"]["asvs"]` and `["masvs"]` directly at runtime without checking them in `validate_config` (`lines 68-82`). Separately, `pipeline/guidance/registry.json:103-118` registers three runtime skills (`effective-control-verification`, `predicate-verification`, `conflict-resolution`) for `job_owasp_control_assessment` and marks `api_web`/`deployment_operations` as migrated inline personas, yet `src/appsec_review/owasp_workbench/assessment.py:251-257,294-301` never calls `load_runtime_skill` (`skills=()` is always empty) and `src/appsec_review/owasp_workbench/guidance.py:18` still routes to `api_web` and `deployment_operations`.
- **Impact**: Missing `parser_versions.asvs` or `parser_versions.masvs` passes `validate_config` and crashes mid-run with `KeyError`, untyped settings bypass `OwaspSettings`, and none of the three registered OWASP runtime verification skills ever reaches the worker or reviewer prompt.
- **Recommendation**: Include all 16 job settings on `OwaspSettings` in `src/appsec_review/config/owasp.py` (explicitly validating `parser_versions["asvs"]` and `["masvs"]`), either load the registered runtime skills via `load_runtime_skill` in `src/appsec_review/owasp_workbench/assessment.py` or remove the dead bindings from `pipeline/guidance/registry.json`, and update `guidance.py:18` off migrated persona names.
- **Effort**: `S (under a day)`
- **Already registered**: `T-147` registers declaring task/skill bindings for generated docs; new here is that the three runtime skills already registered in `registry.json` are never loaded at runtime (`skills=()`) and `OwaspSettings` skips `parser_versions` key validation.

#### C12-F14 `job_owasp_control_assessment` stays on legacy free-text gaps and unconditionally forces `COMPLETED_WITH_GAPS` via static disclaimers
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `src/appsec_review/jobs/job_owasp_control_assessment/job.py:394-398` omits `strict_gaps=True` (remaining in `LEGACY_FREE_TEXT_GAPS` at `tests/test_gap_contract.py:19`), and `publish` (`job.py:362-371`) unconditionally appends two hardcoded prose disclaimers (`"Source procedures establish only their named subjects..."` and `"Runtime/manual evidence ingestion and live-model efficacy are separate, unpassed gates."`) into `value["gaps"]`.
- **Impact**: Every run of `job_owasp_control_assessment` reports `COMPLETED_WITH_GAPS` with unstructured string gaps even when every selected control succeeded cleanly, blurring genuine run-time coverage failures (`max_batches` truncation, cell timeouts, reviewer dissent) with static architectural scope notes and violating the `producer-gap/1` contract.
- **Recommendation**: Keep static scope disclaimers in `value["limitations"]` only (do not union them into `value["gaps"]` at `job.py:371`), convert real operational/coverage gaps to `interchange.producer_gap` (`producer-gap/1`), enable `strict_gaps=True` in `job.py`, and remove `"job_owasp_control_assessment"` from `tests/test_gap_contract.py:19`.
- **Effort**: `M (days)`
- **Already registered**: `docs/reviews/appsec-system-review-2026-11-06.md` §3 item 1 registered migrating the legacy free-text gap list; new here is `job.py:362-371` copying static `limitations` into `gaps` so clean completion is impossible.

#### C12-F15 Unnecessary `schedule_after` barriers and dead roles, catalog tables, and inference hooks inflate C12
- **Kind**: `remove`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/job_threat_model_generation/datasets.py:80-83` sets `schedule_after=("job_owasp_control_assessment", "job_dependency_intelligence", "job_security_tagging")` even though none of those jobs is in `DECLARED_INPUTS` (`src/appsec_review/threat_model/index_view.py:79-90`); meanwhile `src/appsec_review/threat_model/reference.py:37-38,119-135`, `data/reference/threat-model/interaction-catalog.json:664-1160` (120 `dependency_categories` entries), `Asset` (`src/appsec_review/threat_model/contract.py:394-404`), and `LaneResult.unknowns` (`contract.py:488`, ignored by `assemble.py:307`) have zero production callers. In `owasp_workbench`, four of six roles in `src/appsec_review/owasp_workbench/guidance.py:12-26` (`component_classifier`, `applicability_router`, `evidence_verifier`, `result_adjudicator`), `characterize_components(inference=...)` (`src/appsec_review/owasp_workbench/engine.py:121,150-171`), and domain `"deployment_operations"` (`acquisition.py:167-170` never emits it) are dead in production.
- **Impact**: When enabled, `job_threat_model_generation` waits needlessly behind LLM-heavy `job_owasp_control_assessment` despite reading none of its outputs, while dead roles in `pipeline/guidance/registry.json:15-20` and ~500 lines of unused catalog/model scaffolding obscure what C12 actually executes.
- **Recommendation**: Drop `schedule_after` from `src/appsec_review/jobs/job_threat_model_generation/datasets.py:82`, delete the four unused OWASP roles and `characterize_components(inference=...)` from `guidance.py`, `engine.py`, and `pipeline/guidance/registry.json`, and either wire `LaneResult.unknowns` in `assemble.py:307` or remove unused fields until `T-107` implements them.
- **Effort**: `S (under a day)`
- **Already registered**: no.

#### C12-F16 Threat-model and OWASP documentation and docstrings contradict live consumer wiring and TOML configuration
- **Kind**: `doc-drift`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/job_threat_model_generation/job.py:5-6`, `docs/operations/threat-model-generation.md:27,138`, and `docs/architecture/dfd-and-threat-model-generation.md:450,733` state that no job or consumer reads `job_threat_model_generation`, directly contradicting `src/appsec_review/jobs/job_inference_security_review/datasets.py:77-84` and `src/appsec_review/review/behavior.py:199-256` (which are right). Separately, `docs/operations/owasp-control-assessment.md:53-74` documents `provider = "codex-cli"`, `model = "gpt-5.4"`, `timeout_seconds = 180`, and `retries = 2` and omits `max_source_lines`/`max_discovery_files`/`max_discovery_bytes`, whereas `appsec-review.toml:2675-2712` configures `claude-cli` / `claude-haiku-5-5`, `timeout_seconds = 120`, and `retries = 1`.
- **Impact**: Operators and repository agents reading the threat-model docs/docstring are told `job_threat_model_generation` has zero downstream effect when `job_inference_security_review` already consumes its handoff and logs a `behavior_model` gap whenever it is disabled; OWASP operators get wrong model, timeout, and retry defaults.
- **Recommendation**: Update `src/appsec_review/jobs/job_threat_model_generation/job.py:5-6`, `docs/operations/threat-model-generation.md`, and `docs/architecture/dfd-and-threat-model-generation.md` to describe `review/behavior.py` consumption, and reconcile `docs/operations/owasp-control-assessment.md` and `docs/architecture/owasp-control-workbench.md` with `appsec-review.toml` and the two active model roles.
- **Effort**: `S (under a day)`
- **Already registered**: no.

#### C12-F17 Unit tests miss >120-line HTTP route rejection, production-catalog role applicability, non-native threat models, >8-site flow truncation, and real config syntax
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/unit/job_owasp_control_assessment/test_subject_selection.py:57-69` tests `subjects(PROCEDURES[2], item)` on a >120-line file without running `run_batch`/`accept_obligations` (while `tests/test_owasp_assessment_job.py:29-33` uses a 3-line SQL file), `tests/test_owasp_assessment_job.py:390-411` checks `lead_eligible` in `qualification` mode without checking `not_applicable` drift from `component_roles: []` or `test_development_only` override in `assessment` mode, `tests/test_threat_model_generation_job.py:66-109` exercises only a 2-file CMake C fixture, and `tests/test_deployment_inventory.py:18-48` uses synthetic lowercase-only configs.
- **Impact**: Unit suites stayed green while masking four high/medium defects (`C12-F03`, `C12-F04`, `C12-F05`/`C12-F06`, and `C12-F09`) across realistic repository sizes, languages, and configuration files.
- **Recommendation**: Add focused unit regressions in `tests/unit/job_owasp_control_assessment/` (>120-line route batch through `run_batch`, `test_development_only` exclusion in `assessment` mode), `tests/test_threat_model_generation_job.py` (Python/Node/JVM build points, cross-language callee guard, >8 sites into `project_model`), and `tests/test_deployment_inventory.py` (`TimeZone`/`pg_stat_statements.track`, `listen [::];`, `http://unix:...`, `--`/`__` OCI tags).
- **Effort**: `M (days)`
- **Already registered**: no.

#### C12-F18 `mcp/owasp.py` and `WorkbenchIndex.query` do not verify snapshot alignment against the run's current `RetrievalCore` or redact free-text fields
- **Kind**: `weakness`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_owasp_control_assessment`
- **Evidence**: `src/appsec_review/mcp/owasp.py:30-42` and `src/appsec_review/owasp_workbench/indexes.py:131-168` verify shard SHA-256 digests against `data/indexes/owasp-workbench/latest.json`, but unlike `src/appsec_review/indexing/products.py:1120-1127,1286-1305`, `WorkbenchIndex.query` neither checks `manifest["accepted_upstream_manifest"]` against the active `RetrievalCore` snapshot nor runs `redact()` over `rationale`, `assumptions`, and `hypotheses` before returning full deserialized JSON shards.
- **Impact**: Operator MCP queries via `query_owasp_workbench` can read stale OWASP shards from an earlier attempt after upstream re-indexing and receive unredacted worker free-text rationales while deserializing every matching shard file in memory on each call.
- **Recommendation**: Cross-check `accepted_upstream_manifest` against the run's current accepted upstream state when available in `src/appsec_review/mcp/owasp.py` and apply `evidence.redact()` when publishing shard text fields in `src/appsec_review/owasp_workbench/assessment.py` / `indexes.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no.
### C13 Model execution and worker guidance

**Active findings:** 16 (`1` critical, `5` high, `9` medium, `1` low).

Component C13 has strong structural bones: every live model transport disables provider tool execution, worker guidance enforces a single `governing-rules.md` authority with content-addressed run bundles, and `Execution` plus `JobBudget` emit deterministic call and reservation receipts. Three verified defects undermine confidentiality, injection resistance, and run completion today: target credentials bypass `secret-redaction/1` whenever workers, `expand`, `adjudication_judge`, or downstream PoC/remediation readers call `RetrievalCore.read_excerpt` or `read_source` (`C13-F01`), `JobBudget`'s default `time.time` wall clock aborts `job_inference_security_review` on sub-millisecond NTP/WSL2 clock adjustments (`C13-F02`), and both `claude-cli` and `copilot-sdk` collapse system guidance and untrusted target excerpts into one user message across every shipped profile (`C13-F03`). Transport and preflight gaps also let bad model settings fail hours into a run: `job_model_connectivity` strips `reasoning` effort before probing (`C13-F04`), `anthropic_api.send` emits invalid `thinking.budget_tokens` when `max_output_tokens <= 1024` (`C13-F05`), `Execution.retry` silently treats `error=None` as non-retryable `CONTRACT` and disables PoC schema repair (`C13-F06`), and Anthropic/Claude transports drop `cache_creation_input_tokens` from token caps (`C13-F07`). Finally, `route_stack` routes non-service libraries/CLIs and all Ruby targets to `generic` with a `routing_gap` (`C13-F10`), while 12 active build/SBOM worker files bypass `registry.json` frontmatter checks alongside 9 registered roles that never call a model (`C13-F13`).

**Strengths to preserve:**
- Tool-free model transports with explicit credential scrubbing: `claude-cli` forces `--safe-mode --tools "" --allowedTools ""` and strips `GH_TOKEN`/`GITHUB_TOKEN`/`COPILOT_GITHUB_TOKEN` (plus Anthropic API keys in subscription mode), `copilot-sdk` runs in an isolated empty temp directory with `excluded_tools=["builtin:*", "mcp:*", "custom:*"]` and `skip_custom_instructions=True`, and `anthropic-api` posts directly to `/v1/messages` without tool schemas (`src/appsec_review/inference/claude_cli.py:105-120`, `src/appsec_review/inference/copilot_sdk.py:55-68,124-137`, `src/appsec_review/inference/anthropic_api.py:25-46`).
- Single-source worker authority and fail-closed bundle composition: `governing-rules.md` holds shared trust and citation rules once, `compose_guidance` rejects authority-widening phrases, prohibited-action weakening, and ungranted tools before hashing, and `publish_guidance_bundle` pins immutable SHA-256 bundles under `data/guidance/<bundle-sha256>/` (`pipeline/prompt-fragments/governing-rules.md:1-66`, `src/appsec_review/guidance/compose.py:210-241,305-336`, `src/appsec_review/guidance/fragments.py:130-169`).
- Deterministic persona, stack, hunt-panel, and runtime-skill routing that records explicit `routing_gap` or `coverage_gap` reasons instead of silently narrowing coverage, with job-allowlisted skill loading (`src/appsec_review/guidance/routing.py:68-203`, `src/appsec_review/guidance/skills.py:72-97`).
- Bounded conversation execution and atomic reservation/settlement accounting: `Execution.call` enforces monotonic deadlines, call counts, request/response byte limits, and content-free `CallReceipt` persistence, while `JobBudget.reserve_call`/`settle_call` retain missing provider token reports as admission liabilities (`src/appsec_review/inference/execution.py:181-325`, `src/appsec_review/review/budget.py:576-665`).
- Unambiguous single-object JSON extraction in `parse_model_payload`, rejecting prose with multiple distinct schema candidates or mismatched schema identifiers (`src/appsec_review/inference/claude_cli.py:50-79`).
- `job_model_connectivity` separates required enabled models from disabled/optional models, refuses unwired checks at claim time, blocks fast on missing required models, and records unavailable optional models as `strict_gaps=True` `producer-gap/1` records (`src/appsec_review/jobs/job_model_connectivity/job.py:39-87,98`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_model_connectivity` | `data/configuration/resolved.json` and `data/configuration/manifest.json` (`CONTRACT.inputs = ()`) | `model_connectivity` (`model-connectivity.json`, `model-connectivity-handoff.json`), scheduled before `job_image_pin_verification` and `job_review_data_indexing` | `C13-F04` (strips `reasoning` effort before probing, missing unsupported model+effort combinations) and `C13-F09` (serial timeout multiplication) | rework |

#### C13-F01 Target credential literals bypass `secret-redaction/1` through `read_excerpt`, judge citations, downstream readers, and failure/recording artifacts
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/review/secret_redaction.py:3-13`; `src/appsec_review/review/package_view.py:165-169,344-348`; `src/appsec_review/retrieval/core.py:694-725`; `src/appsec_review/jobs/job_inference_security_review/teams.py:268-273`; `src/appsec_review/jobs/job_poc_generation/writer.py:362-378`; `src/appsec_review/inference/recording.py:56-79`; `src/appsec_review/runtime/execution_safety.py:301-312`. `secret_redaction.py` assumes `PackageView` is the only place target source lines reach a model and redacts only lines pre-flagged by `secret` scanner leads, whereas `RetrievalCore.read_excerpt` (called by worker `read_excerpt`/`expand` turns and by `ReviewContext.describe` for `adjudication_judge`), `WorkspaceReader.read_source`, `job_remediation_planning`'s reader, `job_target_analysis_plan`'s `read_document`, `inference/recording.py`, and `retain_failure` emit raw unredacted target text.
- **Impact**: Live API keys, tokens, and private keys in a target repository—even on the exact line a secret scanner already flagged and `PackageView` redacted—are sent verbatim to external LLM providers whenever a review worker expands or reads that entity, when the judge inspects cited rows, or when PoC/remediation/planning workers read nearby lines, and are written unredacted to disk when recording or failure retention is active.
- **Recommendation**: Apply `redact_source_line` (plus multi-line PEM block detection) in `RetrievalCore.read_excerpt` and `read_source_lines` (`src/appsec_review/retrieval/core.py`), `WorkspaceReader.read_source` (`src/appsec_review/jobs/job_poc_generation/writer.py`), `job_remediation_planning`, and `job_target_analysis_plan/job.py`, and pass persisted text in `src/appsec_review/inference/recording.py` and `src/appsec_review/runtime/execution_safety.py` through redaction before writing.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F02 Non-monotonic `time.time` in `JobBudget` aborts `job_inference_security_review` on sub-millisecond wall-clock adjustments
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/review/budget.py:159,417,441-443`; `src/appsec_review/review/cells.py:231-235`. `JobBudget.__init__` defaults `clock` to `time.time` (`CLOCK_REALTIME`) and `_transact` raises `ExecutionContractError("budget clock regressed")` on any strict inequality `now < state["timing"]["last_observed_at"]`, which `run_cell` treats as a fatal contract failure and re-raises out of the job.
- **Impact**: Routine sub-millisecond NTP slews or WSL2 Hyper-V host-clock resynchronizations under load abort an in-progress `job_inference_security_review` run instead of degrading or clamping jitter, losing active team work and blocking report publication.
- **Recommendation**: Anchor `JobBudget` in `src/appsec_review/review/budget.py` to an initial `time.time()` plus process-local `time.monotonic()` delta, clamp small cross-process clock skew (for example `< 5.0` seconds) to `state["timing"]["last_observed_at"]`, and reserve `ExecutionContractError("budget clock regressed")` for large backward jumps.
- **Effort**: `S (under a day)`
- **Already registered**: `T-083` registers `budget clock regressed` only as an unclassified unit-test failure in `tests/review/test_team_handler.py`; what is new is the verified product root cause in `src/appsec_review/review/budget.py:159,441-442` and that it can crash live production reviews.

#### C13-F03 `claude-cli` and `copilot-sdk` collapse trusted worker guidance and untrusted target content into one user message
- **Kind**: `weakness`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/inference/claude_cli.py:92-97,118-122,234`; `src/appsec_review/inference/copilot_sdk.py:114-143`; `src/appsec_review/inference/anthropic_api.py:31-46`; `docs/architecture/worker-prompt-contracts.md:45-58`. Only `anthropic_api.send` places `request.guidance_text` in `system` with `include_guidance=False`; both `claude_cli.send` and `copilot_sdk._send` serialize governing rules, role/persona guidance, and untrusted target source excerpts into a single user JSON blob, even though `claude_cli.py:234` already uses `--system-prompt`.
- **Impact**: Every shipped profile (`dev`, `prod`, `copilot-dev`, `copilot-prod`) uses `claude-cli` or `copilot-sdk`, so zero model calls in default or production runs benefit from provider-level system/user instruction hierarchy; hostile comments or strings in target code compete in the same `user` role as `governing-rules.md` to steer workers toward false `contradicts`/`decline` verdicts or wasted queries.
- **Recommendation**: Pass worker guidance via `--system-prompt` with `include_guidance=False` in `src/appsec_review/inference/claude_cli.py` and via `create_session`'s `system_message` setting in `src/appsec_review/inference/copilot_sdk.py`, matching `anthropic_api.send`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F04 Model preflight strips `reasoning` effort before probing, letting unsupported reasoning levels fail mid-run
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_model_connectivity`
- **Evidence**: `src/appsec_review/jobs/job_review_intake/job.py:141-177`; `src/appsec_review/jobs/job_model_connectivity/job.py:51-77`; `src/appsec_review/inference/copilot_sdk.py:86-97,111-113`; `src/appsec_review/inference/claude_cli.py:231-235`; `src/appsec_review/inference/__init__.py:66-68`. `configured_models()` drops `reasoning` when scanning `resolved.json`, `copilot_sdk._models` checks catalog availability without checking `model.supported_reasoning_efforts`, and `claude_cli.models` omits `--effort`; later, `copilot_sdk._send` raises `ValueError` on unsupported `request.reasoning`, which `infer()` wraps into a fatal `ExecutionContractError`.
- **Impact**: Any profile or overlay pairing a valid model with an unsupported `reasoning` level (`low`, `medium`, `high`, `xhigh`) passes both `job_model_connectivity` and `job_review_intake` cleanly and crashes hours later when that role (`judge`, `poc_writer`, `remediation_reviewer`, etc.) first executes.
- **Recommendation**: Keep `reasoning` on records returned by `configured_models()` in `src/appsec_review/jobs/job_review_intake/job.py`, pass `(model, reasoning)` pairs through `check_models` (`src/appsec_review/inference/__init__.py`), check `model.supported_reasoning_efforts` in `src/appsec_review/inference/copilot_sdk.py`, and include `--effort` in `src/appsec_review/inference/claude_cli.py:231-235`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F05 `anthropic_api.send` sets `thinking.budget_tokens >= max_tokens` when `max_output_tokens <= 1024` and starves compact JSON output budgets
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/inference/anthropic_api.py:20,28,39-44,172`; `appsec-review.toml:768-776`. `budget = min(_THINKING_BUDGETS.get(request.reasoning, 2048), max(1024, request.max_output_tokens - 1024))` unconditionally enables extended thinking with `budget >= 1024` even when `request.max_output_tokens <= 1024` (which `/v1/messages` rejects with HTTP 400 because Anthropic requires `max_tokens > thinking.budget_tokens`), and at `max_output_tokens = 2000` (`job_project_build`) consumes more than half of `max_tokens` for thinking; `anthropic_api.py` also ignores `ANTHROPIC_AUTH_TOKEN`.
- **Impact**: Switching a profile to `anthropic-api` fails any `<= 1024`-token call immediately with a non-retryable `ProviderError` and truncates valid structured JSON responses on tight output budgets (`job_project_build`, `lead_triager`), turning repairable build or triage work into gaps.
- **Recommendation**: In `src/appsec_review/inference/anthropic_api.py`, disable `"thinking"` when `request.reasoning == "none"` or `request.max_output_tokens <= 1024`, otherwise set `max_tokens = request.max_output_tokens + budget` so thinking does not cannibalize JSON output tokens, and check `ANTHROPIC_API_KEY` before falling back to `ANTHROPIC_AUTH_TOKEN` consistently or document key-only auth.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F06 `Execution.retry` silently treats `error=None` as non-retryable `CONTRACT`, disabling schema-repair retries in `job_poc_generation`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/inference/execution.py:141-148,209-213`; `src/appsec_review/inference/errors.py:55-66`; `src/appsec_review/jobs/job_poc_generation/writer.py:229-232,257-267,338-341`. Neither `Execution.retry` nor `RetryPolicy.allows` validates that `error` is a `BaseException` or `FailureCategory`; when `job_poc_generation`'s `_attempt` leaves `attempt.failure = None` on `ModelOutputError`, `malformed_turn`, and `final_result_rejected`, `failure_category(None)` returns `FailureCategory.CONTRACT` and `allows()` returns `False`.
- **Impact**: Callers that omit `error` on schema-validation failures silently lose all configured repair retries instead of failing loudly in tests; in `job_poc_generation`, `max_attempts = 2`, `retry_on_invalid_output = true`, and `attempt.repair_errors` never run a second attempt on malformed JSON or schema violations, degrading confirmed findings' PoC evidence to `writer_invalid` gaps.
- **Recommendation**: Reject `error` values that are neither `BaseException` nor `FailureCategory` with `ExecutionContractError` in `RetryPolicy.allows` (`src/appsec_review/inference/execution.py:141`), and set `attempt.failure = FailureCategory.SCHEMA` on all three invalid-output branches in `src/appsec_review/jobs/job_poc_generation/writer.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F07 `claude_cli` and `anthropic_api` drop `cache_creation_input_tokens`, undercounting billed input spend and bypassing token caps
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/inference/claude_cli.py:155-161`; `src/appsec_review/inference/anthropic_api.py:93-99`; `src/appsec_review/inference/execution.py:305-307`; `src/appsec_review/review/budget.py:475-479,510-513`. Both Anthropic transports map only `usage.get("input_tokens")` (uncached tail tokens) and `usage.get("cache_read_input_tokens")`, completely discarding `usage.get("cache_creation_input_tokens")` (which Anthropic bills at 1.25x input rate and which holds almost the entire prompt on `--no-session-persistence` cache-write turns).
- **Impact**: Per-turn `usage.input_tokens > request.max_input_tokens` checks in `Execution.call` and run-wide `max_input_tokens` admission in `JobBudget` see only the uncached tail (often `< 50` tokens on a 25,000-token prompt), allowing runs on `claude-cli` or `anthropic-api` to spend multiples of their configured input-token budget without stopping. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Partially addressed in `945bc3706`, `a537c313a`, and `da9d4d855`, which harden inference recording replay and uint64 schema bounds.]*
- **Recommendation**: Include `cache_creation_input_tokens` in `input_tokens` (or track `cache_creation_input_tokens` + `cache_read_input_tokens` explicitly on `Usage` and `ModelResult`) in `src/appsec_review/inference/claude_cli.py`, `src/appsec_review/inference/anthropic_api.py`, `src/appsec_review/inference/usage.py`, and `src/appsec_review/review/budget.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F08 `job_owasp_control_assessment` bypasses `builtin_registry` `infer` injection and omits `settings.models.reviewer` from shard fingerprints
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/runtime/registry.py:95,115,158`; `src/appsec_review/jobs/job_owasp_control_assessment/job.py:109-112,296-300`; `src/appsec_review/owasp_workbench/assessment.py:234`; `profiles/prod.toml:42-48`. `builtin_registry` registers `build_owasp_control_assessment` without `infer=infer` (falling back to live `appsec_review.inference.infer` while `assessment.py:234` wraps `recorded(infer)` a second time), and `job.py:298` hashes only `unit.job.config.settings["model"]` into `fingerprint_inputs`, omitting `settings["models"][typed.reviewer_profile]`.
- **Impact**: Offline test or parity harnesses calling `builtin_registry(infer=fake_infer)` silently hit live model providers if `job_owasp_control_assessment` executes, and changing only `settings.models.reviewer` (such as `claude-sonnet-5-5` vs `claude-opus-5-5` in `prod.toml`) fails to change published OWASP shard `fingerprint_inputs`.
- **Recommendation**: Register `partial(build_owasp_control_assessment, infer=infer)` in `src/appsec_review/runtime/registry.py:158`, drop the duplicate inner `recorded(...)` wrapper in `src/appsec_review/owasp_workbench/assessment.py:234`, and add `settings["models"][typed.reviewer_profile]` to `fingerprint_inputs` in `src/appsec_review/jobs/job_owasp_control_assessment/job.py:298`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F09 `claude_cli.models` and `anthropic_api.models` apply the full `timeout_seconds` per model rather than across the gate, including disabled models
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_model_connectivity`
- **Evidence**: `appsec-review.toml:556-559`; `src/appsec_review/jobs/job_model_connectivity/job.py:59-63`; `src/appsec_review/inference/claude_cli.py:230-238`; `src/appsec_review/inference/anthropic_api.py:175,187`. Both `claude_cli.models` and `anthropic_api.models` pass the entire `timeout_seconds` (`120` s) independently to every sequential model probe or alias lookup instead of sharing one monotonic deadline across `names` (unlike `copilot_sdk.models` at `copilot_sdk.py:173`), and `verify_configured_models` also probes `not_required` models from disabled jobs/roles.
- **Impact**: When `claude` CLI or Anthropic's endpoint stalls with 3–4 configured models (including models named only on disabled jobs), `job_model_connectivity` blocks for `N * 120` s instead of `120` s, and `job_review_intake.model_preflight` repeats the same `N` paid `claude -p` probes immediately afterward.
- **Recommendation**: Enforce a single `deadline = time.monotonic() + timeout_seconds` across the loop in `src/appsec_review/inference/claude_cli.py:230` and `src/appsec_review/inference/anthropic_api.py:175`, passing remaining seconds to each call and marking remaining models timed out when the budget expires.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F10 `stack-routing/1` gates managed-language profiles on `SERVICE_COMPONENTS` and lacks Ruby stack and build-worker guidance
- **Kind**: `missing`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/guidance/routing.py:102-121,156-175`; `src/appsec_review/guidance/workers.py:61`; `pipeline/guidance/registry.json:63-80`. `route_stack` enters `MANAGED_STACKS` only when `comps & SERVICE_COMPONENTS` is non-empty (whereas C/C++ at line 147 routes on `c_family` unconditionally), and Ruby (`lang:ruby`) has neither a stack fragment in `MANAGED_STACKS`/`pipeline/prompt-fragments/stacks/` nor a `build-engineer-ruby` family in `BUILD_FAMILIES`.
- **Impact**: Every Python, Rust, Go, Java/Kotlin, C#, JS/TS, or PHP library, CLI, parser, SDK, or game component outside the seven `SERVICE_COMPONENTS` tags—and every Ruby repository—falls back to `generic.md` with `routing_gap = True`, depriving review workers of language-specific sink/invariant guidance (`unsafe` Rust, Python deserialization/subprocess, JVM/Node deserialization, Rails mass-assignment/ERB/ActiveRecord sinks).
- **Recommendation**: Allow `MANAGED_STACKS` in `src/appsec_review/guidance/routing.py:156-165` to match on `langs` even when `comps & SERVICE_COMPONENTS` is empty, and add a `ruby_service.md` stack fragment (plus `ruby` build-engineer role if Ruby container build repair is supported) in `pipeline/prompt-fragments/` and `pipeline/guidance/registry.json`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F11 Review role fragments teach `expand` in examples while omitting it from `## Tools` and stripping `EXPAND_TOOL` from the capability receipt
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `pipeline/prompt-fragments/governing-rules.md:26`; `pipeline/prompt-fragments/roles/red_team_analyst.md:19-20,56`; `pipeline/prompt-fragments/roles/hypothesis_hunter.md:20-21,39`; `pipeline/prompt-fragments/roles/blue_team_refuter.md:18-19,62`; `pipeline/prompt-fragments/roles/adjudication_judge.md:18-19,57`; `src/appsec_review/jobs/job_inference_security_review/teams.py:182-185`; `src/appsec_review/guidance/compose.py:217-219`. `teams.py` strips `EXPAND_TOOL` from `receipt["granted_tools"]` so `compose_guidance` will not reject `granted - set(role_doc.tools)`, even though `CellCapability.public_view()` (`cells.py:394`), `_request_example` (`cells.py:364`), and the roles' own `## Examples` instruct workers to call `{"tool": "expand", ...}`.
- **Impact**: Workers receive contradictory authority instructions—`governing-rules.md` states "Request only tools in your capability receipt", while the rendered capability receipt omits `expand` and `task_input.capability.tools` includes it—causing strict models either to shun `expand` (burning extra queries on manual lookups) or to distrust the capability receipt.
- **Recommendation**: Add `expand` to the five review roles' `tools` lists in `pipeline/guidance/registry.json` and `pipeline/prompt-fragments/roles/{hypothesis_hunter,red_team_analyst,blue_team_refuter,independent_verifier,adjudication_judge}.md`, and remove the `name != EXPAND_TOOL` filter in `src/appsec_review/jobs/job_inference_security_review/teams.py:182-183`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F12 Legacy `ModelRequest` sends duplicate role and persona markdown in planning/build-repair prompts and couples unrelated jobs to planning allowlists
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/inference/request.py:16-39,98-115`; `src/appsec_review/guidance/workers.py:100-126`; `src/appsec_review/jobs/job_target_analysis_plan/job.py:390-415`; `src/appsec_review/jobs/job_project_build/job.py:725-768`; `src/appsec_review/jobs/job_dependency_intelligence/inference.py:169-180`. `publish_worker_guidance` already renders `governing_rules`, `role`, `persona`, `task`, and `procedure` into `request.guidance` (`prompt["task"]`), yet `job_target_analysis_plan` and `job_project_build` also populate `ModelRequest.persona` and `ModelRequest.role` with the full markdown files, while `job_dependency_intelligence` and `job_post_build_security_assessment` pass five empty planning allowlist tuples (`allowed_scanners=()`, etc.).
- **Impact**: Every planning and build-image-repair call pays double input tokens for role and persona markdown, `anthropic_api.send` (`anthropic_api.py:37-38`) places only `persona + role` in `system` while leaving `governing-rules.md` and the runtime skill in the user message, and four jobs maintain dead planning fields on `ModelRequest`.
- **Recommendation**: Migrate `job_target_analysis_plan`, `job_project_build`, `job_post_build_security_assessment`, and `job_dependency_intelligence` to `ReviewModelRequest` (moving planning allowlists into `task_input`), and delete `ModelRequest` and `plan_prompt` from `src/appsec_review/inference/request.py`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C13-F13 Guidance registry split-brain leaves 12 active worker files outside `registry.json` frontmatter checks while keeping 9 non-dispatched roles
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `pipeline/guidance/registry.json:4-62,99-126`; `src/appsec_review/guidance/workers.py:41-98,130-139`; `src/appsec_review/owasp_workbench/guidance.py:66`. Twelve live model-facing files (`pipeline/prompt-fragments/personas/devops-engineer.md`, nine `pipeline/prompt-fragments/roles/build-engineer-*.md` files, and `pipeline/guidance/tasks/dependency-intelligence/{native_component_curation,native_metadata_investigation}.md`) lack `path` entries in `registry.json` or YAML frontmatter and are loaded via special-case filenames in `workers.py` (while `post_build` uses a one-line string instead of a role file); conversely, 9 of 29 registered roles (`DETERMINISTIC_ROLES | NON_DISPATCHED_ROLES`) and 5 markdown files (`completeness_reviewer.md`, `finding_adjudicator.md`, `independent_scorer.md`, `poc_designer.md`, `poc_verifier.md`) never reach any model, and `assignment.domain_persona` still maps to deprecated `"api_web"`/`"deployment_operations"` IDs via `persona_migrations`.
- **Impact**: Specialized build and native-SBOM prompts bypass the `parse_role_text`/`parse_fragment_text`/`parse_task_text` schema and coverage validators that protect review cells, while 5 dead role files (naming unimplemented model outputs and tools) obscure which prompts actually govern workers.
- **Recommendation**: Register `path` and frontmatter for all active specialized worker roles, personas, and tasks in `pipeline/guidance/registry.json`, delete the 5 non-dispatched role markdown files and remove `DETERMINISTIC_ROLES`/`NON_DISPATCHED_ROLES` from model-guidance `registry.json`, and inline `"network_api_surface"`/`"cloud_container_deployment"` in `assignment.domain_persona` so `persona_migrations` can be removed.
- **Effort**: `M (days)`
- **Already registered**: `docs/reviews/appsec-system-review-2026-11-06.md` (§4) noted unwired guidance entries before `workers.py` existed; what is new is that `workers.py` bypassed `registry.json` paths/frontmatter for 12 active files and exempted 9 non-model roles via `DETERMINISTIC_ROLES`/`NON_DISPATCHED_ROLES` instead of reconciling `registry.json`.

#### C13-F14 `inference.infer` hardcodes v3 planning error rewriting that strips `raw_response` before `retain_failure`, alongside dead v2 parser fallback and dead `openai_api.py`
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/inference/__init__.py:24-28,42-88,91-96,121-123`; `src/appsec_review/runtime/registry.py:124-139`; `src/appsec_review/inference/claude_cli.py:67-73`; `src/appsec_review/inference/openai_api.py:1-66`. `infer()` checks `request.schema == "appsec-review/target-analysis-proposal/3"` and replaces `ModelOutputError(str(exc), raw_response=..., rejected_output=...)` with a bare `ModelOutputError("planning model output could not be decoded")` before calling `safety.retain_failure`, duplicating `planning_model()` in `runtime/registry.py`; `parse_model_payload` still normalizes obsolete `"appsec-review/target-analysis-proposal/2"`, and `openai_api.models` calls `https://api.openai.com/v1/models` only for `check_models` to mark every OpenAI model `available: False` because `"openai"` is not in `PROVIDERS`.
- **Impact**: When `job_target_analysis_plan` receives malformed model output in a safety-guarded run, `data/execution-failures/*.json` records `"raw_response": null`, slowing run triage; meanwhile `openai_api.py` and the `/2` schema branch keep dead external-network and parser paths alive solely for stale v2 unit fixtures (`tests/test_claude_cli_inference.py:10`, `tests/test_anthropic_inference.py:73`).
- **Recommendation**: Retain the original `exc.raw_response` when recording planning failures in `src/appsec_review/inference/__init__.py` and consolidate planning error translation into one boundary, delete the `"appsec-review/target-analysis-proposal/2"` branch in `src/appsec_review/inference/claude_cli.py:67-73` (updating v2 test constants to `/3`), and remove `src/appsec_review/inference/openai_api.py` plus `"openai"` in `MODEL_CHECKS` until an OpenAI transport exists.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C13-F15 Unit suites miss `active_v2` clock skew, `anthropic_api` `<= 1024`-token requests, reasoning-effort preflight mismatches, and retrieval-path secret redaction
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/review/test_budget.py:74-135`; `tests/test_anthropic_inference.py:19-69`; `tests/test_copilot_inference.py:1-220`; `tests/unit/job_model_connectivity/test_steps.py:1-265`. `test_budget.py` exercises thread/process concurrency only in `wall_clock_v1` with non-regressing clocks; `test_anthropic_inference.py` tests only `max_output_tokens=2048`; `test_steps.py` stubs `check_models` without `reasoning` validation; and no unit test verifies that `RetrievalCore.read_excerpt` or `ReviewContext.describe` redacts secrets on lines present in `PackageView.secret_lines`.
- **Impact**: High- and critical-severity regressions in credential redaction, budget clock monotonicity, Anthropic extended-thinking bounds, and Copilot/Claude reasoning preflight pass unit CI cleanly and surface only during live reviews.
- **Recommendation**: Add focused `< 1 s` unit tests in `tests/review/test_budget.py` (`active_v2` negative clock jitter), `tests/test_anthropic_inference.py` (`max_output_tokens=512` and `cache_creation_input_tokens`), `tests/test_copilot_inference.py` / `tests/unit/job_model_connectivity/test_steps.py` (unsupported `reasoning` effort), and `tests/review/` (`read_excerpt`/`describe` on a secret line).
- **Effort**: `S (under a day)`
- **Already registered**: `T-083` tracks classifying `test_team_handler.py` and `test_judge.py`; the missing unit regressions for `anthropic_api` thinking/cache tokens, reasoning preflight, and retrieval secret redaction are new.

#### C13-F16 `model-profiles.md` omits three allowlisted model tables and `worker-prompt-contracts.md` overstates system-channel separation
- **Kind**: `doc-drift`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `docs/operations/model-profiles.md:28-43`; `src/appsec_review/config/loader.py:778-820`; `profiles/prod.toml:42-68`; `docs/architecture/worker-prompt-contracts.md:45-58`. `model-profiles.md` omits three profile-allowlisted model settings (`jobs.job_owasp_control_assessment.settings.models.reviewer`, `jobs.job_remediation_planning.settings.writer`, and `jobs.job_remediation_validation.settings.reviewer`, while `loader.py:778` still says "the five model-calling jobs"), and `worker-prompt-contracts.md` states guidance rides in a separate system channel when available even though `claude_cli.py` and `copilot_sdk.py` inline it in the user payload.
- **Impact**: Operators writing profile overlays from `docs/operations/model-profiles.md` leave OWASP reviewer and remediation models on `dev` defaults unintentionally, and maintainers reading `worker-prompt-contracts.md` assume CLI/Copilot system-prompt isolation is already wired.
- **Recommendation**: Update `docs/operations/model-profiles.md` and the docstring in `src/appsec_review/config/loader.py:778` to list all 16 allowlisted model tables across all 8 model-calling jobs, and bring `claude_cli.py`/`copilot_sdk.py` and `docs/architecture/worker-prompt-contracts.md` into agreement (`C13-F03`).
- **Effort**: `S (under a day)`
- **Already registered**: no
### C14 The review protocol

**Active findings:** 20 (`2` critical, `6` high, `10` medium, `2` low).

C14 has a disciplined structural spine—deterministic R5 adjudication, byte-checked blind verification, append-only hash-chained ledger shards, and hash-verified handoffs—so models never directly decide claim states, severities, or ship-blocking status. However, concrete mismatches across its evidence, scoring, and accounting policies currently undermine both recall and calibration: `SECRETS` claims, non-taint `AUTHN`/`AUTHZ`/`RACE` flaws, and any `MEMORY_AND_INPUT` bug outside CodeQL-graph scopes can never reach `confirmed`, while `resolve_relation` conversely lets a dominating, capacity-bounding `guard_fact` confirm a claim if cited as `supports`. In scoring and ship-block policy, `application_risk_matrix/3` adds positive floor points for missing factors (`low` is unreachable; `confirmed` configuration/supply-chain findings stay `unrated`), and `ship_block.decide` downgrades findings whose `[severity_floor, severity_ceiling]` is guaranteed `high`–`critical` to `decision_pending`. Meanwhile, `_run_rounds` attaches unconditional package-subject coverage gaps to every launched package, making `PoolOutcome.COMPLETE` unreachable and triggering `DEGRADED` and `review_incomplete` on clean runs, and the attack-chain stage runs up to 17 multi-turn LLM cells even when `continuity_producers = []` guarantees zero verified chains. Fixing guard-support polarity, obligation/admissibility alignment, interval scoring/ship-block math, and unconditional package-gap accounting will immediately lift verified finding yield and restore honest coverage reporting.

**Strengths to preserve:**
- Deterministic R5 adjudication (`obligation-rules/2` + `adjudication-rules/1`) separates `confirmed` from `supported`, gives direct contradictions precedence, and keeps LLM judge verdicts (`provenance="judge"`) strictly out of state transitions (`src/appsec_review/review/adjudication.py:112-235`).
- Byte-level blind-verifier enforcement (`R6`) builds the verifier input from claim identity fields and the package alone (`statement=False`), scans actual wire-request bytes for red/blue narratives, and requires fresh direct citations per required predicate (`src/appsec_review/jobs/job_inference_security_review/teams.py:1032-1044,1420-1445`, `src/appsec_review/review/independence.py:61-99`).
- Re-resolved, content-hashed evidence relations (`evidence.resolve_relation`) ignore model-asserted payloads, re-read accepted entity metadata and source/pseudo-C anchors from `RetrievalCore`, and convert missing or truncated targets into named `evidence_gap` records (`src/appsec_review/review/evidence.py:216-298`).
- Per-package capability scoping (`capability.py` + `cells.py`) restricts every worker turn to a closed tool schema, entity allowlist, query/turn budget, and repeated-denial circuit breaker (`MAX_IDENTICAL_DENIALS = 2`) with recorded security events (`src/appsec_review/review/capability.py:296-390`, `src/appsec_review/review/cells.py:518-560`).
- Commutative shard-merged hash-chained ledgers (`merge_verified` checks forward vs. reverse merge equality) paired with `exact_accounting` guarantee every expected cell, package, claim, lead, and evidence request has one terminal outcome (`src/appsec_review/jobs/job_inference_security_review/stages.py:62-68`, `src/appsec_review/review/accounting.py:160-265`).
- Accepted-handoff re-verification (`jobs/accepted_review.py`) cryptographically verifies shard hashes, finding/score packages, and attack-chain artifacts before C15/C16 consumers read them (`src/appsec_review/jobs/accepted_review.py:124-260`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_inference_security_review` | `job_review_data_indexing` (`accepted-index-set.json`, indexed shards, pinned feeds), `job_owasp_control_assessment`, optional `job_threat_model_generation`; declares unused `REQUIRED` `job_review_package_assembly` | `accepted_review` (`accepted.json`), `finding_packages`, `score_packages`, `ledger_shards`, `lead_triage`, `attack_chains`, `coverage_matrix`, `poc_basis`, `chain_seeds` | `C14-F01` (syntactic file/line anchor checking without semantic predicate/guard-polarity verification; `T-152` `warrants.py` in flight) and `C14-F03` (budget/truncation blind spots) | rework |

#### C14-F01 `resolve_relation` accepts bounding `guard_fact` and `range_fact` citations as `supports` for `missing_or_ineffective_guard`
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/review/evidence.py:265-282`; `src/appsec_review/review/scoring/factors.py:397-413,441-445`. `resolve_relation` calls `guard_relation_kind` (which checks `fact_bounds_destination`) only when `kind is RelationKind.CONTRADICTS`, leaving a `SUPPORTS` citation of a dominating, capacity-bounding `guard_fact` as `DIRECT_FOR_MAPPED_PREDICATE`, whereas `GuardAbsentExtractor` in `factors.py` already checks `_effective_guard` and drops that exact relation during scoring.
- **Impact**: When a package contains an effective bounds check (`G1`) and both red and the blind verifier mistakenly cite `G1` under `supports` for `missing_or_ineffective_guard`, `adjudicate` marks the predicate `satisfied` and promotes a sanitized non-bug to `confirmed` (while `factors.py` simultaneously treats `guard_absent` as missing). *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Partially addressed in `c12d9ef45` and `f881795d8` (`T-152`), which add `src/appsec_review/review/warrants.py` (`predicate-warrants/1` proposition and guard polarity validator) and wire opt-in predicate warrants into R5 adjudication and scoring; default-on mandatory warrant enforcement across all confirmed findings remains open.]*
- **Recommendation**: Apply the existing guard/range effectiveness check (`fact_bounds_destination` / `_effective_guard`) to `RelationKind.SUPPORTS` in `src/appsec_review/review/evidence.py` so a dominating bounding guard cited as support downgrades to `QUALIFIES` (or `ANALYST_ASSESSED`) instead of `DIRECT_FOR_MAPPED_PREDICATE`, and add a regression in `tests/review/test_guard_bounds_mapping.py`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-152` (`docs/reviews/2026-11-13-triage-verifier-review.md` §G2); new: `T-152` is currently `blocked` behind `T-150`, yet the exact check already exists in `src/appsec_review/review/scoring/factors.py:397-413` and causes an active adjudication-vs-scoring contradiction on false confirmations today.

#### C14-F02 Multi-round `_triage` omits round-1+ red cells from `origin_cell_ids`, leaks rejected claims into `result.claims`, and burns round-1+ caps on refuted claims
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/jobs/job_inference_security_review/teams.py:920-926,1333-1375,1388-1416`. `_triage` appends every unseen claim to `result.claims` at line 1344 before the hunt `unresolvable_citation` filter (lines 1346-1355) and `claims_per_package_cap` slice (lines 1361-1367), never merges new `origin_cell_ids` into `result.claims` when `claim_id in existing` across rounds, and computes `remaining = max(0, cap - len(previous_admitted))` over all prior admitted claims even if round 0 refuted them.
- **Impact**: When `rounds.max_rounds > 1`, round-0 vs. round-1 red cells on the same claim are evaluated in separate `group["cells"]` slices (`_review` at lines 1391, 1408 checks only the current round's `group["cells"]`, missing round-0 red cells on round-1 re-verification and omitting round-1 `origin_cell_ids` from the persisted `Claim`), allowing non-distinct models or leaked round-0 red narratives to bypass R6 checks; meanwhile, rejected/over-cap claims enter `_round_state` and ledger proposals, and refuted round-0 claims block all round-1+ variant claims once `cap` is reached.
- **Recommendation**: In `src/appsec_review/jobs/job_inference_security_review/teams.py`, append to `result.claims` only after `admitted` is selected, union `origin_cell_ids` and prior red narratives/actors across all rounds in `TeamResult` before calling `_review` and `_plan_judges`, and count only non-refuted active claims toward `remaining`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F03 `obligation-rules/2` and `predicate-admission/2` make `confirmed` unreachable for `SECRETS`, non-taint `AUTHN`/`AUTHZ`/`RACE` flaws, and non-CodeQL-graph scopes
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/review/obligations.py:92-106,130-137`; `src/appsec_review/review/admission.py:72-95`; `src/appsec_review/review/tool_rules.py:55-66`; `src/appsec_review/graph/contract.py:187-196`; `tests/review/test_predicate_admission.py:276-282`. `REQUIRED_BY_FAMILY[SECRETS]` requires `missing_or_ineffective_guard`, for which every source/artifact entity kind is `ANALYST_ASSESSED`/`INDIRECT`, `tool_rules.RULES` maps `secret` (`gitleaks`), `source_sast`, `config_scanner`, and `codeql` only to `affected_construct` (or `source_to_sink_reachability`), and CodeQL `guard_fact` requires a taint `SinkClass` that secrets and missing-authz routes lack; similarly, `attacker_input_control` is `DIRECT` only for CodeQL `entry_point`/`dataflow_path` graph facts.
- **Impact**: 100% of hardcoded-secret findings (unless paired with an unrelated `owasp_control` lead), missing-authentication/authorization/CSRF/IDOR/race bugs without a taint sink, secrets outside the 6-CWE `SECRET_CWES` list, and every `MEMORY_AND_INPUT` bug in scopes without CodeQL graph export (buildless/SARIF-only or unsupported languages) are structurally capped at `supported` in `verification_backlog` and can never confirm, block shipping, enter `remediation_intake`, or reach `poc_candidates`.
- **Recommendation**: In `src/appsec_review/review/obligations.py` and `src/appsec_review/review/tool_rules.py`, add a `secret_exposure` member to `SecurityPredicate`, require `(AFFECTED_CONSTRUCT, CONFIGURATION_ENABLES)` or map `secret` observations/shipping scope for `SECRETS`, define an access-control/concurrency obligation family in `REQUIRED_BY_FAMILY` that does not require `source_to_sink_reachability` when no sink applies, and map CodeQL `path` observations in `tool_rules.py:56` to `attacker_input_control` when SARIF source nodes exist.
- **Effort**: `M (days)`
- **Already registered**: no

#### C14-F04 Unconditional package-subject gaps in `_run_rounds` make `PoolOutcome.COMPLETE` unreachable and mark clean runs `DEGRADED` and `review_incomplete`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/jobs/job_inference_security_review/teams.py:946-979`; `src/appsec_review/review/accounting.py:137-145,217,231-237`; `appsec-review.toml:2861,2901-2903`. On every launched package, `_run_rounds` sets `stable = 0` on round 0 (`previous is None`), breaks at `max_rounds = 1` with `stop = "max_rounds"`, and unconditionally appends both `follow_up_cutoff:max_rounds` and `cross_package_and_cross_lane_variant_seeds_unavailable` with `subject_id = work.package_id`, causing `accounting.py:217` to put 100% of `expected_packages` into `gapped_packages` (unlike `teams.py:764-795`, which namespaces routing/strategy gaps under `f"{work.package_id}:..."`).
- **Impact**: `handoff.status == "COMPLETE"` and `ProducerStatus.SUCCEEDED` are unreachable on any non-empty run; worse, in a healthy 1-red-cell-per-package lead lane with zero cell errors and few claims, `gap_ratio = packages / (cells + packages)` approaches `0.50 > incomplete_gap_ratio (0.20)`, setting `review_incomplete = True` and masking genuine cell timeouts or budget drops.
- **Recommendation**: In `src/appsec_review/jobs/job_inference_security_review/teams.py:975-979`, emit `follow_up_cutoff` only when `max_rounds > 1` actually cut off pending follow-up work (or scope design-limitation notes to a run/sub-package subject like `f"{work.package_id}:variant_scope"` instead of `work.package_id`), and add a clean-run `PoolOutcome.COMPLETE` regression in `tests/review/test_accounting.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F05 `application_risk_matrix/3` interval scoring adds positive floor points for missing factors, making `low` unreachable and leaving confirmed configuration/supply-chain findings `unrated`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/review/scoring/risk_model.py:124-138,180-210`; `src/appsec_review/review/scoring/factors.py:66-76`; `src/appsec_review/review/scoring/application_matrix_v3.py:122-145`. `SCALES[TAINT_PATH][0]` is `"code_evidence"` (`10` pts) and `SCALES[GUARD_ABSENT][0]` is `"code_evidence"` (`15` pts) with no `0`-point state, so when those factors are missing (`no counted direct support`), `DimensionModel.interval()` adds `+10` and `+15` to `floor`, giving every claim `floor >= 45 >= bands.medium (40)`.
- **Impact**: Contradicting `risk_model.py:180-181`, the `"low"` exploitability rating and the entire `"low"` column of `technical_severity` are mathematically unreachable; simultaneously, every `confirmed` `CONFIGURATION` or non-KEV `SUPPLY_CHAIN` finding (whose obligation family does not use `taint_path`, `attacker_control`, or `guard_absent`) spans `floor = 65` (`medium`) to `ceiling = 120` (`high`) unless tagged `public`, leaving `technical_severity.rating = None` (`unrated`).
- **Recommendation**: Add `0`-point floor baselines for absent/unproven evidence factors in `src/appsec_review/review/scoring/risk_model.py` (so missing support contributes `0` to `floor`), and scope factor applicability by `obligation_family` in `src/appsec_review/review/scoring/application_matrix_v3.py` so predicates not owed by a `confirmed` family (`CONFIGURATION`, `SUPPLY_CHAIN`, `SECRETS`, `CRYPTOGRAPHY`) do not widen its exploitability interval into `unrated`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C14-F06 `ship_block.decide` ignores `[severity_floor, severity_ceiling]` when both endpoints qualify as ship-blocking
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/review/ship_block.py:147-180`; `src/appsec_review/jobs/job_inference_security_review/stages.py:466-481`. `stages.py` populates `inputs.severity_floor` and `inputs.severity_ceiling` on `ShipBlockInputs`, and `ShipBlockDecision.record` serializes them into `finding-package/2`, but `ship_block.decide` checks only `inputs.technical_severity in settings.blocking_technical_severities` (`None -> False`).
- **Impact**: A `confirmed` `critical`-impact finding (for example `CWE-78` or `CWE-89` where `exploitability` spans `["medium", "high"]` due to a missing tag or numeric guard factor) has `severity_floor = "high"` and `severity_ceiling = "critical"`—meaning every possible resolution is in `("high", "critical")`—yet `ship_block.decide` downgrades it from `ship_blocking` to `decision_pending`.
- **Recommendation**: In `src/appsec_review/review/ship_block.py:150-175` (and the `decision_pending` `allOf` clause in `docs/schemas/inference-security-review/finding-package.schema.json:378-395`), treat `technical_severity_qualifies` as `True` when `inputs.technical_severity in blocking` OR `inputs.severity_floor in blocking` (by matrix monotonicity, if `severity_floor` blocks, every point up to `severity_ceiling` blocks).
- **Effort**: `S (under a day)`
- **Already registered**: no (Deduplicated in headline totals under `C02-F06`: Single-model `dev` and `copilot-dev` profiles collapsing role distinctness (`verifier_model_distinct=False`).)

#### C14-F07 `adapt_graph_request` queries `RetrievalCore` before `capability.authorize`, crashing package teams on `RetrievalGap` and rejecting v2 package labels
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/review/cells.py:521-565`; `src/appsec_review/review/cell_retrieval.py:122-166`; `src/appsec_review/review/capability.py:312-358`. `_retrieve` calls `adapt_graph_request(core, request)` at line 521 before `capability.authorize(...)` at line 522; `_map_subject` calls `core.find(...)` catching only `(ValueError, LookupError)` (whereas `RetrievalGap` is caught only inside the `try` block at lines 550-565), and neither `adapt_graph_request` nor `capability.authorize` resolves v2 short labels (`K1`, `G1`, `F1`) on `query_code_graph` `subject`.
- **Impact**: Any cell—even one denied `query_code_graph`, out of query budget, or probing an out-of-scope `asr:...` identity—triggers uncharged `core.find` reads before authorization; if the index shard raises `RetrievalGap`, the uncaught exception aborts the entire package team (`teams.py:886`) instead of recording a bounded retrieval gap; meanwhile, workers given label-addressed v2 packages waste scarce query budget failing `query_code_graph(subject="K1")`.
- **Recommendation**: Move `adapt_graph_request` after tool/budget/label resolution inside the `RetrievalGap`-guarded block in `src/appsec_review/review/cells.py`, resolve `PackageView` labels on `IDENTITY_PARAMETERS` in `src/appsec_review/review/capability.py:317-335`, and verify the mapped target identity still lies in `capability.entity_scope`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F08 Stale MITRE CWE pins drop hash-verified `entries` from `CweReference.accepted_ids`, stripping valid hunt CWEs and breaking impact derivation
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/review/references.py:67-69,165-171`; `src/appsec_review/review/claims.py:98-109`; `src/appsec_review/jobs/job_inference_security_review/job.py:371-376`. When `pin.get("stale")` is `True`, `load_cwe_reference` loads all ~940 hash-verified SQLite `entries` and comments that *"a stale catalog still names real weaknesses"*, yet returns `_unavailable(..., source="fallback")`; `CweReference.accepted_ids` (`references.py:68`) then ignores `self.entries` whenever `self.source != "mitre_catalog"`, shrinking `accepted_cwe_ids` to scanner-lead CWEs plus the 47-CWE `CROSSWALK`.
- **Impact**: On any offline or stale-feed run, `normalize_claim` strips `weakness_cwe` to `None` on every hunt finding outside those ~47 CWEs (e.g., `CWE-611` XXE, `CWE-94` code injection, `CWE-134` format string, `CWE-295` cert validation, `CWE-347` JWT/signature bypass, `CWE-1321` prototype pollution), colliding distinct CWE claims onto `weakness_cwe=None` and causing `ImpactClassExtractor` (`factors.py:552`) to fail with `"claim names no weakness_cwe"`, leaving valid findings `unrated` and `decision_pending`. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Partially addressed in `08d50a742`..`324dc1fc3` (`T-150` closed), which wires protected `decision-audit` artifacts into `job_final_publication_gate` and `job_dossier_publication`.]*
- **Recommendation**: Change `CweReference.accepted_ids` in `src/appsec_review/review/references.py:68-69` to `return frozenset(self.entries) if self.entries else self.fallback_ids` while keeping `self.gap` (`mitre_stale_feed`) recorded in the lane/handoff artifacts.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F09 `independent_verifier.require_distinct_from_roles` is parsed in TOML but ignored, leaving blue and verifier on the same model in production profiles
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `appsec-review.toml:3175-3178`; `src/appsec_review/config/inference_review.py:276,574-589`; `src/appsec_review/jobs/job_inference_security_review/teams.py:1391`; `profiles/prod.toml:22-25`; `profiles/copilot-prod.toml:42-48`. TOML configures `roles.independent_verifier.require_distinct_from_roles = ["hypothesis_hunter", "red_team_analyst", "blue_team_refuter"]`, and `RoleSettings` parses it, but `verifier_distinctness()` and `teams.py:1391` hardcode `RED_ROLES` only (`hypothesis_hunter`, `red_team_analyst`) and never read `independent_verifier.require_distinct_from_roles`.
- **Impact**: Both `profiles/prod.toml` and `profiles/copilot-prod.toml` bind `blue` and `verifier` to the exact same model (`claude-sonnet-4-6`) with zero warning (`verification.distinct = True`), silently violating the configured TOML distinctness rule and sharing correlated blind spots on refutation vs. verification.
- **Recommendation**: Either enforce `roles[Role.INDEPENDENT_VERIFIER].require_distinct_from_roles` in `src/appsec_review/config/inference_review.py:574-589` and `src/appsec_review/jobs/job_inference_security_review/teams.py:1391` (and diversify `blue` vs. `verifier` in `profiles/prod.toml` and `profiles/copilot-prod.toml`), or remove `"blue_team_refuter"` and the unused `require_distinct_from_roles` field from `independent_verifier` so configuration matches Decision 2.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F10 Attack-chain stage runs up to 17 LLM cells when `continuity_producers = []`, slices candidate pairs by `claim_id` SHA-256 prefix, and misattributes telemetry
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `appsec-review.toml:3048-3056`; `src/appsec_review/jobs/job_inference_security_review/chains.py:66-68,121-225,249-358`; `src/appsec_review/review/attack_chains.py:438-455`; `src/appsec_review/jobs/job_inference_security_review/teams.py:517,535`. With default `continuity_producers = []` (no producer in `src/` emits `chain-continuity-fact/1`), `chains.compose` still runs `chain_composer` plus up to 8 `chain_refuter` and 8 `chain_weakest_link_verifier` cells whenever `>= 2` claims are supported/confirmed, only for `resolve_edge(..., producers=())` to discard every citation; additionally, `admitted_pairs` takes `islice` of `claim-<sha256>` pairs (`max_expansions = 100`, capping pairs to the first ~5 lexicographic SHA-256 claim ids once `>= 25` claims exist and rejecting `seed_hints` outside those pairs at line 183), and `_run_cell` reuses `teams._run` (`step_id="hunt_review", task_id="teams"`).
- **Impact**: Wastes up to 17 multi-turn model calls from the shared `JobBudget` on output structurally guaranteed to land in `insufficient_evidence`, drops valid multi-step seeds by arbitrary hash order once continuity producers exist, and attributes attack-chain model spend to `hunt_review` in C17 telemetry.
- **Recommendation**: Short-circuit `chains.compose` with a named gap (`no_continuity_producers_configured`) before launching LLM cells when `bounds.continuity_producers` is empty, prioritize `seed_hints` and co-component/adjacent pairs before lexicographic `claim_id` pairs in `admitted_pairs`, and pass the actual attack-chain `step_id`/`task_id` into `teams._run`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F11 Lane A package ordering collapses `high`, `medium`, `low`, and `unknown` effective severities into one rank bucket
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/jobs/job_inference_security_review/job.py:380-384,397`; `src/appsec_review/review/lead_triage.py:43,777-782`. `triage_leads` runs deterministic rules, MITRE catalog derivation (which caps catalog-derived severities at `"high"` via `CATALOG_SEVERITY`), and `lead_triager` model batches to distinguish `high`, `medium`, `low`, and `unknown`, yet `job.py:381-383` ranks Lane A packages by `(0 if menu_effective_severity(...) == "critical" else 1, package.package_id)`.
- **Impact**: Every `high`, `medium`, `low`, and `unknown` lead package ties at rank `1` and executes in arbitrary SHA-256 `package_id` order; when `max_model_calls` or `max_wall_clock_seconds` exhausts mid-run, `low` and `unknown` leads consume worker calls ahead of `high`-severity leads, negating much of `lead_triage`'s value. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Partially addressed in `29a2517ce` and `d72b7c28f` (`T-165`–`T-167`), which filter non-first-party paths and stylistic-only leads before review packaging.]*
- **Recommendation**: Replace the binary `"critical"` check in `src/appsec_review/jobs/job_inference_security_review/job.py:381-383` with full severity rank ordering (`{"critical": 0, "high": 1, "medium": 2, "unknown": 3, "low": 4}`).
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F12 `TARGET_GUIDANCE` prompt-injection exclusion misses modern agent-instruction paths and is bypassed in `triage_leads`
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/jobs/job_inference_security_review/job.py:82-84,293-295,358-360,213-222`. `TARGET_GUIDANCE` matches only `agents.md`, `claude.md`, `gemini.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `copilot-instructions.md`, `.cursor/rules/`, and `.github/instructions/`, missing `.claude/` (`skills/`, `commands/`, `agents/`), `.agents/`, `.codex/`, `.gemini/`, `.github/agents/`, `.github/prompts/`, and `CODEX.md`; furthermore, `triage_leads` (`job.py:293-295`) reads source lines for every scanner lead before `_excluded(scope)` is ever applied.
- **Impact**: Hostile target repositories can place adversarial instructions inside `.claude/skills/.../SKILL.md`, `.agents/skills/...`, or `.github/prompts/...` (or trigger a scanner lead inside `AGENTS.md` read by `lead_triager`), feeding target-authored agent directives into model prompts despite `AGENTS.md`'s rule that target guidance never reaches a review worker.
- **Recommendation**: Expand `TARGET_GUIDANCE` in `src/appsec_review/jobs/job_inference_security_review/job.py:82-84` to cover `(^|/)(\.claude|\.agents|\.codex|\.gemini)/`, `(^|/)\.github/(instructions|prompts|agents)/`, and `codex\.md`, and apply `_excluded(scope)` to `triage_leads` (`read_excerpt`) and `assemble_packages` slice inputs, not only post-assembly `retrieval.entity_ids`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F13 Default `judge.when = "all"` runs verifier-blind judge cells on undisputed claims and lets them block PoCs on `confirmed` findings
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `appsec-review.toml:2865-2870`; `src/appsec_review/jobs/job_inference_security_review/teams.py:1095-1122`; `src/appsec_review/jobs/job_inference_security_review/stages.py:390-416`. With `when = "all"`, `_plan_judges` launches an `adjudication_judge` cell for every red-affirmed claim even when both blue tasks returned `supports` or `unresolved`, and `present({"red": red, "blue": blue}, ...)` omits the `independent_verifier`'s citations; downstream, `poc_candidates` (`stages.py:400-405`) requires `verdict == "red_correct"` when `require_judge_agreement = true`.
- **Impact**: Burns an expensive `high`-reasoning model call on every affirmed claim where no red/blue disagreement exists, and if red's initial citations were incomplete (`neither`/`unresolved` to the judge) while the blind verifier independently found decisive direct graph facts that made the claim `confirmed`, the verifier-blind judge verdict blocks `job_poc_generation` from proving the confirmed vulnerability.
- **Recommendation**: Change `roles.adjudication_judge.when` default in `appsec-review.toml:2866` from `"all"` to `"disagreement"` (matching `JudgeSettings` default in `config/inference_review.py:228`), and in `src/appsec_review/jobs/job_inference_security_review/stages.py:400-405` gate PoC exclusion on `verdict == "blue_correct"` (active refutation) rather than blocking `confirmed` findings when no disagreement judge ran or when the judge answered `unresolved`/`neither` on red-only evidence.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F14 Unwired `enclosing_symbol` normalization and narrow `possible_duplicates` split equivalent claims while colliding same-symbol bugs
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/review/claims.py:54-85,125-135`; `src/appsec_review/jobs/job_inference_security_review/teams.py:1274-1279`. `claims.normalize_entities` implements `enclosing_symbol` lookup to canonicalize `SOURCE_SPAN` entities to their enclosing `SYMBOL`, but `teams.py:1274` never passes `enclosing_symbol=`; meanwhile, `possible_duplicates` (`claims.py:133`) flags overlapping entities ONLY when `left.weakness_cwe != right.weakness_cwe`, missing pairs that share a CWE (`CWE-787`) while differing in `preconditions` or `security_predicate`, and missing span-vs-symbol pairs entirely.
- **Impact**: Red specialists (`sink_up`, `entry_down`, `control_gap`) proposing the same bug with `L1` (`source_span`) vs. `F1` (`symbol`), `CWE-120` vs. `CWE-787`, or slightly different preconditions generate separate `claim_id`s that burn multiple `claims_per_package_cap` slots, launch duplicate 3-to-4-cell blue/verifier/judge teams, and publish duplicate findings without even a `possible_duplicates` link.
- **Recommendation**: Pass an `enclosing_symbol` resolver from `ReviewContext` into `normalize_claim` or into `possible_duplicates` (preferring `possible_duplicates` + package-local triage clustering so two distinct line-anchored bugs in one large function do not collide onto one `SYMBOL` `claim_id`), and broaden `possible_duplicates` (`src/appsec_review/review/claims.py:133`) to flag overlapping/enclosed entities regardless of whether `weakness_cwe` differs.
- **Effort**: `S (under a day)`
- **Already registered**: no (`T-150` covers preserving unadmitted proposal provenance, not `enclosing_symbol` wiring or `possible_duplicates` criteria)

#### C14-F15 `score_package_json` strips `application_risk_matrix/3` interval details from `native` after hashing `native_result_sha256`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/review/scoring/application_matrix_v3.py:163-178`; `src/appsec_review/jobs/job_inference_security_review/stages.py:187-218`; `docs/schemas/inference-security-review/score-package.schema.json:77-105`. `ApplicationRiskMatrixV3Provider.score` hashes the full `native` dict (`axes`, `severity_interval`, `exploitability` floor/ceiling/contributions, `environmental` floor/ceiling/contributions) into `native_sha256` and `score_id`, but `score_package_json` overwrites `"native"` with `rendered` containing only `nomenclature`, `rating`, and `matrix_cell` to fit the legacy `/1` schema properties.
- **Impact**: In every persisted `score-package/3` file, `sha256_hex(package["native"]) != package["native_result_sha256"]`, breaking standalone digest verification of `native_result_sha256` and `score_id` and discarding `points_floor`, `points_ceiling`, `contributions`, and `kev_adjusted` from published score artifacts.
- **Recommendation**: Extend `native` properties in `docs/schemas/inference-security-review/score-package.schema.json:77-105` for `application_risk_matrix/3` fields (or serialize the exact dictionary hashed by `native_sha256` in `src/appsec_review/jobs/job_inference_security_review/stages.py:187-194`) so `sha256_hex(score_package["native"]) == score_package["native_result_sha256"]`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F16 Parallel lead and hunt assembly units execute full-repository `assemble_packages` twice and require an unread `job_review_package_assembly` upstream
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/jobs/job_inference_security_review/job.py:345-415,532-539`; `src/appsec_review/jobs/job_inference_security_review/datasets.py:290-294`. `packages.assemble_lead_packages` and `packages.assemble_hunt_packages` run concurrently (`workers=2`), and each calls `assemble_packages(...)` and `publish_packages(...)` across the entire repository (re-slicing all source files, rebuilding SVF memory context and neighborhoods, and writing two identical `assembly/` trees) before filtering `package.lane == lane.value`; meanwhile, `datasets.py:290-294` declares `job_review_package_assembly` (`review_packages`) as `Requirement.REQUIRED` (`MissingBehavior.REJECT`) with zero runtime reads.
- **Impact**: Doubles CPU, I/O, and disk usage of package assembly inside every `job_inference_security_review` attempt (on top of the upstream `job_review_package_assembly` job) and causes `job_inference_security_review` to reject admission if `job_review_package_assembly` is absent even though its output is ignored.
- **Recommendation**: Collapse `packages.assemble_lead_packages` and `packages.assemble_hunt_packages` into one `packages.assemble` unit in `src/appsec_review/jobs/job_inference_security_review/job.py` that runs `assemble_packages` once and writes both `lead-packages.json` and `hunt-packages.json` (or consume `job_review_package_assembly` after feeding triage into it), and drop the unread `REQUIRED` input from `datasets.py:290-294`.
- **Effort**: `M (days)`
- **Already registered**: `docs/reviews/appsec-system-review-2026-11-06.md` noted duplicate upstream `job_review_package_assembly`; new: `job_inference_security_review` also runs full `assemble_packages` twice internally across its two lane units while enforcing `MissingBehavior.REJECT` on the unread upstream.

#### C14-F17 Hunt claims lose advisory `kev_listed`/`reference_cvss` inputs and `lead_families` even when citing an advisory-bearing `tool_observation`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/jobs/job_inference_security_review/stages.py:229-275`. `claim_references` and `claim_lead_families` skip every package where `document.get("kind") != "finding_lead"`, contributing nothing for `hunt` proposals even when a hunt claim's `affected_entities` or counted `EvidenceRelation` rows directly cite a specific `tool_observation` from the hunt package's `lead_menu`.
- **Impact**: A dependency or KEV-backed vulnerability discovered or corroborated only in Lane B (`hunt`) receives `kev_listed = None` (`ThreatExtractor` marks `threat` missing instead of `kev_listed`) and `lead_families = ()`, preventing `kev_dependency_blocks` in `ship_block.decide` and `kev_adjusted` in `application_risk_matrix/3` from firing.
- **Recommendation**: In `src/appsec_review/jobs/job_inference_security_review/stages.py:229-275`, match hunt `lead_menu` entries whose `observation_id` appears in the claim's `affected_entities` or counted supporting `EvidenceRelation` entity ids instead of unconditionally ignoring non-`finding_lead` packages.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F18 Dead `settings.poc` config, unused `independent_verifier.workers`, unstripped `adjudication_judge.workers` in cache digest, and dead `cites_tool_fact`
- **Kind**: `remove`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `src/appsec_review/config/inference_review.py:206-210,275,461-468,590-619`; `appsec-review.toml:2981-3006,3175,3187`; `src/appsec_review/review/numeric_reasoning.py:105-114`. `settings.poc` (referencing unimplemented `"cvss_v4"`) is required by `parse_inference_review_settings` and hashed into `semantic_settings_sha256` despite zero readers (`settings.poc_candidates` is used instead); `independent_verifier.workers` (`8` in TOML) is never read (`teams.verifier_per_team` is used); `adjudication_judge.workers` (`4` in TOML) drives `ThreadPoolExecutor` concurrency (`teams.py:1140`) yet is omitted from `semantic_settings_view()`'s concurrency strip list, invalidating cell/package caches on thread-count tuning; and `numeric_reasoning.cites_tool_fact` has zero production callers.
- **Impact**: Misleads operators tuning TOML settings (`settings.poc` vs. `settings.poc_candidates`, `independent_verifier.workers`), needlessly invalidates cached cell results when tuning `adjudication_judge.workers`, and leaves dead code (`cites_tool_fact`, whose substring match on `"CodeQL"`/`"guard fact"` would be unsafe if ever called).
- **Recommendation**: Remove `PocSettings`/`settings.poc`, `independent_verifier.workers`, and `numeric_reasoning.cites_tool_fact`, and strip `roles["adjudication_judge"]["workers"]` in `semantic_settings_view()` (`src/appsec_review/config/inference_review.py:590-619`).
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C14-F19 `tests/job-test-map.json` omits most of `tests/review/` and `test_predicate_admission.py` masks the `SECRETS` confirmation bug via synthetic relations
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `tests/job-test-map.json:232-247`; `tests/review/test_predicate_admission.py:276-282`. `job-test-map.json` maps `job_inference_security_review` to only 13 unit selectors (omitting `test_adjudication.py`, `test_obligations.py`, `test_predicate_admission.py`, `test_scoring.py`, `test_scoring_factors.py`, `test_ship_block.py`, `test_attack_chains.py`, `test_cells.py`, `test_capability.py`, `test_judge.py`, `test_ledger.py`, `test_accounting.py`, and all 6 `tests/unit/review_behavior/` modules), and `test_a_secret_claim_confirms_on_its_own_family_obligations` fabricates `relation(P.MISSING_OR_INEFFECTIVE_GUARD, "tool_observation", Admissibility.DIRECT_FOR_MAPPED_PREDICATE)` directly instead of going through `resolve_relation` + `tool_rules.lead_predicates`.
- **Impact**: Job-scoped regression runs (`scripts/run-tests.sh` using `job-test-map.json`) skip almost the entire review-protocol unit suite, and synthetic relation construction hid the fact that no real `secret` tool observation can ever produce `DIRECT_FOR_MAPPED_PREDICATE` for `missing_or_ineffective_guard` (C14-F03).
- **Recommendation**: Add all C14 unit test modules under `tests/review/` and `tests/unit/review_behavior/` to `job_inference_security_review` in `tests/job-test-map.json`, and rewrite `test_a_secret_claim_confirms_on_its_own_family_obligations` in `tests/review/test_predicate_admission.py` to resolve real indexed entities through `resolve_relation` and `tool_rules.lead_predicates`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-113` (general test-tier walk) and `T-083` (`test_team_handler.py` fixture speed); new: the specific omission of ~38 existing fast protocol unit files from `tests/job-test-map.json` and the synthetic admissibility bypass in `test_predicate_admission.py:276-282`.

#### C14-F20 Operations docs, architecture docs, `PLANNED_CONSUMERS`, and `handoff.schema.json` drift from live C14 contracts
- **Kind**: `doc-drift`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_inference_security_review`
- **Evidence**: `docs/operations/inference-security-review.md:662,776-780`; `docs/architecture/inference-security-review.md:1079,2393`; `src/appsec_review/jobs/job_inference_security_review/datasets.py:18-29`; `docs/schemas/inference-security-review/handoff.schema.json:532-558`; `appsec-review.toml:3009`. Operations doc line 662 states `chain-seeds.json` is *"now empty: the compact answer carries no chain seeds"* (`compact.py:486-507` populates `seed_hints` into `chain-seeds.json`); `PLANNED_CONSUMERS` and `handoff.schema.json` hardcode `status: "planned"` and omit real consumers `job_poc_generation` and `job_dossier_publication`; architecture doc line 1079 claims CodeQL graph exports exist *"only for scopes with an accepted C/C++ graph export"*, contradicting line 2393 (8 language packs); and `appsec-review.toml:3009` references removed <!-- historical:begin -->`application_risk_matrix/2`<!-- historical:end -->.
- **Impact**: Operators and neighbouring component owners reading C14's handoff contract and runbooks get false information on which jobs consume `/3` handoffs, whether `chain-seeds.json` is active, and which languages supply CodeQL graph facts.
- **Recommendation**: Reconcile `docs/operations/inference-security-review.md`, `docs/architecture/inference-security-review.md:1079`, `appsec-review.toml:3009`, `PLANNED_CONSUMERS` in `src/appsec_review/jobs/job_inference_security_review/datasets.py:18-29`, and `docs/schemas/inference-security-review/handoff.schema.json:532-558` with the active `/3` consumers and compact chain-seed contract.
- **Effort**: `S (under a day)`
- **Already registered**: no
### C15 Evidence completion: proof of concept and remediation

**Active findings:** 17 (`1` critical, `4` high, `9` medium, `3` low).

C15 cleanly preserves finding immutability and honest machine-readable non-execution labels (`execution: "not_performed_by_policy"`, `runtime_verified: false`), attaching attempt-owned C/C++ compile-only PoC harnesses and exact-byte remediation patches to accepted `/3` review findings before the final gate. However, `job_poc_generation` replays captured compiler commands through a denylist (`buildcheck.py`) that permits target-controlled flag/binary execution (`-B`, `-wrapper`, `-specs`, `@rsp`, Clang config files) inside the build container and diverges from the flags used during AST policy validation. On the remediation side, empty confirmed-finding sets emit `SKIPPED_NA` handoffs that crash `job_final_publication_gate` on every default run without confirmed findings, and coupling `SourceReader` to PoC's C/C++-only `AcceptedBuilds` leaves all non-C/C++ confirmed findings unable to access run-owned source while still burning full LLM turns on empty inputs. Closing the compiler/AST holes in `job_poc_generation`, fixing the `SKIPPED_NA` gate contract and `REQUIRED` native-build input gate, and decoupling remediation source custody from C/C++ translation units are the highest-leverage improvements.

**Strengths to preserve:**
- Machine-readable non-execution assurance (`execution: "not_performed_by_policy"`, `runtime_verified: false`, `result_id: null`) is stamped across PoC summaries, remediation plans, and validation records so downstream gates and reports never mistake compilation or syntax checks for runtime proof (`src/appsec_review/jobs/completion_contracts.py:21-25`).
- Exact-byte JSON patch representation (`appsec-review/remediation-exact-patch/1`) verifies every baseline `before_sha256` or new-file absence, rejects symlinks, case-insensitive collisions, and undeclared workspace mutations, and cleans up scratch trees in `finally` with durable receipts (`src/appsec_review/jobs/job_remediation_planning/patches.py:92-194`, `src/appsec_review/jobs/job_remediation_validation/workspace.py:39-66`).
- `job_remediation_validation`'s native syntax replay (`compile_argv`) uses a strict flag and `/usr/bin/` compiler allowlist, forces `--no-default-config` for Clang, rejects response files and workspace escapes, and compares baseline and patched syntax under identical offline container profiles (`src/appsec_review/jobs/job_remediation_validation/compiler.py:100-175`).
- Independent semantic patch review in `job_remediation_validation` runs in a fresh `remediation_reviewer` conversation that receives the finding's invariants, accepted evidence, source files, and patch without the planner's narrative rationale, preventing self-justifying rubber-stamping (`src/appsec_review/jobs/job_remediation_validation/job.py:206-235`).
- Exact intake-to-outcome accounting across all three producers ensures every admitted candidate or confirmed finding gets a deterministic terminal row (`capped` beyond `max_candidates`) and re-verifies upstream review hashes at publication before sealing the handoff (`src/appsec_review/jobs/job_poc_generation/job.py:345-383`, `src/appsec_review/jobs/job_remediation_planning/job.py:149-182`).
- PoC README rendering dynamically sizes Markdown code fences (`fence()`) longer than any backtick run in generated code or model text and sanitizes inline spans, neutralizing Markdown/HTML breakout in developer artifacts (`src/appsec_review/jobs/job_poc_generation/package.py:48-90`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_poc_generation` | `job_inference_security_review`, `job_language_build`, `source_context_core` index shards | `poc_generation_summary`, `poc_writer_cells`, `poc_reproducers` (C/C++ source, compile receipt, `README.md`; never executed) | `C15-F01` (compile-only C/C++ harness check with zero runtime execution or crash/oracle proof, skipping non-C/C++ ecosystems) | rework |
| `job_remediation_planning` | `job_inference_security_review`, `job_language_build`, `source_context_core` index shards | `remediation_planning_summary`, `remediation_proposals` (`remediation-plan/1`, `remediation-exact-patch/1`) | `C15-F03` (patch hunk/context drift and single-file patch assumptions on multi-file fixes) | rework |
| `job_remediation_validation` | `job_inference_security_review`, `job_remediation_planning`, `job_language_build` | `remediation_validation_summary`, `remediation_validation_records` (static/semantic/build receipts) | `C15-F02` / `C15-F04` (`SKIPPED_NA` control-layer mismatch on zero eligible findings, and validation without re-running triggering scanner/PoC) | rework |

#### C15-F01 Denylist compiler replay in `job_poc_generation` permits target binary execution and diverges from AST validation
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_poc_generation`
- **Evidence**: `src/appsec_review/jobs/job_poc_generation/buildcheck.py:41-50, 62-137` vs. `src/appsec_review/jobs/job_remediation_validation/compiler.py:100-156`; `derive()` keeps `argv[0]` verbatim and strips only `DROP_FLAGS`, `DROP_WITH_VALUE`, `DROP_PREFIXES`, and a narrow `PLUGIN_XCLANG` set, while `derive_ast()` keeps only `AST_VALUE_FLAGS` and `AST_ATTACHED` under Clang.
- **Impact**: Captured build flags from a hostile repository can pass `-B/workspace/...` (hijacking `cc1`/`as`), `-wrapper <bin>`, `-specs=<file>` (GCC `%()` spec command execution), `--config=<file>` or implicit Clang `.cfg` files (no `--no-default-config`), `@response_file` containing `-fplugin=...`, or `-Wp,-load,...` into `compile.build_check`, executing target-supplied code inside the build container despite the non-execution invariant. In addition, `derive_ast()` drops separated `-D FOO=1` / `-U FOO` and swaps GCC for Clang while `derive()` retains them and extra positional files, so `compile.build_check` can compile macro-selected branches that `validate.policy` never inspected.
- **Recommendation**: Replace `derive()` and `derive_ast()` in `src/appsec_review/jobs/job_poc_generation/buildcheck.py` with a shared strict allowlist modeled on `src/appsec_review/jobs/job_remediation_validation/compiler.py:100-156` (pinned `/usr/bin/{clang,clang++,gcc,g++}`, `--no-default-config` on Clang, identical paired/attached `-D`/`-U` macro retention across AST and object steps, and rejection of `@rsp`, `-B`, `-wrapper`, `-specs`, `--config`, and extra positional inputs).
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F02 Empty confirmed-finding runs emit `SKIPPED_NA` in remediation handoffs and fail `job_final_publication_gate`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/job_remediation_planning/job.py:179-182` and `src/appsec_review/jobs/job_remediation_validation/job.py:332-335` publish `terminal_status: "SKIPPED_NA"` when `rows` and `gaps` are empty, whereas `src/appsec_review/jobs/job_final_publication_gate/attachments.py:285-289` requires `published.get("terminal_status") in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}`; `tests/test_completion_publication.py:56-63` masked this by hardcoding `"SUCCEEDED"` in `Fixture.publish`.
- **Impact**: Because both remediation jobs ship `enabled = true` in `appsec-review.toml:3463, 3513`, any default review run that produces zero `confirmed` findings (including clean targets or runs whose findings are all `supported` in the verification backlog) fails closed at `job_final_publication_gate` with `IntegrityError: job_remediation_planning summary disagrees with its accepted envelope`.
- **Recommendation**: Accept `published.get("terminal_status") == "SKIPPED_NA"` when `not rows and not document["gaps"]` in `src/appsec_review/jobs/job_final_publication_gate/attachments.py:286-289`, and update `Fixture.publish` in `tests/test_completion_publication.py:56-63` to match the real producer `terminal_status` formula.
- **Effort**: `S (under a day)`
- **Already registered**: no (Deduplicated in headline totals under `C01-F01`: Control-layer `SKIPPED_NA` / zero-eligible-finding contract mismatch between `UnitExecutor`/`JobRunner` and evidence-completion jobs.)

#### C15-F03 Non-C/C++ confirmed findings cannot resolve source or patches, yet `job_remediation_planning` still runs LLM turns on empty source
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_remediation_planning`
- **Evidence**: `src/appsec_review/jobs/job_remediation_planning/inputs.py:12, 75-78` imports `AcceptedBuilds` from `src/appsec_review/jobs/job_poc_generation/buildctx.py:35-42, 149-158, 179-185` (which filters `family == "native"` and rejects non-C/C++ suffixes as `not_c_family`); `src/appsec_review/jobs/job_remediation_planning/job.py:92-121` still dispatches `run_model` when `reader.files` is empty, and `contracts.py:67-79` rejects any resulting patch.
- **Impact**: Every confirmed finding in Python, Java, Go, Rust, JS/TS, C#, PHP, IaC, or containers gets `reader.files == {}` (`run_owned_source_unavailable:<path>:not_c_family`), wastes up to 6 model turns / 600 s on `"source_files": []`, and—if the writer attempts a patch from evidence snippets—hits `PatchError` (`job.py:114-115`) and loses even its `manual_design_required` plan (`status: "insufficient_evidence"`, `plan: None`).
- **Recommendation**: In `src/appsec_review/jobs/job_remediation_planning/job.py:92-121`, forbid `proposal_generated` (or skip model invocation when no source is readable) if `reader.files` is empty, and decouple `SourceReader` (`inputs.py:63-98`) and `verify_patch_scope` (`contracts.py:67-79`) from `job_poc_generation.buildctx.AcceptedBuilds` so hash-verified run-owned files from non-native build workspaces or the indexed target snapshot can be read.
- **Effort**: `M (days)`
- **Already registered**: no

#### C15-F04 C++ constructors and non-array `new` expressions bypass `policy.py` call allowlists and sink checks
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_poc_generation`
- **Evidence**: `src/appsec_review/jobs/job_poc_generation/policy.py:309-355, 390-416, 451-460, 501-505` and `src/appsec_review/jobs/job_poc_generation/ast_reduce.py:29-31, 159-163`; `type_text()` allows every type declared under `/workspace/`, while `on_CXXConstructExpr`, `on_CXXTemporaryObjectExpr`, and `on_CXXNewExpr` check only container/array sizes and never invoke `function_reference()`.
- **Impact**: Under the default `policy.project_calls = "sink_and_path"` (`appsec-review.toml:3373`), a PoC can instantiate arbitrary project classes whose constructors or destructors open files, sockets, or subprocesses off the finding's call path without triggering `call_not_allowlisted`. Conversely, when the vulnerability sink itself is a `CXXConstructorDecl`, `sink_hits` stays zero because Clang emits no child `DeclRefExpr`/`MemberExpr`, falsely failing valid PoCs with `sink_not_called`.
- **Recommendation**: Record constructor declaration references in `src/appsec_review/jobs/job_poc_generation/ast_reduce.py` and pass resolved `CXXConstructorDecl` and `operator new` targets through `function_reference()` in `src/appsec_review/jobs/job_poc_generation/policy.py:390-416`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F05 `job_poc_generation` declares `job_language_build` `REQUIRED`/`REJECT`, contradicting its graceful non-native fallback
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_poc_generation`
- **Evidence**: `src/appsec_review/jobs/job_poc_generation/datasets.py:55-57` sets `availability=Availability.REQUIRED, missing=MissingPolicy.REJECT` on `job_language_build`'s handoff, whereas `src/appsec_review/jobs/job_poc_generation/buildctx.py:130-137` explicitly handles missing `job_language_build` handoffs (`accepted_language_build_unavailable`) and `src/appsec_review/jobs/job_remediation_planning/datasets.py:42-43` leaves `job_language_build` `OPTIONAL`.
- **Impact**: On repositories where `job_language_build` does not produce an accepted handoff (pure interpreted/configuration targets or skipped builds) while `job_poc_generation` is enabled (`appsec-review.toml:3321`) or manually dispatched, runtime contract enforcement rejects the job before `AcceptedBuilds.load()` can emit accounted `not_applicable` candidate outcomes.
- **Recommendation**: Change the `job_language_build` `handoff` requirement in `src/appsec_review/jobs/job_poc_generation/datasets.py:55-57` to `availability=Availability.OPTIONAL, missing=MissingPolicy.GAP`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F06 `job_remediation_planning`'s `retrieve` protocol cannot read new bytes and aborts the candidate on any broader request
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_remediation_planning`
- **Evidence**: `src/appsec_review/jobs/job_remediation_planning/inputs.py:92-116, 130` embeds full `"text"` of every resolved file in `task["source_files"]` on turn 1 while `SourceReader.retrieve()` raises `ValueError` for any `path not in self.files`; `src/appsec_review/jobs/job_remediation_planning/model.py:107-112` catches `ValueError` and breaks the turn loop with `invalid_output:...`.
- **Impact**: All `max_queries = 4` retrieval turns can only slice files already transmitted in full on every turn (re-sending up to 64 KB per turn), and if `remediation_writer` requests an adjacent header or caller path to design a sound fix, `run_model` immediately aborts the entire candidate as `insufficient_evidence` instead of returning a bounded denial like `job_poc_generation/writer.py:194-205`.
- **Recommendation**: Send bounded windows around evidence lines in `writer_task()` (`inputs.py:125-145`), permit `SourceReader.retrieve()` (`inputs.py:99-107`) to read bounded windows of verified workspace headers/files on demand, and return structured denial responses on invalid `retrieve` requests in `src/appsec_review/jobs/job_remediation_planning/model.py:107-112` rather than breaking the loop.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F07 `loop_bound` in `job_poc_generation` ignores loop direction and `!=` stride, admitting non-terminating loops
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_poc_generation`
- **Evidence**: `src/appsec_review/jobs/job_poc_generation/policy.py:422-440` checks `condition.opcode in {"<", "<=", ">", ">=", "!="}` independently of whether `step` increments (`++`, `+=`) or decrements (`--`, `-=`), ignores stride divisibility for `!=`, and returns `abs(limit - initial)` without `+ 1` on `<=`/`>=`.
- **Impact**: Loops such as `for (unsigned i = 0; i < 10; --i)` or `for (int i = 0; i != 10; i += 3)` compute `bound = 10` and pass `max_loop_iterations = 4096`, producing hanging or undefined-behavior harnesses for developers and for a future `T-026` isolated dynamic runner.
- **Recommendation**: Enforce sign agreement between `limit - initial`, `condition.opcode`, and `step` direction, compute `ceil_div` or exact divisibility for `+=`/`-=` and `!=`, and add `1` for `<=`/`>=` in `src/appsec_review/jobs/job_poc_generation/policy.py:422-440`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F08 Negative control in `job_poc_generation` is never checked to omit the trigger or differ from the positive test
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_poc_generation`
- **Evidence**: `src/appsec_review/jobs/job_poc_generation/policy.py:501-513` (`check_sink_and_triggers`) verifies numeric `expectation.triggers` on `expectation.functions[0]` and sink calls on both functions, but performs zero checks on `expectation.functions[1]` (`negative_control`); `src/appsec_review/jobs/job_poc_generation/source.py:140-175` checks only distinct function names.
- **Impact**: A writer answer whose `negative_control` has the exact same body and trigger literal as `test_function` passes `compile_verified`, undermining the documented claim (`docs/operations/poc-generation.md:36-37`) that the negative control demonstrates a safe non-triggering input.
- **Recommendation**: Require normalized body inequality between `test_function` and `negative_control` in `src/appsec_review/jobs/job_poc_generation/source.py` and reject `negative_control` in `src/appsec_review/jobs/job_poc_generation/policy.py:501-513` when numeric `expectation.triggers` exist and all of them remain satisfied in `functions[1]`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F09 Single-TU `-fsyntax-only` validation refuses `-include`/header patches while stamping caller-breaking edits `build_checked`
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_remediation_validation`
- **Evidence**: `src/appsec_review/jobs/job_remediation_validation/compiler.py:29-31, 130-156` omits `-include` from `_INCLUDES` (failing forced-include builds as `accepted_build_replay_unsafe`), `src/appsec_review/jobs/job_remediation_validation/job.py:241-244` refuses any header or multi-file patch, and `compare_build` (`compiler.py:178-213`) checks only the edited `.c`/`.cpp` file; meanwhile `static_checks` (`job.py:194-205`) tests only UTF-8, NUL bytes, and merge markers.
- **Impact**: Autotools/CMake targets using `-include config.h` and any fix touching a `.h` declaration degrade to `manual_validation_required`, whereas a single-`.c` patch that changes a non-static function signature and breaks every caller in sibling TUs is still promoted to `build_checked`; non-native patches stamped `static_checked` undergo no AST or syntax parse at all (`job_tree_sitter_ast` is unused).
- **Recommendation**: Allow workspace-confined `-include <file>` in `src/appsec_review/jobs/job_remediation_validation/compiler.py:29-31, 130-145`, replay `-fsyntax-only` across affected TUs in the same `BuildUnit` (enabling header/caller checks), and add an in-process Tree-sitter syntax parse to `static_checks` in `src/appsec_review/jobs/job_remediation_validation/job.py:194-205`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C15-F10 `job_remediation_planning` schedules after `job_poc_generation` despite consuming nothing from it
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_remediation_planning`
- **Evidence**: `src/appsec_review/jobs/job_remediation_planning/datasets.py:56` sets `schedule_after=('job_inference_security_review', 'job_poc_generation')` (mirrored in `tests/orchestration/dagster/test_completion.py:33`), even though `job_poc_generation` is not in `CONTRACT.inputs` and `src/appsec_review/jobs/job_remediation_planning/job.py:118, 167` hardcodes `"poc_handoff": None`.
- **Impact**: Remediation planning, remediation validation, dossier publication, and the final gate sit idle behind all PoC LLM turns and Docker compile/symbol checks—including PoC work for `supported` backlog findings that remediation never touches—adding full PoC latency to the critical path and slowing repair cycles for zero data flow.
- **Recommendation**: Set `schedule_after=('job_inference_security_review',)` in `src/appsec_review/jobs/job_remediation_planning/datasets.py:56` and update `tests/orchestration/dagster/test_completion.py:33` until PoC context is actually consumed.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F11 `RemediationModel` lacks transient/schema retry support and enforces a `3 * max_input_tokens` byte ceiling
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/config/remediation.py:26-49` defines no `retries` field on `RemediationModel`, and `src/appsec_review/jobs/job_remediation_planning/model.py:39-75` sets `max_request_bytes=profile.max_input_tokens * 3` (`192,000` bytes at `64,000` tokens) and terminates on the first `ProviderError`, `TimeoutError`, or `ModelOutputError`.
- **Impact**: A single provider hiccup or minor JSON schema slip permanently drops a confirmed finding to `insufficient_evidence` or `inconclusive`, and because `assess.propose` and `assess.validate` loop over all candidates inside one monolithic unit, re-running the job to recover one failed candidate re-runs LLM calls for every confirmed finding; multi-turn transcripts carrying `64,000` bytes of `source_files` plus guidance and evidence also hit `input_budget_exceeded` well below `64,000` tokens.
- **Recommendation**: Add bounded retry settings (matching `job_poc_generation/settings.py:55-68`) to `RemediationModel` in `src/appsec_review/config/remediation.py` and raise `max_request_bytes` to at least `profile.max_input_tokens * 4 + len(guidance_text)` in `src/appsec_review/jobs/job_remediation_planning/model.py:39-43`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F12 All three C15 jobs emit free-text gaps (`strict_gaps=False`) instead of `producer-gap/1` records
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/test_gap_contract.py:11-29` keeps `job_poc_generation`, `job_remediation_planning`, and `job_remediation_validation` in `LEGACY_FREE_TEXT_GAPS`; `src/appsec_review/jobs/job_poc_generation/job.py:361-363` appends free-text prose (`f"{row['claim_id']}: {row['status']}: {row['reason']}"[:300]`) directly to `gaps`.
- **Impact**: Violates `AGENTS.md`'s control-layer requirement that new jobs emit structured `producer-gap/1` records with `strict_gaps=True`, and causes `job_final_report_publication/render.py:195` to print unstructured 300-character diagnostic sentences under "Recorded gap identifiers".
- **Recommendation**: Migrate `job_poc_generation`, `job_remediation_planning`, and `job_remediation_validation` to `interchange.producer_gap` (`strict_gaps=True`), update C16 attachment/report readers accordingly, and remove all three from `LEGACY_FREE_TEXT_GAPS` in `tests/test_gap_contract.py`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C15-F13 C15 handoffs omit unredacted link closures and executable regression bindings needed by `T-026` and `T-061`
- **Kind**: `missing`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/job_poc_generation/buildcheck.py:140-156, 232-242, 297-318` discards `poc.o`/`poc_san.o`, redacts non-allowlisted flags to `"<redacted>"` in `compile.json`, and records symbol names in `resolved_by_project` without recording which `.o`/`.a`/`.so` files satisfied them or link order; `docs/schemas/remediation/plan.schema.json:33-45` stores `regression_spec` only as free-text strings.
- **Impact**: When isolated dynamic PoC execution (`T-026`) and post-fix verification (`T-061`/`T-074`) are built, neither can link or execute a `compile_verified` PoC or replay it against a `build_checked` remediation workspace from C15's published artifacts alone without re-deriving build/link graphs and re-prompting a model to turn `regression_spec` prose into code.
- **Recommendation**: Retain protected attempt-owned link-closure metadata (exact allowlisted compile argv digest, ordered resolving object/archive paths from `build.objects`/`build.libraries`, and entry harness symbols) in `src/appsec_review/jobs/job_poc_generation/buildcheck.py`, and bind `finding` PoC function names into `job_remediation_validation` when both lanes cover the same claim.
- **Effort**: `M (days)`
- **Already registered**: `T-026`, `T-061`, `T-074`; what is new is the specific gap in C15's current `poc-compile/1` and `remediation-plan/1` handoff payloads that blocks deterministic link/replay consumption without re-inference.

#### C15-F14 Over-declared `PROVISIONAL` and unused `InputRequirement`s across all three C15 job contracts
- **Kind**: `remove`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/job_poc_generation/datasets.py:39-68`, `src/appsec_review/jobs/job_remediation_planning/datasets.py:25-54`, and `src/appsec_review/jobs/job_remediation_validation/datasets.py:24-54` declare `PROVISIONAL` `lead_triage` and `review_cells` plus `jvm_build_actions`, `build_actions`, and `topology_refinement_inputs`, whereas `src/appsec_review/jobs/accepted_review.py:67-111` and `buildctx.py:128-165` never read them.
- **Impact**: Declaring `PROVISIONAL` triage/cell receipts on confirmed-only remediation contracts misstates their evidence authority boundary and inflates contract/audit surfaces with datasets that have zero read receipts.
- **Recommendation**: Trim `CONTRACT.inputs` in `src/appsec_review/jobs/job_poc_generation/datasets.py`, `src/appsec_review/jobs/job_remediation_planning/datasets.py`, and `src/appsec_review/jobs/job_remediation_validation/datasets.py` to the review and native-build datasets actually opened by `load_accepted_review` and `AcceptedBuilds`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F15 Dead `poc_designer`/`poc_verifier` roles, missing load-time `PocGenerationSettings` validation, and duplicate schema key
- **Kind**: `remove`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_poc_generation`
- **Evidence**: `src/appsec_review/guidance/workers.py:67` (`NON_DISPATCHED_ROLES`), `pipeline/guidance/registry.json:27-28`, `pipeline/prompt-fragments/roles/poc_designer.md:1-16`, `pipeline/prompt-fragments/roles/poc_verifier.md:1-17`, `src/appsec_review/jobs/job_poc_generation/job.py:52, 393-395` (`IMPLEMENTATION`, `package_dir`, `implementation = None`), `src/appsec_review/config/loader.py:1415-1450`, and `docs/schemas/poc-generation/common.schema.json:6, 22-25`.
- **Impact**: `PocGenerationSettings` errors in `appsec-review.toml` or overlays are not caught at config load time (unlike both remediation jobs), duplicate `"entity_id"` in `common.schema.json` silently drops `minLength: 1`, and dead role definitions/constants add maintenance noise.
- **Recommendation**: Parse `PocGenerationSettings.from_mapping(settings)` in `src/appsec_review/config/loader.py:1420-1435`, merge the duplicate `"entity_id"` definition in `docs/schemas/poc-generation/common.schema.json:6, 22-25`, delete unused `IMPLEMENTATION`/`package_dir` in `src/appsec_review/jobs/job_poc_generation/job.py:52, 393-395`, and remove `poc_designer`/`poc_verifier` from `registry.json`, `workers.py`, and `pipeline/prompt-fragments/roles/`.
- **Effort**: `S (under a day)`
- **Already registered**: `docs/reviews/appsec-system-review-2026-11-06.md` (§4 line 263) registered dead `poc_designer`/`poc_verifier`; what is new is `NON_DISPATCHED_ROLES` in `workers.py:67`, the missing `PocGenerationSettings` branch in `config/loader.py`, dead `job.py` constants, and the duplicate `"entity_id"` schema key.

#### C15-F16 Documentation drift on remediation runtime skills and PoC default enablement
- **Kind**: `doc-drift`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `docs/schemas/remediation/README.md:57-58` states `"no runtime skill is loaded"` for `remediation_writer` and `remediation_reviewer` (and `docs/operations/remediation.md:88-96` omits skills), whereas `src/appsec_review/guidance/workers.py:51-55` and `pipeline/guidance/registry.json:108` load `stateful-invariant-analysis`; `docs/operations/poc-generation.md:80-81` tells operators to set `enabled = true` as an opt-in step although `appsec-review.toml:3321` already ships `enabled = true`.
- **Impact**: Operators and auditors inspecting worker prompt provenance see `stateful-invariant-analysis` in `/4` guidance bundles despite schema documentation claiming no runtime skill is sent.
- **Recommendation**: Update `docs/schemas/remediation/README.md:57-58` and `docs/operations/remediation.md:88-96` to document `stateful-invariant-analysis` (the code/registry is right), and reword `docs/operations/poc-generation.md:80-81` to state `enabled = true` is the shipped default.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C15-F17 `job-test-map.json` omits core C15 unit files and tests bypass `upstream_scope` and real `SKIPPED_NA` envelopes
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/job-test-map.json:371-405` omits `tests/test_poc_policy.py`, `tests/test_poc_writer.py`, `tests/test_poc_generation_job.py`, `tests/test_poc_generation_contracts.py`, `tests/test_remediation_compiler.py`, and `tests/test_remediation_jobs.py` from `unit` arrays; `tests/test_remediation_jobs.py:56-80` invokes `job.execute` outside `upstream_scope` (`upstream_handoffs={}`) with synthetic `AcceptedBuilds`; `tests/test_completion_publication.py:56-63` hardcodes `"SUCCEEDED"` on empty summaries.
- **Impact**: Targeted per-job unit selection skips AST policy, writer loop, compiler allowlist, and job-level tests, while synthetic test harnesses masked both the `SKIPPED_NA` publication-gate crash (`C15-F02`) and `job_poc_generation`'s `REQUIRED` `job_language_build` contract failure (`C15-F05`).
- **Recommendation**: Add the six existing unit files to `tests/job-test-map.json:371-405` immediately, run C15 job tests inside `upstream_scope` with real producer handoff envelopes (including `0` confirmed findings and missing `job_language_build`), and fold into `tests/unit/<job_id>/` under `T-113`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-113` covers migrating into `tests/unit/<job_id>/`; what is new is that six existing unit test files are unmapped in `tests/job-test-map.json` today and fake handoff envelopes in tests actively hid `C15-F02` and `C15-F05`.
### C16 Publication and reporting

**Active findings:** 18 (`2` critical, `6` high, `7` medium, `3` low).

C16 establishes a sound post-review spine: `job_final_publication_gate` certifies one hash-pinned review and attachment snapshot without invoking models, `job_final_report_publication` projects deterministic JSON and Markdown solely from that gate, and `reporting/` drives both HTML and XeLaTeX from one typed `Document` tree while preserving PoC and repair non-execution invariants. However, the published reports fail reader verifiability: `final-report.{json,md}` strips claim statements, CWEs, resolving `file:line` locations, and gap meanings down to opaque SHA-256 identifiers, while `reporting/` (`report.html`/`report.pdf`) leaves `asr:...` entity hashes unresolved and merges `ledger.jsonl` across failed/retried attempts. Coverage honesty has two critical blind spots: the gate and final report ignore pre-review build, scanner, dependency, OWASP-control, and threat-model `ProducerGap`s so runs with major upstream failures can still publish `review_complete: true` (`PUBLISHABLE`), while `media_assets.py`'s short magic rules (`ftyp`, 2-byte `\x80\x01`/`\xff\x0a`) silently reclassify generated bundles and native objects as `SKIPPED_NA` media. Runtime contract mismatches also break real runs: `job_final_publication_gate` declares optional completion jobs `WHEN_ENABLED` + `REJECT` (crashing gate admission on any enabled attachment-job failure instead of publishing `PUBLISHABLE_WITH_LIMITATIONS`), `tool-report-latex` still carries `manual = true` in `containers/catalog.toml`, and `job_openvex_export` omits `job_review_intake` from `CONTRACT` so `upstream_scope` silently drops acquisition and repository-IRI verification. Finally, `Heading.anchor` bypasses TeX escaping in `reporting/latex.py`, `scripts/render-report.{sh,ps1}` bypass `ContainerExecutor` pin/signature enforcement, and `job_dossier_publication` plus `job_openvex_export` perform substantial duplicate rendering and re-hashing work.

**Strengths to preserve:**
- Model-free publication boundary: `job_final_publication_gate` classifies every finding package deterministically into `publishable`, `verification_backlog`, or `withheld` with exact bucket accounting and explicit ship-block dispositions (`ship_blocking`, `decision_pending`, `not_ship_blocking`), and `job_final_report_publication` reads only the accepted gate snapshot (`src/appsec_review/jobs/job_final_publication_gate/classify.py:62-193`, `src/appsec_review/jobs/job_final_publication_gate/verify.py:47-76`, `src/appsec_review/jobs/job_final_report_publication/report.py:35-90`).
- Strict non-execution and non-authority of post-review attachments: PoC outcomes, remediation plans, remediation validations, and dossiers are verified against upstream review hashes and non-execution assurances (`executed_target_code: false`, `compile_verified` labeled non-runtime) without ever promoting an unconfirmed claim (`src/appsec_review/jobs/job_final_publication_gate/attachments.py:114-239`, `src/appsec_review/jobs/completion_contracts.py:72-95`).
- Conservative OpenVEX status mapping: `job_openvex_export` emits only `affected` for `confirmed`+`publishable` findings and `under_investigation` for `supported`+`verification_backlog` findings, forbidding `not_affected` and `fixed` in schema, code, and post-assembly validation so incomplete coverage can never masquerade as a clean VEX attestation (`src/appsec_review/jobs/job_openvex_export/projection.py:86-123`, `docs/schemas/openvex-export/result.schema.json:79-91`).
- Single typed document intermediate representation and hardened XeLaTeX runtime: `reporting/model.py` keeps HTML and LaTeX structurally identical, `containers/report/latex/render-pdf.sh` enforces `-no-shell-escape` with `openin_any = p` and `openout_any = p`, `dossier_render.py` runs `tool-report-latex` via `ContainerExecutor`, and `html.py` emits an external-load-blocking CSP (`src/appsec_review/reporting/model.py:45-169`, `containers/report/latex/render-pdf.sh:21-43`, `src/appsec_review/reporting/html.py:29-31`).
- Dossier secret redaction and bounded evidence retrieval: `job_dossier_publication` reads source excerpts only through `RetrievalCore.read_excerpt` (inheriting secret redaction and line/byte caps) and never touches the target checkout (`src/appsec_review/jobs/job_dossier_publication/job.py:102-120`, `src/appsec_review/jobs/job_dossier_publication/datasets.py:60-63`).

**Component jobs:**

| Job | Consumes (real reads) | Produces | Biggest weakness | Verdict |
| --- | --- | --- | --- | --- |
| `job_final_publication_gate` | `job_inference_security_review`, optional `job_poc_generation`, `job_remediation_planning`, `job_remediation_validation`, `job_dossier_publication`, and `resolved.json` | `publication_gate_decisions` (`final-publication-gate.json`) consumed by `job_final_report_publication` and `job_openvex_export` | `C16-F01` (ignores pre-review producer gaps, certifying blind runs as complete) and `C16-F05` (`WHEN_ENABLED` + `REJECT` blocks gate when enabled attachment job fails) | rework |
| `job_dossier_publication` | `job_inference_security_review`, `job_review_data_indexing` (`RetrievalCore.read_excerpt`), optional `job_poc_generation`, `job_remediation_planning`, `job_remediation_validation` | `dossier_publications` (`dossier-publication.json` + per-dossier JSON/TeX/PDF) | `C16-F06` (`tool-report-latex` `manual = true` skips preflight check) and `C16-F12` (duplicate PDF renders and pre-filter excerpt slicing) | rework |
| `job_final_report_publication` | `job_final_publication_gate` (`final-publication-gate.json` + transitive byte verification of `bindings`) | `final_report_publications` (`final-report.json`, `final-report.md`) | `C16-F04` (strips finding statements, CWEs, `file:line` locators, and gap descriptions from terminal report artifacts) | rework |
| `job_openvex_export` | `job_final_publication_gate`, `job_inference_security_review`, `resolved.json`, and undeclared `job_review_intake` `latest.json` | `openvex_exports` (`openvex-export-result.json`, `openvex-manifest.json`, optional `openvex.json`) | `C16-F08` (`job_review_intake` missing from `CONTRACT`, reading `latest.json` directly or failing under `upstream_scope`) | rework |

#### C16-F01 Pre-review producer gaps and security datasets are invisible to the gate and final report, allowing upstream blind spots to publish as `review_complete: true`
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_final_publication_gate`
- **Evidence**: `src/appsec_review/jobs/accepted_review.py:239-269`, `src/appsec_review/jobs/job_final_publication_gate/classify.py:62-119`, and `src/appsec_review/jobs/job_final_report_publication/report.py:42-45,72-75` (`render.py:138`). `load_accepted_review` inspects only `job_inference_security_review`'s internal cell accounting, lane-B `coverage_matrix`, and ledger `gap_ids`, plus the four post-review completion jobs; `classify()` emits `PUBLISHABLE` and `build_report()` sets `review_complete: True` (`review presented as complete: **yes**`) whenever `review["status"] == "COMPLETE"` and no inference-stage or completion-stage `gap` limitation exists.
- **Impact**: If `job_project_build` or `job_language_build` failed to compile major modules, `job_codeql_analysis`/`job_evidence_collection`/`job_clang_static_analysis` degraded with `ProducerGap`s, `job_review_intake` excluded subtrees, or `job_dependency_intelligence`, `job_owasp_control_assessment`, and `job_threat_model_generation` recorded gaps (while `job_inference_security_review` cleanly finished whatever residual packages survived), the final report declares `PUBLISHABLE` and `review_complete: true`—hiding upstream blind spots as clean and omitting dependency advisories, OWASP control assessments, and threat models entirely.
- **Recommendation**: Have `job_final_publication_gate` (`datasets.py`, `attachments.py`, `classify.py`) consume the run-wide producer coverage/gap summary from `job_review_data_indexing` (`input_matrix` / upstream `ProducerGap` inventory), convert any non-`SUCCEEDED` upstream evidence producer into a `kind: "gap"` limitation that blocks `PUBLISHABLE` / `review_complete: true`, and surface bounded dependency-advisory, OWASP-control, and threat-model sections (or explicit non-inclusion notices) in `job_final_report_publication/report.py` and `render.py`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C16-F02 `media_assets.py` unanchored `ftyp` and 2-byte magic checks override producer artifact kinds and hide code/binaries as `SKIPPED_NA` media
- **Kind**: `defect`
- **Severity**: `critical`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/media_assets.py:86-92,163,202`, `src/appsec_review/jobs/job_artifact_security_analysis/formats.py:122-129`, and `src/appsec_review/tool_inputs.py:29-34,116-121`. `_isobmff(head)` checks only `head[4:8] == b"ftyp" and head[8:12] not in _HEIF_BRANDS` without checking `len(head) >= 12` or a valid big-endian box size in `head[0:4]`; `type1` and `jpeg-xl` match bare 2-byte prefixes `(0, b"\x80\x01")` (which collides with Intel/MS OMF `.obj` `0x80` `THEADR` headers) and `(0, b"\xff\x0a")`; and `formats.classify()` allows `recognize_asset(head, "")` to override `accepted-producer-kind` (`generated-bundle`, `unrecognized-native`, `python-bytecode`) as `family="media-asset"`.
- **Impact**: Any extensionless or classified artifact whose bytes 4..8 equal `"ftyp"` (for example a JS/Python bundle starting with `var ftype = ...` or `def ftype(`) or binary starting with `\x80\x01`/`\xff\x0a` is reclassified as video/font/image media and dropped by `tool_inputs.py` as `SKIPPED_NA` (`INPUT_FORMAT_UNSUPPORTED`) instead of being scanned or recorded as a `GAP`; additionally, `.svg` (`media_assets.py:174`) and `.blend` (`media_assets.py:214`) are treated as inert media despite active `<script>`/XXE and embedded auto-run Python vectors.
- **Recommendation**: Tighten `_isobmff`/`_heif` in `src/appsec_review/media_assets.py` to require `len(head) >= 12`, a plausible box size in `head[0:4]`, and printable ASCII major brands; require PFB segment length plus `%!PS-AdobeFont`/`%!FontType1` at offset 6 for `type1`; validate the JPEG XL codestream header beyond 2 bytes; remove `.svg` and `.blend` from blanket media skipping (or scan `.svg` as XML/web source); and never let `recognize_asset` override `unrecognized-native` in `formats.py:124`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C16-F03 Unescaped `Heading.anchor` in `reporting/latex.py` allows LaTeX primitive injection into `\label{...}`
- **Kind**: `weakness`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/reporting/latex.py:343-347` and `containers/report/latex/template/appsec-report.cls:114-133`. While `Heading.text` and `Heading.subtitle` pass through `tex(...)`, `block.anchor` is emitted via `{clean(block.anchor)}` into `\rsection{...}{...}{#3}` (`\label{#3}`), and `clean()` (`reporting/text.py:33-50`) strips only control and bidi characters while leaving `\`, `{`, `}`, `%`, `#`, `$`, `&`, `_`, `^`, and `~` active.
- **Impact**: `Document` and `Heading` are public `reporting` APIs (`src/appsec_review/reporting/__init__.py:18-30`); unlike `reporting/html.py:217` (which calls `_slug(block.anchor)`), any caller constructing a `Heading.anchor` from a target path, package identifier, or symbol name injects raw XeLaTeX macros into `report.tex` or aborts PDF compilation on `_`/`#`/`%`. (Downgraded from `critical` to `low` on Section 7 spot-check: every dynamic `Heading(...)` caller in `reporting/` passes `reporting.text.anchor(*parts)` returning `'a-' + sha256[:16]` or static ASCII literals, so untrusted target bytes cannot currently reach `Heading.anchor`, though `latex.py:346` lacks local defense-in-depth escaping.)
- **Recommendation**: Restrict `block.anchor` in `src/appsec_review/reporting/latex.py:346` through an ASCII slug sanitizer (`re.sub(r"[^A-Za-z0-9:.-]+", "-", clean(block.anchor)).strip("-")`, matching `html.py:_slug`) before emitting `\rsection` / `\rsubsection` / `\rsubsubsection`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C16-F04 Neither `final-report.{json,md}` nor standalone `reporting` (`report.html` / `report.pdf`) lets a reader verify a finding line-by-line from the report
- **Kind**: `weakness`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_final_report_publication`
- **Evidence**: `src/appsec_review/jobs/accepted_review.py:65-97`, `src/appsec_review/jobs/job_final_report_publication/render.py:78-116,220`, `src/appsec_review/reporting/loader.py:185-202,423-451`, and `src/appsec_review/reporting/evidence.py:52-88`. `final-report.json` and `final-report.md` omit the claim `statement`, `weakness_cwe`, `security_predicate`, `affected_entities`, resolving `path:start_line-end_line` locations, source excerpts, and gap descriptions, printing only SHA-256 IDs (`claim-...`, `evrel-...`, `gap-...`); even the offline run renderer (`reporting/loader.py:441-443`) prints abbreviated `asr:source:...` entity hashes without resolving them to `file:line` or source text, showing a location only when a reviewed package happened to be a single-lead package with inline `lead.location`.
- **Impact**: A security engineer receiving `final-report.md`, `final-report.json`, or `report.pdf` cannot inspect what vulnerability was found, which file and line numbers establish it, or what any `gap-...` ID means without opening internal `projection.json`, SQLite retrieval shards, or protected developer dossiers (which themselves exclude `verification_backlog` findings that lack PoCs, `job_dossier_publication/job.py:156-157`).
- **Recommendation**: Include secret-redacted resolving source locators (`path`, `start_line`, `end_line`), `weakness_cwe`, `security_predicate`, bounded claim summaries, and human-readable gap summaries in `accepted_review.py` / `final-report` (or resolve `entity_id` and `gap_id` through accepted index/ledger artifacts in `reporting/loader.py` as `reporting/dossiers.py:100-137` already does).
- **Effort**: `M (days)`
- **Already registered**: `T-076` covers adding attacker position, owner, enclosing function, source/sink symbols, and remediation actionability to claims; what is new is that already-recorded claim statements, CWEs, `evrel-*` source locators, and `gap-*` descriptions are stripped today by both `final-report` and `reporting/loader.py`.

#### C16-F05 `job_final_publication_gate` contract marks optional completion jobs `WHEN_ENABLED` + `REJECT`, crashing gate admission whenever an enabled completion job fails
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_final_publication_gate`
- **Evidence**: `src/appsec_review/jobs/job_final_publication_gate/datasets.py:29-70` versus `src/appsec_review/runtime/inputs.py:186-188` and `src/appsec_review/jobs/job_final_publication_gate/attachments.py:250-252`. `CONTRACT.inputs` declares `job_dossier_publication`, `job_poc_generation`, `job_remediation_planning`, and `job_remediation_validation` with `availability=Availability.WHEN_ENABLED, missing=MissingPolicy.REJECT`, while `appsec-review.toml:3496,3528,3559` enables remediation planning, remediation validation, and dossier publication by default. When any enabled completion job fails without an accepted handoff, `admit_inputs` raises `ValueError("required input unavailable: ...")` before the gate starts, making the gate's `Disposition.GAP` -> `PUBLISHABLE_WITH_LIMITATIONS` path (`attachments.py:250-252`, `classify.py:92-104`, `docs/operations/final-report.md:56-62`) unreachable.
- **Impact**: Any failure in a non-authoritative post-review attachment job (such as a Docker/XeLaTeX error in `job_dossier_publication` or timeout in `job_remediation_validation`) aborts `job_final_publication_gate`, `job_final_report_publication`, and `job_openvex_export`, depriving the user of a final report after a completed review.
- **Recommendation**: Change `job_dossier_publication`, `job_poc_generation`, `job_remediation_planning`, and `job_remediation_validation` in `src/appsec_review/jobs/job_final_publication_gate/datasets.py:29-70` to `availability=Availability.OPTIONAL, missing=MissingPolicy.GAP` (matching `job_dossier_publication/datasets.py:40-55`), and add a `JobRunner` test in `tests/test_final_report.py` covering an enabled completion job with no accepted handoff.
- **Effort**: `S (under a day)`
- **Already registered**: no (Deduplicated in headline totals under `C01-F01`: Control-layer `WHEN_ENABLED` + `MissingPolicy.REJECT` blocking `job_final_publication_gate` when an enabled attachment job fails or skips.)

#### C16-F06 `tool-report-latex` remains marked `manual = true` in `containers/catalog.toml`, skipping preflight image-pin verification for default `job_dossier_publication` runs
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_dossier_publication`
- **Evidence**: `containers/catalog.toml:533-535,547`, `appsec-review.toml:3558-3561`, and `src/appsec_review/reporting/dossier_render.py:70-82,99-101`. `containers/catalog.toml` still sets `manual = true` with comment `"No pipeline job runs it, so job_image_pin_verification does not require it"`, whereas `job_dossier_publication` runs by default (`enabled = true`, `render_pdf = true`) and converts `ContainerIntegrityError` on `tool-report-latex` into `IntegrityError`, failing `dossiers.create`.
- **Impact**: A missing or unpinned `tool-report-latex` image on a review host is not caught by `job_image_pin_verification` at run start and instead crashes `job_dossier_publication` at the end of a multi-hour review (and, with C16-F05, blocks `final-report` publication).
- **Recommendation**: Remove `manual = true` and update `purpose` on `tool-report-latex` in `containers/catalog.toml:533-548` so `job_image_pin_verification` checks its `host-pins.toml` digest whenever `job_dossier_publication` (`render_pdf = true`) or `[reporting.telemetry_report]` is enabled.
- **Effort**: `S (under a day)`
- **Already registered**: `T-050` (`docs/TODO.md:697`) lists dropping `manual = true` when calling `tool-report-latex` from a publication job; what is new is that `job_dossier_publication` already calls it by default, making `manual = true` a live late-run failure bug rather than future feature work.

#### C16-F07 `RunReader` in `reporting/sources.py` globs across all historical `attempts/*`, merging failed/retried review ledgers into `report.html` and `report.pdf`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/reporting/sources.py:85-141,197-204`. `RunReader.ledger()` globs `data/jobs/job_inference_security_review/attempts/*/steps/*/tasks/*/ledger.jsonl` across every attempt directory rather than reading the accepted attempt bound by `latest.json`; `final_report()` and `handoff()` pick `sorted(...)[-1]` without checking `latest.json` or `status == "ACCEPTED"`; and `assembled_package()` picks `sorted(...)[0]` (the oldest attempt).
- **Impact**: Whenever a run undergoes stop/fix/resume or retries an attempt of `job_inference_security_review` or `job_final_report_publication`, `reporting render` (`report.html` and `report.pdf`) concatenates ledger events from aborted attempts—corrupting `claim_state` transitions and inflating claim/relation/gap counts—and can select an unaccepted `final-report.json` or mismatched first-attempt review package.
- **Recommendation**: Resolve `job_final_report_publication`, `job_final_publication_gate`, and `job_inference_security_review` in `src/appsec_review/reporting/sources.py` via `runtime.consume.accepted_upstream(run_dir, job_id, required=False)` and restrict `ledger()` and `assembled_package()` to the accepted attempt's bound `claim-ledger.jsonl` and package manifest.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C16-F08 `job_openvex_export` omits `job_review_intake` from `CONTRACT`, silently disabling intake provenance and repository-IRI conflict checks in real runs
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_openvex_export`
- **Evidence**: `src/appsec_review/jobs/job_openvex_export/datasets.py:28-59`, `src/appsec_review/jobs/job_openvex_export/inputs.py:259-276,456-515`, and `src/appsec_review/runtime/consume.py:65-72,148-165`. `inputs.py:456` calls `_accepted(reader, INTAKE_JOB, optional=True)` to bind `job_review_intake` acquisition provenance and reject an operator `repository_iri` that conflicts with accepted acquisition, but `CONTRACT.inputs` declares only `job_final_publication_gate` and `job_inference_security_review`. When `JobRunner` enters `upstream_scope` (`pins = current_pins(reader.root)` is non-`None`), `INTAKE_JOB not in pins` is always true at `inputs.py:271-273`, so `_accepted` unconditionally returns `None`; moreover, lines `259-266` still require live `latest.json` on disk even when reading a pinned upstream handoff.
- **Impact**: In every real pipeline execution, `products[0].acquisition` in `openvex-manifest.json` is `null`, `RepositoryIdentityBasis.ACCEPTED_ACQUISITION` is unreachable, and an operator `repository_iri` contradicting the reviewed repository is never rejected (masked in `tests/test_openvex_job_units.py:57-63` because `ExportUnits` calls handlers directly outside `upstream_scope`).
- **Recommendation**: Add `job_review_intake` (`handoff` and `review_intake`, `Availability.OPTIONAL`, `MissingPolicy.GAP`) to `CONTRACT.inputs` in `src/appsec_review/jobs/job_openvex_export/datasets.py`, refactor `_accepted` in `inputs.py:256-276` to delegate directly to `accepted_upstream(reader.root, job, required=not optional)` without re-requiring live `latest.json` equality when `pinned.pinned` is true, and execute `JobRunner` in `tests/test_openvex_job_units.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no (Deduplicated in headline totals under `C01-F02`: Undeclared `job_review_intake` read via `latest.json` bypassing `accepted_upstream` (`job_openvex_export`).)

#### C16-F09 Standalone `scripts/render-report.sh` and `scripts/render-report.ps1` bypass `ContainerExecutor`, image-digest pinning, signing verification, and PowerShell timeouts
- **Kind**: `weakness`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `scripts/render-report.sh:159,179,194-202` and `scripts/render-report.ps1:201,226,229-240`. Unlike `reporting/dossier_render.py:70-82`, both scripts invoke raw `docker run` with mutable tag `appsec-review/tool-report-latex:1.0.0` (or unverified `--image`), never verify `deploy/dagster/host-pins.toml` `image_id` or `[signing]` envelopes, omit `--ulimit`, `chmod 0777` the host scratch directory, silently skip `timeout 600` in `render-report.sh:195` if `timeout` is absent, and enforce no timeout at all in `render-report.ps1:239`.
- **Impact**: Rendering `report.pdf` on a run containing hostile target/model strings executes an unverified mutable container tag outside the repository's image-pinning and signing policy, and a hung XeLaTeX invocation stalls `render-report.ps1` indefinitely.
- **Recommendation**: Add `--format pdf` to `src/appsec_review/reporting/__main__.py` backed by `ContainerExecutor` and `load_catalog` (sharing `dossier_render.py`'s pinned `tool-report-latex` runner), and turn `scripts/render-report.{sh,ps1}` into thin CLI wrappers over `python -m appsec_review.reporting render`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C16-F10 C16 jobs bypass `runtime.consume.accepted_upstream` read receipts, ignore `upstream_handoffs` pins in dossiers/gate, and remain on legacy free-text gaps
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/accepted_review.py:168`, `src/appsec_review/jobs/job_dossier_publication/job.py:135-137`, `src/appsec_review/jobs/job_dossier_publication/inputs.py:55,175`, `src/appsec_review/jobs/job_final_publication_gate/attachments.py:95,247,374`, `src/appsec_review/jobs/job_final_publication_gate/verify.py:52`, and `tests/test_gap_contract.py:14-17`. Three C16 jobs read upstream `latest.json` directly via `indexing.store.accepted_handoff` instead of `runtime.consume.accepted_upstream` (recording zero `observe_handoff` receipts); `job_dossier_publication` never consults `unit.job.upstream_handoffs` at all and fails with `IntegrityError` if an optional upstream head advances mid-attempt (`inputs.py:175-180`); `job_final_publication_gate/datasets.py:27-28` consumes `job_language_build` without listing it in `schedule_after`; and all four C16 jobs remain exempted in `LEGACY_FREE_TEXT_GAPS`.
- **Impact**: C16 violates the standardized control-layer contract in `AGENTS.md`: consumption audits cannot see upstream handoff reads for dossiers, gate, or final report; `job_dossier_publication` is exposed to live `latest.json` races instead of reading its claim-pinned upstream handoffs; and C16 gaps lack `producer-gap/1` schema validation.
- **Recommendation**: Migrate `accepted_review.py`, `job_dossier_publication/inputs.py`, `job_final_publication_gate/attachments.py`, and `job_final_publication_gate/verify.py` to `runtime.consume.accepted_upstream`, add `job_language_build` to `job_final_publication_gate`'s `schedule_after`, emit `interchange.producer_gap` with `strict_gaps=True`, and delete all four C16 jobs from `LEGACY_FREE_TEXT_GAPS` in `tests/test_gap_contract.py`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C16-F11 `containers/report/latex/render-pdf.sh` exits 0 with unresolved `??` references when XeLaTeX does not converge in 3 passes
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_dossier_publication`
- **Evidence**: `containers/report/latex/render-pdf.sh:45-67` and `src/appsec_review/reporting/dossier_render.py:86-98`. `render-pdf.sh` loops `while [ "$pass" -le 3 ]`; when pass 3's `report.log` still matches `"Rerun to get\|Label(s) may have changed"`, line 59 increments `pass` to `4`, exits the loop without error, copies `report.pdf`, prints `"wrote /scratch/report.pdf after 4 pass(es)"`, and returns exit code `0`.
- **Impact**: Dossiers or standalone reports whose table-of-contents or cross-reference pagination shifts on pass 2->3 are published as clean `"rendered"` PDFs containing unresolved `??` labels or stale page numbers, with misleading log output (`after 4 pass(es)` when 3 ran).
- **Recommendation**: Check `grep -q "Rerun to get\|Label(s) may have changed\|There were undefined references" report.log` after the loop in `containers/report/latex/render-pdf.sh:61` (allowing a 4th pass if needed) and exit non-zero on non-convergence so `dossier_render.py` records `dossier_pdf_render_failed`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C16-F12 `job_dossier_publication` builds duplicate PDFs for confirmed+PoC findings, slices `max_source_excerpts` before filtering non-source entities, and stamps `1970-01-01` PDF dates
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_dossier_publication`
- **Evidence**: `src/appsec_review/jobs/job_dossier_publication/job.py:102-120,156-210`, `src/appsec_review/reporting/dossiers.py:73-163,265`, and `src/appsec_review/reporting/dossier_render.py:68`. First, `admitted` queues both `(CONFIRMED_FINDING, key)` and `(POC, key)` for any confirmed finding with a PoC while passing identical `poc` and `poc_source` payloads to `build_dossier`, spawning two serial Docker/XeLaTeX containers for identical content under different titles (up to `max_dossiers = 64` x `120s` = 128 minutes). Second, `_excerpts` slices sorted `identities[:settings.max_source_excerpts]` (`4`) before checking entity type, and `asr:artifact:`, `asr:build:`, `asr:ci:`, `asr:component:`, `asr:config:`, and `asr:dependency:` all sort alphabetically before `asr:source:`. Third, `dossier_render.py:68` hardcodes `source-date-epoch` to `b"0\n"`.
- **Impact**: Every confirmed finding with a PoC consumes two `max_dossiers` slots and doubles container runtime; findings citing four build/component/config/dependency relations alongside `asr:source:...` lose their resolving source excerpt behind `source_excerpt_cap`; and every dossier PDF carries a bogus `1970-01-01T00:00:00Z` creation timestamp.
- **Recommendation**: Emit `DossierKind.POC` in `src/appsec_review/jobs/job_dossier_publication/job.py:156-157` only for `supported` findings not already covered by a `CONFIRMED_FINDING` dossier; filter/prioritize `asr:source:` (and `direct_evidence` ahead of `analyst_assessed_evidence`) before applying `max_source_excerpts` in `job.py:105-108`; and derive `source-date-epoch` from the accepted review handoff's `completed_at`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C16-F13 `job_openvex_export` runs 4 full-graph hash sweeps per attempt, has zero report linkage, and emits synthetic URNs unmatchable by VEX tooling
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_openvex_export`
- **Evidence**: `src/appsec_review/jobs/job_openvex_export/job.py:92-104,126,141,160,182`, `src/appsec_review/jobs/job_openvex_export/inputs.py:309-395`, `src/appsec_review/jobs/job_openvex_export/contracts.py:258-278`, and `src/appsec_review/jobs/job_openvex_export/reporting.py:169` (`metrics.py:38`). One attempt executes `verify_inputs` four times (`load`, `assemble`, and twice inside `publish` at lines `160` and `182`), re-hashing every review shard, package, score, and attachment already certified by `job_final_publication_gate`; `load_export` has zero callers outside telemetry `metrics.py:38`; and statements emit only `urn:appsec-review:vulnerability:<sha256>` and `urn:appsec-review:source-snapshot:...` without `CVE-*`/`GHSA-*` aliases or `pkg:` PURL subcomponents.
- **Impact**: ~1,650 lines of exporter code repeat full-run I/O four times, produce an `openvex.json` never referenced in `final-report.{json,md}` or `report.html`/`report.pdf`, and give downstream SBOM/VEX consumers (Grype, Trivy, Dependency-Track, osv-scanner) no standard advisory ID or package PURL to correlate even when a confirmed finding originated from `job_dependency_intelligence` / OSV / Grype.
- **Recommendation**: Verify upstream review artifacts through `job_final_publication_gate/verify.py:verify_gate_snapshot` once in `load` (checking only `verified-inputs.json` and gate handoff stability in later steps), populate `vulnerability.aliases` (`CVE-*`/`GHSA-*`) and `products[].subcomponents` (`pkg:...` PURLs) when a finding cites an indexed dependency/advisory entity, and surface `load_export` summary status in `reporting/loader.py`.
- **Effort**: `M (days)`
- **Already registered**: no

#### C16-F14 `reporting/text.py` leaves ASCII backticks and apostrophes exposed to XeLaTeX smart-quote ligatures in non-monospace text
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/reporting/text.py:25-30,90-108` and `containers/report/latex/template/appsec-report.cls:44-47`. `appsec-report.cls` sets `\defaultfontfeatures{Ligatures=TeX}` globally (disabling it with `Ligatures=TeXOff` only on `\setmonofont`), and `_TEX_SPECIAL` escapes `"` (`\textquotedbl{}`) and `-` (`{-}`) but omits `` ` `` and `'`.
- **Impact**: Any `tex(...)` prose, claim statement, remediation invariant, code caption, or non-monospaced table cell containing `` ` ``, `'`, doubled backticks, or `''` (such as SQL predicates `' OR ''='` or shell/JS snippets) renders typographic curly quotes in dossier and report PDFs, silently corrupting copy-pasted payloads and identifiers.
- **Recommendation**: Escape `` ` `` and `'` in `_TEX_SPECIAL` in `src/appsec_review/reporting/text.py:25-30` (for example `\textasciigrave{}` and `\textquotesingle{}` with `textcomp`, or disable `Ligatures=TeX` on body fonts in `containers/report/latex/template/appsec-report.cls:44`), and extend `tests/reporting/test_reporting.py:143` to assert exact ASCII preservation.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C16-F15 Unit tests bypass `JobRunner` `upstream_scope` and single-attempt assumptions, masking C16-F05, C16-F07, C16-F08, and C16-F11
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/test_openvex_job_units.py:55-63`, `tests/test_dossier_publication.py:57,67-76`, `tests/test_final_report.py:310-375`, and `tests/reporting/test_reporting.py:24-30`. `ExportUnits` invokes `job_openvex_export` unit handlers directly outside `JobRunner` (leaving `current_pins` `None` and hiding C16-F08); `test_final_report.py` tests optional-capability `GAP` classification via `gate_classify.classify()` directly rather than `JobRunner` admission with an enabled missing producer (hiding C16-F05); `test_reporting.py` exercises only a 1-attempt run fixture (hiding C16-F07); and no unit test exercises `scripts/render-report.{sh,ps1}` or `render-pdf.sh` pass-3 non-convergence (C16-F09, C16-F11).
- **Impact**: Extensive unit suites pass green while real `JobRunner` runs fail admission on optional-job gaps, drop `job_review_intake` in OpenVEX export, and merge multi-attempt ledgers in `reporting render`.
- **Recommendation**: Run `job_openvex_export` and `job_final_publication_gate` (with enabled-but-missing optional producers) through `JobRunner` in `tests/test_openvex_job_units.py` and `tests/test_final_report.py`, add a multi-attempt fixture test for `RunReader` in `tests/reporting/test_reporting.py`, and add focused unit tests for `Heading.anchor` escaping and `render-pdf.sh` convergence failure.
- **Effort**: `S (under a day)`
- **Already registered**: `T-050` notes adding a `pdftoppm` visual check for `tool-report-latex`; the `JobRunner` admission/pin scope, multi-attempt `RunReader`, and convergence test gaps are new.

#### C16-F16 `final-report.md` drops attack-chain objectives/qualifications, remediation invariants/reasons, and dossier titles already validated upstream
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_final_report_publication`
- **Evidence**: `src/appsec_review/jobs/job_final_report_publication/render.py:155-208` and `src/appsec_review/jobs/job_final_publication_gate/attachments.py:165-188,283-348`. Even for post-review attachments that succeeded, `render.py` emits only `chain_id` + `status` + path for attack chains (after `attachments.py:165-178` strips chain `objective` and `limitations`), only `finding_package_id` + `status` + artifact path for remediation proposals/validations (dropping `reason`, `violated_invariant`, and `corrected_invariant`), and only `dossier_id` + paths for dossiers.
- **Impact**: Readers of `final-report.md` get an index of SHA-256 IDs and run-internal file paths rather than a self-contained executive/engineering summary of multi-step exploit chains, broken security invariants, or why a PoC/remediation check failed.
- **Recommendation**: Retain bounded `objective`/`qualification` fields in `attachments.py` chain projections and render `reason`, `violated_invariant`, `corrected_invariant`, and dossier finding titles in `src/appsec_review/jobs/job_final_report_publication/render.py:155-208`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C16-F17 Redundant multi-pass full-snapshot re-hashing and duplicate review-preflight logic across C16 jobs
- **Kind**: `remove`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/jobs/job_final_report_publication/job.py:75,85,103`, `src/appsec_review/jobs/job_final_publication_gate/verify.py:20-35,75`, and `src/appsec_review/jobs/job_openvex_export/inputs.py:309-395` (`job.py:160,182`). `job_final_report_publication` calls `verify_gate_snapshot` (re-hashing up to 30,000 transitive `bindings` files) three separate times across its millisecond-scale `load`, `assemble`, and `publish` units; `job_openvex_export` re-implements ~90 lines of review manifest/ledger preflight (`_preflight_review`, `_manifest`) duplicating `accepted_review.py` and calls `reprove` twice inside `publish` alone.
- **Impact**: Multiplies end-of-run file stat/SHA-256 I/O by 3x in `job_final_report_publication` and 4x in `job_openvex_export` while maintaining two diverging review-snapshot verifiers.
- **Recommendation**: Delete `_preflight_review` and `_manifest` in `src/appsec_review/jobs/job_openvex_export/inputs.py:309-395` in favor of `verify_gate_snapshot`, remove the duplicate `reprove` at `job_openvex_export/job.py:182`, and verify transitive `bindings` once in `load` while checking only `gate.json` + `latest.json` pointer stability in `assemble`/`publish`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C16-F18 Documentation, comments, and `telemetry_report.py` drift from `T-051` host-pin configuration and `/2` report contracts
- **Kind**: `doc-drift`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `docs/operations/dossier-publication.md:59` and `containers/report/latex/README.md:27` state `image_id` is configured under `[jobs.job_dossier_publication.settings]` in `appsec-review.toml`, whereas `T-051` moved `image_id` to `deploy/dagster/host-pins.toml` (`src/appsec_review/config/host_pins.py:20,139`); `src/appsec_review/config/telemetry_report.py:10-13,22` still hardcodes `DEFAULT_IMAGE_ID = "sha256:1dd77c96..."` with a comment referencing `jobs.job_dossier_publication.settings`; `docs/operations/report-rendering.md:14` states no pipeline job invokes the PDF container; `docs/operations/final-report.md:56-68` omits `dossiers`, `remediation_*`, and `capabilities` from the `/2` report overview; and `src/appsec_review/media_assets.py` lives at package root under C16 ownership despite having callers only in C09 (`tool_inputs.py:30`, `job_artifact_security_analysis/formats.py:13`).
- **Impact**: Operators following `dossier-publication.md`, `report-rendering.md`, or `containers/report/latex/README.md` configure image pins in the wrong file or assume `tool-report-latex` is offline-only, and `telemetry_report.py` carries a hardcoded image digest in source.
- **Recommendation**: Reconcile `docs/operations/dossier-publication.md`, `docs/operations/report-rendering.md`, `docs/operations/final-report.md`, and `containers/report/latex/README.md` with `host-pins.toml` and `/2` gate/report schemas; resolve `TelemetryReportSettings.image_id` from `host-pins.toml`; and relocate `media_assets.py` next to `tool_inputs.py`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-051` (done) moved container pins to `host-pins.toml`; what is new is that C16 docs and `config/telemetry_report.py` were left pointing at `appsec-review.toml` / hardcoded `DEFAULT_IMAGE_ID`.
### C17 Observability, metrics and quality measurement

**Active findings:** 17 (`0` critical, `5` high, `10` medium, `2` low).

C17 contains strong epistemic machinery—closed `ratio()`/`unavailable()` contracts, absence-is-not-fixed lifecycle classification, paired true-lead retention alongside false-lead removal, and an isolated read-only telemetry PDF renderer—but its finding-quality layer is not yet wired into completed runs or real run artifacts end to end. Today the system cannot automatically answer "did this change make the findings better or worse?" because `GraphRunner._finish` emits only `run-metrics/7` activity counters while three parallel quality frameworks (`observability/quality.py`, `observability/experiments/`, `observability/findings/`) sit behind manual CLIs with half of `scorecard.Inputs` unreachable and `publish_lifecycle` never called. Where `observability/findings` does read real runs, adapter and snapshot defects degrade finding measurement directly: `run_adapter.load_run` hardcodes `function: None` on every resolved location (disabling `function_and_code` relocation and function-level crash corroboration), `build_snapshot` collapses duplicate fingerprints by lexical `finding_id` order (silently dropping `confirmed` `ship_blocking` findings behind lower-state duplicates), and `known_functions` crash binding is circular for missed functions. In core event and cost telemetry, `_SECRET` substring value redaction corrupts shipping identifiers (`authorization_access_control`, `model_token_cap`) into `"<redacted>"`, `EventLog.write` bypasses redaction and byte bounds inside permanently retention-protected `data/jobs/`, and unwired price/finding links plus conflicting token aggregators leave cost per job and cost per finding permanently unavailable. Cleaning up dead surfaces (`FindingLifecycle`/`FINDING_TRANSITION`, unwired `BoundedOTLP`), fixing the adapter/redaction/dedup defects, and wiring one post-run finding snapshot and scorecard path will turn C17 from disconnected library modules into a trustworthy measurement of verified findings and coverage.

**Strengths to preserve:**
- Closed-schema `ratio()` and `unavailable()` discipline ensures missing inputs, zero denominators, and unlabelled populations are emitted as explicit `"unavailable"` or `"empty_denominator"` statuses with named reasons and 95% Wilson intervals rather than zero or "clean" (`src/appsec_review/observability/findings/contracts.py:130-185`, `src/appsec_review/observability/experiments/contracts.py:72-112`).
- Triage accounting separates `dismissed_by_adjudication` (reasoned refutation) from `no_claim_raised` (silence), keeps unadmitted leads partitioned by `residual_coverage` reason, and pairs `true_lead_retention` beside `false_lead_removal` whenever answer-key labels exist (`src/appsec_review/observability/triage_reduction.py:155-315`, `src/appsec_review/observability/findings/triage.py:42-135`).
- Revision lifecycle classification enforces "absence is never fixed": an absent prior finding becomes `fix_candidate`, `not_redetected` (same file hash, recall/stability warning), or `not_covered` (unit unreviewed), and only becomes `fixed` after a diff-citing <!-- historical:begin -->`fix-recheck-result/1`<!-- historical:end --> (`src/appsec_review/observability/findings/lifecycle.py:98-182`, `src/appsec_review/observability/findings/recheck.py:68-195`).
- `PipelineLog` uses `FileLock`, `fsync`, a tail-bounded sequence cache (`_tail_sequence`), torn-final-line recovery that still fails closed on mid-file corruption, and `EventCursor` bounded paging for `OperatorFollower` (`src/appsec_review/observability/events.py:165-306`, `src/appsec_review/observability/operator.py:118-210`).
- Telemetry PDF finalization is strictly read-only, strips control characters and escapes all LaTeX specials before compiling in a pinned `--network none` container with `SOURCE_DATE_EPOCH`, publishes atomically, and catches all failures so observability never alters review outcomes (`src/appsec_review/reporting/telemetry/format.py:32-95`, `src/appsec_review/reporting/telemetry_render.py:145-268`, `src/appsec_review/reporting/telemetry_finalize.py:21-52`).
- Derived metric readers re-verify accepted handoff SHA-256 digests and path custody (`validation_scope`) instead of trusting unverified JSON on disk (`src/appsec_review/observability/findings/run_adapter.py:237-269`, `src/appsec_review/observability/findings/coverage_adapter.py:145-230`, `src/appsec_review/observability/telemetry.py:739-815`).

#### C17-F01 `run_adapter.load_run` hardcodes `function: None`, breaking finding relocation and function-level crash correlation
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/findings/run_adapter.py:255-257`; `load_run` resolves each direct-evidence relation through `core` (the accepted retrieval index) and appends `{"path": location["path"], "start_line": location["start_line"], "end_line": location["end_line"], "function": None, "code": str(excerpts[0]["excerpt"])}`, while `src/appsec_review/observability/findings/identity.py:76-97` and `src/appsec_review/observability/findings/crash/correlate.py:94-108,176-184` require `location["function"]`.
- **Impact**: On every real run, `fingerprint["basis"]` degrades from `"function_and_code"` to `"code_only"` (`relocated == exact`), so a one-line edit inside a cited excerpt breaks cross-revision persistence (`persisting` misclassifies as `fix_candidate` + `new`). Simultaneously, `cli.py:73-74` computes `known_functions=None` and `correlate.py` cannot match crash stack frames to findings in the same function outside the exact cited line range, undercounting corroborated findings and inflating `missed_buckets`. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Tracked under host-allocated `T-5001` (`dd6bce805`) alongside bounded retrieval audit details (`cd28ce80f`, `T-154`).]*
- **Recommendation**: Query enclosing symbol/syntax spans already loaded in `core` inside `load_run` (`src/appsec_review/observability/findings/run_adapter.py`) to populate `function` when an indexed symbol span encloses `(path, start_line, end_line)`, even before review claims carry explicit function fields.
- **Effort**: `S (under a day)`
- **Already registered**: `T-076` notes review claims do not yet carry `function`; new here is that `load_run` already holds `core` with symbol/syntax spans and drops enclosing-symbol lookup, silently defeating `T-060` relocation and `T-072` function-level crash correlation that are marked `done`.

#### C17-F02 `build_snapshot` collapses duplicate fingerprints by lexical `finding_id`, silently dropping `confirmed` findings
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/findings/contracts.py:418-429`; `build_snapshot` iterates `sorted(..., key=lambda item: item["finding_id"])` and keeps the first record whose `identity["exact"]` is unseen, incrementing `first["duplicates_collapsed"]` and discarding all fields of later collisions. `fingerprint()` (`src/appsec_review/observability/findings/identity.py:72-88`) hashes `(weakness_family(cwe), security_predicate, locations)` without `state`, `bucket`, or `severity`.
- **Impact**: When a lower-confidence finding (for example a `supported` `verification_backlog` or medium-severity claim with lexically earlier `finding_id`) shares a weakness family, predicate, and location with a `confirmed` `ship_blocking` finding (for example lane A + lane B or `CWE-121` + `CWE-787` in the `memory_buffer` family), `build_snapshot` discards the `confirmed` `ship_blocking` finding. Downstream `usefulness`, `scorecard`, `lifecycle`, and `crash.corroborate` undercount confirmed actionable yield, ship-blocking count, recall, and precision.
- **Recommendation**: In `src/appsec_review/observability/findings/contracts.py` (`build_snapshot`), select the representative record per `identity["exact"]` by `(bucket_rank, state_rank, severity_rank, ship_blocking, finding_id)` so `confirmed`/`findings`/`ship_blocking`/higher-severity records always win deterministic deduplication.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C17-F03 `PipelineLog` substring value redaction corrupts structured identifiers (`authorization_access_control`, `model_token_cap`)
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/events.py:21,33-41`; `_SECRET` matches `api[_-]?key|authorization|password|secret|token` case-insensitively and line 41 rewrites any string value matching `_SECRET.search(value)` to `"<redacted>"` with none of the suffix exemptions applied to keys on line 34. Shipping persona `"authorization_access_control"` (`pipeline/guidance/registry.json:44`, emitted at `src/appsec_review/inference/execution.py:228`) and failure code `"model_token_cap"` (`src/appsec_review/inference/execution.py:318,349`) both match `_SECRET`.
- **Impact**: Every model and review event for the `authorization_access_control` persona, `model_token_cap` failure reason, or any tool/rule/family/gap string containing `secret`, `token`, `password`, or `authorization` (such as secret-scanning tool ids or token-handling scopes) is rewritten to `"<redacted>"` in `pipeline.jsonl`, `summary.json`, and the telemetry PDF. Per-persona yield, error-class attribution, and tool breakdowns become silently wrong while masquerading as redacted secrets.
- **Recommendation**: Replace raw substring matching on string values in `src/appsec_review/observability/events.py` (`_bounded`) with credential-shape patterns (bearer/header assignments, high-entropy/prefixed tokens, URL userinfo, key=value pairs) or an explicit safe-identifier pattern for snake_case enum/slug tokens (`^[a-z0-9_.:/-]{1,64}$` without credential prefixes), while keeping key-based `_SECRET`/`_CONTENT` redaction strict.
- **Effort**: `S (under a day)`
- **Already registered**: no (Deduplicated in headline totals under `C11-F01`: Blanket substring secret-redaction regex corrupting safe tokens/identifiers in `observability/events.py` and `retrieval/model.py`.)

#### C17-F04 Attempt `EventLog.write` persists unredacted, size-unbounded payloads inside retention-protected `data/jobs/`
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/events.py:313-335`; `EventLog.write` serializes raw `**fields` directly to `attempt_root / "logs" / "events.jsonl"` without calling `_bounded` or checking `MAX_RECORD_BYTES`, and only redacts afterward when forwarding `details=fields` into `self.pipeline.write(...)`. Meanwhile `src/appsec_review/observability/retention.py:157-159` marks `data/jobs/` as permanently `protected_path`.
- **Impact**: Any job or helper passing `prompt`, `response`, `stderr`, `command_line`, `error_message`, or environment/credential text to `context.events.write(...)` writes raw target source, secrets, or multi-megabyte lines to `data/jobs/<job>/attempts/<attempt>/logs/events.jsonl`, bypassing `PipelineLog`'s redaction and 64 KiB record cap inside a directory retention can never prune.
- **Recommendation**: Apply `_bounded` and `MAX_RECORD_BYTES` enforcement inside `EventLog.write` in `src/appsec_review/observability/events.py` before writing to `self.path`, sharing the exact redaction contract of `PipelineLog.write`.
- **Effort**: `S (under a day)`
- **Already registered**: `T-059` (`F10`, "no source or secrets in telemetry"); new here is the concrete bypass in `EventLog.write` while `PipelineLog.write` is redacted. (Deduplicated in headline totals under `C13-F01`: Unredacted target source/credential excerpts escaping `PackageView` into worker prompts, failure recordings, and `EventLog`.)

#### C17-F05 `retention.py` has no catalog producer, fails closed above 10k objects / 20k files, and leaves `data/shared/` and `reports/` unprotected
- **Kind**: `weakness`
- **Severity**: `high`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/retention.py:92-104,149-169`; `_catalog` requires a pre-existing `retention-catalog.json` (which no module in `src/appsec_review/` or `scripts/` produces), rejects catalogs with `len(objects) > 10000` or filesystem trees with `count > 20000` entries, and `protected_path` (`lines 157-158`) protects `data/{jobs,logs,configuration,guidance,orchestration,build}` while omitting `data/shared`, `data/publications`, `data/telemetry`, and `reports`.
- **Impact**: Retention cannot execute on any real run store today; on a real multi-run native/CodeQL store it will immediately abort on the 10,000-object / 20,000-file / 64 MiB `verified_bytes` (`line 149`) ceilings; and if a future catalog generator mismarks a file under `data/shared/` or `reports/` with `role="artifact"` and `retain=False`, `apply_retention` will unlink shared artifacts or published report outputs that findings and dossiers still cite.
- **Recommendation**: Add `"shared"`, `"publications"`, and `"telemetry"` plus top-level `"reports"` to `protected_path` in `src/appsec_review/observability/retention.py`, raise or stream the inventory/verification bounds for real run stores, and build the sealed catalog producer from accepted handoff/report manifests before enabling retention.
- **Effort**: `M (days)`
- **Already registered**: `docs/reviews/appsec-system-review-2026-11-06.md` §8 notes retention is disconnected from real runs; new here are the missing `protected_path` guards over finding-cited `data/shared/` and `reports/` and the 10k-object / 20k-file / 64 MiB ceilings that fail closed on real run stores.

#### C17-F06 Token totals disagree across `cost_provenance`, `model_tokens`, and the telemetry PDF
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/costs.py:107-109` sets `usage[name] = None` for the entire run and job whenever *any* non-reused call has `row[name] is None` (which every failed/timed-out call in `src/appsec_review/inference/execution.py:362-368` emits, and providers without cache reporting emit for `cache_tokens`). Conversely, `src/appsec_review/observability/telemetry.py:1726-1728` sums `isinstance(details.get(key), int)` across *all* events—including replays and partial runs—into `summary["model_tokens"]`, which `src/appsec_review/reporting/telemetry/overview.py:103-107` renders as an unqualified executive-summary `"Tokens (in + out)"` total even when `_models` (`overview.py:330-355`) marks rows `(partial)`.
- **Impact**: A single model timeout in a 500-call review nulls `cost_provenance.run.usage` and `cost_provenance.by_job[job].usage`, while `summary["model_tokens"]` and the page-1 PDF card silently display an understated partial sum (or double-count replayed events carrying integer tokens) with no `(partial)` qualifier.
- **Recommendation**: In `src/appsec_review/observability/costs.py`, report both `known_usage` sums and `missing_usage_calls` counts (excluding `reused` calls), derive `summary["model_tokens"]` in `telemetry.py` from deduplicated non-reused `account_calls` rows, and append `(partial)` in `src/appsec_review/reporting/telemetry/overview.py:_summary_blocks` when `missing_usage > 0`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C17-F07 Cost per job and cost per confirmed finding are unwired end to end
- **Kind**: `missing`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/telemetry.py:1703-1704,1857` calls `account_calls(accounting_records)` without `prices=` or `finding_links=`; `src/appsec_review/observability/costs.py:72-80` also refuses `api_estimate` whenever `cache_tokens is None` or `cache_semantics != "included_in_input"`; and `src/appsec_review/observability/findings/cli.py:134-140` never passes `cost=` into `scorecard.Inputs(...)`.
- **Impact**: Every real API-billed run records `cost_provenance` as `"partial"` / `"unknown"` (`no_trusted_rate_source`) with empty `finding_allocations`, and `finding-metrics/1` always emits `cost_per_confirmed_actionable` as `unavailable` (`no_cost_input`), leaving operators unable to measure model spend per job, per lane, or per confirmed actionable finding.
- **Recommendation**: Add an optional versioned `[telemetry.pricing]` table in central TOML configuration (allowing `cache_tokens = None` as `0` when `cache_semantics == "none"` or unreported), pass configured `prices` and claim-to-invocation `finding_links` into `account_calls` in `telemetry.py`, and read `cost_provenance.run.known_amounts` in `src/appsec_review/observability/findings/cli.py` when `--run-summary` is supplied.
- **Effort**: `M (days)`
- **Already registered**: `T-059` (`F10`) and `T-064` (`done`, added the `cost_per_confirmed_actionable` formula); new here is that `costs.py`, `telemetry.py`, central TOML config, and `findings/cli.py` are never connected, and `costs.py:72` rejects providers that omit `cache_tokens`.

#### C17-F08 `findings/cli.py` leaves half of `finding-metrics/1` unreachable and never persists lifecycle history (`regressed` broken across runs)
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/findings/cli.py:55-63,99-145`; `_snapshot` prints `slice_rules_sha256` to stdout (`line 62`) without storing it on the snapshot, `_scorecard` populates only 13 of the 24 fields of `scorecard.Inputs` (`src/appsec_review/observability/findings/scorecard.py:55-82`), `_scorecard` never calls `history.publish_lifecycle` after `lifecycle.classify` (`lines 108-109`), and `recheck.py`, `stability.py`, and `corpus.py` have no CLI subcommands.
- **Impact**: Using the documented operator CLI (`docs/operations/finding-metrics.md`), `history.previously_fixed(loaded)` (`cli.py:109`) is permanently empty—so `regressed` findings across runs >2 can never be detected and `ages` are not updated from persisted lifecycles—while `fixed`, `still_present`, `slice_rules_sha256`, `stability`/`flapping`/`detection`, `translation_units`, `audit_sample` miss-rate, `role_citations`, `canary`, and `cost` are permanently `0`, `null`, or `"unavailable"` in `finding-metrics/1`.
- **Recommendation**: Persist `slice_rules_sha256` in `finding-snapshot/1` (or pass `--slice-rules` to `scorecard`), add an opt-in `--publish-lifecycle` flag and `recheck` / `stability` / `audit-evaluate` subcommands in `src/appsec_review/observability/findings/cli.py`, and wire `--audit-sample`, `--audit-labels`, and `--cost`/`--run-summary` into `scorecard.Inputs`.
- **Effort**: `M (days)`
- **Already registered**: `T-074` registers only the live model transport for `recheck`; new here is that `publish_lifecycle` is never called by `cli.py` (breaking `previously_fixed` and `regressed`), `slice_rules_sha256` is dropped before `scorecard`, and offline `recheck`/`stability`/`audit` CLI paths are missing.

#### C17-F09 Three overlapping quality frameworks exist (`quality.py`, `experiments/`, `findings/`), none wired into run completion or acceptance
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/quality.py:1-269` (<!-- historical:begin -->`evaluation-trend/1`<!-- historical:end -->, zero imports in `src/appsec_review/`), `src/appsec_review/observability/experiments/metrics.py:1-515` (`quality-experiment/1`, called in `src/` only by `findings/stability.py:412` which itself has no CLI or runtime caller), and `src/appsec_review/observability/findings/scorecard.py:1-360` (`finding-metrics/1`, manual CLI only) implement parallel Wilson intervals, stability/Jaccard, and triage retention/removal formulas while `src/appsec_review/runtime/graph.py:110-124` invokes only `write_run_metrics` and `finalize_telemetry_report`.
- **Impact**: Directly explains why the system cannot answer "did this change make the findings better or worse?" out of the box today: a completed run produces `run-metrics/7` operational counters and a telemetry PDF, while finding-level recall, precision, lifecycle deltas, and stability require manual multi-tool orchestration across three partially overlapping schemas.
- **Recommendation**: Designate `observability/findings` (`finding-snapshot/1` + `finding-metrics/1`) as the single finding-quality surface, fold `quality.py`'s `compare_trends` independent-variable diffing (`configuration`, `prompts`, `model`) into `findings/scorecard.py` comparisons, keep `observability/experiments` strictly as the internal multi-run stability engine called by `findings/stability.py`, and invoke `snapshot_from_run` + `scorecard.build` automatically at the end of `acceptance` / self-grading (`T-090`).
- **Effort**: `M (days)`
- **Already registered**: `T-077` and `T-090` note manual grading steps; new here is the architectural triplication across `observability/quality.py`, `observability/experiments/`, and `observability/findings/` with duplicated statistical/triage primitives and zero runtime callers for two of the three packages.

#### C17-F10 `FindingLifecycle` and `FINDING_TRANSITION` are dead in production, making `summary.json` and the PDF report `0` finding transitions
- **Kind**: `remove`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/telemetry.py:23,51-85,495-496,1713-1714,1859` defines `FindingLifecycle` (`CANDIDATE` -> `REFUTED` | `CONFIRMED`, doing an unlocked O(N) full read of `pipeline.jsonl` per transition at `line 66`), and `src/appsec_review/reporting/telemetry/overview.py:109-110,121,394-404` plus `jobs.py:165-169` render `"Finding transitions"` on page 1 of the telemetry PDF. Zero jobs or review modules in `src/appsec_review/` instantiate `FindingLifecycle` or emit `FINDING_TRANSITION`.
- **Impact**: Every real review PDF displays `"Finding transitions: 0"` on its executive-summary stat strip and `"No finding state transitions were recorded"` in `"Builds and findings"`, even when `job_inference_security_review` adjudicated claims and published confirmed findings—actively misleading readers about whether the review produced findings while `triage_reduction` and `review` hold the real counts.
- **Recommendation**: Remove `FindingLifecycle` and `FINDING_TRANSITION` from `src/appsec_review/observability/telemetry.py`, and replace the dead `"Finding transitions"` stat and table in `src/appsec_review/reporting/telemetry/overview.py` and `jobs.py` with published finding/claim counts from `summary["triage_reduction"]` / `summary["review"]` (or `finding-snapshot/1`).
- **Effort**: `S (under a day)`
- **Already registered**: `T-064` noted `finding_states` double-counted transitions when proposing snapshots, but kept the dead event/PDF card in place; reporting it for removal is new.

#### C17-F11 Crash `missed_buckets` symbol-tier binding is circular when `known_functions` is derived only from reported findings
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/findings/cli.py:72-75` builds `known_functions` exclusively from `{location["function"] for item in snapshot["findings"] for location in item["locations"] if location["function"]}` and passes it to `bind_all` (`src/appsec_review/observability/findings/crash/binding.py:62-75`), before `missed_buckets` (`src/appsec_review/observability/findings/crash/correlate.py:170-189`) filters to `_bound(evidence, index)`.
- **Impact**: Even once `C17-F01` is fixed, a crash report lacking build-id or source-path match (relying on `symbol_matched` tier) can bind **only if the review already reported a finding in one of its stack functions**. Any crash in an unflagged function fails `bind_all` as `unbound` and is silently excluded from `missed_buckets`, blinding the exact recall signal `missed_buckets` exists to provide.
- **Recommendation**: Populate `known_functions` in `src/appsec_review/observability/findings/cli.py` (and `coverage_adapter.py`) from the run's accepted `debug_symbols` or `symbol` retrieval index across the target rather than from `snapshot["findings"]`.
- **Effort**: `S (under a day)`
- **Already registered**: no (`T-087` covers C++/MSVC symbol name normalization, not the circular findings-only symbol universe in `cli.py:73-74`).

#### C17-F12 `_native_sbom_accepted` reads `latest.json` directly and can abort `write_run_metrics` and `telemetry_render`
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: `job_dependency_intelligence`
- **Evidence**: `src/appsec_review/observability/telemetry.py:1244-1275` reads `data/jobs/job_dependency_intelligence/latest.json` directly when `historical is None` instead of resolving the accepted attempt from `HANDOFF_ACCEPTED` events in `pipeline.jsonl` (unlike `_interchange_metrics` at `lines 739-770` and `_review_metrics` at `lines 530-560`), and raises uncaught `ValueError`s inside `_aggregate_run_metrics` (`line 1653`).
- **Impact**: Directly violates `AGENTS.md` ("Never read another job's `latest.json` directly") and lacks per-section error isolation: if `job_dependency_intelligence` (or `_openvex_metrics` / `_tree_sitter_metrics` at `lines 1651-1652`) hits a handoff/member mismatch, `write_run_metrics` raises at run completion (`runtime/graph.py:118`), `summary.json` is never written, and `reporting/telemetry/inputs.py:86-93` hits the identical exception during fallback recomputation, degrading the entire telemetry PDF to `summary_source="unavailable"`.
- **Recommendation**: Resolve `job_dependency_intelligence`'s accepted handoff solely from `HANDOFF_ACCEPTED` records in `records` inside `src/appsec_review/observability/telemetry.py`, and wrap optional per-producer metric sections (`openvex`, `tree_sitter`, `native_sbom`, `codeql`, `owasp`, `review`, `triage_reduction`) in bounded error-recording helpers so one corrupt producer artifact records a named telemetry gap instead of aborting `summary.json`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C17-F13 `PipelineLog.read()` loads the entire `pipeline.jsonl` into memory on every metrics, CLI, and PDF invocation
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/events.py:201-208` reads `self.path.read_bytes()` in full and decodes every JSON line into a Python `list[dict]`, called by `aggregate_run_metrics` (`src/appsec_review/observability/telemetry.py:1609`), `load_telemetry_inputs` (`src/appsec_review/reporting/telemetry/inputs.py:72`), and `logs_command` (`src/appsec_review/cli.py`).
- **Impact**: While `PipelineLog.write` was carefully optimized to read only the tail 64 KiB (`_tail_sequence`), `PipelineLog.read` has no byte or record ceiling. On a full multi-language review with thousands of tool/operation heartbeats and model calls (`pipeline.jsonl` tens or hundreds of megabytes), `GraphRunner._finish` reads and parses the entire file twice back-to-back (`write_run_metrics` then `finalize_telemetry_report` -> `load_telemetry_inputs`), risking high memory spikes at run teardown.
- **Recommendation**: Add streaming line iteration (`iter_records()`) to `PipelineLog` in `src/appsec_review/observability/events.py` with a file-size guard, pass the already-written `summary` from `write_run_metrics` (or stream only job/tool events needed by `inputs.py`) during `GraphRunner._finish`, and route `cli.py` `logs` through `EventCursor`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C17-F14 `tools/quality` omits C17 from `mypy` file scope and runs static sentinel tests instead of job/module-mapped tests
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tools/quality/runner.py:107-112` passes `*paths` to `ruff` and `bandit` but invokes `mypy --config-file=pyproject.toml` without `paths`, restricting type-checking to the six paths hardcoded in `pyproject.toml:84-91` (`[tool.mypy].files`, which excludes all of `observability/`, `reporting/`, and `tools/quality/`). Meanwhile `tools/quality/selection.py:43-60` ignores `tests/job-test-map.json` and returns the same 7 static sentinel test files for every Python change.
- **Impact**: Any type defect or behavioral regression in C17 (`observability/`, `reporting/telemetry*`, `tools/quality/`) passes `python -m tools.quality` with zero `mypy` verification on C17 modules and zero C17 unit tests executed, giving false assurance on quality-gate runs.
- **Recommendation**: Add `src/appsec_review/observability`, `src/appsec_review/reporting`, and `tools/quality` to `[tool.mypy].files` in `pyproject.toml` (or pass changed/scoped `paths` in `tools/quality/runner.py`), and integrate `tests/job-test-map.json` / package-to-test mapping into `tools/quality/selection.py`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C17-F15 `BoundedOTLP` (`observability/otlp.py`) is unwired dead code with no configuration or runtime caller
- **Kind**: `remove`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `src/appsec_review/observability/otlp.py:1-130` defines `BoundedOTLP` (posting JSON over `urllib.request.urlopen`), which is imported nowhere in `src/appsec_review/`, `deploy/`, or `scripts/` (only `tests/test_operations_reporting.py:17`), has no `[telemetry]` / `[otlp]` setting in `appsec-review.toml` or `src/appsec_review/config/`, and contradicts `docs/architecture/telemetry.md:394-395` ("No separate telemetry backend or Azure service is requested").
- **Impact**: Keeps an unused network-egress helper (`urlopen` without scheme restriction beyond caller input) and cursor state file format on the maintenance surface while contributing nothing to review findings, evidence, or local operator observability.
- **Recommendation**: Delete `src/appsec_review/observability/otlp.py` and its unit test in `tests/test_operations_reporting.py` (or, if `T-059` `F10` still wants OTLP later, re-introduce it only with typed central configuration and an `https://` / loopback URL validator when an operator backend exists).
- **Effort**: `S (under a day)`
- **Already registered**: `T-059` (`F10`) lists "optional bounded OTLP export with durable position" as blocked future work; new here is that a partial unconfigured `otlp.py` already landed with zero callers and no URL scheme guard.

#### C17-F16 Documentation drift across `quality-and-retention.md`, `telemetry-report.md`, `finding-metrics.md`, and an unregistered `TODO:` in `telemetry.md`
- **Kind**: `doc-drift`
- **Severity**: `low`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `docs/operations/quality-and-retention.md:133-134` states `compare_trends` returns `incomparable` when prompt, model, or configuration identities differ, contradicting `src/appsec_review/observability/quality.py:160-185` (`T-066`, where those are independent variables reported under `changed`). Additionally, `docs/operations/telemetry-report.md:88` and `docs/architecture/finding-metrics.md:447` state `JobRunner` recomputes `summary.json` on every job completion (contradicting `docs/architecture/telemetry.md:253` and `src/appsec_review/runtime/runner.py`), and `docs/architecture/telemetry.md:371-376` carries a prose `TODO:` block with no `T-NNN` id claiming `FINDING_TRANSITION` is authoritative.
- **Impact**: Misleads operators and agents about trend comparability across prompt/model changes, when `data/telemetry/summary.json` is fresh during an active Dagster run, and violates the `AGENTS.md` rule that every `TODO` names a `T-NNN` entry in `docs/TODO.md`.
- **Recommendation**: Update `docs/operations/quality-and-retention.md:133-134`, `docs/operations/telemetry-report.md:88`, and `docs/architecture/finding-metrics.md:447` to match the code, and remove or register the bare `TODO:` paragraph in `docs/architecture/telemetry.md:371-376`.
- **Effort**: `S (under a day)`
- **Already registered**: no

#### C17-F17 Unit fixtures mask real-run adapter seams (`function: None` fixtures and untested `_SECRET` collisions with shipping enums)
- **Kind**: `test-gap`
- **Severity**: `medium`
- **Confidence**: `verified (traced in code)`
- **Job**: component-wide
- **Evidence**: `tests/test_finding_run_adapter.py:34` and `tests/test_finding_cli.py:48` assert `"function": None` in `run_adapter` snapshots while `tests/test_finding_contracts.py:14,20` hand-authors `"function": "parse_packet"` to test relocation and crash correlation, hiding the broken seam between the two (`C17-F01`). Similarly, `tests/test_pipeline_log.py:19-35` checks synthetic `"token": "must-redact"` keys without testing `PipelineLog.write` on shipping persona/failure values from `pipeline/guidance/registry.json` (`C17-F03`), and `tests/integration/test_finding_metrics.py:72-74` notes its derived-units path has not yet been exercised on a completed run.
- **Impact**: Component unit tests pass individually while missing the exact cross-module regressions where real review artifacts meet finding identity, duplicate collapsing (`C17-F02`), crash `missed_buckets` (`C17-F11`), and telemetry redaction (`C17-F03`).
- **Recommendation**: Add focused unit regressions covering (1) `run_adapter.load_run` -> `identity.fingerprint` -> `crash.correlate` with an indexed enclosing symbol, (2) `build_snapshot` colliding `supported` vs `confirmed` findings on one fingerprint, (3) `PipelineLog.write` + `EventLog.write` over every registered persona/role/failure code in `pipeline/guidance/registry.json`, and (4) `missed_buckets` on a function with zero reported findings.
- **Effort**: `S (under a day)`
- **Already registered**: no
### C18 Tests, acceptance harness and repository process

**Active findings:** 10 (`0` critical, `5` high, `3` medium, `2` low).

C18 owns the offline and live verification harness, the blind acceptance and scoring oracle (`src/appsec_review/acceptance/*`), the test-execution wrapper and collection guards (`scripts/run-tests.sh`, `deploy/dagster/bin/ops_tests.py`, `deploy/dagster/bin/ops_test_guard.py`, `deploy/dagster/bin/stepwise.py`, `src/appsec_review/development/test_selection.py`, `tools/quality/*`), the pytest tier/environment/time-budget enforcement (`tests/conftest.py`, `tests/unit/conftest.py`, `tests/acceptance_plugin.py`, `tests/time_budgets.py`, `tests/test_000_unit_environment_guard.py`), the repository-wide contract gates (`tests/test_gap_contract.py`, `tests/test_skill_separation.py`, `tests/test_todo_registry.py`, `tests/test_documentation.py`, `tests/test_docs_sync.py`, `tests/docs/*`), and the repository-agent development procedures (`.claude/skills/*/SKILL.md`, `.agents/skills/repository-development-skills/SKILL.md`, `docs/TODO.md`). It owns **0 pipeline jobs**, sitting outside the review graph as the measurement and governance plane that decides whether code changes preserve contracts and whether a completed review run actually found real vulnerabilities without answer-key contamination.

**Strengths to preserve:**
- **Fail-closed unit environment guard and timing accountability (`tests/test_000_unit_environment_guard.py:1-95`, `tests/conftest.py:1-210`):** Every pytest session blocks accidental inheritance of production overlays, Dagster homes, or live credentials at collection start and records per-test durations to surface tests exceeding the 10-second unit budget.
- **Strict skill separation and single-backlog enforcement (`tests/test_skill_separation.py:1-120`, `tests/test_todo_registry.py:1-106`):** Automated merge-gate tests prevent repository-agent `.claude/skills/` from leaking into runtime worker prompts (`pipeline/skills/`) and enforce sequential, structured deferred-work tracking in `docs/TODO.md`.
- **Closed documentation metadata and inventory validation (`scripts/docs_support.py:1-265`, `tests/docs/test_docs_frontmatter.py`, `test_docs_identifiers.py`, `test_docs_ledger.py`, `test_docs_links.py`):** Tracked documentation is checked offline against `docs/generated/inventory.json`, `docs/docs-ledger.json`, and `docs/docs-sync.json` for valid frontmatter, live job/schema identifiers, and resolving intra-repo links and anchors.

#### C18-F01 `stepwise.py system` and `answer_key.evaluate` can report `SYSTEM OK` even when `job_inference_security_review` or `job_final_report_publication` publishes zero findings
- **Kind**: `missing-test`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: none (`acceptance/system.py`, `acceptance/answer_key.py`, `deploy/dagster/bin/stepwise.py`)
- **Evidence**: `deploy/dagster/bin/stepwise.py:570-628`, `src/appsec_review/acceptance/system.py:67-131`, `src/appsec_review/acceptance/answer_key.py:160-249`. 1. `final_artifact_problems(run_root)` (`src/appsec_review/acceptance/system.py:67-93`) validates accepted handoffs for **only** `job_review_package_assembly` and `job_document_issue_analysis`. It never checks `job_inference_security_review`, `job_final_publication_gate`, `job_final_report_publication`, or `job_openvex_export`. 2. `command_system` (`deploy/dagster/bin/stepwise.py:576-582`) evaluates required defects via `evaluate(run_root, expectations, include_current_report=system_spec.include_current_report)`. Inside `evaluate()` (`src/appsec_review/acceptance/answer_key.py:216-249`), `observations_from_run(run_root)` loads deterministic scanner observations (`evidence_collection`, `codeql`, `clang`, `cpg`, etc.) and, when `include_current_report=True`, merely appends `current_report_findings(run_root)` into the **same flat `observations` list** (`lines 222-224`). Thus, if Semgrep or CodeQL emitted a raw observation overlapping `defect.line`, `defect.id in matrix.found` succeeds even if `job_inference_security_review` dismissed every lead and `final-report.json` contains zero confirmed findings. 3. `evaluate()` computes `control_violations` for negative controls (`answer_key.py:242-248`), but `command_system` (`stepwise.py:577-582`) checks only `missing` and `artifact_problems`, ignoring `matrix.control_violations`. 4. Both `evaluate_funnel(...)` (`stepwise.py:609-615`) and `score_run(...)` (`stepwise.py:617-625`) are wrapped in `try/except Exception` as strictly informational printouts (`funnel unavailable` / `detector scoring unavailable`) and never gate `return 0` (`SYSTEM OK` at `line 628`).
- **Impact**: An end-to-end acceptance run can pass `SYSTEM OK` when the entire LLM security review, verification, gate, and final report publication stages produce zero confirmed findings—or flood negative controls with false positives—so long as upstream deterministic scanners touched the expected source lines.
- **Recommendation**: Require an accepted `job_final_report_publication` handoff in `final_artifact_problems()`, fail `command_system` on non-empty `matrix.control_violations`, and assert required defects against published review findings (via `FunnelReport.published` or `RunScore` for `producer == "review"`), not undifferentiated raw scanner observations.
- **Effort**: `M`
- **Already registered**: `T-057`, `T-063` (marked `done`, incomplete in `stepwise.py system`)

#### C18-F02 Acceptance funnel halts at `stage="observed"` when no deterministic scanner hits the defect span—marking pure Hunt-lane (`Lane B`) findings as `NOT_REACHED`—and reads lexicographically last attempts instead of accepted handoffs
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: none (`acceptance/funnel.py`)
- **Evidence**: `src/appsec_review/acceptance/funnel.py:448-455, 665-672`. 1. In `_evaluate_defect` (`src/appsec_review/acceptance/funnel.py:665-672`), the stage-1 check runs: Because it returns immediately before inspecting `units`, `leads`, `decisions`, or `published`, any vulnerability discovered solely by `hypothesis_hunter` (`Lane B`, which exists specifically for defects scanners miss) or via a scanner lead anchored on a caller/sink outside `defect.line..end_line` is classified as `NOT_REACHED` (`observed=0, published=0`) even when `final-report.json` confirmed and published it. 2. In `_report` (`src/appsec_review/acceptance/funnel.py:448-455`), the funnel locates `final-report.json` via `sorted((run_root / "jobs" / "job_final_report_publication" / "attempts").glob("*/steps/report/tasks/assemble/final-report.json"))` and reads `paths[-1]`, bypassing `accepted_handoff(run_root, "job_final_report_publication")` (used properly in `system.py:145`). The same unaccepted `attempts/*` globbing occurs in `_load_units` (`lines 296-306`), `_load_leads` (`lines 336-346`), and `_load_decisions` (`lines 393-405`).
- **Impact**: Funnel attribution systematically erases Hunt-lane recall (`T-068` depends on measuring Hunt-lane value) and can grade unaccepted/aborted retry attempts after recovery instead of the run's accepted handoff chain.
- **Recommendation**: Resolve each stage's artifact exclusively from that job's accepted handoff (`accepted_handoff(run_root, job_name)`), evaluate all 5 funnel stages independently of `matching_obs` so Hunt-only leads/publications reach `furthest_stage="published"`, and record `"no_tool_observation_at_location"` only when neither scanner observations nor Lane A/B leads/publications match the defect.
- **Effort**: `S`
- **Already registered**: `T-068` (blocked by accurate Hunt-lane measurement) (Deduplicated in headline totals under `C16-F07`: Post-review readers (`acceptance/funnel.py` and `reporting/sources.py`) globbing `attempts/*` instead of reading `accepted_handoff`.)

#### C18-F03 Detector scoring explodes each published review finding into one `Report` per `direct_evidence` entity, multiplying review false positives while collapsing true positives
- **Kind**: `defect`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: none (`acceptance/answer_key.py`, `acceptance/producer_reports.py`, `acceptance/scoring.py`)
- **Evidence**: `src/appsec_review/acceptance/answer_key.py:199-206`, `src/appsec_review/acceptance/producer_reports.py:173-199`, `src/appsec_review/acceptance/scoring.py:409-424, 496-565`. 1. `current_report_findings(run_root)` (`src/appsec_review/acceptance/answer_key.py:199-206`) iterates `for entity in item.get("direct_evidence", [])` on each finding in `final-report.json`, emitting a separate dict per entity and discarding `finding_id`. 2. `_review_reports(run_root)` (`src/appsec_review/acceptance/producer_reports.py:173-199`) converts every emitted dict into an independent `Report(producer="review", rule="", cwe=..., path=..., start_line=line, ...)`. 3. `_collapse(reports)` (`src/appsec_review/acceptance/scoring.py:409-424`) deduplicates on `(report.producer, report.path, report.start_line, report.rule)`. Because a single multi-line or source-to-sink review finding routinely cites 3–6 distinct `direct_evidence` lines (entry point, intermediate sanitizer bypass, sink), it survives `_collapse` as 3–6 distinct `Report` objects. 4. In `_score_producer` (`scoring.py:513-565`), multiple reports hitting the same expected defect add the same `defect.id` to `hits: set[str]` / `scope_hits: set[str]` (counting once toward recall), whereas a single false-positive finding citing 4 `direct_evidence` lines increments `fp` and `scope_fp` **4 times** (and up to 4 `negative_control_hits` if those lines fall in negative controls).
- **Impact**: Review precision (`precision`, `scope_precision`) and false-positive counts in `RunScore` are systematically distorted against findings that cite rich multi-step `direct_evidence`—penalizing thorough evidence chains even though `T-063` ("Score the published review findings by default") is marked `done`.
- **Recommendation**: Carry `finding_id` on `current_report_findings` / `Report` for `producer == "review"` and score published review findings at the finding level (matching if any cited `direct_evidence` entity matches the defect's location/scope and CWE family, and counting at most 1 FP per `finding_id`).
- **Effort**: `S`
- **Already registered**: `T-063` (marked `done`, entity-explosion regression remains)

#### C18-F04 `model_contract` schema-checks only 2 of 8 model-output families and computes 1-hop rather than transitive taint, breaking `stepwise.py system` baseline comparison on downstream publication jobs
- **Kind**: `defect`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: none (`acceptance/model_contract.py`, `deploy/dagster/bin/stepwise.py`)
- **Evidence**: `src/appsec_review/acceptance/model_contract.py:34-36, 143-175, 218-223`, `deploy/dagster/bin/stepwise.py:591, 599`. 1. `SCHEMA_FILES` (`src/appsec_review/acceptance/model_contract.py:34-36`) registers only `{"target-analysis-proposal/2": "schemas/target-analysis-proposal.schema.json"}`, and `_schema_valid` (`lines 143-175`) adds one structural check for `"native-dependency-resolution-proposal/"`. Every other model-backed job (`job_inference_security_review`, `job_poc_generation`, `job_remediation_planning`, `job_threat_model_generation`, `job_owasp_control_assessment`, `job_build_iteration`) gets `schema_checked=False`. 2. `tainted_jobs(run_root, contract)` (`model_contract.py:218-223`) identifies non-deterministic downstream jobs by checking **only direct 1-hop `upstream_handoffs`**: When `job_inference_security_review` legitimately produces different prose or lead wording across runs, its 1-hop consumers (`job_final_publication_gate`, `job_poc_generation`, `job_remediation_planning`) are added to `tainted`, **but 2-hop+ consumers (`job_final_report_publication` via `job_final_publication_gate` / `job_poc_generation` / `job_remediation_planning`, `job_openvex_export` via `job_final_report_publication`, and `job_remediation_validation` via `job_remediation_planning`) are omitted**. 3. `command_system` (`deploy/dagster/bin/stepwise.py:591, 599`) passes `allowed_jobs=attributable` to `diff_runs(...)`, causing `SYSTEM FAIL` whenever a legitimate model variation in `job_inference_security_review` propagates into `final-report.json` or `openvex.json`.
- **Impact**: Model-contract verification leaves 6 of 8 LLM output families schema-unchecked during acceptance while falsely failing baseline run comparisons whenever review-stage variance reaches terminal report publication.
- **Recommendation**: Compute the fixed-point transitive closure over `upstream_handoffs` in `tainted_jobs()`, and bind JSON schemas in `SCHEMA_FILES` for all structured model proposals/verdicts emitted by inference jobs.
- **Effort**: `M`
- **Already registered**: none

#### C18-F05 GitHub Actions CI (`.github/workflows/quality.yml`) executes at most 7 hardcoded sentinel test files, omitting repository merge gates and allowing broken unit tests (`tests/test_time_budgets.py`) onto `main`
- **Kind**: `missing-test`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: none (`.github/workflows/quality.yml`, `tools/quality/*`)
- **Evidence**: `.github/workflows/quality.yml:31-42`, `tools/quality/selection.py:42-63`, `pyproject.toml:89-100`, `tests/test_time_budgets.py:15, 39-43, 66-69`, `tests/time_budgets.py:21-25`. 1. `.github/workflows/quality.yml` is the only workflow in `.github/workflows/`. It invokes `python -m tools.quality check --base ...`, which selects pytest targets via `tools/quality/selection.py:select_tests` (`lines 42-63`). 2. `select_tests` never consults `src/appsec_review/development/test_selection.py` or `tests/job-test-map.json`: on documentation-only PRs/pushes it runs **only** `config.unit_tests` (the 4 `tests/quality/test_*.py` files at `pyproject.toml:89-94`), and on source/test changes it adds **only** `config.contract_tests` (`tests/test_config.py`, `tests/test_pytest_default_collection.py`, `tests/test_review_model_request.py` at `pyproject.toml:95-99`). 3. Neither `tests/test_todo_registry.py` (explicitly designated "a merge gate" in `AGENTS.md`), `tests/test_skill_separation.py`, `tests/test_gap_contract.py`, `tests/test_job_test_selection.py`, `tests/docs/*`, nor any modified job's unit tests run in CI. 4. Concrete breakage already on `main` at `f29ee4c688`: when `unit_time_budget_seconds = "10"` was added to `pyproject.toml:128` and `tests/time_budgets.py:21-25` (`DEFAULT_TIER_BUDGETS = MappingProxyType({"unit": 10.0, "integration": 300.0, "live": 1800.0})`), `tests/test_time_budgets.py:15` was left at `BUDGETS = {"integration": 300.0, "live": 1800.0}` and `test_ini_values_are_parsed_and_validated` (`lines 66-69`) was left without `"unit_time_budget_seconds"`, causing `tests/test_time_budgets.py` to fail deterministically on `main`.
- **Impact**: PRs and pushes to `main` pass GitHub Actions while breaking `TODO.md` invariants, skill-separation rules, doc-ledger/identifier checks, time-budget tests, or job unit tests.
- **Recommendation**: Update `tests/test_time_budgets.py` for the `"unit": 10.0` tier budget, add repository-wide contract and doc gates (`test_todo_registry.py`, `test_skill_separation.py`, `test_gap_contract.py`, `test_time_budgets.py`, `tests/docs/*`) to `tools.quality` selection (including doc gates when `docs/` changes), and wire `development.test_selection` for touched `src/appsec_review/` job paths once walked `tests/unit/<job_id>/` suites are green.
- **Effort**: `M`
- **Already registered**: none

#### C18-F06 `tests/unit/conftest.py` leaks global monkeypatches across non-`tests/unit/` tests in mixed sessions, while `ops_tests.py` named suites trip `Limits.max_tests = 200` and omit `tests/docs/*`
- **Kind**: `weakness`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: none (`tests/unit/conftest.py`, `deploy/dagster/bin/ops_tests.py`)
- **Evidence**: `tests/unit/conftest.py:101-156`, `tests/conftest.py:92-94, 143-155`, `deploy/dagster/bin/ops_tests.py:36-45, 429-434`, `deploy/dagster/bin/ops_test_guard.py:24-25, 90-95`. 1. `tests/unit/conftest.py:pytest_configure` (`lines 142-151`) replaces `subprocess.Popen.__init__` and `socket.socket.connect` across the entire Python process whenever `tests/unit/` is part of collection, and `guard_dagster_if_imported()` (`lines 126-137`) permanently overwrites `dagster.JobDefinition.execute_in_process`, `GraphDefinition.execute_in_process`, `execute_job`, and `materialize` with `_refuse_dagster` without restoring them in `pytest_runtest_teardown`. In any mixed session (`ops_tests.py` `all-offline`, `orchestration`, or `pytest` collecting both `tests/unit/` and root `tests/test_*.py` / `tests/integration/*`), tests outside `tests/unit/` fail with `UnitTierViolation`. 2. `deploy/dagster/bin/ops_tests.py:run()` (`lines 429-434`) instantiates `Limits()` with `max_tests = 200` and `timeout_seconds = 300` (`ops_test_guard.py:24-25`) even for named suites (`fast`, `all-offline`, `review`, `orchestration`, `graph`). Running `./scripts/run-tests.sh fast` immediately aborts during preflight collection (`unexpected collection count ...; expected=None, max=200`) unless `--max-tests` and `--timeout-seconds` are manually supplied, contradicting `T-113`'s Done-when (`scripts/run-tests.sh fast collects only tests/unit and finishes in under ten minutes`). 3. `SUITES["docs"]` (`ops_tests.py:42-43`) includes only `tests/test_documentation.py`, `tests/test_runtime_guidance.py`, and `tests/test_docs_sync.py`, omitting all 5 `tests/docs/test_*.py` gates (`frontmatter`, `identifiers`, `ledger`, `links`, `generated_docs`). 4. `tests/conftest.py:143-155` runs `assert_unit_test_environment()` in `pytest_configure` only when `_xdist_controller(config)` (`lines 92-94`) is true. A serial focused run (`pytest tests/unit/job_review_intake/test_contract.py` without `-n`) neither collects `tests/test_000_unit_environment_guard.py` nor triggers `_xdist_controller`, bypassing the production-sizing guard documented in `AGENTS.md`.
- **Impact**: Multi-tier or named-suite offline runs fail spuriously from cross-file guard leakage or the 200-test cap, `run-tests.sh docs` misses ledger/frontmatter/identifier violations, and serial focused unit runs skip the production-environment guard. *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Partially addressed in `dd6bce805`, which enforces deterministic `os.umask(0o022)` in `tests/conftest.py`; `tests/unit/conftest.py` session monkeypatch scoping and `ops_tests.py` `max_tests=200` remain open.]*
- **Recommendation**: Scope `subprocess`, `socket`, and `dagster` patches in `tests/unit/conftest.py` to `pytest_runtest_setup`/`teardown` when `_in_unit_tree(item)` holds; give named suites in `ops_tests.py` per-suite `max_tests`/`timeout_seconds` budgets and add `tests/docs` to `SUITES["docs"]`; and call `assert_unit_test_environment()` unconditionally in `tests/conftest.py:pytest_configure` whenever unit/default tests are collected.
- **Effort**: `S`
- **Already registered**: none

#### C18-F07 Large structural distance remains between "unit tests pass" and "a live review run works": all 6 real-tool/deployed/provider acceptance profiles are unimplemented, 35/47 jobs are unwalked in `tests/unit/`, and 36/42 jobs still allow free-text gaps
- **Kind**: `coverage-gap`
- **Severity**: `high`
- **Confidence**: `high`
- **Job**: none (`tests/acceptance/test_system_profiles.py`, `tests/test_gap_contract.py`, `tests/job-test-map.json`)
- **Evidence**: `tests/acceptance_inventory.json:50-94`, `tests/job-test-map.json:1-960`, `tests/test_gap_contract.py:11-28`, `scripts/known-failures.txt:1-190`. 1. In `tests/acceptance_inventory.json:50-94`, all 6 non-offline acceptance profiles—`tools` (real Semgrep/Grype/Flawfinder/Trivy/Gitleaks/Syft), `deployed` (real Dagster PostgreSQL/daemon stack), `provider` (real Claude/Codex/Copilot CLI inference), `guidance` (real model behavioral guidance), `codeql-warm`, and `native`—have `"obligations": []` with `"Unimplemented:"` descriptions, and `review-exhaustive` sits at `599.621s` against a `600.0s` cap (`unqualified_monolithic_targets`). 2. Across all 47 registered jobs in `tests/job-test-map.json` at `f29ee4c688`, only 12 jobs have been walked into `tests/unit/<job_id>/` (`T-113` Waves 1–2 partial); `job_document_issue_analysis` has `"unit": []` (zero unit tests mapped in `job-test-map.json`), 25 jobs have `"integration": []`, 35 have `"acceptance": []`, and 38 have `"live": []`, while `scripts/known-failures.txt` carries ~90 pre-existing root-suite failures/timeouts. 3. In `tests/test_gap_contract.py:11-28`, 36 of 42 producer jobs remain grandfathered in `LEGACY_FREE_TEXT_GAPS` (`strict_gaps=False`), allowing jobs to pass unit contract tests while emitting unvalidated free-text strings in `gaps` instead of `producer-gap/1` records.
- **Impact**: Offline test green status proves contract plumbing on walked slices and faked boundaries, not real container launches, real scanner CLI flags/output schemas, deployed Dagster volume mounts, or live model tool/guidance behavior—explaining why first live review runs (`T-057`) repeatedly surface environment, container, and handoff failures untouched by unit suites.
- **Recommendation**: Complete the `T-113` per-job unit walk (including mapping `job_document_issue_analysis` in `tests/job-test-map.json`), burn down `LEGACY_FREE_TEXT_GAPS` (`T-055` and remaining producers) as each job is walked, and populate minimal bounded obligations for `tools`, `deployed`, and `provider` in `tests/acceptance_inventory.json` for user-authorized acceptance gates.
- **Effort**: `L`
- **Already registered**: `T-055`, `T-057`, `T-064`

#### C18-F08 `.claude/skills/run-triage-and-repair/SKILL.md` contradicts `AGENTS.md` and the deployed bind-mounted source architecture, and `.claude/skills/docs-sync/SKILL.md` omits `tests/docs/`
- **Kind**: `doc-drift`
- **Severity**: `medium`
- **Confidence**: `high`
- **Job**: none (`.claude/skills/run-triage-and-repair/SKILL.md`, `.claude/skills/docs-sync/SKILL.md`)
- **Evidence**: `.claude/skills/run-triage-and-repair/SKILL.md:56-63`, `.claude/skills/docs-sync/SKILL.md:78-86`, `AGENTS.md` ("Container images are tooling only... deploy with `lifecycle.py reload`"). 1. `.claude/skills/run-triage-and-repair/SKILL.md:56-63` tells repository agents: *"Today `Job.identities` binds `pipeline_version`, job configuration and image pins; it does **not** fingerprint edited Python source... Do not mount the whole application to invent hot reload."* 2. That directly contradicts `AGENTS.md`, `deploy/compose.yaml`, `src/appsec_review/runtime/release.py`, and `src/appsec_review/signing/`, where the repository checkout **is** bind-mounted read-only into the Dagster stack, `implementation-release.json` fingerprints and signs mounted Python sources separately from tooling image pins, and code fixes deploy via `lifecycle.py reload` without rebuilding images. 3. `.claude/skills/docs-sync/SKILL.md:82` instructs agents finishing a docs sync to run `pytest -n 4 tests/test_documentation.py tests/test_docs_sync.py --basetemp=test/tmp/docs-sync`, omitting `tests/docs/` (`test_docs_frontmatter.py`, `test_docs_identifiers.py`, `test_docs_ledger.py`, `test_docs_links.py`, `test_generated_docs.py`).
- **Impact**: Agents following `run-triage-and-repair` during live break/fix loops can misdiagnose `implementation-release.json` / signed-source verification failures or unnecessarily rebuild tooling containers instead of running `lifecycle.py reload`; agents following `docs-sync` can commit doc updates that fail `tests/docs/`.
- **Recommendation**: Update `.claude/skills/run-triage-and-repair/SKILL.md` to describe `implementation-release.json`, signed mounted source verification, and `lifecycle.py reload`, and add `tests/docs` + `./scripts/generate-docs.sh` verification to `.claude/skills/docs-sync/SKILL.md`.
- **Effort**: `S`
- **Already registered**: none

#### C18-F09 Answer-key custody checks verify separation from `appsec-review` (`REPO_ROOT`) and worker env vars, but do not check overlap with the reviewed target checkout or configuration overlays
- **Kind**: `trust-boundary`
- **Severity**: `low`
- **Confidence**: `high`
- **Job**: none (`acceptance/custody.py`)
- **Evidence**: `src/appsec_review/acceptance/custody.py:18-41, 58-83, 138-144`. 1. `custody.py` cleanly enforces separation between answer-key guide repositories (`FORBIDDEN_MARKERS`, `FORBIDDEN_ENV`) and `appsec-review` itself: `assert_outside_repository(path, repo_root)` (`lines 58-70`) rejects paths inside `repo_root`, `assert_not_mounted` (`lines 73-83`) rejects Docker `-v`/`--mount` arguments overlapping `forbidden`, and `audit_workspace` (`lines 86-135`) scans git remotes, tracked paths, and untracked trees (including `runs/` and `test/tmp/`). 2. However, `assert_outside_repository` checks only `repo_root`, never verifying that `expectations_path` is outside the **target repository path** being reviewed (`target_dir`), which would allow target acquisition to copy an answer key straight into `runs/<run-id>/` if an operator placed `expectations.toml` inside or adjacent to a local target directory. 3. `audit_run_tree(run_root)` (`lines 138-144`) checks only directory/file names and file contents matching `FORBIDDEN_MARKERS` (`appsec-multi-vuln-guide`, `appsec-review-smoke-guide`), so a custom answer-key file named `expectations.toml` without those two repo strings in its text would not be caught by `audit_run_tree`.
- **Impact**: Standard smoke/benchmark guides are well-guarded against accidental workspace commit or Docker mount, but custom local benchmark answer keys without the two hardcoded repo strings or co-located under a local target directory could bypass `custody.py`.
- **Recommendation**: Extend `assert_outside_repository` (or add `assert_disjoint_paths`) to verify `expectations_path.parent` is disjoint from `target_dir` and `run_root`, and check for `[meta]` + `[[defect]]` answer-key structure or explicit `expectations_path` hashes in `audit_run_tree`.
- **Effort**: `S`
- **Already registered**: none

#### C18-F10 `docs/TODO.md` and `tests/test_todo_registry.py` permit completed items left `open` (`T-114`), `Blocked by` edges pointing solely at `done` items (`T-129 -> T-128`), and untracked `TODO` comments outside `src/` and `deploy/`
- **Kind**: `weakness`
- **Severity**: `low`
- **Confidence**: `high`
- **Job**: none (`docs/TODO.md`, `tests/test_todo_registry.py`)
- **Evidence**: `docs/TODO.md` (`TODO-at-f29ee4c.md:40-44, 1966, 1986-2003, 2231, 2248-2266`), `tests/test_todo_registry.py:98-107, 152-186`. 1. At `f29ee4c688`, `T-114` (`Declare the debug-symbol decision dataset with the schema the job writes`, `TODO-at-f29ee4c.md:1986-2003`) still carries `State: open` in both the index and body even though `T-113` in the same file (`line 1966`) explicitly records: *"Wave 1a (`9c41d5e45`) corrected acquisition/debug-symbol declarations and consumer parity (`T-114` done)"*. 2. `T-129` (`TODO-at-f29ee4c.md:2248-2266`) is `State: open` with `Blocked by: T-128`, while `T-128` (`line 2231`) is already `State: done (2026-11-13, ...)`. Conversely, `T-036` (`line 42`) is `State: open` despite `Blocked by: T-035` (`State: blocked`), whereas `T-059` is `State: blocked` on `T-057` (`in-progress`). `tests/test_todo_registry.py:176-184` checks only that referenced `T-NNN` ids exist, never checking blocker state consistency or `Blocks`/`Blocked by` symmetry. 3. `test_code_todo_comments_name_a_registered_id` (`tests/test_todo_registry.py:98-107`) scans only `(ROOT / "src", ROOT / "deploy")`, leaving `scripts/`, `tools/`, and `tests/` exempt from the registered-TODO rule.
- **Impact**: Agents consulting `docs/TODO.md` encounter already-landed items still marked `open` (`T-114`) and inconsistent `open` vs `blocked` dependency states (`T-129`, `T-036`). *[Post-anchor update on `main` (`f29ee4c688..35aa97b3f`): Partially addressed on `main`: `9c41d5e45` closed `T-114`, and `dd6bce805` reserved `T-5000+` for host-allocated TODO IDs in `tests/test_todo_registry.py`; stale `Blocked by` edges to `done` items and `TODO` scan coverage outside `src/`/`deploy/` remain open.]*
- **Recommendation**: Close `T-114` as `done (2026-11-13, 9c41d5e45)`, tighten `tests/test_todo_registry.py` to flag `Blocked by` lists whose targets are all `done` (and enforce `State: blocked` iff at least one `Blocked by` item is not `done`), and include `scripts/` and `tools/` in `test_code_todo_comments_name_a_registered_id`.
- **Effort**: `S`
- **Already registered**: none

---

## 6. Additions: what the system needs that it does not have

1. **Key- and syntax-aware secret redaction across all outbound model and telemetry paths (`C11-F01`, `C13-F01`, `C17-F03`, `C17-F04`):**
   A single shared redaction facility invoked on `RetrievalCore.read_excerpt`, `PackageView`, PoC/remediation source slices, failure recordings, and `EventLog` that detects high-entropy/structured credential *values* and PEM/header tokens without corrupting taxonomy enum strings (`auth_token`), symbol identifiers, or file paths.
2. **End-to-end semantic warrant and guard-polarity enforcement (`C14-F01`, `T-152`):**
   Full enforcement of `predicate-warrants/1` (`src/appsec_review/review/warrants.py`) inside `review/evidence.py`, challenger prompts, judge acceptance, `job_final_publication_gate`, and `final-report.json` so every confirmed finding records explicit source, sink, and guard-polarity propositions verified against `code_graph` / AST spans.
3. **Isolated runtime verification harness for PoCs, sanitizer builds, and patch validation (`C15-F01`, `C15-F04`, `C06-F10`, `T-047`):**
   A networkless, seccomp/rlimit-bounded container runner (`ContainerExecutor` / `engine_broker`) capable of executing C/C++ ASan/UBSan binaries (`job_sanitizer_build`) and Python/JS/Go/JVM reproducer tests before a finding can claim `verified` status, and re-running the same reproducer after `job_remediation_planning` patches the target.
4. **Mandatory `resolved_config` image-digest binding at container construction (`C04-F01`, `C04-F02`):**
   A required `resolved_config` (or `BoundHostPins`) parameter on `container_runtime.catalog.load_catalog()` and `ContainerExecutor` so unpinned container launches fail at construction time rather than silently skipping digest checks when `expected_image_id is None`.
5. **Self-contained terminal finding schema and end-to-end coverage-gap ledger (`C16-F01`, `C16-F04`):**
   An upgraded `final-report` schema carrying `statement`, `cwe_ids`, primary and supporting `file:start_line-end_line` locators, warrant polarity summaries, PoC/remediation verification state, and aggregated Wave 0–4 `producer-gap/1` blind spots.
6. **Transitive lockfile + call-graph dependency reachability (`C09-F11`):**
   Linking `job_dependency_intelligence` advisory hits (`OSV`/`NVD`/`KEV`) to `job_tree_sitter_ast` / `job_code_graph_index` import and call sites so reachable vulnerable functions are separated from unused transitive lockfile entries.
7. **Cross-service / microservice API contract stitching (`C10-F05`, `C11`, `C12`):**
   Connecting OpenAPI/GraphQL/Protobuf interface definitions (`document_interfaces.py`, after fixing compact JSON and YAML `parameters` parsing in `C10-F05`) to server route handlers and client call sites across multi-component systems.
8. **CI merge-gate and mapped unit-test enforcement (`.github/workflows/quality.yml`, `C18-F05`):**
   Running `test_000_unit_environment_guard.py`, `test_skill_separation.py`, `test_todo_registry.py`, `test_gap_contract.py`, `test_time_budgets.py`, `tests/docs/*`, and `tests/job-test-map.json`-selected suites on every PR and push.

---

## 7. Removals and merges

1. **Retire `job_cpg_analysis` (`C07-F13`):**
   Shipped disabled (`enabled = false`), fails in `whole_program` mode, and emits zero graph edges in `seeded` mode while `job_codeql_analysis` + `job_code_graph_index` + `job_cpp_compiled_analysis` provide active AST/CFG/dataflow coverage. Remove the job, its disabled-gap shard boilerplate, and its `containers/catalog.toml` entry if no standalone Joern workflow remains.
2. **Retire `job_document_issue_analysis` (`C10-F04`, `C18-F01`):**
   Terminal leaf job with zero pipeline consumers, zero unit tests, 142 unused `InputRequirement`s, and a single-line JavaScript `app.get(...)` regex route matcher (`document_issues.py:21`). Remove it from `acceptance/system.py:final_artifact_problems` and route specification-vs-implementation leads directly through `job_review_data_indexing` (`document_context`) into `job_inference_security_review`.
3. **Retire `job_review_package_assembly` (`C11-F03`):**
   Writes legacy `packages/*.json` files that `job_inference_security_review` declares `REQUIRED` in `datasets.py` yet never reads (it builds `PackageView` directly from `job_review_data_indexing`'s `review_package` SQLite shard). Removing `job_review_package_assembly` and `job_document_issue_analysis` together eliminates an entire redundant serialization wave.
4. **Merge `job_build_iteration` into `job_language_build` (`C06-F13`):**
   `job_build_iteration` already executes as an out-of-band helper invoked via unpinned `data/build/iterations/attempts/<id>/{request,result}.json` files rather than DAG handoffs. Fold its bounded repair loop cleanly into a step/unit of `job_language_build` with proper attempt-owned provenance.
5. **Merge `job_post_build_security_assessment` into `job_artifact_security_analysis` (`C08-F07`, `C08-F08`, `C08-F11`):**
   Keep deterministic ELF/PE/Mach-O binary hardening checks inside `job_artifact_security_analysis`, delete the zero-net-information LLM narrative unit (`C08-F11`), and eliminate bogus ELF missing-binary gaps on Go/Rust/JVM targets (`C08-F08`).
6. **Merge `job_change_context_analysis` into `job_source_history_analysis` (`C10-F03`, `C10-F06`):**
   Both jobs inspect the same `.git` repository, run overlapping `git blame` and `fix_on_fix` logic, and spawn hundreds of one-file `tool-git` and `tool-tree-sitter` containers. A single batched history-and-change job reading `job_tree_sitter_ast`'s SQLite shard eliminates up to 555 container startups per repository and whole-repo JSONL RAM spikes.
7. **Merge `job_review_prioritization` into `job_review_data_indexing` / `review/ranking.py` (`C11-F04`):**
   Consolidate the two competing ranking formulas (`job_review_prioritization` vs `review/ranking.py`) into one deterministic scorer inside `job_review_data_indexing` consumed by both `query_hotspots` and `job_inference_security_review`.
8. **Remove dead sub-outputs, duplicate catalog parsers, and stale job/schema references (`C05-F07`, `C05-F08`, `C09-F10`, `C09-F12`, `C12-F04`, `C12-F05`):**
   - Drop `job_target_catalog`'s 7-keyword regex `symbol_index` (`C05-F07`) and Node-only `catalog_dependencies` (`C05-F08`) in favor of `job_tree_sitter_ast` and `job_dependency_intelligence`.
   - Either wire or delete unconsumed `enriched.spdx.json` and `native-sbom-provenance.json` (`C09-F10`) and `cve_bin_tool_db_build` (`C09-F12`).
   - Prune unread `InputRequirement` declarations across `job_owasp_control_assessment` (`104` declared inputs, `C12-F04`), `job_cpp_symbol_index` (`C07-F14`), and `job_inference_security_review`, and remove retired <!-- historical:begin -->`job_tool_image_rebuild`<!-- historical:end --> references from docs/comments (`C04-F08`).

---

## 8. Job verdicts

All 47 registered jobs in `docs/generated/inventory.json` (`2` `keep`, `38` `rework`, `4` `merge`, `0` `split`, `3` `retire`):

| Job | Component | Verdict | Primary reason | Key findings |
| --- | --- | --- | --- | --- |
| `job_image_pin_verification` | `C04` | `rework` | Make run-start pin discovery cover `preinstalled_runtimes` and `('image','image_id')` pairs and reject unpinned `present` status (`expected=None`). | `C04-F01`, `C04-F02`, `C04-F03` |
| `job_target_acquisition` | `C05` | `rework` | Isolate host `git` calls from operator `~/.gitconfig`, enforce `allow_local_sources` at config load, and read `resolved.json` instead of raw TOML. | `C05-F03`, `C05-F09`, `C05-F10` |
| `job_review_intake` | `C05` | `keep` | Clean run-boundary snapshot, binary-evidence, and model-inventory intake; keep and pair with immutable target snapshot enforcement. | `C05-F04`, `C13-F04` |
| `job_target_catalog` | `C05` | `rework` | Verify file SHA-256 on shard reads, migrate to `producer-gap/1`, and retire regex `symbol_index` and Node-only `catalog_dependencies`. | `C05-F04`, `C05-F05`, `C05-F07`, `C05-F08` |
| `job_build_environment_analysis` | `C05` | `rework` | Replace direct `latest.json` reads in `load_environment` with `accepted_upstream` against `CONTRACT`. | `C05-F01` (`C01-F02`) |
| `job_target_analysis_plan` | `C05` | `rework` | Populate `accepted_artifacts` so `tool-spotbugs`/`tool-blint` can be selected, drop unused `job_ci_configuration_analysis` barrier, and enable `strict_gaps=True`. | `C05-F02`, `C05-F05`, `C05-F06`, `C05-F11` |
| `job_project_build` | `C06` | `rework` | Surface missing build toolchains/dependencies explicitly instead of masking broken project builds behind static-workflow dispatches. | `C06-F04`, `C06-F06` |
| `job_language_build` | `C06` | `rework` | Mount `/capture/tools` read-only, authenticate compiler trace records, and stop reporting zero-TU static fallback as clean `COMPLETED`. | `C06-F01`, `C06-F02`, `C06-F07` |
| `job_build_iteration` | `C06` | `merge` | Merge into `job_language_build` as an internal bounded step/unit rather than a pseudo-job exchanging unpinned `request.json`/`result.json` outside `accepted_upstream`. | `C06-F13` |
| `job_sanitizer_build` | `C06` | `rework` | Either wire instrumented ASan/UBSan binaries into a bounded test/PoC execution harness or gate off until runtime execution (`T-047`) lands. | `C06-F10` |
| `job_artifact_indexing` | `C06` | `rework` | Tighten build-unit-to-artifact provenance bindings and migrate to `strict_gaps=True`. | `C06-F05`, `C06-F15` |
| `job_tree_sitter_ast` | `C07` | `rework` | Batch per-scope AST extraction and avoid whole-repo JSONL materialization taxed by downstream consumers. | `C07-F04`, `C10-F03` |
| `job_codeql_analysis` | `C07` | `rework` | Fail/gap honestly on zero-TU or partial trap extraction, include `job_clang_static_analysis` in seeded mode, and fix `GraphExport.qll` C++ scope/guard gaps. | `C07-F02`, `C07-F03`, `C07-F05` |
| `job_code_graph_index` | `C07` | `rework` | Preserve interprocedural call/dataflow continuity and guard polarity across bounded SQLite graph projections. | `C07-F01`, `C07-F06` |
| `job_cpp_symbol_index` | `C07` | `rework` | Fix upstream `/workspace` compile-command path translation and prune unread declared inputs (`job_target_catalog`, `job_evidence_collection`). | `C07-F14`, `C08-F03` |
| `job_cpg_analysis` | `C07` | `retire` | Shipped disabled, fails in `whole_program` mode, and emits zero graph edges in `seeded` mode while `job_codeql_analysis` + `job_code_graph_index` own graph queries. | `C07-F13` |
| `job_cpp_compiled_analysis` | `C08` | `rework` | Fix `.appsec-review-link-commands.json` path, `ignore_patterns('build','target')`, `/workspace` -> `/scratch/source` `-I` rewrite, and missing build-image system headers. | `C08-F01`–`C08-F06` |
| `job_clang_static_analysis` | `C08` | `rework` | Enforce `JobContract` consumption instead of `cpp_index_scopes` bypass and consume repaired C++ compile environments. | `C08-F03`, `C08-F04`, `C08-F09` |
| `job_svf_alias_analysis` | `C08` | `rework` | Restore real multi-TU `link_commands` input from `job_cpp_compiled_analysis` so whole-program points-to and `DISAGREE` verdicts function. | `C08-F01` |
| `job_artifact_security_analysis` | `C08` | `rework` | Bind real `ScannerAdapter.identity` versions/digests instead of `'undeclared'` and absorb ELF/PE binary hardening checks from `job_post_build_security_assessment`. | `C08-F12` |
| `job_post_build_security_assessment` | `C08` | `merge` | Merge deterministic binary hardening checks into `job_artifact_security_analysis` and drop its zero-net-information LLM summary unit and bogus Go/Rust ELF gaps. | `C08-F07`, `C08-F08`, `C08-F11` |
| `job_debug_symbol_indexing` | `C08` | `rework` | Keep DWARF/PDB symbol indexing (`target_decision` schema mismatch closed in `9c41d5e45`), pass `resolved_config` at `execution.py:80`, and enable `strict_gaps=True`. | `C04-F01`, `C08-F10` |
| `job_binary_evidence_indexing` | `C08` | `keep` | Clean frozen/detached Ghidra binary-evidence ingestion; complete PE+PDB live validation (`T-032`) and `strict_gaps=True`. | `C08-F15` |
| `job_evidence_collection` | `C09` | `rework` | Keep `artifact_indexing` wired regardless of `enable_swift`, pass `resolved_config` to `load_catalog`, and surface per-tool truncation/rule failures as `producer-gap/1`. | `C04-F01`, `C09-F01`, `C09-F02` |
| `job_dependency_intelligence` | `C09` | `rework` | Either wire `enriched.spdx.json` and `native-sbom-provenance.json` into indexing/reporting or stop producing dead artifacts; add lockfile/call-graph reachability. | `C09-F10`, `C09-F11` |
| `job_third_party_data_sync` | `C09` | `rework` | Retire unconsumed `cve_bin_tool_db_build` or wire a consumer, and surface feed staleness/offline skips explicitly in downstream advisories. | `C09-F12`, `C09-F13` |
| `job_source_history_analysis` | `C10` | `rework` | preserve synthetic `/gitdir` and PII separation, batch per-file `git blame` / AST complexity into single container invocations, and tighten changelog path heuristics. | `C10-F03`, `C10-F07`, `C10-F09` |
| `job_change_context_analysis` | `C10` | `merge` | Merge diff/PR context into `job_source_history_analysis` to eliminate duplicate `git blame`, `fix_on_fix`, whole-repo AST JSONL RAM loads, and 200+ one-file containers. | `C10-F03`, `C10-F06`, `C10-F07` |
| `job_ci_configuration_analysis` | `C10` | `rework` | Preserve `actionlint` column spans, record malformed tool output as `producer-gap/1`, and parse only `jobs:` children as `kind='job'`. | `C10-F07`, `C10-F08` |
| `job_test_coverage` | `C10` | `rework` | Deduplicate per-file executable line sets in Cobertura/LCOV/multi-unit merges and treat absent optional coverage artifacts as `SKIPPED_NA` rather than gaps. | `C10-F01`, `C10-F06`, `C10-F07` |
| `job_profile_data` | `C10` | `rework` | Bind profiler `source` paths to repository-relative `SourceLocation`s so `review/units.py` stops broadcasting build-wide hotspots to every unit. | `C10-F02`, `C10-F06`, `C10-F07` |
| `job_document_issue_analysis` | `C10` | `retire` | Unconsumed leaf job with 142 unused `InputRequirement`s, zero unit tests, and a single-line JS regex route matcher; fold spec-vs-code checks into `job_inference_security_review`. | `C10-F04`, `C18-F01` |
| `job_review_data_indexing` | `C11` | `rework` | Replace `retrieval/model.py` substring secret redaction with key/value-aware secret detection and pass `resolved_config` to `load_catalog` for `fts_worker`. | `C04-F01`, `C11-F01`, `C11-F02` |
| `job_review_prioritization` | `C11` | `merge` | Unify prioritization with `review/ranking.py` inside `job_review_data_indexing` instead of maintaining a parallel scorer that `job_inference_security_review` ignores. | `C11-F04` |
| `job_security_tagging` | `C11` | `rework` | Fix downstream `retrieval/model.py` tag corruption (`auth_token` -> `<redacted>`) and tighten capability-rule precision. | `C11-F01`, `C11-F06` |
| `job_review_package_assembly` | `C11` | `retire` | Superseded by `job_review_data_indexing`'s `review_package` shard and `review/packages.py`; `job_inference_security_review` never reads `packages/*.json`. | `C11-F03` |
| `job_owasp_control_assessment` | `C12` | `rework` | Pass `infer=infer` in `builtin_registry`, remove raw `target_root` fallback in `evidence.py`, prune 104 over-declared inputs, and hash all `models` in `fingerprint_inputs`. | `C12-F01`–`C12-F04` |
| `job_threat_model_generation` | `C12` | `rework` | Replace stale unregistered job names in `threat_model/index_view.py` and ground DFD trust-boundary claims in `code_graph` entry points and Hunt seeds. | `C12-F05`, `C12-F06` |
| `job_model_connectivity` | `C13` | `rework` | Preserve configured `reasoning` effort during preflight probes and bound concurrent/aggregate probe timeouts. | `C13-F04`, `C13-F09` |
| `job_inference_security_review` | `C14` | `rework` | Wire semantic `predicate-warrants/1` and guard-polarity verification (`T-152`) into `evidence.py`/judge acceptance, redact `RetrievalCore.read_excerpt` secrets, and enforce role model distinctness. | `C13-F01`, `C14-F01`, `C14-F03`, `C14-F06` |
| `job_poc_generation` | `C15` | `rework` | Fix `RetryPolicy` `attempt.failure=None` bug, extend beyond C/C++ compile-only checks, and connect to isolated runtime execution (`T-047`) for `verified` claims. | `C15-F01`, `C15-F05` |
| `job_remediation_planning` | `C15` | `rework` | Anchor patches against exact content-addressed file snapshots and support coordinated multi-hunk/multi-file fixes without context drift. | `C15-F03`, `C15-F06` |
| `job_remediation_validation` | `C15` | `rework` | Align zero-finding `SKIPPED_NA` semantics with `JobRunner` and re-run the triggering scanner/PoC check in addition to compilation. | `C15-F02`, `C15-F04` |
| `job_final_publication_gate` | `C16` | `rework` | Account for pre-review producer coverage gaps (`job_review_data_indexing` `producer-inventory.json`) and decouple optional failed attachment jobs from blocking terminal publication. | `C16-F01`, `C16-F05` |
| `job_dossier_publication` | `C16` | `rework` | Include `tool-report-latex` in active preflight pin checks (`manual=false`), pass `resolved_config` to `load_catalog`, and eliminate duplicate `confirmed_finding`+`poc` PDF renders. | `C04-F01`, `C16-F06`, `C16-F12` |
| `job_final_report_publication` | `C16` | `rework` | Include finding statements, CWE IDs, resolved `file:line` locators, warrant summaries, and structured gap descriptions in `final-report.json` and `final-report.md`. | `C16-F04` |
| `job_openvex_export` | `C16` | `rework` | Declare `job_review_intake` in `CONTRACT.inputs` via `accepted_upstream` instead of reading `latest.json` directly, and avoid 4x artifact re-hashing. | `C16-F08` (`C01-F02`), `C16-F13` |

---

## 9. Coverage of this review

### Spot-check and citation verification summary

- **Critical findings audited against `git show f29ee4c688:<path>`:** 21/21 (100%) — **20 confirmed at `critical`**, **1 downgraded to `low`** (`C16-F03`, `reporting/latex.py:346`, because every dynamic `Heading(...)` caller hashes anchors via `reporting.text.anchor` into `'a-' + sha256[:16]`).
- **High findings audited against `git show f29ee4c688:<path>`:** 91/91 (100%) — **90 confirmed at `high`**, **1 withdrawn** (`C09-F06`, `rules/gitleaks/generic-secrets.toml:13-14`, which already specifies `[extend] useDefault = true`).
- **Medium and low stratified sample audited in full source context:** 32/169 (18.9% across all 18 components) — **32/32 confirmed**, plus mechanical existence and line-count verification of all **1,111 repo-relative `path:line` citations** against `f29ee4c688`.

### Reconciliation with the 2026-11-06 system review (`967a1072bc`)

- **Substantially delivered since 2026-11-06:** Typed `JobContract` + `accepted_upstream` read receipts (`C01`), detached Ed25519 image/module signing (`C04`), bounded CodeQL graph export + `job_code_graph_index` (`C07`), hardened synthetic `/gitdir` and PII separation (`C10`), Stage 1/2 SQLite `job_review_data_indexing` (`C11`), multi-role adversarial `job_inference_security_review` with protected `decision-audit` (`C14`, `T-150`), and transitive-hash `job_final_publication_gate` (`C16`).
- **Partially delivered / regressed at seams:** Host-pin externalization (`T-051`) landed in config, but 23/25 `load_catalog()` callers omit `resolved_config` (`C04-F01`); published-finding scoring (`T-063`) landed in `scoring.py`, but `stepwise.py system` still gates on raw observations (`C18-F01`), `funnel.py` drops pure `Lane B` hits (`C18-F02`), and `scoring.py` explodes multi-entity findings (`C18-F03`).
- **Still open from 2026-11-06 (`T-059` / `T-047` / `T-055`):** Runtime PoC and sanitizer execution (`C15-F01`, `C06-F10`), retirement/rework of `job_document_issue_analysis` (`C10-F04`), `job_build_iteration` DAG cleanup (`C06-F13`), `strict_gaps=True` migration across 36 legacy jobs (`C01-F08`, `C18-F07`), and first end-to-end scored live benchmark validation (`T-057`).

### Reconciliation with `docs/TODO.md` and post-anchor commits (`f29ee4c688..35aa97b3f`)

- **Backlog state at anchor `f29ee4c688` (`156` items, `T-001`–`T-156`) vs `35aa97b3f` (`168` items, adding `T-157`–`T-167` and `T-5001`):** Per review rules, `docs/TODO.md` was not edited by this review. Existing `T-*` items are cross-referenced in each finding's `Already registered` field; roughly **195 of the 270 unique findings** (including `C04-F01`, `C05-F01`, `C05-F02`, `C06-F07`, `C08-F01`–`C08-F04`, `C10-F01`–`C10-F03`, `C11-F01`, `C13-F01`, `C16-F01`, `C16-F04`, `C18-F01`–`C18-F05`) represent newly isolated root causes or regressions under items previously marked `done` (`T-051`, `T-063`).
- **Post-anchor commits on `main` (`f29ee4c688..35aa97b3f`) credited inline:**
  - `04afb24c6` (`T-148`/`T-163`): Resolved `C01-F05` via AST import-walk job release closures in `runtime/release.py`.
  - `5f56d7a20` & `a3d4831c0`: Partially addressed `C01-F03` by re-attesting reused Stage 1/2 index shards.
  - `8c4f1b763` (`T-146`/`T-161`) & `11e71fb0c` (`T-147`/`T-162`): Added `REVALIDATE` on content-equivalent upstream handoffs (`handoff-content/2`) and scoped dataset-contract repair refusal.
  - `69693d133`, `2c9f26f35`, `2780018a6`: Resolved `C03-F08` live Dagster stop-receipt and stale resource-lease handling.
  - `43ac5c7fe`: Partially addressed `C06-F01` by skipping symlinks/FIFOs/special files in `/capture/traces` (explicitly citing `C06-F01` and noting `C06-F07` forged regular trace files remain open).
  - `9c41d5e45` & `8e5cd496c`: Closed `T-114` (`C08-F10`) and hardened ELF segment mapping and typed build causes (`C06-F02` partial).
  - `945bc3706`, `a537c313a`, `da9d4d855`: Hardened inference recording replay and uint64 schema bounds (`C13-F07` partial).
  - `08d50a742`..`324dc1fc3` & `c304064f0` (`T-150`): Closed protected `decision-audit` wiring into gate and dossier (`C14-F08` partial).
  - `29a2517ce` & `d72b7c28f` (`T-165`–`T-167`): Filtered non-first-party scope and stylistic-only leads (`C14-F11` partial).
  - `cd28ce80f` & `dd6bce805` (`T-154`, `T-5001`): Bounded retrieval audit details, enforced `os.umask(0o022)` in `tests/conftest.py` (`C18-F06` partial), and reserved `T-5000+` for host TODOs (`C18-F10` partial).
  - `c12d9ef45` & `f881795d8` (`T-152`): Added `src/appsec_review/review/warrants.py` (`predicate-warrants/1`) and wired opt-in predicate warrants into R5 adjudication and scoring (`C14-F01` partial; default-on enforcement remains open).

### Files read deeply, sampled, and in scope not opened

- **Read deeply (1143 files/globs across `C01`–`C18`):** `.github/workflows/quality.yml`, `AGENTS.md`, `appsec-review.toml`, `containers/build-capture/build-driver.sh`, `containers/build-capture/tool-wrapper.py`, `containers/build-capture/{build-driver.sh,tool-wrapper.py}`, `containers/buildenv/README.md`, `containers/buildenv/android/Dockerfile`, `containers/buildenv/android/assets.lock.json`, `containers/buildenv/cpp/Dockerfile`, `containers/buildenv/dotnet/Dockerfile`, `containers/buildenv/dotnet/assets.lock.json`, `containers/buildenv/go/Dockerfile`, `containers/buildenv/java/Dockerfile`, `containers/buildenv/java/assets.lock.json`, `containers/buildenv/native-toolchain/Dockerfile`, `containers/buildenv/native-toolchain/README.md`, `containers/buildenv/native-toolchain/check-toolchain.sh`, `containers/buildenv/native-toolchain/packages.lock`, `containers/buildenv/php/Dockerfile`, `containers/buildenv/python/Dockerfile`, `containers/buildenv/rust-wasm/Dockerfile`, `containers/buildenv/rust-wasm/README.md`, `containers/buildenv/rust-wasm/assets.lock.json`, `containers/buildenv/typescript/Dockerfile`, `containers/buildenv/typescript/README.md`, `containers/buildenv/typescript/assets.lock.json`, `containers/report/latex/Dockerfile`, `containers/report/latex/README.md`, `containers/report/latex/acquire_assets.sh`, `containers/report/latex/assets.lock.json`, `containers/report/latex/packages.manifest`, `containers/report/latex/render-pdf.sh`, `containers/report/latex/template/appsec-palette.tex`, `containers/report/latex/template/appsec-report.cls`, `containers/report/latex/template/report-skeleton.tex`, `containers/report/latex/tool.toml`, `containers/tools/clang-static-analysis/clang-static.py`, `containers/tools/codeql/codeql_runner.py`, `containers/tools/cppcheck/tool.toml`, `containers/tools/gitleaks/tool.toml`, `containers/tools/grype/tool.toml`, `containers/tools/native-cpp/native.py`, `containers/tools/opengrep/Dockerfile`, `containers/tools/opengrep/tool.toml`, `containers/tools/osv-scanner/tool.toml`, `containers/tools/pmd/tool.toml`, `containers/tools/semgrep/Dockerfile`, `containers/tools/semgrep/tool.toml`, `containers/tools/shared/safe_extract.py`, `containers/tools/svf/svf.py`, `containers/tools/syft/tool.toml`, `containers/tools/tree-sitter/assets.lock.json`, `containers/tools/tree-sitter/parser.py`, `containers/tools/trivy/tool.toml`, `containers/{README.md,build-all.ps1,build-all.sh,build.py,catalog.toml,runtime-policy.toml}`, `data/feeds/osv/current.json`, `data/reference/taxonomy/capability-rules.json`, `data/reference/taxonomy/crosswalk.json`, `data/reference/taxonomy/vocabulary.json`, `data/reference/threat-model/interaction-catalog.json`, `data/reference/threat-model/threat-crosswalk.json`, `data/reference/threat-model/threat-templates.json`, `deploy/dagster/.env.example`, `deploy/dagster/Dockerfile`, `deploy/dagster/README.md`, `deploy/dagster/bin/bootstrap.py`, `deploy/dagster/bin/host.py`, `deploy/dagster/bin/image_signing.py`, `deploy/dagster/bin/lifecycle.py`, `deploy/dagster/bin/ops.py`, `deploy/dagster/bin/ops_clean.py`, `deploy/dagster/bin/ops_readiness.py`, `deploy/dagster/bin/ops_test_guard.py`, `deploy/dagster/bin/ops_tests.py`, `deploy/dagster/bin/recover_runs.py`, `deploy/dagster/bin/review_run.py`, `deploy/dagster/bin/run_report.py`, `deploy/dagster/bin/smoke.py`, `deploy/dagster/bin/stepwise.py`, `deploy/dagster/bin/stepwise_rewind.py`, `deploy/dagster/bin/verify.py`, `deploy/dagster/compose.claude.yaml`, `deploy/dagster/compose.copilot.yaml`, `deploy/dagster/compose.windows.yaml`, `deploy/dagster/compose.yaml`, `deploy/dagster/dagster.yaml`, `deploy/dagster/host-pins.toml`, `deploy/dagster/native/README.md`, `deploy/dagster/native/budget.example.toml`, `deploy/dagster/native/deployment.example.toml`, `deploy/dagster/native/root_entrypoint.py`, `deploy/dagster/requirements.copilot.txt`, `deploy/dagster/requirements.lock.txt`, `deploy/dagster/requirements.txt`, `deploy/dagster/workspace.yaml`, `deploy/windows/Common.ps1`, `deploy/windows/Invoke-NativeBuild.ps1`, `deploy/windows/README.md`, `deploy/windows/Test-BuildToolchain.ps1`, `deploy/windows/canary/CMakeLists.txt`, `deploy/windows/canary/canary.vcxproj`, `deploy/windows/canary/main.cpp`, `docs/SEI-CERT.md`, `docs/TODO.md`, `docs/architecture/bounded-worker-execution.md`, `docs/architecture/build-environments-and-execution-capture.md`, `docs/architecture/build-topology-and-iterations.md`, `docs/architecture/ci-configuration-analysis.md`, `docs/architecture/code-graph-precomputation.md`, `docs/architecture/cross-language-codeql.md`, `docs/architecture/dataflow-bounded-slices.md`, `docs/architecture/dependency-intelligence-enhancement.md`, `docs/architecture/dependency-intelligence.md`, `docs/architecture/deployment-image-and-source-mount.md`, `docs/architecture/dfd-and-threat-model-generation.md`, `docs/architecture/document-evidence-analysis.md`, `docs/architecture/dossier-data-inventory.md`, `docs/architecture/evidence-completion-and-remediation.md`, `docs/architecture/evidence-sources-and-dataflow-retrieval.md`, `docs/architecture/finding-metrics.md`, `docs/architecture/graph-alias-slice-layout-modes.md`, `docs/architecture/guidance-procedures.md`, `docs/architecture/indexing-and-query-reuse.md`, `docs/architecture/inference-security-review.md`, `docs/architecture/job-consumer-read-paths.md`, `docs/architecture/job-input-contracts.md`, `docs/architecture/job-interchange.md`, `docs/architecture/native-build-output-discovery.md`, `docs/architecture/openvex-export.md`, `docs/architecture/owasp-control-workbench.md`, `docs/architecture/profile-data.md`, `docs/architecture/red-discovery-output.md`, `docs/architecture/retrieval-surfaces.md`, `docs/architecture/review-judge-and-poc.md`, `docs/architecture/review-package-contract.md`, `docs/architecture/review-prioritization.md`, `docs/architecture/review-protocol-v2.md`, `docs/architecture/security-tag-taxonomy.md`, `docs/architecture/seeded-neighborhoods.md`, `docs/architecture/sei-cert-rule-pack.md`, `docs/architecture/telemetry.md`, `docs/architecture/test-coverage-ingestion.md`, `docs/architecture/threat-driven-hunting-enhancement.md`, `docs/architecture/tree-sitter-ast.md`, `docs/architecture/triage-verifier-enhancement.md`, `docs/architecture/worker-prompt-contracts.md`, `docs/deployment-inventory.md`, `docs/operations/artifact-indexing.md`, `docs/operations/code-graph-index.md`, `docs/operations/codeql-analysis.md`, `docs/operations/cpp-index-jobs.md`, `docs/operations/dependency-intelligence.md`, `docs/operations/dossier-publication.md`, `docs/operations/final-report.md`, `docs/operations/finding-metrics.md`, `docs/operations/glasswing-experiments.md`, `docs/operations/guidance-evaluation.md`, `docs/operations/inference-security-review.md`, `docs/operations/job_threat_model_generation.md`, `docs/operations/language-build.md`, `docs/operations/lead-severity-triage.md`, `docs/operations/metrics.md`, `docs/operations/model-profiles.md`, `docs/operations/openvex-export.md`, `docs/operations/operator-scripts.md`, `docs/operations/owasp-control-assessment.md`, `docs/operations/performance-assurance.md`, `docs/operations/poc-generation.md`, `docs/operations/project-build.md`, `docs/operations/quality-and-retention.md`, `docs/operations/recovery-repair.md`, `docs/operations/remediation.md`, `docs/operations/report-rendering.md`, `docs/operations/retrieval-mcp.md`, `docs/operations/review-data-indexing.md`, `docs/operations/review-prioritization.md`, `docs/operations/review-startup.md`, `docs/operations/run-readiness.md`, `docs/operations/sanitizer-build.md`, `docs/operations/security-tagging.md`, `docs/operations/sei-cert-rule-pack.md`, `docs/operations/static-analysis.md`, `docs/operations/swift-execution-policy.md`, `docs/operations/telemetry-report.md`, `docs/operations/third-party-data-sync.md`, `docs/operations/threat-model-generation.md`, `docs/operations/unity-build.md`, `docs/operations/wasm-build.md`, `docs/operations/wave1-review.md`, `docs/operations/wsl-native-docker.md`, `docs/operations/{image-pin-verification,job_image_pin_verification,signing}.md`, `docs/reviews/2026-11-13-dependency-intelligence-review.md`, `docs/reviews/2026-11-13-threat-driven-hunting-review.md`, `docs/reviews/2026-11-13-triage-verifier-review.md`, `docs/reviews/appsec-remediation-integration-2026-10-14.md`, `docs/reviews/appsec-system-review-2026-11-06.md`, `docs/reviews/castle-style-detector-scoring.md`, `docs/reviews/evidence-completion-documentation-inventory.md`, `docs/reviews/lead-coverage-audit.md`, `docs/reviews/openvex-export-implementation.md`, `docs/reviews/review-protocol-second-opinion-brief.md`, `docs/schemas/final-report/common.schema.json`, `docs/schemas/final-report/final-publication-gate.schema.json`, `docs/schemas/final-report/final-report.schema.json`, `docs/schemas/inference-security-review/finding-package.schema.json`, `docs/schemas/inference-security-review/handoff.schema.json`, `docs/schemas/inference-security-review/score-package.schema.json`, `docs/schemas/job-control.schema.json`, `docs/schemas/job-interchange.schema.json`, `docs/schemas/openvex-export/README.md`, `docs/schemas/openvex-export/common.schema.json`, `docs/schemas/openvex-export/manifest.schema.json`, `docs/schemas/openvex-export/result.schema.json`, `docs/schemas/owasp-workbench.schema.json`, `docs/schemas/poc-generation/common.schema.json`, `docs/schemas/poc-generation/compile-record.schema.json`, `docs/schemas/poc-generation/poc-candidate.schema.json`, `docs/schemas/poc-generation/poc-generation.schema.json`, `docs/schemas/poc-generation/provenance.schema.json`, `docs/schemas/poc-generation/writer-answer.schema.json`, `docs/schemas/remediation/README.md`, `docs/schemas/remediation/common.schema.json`, `docs/schemas/remediation/exact-patch.schema.json`, `docs/schemas/remediation/plan.schema.json`, `docs/schemas/remediation/planning-handoff.schema.json`, `docs/schemas/remediation/planning.schema.json`, `docs/schemas/remediation/validation-handoff.schema.json`, `docs/schemas/remediation/validation.schema.json`, `docs/schemas/remediation/validations.schema.json`, `docs/schemas/threat-model/generated-dfd.schema.json`, `docs/schemas/threat-model/generated-model-evidence.schema.json`, `docs/schemas/threat-model/generated-threat-model.schema.json`, `docs/schemas/threat-model/threat-model-generation.schema.json`, `docs/tasks/2026-11-08-job-pass-01-model-connectivity.md`, `docs/tasks/2026-11-11-freeciv-walk-01-model-connectivity.md`, `docs/tasks/2026-11-12-multivuln-walk-01-model-connectivity.md`, `pipeline/guidance/registry.json`, `pipeline/guidance/tasks/dependency-intelligence/native_component_curation.md`, `pipeline/guidance/tasks/dependency-intelligence/native_metadata_investigation.md`, `pipeline/guidance/tasks/dependency-intelligence/native_repository_resolution.md`, `pipeline/guidance/tasks/inference-security-review/adjudicate_claim.md`, `pipeline/guidance/tasks/inference-security-review/blind_verifier.md`, `pipeline/guidance/tasks/inference-security-review/blue_control.md`, `pipeline/guidance/tasks/inference-security-review/blue_reachability.md`, `pipeline/guidance/tasks/inference-security-review/chain_composer.md`, `pipeline/guidance/tasks/inference-security-review/chain_refuter.md`, `pipeline/guidance/tasks/inference-security-review/chain_weakest_link_verifier.md`, `pipeline/guidance/tasks/inference-security-review/control_gap.md`, `pipeline/guidance/tasks/inference-security-review/entry_down.md`, `pipeline/guidance/tasks/inference-security-review/lead_red_failure_modes.md`, `pipeline/guidance/tasks/inference-security-review/lead_red_preconditions.md`, `pipeline/guidance/tasks/inference-security-review/lead_red_stack.md`, `pipeline/guidance/tasks/inference-security-review/lead_severity.md`, `pipeline/guidance/tasks/inference-security-review/persona_sweep.md`, `pipeline/guidance/tasks/inference-security-review/sink_up.md`, `pipeline/guidance/tasks/inference-security-review/variant.md`, `pipeline/prompt-fragments/governing-rules.md`, `pipeline/prompt-fragments/personas/authentication_session.md`, `pipeline/prompt-fragments/personas/authorization_access_control.md`, `pipeline/prompt-fragments/personas/build_supply_chain.md`, `pipeline/prompt-fragments/personas/business_logic_abuse.md`, `pipeline/prompt-fragments/personas/ci_cd_pipeline.md`, `pipeline/prompt-fragments/personas/cloud_container_deployment.md`, `pipeline/prompt-fragments/personas/cryptography_data_protection.md`, `pipeline/prompt-fragments/personas/dependency_repository_investigator.md`, `pipeline/prompt-fragments/personas/devops-engineer.md`, `pipeline/prompt-fragments/personas/filesystem_resources.md`, `pipeline/prompt-fragments/personas/generalist.md`, `pipeline/prompt-fragments/personas/injection_interpreters.md`, `pipeline/prompt-fragments/personas/memory_safety_native.md`, `pipeline/prompt-fragments/personas/mobile_platform.md`, `pipeline/prompt-fragments/personas/native_dependency_analyst.md`, `pipeline/prompt-fragments/personas/network_api_surface.md`, `pipeline/prompt-fragments/personas/parsing_deserialization.md`, `pipeline/prompt-fragments/roles/adjudication_judge.md`, `pipeline/prompt-fragments/roles/attack_chain_analyst.md`, `pipeline/prompt-fragments/roles/blue_team_refuter.md`, `pipeline/prompt-fragments/roles/build-engineer-dotnet.md`, `pipeline/prompt-fragments/roles/build-engineer-go.md`, `pipeline/prompt-fragments/roles/build-engineer-java.md`, `pipeline/prompt-fragments/roles/build-engineer-native.md`, `pipeline/prompt-fragments/roles/build-engineer-node.md`, `pipeline/prompt-fragments/roles/build-engineer-php.md`, `pipeline/prompt-fragments/roles/build-engineer-python.md`, `pipeline/prompt-fragments/roles/build-engineer-rust.md`, `pipeline/prompt-fragments/roles/build-engineer-wasm.md`, `pipeline/prompt-fragments/roles/completeness_reviewer.md`, `pipeline/prompt-fragments/roles/finding_adjudicator.md`, `pipeline/prompt-fragments/roles/hypothesis_hunter.md`, `pipeline/prompt-fragments/roles/independent_scorer.md`, `pipeline/prompt-fragments/roles/independent_verifier.md`, `pipeline/prompt-fragments/roles/lead_triager.md`, `pipeline/prompt-fragments/roles/native_dependency_resolver.md`, `pipeline/prompt-fragments/roles/native_sbom_investigator.md`, `pipeline/prompt-fragments/roles/poc_designer.md`, `pipeline/prompt-fragments/roles/poc_verifier.md`, `pipeline/prompt-fragments/roles/poc_writer.md`, `pipeline/prompt-fragments/roles/red_team_analyst.md`, `pipeline/prompt-fragments/roles/remediation_reviewer.md`, `pipeline/prompt-fragments/roles/remediation_writer.md`, `pipeline/prompt-fragments/stacks/android.md`, `pipeline/prompt-fragments/stacks/c_systems_embedded.md`, `pipeline/prompt-fragments/stacks/ci_pipeline.md`, `pipeline/prompt-fragments/stacks/cpp_native_service.md`, `pipeline/prompt-fragments/stacks/cpp_rpc_service.md`, `pipeline/prompt-fragments/stacks/dotnet_service.md`, `pipeline/prompt-fragments/stacks/generic.md`, `pipeline/prompt-fragments/stacks/go_service.md`, `pipeline/prompt-fragments/stacks/iac_kubernetes.md`, `pipeline/prompt-fragments/stacks/ios.md`, `pipeline/prompt-fragments/stacks/jvm_service.md`, `pipeline/prompt-fragments/stacks/node_web.md`, `pipeline/prompt-fragments/stacks/php_web.md`, `pipeline/prompt-fragments/stacks/python_service.md`, `pipeline/prompt-fragments/stacks/rust_service.md`, `pipeline/prompt-fragments/stacks/wasm.md`, `pipeline/skills/binary-evidence/SKILL.md`, `pipeline/skills/build-image-repair/SKILL.md`, `pipeline/skills/conflict-resolution/SKILL.md`, `pipeline/skills/effective-control-verification/SKILL.md`, `pipeline/skills/generative-investigation/SKILL.md`, `pipeline/skills/native-dependency-resolution/SKILL.md`, `pipeline/skills/native-sbom-investigation/SKILL.md`, `pipeline/skills/poc-writer/SKILL.md`, `pipeline/skills/post-build-security-assessment/SKILL.md`, `pipeline/skills/predicate-verification/SKILL.md`, `pipeline/skills/stateful-invariant-analysis/SKILL.md`, `pipeline/skills/target-analysis-planning/SKILL.md`, `profiles/copilot-dev.toml`, `profiles/copilot-prod.toml`, `profiles/prod.toml`, `pyproject.toml`, `quality/baseline.json`, `release-dependencies.json`, `rules/README.md`, `rules/codeql-graph-export/README.md`, `rules/codeql-graph-export/cpp/CallSites.ql`, `rules/codeql-graph-export/cpp/FlowSummaries.ql`, `rules/codeql-graph-export/cpp/GraphExport.qll`, `rules/codeql-graph-export/cpp/Guards.ql`, `rules/codeql-graph-export/cpp/Neighborhood.ql`, `rules/codeql-graph-export/cpp/Paths.ql`, `rules/codeql-graph-export/cpp/Ranges.ql`, `rules/codeql-graph-export/cpp/Seeds.ql`, `rules/codeql-graph-export/cpp/SinkSites.ql`, `rules/codeql-graph-export/cpp/SourceSites.ql`, `rules/codeql-graph-export/cpp/graph-export.qls`, `rules/codeql-graph-export/cpp/qlpack.yml`, `rules/codeql-graph-export/csharp/GraphExport.qll`, `rules/codeql-graph-export/go/GraphExport.qll`, `rules/codeql-graph-export/java/GraphExport.qll`, `rules/codeql-graph-export/javascript/GraphExport.qll`, `rules/codeql-graph-export/python/GraphExport.qll`, `rules/codeql-graph-export/ruby/GraphExport.qll`, `rules/codeql-graph-export/rust/GraphExport.qll`, `rules/codeql-graph-export/swift/GraphExport.qll`, `rules/cpp-cert/README.md`, `rules/cpp-cert/bundle-lock.json`, `rules/cpp-cert/verify_bundle.py`, `rules/gitleaks/README.md`, `rules/gitleaks/generic-secrets.toml`, `rules/gitleaks/rules.lock.json`, `rules/lua-game-security/README.md`, `rules/lua-game-security/fixtures/game-security.lua`, `rules/lua-game-security/game-security.yml`, `rules/pmd/README.md`, `rules/pmd/java-security.xml`, `rules/pmd/rules.lock.json`, `rules/registry.toml`, `rules/sei-cert/README.md`, `rules/sei-cert/pack.json`, `rules/sei-cert/rules/c/env33-c.yml`, `rules/sei-cert/rules/cpp/mem51-cpp.yml`, `rules/sei-cert/rules/java/ids07-j.yml`, `rules/semgrep/README.md`, `rules/semgrep/banned-functions.yml`, `rules/semgrep/review-signals.yml`, `rules/semgrep/rules.lock.json`, `rules/semgrep/security.yml`, `scripts/README.md`, `scripts/clean-temp.ps1`, `scripts/clean-temp.sh`, `scripts/compile-codeql-queries.ps1`, `scripts/compile-codeql-queries.sh`, `scripts/docs_matrices.py`, `scripts/docs_support.py`, `scripts/documentation.py`, `scripts/generate-docs.py`, `scripts/generate-docs.sh`, `scripts/known-failures.txt`, `scripts/lib/common.ps1`, `scripts/lib/common.sh`, `scripts/render-report.ps1`, `scripts/render-report.sh`, `scripts/review-recover.ps1`, `scripts/review-recover.sh`, `scripts/review-start.ps1`, `scripts/review-start.sh`, `scripts/review-status.ps1`, `scripts/review-status.sh`, `scripts/review-stop-id.ps1`, `scripts/review-stop-id.sh`, `scripts/review-stop.ps1`, `scripts/review-stop.sh`, `scripts/review-watch.ps1`, `scripts/review-watch.sh`, `scripts/run-readiness.ps1`, `scripts/run-readiness.sh`, `scripts/run-tests.sh`, `scripts/stack-logs.ps1`, `scripts/stack-logs.sh`, `scripts/stack-rebuild.ps1`, `scripts/stack-rebuild.sh`, `scripts/stack-restart.ps1`, `scripts/stack-restart.sh`, `scripts/stack-start.ps1`, `scripts/stack-start.sh`, `scripts/stack-status.ps1`, `scripts/stack-status.sh`, `scripts/stack-stop.ps1`, `scripts/stack-stop.sh`, `src/appsec_review/__main__.py`, `src/appsec_review/acceptance/answer_key.py`, `src/appsec_review/acceptance/custody.py`, `src/appsec_review/acceptance/funnel.py`, `src/appsec_review/acceptance/model_contract.py`, `src/appsec_review/acceptance/producer_reports.py`, `src/appsec_review/acceptance/scoring.py`, `src/appsec_review/acceptance/system.py`, `src/appsec_review/applicability.py`, `src/appsec_review/application_paths.py`, `src/appsec_review/binary_decompilation/efficacy.py`, `src/appsec_review/binary_decompilation/publication.py`, `src/appsec_review/binary_decompilation/runner.py`, `src/appsec_review/cli.py`, `src/appsec_review/codeql/__init__.py`, `src/appsec_review/codeql/execution_metrics.py`, `src/appsec_review/codeql/predecessor.py`, `src/appsec_review/codeql/runtime.py`, `src/appsec_review/codeql/scheduler.py`, `src/appsec_review/config/__init__.py`, `src/appsec_review/config/assurance.py`, `src/appsec_review/config/attack_chains.py`, `src/appsec_review/config/banned_functions.py`, `src/appsec_review/config/binary_decompilation.py`, `src/appsec_review/config/build_outputs.py`, `src/appsec_review/config/build_selection.py`, `src/appsec_review/config/build_workspaces.py`, `src/appsec_review/config/codeql.py`, `src/appsec_review/config/compiler_target.py`, `src/appsec_review/config/debug_symbols.py`, `src/appsec_review/config/evidence_collection.py`, `src/appsec_review/config/exclusions.py`, `src/appsec_review/config/grype.py`, `src/appsec_review/config/host_pins.py`, `src/appsec_review/config/image_builder_service.py`, `src/appsec_review/config/image_pin_verification.py`, `src/appsec_review/config/inference_review.py`, `src/appsec_review/config/loader.py`, `src/appsec_review/config/native_dagster.py`, `src/appsec_review/config/native_engine.py`, `src/appsec_review/config/owasp.py`, `src/appsec_review/config/remediation.py`, `src/appsec_review/config/run_selection.py`, `src/appsec_review/config/seeding.py`, `src/appsec_review/config/signing.py`, `src/appsec_review/config/target_acquisition.py`, `src/appsec_review/config/telemetry_report.py`, `src/appsec_review/config/unity.py`, `src/appsec_review/container_runtime/build_capture.py`, `src/appsec_review/container_runtime/build_executor.py`, `src/appsec_review/container_runtime/capture_files.py`, `src/appsec_review/container_runtime/identity.py`, `src/appsec_review/container_runtime/project_images.py`, `src/appsec_review/container_runtime/raw_traces.py`, `src/appsec_review/container_runtime/{__init__,build_capture,build_executor,builder_admission,buildkit_worker,capture_files,catalog,compiler_profiles,engine_admission,engine_broker,executor,identity,image_builder,image_builder_service,measurement,native_client,native_commands,native_contracts,project_images,raw_traces}.py`, `src/appsec_review/debug_symbols/execution.py`, `src/appsec_review/debug_symbols/readers.py`, `src/appsec_review/deployment/__init__.py`, `src/appsec_review/deployment/builder.py`, `src/appsec_review/deployment/catalog.py`, `src/appsec_review/deployment/configuration.py`, `src/appsec_review/deployment/descriptors.py`, `src/appsec_review/deployment/inventory.py`, `src/appsec_review/deployment/model.py`, `src/appsec_review/deployment/observations.py`, `src/appsec_review/deployment/parsing.py`, `src/appsec_review/deployment/schemas.py`, `src/appsec_review/document_issues.py`, `src/appsec_review/graph/__init__.py`, `src/appsec_review/graph/analyzers.py`, `src/appsec_review/graph/bounds.py`, `src/appsec_review/graph/catalog.py`, `src/appsec_review/graph/contract.py`, `src/appsec_review/graph/correlate.py`, `src/appsec_review/graph/crosscheck.py`, `src/appsec_review/graph/normalize.py`, `src/appsec_review/graph/settings.py`, `src/appsec_review/graph/svf_crosscheck.py`, `src/appsec_review/guidance/__init__.py`, `src/appsec_review/guidance/cards.py`, `src/appsec_review/guidance/compose.py`, `src/appsec_review/guidance/coverage.py`, `src/appsec_review/guidance/fragments.py`, `src/appsec_review/guidance/routing.py`, `src/appsec_review/guidance/skills.py`, `src/appsec_review/guidance/workers.py`, `src/appsec_review/indexing/build_facts.py`, `src/appsec_review/indexing/derive.py`, `src/appsec_review/indexing/document_interfaces.py`, `src/appsec_review/indexing/fts_worker.py`, `src/appsec_review/indexing/input_matrix.py`, `src/appsec_review/indexing/inventory.py`, `src/appsec_review/indexing/links.py`, `src/appsec_review/indexing/matrix.py`, `src/appsec_review/indexing/metrics.py`, `src/appsec_review/indexing/products.py`, `src/appsec_review/indexing/products_base.py`, `src/appsec_review/indexing/sast.py`, `src/appsec_review/indexing/store.py`, `src/appsec_review/indexing/target_documents.py`, `src/appsec_review/inference/__init__.py`, `src/appsec_review/inference/anthropic_api.py`, `src/appsec_review/inference/claude_cli.py`, `src/appsec_review/inference/copilot_sdk.py`, `src/appsec_review/inference/errors.py`, `src/appsec_review/inference/execution.py`, `src/appsec_review/inference/openai_api.py`, `src/appsec_review/inference/recording.py`, `src/appsec_review/inference/request.py`, `src/appsec_review/inference/usage.py`, `src/appsec_review/interchange.py`, `src/appsec_review/jobs/accepted_review.py`, `src/appsec_review/jobs/artifact_kinds.py`, `src/appsec_review/jobs/bound_artifacts.py`, `src/appsec_review/jobs/build_bookkeeping.py`, `src/appsec_review/jobs/build_iterations.py`, `src/appsec_review/jobs/build_output_scope.py`, `src/appsec_review/jobs/build_points.py`, `src/appsec_review/jobs/build_recipe_commands.py`, `src/appsec_review/jobs/build_recipe_replay.py`, `src/appsec_review/jobs/build_topology.py`, `src/appsec_review/jobs/build_topology_artifacts.py`, `src/appsec_review/jobs/build_workspace.py`, `src/appsec_review/jobs/cataloging.py`, `src/appsec_review/jobs/completion_contracts.py`, `src/appsec_review/jobs/component_ownership.py`, `src/appsec_review/jobs/cpp_index_scopes.py`, `src/appsec_review/jobs/cpp_seeded.py`, `src/appsec_review/jobs/engine_contracts.py`, `src/appsec_review/jobs/job_artifact_indexing/__init__.py`, `src/appsec_review/jobs/job_artifact_indexing/datasets.py`, `src/appsec_review/jobs/job_artifact_indexing/job.py`, `src/appsec_review/jobs/job_artifact_security_analysis/blint_report.py`, `src/appsec_review/jobs/job_artifact_security_analysis/datasets.py`, `src/appsec_review/jobs/job_artifact_security_analysis/findings.py`, `src/appsec_review/jobs/job_artifact_security_analysis/formats.py`, `src/appsec_review/jobs/job_artifact_security_analysis/job.py`, `src/appsec_review/jobs/job_artifact_security_analysis/scanners.py`, `src/appsec_review/jobs/job_binary_evidence_indexing/datasets.py`, `src/appsec_review/jobs/job_binary_evidence_indexing/job.py`, `src/appsec_review/jobs/job_build_environment_analysis/datasets.py`, `src/appsec_review/jobs/job_build_iteration/__init__.py`, `src/appsec_review/jobs/job_build_iteration/datasets.py`, `src/appsec_review/jobs/job_build_iteration/job.py`, `src/appsec_review/jobs/job_change_context_analysis/attribution.py`, `src/appsec_review/jobs/job_change_context_analysis/datasets.py`, `src/appsec_review/jobs/job_change_context_analysis/job.py`, `src/appsec_review/jobs/job_change_context_analysis/metrics.py`, `src/appsec_review/jobs/job_change_context_analysis/settings.py`, `src/appsec_review/jobs/job_change_context_analysis/sources.py`, `src/appsec_review/jobs/job_ci_configuration_analysis/datasets.py`, `src/appsec_review/jobs/job_ci_configuration_analysis/job.py`, `src/appsec_review/jobs/job_ci_configuration_analysis/static_rules.py`, `src/appsec_review/jobs/job_clang_static_analysis/datasets.py`, `src/appsec_review/jobs/job_clang_static_analysis/job.py`, `src/appsec_review/jobs/job_clang_static_analysis/seeded.py`, `src/appsec_review/jobs/job_code_graph_index/__init__.py`, `src/appsec_review/jobs/job_code_graph_index/datasets.py`, `src/appsec_review/jobs/job_code_graph_index/job.py`, `src/appsec_review/jobs/job_code_graph_index/producers.py`, `src/appsec_review/jobs/job_code_graph_index/scopes.py`, `src/appsec_review/jobs/job_codeql_analysis/__init__.py`, `src/appsec_review/jobs/job_codeql_analysis/datasets.py`, `src/appsec_review/jobs/job_codeql_analysis/job.py`, `src/appsec_review/jobs/job_codeql_analysis/planning.py`, `src/appsec_review/jobs/job_codeql_analysis/sarif.py`, `src/appsec_review/jobs/job_cpg_analysis/__init__.py`, `src/appsec_review/jobs/job_cpg_analysis/datasets.py`, `src/appsec_review/jobs/job_cpg_analysis/export.py`, `src/appsec_review/jobs/job_cpg_analysis/job.py`, `src/appsec_review/jobs/job_cpg_analysis/seeded.py`, `src/appsec_review/jobs/job_cpp_compiled_analysis/clang_cfg.py`, `src/appsec_review/jobs/job_cpp_compiled_analysis/datasets.py`, `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py`, `src/appsec_review/jobs/job_cpp_compiled_analysis/llvm_ir.py`, `src/appsec_review/jobs/job_cpp_compiled_analysis/seeded.py`, `src/appsec_review/jobs/job_cpp_symbol_index/__init__.py`, `src/appsec_review/jobs/job_cpp_symbol_index/clangd_yaml.py`, `src/appsec_review/jobs/job_cpp_symbol_index/datasets.py`, `src/appsec_review/jobs/job_cpp_symbol_index/job.py`, `src/appsec_review/jobs/job_debug_symbol_indexing/datasets.py`, `src/appsec_review/jobs/job_debug_symbol_indexing/job.py`, `src/appsec_review/jobs/job_dependency_intelligence/__init__.py`, `src/appsec_review/jobs/job_dependency_intelligence/curation.py`, `src/appsec_review/jobs/job_dependency_intelligence/datasets.py`, `src/appsec_review/jobs/job_dependency_intelligence/discovery.py`, `src/appsec_review/jobs/job_dependency_intelligence/inference.py`, `src/appsec_review/jobs/job_dependency_intelligence/integration.py`, `src/appsec_review/jobs/job_dependency_intelligence/investigation.py`, `src/appsec_review/jobs/job_dependency_intelligence/job.py`, `src/appsec_review/jobs/job_dependency_intelligence/native.py`, `src/appsec_review/jobs/job_dependency_intelligence/native_inference_contracts.py`, `src/appsec_review/jobs/job_dependency_intelligence/native_inference_integration.py`, `src/appsec_review/jobs/job_dependency_intelligence/native_inference_runtime.py`, `src/appsec_review/jobs/job_dependency_intelligence/native_sbom_contracts.py`, `src/appsec_review/jobs/job_dependency_intelligence/resolution.py`, `src/appsec_review/jobs/job_dependency_intelligence/sbom.py`, `src/appsec_review/jobs/job_dependency_intelligence/scorecard.py`, `src/appsec_review/jobs/job_dependency_intelligence/unity.py`, `src/appsec_review/jobs/job_document_issue_analysis/datasets.py`, `src/appsec_review/jobs/job_document_issue_analysis/job.py`, `src/appsec_review/jobs/job_dossier_publication/__init__.py`, `src/appsec_review/jobs/job_dossier_publication/datasets.py`, `src/appsec_review/jobs/job_dossier_publication/inputs.py`, `src/appsec_review/jobs/job_dossier_publication/job.py`, `src/appsec_review/jobs/job_dossier_publication/settings.py`, `src/appsec_review/jobs/job_evidence_collection/__init__.py`, `src/appsec_review/jobs/job_evidence_collection/adapters.py`, `src/appsec_review/jobs/job_evidence_collection/datasets.py`, `src/appsec_review/jobs/job_evidence_collection/evidence.py`, `src/appsec_review/jobs/job_evidence_collection/job.py`, `src/appsec_review/jobs/job_final_publication_gate/__init__.py`, `src/appsec_review/jobs/job_final_publication_gate/attachments.py`, `src/appsec_review/jobs/job_final_publication_gate/classify.py`, `src/appsec_review/jobs/job_final_publication_gate/datasets.py`, `src/appsec_review/jobs/job_final_publication_gate/job.py`, `src/appsec_review/jobs/job_final_publication_gate/settings.py`, `src/appsec_review/jobs/job_final_publication_gate/verify.py`, `src/appsec_review/jobs/job_final_report_publication/__init__.py`, `src/appsec_review/jobs/job_final_report_publication/datasets.py`, `src/appsec_review/jobs/job_final_report_publication/job.py`, `src/appsec_review/jobs/job_final_report_publication/render.py`, `src/appsec_review/jobs/job_final_report_publication/report.py`, `src/appsec_review/jobs/job_final_report_publication/settings.py`, `src/appsec_review/jobs/job_image_pin_verification/{__init__,datasets,job,pins}.py`, `src/appsec_review/jobs/job_inference_security_review/__init__.py`, `src/appsec_review/jobs/job_inference_security_review/chains.py`, `src/appsec_review/jobs/job_inference_security_review/datasets.py`, `src/appsec_review/jobs/job_inference_security_review/job.py`, `src/appsec_review/jobs/job_inference_security_review/schemas.py`, `src/appsec_review/jobs/job_inference_security_review/stages.py`, `src/appsec_review/jobs/job_inference_security_review/teams.py`, `src/appsec_review/jobs/job_language_build/__init__.py`, `src/appsec_review/jobs/job_language_build/capture.py`, `src/appsec_review/jobs/job_language_build/datasets.py`, `src/appsec_review/jobs/job_language_build/dotnet.py`, `src/appsec_review/jobs/job_language_build/elf.py`, `src/appsec_review/jobs/job_language_build/go.py`, `src/appsec_review/jobs/job_language_build/go_vendored.py`, `src/appsec_review/jobs/job_language_build/gradle_provenance.py`, `src/appsec_review/jobs/job_language_build/job.py`, `src/appsec_review/jobs/job_language_build/jvm.py`, `src/appsec_review/jobs/job_language_build/native.py`, `src/appsec_review/jobs/job_language_build/native_components.py`, `src/appsec_review/jobs/job_language_build/native_layout.py`, `src/appsec_review/jobs/job_language_build/native_outputs.py`, `src/appsec_review/jobs/job_language_build/node.py`, `src/appsec_review/jobs/job_language_build/node_installed.py`, `src/appsec_review/jobs/job_language_build/node_scripts.py`, `src/appsec_review/jobs/job_language_build/output_attribution.py`, `src/appsec_review/jobs/job_language_build/php.py`, `src/appsec_review/jobs/job_language_build/php_installed.py`, `src/appsec_review/jobs/job_language_build/python.py`, `src/appsec_review/jobs/job_language_build/rust.py`, `src/appsec_review/jobs/job_language_build/wasm.py`, `src/appsec_review/jobs/job_model_connectivity/__init__.py`, `src/appsec_review/jobs/job_model_connectivity/datasets.py`, `src/appsec_review/jobs/job_model_connectivity/job.py`, `src/appsec_review/jobs/job_openvex_export/__init__.py`, `src/appsec_review/jobs/job_openvex_export/contracts.py`, `src/appsec_review/jobs/job_openvex_export/datasets.py`, `src/appsec_review/jobs/job_openvex_export/inputs.py`, `src/appsec_review/jobs/job_openvex_export/job.py`, `src/appsec_review/jobs/job_openvex_export/metrics.py`, `src/appsec_review/jobs/job_openvex_export/projection.py`, `src/appsec_review/jobs/job_openvex_export/reporting.py`, `src/appsec_review/jobs/job_openvex_export/settings.py`, `src/appsec_review/jobs/job_openvex_export/validation.py`, `src/appsec_review/jobs/job_owasp_control_assessment/__init__.py`, `src/appsec_review/jobs/job_owasp_control_assessment/datasets.py`, `src/appsec_review/jobs/job_owasp_control_assessment/job.py`, `src/appsec_review/jobs/job_poc_generation/__init__.py`, `src/appsec_review/jobs/job_poc_generation/ast_reduce.py`, `src/appsec_review/jobs/job_poc_generation/brief.py`, `src/appsec_review/jobs/job_poc_generation/buildcheck.py`, `src/appsec_review/jobs/job_poc_generation/buildctx.py`, `src/appsec_review/jobs/job_poc_generation/candidates.py`, `src/appsec_review/jobs/job_poc_generation/datasets.py`, `src/appsec_review/jobs/job_poc_generation/inputs.py`, `src/appsec_review/jobs/job_poc_generation/job.py`, `src/appsec_review/jobs/job_poc_generation/package.py`, `src/appsec_review/jobs/job_poc_generation/policy.py`, `src/appsec_review/jobs/job_poc_generation/settings.py`, `src/appsec_review/jobs/job_poc_generation/source.py`, `src/appsec_review/jobs/job_poc_generation/statuses.py`, `src/appsec_review/jobs/job_poc_generation/writer.py`, `src/appsec_review/jobs/job_post_build_security_assessment/assessment.py`, `src/appsec_review/jobs/job_post_build_security_assessment/datasets.py`, `src/appsec_review/jobs/job_post_build_security_assessment/hardening.py`, `src/appsec_review/jobs/job_post_build_security_assessment/job.py`, `src/appsec_review/jobs/job_profile_data/datasets.py`, `src/appsec_review/jobs/job_profile_data/job.py`, `src/appsec_review/jobs/job_profile_data/parsers.py`, `src/appsec_review/jobs/job_project_build/__init__.py`, `src/appsec_review/jobs/job_project_build/datasets.py`, `src/appsec_review/jobs/job_project_build/enforcement.py`, `src/appsec_review/jobs/job_project_build/job.py`, `src/appsec_review/jobs/job_project_build/repair.py`, `src/appsec_review/jobs/job_remediation_planning/__init__.py`, `src/appsec_review/jobs/job_remediation_planning/contracts.py`, `src/appsec_review/jobs/job_remediation_planning/datasets.py`, `src/appsec_review/jobs/job_remediation_planning/inputs.py`, `src/appsec_review/jobs/job_remediation_planning/job.py`, `src/appsec_review/jobs/job_remediation_planning/model.py`, `src/appsec_review/jobs/job_remediation_planning/patches.py`, `src/appsec_review/jobs/job_remediation_validation/__init__.py`, `src/appsec_review/jobs/job_remediation_validation/compiler.py`, `src/appsec_review/jobs/job_remediation_validation/datasets.py`, `src/appsec_review/jobs/job_remediation_validation/inputs.py`, `src/appsec_review/jobs/job_remediation_validation/job.py`, `src/appsec_review/jobs/job_remediation_validation/workspace.py`, `src/appsec_review/jobs/job_review_data_indexing/__init__.py`, `src/appsec_review/jobs/job_review_data_indexing/datasets.py`, `src/appsec_review/jobs/job_review_data_indexing/job.py`, `src/appsec_review/jobs/job_review_package_assembly/__init__.py`, `src/appsec_review/jobs/job_review_package_assembly/datasets.py`, `src/appsec_review/jobs/job_review_package_assembly/job.py`, `src/appsec_review/jobs/job_review_prioritization/__init__.py`, `src/appsec_review/jobs/job_review_prioritization/complexity.py`, `src/appsec_review/jobs/job_review_prioritization/datasets.py`, `src/appsec_review/jobs/job_review_prioritization/dependencies.py`, `src/appsec_review/jobs/job_review_prioritization/heuristics.py`, `src/appsec_review/jobs/job_review_prioritization/inputs.py`, `src/appsec_review/jobs/job_review_prioritization/job.py`, `src/appsec_review/jobs/job_review_prioritization/languages.py`, `src/appsec_review/jobs/job_review_prioritization/rules.py`, `src/appsec_review/jobs/job_review_prioritization/scoring.py`, `src/appsec_review/jobs/job_review_prioritization/semantic.py`, `src/appsec_review/jobs/job_review_prioritization/streaming.py`, `src/appsec_review/jobs/job_review_prioritization/syntax.py`, `src/appsec_review/jobs/job_sanitizer_build/__init__.py`, `src/appsec_review/jobs/job_sanitizer_build/datasets.py`, `src/appsec_review/jobs/job_sanitizer_build/evidence.py`, `src/appsec_review/jobs/job_sanitizer_build/job.py`, `src/appsec_review/jobs/job_sanitizer_build/settings.py`, `src/appsec_review/jobs/job_security_tagging/__init__.py`, `src/appsec_review/jobs/job_security_tagging/cloud.py`, `src/appsec_review/jobs/job_security_tagging/crosswalk.py`, `src/appsec_review/jobs/job_security_tagging/datasets.py`, `src/appsec_review/jobs/job_security_tagging/job.py`, `src/appsec_review/jobs/job_security_tagging/producers.py`, `src/appsec_review/jobs/job_security_tagging/taxonomy.py`, `src/appsec_review/jobs/job_source_history_analysis/__init__.py`, `src/appsec_review/jobs/job_source_history_analysis/changelog.py`, `src/appsec_review/jobs/job_source_history_analysis/datasets.py`, `src/appsec_review/jobs/job_source_history_analysis/discovery.py`, `src/appsec_review/jobs/job_source_history_analysis/filters.py`, `src/appsec_review/jobs/job_source_history_analysis/git.py`, `src/appsec_review/jobs/job_source_history_analysis/github.py`, `src/appsec_review/jobs/job_source_history_analysis/hotspots.py`, `src/appsec_review/jobs/job_source_history_analysis/job.py`, `src/appsec_review/jobs/job_source_history_analysis/lines.py`, `src/appsec_review/jobs/job_source_history_analysis/settings.py`, `src/appsec_review/jobs/job_source_history_analysis/signals.py`, `src/appsec_review/jobs/job_source_history_analysis/sources.py`, `src/appsec_review/jobs/job_source_history_analysis/symbols.py`, `src/appsec_review/jobs/job_source_history_analysis/window.py`, `src/appsec_review/jobs/job_svf_alias_analysis/datasets.py`, `src/appsec_review/jobs/job_svf_alias_analysis/job.py`, `src/appsec_review/jobs/job_svf_alias_analysis/planning.py`, `src/appsec_review/jobs/job_target_analysis_plan/datasets.py`, `src/appsec_review/jobs/job_test_coverage/datasets.py`, `src/appsec_review/jobs/job_test_coverage/job.py`, `src/appsec_review/jobs/job_test_coverage/parsers.py`, `src/appsec_review/jobs/job_third_party_data_sync/__init__.py`, `src/appsec_review/jobs/job_third_party_data_sync/datasets.py`, `src/appsec_review/jobs/job_third_party_data_sync/job.py`, `src/appsec_review/jobs/job_third_party_data_sync/publication.py`, `src/appsec_review/jobs/job_third_party_data_sync/steps/cve_bin_tool_db_build/database.py`, `src/appsec_review/jobs/job_third_party_data_sync/steps/epss_sync/feed.py`, `src/appsec_review/jobs/job_third_party_data_sync/steps/grype_db_sync/feed.py`, `src/appsec_review/jobs/job_third_party_data_sync/steps/kev_sync/feed.py`, `src/appsec_review/jobs/job_third_party_data_sync/steps/mitre_sync/feed.py`, `src/appsec_review/jobs/job_third_party_data_sync/steps/nvd_sync/feed.py`, `src/appsec_review/jobs/job_third_party_data_sync/steps/nvd_sync/index.py`, `src/appsec_review/jobs/job_third_party_data_sync/steps/nvd_sync/models.py`, `src/appsec_review/jobs/job_third_party_data_sync/steps/osv_sync/feed.py`, `src/appsec_review/jobs/job_threat_model_generation/__init__.py`, `src/appsec_review/jobs/job_threat_model_generation/datasets.py`, `src/appsec_review/jobs/job_threat_model_generation/job.py`, `src/appsec_review/jobs/job_tree_sitter_ast/__init__.py`, `src/appsec_review/jobs/job_tree_sitter_ast/dagster.py`, `src/appsec_review/jobs/job_tree_sitter_ast/datasets.py`, `src/appsec_review/jobs/job_tree_sitter_ast/generated_sources.py`, `src/appsec_review/jobs/job_tree_sitter_ast/job.py`, `src/appsec_review/jobs/job_tree_sitter_ast/model.py`, `src/appsec_review/jobs/job_tree_sitter_ast/normalize.py`, `src/appsec_review/jobs/job_tree_sitter_ast/projection.py`, `src/appsec_review/jobs/job_tree_sitter_ast/scope_execution.py`, `src/appsec_review/jobs/unity_build.py`, `src/appsec_review/mcp/adapter.py`, `src/appsec_review/mcp/capability.py`, `src/appsec_review/mcp/configuration.py`, `src/appsec_review/mcp/dagster.py`, `src/appsec_review/mcp/operator.py`, `src/appsec_review/mcp/operator_schema.py`, `src/appsec_review/mcp/owasp.py`, `src/appsec_review/mcp/schema.py`, `src/appsec_review/mcp/stdio.py`, `src/appsec_review/media_assets.py`, `src/appsec_review/migration.py`, `src/appsec_review/observability/__init__.py`, `src/appsec_review/observability/completion.py`, `src/appsec_review/observability/costs.py`, `src/appsec_review/observability/debug_symbols.py`, `src/appsec_review/observability/diagnostics.py`, `src/appsec_review/observability/events.py`, `src/appsec_review/observability/experiments/__init__.py`, `src/appsec_review/observability/experiments/contracts.py`, `src/appsec_review/observability/experiments/exports.py`, `src/appsec_review/observability/experiments/metrics.py`, `src/appsec_review/observability/findings/__init__.py`, `src/appsec_review/observability/findings/__main__.py`, `src/appsec_review/observability/findings/actionability.py`, `src/appsec_review/observability/findings/cli.py`, `src/appsec_review/observability/findings/contracts.py`, `src/appsec_review/observability/findings/corpus.py`, `src/appsec_review/observability/findings/coverage.py`, `src/appsec_review/observability/findings/coverage_adapter.py`, `src/appsec_review/observability/findings/crash/__init__.py`, `src/appsec_review/observability/findings/crash/adapter_sanitizer.py`, `src/appsec_review/observability/findings/crash/adapter_sentry.py`, `src/appsec_review/observability/findings/crash/adapter_stackwalk.py`, `src/appsec_review/observability/findings/crash/adapters.py`, `src/appsec_review/observability/findings/crash/binding.py`, `src/appsec_review/observability/findings/crash/correlate.py`, `src/appsec_review/observability/findings/crash/records.py`, `src/appsec_review/observability/findings/history.py`, `src/appsec_review/observability/findings/identity.py`, `src/appsec_review/observability/findings/integrity.py`, `src/appsec_review/observability/findings/labels.py`, `src/appsec_review/observability/findings/lead_adapter.py`, `src/appsec_review/observability/findings/lifecycle.py`, `src/appsec_review/observability/findings/recheck.py`, `src/appsec_review/observability/findings/run_adapter.py`, `src/appsec_review/observability/findings/scorecard.py`, `src/appsec_review/observability/findings/slices.py`, `src/appsec_review/observability/findings/stability.py`, `src/appsec_review/observability/findings/triage.py`, `src/appsec_review/observability/findings/usefulness.py`, `src/appsec_review/observability/model_calls.py`, `src/appsec_review/observability/native_inference.py`, `src/appsec_review/observability/operator.py`, `src/appsec_review/observability/otlp.py`, `src/appsec_review/observability/quality.py`, `src/appsec_review/observability/retention.py`, `src/appsec_review/observability/spans.py`, `src/appsec_review/observability/telemetry.py`, `src/appsec_review/observability/triage_reduction.py`, `src/appsec_review/orchestration/__init__.py`, `src/appsec_review/orchestration/dagster/__init__.py`, `src/appsec_review/orchestration/dagster/adapter.py`, `src/appsec_review/orchestration/dagster/definitions.py`, `src/appsec_review/orchestration/dagster/error_state.py`, `src/appsec_review/orchestration/dagster/fail_fast.py`, `src/appsec_review/orchestration/dagster/native.py`, `src/appsec_review/orchestration/dagster/native_lifecycle.py`, `src/appsec_review/orchestration/dagster/native_operator.py`, `src/appsec_review/orchestration/topology.py`, `src/appsec_review/osv_matching.py`, `src/appsec_review/osv_offline.py`, `src/appsec_review/owasp_workbench/__init__.py`, `src/appsec_review/owasp_workbench/acquisition.py`, `src/appsec_review/owasp_workbench/assessment.py`, `src/appsec_review/owasp_workbench/engine.py`, `src/appsec_review/owasp_workbench/evidence.py`, `src/appsec_review/owasp_workbench/guidance.py`, `src/appsec_review/owasp_workbench/indexes.py`, `src/appsec_review/owasp_workbench/obligations.py`, `src/appsec_review/owasp_workbench/standards.py`, `src/appsec_review/owasp_workbench/subject_selection.py`, `src/appsec_review/provenance.py`, `src/appsec_review/reporting/__init__.py`, `src/appsec_review/reporting/__main__.py`, `src/appsec_review/reporting/digest.py`, `src/appsec_review/reporting/dossier_render.py`, `src/appsec_review/reporting/dossiers.py`, `src/appsec_review/reporting/evidence.py`, `src/appsec_review/reporting/html.py`, `src/appsec_review/reporting/interchange.py`, `src/appsec_review/reporting/latex.py`, `src/appsec_review/reporting/loader.py`, `src/appsec_review/reporting/model.py`, `src/appsec_review/reporting/sources.py`, `src/appsec_review/reporting/telemetry/__init__.py`, `src/appsec_review/reporting/telemetry/format.py`, `src/appsec_review/reporting/telemetry/inputs.py`, `src/appsec_review/reporting/telemetry/jobs.py`, `src/appsec_review/reporting/telemetry/overview.py`, `src/appsec_review/reporting/telemetry_finalize.py`, `src/appsec_review/reporting/telemetry_render.py`, `src/appsec_review/reporting/text.py`, `src/appsec_review/reporting/tokens.py`, `src/appsec_review/retrieval/__init__.py`, `src/appsec_review/retrieval/core.py`, `src/appsec_review/retrieval/debug_symbol_index.py`, `src/appsec_review/retrieval/graph.py`, `src/appsec_review/retrieval/index.py`, `src/appsec_review/retrieval/interfaces.py`, `src/appsec_review/retrieval/model.py`, `src/appsec_review/retrieval/neighborhood.py`, `src/appsec_review/retrieval/observations.py`, `src/appsec_review/retrieval/precomputed.py`, `src/appsec_review/retrieval/producer_facts.py`, `src/appsec_review/retrieval/source_resolution.py`, `src/appsec_review/retrieval/syntax.py`, `src/appsec_review/retrieval/syntax_contract.py`, `src/appsec_review/review/__init__.py`, `src/appsec_review/review/accounting.py`, `src/appsec_review/review/adjudication.py`, `src/appsec_review/review/admission.py`, `src/appsec_review/review/advisories.py`, `src/appsec_review/review/artifact_context.py`, `src/appsec_review/review/attack_chains.py`, `src/appsec_review/review/behavior.py`, `src/appsec_review/review/budget.py`, `src/appsec_review/review/capability.py`, `src/appsec_review/review/cell_retrieval.py`, `src/appsec_review/review/cells.py`, `src/appsec_review/review/claims.py`, `src/appsec_review/review/compact.py`, `src/appsec_review/review/competence.py`, `src/appsec_review/review/evaluation.py`, `src/appsec_review/review/evidence.py`, `src/appsec_review/review/fact_summary.py`, `src/appsec_review/review/identity.py`, `src/appsec_review/review/independence.py`, `src/appsec_review/review/judge.py`, `src/appsec_review/review/labels.py`, `src/appsec_review/review/lead_families.py`, `src/appsec_review/review/lead_triage.py`, `src/appsec_review/review/lead_triage_settings.py`, `src/appsec_review/review/ledger.py`, `src/appsec_review/review/memory_context.py`, `src/appsec_review/review/models.py`, `src/appsec_review/review/neighborhood.py`, `src/appsec_review/review/numeric_reasoning.py`, `src/appsec_review/review/obligations.py`, `src/appsec_review/review/package_view.py`, `src/appsec_review/review/packages.py`, `src/appsec_review/review/ranking.py`, `src/appsec_review/review/red_discovery.py`, `src/appsec_review/review/references.py`, `src/appsec_review/review/result_cache.py`, `src/appsec_review/review/schemas.py`, `src/appsec_review/review/scope.py`, `src/appsec_review/review/scoring/__init__.py`, `src/appsec_review/review/scoring/application_matrix.py`, `src/appsec_review/review/scoring/application_matrix_v3.py`, `src/appsec_review/review/scoring/cwe_impact.py`, `src/appsec_review/review/scoring/evidence_source.py`, `src/appsec_review/review/scoring/factors.py`, `src/appsec_review/review/scoring/interface.py`, `src/appsec_review/review/scoring/risk_model.py`, `src/appsec_review/review/secret_redaction.py`, `src/appsec_review/review/ship_block.py`, `src/appsec_review/review/slicing/__init__.py`, `src/appsec_review/review/slicing/anchors.py`, `src/appsec_review/review/slicing/compose.py`, `src/appsec_review/review/slicing/contract.py`, `src/appsec_review/review/slicing/registry.py`, `src/appsec_review/review/slicing/sources.py`, `src/appsec_review/review/slicing/spans.py`, `src/appsec_review/review/slicing/strategies/__init__.py`, `src/appsec_review/review/slicing/strategies/lexical.py`, `src/appsec_review/review/slicing/strategies/llvm_ir.py`, `src/appsec_review/review/slicing/strategies/svf.py`, `src/appsec_review/review/slicing/strategies/tree_sitter.py`, `src/appsec_review/review/teams.py`, `src/appsec_review/review/tool_rules.py`, `src/appsec_review/review/units.py`, `src/appsec_review/review/worker_competence.py`, `src/appsec_review/review_packages.py`, `src/appsec_review/rulepacks/__init__.py`, `src/appsec_review/rulepacks/banned_functions.py`, `src/appsec_review/rulepacks/sei_cert/__init__.py`, `src/appsec_review/rulepacks/sei_cert/__main__.py`, `src/appsec_review/rulepacks/sei_cert/engines.py`, `src/appsec_review/rulepacks/sei_cert/evaluate.py`, `src/appsec_review/rulepacks/sei_cert/fixtures.py`, `src/appsec_review/rulepacks/sei_cert/pack.py`, `src/appsec_review/rulepacks/sei_cert/report.py`, `src/appsec_review/rulepacks/sei_cert/sources.py`, `src/appsec_review/rulepacks/sei_cert/validate.py`, `src/appsec_review/runtime/__init__.py`, `src/appsec_review/runtime/checkpoints.py`, `src/appsec_review/runtime/consume.py`, `src/appsec_review/runtime/contracts.py`, `src/appsec_review/runtime/datasets.py`, `src/appsec_review/runtime/dependencies.py`, `src/appsec_review/runtime/execution_safety.py`, `src/appsec_review/runtime/failure_replay.py`, `src/appsec_review/runtime/graph.py`, `src/appsec_review/runtime/handoff.py`, `src/appsec_review/runtime/inputs.py`, `src/appsec_review/runtime/job.py`, `src/appsec_review/runtime/launch.py`, `src/appsec_review/runtime/plan.py`, `src/appsec_review/runtime/registry.py`, `src/appsec_review/runtime/release.py`, `src/appsec_review/runtime/repair.py`, `src/appsec_review/runtime/resources.py`, `src/appsec_review/runtime/resume.py`, `src/appsec_review/runtime/runner.py`, `src/appsec_review/runtime/scope.py`, `src/appsec_review/runtime/selection.py`, `src/appsec_review/runtime/units.py`, `src/appsec_review/seeding/__init__.py`, `src/appsec_review/seeding/ledger.py`, `src/appsec_review/seeding/neighborhood.py`, `src/appsec_review/seeding/plan.py`, `src/appsec_review/seeding/record.py`, `src/appsec_review/seeding/units.py`, `src/appsec_review/signing/{__init__,bootstrap,cli,container_self_check,core,images,import_hook,modules,policy,release_lib,sitecustomize_shim}.py`, `src/appsec_review/storage/__init__.py`, `src/appsec_review/storage/admission.py`, `src/appsec_review/storage/atomic.py`, `src/appsec_review/storage/feed_provenance.py`, `src/appsec_review/storage/lock.py`, `src/appsec_review/storage/runs.py`, `src/appsec_review/storage/shared.py`, `src/appsec_review/storage/validation.py`, `src/appsec_review/storage/verify.py`, `src/appsec_review/swift_policy.py`, `src/appsec_review/threat_model/__init__.py`, `src/appsec_review/threat_model/assemble.py`, `src/appsec_review/threat_model/codec.py`, `src/appsec_review/threat_model/contract.py`, `src/appsec_review/threat_model/documents.py`, `src/appsec_review/threat_model/index_view.py`, `src/appsec_review/threat_model/lanes/__init__.py`, `src/appsec_review/threat_model/lanes/interactions.py`, `src/appsec_review/threat_model/lanes/structure.py`, `src/appsec_review/threat_model/reference.py`, `src/appsec_review/threat_model/render.py`, `src/appsec_review/threat_model/schemas.py`, `src/appsec_review/threat_model/threats.py`, `src/appsec_review/threat_model/validate.py`, `src/appsec_review/threat_model/view.py`, `src/appsec_review/tool_inputs.py`, `test/acceptance/prod-capacity-overlay.toml`, `tests/acceptance/test_system_profiles.py`, `tests/conftest.py`, `tests/integration/test_finding_metrics.py`, `tests/job-test-map.json`, `tests/orchestration/dagster/test_completion.py`, `tests/orchestration/dagster/test_definitions.py`, `tests/orchestration/dagster/test_error_state.py`, `tests/orchestration/test_topology.py`, `tests/quality/test_config_selection.py`, `tests/reporting/test_reporting.py`, `tests/review/test_adjudication.py`, `tests/review/test_attack_chain_job.py`, `tests/review/test_budget.py`, `tests/review/test_cell_retrieval.py`, `tests/review/test_obligations.py`, `tests/review/test_scoring.py`, `tests/review/test_ship_block.py`, `tests/test_000_unit_environment_guard.py`, `tests/test_anthropic_inference.py`, `tests/test_bounded_execution.py`, `tests/test_claude_cli_inference.py`, `tests/test_code_graph_index_job.py`, `tests/test_codeql_export_step.py`, `tests/test_cpg_export.py`, `tests/test_dagster_host.py`, `tests/test_dagster_smoke.py`, `tests/test_dagster_verify.py`, `tests/test_deployment_inventory.py`, `tests/test_dossier_publication.py`, `tests/test_dossiers.py`, `tests/test_final_report.py`, `tests/test_gap_contract.py`, `tests/test_job_selection.py`, `tests/test_media_asset_inputs.py`, `tests/test_migration_ledger.py`, `tests/test_native_dagster_config.py`, `tests/test_native_operator.py`, `tests/test_openvex_job_units.py`, `tests/test_operator_configuration.py`, `tests/test_operator_dagster.py`, `tests/test_operator_queries.py`, `tests/test_operator_scripts.py`, `tests/test_owasp_assessment_job.py`, `tests/test_poc_generation_units.py`, `tests/test_poc_policy.py`, `tests/test_remediation_compiler.py`, `tests/test_remediation_jobs.py`, `tests/test_remediation_models.py`, `tests/test_remediation_patches.py`, `tests/test_repair_dagster_contract.py`, `tests/test_sanitizer_build.py`, `tests/test_skill_separation.py`, `tests/test_swift_policy.py`, `tests/test_todo_registry.py`, `tests/unit/conftest.py`, `tests/unit/job_artifact_indexing/test_receipt_validation.py`, `tests/unit/job_build_iteration/test_controller.py`, `tests/unit/job_language_build/test_job_graph.py`, `tests/unit/job_model_connectivity/support.py`, `tests/unit/job_model_connectivity/test_contract.py`, `tests/unit/job_model_connectivity/test_job_graph.py`, `tests/unit/job_model_connectivity/test_steps.py`, `tests/unit/job_owasp_control_assessment/test_subject_selection.py`, `tests/unit/job_project_build/test_job_graph.py`, `tests/unit/job_project_build/test_repair.py`, `tests/unit/job_third_party_data_sync/test_job_graph.py`, `tools/cve-bin-tool/Dockerfile`, `tools/cve-bin-tool/README.md`, `tools/cve-bin-tool/build_db.py`, `tools/quality/__init__.py`, `tools/quality/__main__.py`, `tools/quality/baseline.py`, `tools/quality/boundaries.py`, `tools/quality/config.py`, `tools/quality/process.py`, `tools/quality/pytest_guard.py`, `tools/quality/run_checks.py`, `tools/quality/runner.py`, `tools/quality/select_checks.py`, `tools/quality/selection.py`.
- **Sampled (11 files/globs across `C01`–`C18`):** `containers/tools/ghidra/scripts/AppsecExportProgram.java`, `docs/architecture/change-context-analysis.md`, `docs/architecture/source-history-analysis.md`, `job.py`, `src/appsec_review/jobs/job_artifact_security_analysis/installer_records.py`, `tests/test_change_context_analysis.py`, `tests/test_ci_configuration_analysis.py`, `tests/test_profile_data.py`, `tests/test_target_document_pipeline.py`, `tests/test_test_coverage.py`, `tests/unit/job_source_history_analysis/test_contract.py`.
- **In scope, not opened (7 files/globs across `C01`–`C18`, plus external answer-key repos and `old/`):** `containers/tools/ghidra/scripts/AppsecLoadDebugSymbols.java`, `containers/tools/svf/driver/svf-alias-export.cpp`, `docs/operations/job_*.md`, `src/appsec_review/debug_symbols/dwarf.py`, `src/appsec_review/debug_symbols/pdb.py`, `src/appsec_review/jobs/job_source_history_analysis/complexity.py`, `src/appsec_review/jobs/job_source_history_analysis/sii.py`.

---

## 10. Questions for the owner

1. **Single-model development profiles vs production assurance (`C02-F06`, `C14-F06`):** When a run executes under a single-model profile (`dev`, `copilot-dev`, or homogeneous local endpoints where `verifier_model_distinct=False`), should `job_final_publication_gate` cap finding status below `confirmed` (for example `provisional_single_model`), or refuse `final-report` publication altogether outside `development` mode?
2. **Evidence threshold for `confirmed` vs `verified` findings (`C14-F01`, `C15-F01`, `T-047`):** Until isolated runtime PoC execution (`T-047`) lands across languages, should `confirmed` remain eligible for static + semantic-warrant (`T-152`) proof with `verified` reserved strictly for executed behavioral reproducers, or should native C/C++ memory-safety findings require sanitizer/PoC execution before publication?
3. **Disposition of the 3 `retire` and 4 `merge` jobs (`C07-F13`, `C10-F04`, `C11-F03`, `C06-F13`, `C08-F11`, `C10-F03`, `C11-F04`):** Do you approve retiring `job_cpg_analysis`, `job_document_issue_analysis`, and `job_review_package_assembly` outright and merging `job_build_iteration`, `job_post_build_security_assessment`, `job_change_context_analysis`, and `job_review_prioritization` into their adjacent owners (47 -> 40 jobs), or must any of those job IDs remain stable for external run-walk tooling?
4. **Zero-TU native build fallback policy (`C06-F02`, `C07-F02`, `C08-F01`):** When a repository contains C/C++/Rust/Go/JVM build manifests (`CMakeLists.txt`, `Makefile`, `Cargo.toml`, `pom.xml`) and `job_language_build` captures zero compiled translation units, should the run halt at a build gate for operator intervention, or continue static-only while forcing `job_final_publication_gate` to stamp the terminal report `PARTIAL / UNCOMPILED_NATIVE_SURFACE`?
5. **Pre-review coverage gaps at `job_final_publication_gate` (`C16-F01`, `C16-F05`):** Which pre-review `producer-gap/1` classes (for example failed primary SAST/CodeQL on first-party code vs unavailable optional third-party feed or profiler input) should hard-block `job_final_publication_gate`, and which should pass with prominent blind-spot disclosure in `final-report.md`?
6. **Unconsumed SBOM and binary-CVE investments (`C09-F10`, `C09-F12`):** Should `enriched.spdx.json`, `native-sbom-provenance.json` (`job_dependency_intelligence`), and `cve-bin-tool` (`job_third_party_data_sync`) be wired into `job_review_data_indexing` and `job_dossier_publication` as first-class deliverables, or deleted to cut sync and container build maintenance?
7. **Outbound secret redaction policy for cloud LLM providers (`C13-F01`, `C11-F01`):** When `secret_redaction.py` detects a live-looking credential value inside `RetrievalCore.read_excerpt` on a suspected hardcoded-secret lead, should workers receive a deterministic placeholder (`<REDACTED_SECRET:sha256_prefix:entropy_class>`) sufficient to prove hardcoded credential presence without transmitting raw secret bytes to external model APIs?
8. **POSIX signing enforcement default (`C04-F01`, `C04-F04`, `C04-F05`):** Should `[signing] image_enforcement` remain `"disabled"` by default once `load_catalog(..., resolved_config=...)` mandatory digest pinning is restored, or do you want `"required"` enabled on the primary Linux/WSL Dagster hosts (`WSOLLERS1`, HAL, Zarathustra)?
9. **Optional attachment jobs on terminal publication (`C16-F05`, `C15-F02`):** When `job_poc_generation`, `job_remediation_planning`, or `job_remediation_validation` is enabled in configuration and fails or times out on a subset of findings, should `job_final_publication_gate` still publish the confirmed security findings with explicit `attachment_missing` gap records rather than failing the entire report?
10. **GitHub Actions CI budget and scope (`C18-F05`):** Are GitHub-hosted runners permitted to run the full fast unit + `tests/docs/` merge-gate suite (roughly 2–4 minutes with `-n 4`) on every push/PR to `main`, or should `.github/workflows/quality.yml` stay restricted to fast governance gates plus `tests/job-test-map.json` diff-targeted unit tests?
