# Gap punch list: hello-autotools run `20261003T000827Z-a02791`

Source: the gap summary of `full_review` run `20261003T000827Z-a02791` on `hello-autotools`
(pinned `632522b`). Each gap is traced to the code that emits it and classified as:

- **defect**: our code is wrong or missing a feature; fix it.
- **env**: host or image setup; fix on the host, not in code.
- **absence**: a true statement that the target lacks something; report it as N/A or an
  observation, not as a coverage gap (AGENTS.md rule 2 still holds: a gap is something we could not
  examine, not something that is not there).
- **limit**: inherent to the tool; keep the gap and make the wording accurate.

Every code item has an acceptance test in `appsec-review-process/tests/test_gap_punchlist_*.py`,
marked `@unittest.expectedFailure` with its punch-list id in the docstring. Each test fails on an
assertion (not an import or attribute error) against today's code. When you fix an item, delete
its decorator: an "unexpected success" in the suite means a fix landed without removing the
decorator. Paths below are relative to `appsec-review-process/` unless they start with a top-level
directory.

Run them with:

```bash
cd appsec-review-process && python3 -m unittest tests.test_gap_punchlist_binary_ir \
  tests.test_gap_punchlist_code_sast tests.test_gap_punchlist_ingest_sca \
  tests.test_gap_punchlist_owasp_threat
```

## A. Binary, debug symbols, IR facts

| Id | Gap | Class | Cause | Fix |
|---|---|---|---|---|
| P01 | `packed-state:unknown`, `static-packer-classification-inconclusive` (02-binary-triage, repeated by 02-binary-intelligence-ingest) | defect | `binary_evidence_adapter.py` `_triage_record` always sets `packed: UNKNOWN` and adds the gap. The image already writes `die.json`, `strings.txt` and the section list; nothing reads them. `binary_evidence_core.py` then copies triage gaps into every intelligence lead. | Add `_packed_state`: YES on a DIE packer/protector, `UPX!` or `UPX0/UPX1` sections; NO when DIE parsed with no packer and the normal ELF sections are present; else UNKNOWN plus the gap. Bind `die.json` and `strings.txt` into the hashed outputs. |
| P02 | `duplicate-symbol-identity` (02-debug-symbol-index) | defect | `analyze-binary.sh` runs `nm -an`; `-a` adds STT_FILE `a` symbols at address 0 (two `crtstuff.c` entries from crtbegin/crtend always collide). | Skip nm kinds `a` and `N` in `_debug_record`; keep the duplicate check for real collisions. |
| P03 | `source-locations-unavailable` (02-debug-symbol-index) | defect | `_debug_record` hard-codes `source_path: None, line: None`; DWARF is never read. | `nm -anl` (or `llvm-symbolizer`), parse the trailing `file:line`, strip `/scratch/src/` or `/workspace/` to a repo-relative path, None outside the checkout. Gap only for defined text symbols without a location while debug sections exist; `debug-info-absent` otherwise. Needs an `audit-binary-analysis` rebuild and re-pin. |
| P04 | 267x `fact-source-ambiguous` (02-ir-facts) | defect | The `!DILocation` regex in `ir_evidence.py` requires `column:` and misses `distinct !DILocation` and `!DILocation(line: 0, scope: ...)` (common at `-O2`), so those ids never enter the location map. | Regex `^!(\d+) = (?:distinct )?!DILocation\(line: (\d+)(?:, column: (\d+))?, scope: !(\d+)(?:, inlinedAt: !(\d+))?`. |
| P05 | 344x `debug-location-source-ambiguous` (02-ir-facts) | defect | Inlined code (libstdc++ `basic_string.h` into `build_greeting`, `run_report`, `main`) has a header scope plus `inlinedAt`; `inlinedAt` is never followed. Repo headers are not in `source_by_path`. | Walk the `inlinedAt` chain to the outermost location that maps to a source. Report system-header locations as `debug-location-outside-checkout`; keep "ambiguous" for more than one match. |
| P06 | (side bug) every hardening lead reads "not confirmed" | defect | `binary_evidence_core.py` tests `state is True`; hardening values are strings (`ENABLED`). | Compare against the enum. |

## B. Code index, CPG, SAST, tree-sitter

| Id | Gap | Class | Cause | Fix |
|---|---|---|---|---|
| P07 | `cpg-coverage-gap:no-source-location:119` (02-code-index), `no-source-location` (02-code-property-graph) | defect | `pipeline/joern_export_records.sc` exports every `cpg.method`/`cpg.typeDecl`, including external stubs (`<operator>.*`, libc, `<global>`) whose file is `<empty>`; `code_graph_evidence.py` counts them as missing locations. | Export `isExternal(false)` only, or count location-less METHOD/TYPE_DECL rows as `external-stub` info, not a gap. CALLs without a location stay a gap. |
| P08 | `duplicate` (02-code-property-graph) | limit | c2cpg emits identical nodes at macro expansion sites (cJSON macros); dedup is correct. | Report the dedup count as info; it must not set `OK_WITH_GAPS`. |
| P09 | `source-not-indexed:02-ir-facts`, `source-not-indexed:02-debug-symbol-index` (02-code-index) | defect | Hard-coded in `code_index.py`; `pipeline/job-graph.json` gives 02-code-index no edge to either job and `code_index_job.py` binds neither. | Add optional edges and bindings; emit `source-not-indexed:<job>` only when that job was accepted and its records were not ingested; ingest them as the follow-up feature. |
| P10 | `cpg-exporter:no-inheritance-edges`, `cpg-exporter:no-method-reference-nodes` (02-code-index) | defect | Hard-coded in `code_index.py`; the exporter never walks `inheritsFromTypeFullName` or `cpg.methodRef`, so `type_edges` stays empty. | Export `INHERITS` type rows and `METHOD_REF` rows (extend `code_graph_evidence.KINDS` and the record schema), fill `type_edges`, emit the gap only when the count is zero. |
| P11 | 02-codeql-cpp "ran with --build-mode none" | defect (wording) + env | `FIDELITY_GAPS["cpp"]` is appended for the none-mode row even when traced rows ran; traced rows are UNAVAILABLE when `audit-codeql-native` has no current B16 record. | Replace the fidelity gap with "none-mode row only; traced units cover N" when READY traced rows exist. Env: build `audit-codeql-native` and register its B16 record (E2). |
| P12 | `clang-tidy-tool-error:6-translation-units` (02-native-sast) | defect | `run_native_sast.py` counts any non-zero exit as a tool error; clang-tidy exits 1 on `clang-diagnostic-error` (missing `config.h`, unmounted generated includes) while still producing findings. | Split: 124 timeout, 127 missing tool (tool errors); 1 with `clang-diagnostic-error` is `clang-tidy-compile-error:<n>` with the first message. Then fix the compile-DB/include cause it reveals. |
| P13 | Semgrep has no taint flow (02-source-sast) | defect (intraprocedural), limit (interprocedural) | No rule in `data/source-sast/` uses `mode: taint`. | Add CE taint rules (sources `argv`, `getenv`, `fgets`, `recv`; sinks `system`, `popen`, `strcpy`, `sprintf`, `printf` format); narrow `RULES_GAP` to interprocedural/interfile. |
| P14 | Shell source has no analyzer (02-source-sast) | defect + env | No shellcheck image; `.sh` maps to `shell` and lands in `uncovered_language_gaps`. | `tool-shellcheck` image pinned via `tool_pins.py`, adapter plan row, hit exit code 1. |
| P15 | `no-grammar` (02-treesitter-ast) | absence | C/C++ are covered; the gap counts `.am`, `.ac`, `.in`, `.m4`, `.md`, `Makefile`, `configure`. | `NON_SOURCE_SUFFIXES` counted as info, not a gap. |

## C. Ingests, SBOM/SCA, reachability, build discovery

| Id | Gap | Class | Cause | Fix |
|---|---|---|---|---|
| P16 | `readme-only-no-specialized-inputs` (02-api-collection-intelligence-ingest, 02-operations-doc-ingest) | absence | `static_intelligence_core.py` adds the gap when no candidate matches. A CLI with no API spec is not a coverage gap. | `SKIPPED` with `applicability: SKIPPED_NA_NO_APPLICABLE_INPUTS`; add `SKIPPED` to the four intelligence schemas' status enum. Also add `build`/`install` to the ops tokens so `docs/BUILDING.md` is ingested. |
| P17 | `zero-indexable-records` (02-test-intelligence-ingest) | defect | `tests/run.sh` is a candidate but `_summaries` only knows Python `def test_`, gtest and JS patterns. | Shell `test_x()` / `run_test x`, C `test_x(`, Unity/CUnit `RUN_TEST(x)` patterns; one `test-entrypoint` record per runnable script. |
| P18 | "No target evidence for: disa_gpos_srg, owasp_api_security_top_10, owasp_llm_top_10, owasp_mastg, owasp_masvs" (02-standards-source-ingest) | absence | `automatic_evidence_inputs._standards_selection` deselects them (DISA GPOS is hard-coded off) and `standards_source_ingest.py` turns every unselected family into a gap. | Publish them as `not_applicable_families`; gaps only for selected-but-missing families. |
| P19 | `no-dependency-components-detected` (02-sbom-inventory) and `OSV_SKIPPED_NA_NO_PURL_COMPONENTS` (02-sca-vulnerability-match) | defect | `dependency_workers._CJSON_MEMBER` needs the version in the directory name (`cJSON-1.7.18`); the target uses `vendor/cJSON`. Even on a match it emits `purl=None, cpe=None`. | Accept `vendor/cJSON`, read `CJSON_VERSION_MAJOR/MINOR/PATCH` from the hash-bound `cJSON.h`, emit `pkg:github/davegamble/cjson@v1.7.18` and `cpe:2.3:a:cjson_project:cjson:1.7.18:*:*:*:*:*:*:*`. The OSV skip then clears; expect real CVE matches from Grype/NVD by CPE, since OSV's C advisories use GIT ranges. |
| P20 | `ENGINE_INPUT:osv-unusable:DATA_ROOT_MISSING` (06-reachability-codeql, 06-reachability-ir) | defect + env | `reachability_engine_jobs.py` appends the OSV input gap unconditionally, even with zero rows (no SCA match needed OSV). On this host `APPSEC_OSV_ROOT` is unset and `data/feeds/osv` does not exist. | Emit the job-level gap only when a row needed OSV. Env: `osv_feed.py sync` and set `APPSEC_OSV_ROOT` (E1). |
| P21 | "autotools toolchain in audit-buildenv-cpp:local not verified from catalog" (02-dev-project-discovery) | defect | `tooling/buildenv-catalog.json` cpp entry lacks `configure.ac`/`Makefile.am`/`configure` markers and a `tools` list, although `images/audit-buildenv-cpp/Dockerfile` installs autoconf, automake, libtool, make, bear and pkg-config. | Add the markers and `tools`. |

The other 02-dev-project-discovery notes (docs partition deferred, no lockfile, vendored cJSON has no
independent build, Dockerfile build path not planned, script-execution capability) are persona
output the prompt asks for. They are **absence**/**limit** notes; see P34.

## D. OWASP, STIG/SRG, threat model, control

| Id | Gap | Class | Cause | Fix |
|---|---|---|---|---|
| P22 | 2277 gaps in 04-owasp-join-report | defect | `owasp_join_report._gap` puts `row_index` in the gap id, so every control x component row repeats the same three statements. | One gap per (kind, statement) with `row_indices`/count. |
| P23 | "Source completeness is unknown" always paired with "No deterministic applicability rule matched" | defect | `owasp_applicability._unresolved` hard-codes `source_completeness: "unknown"`, which triggers the second gap. | Do not raise the completeness gap for a `cannot_determine` row whose only cause is "no rule". |
| P24 | OWASP controls for a CLI are `cannot_determine` instead of N/A | defect | `owasp_component_routing` only ever emits `applicable/all_controls` rules for components whose family matches web/api/service aliases; it never emits `not_applicable`. | For a known `cli`/`library` component with no network/http trait, emit domain-selector `not_applicable` rules (ASVS web, session, API chapters) with `positive_exclusion`, `source_completeness: adequate` and a component-map citation. |
| P25 | "4 components with incomplete classification" (04-owasp-component-routing) | defect | `_classification_state` makes any medium-confidence component or any component named in `unknowns[]` `partial`, and `partial` gets no rule. | Treat `partial` as known for rule emission and carry the unknown as a condition; gap only for `unknown`. |
| P26 | "control-specific assessment has not been performed" (04-owasp-validation-worklist, 15-stig-srg-validation-worklist) | defect | `standards_lifecycle.py` puts this gap on every control x target row without a dynamic runtime; `_component_targets` falls back to all components. | One summary gap with a count; no fallback to all components. |
| P27 | 15-deployment-hardening "No IaC/STIG-SRG evidence" (Dockerfile not scanned) | defect | `full_review_input_assembly.py` sets `iac_present` only for `.tf`/`.tfvars` and deploy YAML, so a Dockerfile-only target skips `02-iac-config-scan` (checkov, trivy-config, hadolint would run). | Include Dockerfiles and `.github/workflows` in `iac_present`. |
| P28 | 15-deployment-hardening never matches a scan hit | defect | `standards_lifecycle.py` matches `work["target_id"] in str(hit)`; target ids are component ids, hits carry only `location.path`. | Match the hit path against the component's `path_patterns`/representative locations. |
| P29 | 05-native-memory "Host/runtime verification not performed" | limit | `bounded_analysis_workers.native_memory` adds the gap and `OK_WITH_GAPS` unconditionally, even with zero candidates; `claim_limits.runtime_claimed: false` already says it. | Gap only when there are candidates. |
| P30 | 02-devops-project-discovery / 02-sre-operations-topology: no CI/CD, no IaC, no ports, no runbooks, no health checks, partitions without routing | absence | The task prompts require absence to be a coverage gap; the schemas have only `coverage_gaps`; `automatic_discovery.py` turns any gap into `OK_WITH_GAPS`. | `absence_observations` in `schemas/project-discovery.schema.json` and `schemas/operations-topology.schema.json`; prompts put verified absence there; only gaps drive status. |
| P31 | 03-threat-model-dfd-stride "No challenge/refutation cell ran", "native-parser-input-specialist (not built)" | defect (reporting) + feature | `threat_workbench.NOT_BUILT` adds one gap per unbuilt cell on every run (challenge cell unconditionally, native specialist for every C target). | One gap "ADR-0019 slice-1 cells not built: [...]". Building the wave-3 challenge cell and the native-parser specialist stays on the threat-workbench list in TODO.md. |
| P32 | 03 and 03-reconciliation repeat the same unknowns (CODEOWNERS, seeded fixture, BUILDING.md option 2, VENDORED.md origin) | defect | `threat_model_core.py` counts every assumption as a gap next to `classification_gaps`; `threat_model_reconciliation.py` repeats unresolved assumptions as gaps. | Assumptions stay assumptions; reconciliation gaps only for assumptions that changed against the baseline. |
| P33 | dynamic-rescope `initial-intake-change-rescopes-current-graph` | defect | `control_feature_lifecycle.py` always passes `changed_nodes=["00-intake"]`, `max_iterations=1`, and returns `OK_WITH_GAPS` with this gap. | First run with no prior accepted generation: `OK`, no gap, state `INITIAL_BASELINE`. |
| P34 | dev-project-discovery notes listed under C | absence/limit | Persona schema has only `coverage_gaps`. | `informational_notes` in the persona output schema and prompt (same shape as P30). |
| P35 | root cause of P12: clang-tidy (and likely traced CodeQL) compile errors | defect | Found while fixing P12. The native build runs configure/make in a private `/scratch/src` copy where `config.h` is generated; `build_replay.py` keeps only `compile_commands.json` and binaries; native-sast mounts the pristine checkout, so `-DHAVE_CONFIG_H -I.` finds no `config.h`. | `build_replay.py` publishes configure-generated headers as hash-bound artifacts; native-sast (and the traced CodeQL replay if affected) mounts them read-only and adds them as an include path. |
| P36 | (owner request 2026-10-03) builds do not publish what they consumed: include dirs, headers actually included, link commands, linked libraries | feature | `build_replay.py` publishes `compile_commands.json`, binaries and (P35) generated headers only. Link lines, `-l`/`-L`, resolved shared objects and out-of-checkout headers are not recorded, so the SBOM cannot infer system or third-party dependencies. | Per unit, inside the build image after a successful build: (1) the headers each translation unit includes (compiler `-M` over each compile-DB entry), classified as checkout, generated, third-party-in-checkout (e.g. `vendor/`) or system; (2) include and library search dirs; (3) link commands (wrap or trace the link step) with `-l`/`-L`/rpath; (4) `DT_NEEDED`/RUNPATH of each built binary resolved to the real file; (5) the owning OS package and version of every out-of-checkout header and library (`dpkg -S` / `dpkg-query`, distro id from `/etc/os-release`). Publish one hash-bound, bounded `build-dependencies.json` per unit; files that cannot be attributed are gaps, never dropped. |
| P37 | SBOM cannot use build evidence beyond the cJSON heuristic | feature | `dependency_workers` enriches from the build index only, special-casing cJSON. | `02-sbom-inventory` takes P36's record (optional edge from `02-native-build`, skip-propagated): OS-package components as `pkg:deb/<distro>/<name>@<version>?arch=<arch>` with scope `runtime` (DT_NEEDED) or `build` (headers/static only), evidence citing the header/library paths; third-party-in-checkout header trees become vendored-component candidates, versioned from version macros generically (cJSON becomes one case of the rule); unattributed out-of-checkout files are gaps. CycloneDX export carries scope and evidence so Grype and OSV can match them. |

## Environment items (no code test)

| Id | Item | Where |
|---|---|---|
| E1 | OSV feed not published on the run host: `osv_feed.py sync`, set `APPSEC_OSV_ROOT` for the Dagster stack | `docs/osv-feed.md`, TODO.md "OSV feed" |
| E2 | `audit-codeql-native` image and B16 record so traced C/C++ CodeQL rows run | TODO.md section G |
| E3 | Rebuild `audit-binary-analysis` after P02/P03 change `analyze-binary.sh`; re-pin | `docs/processes/tool-images.md` |

## Target-intrinsic gaps that stay

These describe the target and stay gaps or assumptions in the report: no CODEOWNERS, the fixture is
deliberately seeded (confidence bounds), `vendor/cJSON` origin claimed by `VENDORED.md` but not
verified against upstream, `strcpy` in `greet.cpp` not confirmed by dynamic evidence (13-fuzz /
12b), deployed umask/container user unknown, `docs/BUILDING.md` option 2 not built. After P32
each appears once.

## Suggested order

1. P19, P20 (SBOM/SCA is the largest evidence hole: the one dependency has no CVE match today).
2. P04, P05, P02, P03, P01 (native evidence quality feeds reachability and 07/09/12).
3. P22-P26 (2277 OWASP gaps drown the report), then P27, P28.
4. P07, P09, P10, P12 (code index and native SAST coverage).
5. P13, P14, P17 (new analysis coverage).
6. P15, P16, P18, P29-P34 (report honesty: absence is not a gap).

## Fix plan (coordinated, 2026-10-03)

Fixes run in three waves of up to four agents. Each agent owns a disjoint set of files, works in its
own git worktree and commits there; the coordinator merges each branch into
`claude/practical-darwin-yk9370`, runs the full gate below, and records each fix in the TODO.md
breakage log. An item is closed when its `@unittest.expectedFailure` decorator is removed and the
test passes.

| Wave | Agent | Items | Files owned |
|---|---|---|---|
| 1 | dep | P19, P20 | `dependency_workers.py`, `reachability_engine_jobs.py`, SBOM schemas/contracts if needed |
| 1 | ir | P04, P05 | `ir_evidence.py` |
| 1 | binary | P01, P02, P03, P06 | `binary_evidence_adapter.py`, `binary_evidence_core.py`, `images/audit-binary-analysis/` |
| 1 | owasp | P22, P23, P24, P25 | `owasp_join_report.py`, `owasp_applicability.py`, `owasp_component_routing.py` |
| 2 | standards | P26, P27, P28 (+ 4 pre-existing errors in `test_full_review_input_assembly`) | `standards_lifecycle.py`, `full_review_input_assembly.py` |
| 2 | cpg | P07, P08, P09, P10 | `code_graph_evidence.py`, `pipeline/joern_export_records.sc`, `code_index.py`, `code_index_job.py`, `code_query_mcp.py`, `pipeline/job-graph.json` and generated views |
| 2 | native | P11, P12 | `codeql_sast.py`, `native_sast.py`, `images/audit-native/scripts/run_native_sast.py` |
| 2 | intel | P16, P17, P18, P21 | `static_intelligence_core.py`, `standards_source_ingest.py`, `automatic_evidence_inputs.py`, `tooling/buildenv-catalog.json`, their schemas |
| 3 | sast | P13, P14 | `data/source-sast/`, `source_sast*.py`, new `images/tool-shellcheck/` |
| 3 | misc | P15, P29, P33 | `treesitter_ast.py`, `bounded_analysis_workers.py`, `control_feature_lifecycle.py` |
| 3 | discovery | P30, P34 | discovery schemas, `02-evidence-pregather/task-*.md` prompts, `automatic_discovery.py` |
| 2b | headers | P35 | `build_replay.py`, `native_sast.py` (mount/include only), traced CodeQL replay if affected |
| 3 | builddeps | P36, P37 | `build_replay.py` (dependency capture), native-build schema/contract, `dependency_workers.py`, `sbom_family_contracts.py`, SBOM schemas, `02-sbom-inventory` edge in `pipeline/job-graph.json` |
| 3 | threat | P31, P32 | `threat_workbench.py`, `threat_model_core.py`, `threat_model_reconciliation.py` |

Gate after each merge: the four `test_gap_punchlist_*` modules, every existing test module for the
touched files, `python3 appsec-review-process/validate_design_parity.py --check-generated-views`, and
`python3 docs/processes/job_catalog.py --check`. Image changes (P03, P12, P14) also need a rebuild
and re-pin on the run host before the re-run (E3 plus `audit-native`, `tool-shellcheck`).

Then: E1 and E2 on the host, and a fresh `full_review` of `hello-autotools` to compare gap counts against
run `20261003T000827Z-a02791`.
