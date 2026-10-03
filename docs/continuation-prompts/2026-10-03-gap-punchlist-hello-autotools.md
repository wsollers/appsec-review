# Gap punch list: hello-autotools run `20261003T000827Z-a02791`

Engagement record. Moved here from `docs/TODO/` on 2026-10-03 (that folder holds docs-reorganisation
chunks only; `docs/README.md` puts dated records in `continuation-prompts/`). The `Status` column is
filled from the merge commits; see "Result" under the fix plan.

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

| Id | Gap | Class | Cause | Fix | Status |
|---|---|---|---|---|---|
| P01 | `packed-state:unknown`, `static-packer-classification-inconclusive` (02-binary-triage, repeated by 02-binary-intelligence-ingest) | defect | `binary_evidence_adapter.py` `_triage_record` always sets `packed: UNKNOWN` and adds the gap. The image already writes `die.json`, `strings.txt` and the section list; nothing reads them. `binary_evidence_core.py` then copies triage gaps into every intelligence lead. | Add `_packed_state`: YES on a DIE packer/protector, `UPX!` or `UPX0/UPX1` sections; NO when DIE parsed with no packer and the normal ELF sections are present; else UNKNOWN plus the gap. Bind `die.json` and `strings.txt` into the hashed outputs. | fixed `73b64a7` |
| P02 | `duplicate-symbol-identity` (02-debug-symbol-index) | defect | `analyze-binary.sh` runs `nm -an`; `-a` adds STT_FILE `a` symbols at address 0 (two `crtstuff.c` entries from crtbegin/crtend always collide). | Skip nm kinds `a` and `N` in `_debug_record`; keep the duplicate check for real collisions. | fixed `73b64a7` |
| P03 | `source-locations-unavailable` (02-debug-symbol-index) | defect | `_debug_record` hard-codes `source_path: None, line: None`; DWARF is never read. | `nm -anl` (or `llvm-symbolizer`), parse the trailing `file:line`, strip `/scratch/src/` or `/workspace/` to a repo-relative path, None outside the checkout. Gap only for defined text symbols without a location while debug sections exist; `debug-info-absent` otherwise. Needs an `audit-binary-analysis` rebuild and re-pin. | partial `73b64a7` (+E3: rebuild `audit-binary-analysis` for `nm -anl`) |
| P04 | 267x `fact-source-ambiguous` (02-ir-facts) | defect | The `!DILocation` regex in `ir_evidence.py` requires `column:` and misses `distinct !DILocation` and `!DILocation(line: 0, scope: ...)` (common at `-O2`), so those ids never enter the location map. | Regex `^!(\d+) = (?:distinct )?!DILocation\(line: (\d+)(?:, column: (\d+))?, scope: !(\d+)(?:, inlinedAt: !(\d+))?`. | fixed `c0afe2e` |
| P05 | 344x `debug-location-source-ambiguous` (02-ir-facts) | defect | Inlined code (libstdc++ `basic_string.h` into `build_greeting`, `run_report`, `main`) has a header scope plus `inlinedAt`; `inlinedAt` is never followed. Repo headers are not in `source_by_path`. | Walk the `inlinedAt` chain to the outermost location that maps to a source. Report system-header locations as `debug-location-outside-checkout`; keep "ambiguous" for more than one match. | fixed `c0afe2e` |
| P06 | (side bug) every hardening lead reads "not confirmed" | defect | `binary_evidence_core.py` tests `state is True`; hardening values are strings (`ENABLED`). | Compare against the enum. | fixed `73b64a7` |

## B. Code index, CPG, SAST, tree-sitter

| Id | Gap | Class | Cause | Fix | Status |
|---|---|---|---|---|---|
| P07 | `cpg-coverage-gap:no-source-location:119` (02-code-index), `no-source-location` (02-code-property-graph) | defect | `pipeline/joern_export_records.sc` exports every `cpg.method`/`cpg.typeDecl`, including external stubs (`<operator>.*`, libc, `<global>`) whose file is `<empty>`; `code_graph_evidence.py` counts them as missing locations. | Export `isExternal(false)` only, or count location-less METHOD/TYPE_DECL rows as `external-stub` info, not a gap. CALLs without a location stay a gap. | partial `55a173e` (+exporter change not yet compiled by a host Joern run) |
| P08 | `duplicate` (02-code-property-graph) | limit | c2cpg emits identical nodes at macro expansion sites (cJSON macros); dedup is correct. | Report the dedup count as info; it must not set `OK_WITH_GAPS`. | fixed `55a173e` |
| P09 | `source-not-indexed:02-ir-facts`, `source-not-indexed:02-debug-symbol-index` (02-code-index) | defect | Hard-coded in `code_index.py`; `pipeline/job-graph.json` gives 02-code-index no edge to either job and `code_index_job.py` binds neither. | Add optional edges and bindings; emit `source-not-indexed:<job>` only when that job was accepted and its records were not ingested; ingest them as the follow-up feature. | fixed `55a173e` |
| P10 | `cpg-exporter:no-inheritance-edges`, `cpg-exporter:no-method-reference-nodes` (02-code-index) | defect | Hard-coded in `code_index.py`; the exporter never walks `inheritsFromTypeFullName` or `cpg.methodRef`, so `type_edges` stays empty. | Export `INHERITS` type rows and `METHOD_REF` rows (extend `code_graph_evidence.KINDS` and the record schema), fill `type_edges`, emit the gap only when the count is zero. | partial `55a173e` (+exporter change not yet compiled by a host Joern run) |
| P11 | 02-codeql-cpp "ran with --build-mode none" | defect (wording) + env | `FIDELITY_GAPS["cpp"]` is appended for the none-mode row even when traced rows ran; traced rows are UNAVAILABLE when `audit-codeql-native` has no current B16 record. | Replace the fidelity gap with "none-mode row only; traced units cover N" when READY traced rows exist. Env: build `audit-codeql-native` and register its B16 record (E2). | partial `f0fcc17` (+E2: `audit-codeql-native` and its B16 record) |
| P12 | `clang-tidy-tool-error:6-translation-units` (02-native-sast) | defect | `run_native_sast.py` counts any non-zero exit as a tool error; clang-tidy exits 1 on `clang-diagnostic-error` (missing `config.h`, unmounted generated includes) while still producing findings. | Split: 124 timeout, 127 missing tool (tool errors); 1 with `clang-diagnostic-error` is `clang-tidy-compile-error:<n>` with the first message. Then fix the compile-DB/include cause it reveals. | partial `f0fcc17` (+rebuild `audit-native`; root cause fixed by P35) |
| P13 | Semgrep has no taint flow (02-source-sast) | defect (intraprocedural), limit (interprocedural) | No rule in `data/source-sast/` uses `mode: taint`. | Add CE taint rules (sources `argv`, `getenv`, `fgets`, `recv`; sinks `system`, `popen`, `strcpy`, `sprintf`, `printf` format); narrow `RULES_GAP` to interprocedural/interfile. | partial `580bfb5` (+interprocedural/interfile taint stays a named limit) |
| P14 | Shell source has no analyzer (02-source-sast) | defect + env | No shellcheck image; `.sh` maps to `shell` and lands in `uncovered_language_gaps`. | `tool-shellcheck` image pinned via `tool_pins.py`, adapter plan row, hit exit code 1. | partial `580bfb5` (+build `tool-shellcheck` on the host; autotools-generated scripts are a named gap) |
| P15 | `no-grammar` (02-treesitter-ast) | absence | C/C++ are covered; the gap counts `.am`, `.ac`, `.in`, `.m4`, `.md`, `Makefile`, `configure`. | `NON_SOURCE_SUFFIXES` counted as info, not a gap. | fixed `7364a59` |

## C. Ingests, SBOM/SCA, reachability, build discovery

| Id | Gap | Class | Cause | Fix | Status |
|---|---|---|---|---|---|
| P16 | `readme-only-no-specialized-inputs` (02-api-collection-intelligence-ingest, 02-operations-doc-ingest) | absence | `static_intelligence_core.py` adds the gap when no candidate matches. A CLI with no API spec is not a coverage gap. | `SKIPPED` with `applicability: SKIPPED_NA_NO_APPLICABLE_INPUTS`; add `SKIPPED` to the four intelligence schemas' status enum. Also add `build`/`install` to the ops tokens so `docs/BUILDING.md` is ingested. | fixed `da62ed8` |
| P17 | `zero-indexable-records` (02-test-intelligence-ingest) | defect | `tests/run.sh` is a candidate but `_summaries` only knows Python `def test_`, gtest and JS patterns. | Shell `test_x()` / `run_test x`, C `test_x(`, Unity/CUnit `RUN_TEST(x)` patterns; one `test-entrypoint` record per runnable script. | fixed `da62ed8` |
| P18 | "No target evidence for: disa_gpos_srg, owasp_api_security_top_10, owasp_llm_top_10, owasp_mastg, owasp_masvs" (02-standards-source-ingest) | absence | `automatic_evidence_inputs._standards_selection` deselects them (DISA GPOS is hard-coded off) and `standards_source_ingest.py` turns every unselected family into a gap. | Publish them as `not_applicable_families`; gaps only for selected-but-missing families. | fixed `da62ed8` |
| P19 | `no-dependency-components-detected` (02-sbom-inventory) and `OSV_SKIPPED_NA_NO_PURL_COMPONENTS` (02-sca-vulnerability-match) | defect | `dependency_workers._CJSON_MEMBER` needs the version in the directory name (`cJSON-1.7.18`); the target uses `vendor/cJSON`. Even on a match it emits `purl=None, cpe=None`. | Accept `vendor/cJSON`, read `CJSON_VERSION_MAJOR/MINOR/PATCH` from the hash-bound `cJSON.h`, emit `pkg:github/davegamble/cjson@v1.7.18` and `cpe:2.3:a:cjson_project:cjson:1.7.18:*:*:*:*:*:*:*`. The OSV skip then clears; expect real CVE matches from Grype/NVD by CPE, since OSV's C advisories use GIT ranges. | fixed `3436f9c` |
| P20 | `ENGINE_INPUT:osv-unusable:DATA_ROOT_MISSING` (06-reachability-codeql, 06-reachability-ir) | defect + env | `reachability_engine_jobs.py` appends the OSV input gap unconditionally, even with zero rows (no SCA match needed OSV). On this host `APPSEC_OSV_ROOT` is unset and `data/feeds/osv` does not exist. | Emit the job-level gap only when a row needed OSV. Env: `osv_feed.py sync` and set `APPSEC_OSV_ROOT` (E1). | partial `3436f9c` (+E1: OSV feed on the host) |
| P21 | "autotools toolchain in audit-buildenv-cpp:local not verified from catalog" (02-dev-project-discovery) | defect | `tooling/buildenv-catalog.json` cpp entry lacks `configure.ac`/`Makefile.am`/`configure` markers and a `tools` list, although `images/audit-buildenv-cpp/Dockerfile` installs autoconf, automake, libtool, make, bear and pkg-config. | Add the markers and `tools`. | fixed `da62ed8` |

The other 02-dev-project-discovery notes (docs partition deferred, no lockfile, vendored cJSON has no
independent build, Dockerfile build path not planned, script-execution capability) are persona
output the prompt asks for. They are **absence**/**limit** notes; see P34.

## D. OWASP, STIG/SRG, threat model, control

| Id | Gap | Class | Cause | Fix | Status |
|---|---|---|---|---|---|
| P22 | 2277 gaps in 04-owasp-join-report | defect | `owasp_join_report._gap` puts `row_index` in the gap id, so every control x component row repeats the same three statements. | One gap per (kind, statement) with `row_indices`/count. | fixed `14d295f` |
| P23 | "Source completeness is unknown" always paired with "No deterministic applicability rule matched" | defect | `owasp_applicability._unresolved` hard-codes `source_completeness: "unknown"`, which triggers the second gap. | Do not raise the completeness gap for a `cannot_determine` row whose only cause is "no rule". | fixed `14d295f` |
| P24 | OWASP controls for a CLI are `cannot_determine` instead of N/A | defect | `owasp_component_routing` only ever emits `applicable/all_controls` rules for components whose family matches web/api/service aliases; it never emits `not_applicable`. | For a known `cli`/`library` component with no network/http trait, emit domain-selector `not_applicable` rules (ASVS web, session, API chapters) with `positive_exclusion`, `source_completeness: adequate` and a component-map citation. | partial `14d295f` (+owner confirmation that an N/A rule may rest on the bound component map) |
| P25 | "4 components with incomplete classification" (04-owasp-component-routing) | defect | `_classification_state` makes any medium-confidence component or any component named in `unknowns[]` `partial`, and `partial` gets no rule. | Treat `partial` as known for rule emission and carry the unknown as a condition; gap only for `unknown`. | fixed `14d295f` |
| P26 | "control-specific assessment has not been performed" (04-owasp-validation-worklist, 15-stig-srg-validation-worklist) | defect | `standards_lifecycle.py` puts this gap on every control x target row without a dynamic runtime; `_component_targets` falls back to all components. | One summary gap with a count; no fallback to all components. | fixed `7280324` |
| P27 | 15-deployment-hardening "No IaC/STIG-SRG evidence" (Dockerfile not scanned) | defect | `full_review_input_assembly.py` sets `iac_present` only for `.tf`/`.tfvars` and deploy YAML, so a Dockerfile-only target skips `02-iac-config-scan` (checkov, trivy-config, hadolint would run). | Include Dockerfiles and `.github/workflows` in `iac_present`. | fixed `7280324` |
| P28 | 15-deployment-hardening never matches a scan hit | defect | `standards_lifecycle.py` matches `work["target_id"] in str(hit)`; target ids are component ids, hits carry only `location.path`. | Match the hit path against the component's `path_patterns`/representative locations. | fixed `7280324` |
| P29 | 05-native-memory "Host/runtime verification not performed" | limit | `bounded_analysis_workers.native_memory` adds the gap and `OK_WITH_GAPS` unconditionally, even with zero candidates; `claim_limits.runtime_claimed: false` already says it. | Gap only when there are candidates. | fixed `7364a59` |
| P30 | 02-devops-project-discovery / 02-sre-operations-topology: no CI/CD, no IaC, no ports, no runbooks, no health checks, partitions without routing | absence | The task prompts require absence to be a coverage gap; the schemas have only `coverage_gaps`; `automatic_discovery.py` turns any gap into `OK_WITH_GAPS`. | `absence_observations` in `schemas/project-discovery.schema.json` and `schemas/operations-topology.schema.json`; prompts put verified absence there; only gaps drive status. | fixed `5be1507` |
| P31 | 03-threat-model-dfd-stride "No challenge/refutation cell ran", "native-parser-input-specialist (not built)" | defect (reporting) + feature | `threat_workbench.NOT_BUILT` adds one gap per unbuilt cell on every run (challenge cell unconditionally, native specialist for every C target). | One gap "ADR-0019 slice-1 cells not built: [...]". Building the wave-3 challenge cell and the native-parser specialist stays on the threat-workbench list in TODO.md. | partial `1eb8a18` (+building the wave-3 challenge cell and native-parser specialist stays open) |
| P32 | 03 and 03-reconciliation repeat the same unknowns (CODEOWNERS, seeded fixture, BUILDING.md option 2, VENDORED.md origin) | defect | `threat_model_core.py` counts every assumption as a gap next to `classification_gaps`; `threat_model_reconciliation.py` repeats unresolved assumptions as gaps. | Assumptions stay assumptions; reconciliation gaps only for assumptions that changed against the baseline. | fixed `1eb8a18` |
| P33 | dynamic-rescope `initial-intake-change-rescopes-current-graph` | defect | `control_feature_lifecycle.py` always passes `changed_nodes=["00-intake"]`, `max_iterations=1`, and returns `OK_WITH_GAPS` with this gap. | First run with no prior accepted generation: `OK`, no gap, state `INITIAL_BASELINE`. | fixed `7364a59` |
| P34 | dev-project-discovery notes listed under C | absence/limit | Persona schema has only `coverage_gaps`. | `informational_notes` in the persona output schema and prompt (same shape as P30). | fixed `5be1507` |
| P35 | root cause of P12: clang-tidy (and likely traced CodeQL) compile errors | defect | Found while fixing P12. The native build runs configure/make in a private `/scratch/src` copy where `config.h` is generated; `build_replay.py` keeps only `compile_commands.json` and binaries; native-sast mounts the pristine checkout, so `-DHAVE_CONFIG_H -I.` finds no `config.h`. | `build_replay.py` publishes configure-generated headers as hash-bound artifacts; native-sast (and the traced CodeQL replay if affected) mounts them read-only and adds them as an include path. | fixed `e4eb405` |
| P36 | (owner request 2026-10-03) builds do not publish what they consumed: include dirs, headers actually included, link commands, linked libraries | feature | `build_replay.py` publishes `compile_commands.json`, binaries and (P35) generated headers only. Link lines, `-l`/`-L`, resolved shared objects and out-of-checkout headers are not recorded, so the SBOM cannot infer system or third-party dependencies. | Per unit, inside the build image after a successful build: (1) the headers each translation unit includes (compiler `-M` over each compile-DB entry), classified as checkout, generated, third-party-in-checkout (e.g. `vendor/`) or system; (2) include and library search dirs; (3) link commands (wrap or trace the link step) with `-l`/`-L`/rpath; (4) `DT_NEEDED`/RUNPATH of each built binary resolved to the real file; (5) the owning OS package and version of every out-of-checkout header and library (`dpkg -S` / `dpkg-query`, distro id from `/etc/os-release`). Publish one hash-bound, bounded `build-dependencies.json` per unit; files that cannot be attributed are gaps, never dropped. | partial `fcc1058` (+capture not yet run inside a buildenv container) |
| P37 | SBOM cannot use build evidence beyond the cJSON heuristic | feature | `dependency_workers` enriches from the build index only, special-casing cJSON. | `02-sbom-inventory` takes P36's record (optional edge from `02-native-build`, skip-propagated): OS-package components as `pkg:deb/<distro>/<name>@<version>?arch=<arch>` with scope `runtime` (DT_NEEDED) or `build` (headers/static only), evidence citing the header/library paths; third-party-in-checkout header trees become vendored-component candidates, versioned from version macros generically (cJSON becomes one case of the rule); unattributed out-of-checkout files are gaps. CycloneDX export carries scope and evidence so Grype and OSV can match them. | fixed `fcc1058` |
| P38 | (found fixing P27) vendor IaC probe misses `*.Dockerfile` and `Containerfile` | defect | `vendor_evidence_workers._dockerfile` recognises only `Dockerfile`/`Dockerfile.*`; the assembly now launches `02-iac-config-scan` for those names but the probe reports not applicable. | Same name rules as `full_review_input_assembly._iac_input`, shared in one place. | fixed `5be1507` |
| P39 | (found fixing P26) STIG/SRG and OWASP worklists route from `downstream_lanes`, not from the T04 OWASP routing decisions | defect | `standards_lifecycle` reads the component map's `downstream_lanes`; the P24/P25 routing (CLI/library N/A, partial as conditional) does not reach the worklists. | Consume the accepted T04 routing for OWASP worklist targets; keep `downstream_lanes` for STIG/SRG only where no routing exists. | fixed `4622a7f` |
| P40 | (found fixing P26) standalone vendor and dependency requests from the assembly use an older shape | defect | No `source_binding`, vendor `applicability` or SCA `snapshot_identities`; `full_review` does not dispatch them, the standalone path would be refused. | Bring `full_review_input_assembly` requests to the orchestrators' current shape, with a round-trip test. | fixed `4622a7f` |
| P41 | (owner request 2026-10-03, appsec-multi-vuln case-081/082) base images are inventoried as text only | defect + feature | `vendor_evidence_workers._scan_base_images` records the `FROM` token and never looks inside the image, so an end-of-life base with vulnerable OS packages (case-081: `debian:buster-20190708-slim@sha256:0cee610a…`) yields no component or CVE, and a clean control (case-082) cannot be told apart from it. It also misparses `repo:tag@sha256:…` (the tag ends up in `repository`). | Parse `repo[:tag][@digest]` correctly. Resolve digest-pinned base images outside B13 into a content-addressed, hash-verified image cache on the host (tag-only references: resolve to a digest and record that it was mutable). Inventory each image's OS packages offline (Syft over the image filesystem: dpkg/apk/rpm databases, `os-release`) as SBOM components with `pkg:deb`/`pkg:apk`/`pkg:rpm` purls and distro qualifiers, flag end-of-life distributions from a pinned EOL table, and let Grype/OSV match them like any other component. Images that cannot be fetched or resolved are gaps. | partial `b34391d` (+host step 6b fetch; rpm databases not inventoried) |
| P42 | (found merging P37) the new optional `02-native-build` -> `02-sbom-inventory` edge lets a crashed native build stop the SBOM | defect | The Dagster native-build op raises when the job does not publish, and Dagster skips every downstream op, now including `02-sbom-inventory` (before P37 the SBOM did not wait on the build). Unit build failures still publish OK_WITH_GAPS, so only a native-build crash or BLOCKED is affected. Also: SBOM requests built by `full_review_input_assembly` carry no native-build binding. | The SBOM must run whenever the target source is available: the native-build edge into the SBOM is ordering-only and tolerant (the op returns a NOT_PUBLISHED marker for optional consumers, as lane 14 does for 10, or the SBOM op takes the edge through a non-raising adapter), and the SBOM records `native-build-not-published` as a gap. Assembly requests bind the accepted native build when present. Test: a raising native-build stub still lets the SBOM publish with that gap. | fixed `f75ef1d` |
| P43 | SBOM does not yet include base-image OS packages (follow-up to P41) | feature | `02-iac-config-scan` now publishes `base_images[].components[]` in `outputs/base-image-inventory.json`, but `02-sbom-inventory` does not read it, so Grype never matches them. | SBOM reads the accepted base-image inventory (optional edge from `02-iac-config-scan`, skip-propagated), adds each package as a CycloneDX component with its `pkg:deb`/`pkg:apk` purl, distro qualifier, the image reference as evidence and scope `container-base`, plus the EOL flag as a property; dedupe with Syft and P37 rows by purl; inventory gaps carry through. Also: register Debian and Alpine in the OSV feed ecosystems (`osv_feed.py`) so OSV can corroborate Grype. | partial `2e180f2`, `c87f694` (+re-run `osv_feed.py sync` for Debian/Alpine; their advisory licences unspecified) |

## Environment items (no code test)

| Id | Item | Where | Status |
|---|---|---|---|
| E1 | OSV feed not published on the run host: `osv_feed.py sync`, set `APPSEC_OSV_ROOT` for the Dagster stack | `docs/osv-feed.md`, TODO.md "OSV feed" | env (host) |
| E2 | `audit-codeql-native` image and B16 record so traced C/C++ CodeQL rows run | TODO.md section G | env (host) |
| E3 | Rebuild `audit-binary-analysis` after P02/P03 change `analyze-binary.sh`; re-pin | `docs/processes/tool-images.md` | env (host) |

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
| 3 | discovery | P30, P34, P38 | discovery schemas, `02-evidence-pregather/task-*.md` prompts, `automatic_discovery.py` |
| 2b | headers | P35 | `build_replay.py`, `native_sast.py` (mount/include only), traced CodeQL replay if affected |
| 3 | builddeps | P36, P37 | `build_replay.py` (dependency capture), native-build schema/contract, `dependency_workers.py`, `sbom_family_contracts.py`, SBOM schemas, `02-sbom-inventory` edge in `pipeline/job-graph.json` |
| 3 | threat | P31, P32 | `threat_workbench.py`, `threat_model_core.py`, `threat_model_reconciliation.py` |
| 4 | baseimages | P41 | `vendor_evidence_workers.py` (base-image parse), new base-image cache/inventory module and host step; SBOM consumption after `builddeps` merges |
| 5 | sbomwire | P42, SBOM side of P41 | `dagster_workflow.py` (native-build/SBOM wiring), `dependency_workers.py`, `full_review_input_assembly.py` (SBOM binding) |
| 6 | sbombase | P43 | `dependency_workers.py`, `sbom_family_contracts.py`, SBOM schemas, `02-sbom-inventory` edge, `osv_feed.py` ecosystem list |
| 4 | worklist | P39, P40 | `standards_lifecycle.py`, `full_review_input_assembly.py` |

Gate after each merge: the four `test_gap_punchlist_*` modules, every existing test module for the
touched files, `python3 appsec-review-process/validate_design_parity.py --check-generated-views`, and
`python3 docs/processes/job_catalog.py --check`. Image changes (P03, P12, P14) also need a rebuild
and re-pin on the run host before the re-run (E3 plus `audit-native`, `tool-shellcheck`).

Then: E1 and E2 on the host, and a fresh `full_review` of `hello-autotools` to compare gap counts against
run `20261003T000827Z-a02791`.

### Result (2026-10-03)

Merged on `claude/practical-darwin-yk9370` (one breakage-log row per group in
`appsec-review-process/TODO.md`): wave 1 `c0afe2e` (P04/P05), `73b64a7` (P01-P03, P06), `3436f9c`
(P19/P20), `14d295f` (P22-P25), `f0fcc17` (P11/P12); wave 2 `55a173e` (P07-P10), `7280324`
(P26-P28), `da62ed8` (P16-P18, P21), `e4eb405` (P35, found fixing P12); wave 3 `580bfb5` (P13/P14),
`7364a59` (P15, P29, P33), `5be1507` (P30, P34, P38), `1eb8a18` (P31/P32), `fcc1058` (P36/P37);
wave 4-6 `4622a7f` (P39/P40), `b34391d` (P41), `f75ef1d` (P42), `2e180f2` and `c87f694` (P43).
Generated views and sample data: `55659a8`, `9f2362a`, `2c9d954`.

Every code item has a status above; the `partial` ones need the host or remain
named limits:

- **Host (before the re-run):** E1 `osv_feed.py sync` (now including Debian and Alpine), E2
  `audit-codeql-native` plus its B16 record, E3 rebuilt `audit-binary-analysis`, `audit-native` (and the
  images layered on it) and the new `tool-shellcheck`, and `prepare-host.sh` step 6b for base images.
  Commands: [operator guide](../report-path/happy-path-operator-guide.md#host-steps-after-the-gap-punch-list-2026-10-03).
- **First host run is the test:** the Joern exporter change (P07/P10), build-dependency capture inside a
  buildenv container (P36), and the P42/P43 Dagster wiring (verified in a pinned-version venv only).
- **Limits that stay:** Semgrep interprocedural/interfile taint (P13), autotools-generated shell
  scripts (P14), rpm base images (P41), the unbuilt wave-3 challenge cell and native-parser specialist (P31).
- **Owner decisions open:** P24 (an OWASP N/A routing rule resting on the bound component map, a narrow
  exception to the canonical-evidence rule) and the four static intelligence ingests not honouring the
  partition map's `docs/**` deferral (seeded-defect leakage).
- **New items found during the fixes:** P35 (configure-generated headers, root cause of P12), P36/P37
  (build-dependency capture into the SBOM), P38-P40, P41-P43 (base-image OS packages).

Re-run: [`2026-10-03-hello-autotools-rerun.md`](2026-10-03-hello-autotools-rerun.md).
