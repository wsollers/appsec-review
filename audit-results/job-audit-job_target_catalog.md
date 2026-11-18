# Job 5/47 functional audit — job_target_catalog

## Result and source identity

- Audited **`main`, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, in the authorized `/home/wsollers/projects/appsec-review` checkout through SSH `wsl-ubuntu` and the Ubuntu-22.04 UNC root. The default Windows checkout was not audited or tested.
- Confirmed exact HEAD, base ancestry, clean `git status --porcelain`, and editable import `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py` before validation. Final HEAD/branch/cleanliness were unchanged; `git diff --check` passed.
- **Five medium functional findings reproduced**, plus **one low documentation discrepancy**. None is a live-run observation.
- **149 passing test executions, 146 unique cases**: 123 job-directory cases, six shared catalog contract cases, 14 selected document-parser cases, and three environment-guard cases executed in both runs. **Zero failures, skips, xfails, or cases exceeding 10 seconds.** Pytest elapsed: **8.64 s + 4.32 s = 12.96 s**; wrapper shell elapsed: **17.069 s + 12.221 s = 29.290 s**.
- No source/config/test edits, commits, pushes, models, provider calls, Docker/service operations, target execution, integration/acceptance/live tests, or Dagster runs. Synthetic test/reproducer files stayed beneath `test/tmp/`; owned disposable fixtures were removed, while logs/reports were retained. This session report is the only requested authored deliverable.
- Passing the focused units does **not** certify exact correctness, full-run immutable publication/admission, every build-system grammar, or useful live review output.

All source paths below are repository-relative.

## Registration, activation, inputs, and settings

`src/appsec_review/runtime/registry.py:122` registers the actual factory. `appsec-review.toml:613-653` declares five steps, fourteen tasks, and one worker per job/step. There is no model/task prompt dispatch in this job. Generated undeclared tool bindings remain the existing **T-147** documentation limitation, not missing handler implementations.

The job is enabled in the shipped recipe: it has no `settings.enabled` field, so `runtime/selection.py:11-24` selects it. Its typed document-settings parser accepts only the documented bounds (`config/loader.py:1407-1419`); there is no catalog-local feature-disabled branch. Shared graph placement derives from the contract (`orchestration/topology.py:47-83`), not a competing hard-coded catalog predecessor.

`jobs/job_target_catalog/datasets.py:45-70` declares:

| Input | Schema | Requirement / actual use |
|---|---|---|
| `job_review_intake/handoff` | `appsec-review/job-handoff/2` | Required; missing rejects admission. |
| `job_review_intake/model_preflight` | `appsec-review/model-preflight/1` | Optional, missing policy gap. |
| `job_review_intake/binary_evidence` | `appsec-review/binary-evidence-intake/1` | Optional, missing policy gap. |
| `job_review_intake/review_intake` | `appsec-review/review-intake/1` | Optional, missing policy gap. |

All have producer-evidence authority, handoff channel, and allow-partial coverage. Scheduling is after intake, dispatch is `review_graph`, target access is `checkout`, `always_execute=False`, and `propagate_handoff=True`. The handlers inventory the supplied checkout rather than reading the optional intake payloads. Admission is not evidence that these optional datasets were read. The job itself does not open an upstream `latest.json`.

The checkout path and claimed snapshot come from the runtime context; accepted inventory rows bind paths, sizes, hashes, languages, and scope. Global/job exclusions and global inventory file-size limit reach `inventory`. Its remaining defaults are 10,000 ordinary content files, 256 MiB content, and 512-character paths; descriptor discovery continues beyond ordinary content count/total-byte limits, but descriptors still obey the per-file limit. `raw_snapshot` separately hashes all regular non-VCS target bytes, including policy-excluded files. Source metrics have their own named omissions.

Document configuration is typed: 128 files, 256,000 bytes/file, 2,000 records, 80 lines/chunk, 4,096 bytes/chunk, parse depth 64, parse nodes 200,000. All seven settings reach the document collector and its fingerprint. **TC-03** identifies a format branch that does not honor the two parser settings. Other code-owned bounds include the 1-MiB discovery descriptor read, descriptor packages at 24 files / 64 KiB each / 256 KiB total, and 50,000 symbols / 16-MiB source reads. Making descriptor-package limits typed and reporting their omissions canonically is already **T-111**.

## Every declared step and task

Implementation locations in this table refer to `src/appsec_review/jobs/job_target_catalog/job.py`.

| Step.task | Actual implementation and input → processing → output | Validation, mismatch, or limit |
|---|---|---|
| `repository_discovery.partition_repository` | `partition`, lines 223-269: checkout → bounded inventory/exclusions/scope; binary candidates re-read with exact accepted size/hash, stored as immutable shared objects → `repository-partition.json`, accepted files/artifacts and discovery counters. | Binary custody/hash/size failures reject. Inventory gaps become typed records; raw payload retains path/reason records. Unit tests cover candidate mutation and unsafe paths. Full inventory/build grammar matrix was not run. |
| `repository_discovery.census_languages` | `census`, 271-276: accepted partition files → sorted language counts, `None` as Other → `language-census.json`. | Counts accepted text/descriptor files, not omitted files or binary candidates. No mismatch isolated. |
| `repository_discovery.discover_projects` | `projects`, 278-310: partition plus engine discovery → recognized manifests/suffixes, suppress Unity-generated generic manifests, append Unity roots → `projects.json`. | No-project and engine gaps explicit. Deterministic for the deterministic inventory; this is manifest discovery, not semantic component completeness. |
| `build_discovery.discover_build_systems` | `build_systems`, 312-374: accepted files + hash-bound descriptor reader → Unity metadata, build points/drives/folding/demotion, orphan/source-only scopes → `build-systems.json` `/4`, event. | Changed descriptors reject; oversize reads named. Extractor dispatch and all extractor implementations were read. Bounded static grammars are not actual builds. |
| `build_discovery.discover_compile_commands` | `compile_commands`, 376-386: accepted files → exact basename selection → `compile-commands.json`. | Records database identity only, not parsed/executed compile commands. Absence is explicit. |
| `build_discovery.catalog_build_targets` | `build_targets`, 388-417: discovered units + accepted inventory → descriptor packages, Unity fingerprint or Android facts, image profile → `build-targets.json` `/2`. | **TC-04**: a smaller packaging bound erases already-discovered Android facts and misroutes to Java. Package omissions not copied to canonical gaps: known **T-111**. |
| `component_discovery.catalog_components` | `components`, 419-429: projects → ordered `component:NNNN` records; empty projects get one root fallback → `components.json`. | One component per manifest, not ownership resolution; **T-035** covers richer component topology. |
| `component_discovery.catalog_dependencies` | `dependencies`, 431-481: component manifests → npm dependencies/devDependencies with declaration evidence and scope → `dependencies.json`. | Non-Node parser/missing/syntax/decode gaps explicit; normal dependency delivery remains unknown. **TC-02**: valid JSON with invalid object/section shape escapes error handling and fails the task. |
| `retrieval_indexes.build_path_index` | `path_index`, 483-528: source-in-scope accepted files → source identities, bounded text and locations → `source` SQLite shard. | Propagates inventory gaps; hashes final shard. Tests fake SQLite for detailed transform assertions; shared contract test writes real SQLite. Source text re-read is not locally rehashed; concurrent mutation behavior was not certified. |
| `retrieval_indexes.build_symbol_index` | `symbol_index`, 530-597: accepted source files → bounded declaration regex, symbols and exact `DEFINES` relations → `analysis` shard. | **TC-01**: universal-newline conversion corrupts raw byte offsets. **TC-05**: upstream inventory omissions disappear from shard coverage. Regex intentionally is not AST/compiler analysis. |
| `retrieval_indexes.build_component_index` | `component_index`, 599-618: component catalog → component identities/payloads/text → `components` shard. | Publishes the discovered component list, including fallback; complete here is not a claim that manifest-based discovery found every actual product/dependency. |
| `retrieval_indexes.build_target_documents` | `document_index`, 620-745: classified accepted inventory + typed bounds → collector records/links; verify actual file hash and source-line/byte ranges → `documents` shard. | **TC-03**: OpenAPI 3 JSON branch loses compact operations, binds lookalikes, ignores parser bounds. Missing kinds and collector/inventory gaps remain explicit. Gap list capped at 200 plus truncation record. |
| `publish_catalog.validate_catalog` | `validate_catalog`, 747-759: four index artifact identities → presence + fresh SHA-256 comparison → VALID and retained upstream gap reasons. | Missing/tampered shard rejects. This is artifact integrity, not semantic correctness; cannot detect TC-01/03/04/05. |
| `publish_catalog.publish_handoff` | `publish`, 761-851: catalog artifacts, build targets, compile identities, validation → build shard, five-shard manifest, `target-catalog.json`, `REVIEW_SCOPE_CATALOGED`. | Build/compile absence reported; security findings intentionally empty. Real runner publication was read, not executed. Build-action coverage also uses target presence rather than considering every discovery gap; see coverage caveat below. |

The explicit unit dependency DAG at lines 854-876 contains all fourteen tasks. Cross-step ordering is intentional: project discovery waits for engine/build discovery. Final publication's direct dependencies transitively cover all artifacts it reads. `_validate_config` checks exact configured step/task order (209-215); there are no job-domain output validators or per-unit custom validators beyond handler checks and shared framework validation.

### Shared processing and publication boundaries

- `jobs/cataloging.py` implements deterministic non-following traversal, content/descriptor admission, binary candidates, source metrics, raw snapshot and JSON serialization. `config/exclusions.py` matchers and `runtime/scope.py:52-59` determine policy exclusions and target/build-chain classification. `delivery_scope.py` preserves provenance separate from delivery.
- `jobs/build_discovery.py` preserves units, markers, member folding, drivers, parallel capture authority, installed/generated tree handling, orphan decisions and source-only scopes. `jobs/build_points.py` dispatches CMake, Make, autotools, Meson, Cargo, Go, Node, Gradle, Maven, MSBuild, Xcode, Unity and generic package readers without execution. Unity metadata and configuration fingerprints are in `jobs/engine_discovery.py`; identity errors caught there are surfaced by the catalog descriptor reader's changed list.
- `indexing/target_documents.py` and `document_interfaces.py` classify and parse documents only as data. The real collector currently emits exact links only; the mapped test that deliberately supplies a nonexact link and expects a missing-ambiguity exception is **not** evidence that normal production links hit that branch.
- `retrieval/model.py` validates structural identity/location metadata but does not check a symbol's byte range against source text. `retrieval/index.py:143-240` writes deterministic shards and refuses a conflicting existing path instead of overwriting it. `write_manifest` at 364 onward binds five shard identities; loading checks their identities/hashes and relation closure.
- `runtime/handoff.py:466-513` checks required outputs against this producer's own direct/computed shards and declared steps; inherited shards do not satisfy them. `runtime/runner.py:960-1054` checks task receipts/results, produces strict outcomes, verifies required outputs and artifact references, and retains input-read checks before admission. This code path was not exercised end-to-end.
- `runtime/checkpoints.py:25-41` makes artifact/index-bearing unit results nonportable; a failed catalog cannot generically transplant those files. Whole-job reuse checks configuration, source fingerprint, implementation/schema/validator/contract and upstream identities (`runtime/resume.py:108-134`). No full reuse/restart cycle was executed.

### Published datasets and consumers

All seven declarations have producer-evidence authority and internal sensitivity (`datasets.py:12-40`).

| Dataset | Actual storage and declared schema | Downstream expectation traced |
|---|---|---|
| `target_artifact_inputs` | Optional artifact-only `data/shared/objects/*`, `target-artifact-intake/1`; reference metadata in partition. | Artifact indexing/scanner catalog needs exact target provenance and separately retained binary gaps; bytes are not public retrieval payloads. |
| `source_files` | Required `source` shard, `retrieval-index/2`. | `find/search/read_excerpt`; source identity and scope, not semantic compilation. |
| `declaration_symbols` | Required `analysis` shard, `retrieval-index/2`. | Symbol search/trace and exact file relation/location. TC-01 and TC-05 affect this contract. |
| `components` | Required `components` shard, `retrieval-index/2`. | Component identities/manifests; not inferred complete ownership. |
| `target_documents` | Required `documents` shard, `retrieval-index/2`. | Declared/intent records with resolving source references; TC-03 affects this contract. |
| `build_units` | Required `build` shard from publication, `retrieval-index/2`. | Build-action facts and compile-database identities, not built outputs. |
| `catalog_documents` | Artifact-only `data/jobs/job_target_catalog/attempts/*/artifacts/catalog/*.json`, aggregate declaration `target-catalog/1`. | Nine JSON catalogs retain their own payload schemas; accepted final catalog references each. |

`job_evidence_collection/job.py:167-203` reads the accepted envelope, verifies referenced catalog documents and projects files, compile databases and target artifacts into `ScanCatalog`; it does not invent built artifacts. `job_dependency_intelligence/job.py:159-167` consumes `dependency-catalog/1`. `job_target_analysis_plan/job.py:95-145` takes its **build_units from the targets document**, then selects/group-bounds image profiles at 365-411; therefore the TC-04 fact loss persists downstream rather than being repaired from the systems document. Retrieval coverage (`retrieval/core.py:839-881`) reads the selected shard's rows/gaps, which makes the TC-05 inconsistency observable without querying the source shard.

## Findings

### TC-01 — Medium — CRLF sources publish incorrect “exact” symbol byte spans

- **Evidence:** `src/appsec_review/jobs/job_target_catalog/job.py:552`, `:561`, `:579`.
- **Trigger:** A recognized declaration after CRLF line endings; also any equivalent newline-normalizing read.
- **Expected:** Byte spans resolve to the original accepted file bytes identified by `file_sha256`.
- **Actual:** `Path.read_text` normalizes CRLF to LF; offsets are accumulated from the normalized text and advertised as `source-line-exact`, confidence 1.0, against the raw-file hash. In the real SQLite reproduction, `first` started at byte 10 and sliced `"\ndef first():"`; `Last` started at byte 32 and sliced `"s\r\nclass Las"`. No gap was emitted.
- **Impact:** Byte-addressed evidence and location consumers receive false exact locations on ordinary Windows-authored files. Line-only excerpt readers can still show the correct line; this is not a claim that every excerpt fails.
- **Confidence:** High, reproduced against the actual handler and SQLite writer.
- **Smallest correction:** Read accepted raw bytes, decode without universal-newline translation, and derive byte offsets from those exact bytes; add a CRLF regression analogous to the current LF/UTF-8 test.
- **Existing work:** No matching newline/span fix found in relevant TODO/history searches. Current `test_indexes.py:90-119` exercises UTF-8 but LF only.

### TC-02 — Medium — Invalid npm manifest shapes fail the entire catalog instead of producing parse gaps

- **Evidence:** `src/appsec_review/jobs/job_target_catalog/job.py:447-449`, `:472-478`.
- **Trigger:** Syntactically valid JSON whose root is not an object, or `dependencies`/`devDependencies` is null, a list, or another non-mapping.
- **Expected:** Record a file-scoped parser gap, preserve other components, and continue the bounded catalog.
- **Actual:** `.get` / `.items` raises uncaught `AttributeError`. Four reproductions: `[]`, `{"dependencies":null}`, `{"dependencies":["bad"]}`, `{"devDependencies":2}`. The handler emits no dependency artifact on these failures; final publication depends on this task.
- **Impact:** One malformed manifest prevents publication of otherwise useful repository/source/build inventories. This is inconsistent with the adjacent handling of malformed JSON syntax and unsupported manifest formats.
- **Confidence:** High; real handler, synthetic manifests.
- **Smallest correction:** Validate root and section mappings explicitly and emit `PARSER_ERROR` for invalid shapes; preserve valid components/sections according to an explicit policy rather than adding a broad catch-all.
- **Existing work:** T-098/T-099/T-101 cover missing dependency sources/parser expansion, not this error-handling defect. Existing negative tests cover missing files, syntax and UTF-8, not JSON shape.

### TC-03 — Medium — OpenAPI 3 JSON bypasses structural parsing, losing or misbinding operations and ignoring parser limits

- **Evidence:** `src/appsec_review/indexing/target_documents.py:255-305`, especially `:282-300`; contrast the bounded structural routes at `:225-240`, `:260-268`, and `:312-315`. The job passes both parser limits at `jobs/job_target_catalog/job.py:635-641`.
- **Trigger:** Compact/inline OpenAPI 3 JSON, an earlier example containing the same route/method keys, or a parser budget below the document's structure.
- **Expected:** Parse the same supported operation regardless of JSON whitespace, cite the actual `paths/<route>/<method>` member, and apply configured parse depth/node limits.
- **Actual, reproduced:**
  1. Pretty JSON emits one `GET /orders`; equivalent compact JSON emits zero and `unresolved_span`.
  2. A route/method lookalike in `components.schemas.Example.example` receives the operation's source line **12**, while real `paths` begins on line **20**. Fields come from the real operation, but the location points at the example; **no gap**.
  3. `max_parse_depth=1`, `max_parse_nodes=1` still emit the pretty operation with **no gap**. Those settings are never read in this JSON-3 branch.
- **Impact:** Format-dependent interface loss, source evidence bound to the wrong structural object, and an operator bound silently ignored. No live model or resource-exhaustion experiment was performed.
- **Confidence:** High; real collector and source files.
- **Smallest correction:** Reuse the bounded structural OpenAPI path (or structural JSON member spans) for OpenAPI 3 JSON too, preserving the intended payload fields and exact operation-member locations. Add compact, lookalike and small-bound tests.
- **Existing work:** The historical catalog report records the **same class of whitespace/source-location issue repaired for Postman**, not OpenAPI. Its `target-documents/3` identity is present. Existing parser-limit tests cover YAML and Postman; the compact JSON interface fixture is Swagger 2, which already uses the structural path. No matching OpenAPI 3 item found.

### TC-04 — Medium — Descriptor packaging erases accepted Android facts and selects the Java profile

- **Evidence:** `src/appsec_review/jobs/job_target_catalog/job.py:403-409`; facts originally established at `src/appsec_review/jobs/build_discovery.py:535-541`; descriptor omission at `:1241-1246`; profile gate at `:136-144`.
- **Trigger:** An accepted Android Gradle descriptor readable by the 1-MiB discovery reader but omitted by the 64-KiB descriptor-package limit (or another packaging omission of the declaring document).
- **Expected:** Preserve accepted Android facts/image routing independently of bounded planner-text packaging; report the missing package text.
- **Actual:** A 77,067-byte `build.gradle` yields `android-gradle-application`, plugin `com.android.application`, compile SDK 35 during discovery. `catalog_build_targets` recomputes from an empty package, overwrites `descriptor_facts` with `{}`, changes `project_type` to `generic`, and sets `required_image_profile=java`. Its canonical `gaps` is empty; only the nested package names the omitted bytes.
- **Impact:** Planning consumes these target records (`job_target_analysis_plan/job.py:142`) and chooses allowed image profiles from them (`:369-411`), so the Android SDK/tooling lane is lost before build planning.
- **Confidence:** High; both real handlers and shared descriptor/fact helpers exercised. No actual build was attempted.
- **Smallest correction:** Preserve/merge previously validated discovery facts instead of replacing them with absence from a smaller evidence package; retain explicit omitted-text coverage.
- **Existing work:** **T-111** already tracks hidden canonical package-bound gaps and untuned limits. The **routing/fact-erasure consequence is additional**; merely exposing the existing gap does not fix it.

### TC-05 — Medium — Symbol shard reports complete declarations after the source inventory omits files

- **Evidence:** `src/appsec_review/jobs/job_target_catalog/job.py:533-538`, `:588-596`; compare propagation in `path_index` at `:490-492`. Retrieval exposes only selected shard rows/gaps at `src/appsec_review/retrieval/core.py:858-881`.
- **Trigger:** Inventory drops an otherwise eligible source because of count/size/total-byte bounds.
- **Expected:** The dependent declaration shard retain the omitted-source coverage limitation, with a resolving typed gap, instead of an unqualified complete declaration inventory.
- **Actual:** Real inventory with a one-content-file bound retains `a.py`, omits `b.py`, and reports `b.py: inventory_bound_reached`. The real symbol handler produces `gaps=[]`; SQLite coverage is `declarations, complete, NULL`. The production default reaches the same branch at its normal bounds.
- **Impact:** `coverage(indexes=["analysis"])` can describe incomplete declaration coverage as complete and provide no omission reason. **The partition/global outcomes and source shard still retain their gaps**; this finding does not allege that the whole-run gap is erased.
- **Confidence:** High for the reproduced shard output; the policy recommendation is to propagate relevant source omissions, not treat configured exclusions as newly forbidden.
- **Smallest correction:** Seed symbol gaps from relevant partition inventory omissions, as the source/document handlers do, and keep shard coverage partial when declarations could not be inspected.
- **Existing work:** T-055 migrates gap shape/strictness, not this propagation behavior; no matching dedicated item found.

### TC-D01 — Low — Operations page incorrectly says the catalog still uses legacy untyped gaps

- **Evidence:** `docs/operations/job_target_catalog.md:232-234`; actual `src/appsec_review/jobs/job_target_catalog/job.py:882-886`; completed `docs/TODO.md:925-941`.
- **Trigger:** Operator follows the canonical page at this revision.
- **Expected versus actual:** The page says the pinned implementation is not strict-gap migrated and converts legacy unit gaps. The factory has `strict_gaps=True`, typed gap outputs, and typed catalog exceptions; the six shared Wave 5 tests pass.
- **Impact:** Misleading operational interpretation of unit gaps, despite payload/index-identity strings legitimately remaining strings.
- **Confidence:** High, static mismatch plus unit validation.
- **Smallest correction:** Reconcile the prose with T-055, distinguishing raw catalog payload gaps and index identity reason strings from strict unit-level producer-gap records.

## Existing limitations and non-findings

- Fully read `docs/tasks/2026-11-08-job-pass-05-target-catalog.md` and `docs/tasks/2026-11-11-freeciv-walk-05-target-catalog.md`. Previously repaired Postman environment classification/member spans, descriptor read-size gaps, source `data/` artifact collision, Meson lookup parsing, automake conditionals and strict gaps are historical evidence, not new findings here.
- Reviewed relevant TODO entries/references: **T-035**, **T-055**, **T-056**, **T-091**, **T-096**, **T-098–T-101**, **T-111**, **T-113**, **T-147**. No TODO was edited. Deferred non-Node parsers, vendored-library discovery, and the unfinished static build grammar matrix are known scope limits, not newly invented requirements.
- A compile database identity represents a database, not every compilation command. Empty `security_findings` is intentional and never a clean-target assertion.
- Build-action coverage currently becomes complete whenever targets exist, even if discovery gap reasons remain in the shard identity. That difference is observable in code, but this audit did not separately reproduce a consumer misinterpretation and does not add another scored finding.
- Source/symbol/dependency content reads do not locally rehash accepted input like the binary and document readers do. A concurrent mutation/revert scenario and the whole execution host's source-freeze guarantees were not tested; no additional end-to-end integrity failure is claimed.
- The source-index `item_count` counts partition rows even when its scope predicate skips a row. Its mapped test demonstrates that with a supplied-platform synthetic row, but current inventory emits target-source/build-chain roles; no new reachable ordinary-catalog count defect is claimed.

## Focused validation commands and outcomes

Commands were transported, preserving Linux quoting, with:

```powershell
$encoded = [Convert]::ToBase64String(
  [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
  "printf %s $encoded | base64 -d | bash"
```

Each validation script used `set -eu`, `cd /home/wsollers/projects/appsec-review`, exact HEAD/cleanliness guards, and `export PYTHONDONTWRITEBYTECODE=1`. The inspected environment had no inherited `APPSEC_*`, `DAGSTER_HOME`, `PYTEST*`, or other `PYTHON*` selectors. Tests used this checkout's existing `.venv`; nothing was installed.

### A. Complete mapped catalog unit selection

The exact selectors, shown as a Bash array for legibility:

```bash
selectors=(
  tests/test_000_unit_environment_guard.py
  tests/unit/job_target_catalog/test_cataloging_languages.py
  tests/unit/job_target_catalog/test_contract.py
  tests/unit/job_target_catalog/test_descriptor_discovery.py
  tests/unit/job_target_catalog/test_discovery.py
  tests/unit/job_target_catalog/test_documents.py
  tests/unit/job_target_catalog/test_graph.py
  tests/unit/job_target_catalog/test_helpers.py
  tests/unit/job_target_catalog/test_indexes.py
  tests/unit/runtime/test_wave5_contracts.py
)
time .venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-job_target_catalog-collect-20261118 "${selectors[@]}"
time scripts/run-tests.sh --expect-tests 132 --parallel --test-workers 2 \
  --shuffle-seed 20261118 --strict -- "${selectors[@]}"
```

- Collection: **132**, pytest **2.52 s**, shell **4.018 s**, exit 0.
- Execution: **132 passed**, pytest **8.64 s**, wrapper shell **17.069 s**, exit 0.
- Zero failures, skips, xfails, or >10-s tests. Slowest case: `tests/unit/job_target_catalog/test_indexes.py::test_symbol_limit_stops_current_file_and_remaining_files_at_fifty_thousand`, **3.025426 s**.
- Both supervised phases confirmed cleanup and zero remaining processes. Default bounds were not raised: max-tests 200, collection 30 s, total 300 s.
- File counts: languages 2; contract 13; descriptor discovery 2; discovery 31; documents 12; graph 22; helpers 18; indexes 23; shared Wave 5 6; environment guard 3.
- The shared test executes **all fourteen real handlers**, produces actual SQLite shards/manifest and builds strict outcomes from synthetic receipts. It does not launch a runner/Dagster review.

Retained prefix under the authorized checkout:

`test/tmp/tests-custom-20261118-103645-063947-2221926`

Artifacts: `.collection.json`, `.junit.xml`, `.timings.sqlite`; logs in `test/tmp/logs/` with the same basename plus `.log` / `.collection.log`; report in `test/tmp/reports/` with the same basename plus `.json`.

### B. Narrow real document-parser selection

```bash
selectors=(
  tests/test_000_unit_environment_guard.py
  tests/test_target_documents.py::test_northwind_contracts_intent_and_resolving_source_identity
  tests/test_target_documents.py::test_interface_bounds_are_enforced
  tests/test_target_documents.py::test_postman_source_location_parsing_is_bounded
  tests/test_target_documents.py::test_broader_interfaces_are_source_located_declarations
)
time .venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-job_target_catalog-docs-collect-20261118 "${selectors[@]}"
time scripts/run-tests.sh --expect-tests 17 --parallel --test-workers 2 \
  --shuffle-seed 20261118 --strict -- "${selectors[@]}"
```

- Collection: **17**, pytest **2.29 s**, shell **3.720 s**, exit 0.
- Execution: **17 passed**, pytest **4.32 s**, wrapper shell **12.221 s**, exit 0.
- Zero failures, skips, xfails, or >10-s tests; slowest case was the environment guard, **0.374635 s**.
- Retained evidence basename: **`tests-custom-20261118-103917-909594-2234305`**, in the same locations/suffixes as A.
- These 14 parser cases use synthetic documents and repository fixture files, not tools/providers. Their passing bounds checks apply to YAML/Postman, not the defective OpenAPI 3 JSON branch.

The required wrapper owns its unique `tests-custom-*` basetemp and does not use a caller override. Initial collections and reproducers used the requested job-prefixed scratch. No wrapper guard was bypassed; all scratch remained under `test/tmp/`.

### C. Defect reproductions

Executed inline with `.venv/bin/python -` through the same SSH transport. Real transforms and SQLite writers; only synthetic files, no network/tool/provider calls. The first attempt failed at the audit query because it joined nonexistent `locations.identity`; that was a **reproducer error**, not a product test failure. Elapsed **0.507 s**, exit 1, scratch removed by `finally`. Correcting it to the real `locations.entity_id` produced:

```text
TC01: first byte slice "\ndef first():", Last byte slice "s\r\nclass Las"; gaps=[]
TC02: four malformed manifest shapes -> uncaught AttributeError
TC03: pretty=1 operation; compact=0 with unresolved_span;
      max_parse_depth=1/max_parse_nodes=1 -> 1 operation, gaps=[]
TC04: 77067-byte Android Gradle descriptor -> generic/Java target, canonical gaps=[]
TC05: b.py inventory omission -> declarations complete, gap NULL
```

Corrected reproducer: **exit 0**, measured body **0.048549 s**, shell **0.535 s**. These assertions characterize defects; they are not five added passing regression tests.

Exact corrected body:

```python
import json, sqlite3, shutil
from pathlib import Path
from time import perf_counter
from tests.unit.job_target_catalog.support import (
    context, source, partition, handler, PARTITION, COMPONENTS,
    DEPENDENCIES, SYSTEMS, TARGETS, INDEX_UNITS,
)
from appsec_review.indexing.target_documents import collect_target_documents
from appsec_review.jobs.cataloging import inventory, Bounds
base = Path('test/tmp/job-audit-job_target_catalog-repro-20261118').resolve()
assert not base.exists()
base.mkdir(parents=True)
start = perf_counter()
def unit(name, task):
    p = base / name
    p.mkdir()
    return context(p, task)
def query(u, output, sql):
    with sqlite3.connect(u.job.run_root / output['artifact']['path']) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute(sql)]
try:
    u = unit('crlf', INDEX_UNITS[1])
    raw = b'# comment\r\ndef first():\r\n    pass\r\nclass Last:\r\n    pass\r\n'
    entry = source(u, raw=raw)
    u.outputs[PARTITION] = partition([entry])
    result = handler(u.unit_id)(u)
    rows = query(u, result, 'SELECT e.name, e.text, l.start_byte, l.end_byte, l.start_line FROM entities e JOIN locations l ON l.entity_id=e.identity ORDER BY l.start_line')
    for row in rows:
        row['actual_slice'] = raw[row['start_byte']:row['end_byte']].decode()
    assert rows[-1]['start_byte'] != raw.index(b'class Last:')
    assert not result['gaps']
    print('TC01', json.dumps({'rows':rows,'gaps':result['gaps']}))
    failures = []
    for i, payload in enumerate(([], {'dependencies':None}, {'dependencies':['bad']}, {'devDependencies':2})):
        u = unit(f'dep-{i}', DEPENDENCIES)
        entry = source(u, 'package.json', json.dumps(payload).encode(), None)
        u.outputs[COMPONENTS] = {'components':[{'component_id':'component:0001','manifest':'package.json','manifest_sha256':entry['sha256']}]}
        try:
            handler(u.unit_id)(u)
        except AttributeError as exc:
            failures.append({'input':payload,'exception':str(exc)})
        else:
            raise AssertionError('malformed package unexpectedly handled')
    print('TC02', json.dumps(failures))
    u = unit('openapi', INDEX_UNITS[3])
    spec = {'openapi':'3.0.3','info':{'title':'sample','version':'1'},'paths':{'/orders':{'get':{'responses':{'200':{'description':'ok'}}}}}}
    outputs = {}
    for name, content, bounds in (
        ('pretty',json.dumps(spec,indent=2),{}),
        ('compact',json.dumps(spec,separators=(',',':')),{}),
        ('tiny-parser-bounds',json.dumps(spec,indent=2),{'max_parse_depth':1,'max_parse_nodes':1}),
    ):
        entry = source(u, f'{name}.openapi.json', content.encode(), None)
        res = collect_target_documents(u.job.target_root, 'a'*64, [{'path':entry['path'],'sha256':entry['sha256'],'kind':'openapi'}], **bounds)
        outputs[name] = {'record_count':len(res.records),'gaps':res.gaps}
    assert outputs['pretty']['record_count'] == 1 and outputs['compact']['record_count'] == 0
    assert outputs['tiny-parser-bounds']['record_count'] == 1 and not outputs['tiny-parser-bounds']['gaps']
    print('TC03',json.dumps(outputs))
    u = unit('android', SYSTEMS)
    raw = b"plugins { id 'com.android.application' }\nandroid { compileSdk 35 }\n" + b'// padding\n'*7000
    entry = source(u, 'build.gradle', raw, None)
    u.outputs[PARTITION] = partition([entry])
    discovered = handler(SYSTEMS)(u)
    u.outputs[SYSTEMS] = discovered
    u.unit_id = TARGETS
    targets = handler(TARGETS)(u)
    before = discovered['build_units'][0]['descriptor_facts']
    after = targets['targets'][0]
    assert before['kind'] == 'android-gradle-application'
    assert after['project_type'] == 'generic' and after['required_image_profile'] == 'java'
    print('TC04',json.dumps({'descriptor_bytes':len(raw),'discovered':before,'target_type':after['project_type'],'target_profile':after['required_image_profile'],'package_gaps':after['descriptor_package']['gaps'],'canonical_gaps':targets['gaps']}))
    u = unit('omitted', INDEX_UNITS[1])
    source(u, 'a.py', b'def included():\n    pass\n')
    source(u, 'b.py', b'def omitted():\n    pass\n')
    snapshot = inventory(u.job.target_root, Bounds(max_files=1))
    assert [item['path'] for item in snapshot['files']] == ['a.py']
    assert snapshot['gaps'] == [{'path':'b.py','reason':'inventory_bound_reached'}]
    u.outputs[PARTITION] = {**partition(snapshot['files'], snapshot['gaps']), 'inventory_gaps':snapshot['gaps']}
    res = handler(u.unit_id)(u)
    coverage = query(u,res,'SELECT area,status,gap FROM coverage')
    assert res['gaps'] == [] and coverage == [{'area':'declarations','status':'complete','gap':None}]
    print('TC05',json.dumps({'inventory_gaps':snapshot['gaps'],'index_gaps':res['gaps'],'coverage':coverage}))
    print(f'5 defect groups reproduced; Python elapsed {perf_counter()-start:.6f}s; synthetic files/SQLite only, no external calls')
finally:
    shutil.rmtree(base)
```

Additional TC-03 source-binding reproduction: **exit 0**, body **0.000785 s**, shell **0.130 s**:

```python
import json, hashlib, shutil
from pathlib import Path
from time import perf_counter
from appsec_review.indexing.target_documents import collect_target_documents
p = Path('test/tmp/job-audit-job_target_catalog-openapi-span-20261118').resolve()
assert not p.exists()
p.mkdir(parents=True)
start = perf_counter()
try:
    spec = {'openapi':'3.0.3','info':{'title':'sample','version':'1'},'components':{'schemas':{'Example':{'example':{'/orders':{'get':{'description':'example-only'}}}}}},'paths':{'/orders':{'get':{'responses':{'200':{'description':'real'}}}}}}
    text = json.dumps(spec, indent=2)
    raw = text.encode()
    (p / 'openapi.json').write_bytes(raw)
    res = collect_target_documents(p, 'a'*64, [{'path':'openapi.json','sha256':hashlib.sha256(raw).hexdigest(),'kind':'openapi'}])
    [record] = res.records
    paths_line = next(i for i, line in enumerate(text.splitlines(),1) if line.lstrip().startswith('"paths"'))
    assert record['line'] < paths_line and not res.gaps
    print(json.dumps({'TC03_wrong_structural_span':{'record_line':record['line'],'paths_start_line':paths_line,'claimed_fields':record['fields'],'gaps':res.gaps}}))
    print(f'Python elapsed {perf_counter()-start:.6f}s')
finally:
    shutil.rmtree(p)
```

## Read coverage and material limits

**Read fully:** brief; authorized `AGENTS.md`; canonical coordination skill; catalog operations page; the two historical catalog task reports; all three catalog job-package files; `jobs/cataloging.py`, `jobs/build_points.py`, `jobs/engine_discovery.py`, `jobs/delivery_scope.py`; `indexing/target_documents.py`, `indexing/document_interfaces.py`; `retrieval/model.py`; all eight mapped job test files and `support.py`; shared `tests/unit/runtime/test_wave5_contracts.py`; `tests/test_target_documents.py`; `tests/conftest.py`; environment guard; `runtime/selection.py`, `runtime/checkpoints.py`; Python/retrieval and job-input-contract architecture pages; shell wrapper.

**Read relevant ranges/searches:** `jobs/build_discovery.py` lines 1-1281 and 1338-1373 (all discovery, workspace, descriptor packaging and Android/profile paths; downstream recipe execution/validation sections outside these ranges were not audited); exact TOML/test-map entries; config bounds/exclusion matching; runtime scope, registry, topology, units, runner, resume, consume, datasets and handoff; SQLite builder/manifest construction and verification; retrieval coverage/excerpt interfaces; binary-role and shared-object/path helpers; downstream scanner, dependency and planning loaders/profile use; TODO entries/references and recent scoped history.

**Material unread/unexecuted scope:**

- No full runner/publication/admission/reuse/restart cycle, Docker, real compiler/build descriptors executing, model quality, providers, integration tests, acceptance tests or Dagster review. No accepted live catalog output was independently compared to its source.
- The broad build-discovery fixture matrix and standalone extractor suites were **not run**. Shared parser code was read, but this is not a grammar-completeness certification. The matrix remains an explicit T-056 gap.
- Low-level OS races, all storage/admission internals, every payload-schema validator and every downstream consumer were not exhaustively audited. Necessary catalog interfaces were traced; unrelated jobs retain their own audits.
- `engine_contracts` type definitions, low-level ELF/PE/Mach-O subparsers, and all publication-inventory reconciliation implementations were not read in full. No claim of live binary classification or exhaustive schema audit.
- Shard transform tests frequently fake `IndexBuilder`; the shared Wave 5 handler-chain tests and reproducers use real SQLite. No passing mocked transform was substituted for full production publication proof.
- The supplemental legacy document test has verbose automatically generated parameter IDs containing escaped newline text; selectors were deterministic and guarded, but IDs are not as concise as the repository guidance requests. No test file was changed.
- Native WSL `rg` was unavailable in the initial discovery command; subsequent searches used the authorized UNC `rg` tool. This did not redirect the audit to the Windows checkout.

The final root inspection and clean Git check found no repository source changes from this audit. Only retained ignored test evidence and this per-job report remain. **Stop: job_target_catalog only.**
