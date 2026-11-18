# Job 15/47 — job_debug_symbol_indexing

## Scope and result

- **Audited source:** clean `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`; branch `main`, exact revision **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**. HEAD and clean `git status --short` were verified before and after validation. The editable installation resolves to this checkout's `src/appsec_review/__init__.py`. The Windows checkout was not audited.
- **Result:** **four medium functional findings reproduced**, plus one already tracked, conditional build-outcome defect. All four declared tasks were traced.
- **Focused tests:** **357 passed**, zero failures/skips/over-10-second cases in executed selections; **20.59 seconds summed pytest elapsed**. The 195-case wrapper took **22.989 seconds total**, including its collection and supervision. Two offline reproduction invocations took **0.5612 s** and **0.1198 s** after imports.
- **Limits:** no source/environment modifications, installations, real LLVM/compiler/container/provider execution, target execution, service operations, integration/acceptance/live reviews, or nested agents. Tests used at most two workers and isolated base directories. Passing units do not certify live reader output.

Evidence paths below are repository-relative. `job.py` in findings means `src/appsec_review/jobs/job_debug_symbol_indexing/job.py`.

## Registration, configuration, and contracts

The factory is registered at `src/appsec_review/runtime/registry.py:81,151`. The job and default reader are enabled in `appsec-review.toml:1561-1589`; the four units are built at `job.py:729-757`. The authoritative contract is `src/appsec_review/jobs/job_debug_symbol_indexing/datasets.py:40-79`: review-graph dispatch, checkout target access, handoff propagation, not always-execute, scheduled after artifact indexing. `orchestration/topology.py:48-83` derives enabled graph dependencies from the contracts; the project-build graph also explicitly inserts it after artifact indexing (`orchestration/dagster/adapter.py:498-506`). Disabled graph behavior was exercised by definition-only unit tests, not a Dagster run.

### Declared/admitted inputs

All eleven requirements are optional/gap, handoff-channel producer evidence permitting partial coverage:

| Producer | Declared datasets | Actual use |
|---|---|---|
| `job_artifact_indexing` | `handoff`; `artifact_catalog`; `archive_members`; `artifact_relationships`; `artifact_index_summary` | Real accepted loader resolves the admitted handoff, verifies summary and composite manifest. `_accepted_inputs` reads only `artifacts`/`catalog-*` shards for native candidates and retains upstream gaps/manifest/handoff hash (`job.py:111-183`). Member/relationship shards are carried forward, not separately mined for symbols. |
| `job_language_build` | `handoff`; `topology_refinement_inputs`; `build_actions`; `jvm_build_actions`; `language_build_receipts`; `build_workspaces` | When admitted, checks source fingerprint and its handoff hash against artifact-index provenance; associates qualifying receipt artifacts with exact image ID/user (`job.py:126-145`). It does not independently analyze JVM actions/topology. See known T-5039 below. |
| **Undeclared source producer** | No `job_target_catalog/source_files` or other source-shard producer requirement | `_Sources` reads source shards carried in the composite manifest and binds their bytes/checksums (`job.py:274-402`). This is actual evidence use, not just manifest forwarding: **DS-F01**. |

Envelope resolution uses `runtime.consume.accepted_upstream`, not a direct unverified `latest.json` read. The active scope requires a typed envelope and exact supplied digest (`runtime/consume.py:168-212`). However, the job's direct SQLite paths do not invoke the typed shard observation boundary. Availability, composite-manifest inclusion, and content verification do not replace dataset admission/read observations.

### Every declared step/task

| Step/task | Actual handler and processing | Output/validation and limits |
|---|---|---|
| `decide.target` | `_decision`, `job.py:186-201`, invokes `_accepted_inputs`; freezes compiler target, selected lane, settings, reader identity, upstream/artifact hashes, optional build images and production execution plan. | `decision.json`, `/debug-symbol-decision/2`, canonical input fingerprint. `_read_decision` rechecks bytes, settings, source, lane and execution plan on every later task (`:204-222`). Config validates exact step/task order (`:680-686`). No model. |
| `extract.clang_dwarf` | `_extract`, `:484-640`, selected for `clang`; probes accepted references, first tries embedded DWARF, then cataloged companions. Real reader dispatch is `debug_symbols/readers.py:147-237`. | Nonselected lane exits before probing with domain `SKIPPED`, terminal `SKIPPED_NA`, no index. Selected lane verifies input bytes before/after reader; emits normalized shard, coverage/raw refs. DWARF line ownership mismatch **DS-F02**; lookup-bound failure **DS-F03**. |
| `extract.msvc_pdb` | Same handler with `msvc`; pairs PE RSDS GUID/age with accepted MSF PDB before export; parses PDB YAML and native inline annotations. | Same normalized contract and explicit skipped counterpart. Empty/missing/ambiguous companions are gaps, not successful empty symbol coverage. Mixed-PDB public symbols are dropped: **DS-F04**. Source-range query mismatch also affects this lane. |
| `acceptance.publish_handoff` | `_publish`, `:643-678`, requires selected indexes and deliberately skipped other lane; removes prior `debug_symbols`, retains other upstream shards, writes/verifies composite manifest. | `accepted-index.json` binds decision/raw evidence/artifact handoff/fingerprint/counts/gaps/manifest. Item count is normalized records, not binaries. No bespoke job/unit output validator; normal shared control validation plus domain dataclasses/index validation apply. Full runtime finalization was not executed. |

There are no model/persona/prompt/runtime-skill dispatches in this job. Generated “Undeclared” tool-binding cells are existing **T-147**, not proof of nonexecution.

### Transforms, bounds, and counts

- **Binary identity:** ELF class/endian/section bounds, embedded `.debug_info` or `.zdebug_info`, verified build-ID/debug-link CRC for companions; no filename-only pairing. PE section mapping and RSDS GUID/age, MSF information-stream identity, and repeated YAML identity checks precede records (`debug_symbols/_reader_binary.py`, `_reader_pdb.py:80-101`). No recorded path is opened.
- **Native transforms:** DWARF DIE/line-table parsing yields functions/signatures, type/member metadata, inline ancestry, compilation units and half-open link-address ranges. PDB maps segment/offset/length to RVAs; native DBI/CodeView inline annotation ranges are cross-checked against YAML parents/end/procedure identities. Source-line/end-address ordering and inline interval containment are checked. Unsupported format/location families remain named gaps.
- **Normalization:** identities bind target snapshot, compiler target, accepted artifact identity, record kind, and a fingerprint of binary SHA/debug SHA/native key (`job.py:405-433`). Binary/debug evidence and receipt references remain on rows. Duplicate native keys fail; missing parents are gaps. `DERIVED_FROM`, `OBSERVED_AT`, and lexical `CONTAINS` relations do not assert call/taint edges.
- **Source authority:** checksum algorithms are SHA-256/MD5, not path-only assertions; source identity derives from accepted path/hash. Shared object bytes, verified generated backing or exact reconstructed SQLite text must match. CR/LF/CRLF offsets and line/column bounds are checked. Resolution is capped at min(reader input bound, 16 MiB); source inventory uses `max_records`; line-offset/cache memory is bounded. Truncated inventory is not separately named as an inventory-limit reason (see remaining limits).
- **Privacy:** raw records and recorded paths stay protected; path-like normalized fields are hashed, and verified source paths enter location rows only after checksum binding. Deliberate variable-location gaps do not justify losing known public names.
- **Settings:** closed parser `config/debug_symbols.py:11-46`: defaults 128 artifacts; 512 MiB/input; 16 MiB/export/normalized extraction; 100,000 records; depth 128; timeout 120 s. Upper bounds: 4096 artifacts, 4 GiB/input, 256 MiB/output, 1,000,000 records, depth 256, timeout 1800 s. Unknown/tool-path settings and wrong types are rejected. Compiler target is injected at launch, not accepted in job settings (`config/loader.py:1461-1466`).
- **Extraction totals:** record/output caps are checked before accepting an artifact; artifact count counts non-debug subjects, decision artifact count includes debug companions. `max_artifacts` also includes companions, despite operator prose calling it “candidate binaries.” Record totals are the emitted normalized entities. Coverage is complete/partial/unavailable per artifact, with unavailable `native-artifacts` coverage when there is no binary.
- **Production reader:** `debug_symbols/execution.py` binds frozen resolved config/host pins, release, catalog policy and exact image/user. Build image is tried first; only unavailable/incompatible image or missing tool permits compatibility fallback. Launcher staging/retained output is verified; reads use file-backed bounded exports. `ContainerExecutor` puts `execution.json` and `raw/*` under the supplied scratch directory (`container_runtime/executor.py:262-265,360-394`), inside the declared protected glob. These are static traces, not verified container executions.
- **Reuse:** frozen decision and reader/execution plan enter identity; production output fingerprint additionally includes execution receipts, avoiding aliases to an earlier attempt's evidence (`job.py:616-623`). Missing release disallows reuse in the execution plan. Unit tests cover frozen host identity and identical injected-reader repeat behavior; full runtime resume was not run.

### Publication and downstream compatibility

| Dataset | Actual shape/location | Result |
|---|---|---|
| `normalized_symbols` | `debug_symbols` SQLite `/retrieval-index/2`, `symbols-clang_dwarf` or `symbols-msvc_pdb`; artifact/family/source/parent facets and unsigned interval lookup | Prefix/index declaration matches. Producer now uses `producer["job"]`; historic defect underlying T-164 is fixed here. |
| `symbol_coverage` | attempt `artifacts/debug-symbols/coverage.json`, `/debug-symbol-coverage/1` | Matching glob/schema, also represented in SQLite. |
| `target_decision` | same directory `decision.json`, `/debug-symbol-decision/2` | Matching declaration; T-114 is fixed, not re-reported. |
| `raw_artifact_refs` | `raw-refs.json`, `/debug-symbol-inputs/1` | Protected; contains raw reader records, binary/debug references and execution references. |
| `reader_executions` | `executions/**`, `/container-execution/1` logical family | Protected receipts plus raw binary/text streams; the family declaration does not mean each stream is a JSON receipt. Production glob fit traced, not run. |
| `debug_symbol_summary` | `accepted-index.json`, `/debug-symbol-indexing/1` | Counts, source/decision/reader/manifests bound as described above. |

The accepted loader (`job.py:689-726`) checks summary handoff membership, bytes/schema, reader evidence and retained execution/output/diagnostic hashes, decision fingerprint/target/source/lane, and manifest binding/integrity. It has no direct `observe_output` call; this is another manifestation of the observation limitation in DS-F01, not another finding.

Downstream declaration searches found normalized-symbol/coverage/decision/raw/execution/summary inputs in review-data indexing, review-package assembly, inference review, OWASP, CodeQL, document analysis and security tagging. Their decision schemas agree at `/2`; no consumer schema mismatch was found. The actual shared query implementation was read completely: closed modes/subjects, exact artifact address scoping, max 100 rows, query-bound cursor, response/time limits, and full unsigned 64-bit half-open address lookup. The producer's line hierarchy does not satisfy two admitted query forms (DS-F02). All downstream job implementations were not re-audited.

Legacy reason strings remain intentional `strict_gaps=False`; `runtime/handoff.py:121-143` projects them to canonical producer-reported gaps, not inferred retryability. Extraction and acceptance repeat causes in separate units; summing those is not a unique-cause count.

## Findings

### DS-F01 — Medium — Source evidence is read outside the typed dataset contract and omitted from read receipts

- **Evidence:** `job.py:150-160,287-316,334-336,405-425`; `datasets.py:44-72`; enforcement boundary `runtime/inputs.py:474-500`; `retrieval/index.py:391-528` verifies manifests/custody but does not call `observe_shard`.
- **Trigger:** an artifact composite manifest includes a `source` shard from `job_target_catalog` (the normal upstream source-index producer), and a symbol source checksum matches one of its files.
- **Expected:** the source producer/dataset must be declared and supplied; the actual catalog/source reads must produce typed shard observations, distinct from envelope reads and integrity verification.
- **Actual:** `_Sources` directly opens every source shard in the manifest with SQLite, reads/reconstructs source bytes, and emits checksum-verified mappings. No source-producer input is declared and no typed observation is emitted. The analogous direct catalog SQLite path also omits `artifact_catalog` read observations.
- **Reproduction:** a real source shard labelled `producer.job=job_target_catalog`, real manifest, real `_Sources`, and real `input_read_scope` using the actual debug job contract and only an artifact-index pin resolved `src/main.cc` successfully. `reads.document()["reads"]` was **`[]`**; exiting the scope succeeded.
- **Impact:** typed supply/read accounting can say “unread,” or omit source authority entirely, while source evidence is used for exact locations. Content hashing and named shared custody still apply; this finding does **not** claim unchecked bytes.
- **Confidence:** high, reproduced. **Smallest correction:** declare the actual source producers/datasets required by this path, use admitted source projections, and observe each actually read shard/output. Add a real scoped read test, including rejection when the source pin is absent.
- **Overlap:** same general observation class as prior **PB-F04**/planner payload-observation findings, but a distinct debug-symbol source-shard manifestation. **T-054** is a completed earlier missing-input repair for other jobs; **T-164** is producer-key enforcement, not a fix here. No exact open TODO found for this path.

### DS-F02 — Medium — Valid source-range queries by function (and DWARF compilation unit) return no existing line records

- **Evidence:** allowed subject kinds and direct-child query in `retrieval/debug_symbols.py:23,229-242`; DWARF line record creation `_reader_dwarf.py:172-178` has no parent; PDB source ranges use only module parent `_reader_pdb.py:360-364`.
- **Trigger:** query `mode="source_ranges"` with the exact normalized function identity. For DWARF, the exact compilation-unit identity has the same problem.
- **Expected:** an admitted query form should retrieve that subject's existing source ranges, using evidence-backed unit/address relationships; or be explicitly unsupported rather than accepted as a working form.
- **Actual/reproduction:** genuine captured tiny fixtures went through real extraction, normalization, publication and `RetrievalCore`. Clang published **18 records / 11 source-range rows**, but `entry` returned **0** and compilation unit **0**. MSVC published **6 records / 2 source-range rows**, but `entry` returned **0** (its module correctly returned 2). Artifact-wide queries returned the rows.
- **Impact:** subject-scoped consumers cannot find already indexed line mappings; widening to artifact-wide scope is not a replacement for a functioning subject query.
- **Confidence:** high, reproduced for both lanes. **Smallest correction:** bind line records to their verified compilation unit and support function-range intersection/ownership in bounded queries, retaining ambiguity where overlaps prevent a unique owner. Test real producer output, not only handcrafted query rows.
- **Overlap:** no matching TODO found. T-169's future alternate graph synthesis is not this existing query mismatch.

### DS-F03 — Medium — Valid fragmented records exceed an unhandled index-only bound and abort the entire extraction

- **Evidence:** reader normalizes range lists in `_reader_dwarf.py:254-265`; job checks only record totals/serialized bytes at `job.py:561-571`, then unguarded `builder.build()` at `:624`; `retrieval/debug_symbol_index.py:81-93` rejects >500 ranges, >4096 lookup prefixes/record or >2,000,000 lookup rows/shard.
- **Trigger:** otherwise valid record with 501 half-open ranges, within configured input/output/depth/record limits.
- **Expected:** bounded extraction/normalization should report a named coverage limit and preserve unrelated valid work, per documented coverage-failure semantics.
- **Actual/reproduction:** real `parse_dwarf` accepted a fixture-shaped 501-interval function, returning 18 records without a bound reason. Real `_extract` with the valid 501-interval record raised **`ValueError: debug-symbol address range count exceeds the normalized record bound`** at SQLite construction; **no coverage.json was written**.
- **Impact:** one highly fragmented function or inline record can prevent all artifacts' selected-lane publication instead of producing a scoped unavailable/partial result. This is boundedness handling, not a recommendation to enlarge the limit.
- **Confidence:** high, reproduced with controlled reader output. **Smallest correction:** apply the downstream range/expansion bounds before committing a record/artifact to the builder and record precise gaps; retain all existing bounds.
- **Overlap:** no exact TODO found. Existing lookup-bound unit tests only assert the builder rejection, not the producer's required gap behavior.

### DS-F04 — Medium — Mixed PDBs silently omit public symbols whenever any private function exists

- **Evidence:** `_reader_pdb.py:370-385` iterates the entire `PublicsStream` only if **no** `RecordKind.SYMBOL` has already been emitted. Real fixture `tests/fixtures/debug_symbols/msvc-inline.pdb.yaml:331-345` contains `entry` and `global_pair`.
- **Trigger:** a PDB contains at least one private procedure plus another public-only symbol.
- **Expected:** preserve public names/RVAs absent from private records, without inventing size/signature or duplicating an already represented symbol.
- **Actual/reproduction:** the genuine MSVC fixture lists public `entry` and `global_pair`, but normalized symbols contain only `entry`. Adding a valid public-only **function** to its in-memory YAML likewise produces only `entry`. The generic `public_symbols_have_no_lengths_or_signatures` gap does not state that these names were discarded.
- **Impact:** incomplete symbol inventory and understated record counts; downstream symbol enumeration cannot discover those known names. `variable_locations_not_indexed` concerns locations, not justification for discarding public identities, and the function variant demonstrates this is not limited to globals.
- **Confidence:** high, reproduced. **Smallest correction:** merge unrepresented public records using native identity/address evidence, retaining their public-only limitations and never inferring a range from the next symbol.
- **Overlap:** no exact matching TODO found.

## Existing defects, documentation drift, and unproven limits

1. **T-5039, already open — build-outcome/image association.** `job.py:135` ignores `COMPLETED_WITH_GAPS` receipts even with `build_outcome="built"`, losing exact build-image association. Isolated `_accepted_inputs` reproduction returned `build_image=None` for such a receipt. **Do not count this as a new discovery or as an established current end-to-end fallback:** artifact indexing currently rejects a non-SUCCEEDED receipt carrying artifacts (`job_artifact_indexing/job.py:429-436`), so an upstream repair/admitted such receipt is needed to reach this exact downstream branch. Use `build_succeeded` for product existence without admitting rejected artifacts.
2. **T-114 fixed:** decision declaration and output both `/2`; regression passes. **T-164:** this producer now emits `producer["job"]`; remaining general enforcement TODO remains open.
3. **T-113:** mapped whole-job/fake-engine/genuine-fixture integration tests are historically documented as stale or admission-failing (`docs/TODO.md:3651-3659`). They were not executed and no current failure count is asserted.
4. **T-147:** missing declarative task/tool binding metadata remains; source inspection identified the real LLVM path.
5. **Low documentation drift:** `docs/operations/debug-symbol-indexing.md:89-91` describes 128 candidate binaries, but the limit bounds binaries **plus debug companions** (`job.py:149-177`). `tests/fixtures/debug_symbols/README.md:133-155` still describes host-tool pins/subprocess as production, whereas production uses the container exporter; its host runner remains a test seam.
6. **Unproven/incomplete scope, not additional verified defects:** array element/dimension fidelity is not established by the struct-oriented fixtures; `_Sources` silently omits inventory rows beyond its row cap and later emits generic checksum-unverified reasons; checksum-bearing line rows do not imply checksum-bearing DWARF function declaration locations. No native corpus/scale test established practical frequency or completeness of these limitations.

## Focused validation — exact commands and outcomes

All commands ran from `/home/wsollers/projects/appsec-review` via the SSH/base64 transport in the audit brief, using that checkout's `.venv`. Environment inspection returned `unit environment offences: []` and no `PYTEST_ADDOPTS`, `APPSEC_HOST_PINS`, or `PYTHONPATH` overrides. The parallel preflight also ran the repository's production-environment guard.

### Collection

```sh
.venv/bin/python -m pytest --collect-only -q -o addopts= \
  -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-debug-symbol-20261118-collection \
  tests/unit/job_debug_symbol_indexing
```

**Exit 0; 195 collected in 1.60 s.** No tests executed. One `PytestConfigWarning: Unknown config option: cache_dir` was caused by explicitly disabling pytest's cache plugin, not by source/test failure.

### Job-unit wrapper

Initial invocation appended `-p no:cacheprovider` after the following selector array; wrapper refused it with **exit 2**, `unsupported focused pytest option '-p'`, before collection/execution. Nothing failed in the job. Corrected invocation:

```sh
mapfile -t tests < <(
  find tests/unit/job_debug_symbol_indexing -maxdepth 1 -name 'test_*.py' -print | sort
)
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 151118 \
  --max-tests 195 --expect-tests 195 --strict -- "${tests[@]}"
```

The exact 15-file selector array was:

```text
tests/unit/job_debug_symbol_indexing/test_accepted_inputs.py
tests/unit/job_debug_symbol_indexing/test_accepted_loader.py
tests/unit/job_debug_symbol_indexing/test_contract.py
tests/unit/job_debug_symbol_indexing/test_decision.py
tests/unit/job_debug_symbol_indexing/test_extract.py
tests/unit/job_debug_symbol_indexing/test_host_bindings.py
tests/unit/job_debug_symbol_indexing/test_job_graph.py
tests/unit/job_debug_symbol_indexing/test_metrics.py
tests/unit/job_debug_symbol_indexing/test_normalize.py
tests/unit/job_debug_symbol_indexing/test_probe_and_privacy.py
tests/unit/job_debug_symbol_indexing/test_publish.py
tests/unit/job_debug_symbol_indexing/test_settings.py
tests/unit/job_debug_symbol_indexing/test_source_bounds.py
tests/unit/job_debug_symbol_indexing/test_sources.py
tests/unit/job_debug_symbol_indexing/test_workflow.py
```

**Exit 0; 195 passed in 14.01 s; 0 failures/skips; 0 cases over 10 s.** Wrapper total **22.989311884972267 s**; collection subprocess **3.669452415080741 s**, execution subprocess **18.876695899059996 s**. Cleanup confirmed no remaining processes.

Wrapper-owned basename: `tests-custom-20261118-121511-136394-2766603`. Collection and execution used its unique `test/tmp/<basename>` base, two workers only for execution, identical guarded selectors/counts. Evidence retained:

- `test/tmp/reports/tests-custom-20261118-121511-136394-2766603.json` — complete emitted commands and stage timings.
- `test/tmp/logs/tests-custom-20261118-121511-136394-2766603.log`
- `test/tmp/tests-custom-20261118-121511-136394-2766603.junit.xml`
- `test/tmp/tests-custom-20261118-121511-136394-2766603.timings.sqlite`
- Wrapper command/output copies: `test/tmp/job-audit-debug-symbol-20261118-unit-wrapper.log` (refusal) and `...-unit-wrapper-retry.log` (success).

### Captured reader and downstream retrieval units

```sh
.venv/bin/python -m pytest -q -o addopts= \
  -o cache_dir=test/tmp/job-audit-debug-symbol-20261118-reader-cache \
  --basetemp=test/tmp/job-audit-debug-symbol-20261118-readers \
  -n 2 --shuffle-seed=151119 tests/test_debug_symbol_readers.py \
  -k 'not test_bounded_subprocess_runner_is_real'

.venv/bin/python -m pytest -q -o addopts= \
  -o cache_dir=test/tmp/job-audit-debug-symbol-20261118-retrieval-cache \
  --basetemp=test/tmp/job-audit-debug-symbol-20261118-retrieval \
  -n 2 --shuffle-seed=151120 tests/test_debug_symbol_retrieval.py
```

These ran **sequentially**, never four auditor-owned workers simultaneously.

- Readers: **exit 0; 93 passed in 3.02 s**, shell elapsed 7 s; zero skips/failures/slow cases. The real subprocess-runner test was deliberately excluded, not counted as a pass or skip. Fixtures' binary bytes and captured exports were inspected/parsed, never executed.
- Retrieval: **exit 0; 69 passed in 3.56 s**, shell elapsed 8 s; zero skips/failures/slow cases. Synthetic SQLite/index/capability fixtures only.
- Logs: `test/tmp/job-audit-debug-symbol-20261118-readers.log`, `...-retrieval.log`; timing databases have the respective base names plus `.timings.sqlite`.
- Shared `tests/unit/runtime/test_wave1a_contracts.py` was **not run**: inspected fixture setup drives `JobRunner` publication/admission, beyond this audit's chosen safe handler-only scope. No integration/live mapping was run.

### Offline reproductions

Executed `.venv/bin/python - <<'PY' ... PY` via SSH, using a fresh owned `test/tmp/job-audit-debug-symbol-20261118-repro` directory. Real functions and genuine captured fixtures were used; only external/accepted-loader boundaries were faked with process-local `pytest.MonkeyPatch`. No repository file was changed.

Exact exercised sequences and observed outputs:

```text
R1:
  support.source_shard(..., b"int x;\n"), replace its producer with job_target_catalog;
  real CONTRACT + input_read_scope with only job_artifact_indexing supplied;
  _Sources(...).resolve(SourceSpan("src/main.cc", 1, 0, sha256(bytes), "sha256"))
  => bound="src/main.cc", gap=None, read_receipts=[]

R2, per clang tiny.elf/tiny.dwarf.txt and msvc tiny.exe/tiny.pdb/tiny.pdb.yaml:
  extract_symbols(..., exporter=callback returning the captured export)
  => real binary/pairing checks and real parse.
  support job_context/artifact/catalog_shard/source_shard + fake accepted-input loader;
  real decide.target, both extract handlers, acceptance.publish_handoff;
  RetrievalCore over resulting composite manifest; query source_ranges by artifact,
  by normalized entry identity, and by normalized compilation-unit identity.
  => clang: 18 records; artifact rows=11; entry rows=0; unit rows=0
  => msvc:   6 records; artifact rows=2;  entry rows=0; unit rows=2

R3:
  Extraction((SymbolRecord("f", SYMBOL, "f",
    tuple(AddressRange(2*i, 2*i+1) for i in range(501))),))
  => real _extract raises "debug-symbol address range count exceeds the normalized record bound";
     coverage_written=false.

R4:
  real parse_pdb(msvc-inline.pdb.yaml, pe(msvc-inline.exe), native_pdb=msvc-inline.pdb)
  => public_names=["entry", "global_pair"]; normalized_symbol_names=["entry"]
     gaps=["optimized_debug_information", "public_symbols_have_no_lengths_or_signatures",
           "signature_parameter_names_unavailable", "source_paths_unverified",
           "variable_locations_not_indexed"]

R5 (known/conditional):
  real _accepted_inputs, loader-returned valid catalog + receipt with
  build_outcome="built", terminal_status="COMPLETED_WITH_GAPS",
  image={"image_id":"sha256:"+"d"*64,"user":"10001:10001"}, accepted artifact
  => selected_build_image=null
```

**Main reproduction invocation: exit 0; 0.5612 s measured after imports.** All assertions confirming the listed behavior passed; these are demonstrations of defects, not tests certifying expected behavior.

Supplemental invocation (no files written):

```text
R3 stronger:
  Replace the single entry DW_AT_high_pc(0x40102f) in the captured tiny DWARF text
  with DW_AT_ranges containing 501 intervals [0x401000+2*i, 0x401001+2*i).
  real parse_dwarf(max_records=10000,max_depth=128)
  => 18 records, entry.ranges length=501, no parser-bound reason.

R4 stronger:
  _document(msvc-inline.pdb.yaml); append PublicsStream S_PUB32:
  {Flags:[Function],Segment:1,Offset:16,Name:public_only_function};
  yaml.safe_dump(explicit_start=True,explicit_end=True); real parse_pdb
  => normalized symbol names still ["entry"].
```

**Supplement: exit 0; 0.1198 s measured.** These controlled export variants are not represented as genuine additional compiler outputs.

## Read coverage and material gaps

**Fully read:**

- Authorized `AGENTS.md`, canonical multi-session coordination skill, complete updated audit brief.
- `docs/operations/job_debug_symbol_indexing.md`, `docs/operations/debug-symbol-indexing.md`, `docs/architecture/debug-symbol-indexing.md`.
- Entire job `job.py`, `datasets.py`; `config/debug_symbols.py`; `debug_symbols/contract.py`, `readers.py`, `execution.py`, `_container_export.py`, `_reader_binary.py`, `_reader_dwarf.py`, `_reader_pdb.py`, `_reader_codeview.py`.
- `retrieval/debug_symbol_index.py`, `retrieval/debug_symbols.py`, `observability/debug_symbols.py`.
- All fifteen `tests/unit/job_debug_symbol_indexing/test_*.py` files and `support.py`; `tests/test_debug_symbol_readers.py`; `tests/test_debug_symbol_retrieval.py`; `tests/conftest.py`; environment-guard test file; fixture README.
- `jobs/build_outcome.py`; `scripts/run-tests.sh` and `scripts/lib/common.sh`.

**Relevant ranges/searches read:**

- TOML registration/settings/release; loader compiler-target wiring; runtime registry; topology dependency functions; Dagster project graph insertion.
- Artifact-index accepted loader, receipt success guard, composite publication; language-build imports/contracts; target-catalog source-shard emission.
- Runtime input scopes/observations/admission, consume resolver, handoff artifact/gap projection, unit control validation, dataset declaration model; index construction/manifest integrity and shared named-custody functions.
- Container receipt placement and isolation command construction; generated-source resolution branch locations (not full implementation); downstream input declarations and matrix wiring.
- Test map's debug job block; wrapper selection/command/supervision/report options; `test_wave1a_contracts.py:1-180`.
- Genuine tiny/inline/MSVC fixture text excerpts, plus full exports and binary bytes processed by the bounded readers in tests/reproductions. These are recorded fixtures, not independent current tool observations.
- TODO entries/searches T-054, T-113, T-114, T-147, T-164, T-169 and T-5039; historical implementation report search results; prior cumulative/project-build/language-build/source audit report matches. Local job history and branches inspected without fetching/changing them.

**Unread/unexecuted material scope:**

- No full container runtime/image build/signing/native launcher validation; no production `ContainerExporter` execution. Its fake-engine and end-to-end integration suites were not run. Real LLVM 18/MSVC record variants, platform compatibility, timeouts, filesystem-custody behavior and actual image provenance remain unverified.
- No live target corpus, independent native-reader comparison, large/fragmented production binary measurement, acceptance inventory or review quality certification.
- Generated-source backing resolution was traced only at the call boundary; full generated/multi-shard provenance, all source-encoding/checksum variants and full runtime dataset observations/publication/resume were not proven.
- No independent audit of downstream jobs' complete behavior; their declared schemas and shared symbol retrieval path were inspected.
- Parser fixtures cover representative functions/structs/inline cases, not every supported DWARF2–5/CodeView type/location/array form. Known LLVM `S_REGREL32` exporter crash remains a documented live limitation, not repaired or exercised.
- All declared tasks were read; omitted scope is shared runtime/native/corpus depth, not an unexamined declared lane.

Only this session report was added. Test logs/receipts/timings remain under the owned `test/tmp` paths for review; source stayed clean at the required revision. **Stopped after this job.**
