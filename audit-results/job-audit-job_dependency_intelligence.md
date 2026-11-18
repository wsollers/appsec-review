# Job 21/47 — job_dependency_intelligence

## Verdict and evidence boundary

**Audited revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, clean `main`, `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 via `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`. HEAD and cleanliness were checked before collection, before execution and after the probes. `.venv/bin/python` imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. The Windows default checkout was not audited.

**Nine functional findings: four high, five medium**, plus documentation/test-map drift and separately attributed pre-existing limitations. Findings are source-verified and reproduced with local synthetic inputs or explicitly identified mocked input boundaries; they are not observed production incidents.

**Validation:** 108 focused unit cases passed, no failures/skips/slow cases; pytest **5.12 s**, supervised wrapper **12.578 s**. Three separate offline probe programs completed in **0.603 s**, **0.137 s**, and **0.019 s**. Passing tests do not certify the whole job, live providers, scanners, actual feed quality or downstream review usefulness.

No repository code/configuration/environment edits, installs, commits, network lookups, real scanners/providers, service operations, integration/live reviews or nested agents were performed. Only the requested session report and permitted private test fixtures/results were written.

## Registration, inputs, outputs and dispatch

The job is registered at `src/appsec_review/runtime/registry.py:87,157`; the factory receives the runtime inference boundary. Central TOML declares all eleven tasks (`appsec-review.toml:2628-2729`). It is enabled in the dev recipe, `REVIEW_GRAPH`, `CHECKOUT`, reusable (`always_execute=False`) and propagates its handoff. Its contract has **33 requirements**, including **32 handoff-channel requirements** from five producers and one external `feed_snapshot` requirement. The full declared schedule is catalog, language build, artifact indexing, evidence collection and C/C++ compiled analysis; redundant-edge projection leaves artifact indexing and C/C++ analysis as direct graph predecessors.

Actual input flow:

* Catalog dependency declarations are loaded from `component_discovery.catalog_dependencies`; catalog partition supplies accepted target paths/hashes/sizes. `_target_dependencies` drops the dependency subcatalog's gaps (known D10 below).
* Source Syft observation shards supply flattened package name/version/PURL/repository/first-location context. The exact accepted source Syft JSON is separately retained for SPDX conversion.
* Language receipts supply protected compile/link argv, accepted working-directory mappings, workspace manifests and artifact/loader metadata. Accepted zero receipts are permitted; successful native builds are not a source-discovery precondition.
* Artifact-index publication supplies target-artifact/loader context. The job explicitly gaps unmerged artifact scanner inventories; it does not consume artifact-security SBOMs.
* **C/C++ compiled-analysis datasets are declared/ordered but never read by this job.** No symbol/call-graph join occurs in reachability; it is a bounded source-text heuristic.
* OSV reads its claim-selected immutable external snapshot, checks manifest/index hashes and records external consumption. Native CPE lookup uses the existing cve-bin-tool snapshot verifier, which resolves the current verified snapshot under frozen builder settings. Current-pointer changes versus admitted native-feed pins were not exercised.

All five envelope inputs are declared optional; four are nevertheless required by unconditional handlers (**DI-09**).

There are **18 datasets** (`datasets.py:6-91`): two indexed shards (`dependency_context`, `native_advisory_observations`); protected native input/model/converter material; and artifact-only discovery, curation, metadata, inference metrics/inputs, SPDX, provenance, SBOM metrics, advisory decision, reachability, Scorecard responses, Unity inventory and final handoff. Existing glob tests claim all tested publication shapes exactly once. These declarations are dataset families, not a requirement that every nested JSON file have the family schema.

## Every declared step/task

All eleven configured tasks have actual handlers and explicit dependencies (`job.py:721-751`).

| Declared step/task | Actual implementation and behavior | Result/limit |
|---|---|---|
| `inputs.load_accepted` | `job.py:314-330`, `integration.py:95-284`; four accepted loaders, snapshot/membership checks, protected argv/artifact source records, authenticated target/workspace files, Syft and Unity intake | Returns `SUCCEEDED` with separately retained inherited gaps; optional/required discrepancy DI-09. Does not read declared C/C++ payloads. |
| `resolution.detect_dependencies` | `job.py:332-361`; `discovery.py` interprets bounded argv, paths, artifacts, headers, pkg-config, CMake and documents; claims/evidence/root scope remain separate | Writes bounded discovery and first normalization. Commented macros can become corroborated releases, DI-01. |
| `resolution.curate_components` | `job.py:725-726`, `native_inference_integration.py:96-126`, `curation.py`; bounded detached path-only proposals, exact candidate/path lists, coherent SDK groups, domain-local effective candidates | Originals survive absent/invalid/bounded inference; protects corroborated/conflicted originals. Result, effective discovery and model/metrics manifests published. Model quality not tested. |
| `resolution.investigate_components` | `job.py:727-728`, `investigation.py`; group by domain/root/package root; bounded plan selects only catalog paths; hash-checked byte reads; exact line/quote citations and literal facts; version/PURL/supplier/license/download/upstream claims | Invalid citations remain inferred/gapped. Header literals are checked only after a plan selects files; no-model limitation overlaps T-5050. |
| `resolution.infer_repositories` | `job.py:363-390`, `inference.py`, `resolution.py`; re-normalize investigated candidates; infer only unresolved native repositories; allowed references, host/URL consistency, confidence <= .95, abstention, retries/failure memoization | Model identities explicitly inexact. General normalization identity loss DI-04; pre-existing GitLab namespace defect remains. |
| `repositories.deduplicate` | `job.py:392-399`, `resolution.py:69-101`; canonical repository key, sorted unique groups and dependency fanout | Repository cap gaps each omitted dependency without deleting dependency inventory. |
| `scorecards.fetch` | `job.py:400-463`, `scorecard.py`; verified age-bounded cache then HTTPS transport, request/byte/time/retry limits, response artifacts and typed failure reasons | Context-only signals; not vulnerability findings. Cache/request/repository counts separate. Active execution-safety policy can stop before fallback/retry, by design; not tested live. |
| `publication.publish_sbom` | `job.py:733-735`, `integration.py:346-509`, `sbom.py`, `unity.py`; convert exact accepted Syft through injected/pinned converter; merge native and Unity; official local SPDX schema, reference/field/count/byte validation, provenance and metrics | Integrity/infrastructure exceptions propagate; conversion failure permits partial inventory; invalid SPDX emits no SPDX artifact, `status=FAILED` plus terminal gaps. DI-01 survives into versionInfo. |
| `publication.native_advisory_lookup` | `job.py:465-544`, `native_advisories.py`; native/generic and purl-less versions, all vendor CPE rows, exact/range interpretation, unknown bounds, severity/KEV joins, component/row/match limits | Disabled/unavailable are explicit gaps; findings are leads plus component summaries. Vendor heuristic is known T-5047. Actual native database not opened. |
| `publication.publish_context` | `job.py:546-683`; deduplicate prior gaps, dependency/native/Scorecard inventory, advisory shard manifest; source-text SCA matching and reachability signals | DI-02/03/04/07 affect results. Reachability is computed after fingerprint, DI-08. It always retains `static_reachability_only`, so present implementation normally finishes with gaps, not a clean absence certificate. |
| `acceptance.publish_handoff` | `job.py:685-719`; references upstream hashes, normalized inventory, repositories, Scorecards/counts, raw/effective discovery, inference, Unity, SBOM, advisory/reachability and index manifest | `item_count` is dependencies, `security_findings=[]`; status from aggregate gaps. Accepted reader verifies handoff/manifest and native publication bindings (`job.py:758-778`, `integration.py:512-589`), but downstream field/key contracts disagree, DI-05/06. |

Guidance wiring was traced as data: `guidance/workers.py:40-51` binds `dependency_repository`, `native_curation`, `native_plan`, `native_metadata`; all three task prompt files, both roles and both personas were read. Native plan and metadata share task text but use different closed response schemas. No worker was launched. Runtime skill content was not loaded as repository-agent instructions.

Native bounds are typed (`native_sbom_contracts.py`, `native_inference_contracts.py`); discovery cap accounting is explicit. Inference records immutable request/response/attempt artifacts, served identity, known/unknown usage, retries and result fingerprints. Curation handles usable over-output-cap replies with a named budget gap. Domain gaps remain legacy records, converted by common publication rather than a job-specific `strict_gaps=True` migration.

## Findings

### DI-01 — High — Commented header text becomes a corroborated release and published SPDX version

**Evidence:** `src/appsec_review/jobs/job_dependency_intelligence/discovery.py:438-460,516-572,612-614,870-891`; `sbom.py:564-565`. The comment/continuation masker exists only in later metadata investigation (`investigation.py:253-301,326-331`).

**Trigger/reproduction:** feed an authenticated `vendor/zlib/zlib.h` containing:

```c
/* Historical example only.
#define ZLIB_VERSION "1.2.11"
*/
```

Real `discover_native_dependencies` returns **no gaps** and release `1.2.11`, status `corroborated`. Passing that result through real no-proposer curation, metadata investigation and `build_spdx` produces package `zlib`, `versionInfo: "1.2.11"`.

**Expected/actual:** comments must not establish active release declarations; initial discovery scans raw physical lines and treats known macro names as strong evidence. Later conservative stages preserve the false corroboration.

**Impact:** incorrect inventory version, native advisory candidates and downstream review context from a comment rather than a declaration. **Confidence:** high, reproduced through four real native stages. **Smallest correction:** apply one shared lexical masking/continuation policy before initial header directive parsing, preserving original byte/line evidence; test inactive commented/spliced examples against a real declaration. **Overlap:** related T-5050 header work, but no matching comment-promotion defect found in the searched TODO/prior review.

### DI-02 — High — Imports and unrelated local calls are promoted to vulnerable-symbol reachability

**Evidence:** `reachability.py:635-644,675-715`; source call extraction `:391-401`; prioritization consumes positive states at `job_review_prioritization/composite.py:481-484`.

**Reproduction:** `from danger import parse` with advisory symbol `parse` and **no call** yields `symbol_reachable`, with the import line labeled `symbol_call`. Separately:

```python
import ctypes
z = ctypes.CDLL("libz.so.1")
print("hello")
```

An advisory for generic `z` with no known affected symbol yields `symbol_reachable`; `print` is emitted as a `python_ctypes` FFI boundary.

**Expected/actual:** imports establish at most package/import context; unrelated functions are not calls through the loaded library. The classifier explicitly appends imported symbols to call hits, and with unknown symbols treats almost any call in a file containing a library load as an FFI call.

**Impact:** synthetic vulnerable-symbol sites, inflated reachability counts, stronger prioritization and misleading VEX input. The global static-analysis caveat does not make an incorrect positive call site true. **Confidence:** high, both cases reproduced. **Correction:** distinguish imported declarations from actual calls and resolve receiver/import alias/library provenance; unknown native symbol evidence must remain package-imported/unknown. **Overlap:** T-170 is marked done and covers reachability; this is a residual implementation defect, not a request for unrestricted target execution or a new scanner.

### DI-03 — High — Scanner advisories attach to fixed versions and foreign ecosystems sharing a name

**Evidence:** `reachability.py:764-816`; dependency signal relations are written from the resulting IDs at `job.py:649-667`.

**Reproduction:** dependencies `same@1.0` (npm), `same@2.0` (npm) and `same@1.0` (PyPI), with one scanner observation for `pkg:npm/same@1.0`, produce advisory `dependency_ids=["fixed","foreign","old"]`.

**Expected/actual:** join the scanner's versioned coordinate to matching accepted instances, retaining uncertainty when coordinates are incomplete. `deps_by_name` ignores version/ecosystem; default IDs select every same-name dependency. The advisory merge key itself omits ecosystem/PURL, allowing distinct coordinates to collapse.

**Impact:** an advisory for one installed package is linked to a fixed or unrelated dependency; subsequent provenance and reachability signals misidentify affected subjects. **Confidence:** high, reproduced. **Correction:** use canonical ecosystem/namespace/name/version plus relevant instance identity for joining; preserve an explicit unresolved join rather than guessing by name. **Overlap:** T-099/T-105 and historical review D8 identify general identity weakness; the new SCA name-only fanout is additional concrete evidence.

### DI-04 — Medium — Normalization and OSV name projection discard usable package coordinates

**Evidence:** `resolution.py:227-272`; `reachability.py:530-562`; `native_advisories.py:123-136`.

**Reproduction:** a dependency `{name:"same", version:"1.0.0", ecosystem:"npm", direct:false}` matches one miniature pinned OSV advisory before normalization. After the real normalizer, matching returns zero plus `osv_dependency_identity_incomplete`; `ecosystem` and `direct` disappeared, and `_is_direct_dependency` now returns true. A Maven PURL `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` with display name `log4j-core` is projected as OSV name `log4j-core`, not `org.apache.logging.log4j:log4j-core`.

**Expected/actual:** retain supported structured identity/scope fields and derive ecosystem-specific full names from PURLs, not only a display name/last segment. The tests pass hand-authored richer dependencies directly to reachability, bypassing this producer projection.

**Impact:** avoidable OSV misses and loss of transitive-only semantics; purl-less managed rows can also enter the native CPE path. **Confidence:** high for reproduced loss; the exact production frequency is unmeasured. **Correction:** preserve provenance-bearing ecosystem/directness/version-kind fields and reuse an ecosystem-aware coordinate decoder with conflict checks. **Overlap:** partly pre-existing D8/T-099; T-170 exposes the additional OSV/directness consequence. Do not count the general normalizer defect as wholly new.

### DI-05 — High — Accepted dependency output crashes the OpenVEX companion on the wrong task key

**Evidence:** producer `job.py:712-719,743-748`; consumer `src/appsec_review/jobs/job_openvex_export/dependencies.py:31`; invoked during OpenVEX load at `job_openvex_export/job.py:129-130`. `_accepted` preserves the decoded output map (`job_openvex_export/inputs.py:263-300`).

**Reproduction:** supplying an accepted handoff boundary with this job's actual `outputs["acceptance.publish_handoff"]` and matching resolved-config hash to real `dependency_projection` raises **`KeyError: 'publication.publish_handoff'`**, before it can read the reachability document.

**Expected/actual:** consume `acceptance.publish_handoff`; consumer indexes a nonexistent `publication.publish_handoff`.

**Impact:** with an accepted dependency handoff present, the enabled OpenVEX companion cannot pass its load phase even if the dependency output itself is valid. **Confidence:** high; exact-key failure reproduced with only accepted-input retrieval mocked. **Correction:** use the actual producer key (ideally its loader/contract) and add a producer-shaped handoff regression. **Overlap:** no identical TODO/prior report found; related T-170/T-171 downstream delivery. This is a compatibility finding for the OpenVEX owner, not a separate audit of that job.

### DI-06 — Medium — Other consumers use field names the SCA producer never emits

**Evidence:** producer `reachability.py:904-921` and `job.py:630-647`; consumer `retrieval/core.py:2087-2093`, `job_review_prioritization/composite.py:470-473,502-515`.

**Reproduction:** a real inventory shard containing this producer's `reachability:"symbol_reachable"` returns one row for `query_sca_reachability(package="danger")`, but **zero** with `reachability_class="symbol_reachable"`. The query reads `reachability_class`, not `reachability`. Feeding the real generated FFI document to `_load_sca_reachability` produces package `unknown-package` and non-FFI attack class: it reads `package` and top-level `ffi_boundaries`, while the document emits `package_name` and per-advisory `ffi_mechanisms`/`call_sites`.

**Expected/actual:** query/filter/promote the fields specified by `sca-reachability/1`. Filters silently lose real results, while prioritization loses package identity and FFI labeling.

**Impact:** unusable filtered retrieval and degraded/colliding review leads. **Confidence:** high, reproduced with real retrieval and mocked accepted JSON boundary for prioritization. **Correction:** align readers with the schema and test real producer payloads, not synthetic alternate field names. **Overlap:** T-170/T-171/T-172 themes; no matching dedicated item found. Avoid double-counting when these consumers receive their own audits.

### DI-07 — Medium — An internal 32-entry symbol cap silently loses call sites and ignores the configured cap

**Evidence:** `reachability.py:391-401`, final truncation detection `:894-902`.

**Reproduction:** 40 lines of `danger.parse(x)` after `import danger`, with `max_call_sites_per_advisory=64`, publish only **16 unique call sites**, with **no truncation gap**. Every member call is inserted by both regexes, filling the fixed 32-entry bucket before deduplication. Final code only checks whether the already-truncated result exceeds the configured limit.

**Expected/actual:** honor the configured bound and name every omission. Silent pre-cap duplication/truncation drops later evidence even when the configured allowance is sufficient.

**Impact:** incomplete reachability locations and misleading coverage/bound accounting. **Confidence:** high, reproduced. **Correction:** deduplicate before cap, derive collection bounds from settings, and retain an explicit omitted count/gap. **Overlap:** T-170 bounds/testing; no matching TODO found.

### DI-08 — Medium — Inventory fingerprint excludes the reachability output and its OSV snapshot

**Evidence:** `job.py:560-574` fingerprints dependencies, Scorecards, prior gaps, native advisory artifact and SBOM, **before** computing SCA at `:606-620`; SCA entities enter that shard at `:630-667`; immutable build occurs at `:671`. `retrieval/index.py:231-249` correctly rejects conflicting named shard bytes.

**Reproduction:** call the real `publication.publish_context` handler twice with identical upstream/native/Scorecard/SBOM outputs and different injected, verified miniature OSV snapshots (one matching advisory, then none). Only unrelated native-evidence indexing and scanner-input retrieval are mocked. First publication has one advisory and fingerprint `70c4ecabb5dd46c504a7305a0a15ef41c087ebfb7f89b28796781dc56fbbdb7e`; second fails **`immutable index shard conflicts with existing bytes: inventory/dependency-intelligence`**.

**Expected/actual:** externally changed SCA input/result must affect the content-derived shard path. Instead it changes entities/gaps without changing the fingerprint. A whole rerun may incidentally change another upstream artifact path/hash; that is not a reliable identity for this output.

**Impact:** bounded recomputation/resume can collide instead of publishing its new SCA evidence. **Confidence:** high at this real handler boundary; whole-run reuse/admission sequence was not executed. **Correction:** compute SCA before fingerprinting and bind its result hash, snapshot identity and effective settings/comparator identity. **Overlap:** no exact prior item found; T-105 input/version identity and T-170 SCA wiring are related.

### DI-09 — Medium — Required loader reads disagree with optional input declarations

**Evidence:** `datasets.py:102-173` uses default availability; `runtime/contracts.py:60` defaults to `OPTIONAL`. `job.py:159-170,314-320` and `integration.py:101-107` unconditionally require four envelopes.

**Reproduction:** real `inputs.load_accepted` on an empty private run raises **`UpstreamIntegrityError: accepted job_target_catalog handoff is required`**. The five declared handoff availabilities are all `"optional"`.

**Expected/actual:** contract admission should truthfully require the four prerequisites, or the handler should implement missing-policy gaps. Current declarations promise optional/gap behavior but runtime discovers missing prerequisites as task failure.

**Impact:** disabled/absent prerequisite combinations are admitted under the wrong availability semantics and then fail instead of producing the declared outcome. **Confidence:** high for loader/declaration mismatch; full runner admission was not executed. **Correction:** make genuinely required envelope/dataset declarations required in accord with the existing native-SBOM architecture; keep genuinely unused C/C++ inputs separate. **Overlap:** related shared input-contract repairs; no exact dependency-intelligence item found.

## Existing limitations reconfirmed, not newly discovered

| Prior item | Current evidence/result |
|---|---|
| Historical dependency review **D8**, **T-099** | `resolution.py:227-272` still groups purl-less names without ecosystem and uses first nonempty repository/version. Reversing two same-name/version npm/PyPI rows changes the chosen repository while emitting one row and no gap. DI-04 attributes the added OSV consequence rather than relabeling D8 new. |
| Historical **D9**, **T-099** | `repository_identity`, `resolution.py:60-67`, still turns `https://gitlab.com/group/subgroup/project` into `https://gitlab.com/group/subgroup`; reproduced. Forge namespace correction is already in T-099 scope. |
| Historical **D1/D2**, **T-099/T-105** | `integration.py:212-218` explicitly names unmerged artifact inventories; `publish_sbom` does not consume normalized declarations. Unity enriches SPDX only (`unity.py`), while normalized dependencies are declared/source-Syft/native. Indexed inventory and SPDX are not equivalent populations. No new claim that artifact-only packages were tested. |
| Historical **D10**, **T-099** | `_target_dependencies` returns dependencies and hash only (`job.py:165-173`); catalog's dependency-parser/delivery gaps (`job_target_catalog/job.py:460-481`) are not propagated through this path. Partition/build/artifact/Syft gaps are inherited separately. |
| **T-5050** | Metadata investigation returns before reading header facts if no plan/proposer exists (`investigation.py:624-625`); generic PURL derivation is in `apply`, not a universal deterministic final pass. |
| **T-5075** | Command-local native roots and target link names are still candidate inputs (`discovery.py:325,411-436`); no first-party-output exclusion or universal pre-curation collapse was added. Exact host run's candidate counts were not inspected. |
| **T-5047/T-5049** | Vendor confidence is heuristic; product rows are read before per-component evaluation caps (`native_advisories.py:246-260,335-356`). No real database timing was measured. T-5048's downstream NVD-first enrichment issue was read, not independently reproduced. |
| **T-5022/T-5032** | Repository-resolution retry/allowlist repair tests pass; explicit native advisory lead/non-lead tests also pass. Do not describe the older missing-lead-decision report as necessarily current. Model efficacy remains unverified. |

The historical review used `592617...`; it is context, not proof at this revision. Relevant local history includes `3c76b820e` (T-170/T-171), `94d46b107` (over-cap curation), `34cb847f9` (run-owned curation paths), and `c8ce3e507` (consumer dataset declarations).

### Documentation and test-map drift (low)

* `docs/operations/dependency-intelligence.md`'s ordered publication list omits `native_advisory_lookup`; its focused command still names absent `tests/test_dependency_intelligence.py`. Current files are below `tests/unit/job_dependency_intelligence/`.
* `tests/job-test-map.json:252-267` omits existing `test_sca_reachability.py` and `test_consumers_declare_every_dataset.py`; the canonical generated operation page repeats that incomplete selection. Thirteen SCA cases were explicitly added to this audit's selection, not silently assumed absent.
* T-170's completed scope says artifact/debug-symbol/code-graph joins; this implementation reads text, not those graphs. Current operations prose correctly limits it to static import/call matching. Preserve that limitation rather than implying verified executable reachability.
* Generic exact task/applicability documentation gaps remain T-147/T-157; they are not evidence of a missing handler.

## Validation record

### Safety/fixture inspection

Read the complete selected test modules before execution. Model functions use fake `Infer`; Scorecard functions use injected transports; native advisory tests use miniature SQLite databases and injected snapshot resolvers; SCA uses local `publish_snapshot` fixtures and hash-bound local files. The selected converter test replaces `ContainerExecutor` before its successful tool path. Three safe exact nodes were selected from `test_job_graph.py`; **the full graph tests were not run**, because their default native advisory resolver can consult the host feed instead of an injected fixture.

Unit-environment preflight used `tests.test_000_unit_environment_guard.offending_environment(os.environ)` and rejected ambient `PYTEST_ADDOPTS`. The wrapper also performs the guard before xdist workers. Source/import identity checks are listed above.

### Commands actually executed

All Linux commands below ran from `/home/wsollers/projects/appsec-review` through the brief's base64-over-SSH transport, not through the Windows checkout:

```bash
.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-dependency-collect-20261118-01 \
  tests/unit/job_dependency_intelligence/test_contract.py \
  tests/unit/job_dependency_intelligence/test_datasets.py \
  tests/unit/job_dependency_intelligence/test_dependency_intelligence.py \
  tests/unit/job_dependency_intelligence/test_native_advisories.py \
  tests/unit/job_dependency_intelligence/test_sca_reachability.py \
  tests/unit/job_dependency_intelligence/test_job_graph.py::test_validate_config_rejects_invalid_settings \
  tests/unit/job_dependency_intelligence/test_job_graph.py::test_safe_read_and_upstream_helper_error_branches \
  tests/unit/job_dependency_intelligence/test_job_graph.py::test_convert_syft_and_integration_validation_branches
```

**Result:** 108 collected, **1.44 s**, exit 0. One `PytestConfigWarning: Unknown config option: cache_dir` because cacheprovider was disabled for this collection. No tests executed in this command.

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 21047 \
  --max-tests 108 --expect-tests 108 --timeout-seconds 180 -- \
  tests/unit/job_dependency_intelligence/test_contract.py \
  tests/unit/job_dependency_intelligence/test_datasets.py \
  tests/unit/job_dependency_intelligence/test_dependency_intelligence.py \
  tests/unit/job_dependency_intelligence/test_native_advisories.py \
  tests/unit/job_dependency_intelligence/test_sca_reachability.py \
  tests/unit/job_dependency_intelligence/test_job_graph.py::test_validate_config_rejects_invalid_settings \
  tests/unit/job_dependency_intelligence/test_job_graph.py::test_safe_read_and_upstream_helper_error_branches \
  tests/unit/job_dependency_intelligence/test_job_graph.py::test_convert_syft_and_integration_validation_branches
```

**Result:** 108 passed, **5.12 s pytest / 12.578133314 s wrapper**, two workers, exit 0; failures 0, skips 0, cases >10 s 0. Wrapper collection and execution both completed with process cleanup confirmed. Its fresh unique base temp was `test/tmp/tests-custom-20261118-123547-838138-2922313`, with permitted sequential collection/execution reuse.

Retained evidence, relative to the WSL checkout:

* `test/tmp/logs/tests-custom-20261118-123547-838138-2922313.log`
* `test/tmp/logs/tests-custom-20261118-123547-838138-2922313.collection.log`
* `test/tmp/tests-custom-20261118-123547-838138-2922313.junit.xml`
* `test/tmp/tests-custom-20261118-123547-838138-2922313.timings.sqlite`
* `test/tmp/tests-custom-20261118-123547-838138-2922313.collection.json`
* `test/tmp/reports/tests-custom-20261118-123547-838138-2922313.json`

After recording the probe outcomes, only this auditor's two probe fixture directories and initial collection scratch/host-pins were removed. Unit validation logs, reports, JUnit and timing evidence were retained. Final `git diff --check` and `git status --short` were clean at the same exact HEAD.

### Offline probes and reproduction recipe

Three `.venv/bin/python - <<'PY' ... PY` programs were transported over SSH:

1. **Identity/joins/reachability/consumer program — 0.603 s, exit 0.** Used private `test/tmp/job-audit-dependency-probes-20261118-01`; local fixture helpers `_build_osv_sqlite`/`_pin` from `test_sca_reachability`; no host feeds. Asserted all DI-02/03/04/05/06/07 outputs described above and both historical normalizer/GitLab outputs.
2. **Publication/optional-input program — 0.137 s, exit 0.** Used private `test/tmp/job-audit-dependency-publication-20261118-01`; two miniature OSV snapshots, real `publication.publish_context` handler and `IndexBuilder`. Mocked only `_index_native_evidence` (unrelated native subsystem) and `_evidence_advisories` (accepted scanner boundary). Asserted DI-08 immutable conflict and printed DI-09 required-read error versus declared optional availabilities.
3. **Commented-header native pipeline program — 0.019 s, exit 0.** Entirely in memory except the existing local official schema read. No model or executable fixture code. Exact core reproduction:

```python
import hashlib
from appsec_review.jobs.job_dependency_intelligence.discovery import discover_native_dependencies
from appsec_review.jobs.job_dependency_intelligence.curation import curate_native_components
from appsec_review.jobs.job_dependency_intelligence.investigation import investigate_native_metadata
from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import NativeInferenceBounds
from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import NativeBounds, SbomBounds
from appsec_review.jobs.job_dependency_intelligence.sbom import build_spdx

raw = b'/* Historical example only.\n#define ZLIB_VERSION "1.2.11"\n*/\n'
ref = {"path": "accepted-partition.json", "sha256": "a"*64, "size_bytes": 1}
file = {"domain": "target", "root_id": "target", "path": "vendor/zlib/zlib.h",
        "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
        "upstream": ref, "backing": None}
discovery = discover_native_dependencies(
    source_fingerprint="f"*64, files=[file], invocations=[], artifacts=[],
    read_file=lambda r,n: raw,
    bounds=NativeBounds(10,64,10,4096,4096,10,100,32,4096,512))
curated = curate_native_components(
    discovery, [file], propose=None, bounds=NativeInferenceBounds())
investigated = investigate_native_metadata(
    curated["discovery"], [file], read_file=lambda r,n: raw,
    propose=None, bounds=NativeInferenceBounds())
spdx = build_spdx(
    source_fingerprint="f"*64, created="2026-11-18T00:00:00Z", baselines=[],
    discovery=investigated["discovery"], input_identities=[ref],
    bounds=SbomBounds(65536,100,262144,16384))
assert discovery["gaps"] == []
assert discovery["candidates"][0]["release"]["status"] == "corroborated"
assert spdx["document"]["packages"][0]["versionInfo"] == "1.2.11"
```

For the other programs, the smallest reproduction inputs and calls are:

```python
# DI-02/07: write only these inert fixtures under a new test/tmp/<unique>/target;
# pass {path, sha256, size_bytes} records to evaluate_sca_reachability.
unused = "from danger import parse\n"
ffi = 'import ctypes\nz = ctypes.CDLL("libz.so.1")\nprint("hello")\n'
many = "import danger\n" + "danger.parse(x)\n"*40
# scanner_advisories respectively:
{"advisory":"CVE-2026-1002","package":"danger","affected_symbols":["parse"]}
{"advisory":"CVE-2026-1003","package":"z","purl":"pkg:generic/z@1.0"}
{"advisory":"CVE-2026-1004","package":"danger","affected_symbols":["parse"]}
# Settings: osv_version_matching="disabled"; max_call_sites_per_advisory=64 for many.
# Results: symbol_reachable at unused import; symbol_reachable at print; only 16 sites.

# DI-03: dependencies old/fixed/foreign:
{"dependency_id":"old","name":"same","version":"1.0","purl":"pkg:npm/same@1.0"}
{"dependency_id":"fixed","name":"same","version":"2.0","purl":"pkg:npm/same@2.0"}
{"dependency_id":"foreign","name":"same","version":"1.0","purl":"pkg:pypi/same@1.0"}
# One scanner_advisory: advisory CVE-2026-1001, package same, version 1.0,
# purl pkg:npm/same@1.0. evaluate_sca_reachability -> all three dependency_ids.

# DI-04: _build_osv_sqlite with
{"id":"ADV-SAME","affected":[{"package":{"ecosystem":"npm","name":"same"},
                            "versions":["1.0.0"]}]}
# _pin a fresh local feed. evaluate with
{"dependency_id":"dep","name":"same","version":"1.0.0","ecosystem":"npm","direct":False}
# then with normalize_dependencies([row], [], [], supported_hosts=("github.com",),
#                                  max_dependencies=10)[0].
# Results: one advisory before / zero after; normalized directness defaults true.

# DI-05: patch only dependencies._accepted to a SimpleNamespace with
{"resolved_config_sha256":"a"*64,
 "outputs":{"acceptance.publish_handoff":{"sca_reachability":{
   "path":"sca.json","sha256":"b"*64,"size_bytes":1}}}}
# verified.provenance.resolved_config_sha256="a"*64;
# dependency_projection(run, verified, OpenVexExportSettings(), repo, "audit")
# -> KeyError('publication.publish_handoff').

# DI-06: IndexBuilder: inventory/dependency-intelligence, producer job_dependency_intelligence.
# Add EntityKind.REVIEW_SIGNAL payload {"signal_kind":"sca_reachability", **unused_advisory}.
# Write/verify manifest; RetrievalCore(..., manifest_path=manifest).
# query_sca_reachability(package="danger") -> 1;
# query_sca_reachability(package="danger", reachability_class="symbol_reachable") -> 0.
# _load_sca_reachability with has_handoff=True, accepted_handoff pointing to actual
# acceptance.publish_handoff.sca_reachability, read_json returning the real FFI document
# -> unknown-package / vulnerable_dependency_reachability.
```

DI-08 setup used a minimal `UnitContext` with identical dependencies, empty discovery/curation/investigation/repository/Scorecard gaps, empty Scorecards, no native observations, one fixed native-advisory decision reference, fixed `sbom.input_fingerprint="b"*64`, no SPDX artifact, no target and no source files. `build_job(osv_snapshot=pin)` supplies the two real verified local pins, containing an explicit `sample@1.0.0` npm match and then an empty advisory database. Both calls used one run with separate task directories. This isolates the fingerprint rather than pretending to validate complete admitted execution.

A report-metadata inspection initially failed from PowerShell/SSH quoting (`SyntaxError: unterminated string literal`), then was corrected using the prescribed base64 transport. One initial skill glob used backslashes in a glob pattern and found nothing; the corrected glob listed the skills. A search for an as-yet nonexistent third-party-sync audit report failed explicitly; no such report was used as evidence. None of these were test failures or changed source.

## Read scope and material unverified gaps

**Read fully:** shared brief, authorized `AGENTS.md` and coordination skill; both dependency operation pages; historical `2026-11-13-dependency-intelligence-review.md`; `job-input-contracts.md`; **all 19 Python modules directly inside `src/appsec_review/jobs/job_dependency_intelligence/`**, including the complete discovery/curation/investigation/SPDX algorithms; all three native task prompts, two roles, two personas; SCA JSON schema; selected test modules `test_contract`, `test_datasets`, `test_dependency_intelligence`, `test_native_advisories`, `test_sca_reachability`, `test_job_graph`; unit-environment guard; `job_openvex_export/dependencies.py`.

**Sampled/narrow symbol reads:** TOML job settings/tasks; registry/topology/guidance mappings; runtime contracts/inputs/job declaration; native architecture lines 1-230; shared retrieval index/core and prioritization SCA readers; accepted OpenVEX input reader/load wiring; catalog dependency producer and Syft parser; cve-bin-tool consumer verifier/publication/feed-provenance; wrapper/test harness; relevant TODO sections and prior current-session reports by dependency/symptom search.

**Material unread/unexecuted scope:**

* Other per-job unit files (native curation/discovery/inference runtime/wiring/metadata/SPDX metrics/SPDX/Unity edge suites) were not run; only the specified direct probes exercise additional native stages. Some names/matches were inspected, not full tests. The consumer-declaration test was not executed.
* The packaged official SPDX schema is hash-verified by real validation exercised here, but its entire resource text was not manually read. Other runtime-control schemas/shared validators and all possible downstream consumers were not exhaustively re-audited.
* The imported `load_accepted_language_build` and `load_accepted_artifact_index` helper internals were not fully read; their call sites and this job's additional nested membership/snapshot/input reconciliation were read. Their complete transitive custody behavior remains a named shared-helper gap.
* No full `JobRunner`/Dagster finalization, admission/read-receipt/reuse sequence, actual accepted whole-job handoff or end-to-end VEX/report publication was executed. DI-05/06 consumer checks use controlled accepted boundaries; DI-08 isolates publication with controlled upstream outputs.
* No live model/guidance efficacy, real Syft conversion, Scorecard HTTPS behavior/cache freshness, native scanner output, production OSV/NVD/cve-bin-tool contents, binary reachability, real call graphs, patched-fork applicability or final target finding quality was verified.
* Runtime skill bodies were not loaded; worker-bound registry/task/role/persona assembly paths were traced. No historical run or private answer key was used.

The report completes this job's bounded functional audit, not a claim that every possible input or the system is correct. Stop after job 21; the coordinator owns cumulative attribution and follow-up.
