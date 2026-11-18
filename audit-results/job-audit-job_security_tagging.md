# Job 32/47 — job_security_tagging

## Scope and verdict

- Audited clean WSL checkout `/home/wsollers/projects/appsec-review`, branch `main`, exact revision `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`. HEAD, clean status and editable import were checked before testing and HEAD/clean status again afterward.
- Read-only functional audit. No repository edits, installation, service operation, target execution, real provider/model/tool invocation, integration/live run, or subagent. The Windows default checkout was not audited.
- **Seven functional defects:** six medium, one low; additionally one low-severity stale unit-test assertion. Reproducers exercised real classification/validation functions with in-memory accepted-index, transport or admission doubles.
- Focused suite: **215 passed, 1 failed, 0 skipped, no tests over 10 seconds; pytest 9.50 seconds**. The failure is the stale direct-edge topology expectation below, not evidence of lost transitive inputs.
- This does not certify real-run tag quality, complete retrieval authorization, or live model behavior.

## Registration, contract, activation

`runtime/registry.py:171` wires `build_security_tagging(infer=infer)`. The job has twelve units in seven steps, `REVIEW_GRAPH` dispatch, checkout access, `always_execute=False`, and propagated handoffs. Dev enables it; job workers are 4, collection workers 3, publication workers 2, with individual tasks defaulting to one. Audit tests used only two workers.

The authoritative contract has **128 input declarations from 24 producers**, not 128 guaranteed reads. All are optional/gap except the two native-advisory declarations that use `WHEN_DECLARED`/`NOT_APPLICABLE`. Scheduling names CodeQL, prioritization and code graph; the reduced graph has direct predecessors `job_code_graph_index` and `job_binary_evidence_indexing`. Dependency intelligence, profile data and test coverage remain transitive ancestors.

### Accepted inputs and actual use

| Input group | Actual processing |
|---|---|
| Target catalog source files, components, documents, build units and catalog material | `AcceptedIndexes` verifies the claimed manifest; component rows establish project/component ownership; source rows establish language/path facts; source bytes feed collation; interface document rows feed component mechanisms. Other catalog artifacts are declarations, not independently parsed inputs here. |
| Code graph facts | Only `entry_point`/`sink_site` rows become invoked capabilities. The reader revalidates graph schema, family/native identity, admissibility, exact source span, source hash, language mapping and component agreement. Other graph families are not directly classified. |
| CodeQL, static evidence collection, CI, artifact security and other observation producers | Only `observations`/`tool_observation` rows are matched. CodeQL CWE tags, CERT rule IDs, Gitleaks credentials, configured advisory producers, Syft package capabilities and nine CI rule mappings are supported. Unmapped non-inventory observations receive `gap:crosswalk-unmapped`, not guessed findings. |
| Language build / compiled build material | Collation reads `build_action` rows looking for `build_points` (ST-02). Coverage collection reads selected index coverage tables, including `build`, `compiled`, `build_security`, `artifacts` and `analysis`. |
| Binary indexing, debug symbols, artifact catalog, CPG, Clang, SVF, tree-sitter | These are declared accepted inputs, but the job does not directly scan `binary`, symbol or arbitrary analysis entities to derive tags. Eligible consolidated graph facts may incorporate these producers; selected coverage families are read. Binary pseudo-C in the `binary` index is not itself a collation source file. |
| Change context, history, profile data, test coverage, priority items and dependency-intelligence engineering data | Declared and eligible for manifest propagation, but no dedicated classifier consumes their engineering rows. Native advisory observations lacking a configured producer mapping become unmapped gap tags. This is a bounded implemented capability, not proof that every declared input contributes tags. |

The read boundary is `producers.py:73-113` → `runtime/inputs.py:474-501`: opening a shard observes its actual producer/dataset read and verifies its bytes. Manifest selection uses `retrieval/core.py:112-125`; normal runtime contexts use claim pins. The standalone fixture fallback uses the accepted pointer. Ownership is deepest root, exact manifest, then ecosystem, retaining shared/ambiguous/unowned states (`jobs/component_ownership.py:24-56`).

## Every declared step/task

All handlers below are in `src/appsec_review/jobs/job_security_tagging/job.py`.

| Step/task | Implementation and output | Result / limit |
|---|---|---|
| `taxonomy.load_taxonomy` | Lines 263-272; hash-check vocabulary, capabilities and crosswalk; write taxonomy identity | Real parsers/pins covered; proposed namespaces remain unusable. |
| `scope.resolve_inputs` | Lines 274-292; verified manifest, target fingerprint, bounded components and topology/ownership hash | Real scope and identity drift tests pass. |
| `collection.source_facts` | Lines 294-303; declared language/path facts plus eligible invoked graph sites | Bounded reads; exact graph source and ownership checks tested. Source-only language/path rows are not graph claims. |
| `collection.observation_facts` | Lines 305-309; producer/rule/extractor mappings | Declared package versus reported scanner bases retained; CWE/CERT normalization and CI correlation tested. |
| `collection.coverage_gaps` | Lines 311-314; selected shard coverage and absent source/observations/components | Gap tags plus missing-index notes. No claim that absent tags prove absence. |
| `collation.collate_facets` | Lines 316-331; dispositions, lexical/path rules, capability→facet, facet fixed point, component rollup/classes | ST-01, ST-02, ST-03 and ST-07. Writes `facet-facts.json`, `collation.json`. |
| `collation.model_pass` | Lines 333-356; default disabled record; optionally specialized worker per selected component | ST-04, ST-05, ST-06, ST-07. Deterministic artifacts are separate, but later units depend on this unit succeeding. |
| `crosswalk.apply_crosswalk` | Lines 358-390; one-hop observed assignments grouped by same subject/component/project/CI job | Derived inputs are excluded; matched source IDs retained; fixture catalogs add `gap:catalog-fixture`. |
| `integrity.validate_assignments` | Lines 392-409; merge, reconstruct identity/basis, check derived references/evidence, count | Does not validate semantic classifier correctness or exact lexical UTF-16 coordinates. |
| `publication.publish_index` | Lines 411-426 and 193-258; content-addressed family/facets shards, subject and derivation edges, combined verified manifest | Real synthetic index publication and reuse pass; not a live admission test. |
| `publication.publish_tag_cloud` | Lines 428-433; distinct subjects/components, strongest basis, lens and rollup-gap views | Raw hits do not inflate subject/component counts; unowned states have distinct buckets. |
| `publication.publish_handoff` | Lines 435-458; artifacts, counts, gap tags, own and aggregate gaps, empty findings | Always has standing limitations; normally `COMPLETED_WITH_GAPS`, not clean-target certification. |

## Findings

### ST-01 — Medium: the declared mobile target rule cannot see its inputs

- **Evidence:** `src/appsec_review/jobs/job_security_tagging/collation.py:145-160,341-356`; `data/reference/taxonomy/capability-rules.json:579-580`.
- **Trigger:** a valid component capability `component:android-mobile`, `component:ios-mobile` or `func:mobile:*`, with first-party source.
- **Expected:** `target-mobile` evaluates those capabilities and derives `target:mobile` with their assignment IDs.
- **Actual:** capabilities are stored in `component_inputs`, but only matching facet-rule outputs enter component `records`. `_target_class` examines only those records; there is no mobile facet rule or lexical mobile capability emitter. Consequently the mobile target predicate is unreachable with the shipped rules. A supplied valid Android component tag plus Java authentication source produced **`target:library`**, not mobile.
- **Impact:** target-class routing can exclude MASVS despite an admitted mobile capability. The downstream gate requires mobile (`owasp_workbench/engine.py:47,337-358`).
- **Confidence:** high for the unreachable rule; no real Android/iOS run was attempted.
- **Smallest correction:** evaluate target rules against appropriate retained component capabilities as well as facets, preserving their derivation IDs and existing ownership restrictions.
- **Overlap:** T-5008 explicitly promises this target class. T-007 covers broader mobile support; that deferred platform work does not repair this existing rule-input disconnect.

### ST-02 — Medium: build classification reads a payload shape the actual producers never publish

- **Evidence:** `src/appsec_review/jobs/job_security_tagging/collation.py:269-287,378-387`; `src/appsec_review/jobs/job_language_build/job.py:1792-1823`; `src/appsec_review/jobs/job_language_build/jvm.py:609-645`.
- **Trigger:** accepted language-build index containing real `build_action` command rows and `library` or `executable` artifact entities.
- **Expected:** build evidence distinguishes libraries from executables and can substantiate library classification.
- **Actual:** the collector selects only `build_action` and expects `payload.build_points[].kind/sources`. Language-build publishes command fields there and artifact kinds in separate entities; JVM likewise publishes command/invocation/task fields, not `build_points`. The collector silently returns no build kinds and falls back to absence. Canned rows matching each real publication shape yielded identical **`build_point_kinds=[]`, `target:library`** for a library and an executable containing a crypto include.
- **Impact:** build evidence cannot confirm or correct component class; executables without a recognized lexical entry mechanism can be labeled libraries. The existing positive test fabricates the missing `build_points` field.
- **Confidence:** high static producer/consumer mismatch, reproduced against bounded real-shape reader inputs; no build executed.
- **Smallest correction:** read the actually published artifact/build-unit relationships or add an explicit accepted normalized build-point dataset; distinguish unavailable classification evidence from available command rows, and cite the build evidence used.
- **Overlap:** T-5008, T-056 are related feature/test work; neither inspected entry records this payload mismatch.

### ST-03 — Medium: document facets survive the “no first-party files” exclusion

- **Evidence:** `src/appsec_review/jobs/job_security_tagging/collation.py:290-308,314-334,427-429`.
- **Trigger:** a component has only disposition-excluded files and an accepted interface document.
- **Expected:** the component gets no facet or target class, as both code's gap and architecture state.
- **Actual:** `_document_facts` first appends component assignments; the subsequent no-files branch appends an empty summary and continues without removing them. Final flattening publishes those assignments. A vendored-only Python component with an OpenAPI document produced **summary facets `[]`, file count 0, but a published `mechanism:http` assignment**.
- **Impact:** summary and tag shards disagree; excluded components can route as network/API components. Document paths themselves are not disposition-filtered either.
- **Confidence:** high, reproduced.
- **Smallest correction:** select eligible first-party components before adding document facets, or discard their pre-collected records on exclusion; make summary and assignments use the same eligible set.
- **Overlap:** T-5008 and T-165. This is distinct from T-165's deferred catalog-fact disposition inference.

### ST-04 — Medium: malformed JSON values escape model rejection and fail the job

- **Evidence:** `src/appsec_review/jobs/job_security_tagging/model_pass.py:119-143,236-246`; `src/appsec_review/jobs/job_security_tagging/job.py:467-482`.
- **Trigger:** enabled model pass returns otherwise valid JSON with `unknown:[{}]`, a list-valued claim tag/path, or a list-valued assignment citation.
- **Expected:** closed-schema rejection and a named gap, leaving deterministic publication usable.
- **Actual:** set construction/membership raises `TypeError` before `ProposalRejected`. `_failures()` does not catch it. Four direct validator probes raised unhashable-type errors; the **real model-pass handler** also propagated `TypeError` for `unknown:[{}]`. The upstream JSON parser accepts schema-bearing objects without checking nested value types (`inference/claude_cli.py:47-63`).
- **Impact:** optional model output blocks crosswalk, integrity and publication rather than producing a rejection record. Default-off deployments are unaffected.
- **Confidence:** high, handler reproduced with scripted transport.
- **Smallest correction:** type-check every nested value before membership/hash operations and reject malformed citations/unknown entries using `ProposalRejected`; do not mask arbitrary implementation errors.
- **Overlap:** T-5008 owns the model pass. No inspected prior tagging report or TODO names this nested-value failure.

### ST-05 — Medium: actual inference failure policy contradicts the optional-pass gap behavior

- **Evidence:** `src/appsec_review/jobs/job_security_tagging/model_pass.py:38-43,231-246`; `src/appsec_review/inference/__init__.py:46-62`; `src/appsec_review/runtime/execution_safety.py:32,329-338,361-384`.
- **Trigger:** optional pass is enabled under active run admission, and the provider raises a normal `ProviderError` or equivalent transport failure.
- **Expected:** per documented model-pass contract, record a named failure gap and retain deterministic publication.
- **Actual:** the real inference operation converts the provider exception to **`ReviewStopped`**, calls the admission failure latch, and escapes the model-pass catch list. The passing provider-failure test replaces the entire inference transport, so it never sees this policy boundary.
- **Repro:** real `inference.infer` with an in-memory provider that raises and an in-memory admission client produced `ReviewStopped`, `caught_by_model_pass=False`, calls `['admit','failure','finish']`. No real provider or admission service was contacted.
- **Impact:** enabling an optional classifier can stop the entire review on a transport failure instead of degrading only the optional result.
- **Confidence:** high for this boundary interaction; not live-validated.
- **Smallest correction:** reconcile the declared optional-error contract with inference admission policy at the operation boundary. If optional errors are meant to be nonfatal, classify them before spending the stop latch; **never swallow `ReviewStopped` or bypass an already-latched stop**. If fail-stop is intentional, correct the job's gap promise and test that actual contract.
- **Overlap:** T-5008; shared execution-safety policy may affect other jobs, which this audit does not assess.

### ST-06 — Medium: empty/excluded components spend the first-party model budget

- **Evidence:** `src/appsec_review/jobs/job_security_tagging/model_pass.py:190-201`; `src/appsec_review/config/collation.py:29-32`.
- **Trigger:** `max_components=1`, an empty/disposition-excluded component sorts before a component with first-party files.
- **Expected:** the one allowed first-party component receives the call.
- **Actual:** slicing occurs before resolving subject/first-party paths. The empty component is skipped, while the eligible component receives `model_pass_bound`; **zero calls** are made.
- **Impact:** configured model capacity is lost to ineligible components; enough earlier vendor-only components can starve all eligible components. The existing edge-case test asserts this current behavior instead of eligible-component budgeting.
- **Confidence:** high, reproduced with scripted transport.
- **Smallest correction:** determine and record ineligible components first, then apply `max_components` to the eligible sequence.
- **Overlap:** T-5008 and first-party scope T-165.

### ST-07 — Low: lexical/model evidence columns count code points rather than UTF-16 units

- **Evidence:** `src/appsec_review/jobs/job_security_tagging/collation.py:198-201`; `src/appsec_review/jobs/job_security_tagging/model_pass.py:260-263`; expected convention in `src/appsec_review/graph/crosscheck.py:102-118`.
- **Trigger:** a matched/cited line contains a non-BMP character before its end.
- **Expected:** declared byte span and SARIF/LSP UTF-16 columns identify the same text.
- **Actual:** both paths use `len(text)+1`. For `import jwt # 😀x`, collation emits end column **16**, which resolves to byte **17**, while its declared end byte is **18**. Whole-file identity/basis validation does not catch this disagreement.
- **Impact:** exact-location consumers get inconsistent spans, although line-level browsing still works.
- **Confidence:** high for deterministic reproduction; the identical model projection was statically checked, not separately run.
- **Smallest correction:** reuse the canonical UTF-16 coordinate conversion when creating lexical/model locations.
- **Overlap:** T-5008; no exact overlap found.

### ST-08 — Low, test defect: direct-parent assertion rejects valid transitive scheduling

- **Evidence:** `tests/orchestration/dagster/test_security_tagging.py:26-32`; `src/appsec_review/orchestration/topology.py:79-81,90-106`.
- **Trigger:** current contract-derived graph with transitive-reduced edges.
- **Actual test failure:** demands direct finalizer edges from dependency intelligence, profile data and test coverage. Only graph and binary finalizers are direct predecessors; all three demanded jobs remain in the transitive closure and their handoffs propagate.
- **Impact:** focused job suite remains red despite this scheduling path preserving its required ancestors.
- **Confidence:** high: unit failed, and independent pure topology inspection confirmed all three ancestors.
- **Smallest correction:** assert relevant transitive ancestry/propagated handoffs, while retaining direct-edge checks only where direct edges are the contract.
- **Overlap:** T-147 concerns binding declarations, not this stale assertion. No exact existing TODO found.

## Output, identity and downstream contract

- Indexed dataset `tag_assignments` is routing context, schema `appsec-review/tag-assignment/1`, index `tags`; family shards include separate `facets`.
- Artifact-only `tagging_documents` uses the job handoff schema declaration and `data/jobs/job_security_tagging/attempts/*/artifacts/security-tagging/*.json`. The glob covers taxonomy identity, scope, assignment sets, collation, model purposes, cloud and handoff artifacts. These payloads have their own schema IDs (`tag-taxonomy-identity/1`, `tag-scope/2`, `tag-assignment-set/1`, `collation-pass/1`, `unit-purposes/1`, `tag-cloud/1`, `security-tagging-handoff/1`).
- `_assignment_set` fails on overflow; assignment validation reconstructs content identity and checks basis/evidence. Derived records must refer to known assignments. Crosswalk grouping uses whole subject identity, component/project identity, or workflow-path plus CI-job identity; no multi-hop promotion.
- Published shard fingerprints include assignment bytes, target snapshot, vocabulary/capability/crosswalk hashes, ownership topology and input manifest. Existing shards are attested; a combined manifest is verified before publication.
- The job uses legacy text gaps, permitted by its current non-strict gap contract; runtime canonicalization is not a separate classifier. The publisher separates its own standing/rollup gaps from previously reported collector gaps.
- Five explicit downstream dataset declarations were inspected by search: document-issue analysis, review-data indexing, review-package assembly, inference review and OWASP. Built-in expanded contracts additionally list dossier publication, PoC generation and remediation planning as consumers. Their entire implementations were not audited.
- `review/packages.py:1529-1582` reads facet/target records for unit context and obligations; `review/units.py:450-459` uses exposure/trust for ranking; OWASP reads roles/classes and gates standards. Consumers correctly recover canonical tag names from entity `name` when payload sanitization redacts credential-like strings.
- Purpose forwarding to package unit context, threat-model facet seeding and report-purpose sentences remain explicitly unwired/deferred in T-5008/architecture. They are not counted as newly discovered defects.
- The optional worker is correctly registered as `unit_purpose` → `unit_purpose_collator` / `unit_purpose_collation` / `unit-purpose-collation`, no persona and no tools. Its generic task text is assembled by `guidance/workers.py:142-160`; role and runtime procedure carry the closed response/citation contract. Bundle hash is pinned and included in request/provenance.
- Model `retries` is validated as part of the complete profile but is not read by `run_model_pass`; documentation also promises one call per component. Retry semantics remain a named configuration ambiguity rather than an additional asserted defect.

## Focused validation

All commands were transported by:

```powershell
$encoded = [Convert]::ToBase64String(
  [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Linux script prefix: `set -euo pipefail; cd /home/wsollers/projects/appsec-review` except the initial collection/refused-wrapper commands used `set -eu`. This matters for the refused-wrapper exit accounting below.

### Source / environment checks

```bash
git --no-pager log -1 --format='%H %D'
git status --short
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'from tests.test_000_unit_environment_guard import offending_environment; import os; errors=offending_environment(os.environ); print("unit environment:", errors); assert not errors'
```

Import resolved to this checkout's `src/appsec_review/__init__.py`; environment offences `[]`; source clean. These are probes, not additional pytest passes.

### Collection

```bash
time .venv/bin/python -m pytest --collect-only -q -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-job_security_tagging-20261118-collect32 \
  tests/unit/job_security_tagging/test_behavioral_tags.py \
  tests/unit/job_security_tagging/test_collation.py \
  tests/unit/job_security_tagging/test_contract.py \
  tests/unit/job_security_tagging/test_handler.py \
  tests/unit/job_security_tagging/test_model_pass.py \
  tests/unit/job_security_tagging/test_native_language_aliases.py \
  tests/unit/job_security_tagging/test_reader.py \
  tests/unit/job_security_tagging/test_rules_and_roles.py \
  tests/orchestration/dagster/test_security_tagging.py \
  tests/test_security_tagging.py | tail -3
```

**216 collected in 2.83 s; wall 4.725 s.** Collection executes no test cases.

### Execution

First tried the following wrapper command with an extra `-p no:cacheprovider` after the selectors. It was refused before collection/execution: `unsupported focused pytest option '-p'; scope/report/worker options belong to run-tests`. No tests ran. The outer `tail` pipeline masked the wrapper status (shell returned 0); this is **not** a passing validation. Elapsed time was not captured.

Corrected command, with `pipefail`:

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 32047 \
  --max-tests 216 --expect-tests 216 --timeout-seconds 180 -- \
  tests/unit/job_security_tagging/test_behavioral_tags.py \
  tests/unit/job_security_tagging/test_collation.py \
  tests/unit/job_security_tagging/test_contract.py \
  tests/unit/job_security_tagging/test_handler.py \
  tests/unit/job_security_tagging/test_model_pass.py \
  tests/unit/job_security_tagging/test_native_language_aliases.py \
  tests/unit/job_security_tagging/test_reader.py \
  tests/unit/job_security_tagging/test_rules_and_roles.py \
  tests/orchestration/dagster/test_security_tagging.py \
  tests/test_security_tagging.py | tail -35
```

**215 passed, 1 failed in 9.50 s; exit 1; zero skips, zero over 10 s.** Supervised collection: **4.418 s**. Supervised execution/process cleanup: **13.764 s**. Both stages confirmed cleanup with zero remaining processes.

```text
FAILED tests/orchestration/dagster/test_security_tagging.py::test_security_tagging_follows_the_last_retrieval_manifest_publisher
E       AssertionError: assert {'binary_evid...ge__finalize'} <= {'binary_evid...ex__finalize'}
E         Extra items in the left set:
E         'dependency_intelligence__finalize'
E         'profile_data__finalize'
E         'test_coverage__finalize'
```

Private wrapper base: `test/tmp/tests-custom-20261118-131058-123257-3242330`.

Evidence retained under that checkout:

- `test/tmp/logs/tests-custom-20261118-131058-123257-3242330.log`
- `test/tmp/logs/tests-custom-20261118-131058-123257-3242330.collection.log`
- `test/tmp/tests-custom-20261118-131058-123257-3242330.junit.xml`
- `test/tmp/tests-custom-20261118-131058-123257-3242330.timings.sqlite`
- `test/tmp/tests-custom-20261118-131058-123257-3242330.collection.json`
- `test/tmp/reports/tests-custom-20261118-131058-123257-3242330.json`

### Bounded reproducers

These are ordinary `.venv/bin/python - <<'PY'` scripts over inspected fixture helpers, not additional pytest counts. They run no target code.

**R1: mobile/build/excluded-document cases**, executed together:

```python
from appsec_review.jobs.job_security_tagging.collation import collect_facets
from appsec_review.jobs.job_security_tagging.taxonomy import assignment
from appsec_review.jobs.job_security_tagging.producers import Row
from tests.unit.job_security_tagging.helpers import scope, taxonomy, shard
from tests.unit.job_security_tagging.test_collation import canned, settings
v, r, _ = taxonomy()
sc = scope()
mobile = assignment(
    vocabulary=v, tag="component:android-mobile", basis="declared",
    subject=sc.component_subject("component:app"), producer={"name": "fixture"},
    evidence=[{"ref": "manifest:AndroidManifest.xml"}])
result = collect_facets(
    canned(("app/Main.java", "AuthenticationManager manager;\n", "Java")),
    sc, v, r, settings(), [mobile], 100)
print(result[2]["components"][0]["target_classes"])
assert "target:mobile" not in result[2]["components"][0]["target_classes"]
for kind in ("library", "executable"):
    indexes = canned(("lib/x.c", "#include <openssl/evp.h>\n", "C"))
    indexes.groups.append((shard("build", "language-build"), [
        Row("build:command", "build_action", "cmd-1", "clang command",
            {"command_id": "cmd-1", "tool": "clang", "tool_kind": "compiler",
             "exit_code": 0, "working_directory": "."}, None),
        Row("build:artifact", kind, "out/libx", "out/libx",
            {"kind": "static-library" if kind == "library" else "executable",
             "workspace_path": "out/libx"}, None)]))
    result = collect_facets(indexes, sc, v, r, settings(), [], 100)
    print(kind, result[2]["components"][0])
    assert result[2]["components"][0]["build_point_kinds"] == []
indexes = canned(("third_party/x.py", "import jwt\n", "Python"))
indexes.groups.append((shard("documents"), [
    Row("document:1", "document_record", "openapi.yaml", "openapi.yaml",
        {"kind": "openapi", "path": "third_party/openapi.yaml"}, None)]))
result = collect_facets(indexes, sc, v, r, settings(), [], 100)
print(result[2]["components"], [x["tag"] for x in result[0]])
assert result[2]["components"][0]["facets"] == []
assert any(x["tag"] == "mechanism:http" for x in result[0])
```

All those assertions completed. The same initial process next tested an emoji at the very end of a line and incorrectly expected a differing offset; that assertion failed because the current offset routine rounds the partial final surrogate to the full character. Its remaining model/topology probes did **not** run. No elapsed value was captured before that abort. This initial coordinate case is not evidence of ST-07.

**R2: corrected coordinates, malformed nested values, transitive ancestry** — successful, **1.022 s**, exit 0:

```python
from time import perf_counter
from copy import deepcopy
from appsec_review.jobs.job_security_tagging.collation import collect_facets
from appsec_review.jobs.job_security_tagging.model_pass import _validate, PROPOSAL_SCHEMA
from appsec_review.graph.crosscheck import SourceFile
from tests.unit.job_security_tagging.helpers import scope, taxonomy
from tests.unit.job_security_tagging.test_collation import canned, settings
from appsec_review.runtime.registry import builtin_contracts
from appsec_review.orchestration.topology import wave1_dependencies, upstream_closure
start = perf_counter()
v, r, _ = taxonomy()
text = "import jwt # 😀x\n"
result = collect_facets(canned(("app/a.py", text, "Python")),
                        scope(), v, r, settings(), [], 100)
record = next(x for x in result[0] if x["basis"] == "declared")
loc = record["evidence"][0]["location"]
mapped = SourceFile.from_bytes(text.encode()).offset(loc["end_line"], loc["end_column"])
print(loc["end_column"], mapped, loc["end_byte"])
assert mapped != loc["end_byte"]
base = {"schema": PROPOSAL_SCHEMA, "component_id": "component:app",
        "role": ["role:auth"], "asset": [], "purpose": "Auth", "unknown": [],
        "claims": [{"tag": "role:auth", "citations": [{"path": "a.py", "line": 1}]}]}
for case in ("unknown-object", "claim-tag-list", "path-list", "assignment-list"):
    p = deepcopy(base)
    if case == "unknown-object": p["unknown"] = [{}]
    elif case == "claim-tag-list": p["claims"][0]["tag"] = []
    elif case == "path-list": p["claims"][0]["citations"][0]["path"] = []
    else: p["claims"][0]["citations"] = [{"assignment_id": []}]
    try:
        _validate(p, component_id="component:app", vocabulary=v,
                  excerpt_keys={("a.py", 1)}, assignment_ids=set())
    except TypeError as e: print(case, type(e).__name__, str(e))
    else: raise AssertionError(case)
contracts = builtin_contracts()
deps = wave1_dependencies(set(contracts))
closure = upstream_closure("job_security_tagging", deps, set(contracts))
print(deps["job_security_tagging"])
assert all(x in closure for x in (
    "job_dependency_intelligence", "job_profile_data", "job_test_coverage"))
print("elapsed_seconds=", round(perf_counter() - start, 3))
```

**R3: real model handler rejection and eligibility budget** — successful, **0.147 s**, exit 0:

```python
from pathlib import Path
from time import perf_counter
from dataclasses import replace
from shutil import rmtree
import pytest
from tests.unit.job_security_tagging.test_model_pass import run_pass, Scripted, valid_proposal, settings
from tests.unit.job_security_tagging.test_collation import canned, HTTP_LOGIN
from tests.unit.job_security_tagging.helpers import scope, taxonomy, ROOT
from appsec_review.jobs.job_security_tagging.model_pass import run_model_pass
start = perf_counter()
root = Path("test/tmp/job-audit-job_security_tagging-repro32")
root.mkdir(parents=True, exist_ok=False)
root = root.resolve()
try:
    def malformed(request):
        p = valid_proposal(request)
        p["unknown"] = [{}]
        return p
    with pytest.MonkeyPatch.context() as patch:
        try: run_pass(root / "malformed", patch, Scripted(malformed))
        except TypeError as e: print("HANDLER:", type(e).__name__, str(e))
        else: raise AssertionError("malformed reply did not escape")
    v, r, _ = taxonomy()
    cfg = settings()
    cfg = replace(cfg, model_pass=replace(cfg.model_pass, max_components=1))
    transport = Scripted(valid_proposal)
    collation = {
        "components": [{"component_id": "component:000-empty"}, {"component_id": "component:app"}],
        "files": [{"path": "app/login.py", "component_ids": ["component:app"]}]}
    records, gaps, doc = run_model_pass(
        repository_root=ROOT, run_root=root / "bound",
        indexes=canned(("app/login.py", HTTP_LOGIN, "Python")), scope=scope(),
        vocabulary=v, rules_sha256=r.sha256, settings=cfg, collation=collation,
        facet_records=[], infer=transport, limit=100, unit_id="collation.model_pass")
    print(len(transport.calls), doc["components"], gaps)
    assert len(transport.calls) == 0
    assert any("model_pass_bound:component:app" in x for x in gaps)
finally:
    rmtree(root)
print("elapsed_seconds=", round(perf_counter() - start, 3))
```

The first R3 attempt omitted `root=root.resolve()` and failed in guidance publication's path-relative check, before reaching the behavior under test. That is a reproducer setup error, not a job finding. Its `finally` removed its private scratch; elapsed was not captured. The successful attempt above also removed only its own scratch.

**R4: real inference operation, fake provider and fake admission client** — successful, **0.018 s**, exit 0:

```python
from time import perf_counter
import pytest
from appsec_review import inference
from appsec_review.runtime import execution_safety as safety
from appsec_review.inference import ModelRequest
from appsec_review.inference.errors import ProviderError
from appsec_review.jobs.job_security_tagging.model_pass import PROPOSAL_SCHEMA, _failures
start = perf_counter()
class Admission:
    def __init__(self): self.events = []
    def request(self, verb, **details):
        self.events.append(verb)
        return {"permit": "fake-permit"} if verb == "admit" else {}
def fake_provider(*args, **kwargs):
    raise ProviderError("scripted outage", code="down")
request = ModelRequest(PROPOSAL_SCHEMA, "", "unit_purpose_collator", "fixture",
                       {}, (), (), ("component:app",), (), (),
                       "audit-fake", "fixture", "low", 100, 100)
client = Admission()
token = safety._ACTIVE.set(client)
try:
    with pytest.MonkeyPatch.context() as patch:
        patch.setitem(inference.PROVIDERS, "audit-fake", fake_provider)
        try: inference.infer(request, timeout_seconds=1)
        except BaseException as exc:
            print(type(exc).__name__, isinstance(exc, _failures()), client.events)
            assert isinstance(exc, safety.ReviewStopped)
            assert not isinstance(exc, _failures())
        else: raise AssertionError("expected scripted provider failure")
finally:
    safety._ACTIVE.reset(token)
print("elapsed_seconds=", round(perf_counter() - start, 3))
```

Two prior R4 attempts: (1) the fake client's first argument was called `action`, conflicting with the real keyword and causing a setup `TypeError`; (2) corrected client with `except Exception` let the expected `ReviewStopped(BaseException)` escape, producing the confirming traceback but exit 1. Neither had a captured elapsed value. The final script catches only for observation/assertion and restores the context; it does not change production cancellation behavior.

## Read coverage and remaining gaps

**Read fully:**

- Updated shared audit brief; authorized `AGENTS.md`; canonical multi-session coordination skill.
- All nine files in `src/appsec_review/jobs/job_security_tagging/`: `__init__`, job, datasets, producers, taxonomy, crosswalk, cloud, collation, model pass.
- `src/appsec_review/config/collation.py`; `jobs/component_ownership.py`; `retrieval/source_resolution.py`; `inference/request.py`; `inference/__init__.py`.
- All three pinned taxonomy JSON files, including every lexical/path/package/observation/graph/facet/target/crosswalk rule.
- `docs/operations/job_security_tagging.md`, `docs/architecture/collation-pass.md`.
- Role and runtime procedure for unit-purpose collation, read as audit data, not agent instructions.
- All ten selected test files; unit helper module; root conftest and environment guard. Inspected fakes: canned index/source reads, scripted model transport, local SQLite, fake index builder. The contract test executes real twelve-unit handlers over synthetic local artifacts; no real runner/provider. Dagster test constructs definitions only.
- Shell test wrapper and its common Python locator.

**Read relevant sections / searched, not whole files:**

- Taxonomy architecture assignment/basis/namespace sections; TODO entries T-007, T-056, T-086, T-147, T-165, T-5008 and T-5051; cumulative/per-job reports searched for tagging overlap.
- Config loader disposition inheritance, central tagging TOML, registry wiring, test-map entry and expanded consumer contracts.
- Guidance workers (specialized registration and assembly), registry role/skill records, capability cards, model JSON parser.
- Retrieval manifest selection, accepted shard read observation, logical/source-location model, source coordinate mapper.
- Runtime unit execution/error propagation, interchange output/gap validation, execution-safety operation/latch behavior.
- Actual language/JVM build publications; binary function/source backing publication; static observation/Syft/Grype/OSV and CI publication shapes.
- Downstream package facet collection, ranking signals, OWASP roles/class gate; dataset declaration references.
- Standard wrapper supervision/collection/count logic and its persisted report.

**Material unread/unexecuted scope:**

- No actual review output, target checkout, provider response corpus, live model quality, external scanner run, compiled graph export, binary decompilation or deployment/service behavior.
- Integration/acceptance suites and complete runner admission/publication were not run; the fixture executor does not prove all real read receipts, reuse/cancellation behavior or live schema inventory.
- Full transitive implementations of 24 upstream producers and eight expanded downstream consumers, broad shared schema/index sanitizer/storage internals, complete runtime checkpoint/recovery and recording machinery were not re-audited.
- Threat-model/report consumers and optional purpose forwarding are named deferred/unwired work, not checked outcomes.
- No test or source changes were made. Standard private wrapper evidence remains under `test/tmp`; ad-hoc reproducer scratch was removed. Final HEAD and tracked/untracked Git status remained unchanged and clean.
