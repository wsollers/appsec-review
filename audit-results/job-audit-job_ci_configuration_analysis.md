# Job 7/47 — job_ci_configuration_analysis

## Scope and result

- **Source:** authorized WSL checkout `/home/wsollers/projects/appsec-review`, branch `main`, exact revision **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**. Initial and pre-validation Git checks were clean. `.venv/bin/python` imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. No Windows-checkout code was audited.
- **Read-only functional audit:** all five job package files and all six job unit-test files inspected; every **51 tasks across seven steps** traced. No repository code/configuration changes, real scanner/provider calls, container/service operations, target-code execution, integration, acceptance, or live review.
- **Findings:** one high and five medium reproduced functional defects; separately, low-severity documentation/test-map drift. No exploit-discovery claim.
- **Existing tests:** **131 passed** = **128 job cases + 3 environment-guard cases**, **7.12 s pytest / 15.165237675 s supervised wrapper**. No failures, errors, skips, or cases over ten seconds. Slowest case **1.437530628 s**.
- **Additional probes:** twelve small in-memory defect checks completed in **0.028668118 s**, exit 0. They assert the observed defective behavior, not desired-correctness regressions. An earlier probe failed because its hard-coded expected byte lengths were off by one; that audit-script error and its corrected rerun are recorded below.
- Passing fixture tests does **not** establish correct native scanner output, runtime admission, useful review leads, or live output quality.

## Registration, intent, and input authority

`src/appsec_review/runtime/registry.py:88,158` imports/registers the factory. `datasets.py:39-67` declares a review-graph job with checkout access, `schedule_after=("job_target_catalog",)`, `always_execute=False`, and propagating handoff. The central recipe at `appsec-review.toml:2409-2512` contains all seven steps; there is no job-level disabled flag, so it is enabled by `runtime/selection.py:11-24`. Disabled-job graph selection is shared infrastructure, not a per-provider switch.

The contract admits only `job_target_catalog`:

| Input | Schema | Admission |
| --- | --- | --- |
| `handoff` | `appsec-review/job-handoff/2` | Required; reject absence |
| `target_artifact_inputs` | `appsec-review/target-artifact-intake/1` | Optional; gap if unavailable |
| `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units` | `appsec-review/retrieval-index/2` | Optional; gap |
| `catalog_documents` | `appsec-review/target-catalog/1` | Optional; gap |

All are producer evidence on the handoff channel. `job.py:697-711,714-724` calls `load_target_catalog(..., intake_target_root=False)` and verifies its source fingerprint against the job context. The shared loader (`jobs/job_evidence_collection/job.py:157-212`) resolves `accepted_upstream("job_target_catalog")`, verifies referenced catalog/partition/project/build/compile-command artifacts, and returns the catalog's enumerated files. It does **not** implicitly read intake for this caller. The undeclared-intake defect from the historical pass is fixed, not re-reported.

`runtime/consume.py:168-212` requires the typed envelope declaration and the claim's admitted digest under runtime scope, verifies bytes, and records the handoff read. Source/catalog artifact traversal and inherited manifest use do not mean every optional dataset was semantically consumed. Publishing resolves the context's pinned manifest, verifies it, replaces only this producer's prior shards, and carries other producers' identities (`job.py:760-776`; `retrieval/core.py:112-125`).

The intended job is bounded, offline structural analysis: discover provider definitions, run applicable linters, normalize and deduplicate observations, attach conservative hierarchy, publish searchable shards, correlate exact duplicates, and join coverage. T-170 has additionally implemented actionable lead metadata and a nonempty `security_findings` subset; the older “always empty” operations text is stale.

## Every step/task and actual wiring

The table below names every branch task. The scan, normalization, and publication columns belong respectively to `ci_analysis`, `ci_normalization`, and `ci_observation_publication`.

Shared wiring (`job.py:741-754`):

- Every scan depends on `ci_discovery.classify_providers`.
- Each normalize depends on its own scan and calls `_normalize` (`461-496`).
- Each index depends on its normalize and `ci_enrichment.build_hierarchy`, and calls `_index` (`554-597`).
- No model, role task, runtime skill, or task prompt is invoked by this job. Guidance-registry search found downstream `query_ci_configuration` availability, not a worker binding for this producer.

| Scan task | Normalize task | Index task | Actual selected behavior / audit result |
| --- | --- | --- | --- |
| `github_zizmor_scan` | `github_zizmor_normalize` | `github_zizmor_index` | External Zizmor, offline JSON array; workflow and action-definition support; native primary-location validation. CI-02/03/05/06 apply; real binary not run. |
| `github_checkov_scan` | `github_checkov_normalize` | `github_checkov_index` | External Checkov `github_actions`, workflows only; source-range/sentinel binding. CI-01/02/03/05/06. |
| `github_actionlint_scan` | `github_actionlint_normalize` | `github_actionlint_index` | External actionlint `-format "{{json .}}"`, workflows only; generic decoder. CI-01/02/03/04/05/06. |
| `github_schema_scan` | `github_schema_normalize` | `github_schema_index` | `ci-schema`: regex structural rules, not provider-schema/YAML evaluation. CI-02/03/05/06. |
| `azure_checkov_scan` | `azure_checkov_normalize` | `azure_checkov_index` | External Checkov `azure_pipelines`; YAML support, generic decoding plus range binding. Same shared CI-01/02/03/05 paths. |
| `azure_schema_scan` | `azure_schema_normalize` | `azure_schema_index` | Shared `ci-schema` structural rules; no Azure controller or template expansion. CI-02/03/05; hierarchy is heuristic. |
| `gitlab_checkov_scan` | `gitlab_checkov_normalize` | `gitlab_checkov_index` | External Checkov `gitlab_ci`; shared generic decoder and mapping paths. CI-01/02/03/05. |
| `gitlab_schema_scan` | `gitlab_schema_normalize` | `gitlab_schema_index` | Shared `ci-schema` structural rules; no include/controller resolution. CI-02/03/05. |
| `circleci_checkov_scan` | `circleci_checkov_normalize` | `circleci_checkov_index` | External Checkov `circleci_pipelines`; same generic/range path. CI-01/02/03/05. |
| `circleci_schema_scan` | `circleci_schema_normalize` | `circleci_schema_index` | Shared `ci-schema` structural rules. CI-02/03/05. |
| `bitbucket_checkov_scan` | `bitbucket_checkov_normalize` | `bitbucket_checkov_index` | External Checkov `bitbucket_pipelines`; explicit coarse clipping covered by focused fixtures. CI-01/02/03/05; coarse-mapping repair itself passes. |
| `bitbucket_schema_scan` | `bitbucket_schema_normalize` | `bitbucket_schema_index` | Shared `ci-schema` structural rules. CI-02/03/05. |
| `jenkins_structural_scan` | `jenkins_structural_normalize` | `jenkins_structural_index` | `ci-jenkins-structural`; same regex rules, no Groovy execution. CI-02/03/05; full DSL semantics intentionally absent. |
| `teamcity_structural_scan` | `teamcity_structural_normalize` | `teamcity_structural_index` | `ci-teamcity-structural`; same regex rules, no Kotlin execution. CI-02/03/05; plugin/controller semantics absent. |
| `other_discovery_scan` | `other_discovery_normalize` | `other_discovery_index` | Discovery-only: one `producer_reported_gap` per recognized unsupported definition, no tool; empty definitions are NOT_APPLICABLE. Index carries unavailable/partial coverage truthfully for this path. |

| Remaining task | Implementation, admitted information, output, and coverage |
| --- | --- |
| `ci_discovery.discover_definitions` | `job.py:714-724`, `discovery.py:11-59`: consume accepted inventory, fixed provider/path classification, retain path/hash/size, stop at `max_files`, sort retained provider/path records, publish `ci-definitions.json`, emit origin-owned truncation gaps. No whole-tree scan. |
| `ci_discovery.classify_providers` | `job.py:726-733`: group discovered definitions; publish `provider-classification.json`; carry discovery gaps as `gap_records`, declare none again. |
| `ci_enrichment.build_hierarchy` | `job.py:499-519`, `static_rules.py:122-145`: depends on classification and every normalize; read source, apply UTF-8/byte checks, build `hierarchy.json`, own parse/size gaps. CI-03/06. |
| `ci_correlation.correlate_findings` | `job.py:600-665`: join all 15 indexes by exact provider/path/line-column/category/message; coarse mappings additionally match provenance/bytes; derive deterministic canonical IDs, observation/tool/rule lists, lead metadata; emit `canonical-findings.json` and `evidence/ci_findings`. CI-05. |
| `ci_coverage.join_coverage` | `job.py:668-693`: join classification, scan and hierarchy gaps by gap ID; retain provider definition counts, per-tool status/counts, not-applicable accounting; publish `coverage.json`; “complete” iff joined gaps empty. Thus CI-01's missing gap is inherited as false completeness. |
| `ci_coverage.publish_handoff` | `job.py:760-795`: verify inherited manifest, replace this job's prior shards, add 15 observation shards + canonical evidence, verify combined manifest, publish `handoff.json` with references/counts/coverage and promoted lead subset. Own status succeeds without re-declaring upstream gaps. CI-D1. |

### Common transforms and failure paths

- `_scan` reads configured bounds, selects by provider, partitions external paths **before** image resolution, and returns NOT_APPLICABLE without gaps for absent/unsupported definitions (`job.py:343-379`). Unsupported action metadata is correctly excluded from actionlint/Checkov but admitted by Zizmor (`tool_inputs.py:239-261`).
- External argv is fixed (`job.py:147-156`). Tool manifests specify offline networking, read-only target/root, non-root user, 1 GiB RAM, two CPUs, PID 256, 600-second timeout, and 16 MiB output bounds. These are declarations inspected, not live enforcement verified.
- Static UTF-8 failures and native Zizmor/Checkov mapping errors become scoped parser gaps; unavailable images and failed invocations have blocked/failed gaps. With an active execution-safety guardian, `safety.fail` raises `ReviewStopped(BaseException)` before a fallback can continue; this audit did not activate that guardian.
- Records are capped after collection, messages redacted, normalized fields and stable IDs constructed, and duplicate IDs removed. Raw/duplicate/normalized counts are retained. Missing generic severity remains `null` with a producer gap; this deliberate recent behavior is not treated as a defect.
- Normalization/indexing preserve `scan_terminal_status` and `scan_gap_records` as payload, not duplicate unit gaps. `_coverage` deduplicates the originals.
- `_read` verifies run containment and artifact digest; it is not a CI-domain JSON-schema validator. No output validators are attached to these units. `SourceLocation`, index identities, manifest validation, shared control-output validation and handoff admission are separate checks, not evidence that arbitrary CI-domain payload fields are correct.

## Outputs and downstream compatibility

| Dataset | Actual publication | Declared schema/disposition and traced consumption |
| --- | --- | --- |
| `ci_observations` | `data/indices/observations/ci_<provider>_<tool>/<fingerprint>.sqlite` | `retrieval-index/2`, indexed, observation-publication step; 15 declared shards. Each row is `TOOL_OBSERVATION`, with source location and enriched payload. `query_ci_configuration`, tagging, review inputs, and `ci_trust` consume it. CI-04/06 affect facets/locations. |
| `ci_findings` | `data/indices/evidence/ci_findings/<fingerprint>.sqlite` | `retrieval-index/2`, indexed, correlation step; `FINDING_PACKAGE` records, not final adjudicated vulnerabilities. `query_ci_configuration` and `ci_trust` consume them. CI-05 loses exact byte spans. |
| `ci_documents` | Attempt `artifacts/ci/<12-char task hash>/*.json` | Artifact-only umbrella `ci-configuration-analysis-handoff/1`; the declared glob matches definitions/classification/raw/normalized/hierarchy/canonical/coverage/handoff JSON, whose individual domain schemas differ. An umbrella declaration is not itself a per-file schema mismatch. Metadata route only. |
| `ci_tool_io` | Attempt `steps/ci_analysis/tasks/<task>/scratch/file_NNNN/**` | Protected `container-execution/1`; glob matches raw streams and execution receipts. The native payload is not exposed as an indexed public document. |

The combined manifest lives under `data/indices/manifests/ci-<attempt>.json`, referenced by the final publication. Unit artifacts retain run-relative paths, sizes and hashes. Index fingerprints bind snapshot, producing artifacts, provider/tool/framework, hard-coded rules/parser/normalizer/mapping identities, and settings digest.

Direct downstream reads inspected:

- `retrieval/core.py:1023-1084`: exact JSON-payload facets over CI observation/evidence shards. This makes incorrect `job` values and columns material, not cosmetic.
- `indexing/products.py:928-995`: `ci_trust` groups CI records by workflow path, counts categories/observations/tools/jobs, and derives trust-path candidates; explicitly reports unresolved dynamic workflows and missing build mapping.
- `jobs/job_review_prioritization/composite.py:324-383`: accepted CI handoff's `security_findings`, or observation fallback, supplies promoted leads.
- `jobs/job_security_tagging/producers.py:445-451`: CI-specific producer identity. Additional consumer contracts were searched, not their entire implementations audited.

## Evidence-backed functional findings

### CI-01 — High: malformed/truncated generic scanner output becomes a successful clean or incomplete scan

- **Evidence:** `src/appsec_review/jobs/job_ci_configuration_analysis/job.py:271-294` decodes invalid UTF-8 with replacement, discards every malformed JSONL line, and silently ignores unknown records. At `:423-431` only exit/timeout/OOM is checked; output truncation flags are ignored. At `:457-458` no detected gap means SUCCEEDED. `_index` marks such scans complete (`:579-583`).
- **Trigger:** actionlint or any CI Checkov adapter exits 0/1 but prints corrupt/non-native output; or its retained output ends with a partial JSONL record at the executor's output limit.
- **Expected versus actual:** unreadable native output must produce a parser/truncation gap, not evidence of an empty or complete scan. Both actionlint and Checkov given `b'{not valid json'` returned **SUCCEEDED / 0 records / [] gaps**. A declared-truncated stream containing one valid record and a partial next record returned **SUCCEEDED / 1 record / [] gaps**, while the embedded execution receipt explicitly held `stdout_truncated=True`.
- **Impact:** silently lost observations and false complete coverage propagate to indexed evidence and downstream reviewers. The executor does report truncation (`container_runtime/executor.py:361-377`); the job fails to consume that signal.
- **Confidence:** high; real `_scan` and parser reproduced with only executor/I/O boundaries replaced. All Checkov frameworks share this code. No real scanner failure was induced.
- **Smallest correction:** validate adapter-specific nonempty output atomically or retain explicit per-record parse gaps; distinguish accepted empty forms from malformed output; consume stdout/stderr truncation metadata with the appropriate gap policy. Preserve intentional empty-array/object compatibility where actually supported.
- **Overlap:** historical job-pass-07 fixed phantom observations from `{}` and later native Zizmor parsing; neither fixes this generic corruption/truncation path. No exact open TODO found in searched entries.

### CI-02 — Medium: advertised provider/tool/framework and identity settings do not control execution

- **Evidence:** `appsec-review.toml:2417-2440` declares `correlation`, `ruleset`, and per-provider `tools`/`framework`; `docs/operations/ci-configuration-analysis.md:15-18` calls these configuration. `job.py:52-65,741-748` unconditionally builds hard-coded `SPECS`; `_scan` only consults bounds (`:343-344`), `_argv` uses `spec.framework` (`:154-156`), and validation checks only topology, bounds and catalog fingerprint (`:697-711`). Correlation/ruleset identities are hard-coded (`:357,631-632`).
- **Trigger:** configure a provider's tools as empty/a subset, change its framework, or provide a different ruleset/correlation identity.
- **Expected versus actual:** admitted settings should affect routing or be rejected as unsupported constants. An in-memory context with `providers.github.tools=[]` and a different framework still executed one Checkov request with `--framework github_actions`. None of those settings are read to select the implementation.
- **Impact:** operators cannot disable a provider linter through the advertised routing configuration; resolved settings/fingerprints can describe a requested implementation different from the one actually run.
- **Confidence:** high for handler behavior and static validation trace. The probe did not edit/load a modified production TOML.
- **Smallest correction:** parse/validate a closed typed CI settings object; honor tool selection with explicit skipped dispositions while preserving declared task topology, and either resolve or reject non-supported framework/ruleset/correlation values.
- **Overlap:** T-147 tracks missing authoritative task bindings generally, but not this ignored configuration behavior. No exact TODO found.

### CI-03 — Medium: max_file_bytes is not an effective pre-read/pre-launch bound

- **Evidence:** `job.py:386-390,505-509` reads entire source files before checking their size; `_source_location` at `:532-536` reads the entire file with no size check. External scanning (`:412-441`) launches every supported definition without checking size; only Checkov's *nonempty result* range reconstruction reads at most `max_bytes+1`.
- **Trigger:** a cataloged definition exceeds `max_file_bytes`, especially a large file for which the external linter returns no observations.
- **Expected versus actual:** a configured byte cap should prevent over-bound read/analysis and report scoped omitted coverage. For each of the three GitHub external linters, a definition declaring 200 bytes with `max_file_bytes=1` still produced one request and **SUCCEEDED / [] gaps** on empty stdout. Static/hierarchy paths can eventually emit gaps, but only after unbounded host reads.
- **Impact:** the setting neither bounds those host allocations nor the external input size; tool-level scan coverage disagrees with the configured file limit. No large allocation, OOM, or real tool execution was performed in this audit.
- **Confidence:** high for control flow and fake-boundary reproduction; actual resource exhaustion not tested.
- **Smallest correction:** use bounded `read(max_bytes+1)`/verified size admission before every source reader and external launch, skip over-bound definitions with a scoped gap, and carry that disposition consistently into coverage.
- **Related validation weakness:** `analysis_bounds` (`:123-131`) silently converts `True` and `1.9` to one rather than rejecting non-integer settings; both were reproduced. Use strict integer validation alongside the read-bound fix.
- **Overlap:** historical pass tested limits specifically on static readers, not their allocation behavior or external launch gating. T-111 concerns different build-descriptor bounds; no matching CI TODO found.

### CI-04 — Medium: native actionlint columns are discarded

- **Evidence:** `job.py:299-315` accepts top-level `line`, but `start_column`/`end_column` read only nested `location.column`; actionlint's top-level `column` is ignored. The repository's actionlint-native fixture is itself top-level (`tests/unit/job_ci_configuration_analysis/test_zizmor_output.py:161-181`).
- **Trigger:** ordinary actionlint JSON such as `{"kind":"syntax-check","message":"diagnostic","line":2,"column":17}`.
- **Expected versus actual:** preserve column 17; decoder returns column **1**. The focused existing fixture asserts rule/message/line but never its column.
- **Impact:** wrong source anchoring; otherwise-identical diagnostics at different columns of the same line can acquire the same normalized observation ID and be deduplicated. Later normalization cannot recover the omitted coordinate.
- **Confidence:** high; direct real decoder reproduction.
- **Smallest correction:** use an adapter-specific actionlint location mapper or explicitly accept its native top-level coordinate fields, then exercise two same-line/different-column observations through normalization.
- **Overlap:** prior native fixes concern Zizmor and Checkov, not actionlint columns; no exact TODO found.

### CI-05 — Medium: canonical correlation discards exact byte spans while continuing to claim exact mapping

- **Evidence:** canonical construction `job.py:613-629` copies `start_byte`, `end_byte`, and mapping metadata **only if** the first observation is ambiguous. For normal exact records, `_source_location` (`:537-550`) reconstructs whole-line byte offsets, ignoring retained columns, and labels the result confidence **1.0**, `ambiguous=False`. The canonical index invokes that helper at `:643-647`.
- **Trigger:** any exact observation that covers only part of a source line, including ordinary static matches and native Zizmor primary spans.
- **Expected versus actual:** exact canonical duplicate correlation should preserve the contributing precise span or explicitly mark a broadened mapping. For `b'    permissions: write-all\n'`, the real static rule produced bytes **[4,26)** (`permissions: write-all`), but real correlation created location **[0,27)** (entire indented line plus newline), confidence **1.0**, non-ambiguous; canonical payload has no byte fields.
- **Impact:** canonical evidence excerpts differ from the observation they claim to represent, and line/column/byte claims become inconsistent. Existing coarse Checkov provenance tests do not cover this exact-record path.
- **Confidence:** high; real static rule, correlator and `SourceLocation` construction, with storage/index writers replaced by in-memory boundaries.
- **Smallest correction:** retain exact span and mapping metadata for exact canonical records too; require compatible byte spans when correlating precise observations; test equality of observation/canonical source bytes.
- **Overlap:** the historical Checkov clipping/sentinel repairs explicitly preserved *ambiguous* mappings. This is the complementary exact path, not a re-report of those fixed bugs. No exact TODO found.

### CI-06 — Medium: ordinary GitHub jobs are published under the invented job name “steps”

- **Evidence:** `static_rules.py:136-139` treats any bare YAML key with indentation <=4 as a job, including `steps:`. `_enrich` chooses the latest preceding job node (`job.py:521-530`).
- **Trigger:** normal structure `jobs:`, two-space `build:`, four-space `steps:`, six-space `- run: ...`.
- **Expected versus actual:** observation context should identify `job="build"`; real hierarchy/enrichment returns **`job="steps"`**. The tests assert node kinds/nearest-node mechanics, not actual native hierarchy names.
- **Impact:** `query_ci_configuration(job="build")` filters out the observation because it performs exact payload filtering (`retrieval/core.py:1031-1066`); downstream CI-trust job summaries also use the invented value (`indexing/products.py:951-954`).
- **Confidence:** high; direct real hierarchy/enrichment reproduction.
- **Smallest correction:** distinguish provider structural containers from job IDs, track nesting/context boundaries, and add a native-shaped multi-job fixture checking actual job and step attachment. Full DSL execution is neither needed nor recommended.
- **Overlap:** conservative/latest-preceding enrichment is a documented limit; treating the `steps` container itself as a job is a distinct deterministic misclassification, not a demand for CI runtime semantics. No exact TODO found.

## Documentation and coverage drift (separate from code defects)

- **CI-D1 — Low:** `docs/operations/job_ci_configuration_analysis.md:16-18,265-267` says the handoff's security-findings list remains empty. `job.py:786` now publishes the `lead_candidate` subset, consumed by prioritization. T-170 is done (`docs/TODO.md:2799-2806`) and intentionally introduced this behavior; update the documentation, **do not** remove promotion to satisfy the old text.
- **CI-D2 — Low:** `tests/job-test-map.json:108-120` lists only five unit files, omitting the two cases in `tests/unit/job_ci_configuration_analysis/test_lead_promotion.py`. Those tests were found, inspected and executed explicitly here. T-113 is the broader ongoing test-tier/map work. Historical “49 units / 120 cases / ten rules” comments are stale: current code has 51 units, 128 job cases, and eleven regex rules. These stale counts are not evidence of missing runtime tasks.
- **Known T-147:** missing authoritative task/tool bindings remain a documented declaration gap. This audit traced actual handlers rather than treating the generated inventory as proof.
- **Not newly reported:** optional upstream gaps, deliberate no-linter classification, unresolved remote/dynamic CI semantics, no build-unit identity in CI trust, and accepting absent generic severity as unknown are decided boundaries or named downstream gaps.

## Focused validation — exact commands and outcomes

Linux scripts below were transported through PowerShell without quote loss:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Validation preamble:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
[ "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe ]
[ -z "$(git status --porcelain)" ]
for name in $(compgen -e | grep -E '^(APPSEC_|DAGSTER_HOME$|PYTEST_|PYTHONPATH$)' || true); do unset "$name"; done
export PYTHONDONTWRITEBYTECODE=1
```

Source/interpreter preflight additionally ran `.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'`; it resolved to the authorized checkout. No packages were installed, no guards or test bounds were relaxed.

### Collection

```bash
.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-ci-20261118-collection \
  tests/test_000_unit_environment_guard.py tests/unit/job_ci_configuration_analysis
```

**131 collected in 2.46 s**, exit 0, no tests executed. One `PytestConfigWarning: Unknown config option: cache_dir` resulted from deliberately disabling `cacheprovider` during this collection; the execution did not disable that plugin. No failed/skipped cases. The inspected collection included only the six job files and the environment guard.

### Supervised parallel execution

```bash
scripts/run-tests.sh --parallel --test-workers 4 --shuffle-seed 20261118 \
  --max-tests 131 --expect-tests 131 --strict -- \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_ci_configuration_analysis/test_contract.py \
  tests/unit/job_ci_configuration_analysis/test_discovery_and_static_rules.py \
  tests/unit/job_ci_configuration_analysis/test_checkov_locations.py \
  tests/unit/job_ci_configuration_analysis/test_zizmor_output.py \
  tests/unit/job_ci_configuration_analysis/test_job_graph.py \
  tests/unit/job_ci_configuration_analysis/test_lead_promotion.py
```

| File | Passed |
| --- | ---: |
| Environment guard | 3 |
| `test_contract.py` | 10 |
| `test_discovery_and_static_rules.py` | 7 |
| `test_checkov_locations.py` | 43 |
| `test_zizmor_output.py` | 54 |
| `test_job_graph.py` | 12 |
| `test_lead_promotion.py` | 2 |
| **Total** | **131** |

**Exit 0.** Fixed report: 131 passed, no FAILED/ERROR nodes, no skips, no slow cases. Pytest elapsed **7.12 s**; total wrapper **15.165237674955279 s**. Supervisor collection **3.989720086 s**, execution **10.859160752 s**; both cleanup records confirmed zero remaining processes. Slowest case: `test_hierarchy_error_branches_and_default_executor_factory`, **1.43753062793985 s**; full fake-boundary job case **1.42085138207767 s**.

The mandatory multi-file wrapper owns its unique basetemp name (`tests-custom-*`), rather than supporting a `job-audit-*` name override. No override/workaround was added. The separate collection used the requested job-specific scratch descendant. All scratch remained under `test/tmp/`.

Retained evidence (relative to the authorized checkout):

- Report: `test/tmp/reports/tests-custom-20261118-110027-802620-2351095.json`
- Log: `test/tmp/logs/tests-custom-20261118-110027-802620-2351095.log`
- Collection log: same basename with `.collection.log`
- JUnit: `test/tmp/tests-custom-20261118-110027-802620-2351095.junit.xml`
- Collection manifest: same basename with `.collection.json`
- Timings: same basename with `.timings.sqlite`

Fixture boundaries were inspected first: `tests/ci_support.py` fakes only image resolution/execution; the unit-tier conftest blocks real engines, external sockets and Dagster execution and disables fsync; support fixtures create only isolated synthetic catalogs, source files and SQLite stores. The full handler case executes the real 51-unit in-process graph, **not** a live or integration review. It does not prove full JobRunner admission/resume or native tool policy.

### In-memory defect probes

Final successful script after the same preamble:

```bash
.venv/bin/python - <<'PY'
import json, time
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.job_ci_configuration_analysis import job as j
from appsec_review.jobs.job_ci_configuration_analysis.static_rules import hierarchy, scan_text
started = time.monotonic()
root = Path.cwd() / 'test/tmp/job-audit-ci-memory-only'
wf = '.github/workflows/ci.yml'
specs = {s.key: s for s in j.SPECS}
captured = []
def write(unit, name, doc):
    captured.append((name, doc))
    return {'path': 'memory/' + name, 'sha256': 'a'*64, 'size_bytes': 0}
def scan(key, stdout, settings=None, truncated=False):
    calls = []
    result = ExecutionResult('appsec-review/container-execution/1', specs[key].tool_id,
        'fake', 'sha256:'+'a'*64, 'sha256:'+'a'*64, 'fake', (), {}, '', '',
        0, False, False, truncated, False, 'stdout', 'stderr', 'receipt')
    def execute(req):
        calls.append(req)
        return result
    fake = NS(catalog=NS(tool=lambda _: NS(executable='/inert/tool')),
              resolve_image=lambda _: 'sha256:'+'a'*64, execute=execute)
    definitions = [{'path':wf, 'sha256':'a'*64, 'size_bytes':200, 'provider':'github'}]
    unit = NS(unit_id='ci_analysis.'+key+'_scan', unit_root=root/'unit',
        output=lambda _: {'definitions':definitions},
        job=NS(run_root=root, target_root=root/'target', events=NS(write=lambda *a, **k: None),
               config=NS(settings=settings or {})))
    with patch.object(j, '_write', write), patch.object(Path, 'read_bytes', return_value=stdout):
        out = j._scan(unit, specs[key], lambda _: fake, None)
    return out, calls
for key in ['github_actionlint', 'github_checkov']:
    out, calls = scan(key, b'{not valid json')
    assert (out['terminal_status'], out['record_count'], out['gaps']) == ('SUCCEEDED', 0, [])
    print('MALFORMED', key, out['terminal_status'], out['record_count'], out['gaps'])
payload = b'{"kind":"syntax-check","message":"diagnostic","severity":"high","line":2}\n{"kind":'
out, calls = scan('github_actionlint', payload, truncated=True)
assert out['terminal_status'] == 'SUCCEEDED' and out['record_count'] == 1 and out['gaps'] == []
print('TRUNCATED', out['terminal_status'], out['record_count'], out['gaps'], out['executions'][0]['stdout_truncated'])
settings = {'providers':{'github':{'tools':[], 'framework':'not-the-configured-framework'}},
            'ruleset':'not-the-active-ruleset', 'correlation':'not-the-active-correlator'}
out, calls = scan('github_checkov', b'[]', settings)
assert len(calls) == 1 and 'github_actions' in calls[0].argv
print('IGNORED_TOOL_SELECTION', len(calls), calls[0].argv)
for key in ['github_zizmor', 'github_actionlint', 'github_checkov']:
    out, calls = scan(key, b'[]', {'max_file_bytes':1})
    assert len(calls) == 1 and out['terminal_status'] == 'SUCCEEDED' and not out['gaps']
    print('OVERBOUND_EXTERNAL', key, len(calls), out['terminal_status'], out['gaps'])
assert j.analysis_bounds({'max_files':True})[0] == 1
assert j.analysis_bounds({'max_files':1.9})[0] == 1
print('NONINTEGER_BOUNDS_ACCEPTED', j.analysis_bounds({'max_files':True}), j.analysis_bounds({'max_files':1.9}))
record = j._external_records(specs['github_actionlint'],
    b'[{"kind":"syntax-check","message":"diagnostic","line":2,"column":17}]', wf)[0]
assert record['start_column'] == 1
print('ACTIONLINT_COLUMN', 'native=17', 'normalized='+str(record['start_column']))
text = 'jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n'
nodes = hierarchy('github', wf, text)
enriched = j._enrich({'path':wf, 'start_line':5}, nodes)
assert enriched['job'] == 'steps'
print('HIERARCHY_JOB', enriched['job'], 'expected=build')
source = b'    permissions: write-all\n'
record = scan_text('github', wf, source.decode(), tool_id='ci-schema')[0]
record['observation_id'] = 'cio:memory'
entities = []
class MemoryIndex:
    def __init__(self, *a, **k): pass
    def add_entity(self, entity): entities.append(entity)
    def add_coverage(self, *a, **k): pass
    def build(self): return 'a'*64
unit = NS(unit_id='ci_correlation.correlate_findings', output=lambda _: {'records':[record]},
          job=NS(run_root=root, target_root=root/'target', source_fingerprint='a'*64))
with patch.object(j, '_write', write), patch.object(j, '_artifact', return_value={}), \
     patch.object(j, 'IndexBuilder', MemoryIndex), patch.object(Path, 'is_file', return_value=True), \
     patch.object(Path, 'read_bytes', return_value=source), patch.object(j, 'file_sha256', return_value='a'*64):
    out = j._correlate(unit, ('one-index',))
loc = entities[0].location
original = source[record['start_byte']:record['end_byte']]
canonical = source[loc.start_byte:loc.end_byte]
assert original == b'permissions: write-all'
assert canonical == source and original != canonical and loc.confidence == 1.0 and not loc.ambiguous
print('CANONICAL_SPAN', 'observation='+str((record['start_byte'],record['end_byte'])),
      'canonical='+str((loc.start_byte,loc.end_byte)), 'confidence='+str(loc.confidence), 'ambiguous='+str(loc.ambiguous))
print('REPRO_CHECKS', 12, 'all observed-defect checks passed', 'elapsed_seconds', time.monotonic()-started)
PY
```

Output: both malformed scans succeeded empty; truncated actionlint succeeded with one record and no gap; disabled tool selection still made a Checkov request; all three external branches launched over-bound definitions; both non-integer settings became one; native column 17 became one; job `build` became `steps`; exact `[4,26)` became canonical `[0,27)` with confidence 1.0. **Twelve checks completed, 0.02866811805870384 s, exit 0.** No files were written by this script; `root` is only a path value, and all external storage/execute boundaries are in-memory.

**Earlier failed probe, explicitly retained:** same command/body through `loc = entities[0].location`, followed by:

```python
assert (record['start_byte'],record['end_byte']) == (4,25)
assert (loc.start_byte,loc.end_byte) == (0,26)
assert loc.confidence == 1.0 and loc.ambiguous is False
```

It exited 1 at the first assertion after printing the other defect observations. The actual lengths are 26 and 27; this was an **audit-script arithmetic error**, not a failing repository regression. Its elapsed timer was never printed. A projection-only rerun of real `_correlate` with the same memory boundaries and content-based assertions confirmed `[4,26)` versus `[0,27)` in **0.0231107990257442 s**, exit 0, before the complete corrected script above ran.

Other read-only probe limitations: Linux `rg` was unavailable (`command not found`, exit 127) during initial discovery; subsequent searches used the provided UNC-aware `rg` tool. The TODO's alternative T-170 task-document spelling did not exist; the existing `2026-11-17-t170-sast-flows-dedupe-and-sca-reachability.md` was found and read. Neither incident affected test execution or source revision.

## Prior work and TODO comparison

Read the complete historical `docs/tasks/2026-11-08-job-pass-07-ci-configuration-analysis.md`, including its subsequent Zizmor and Checkov repairs; read relevant rows from the historical catalog/interchange and lead-coverage audits; searched the prior per-job session reports. No previous report for this current assigned job was present in the session files.

Local history inspected without fetch/pull:

```bash
git --no-pager log -6 --format='%h %s' -- src/appsec_review/jobs/job_ci_configuration_analysis
git --no-pager log --all -5 --format='%h %s' -S 'settings.providers.github' -- appsec-review.toml
git --no-pager log --all -5 --format='%h %s' --grep='CI.*audit\|ci_configuration.*audit\|CI.*parser'
```

Relevant commits include `215a414dc` (strict gap/typed-input repair), `0afa094c5` (native Zizmor), `190617b3b`/`1c2d4fe05` (Checkov ranges/sentinel), `e007c15cc` (T-170/T-171 promotion), and `918154c06` (no invented severity). Those completed repairs are preserved.

TODO sections searched/read: **T-057**, **T-113** (including its CI entry), **T-147**, **T-170**, **T-171**; related bound entries T-111/T-112 were compared by scope. They do not already describe the six reproduced defects above. This is a bounded overlap check, not a claim that no other session has ever discussed them. No TODO was added or modified.

## Read inventory and material gaps

**Fully read:**

- Authorized `AGENTS.md`, multi-session-coordination skill, shared audit brief.
- All five files in `src/appsec_review/jobs/job_ci_configuration_analysis/`.
- All six `tests/unit/job_ci_configuration_analysis/test_*.py` files and its `support.py`.
- `tests/ci_support.py`, `tests/handoff_fixture.py`, `tests/conftest.py`, `tests/unit/conftest.py`, `tests/test_000_unit_environment_guard.py`.
- Both CI operations pages, CI architecture pointer, `docs/architecture/job-input-contracts.md`, historical job-pass-07 task document, current T-170 task plan.
- `runtime/units.py`, `runtime/consume.py`, `runtime/selection.py`; three tool manifests; `scripts/run-tests.sh` and `scripts/lib/common.sh`.

**Read relevant ranges/searches, not fully:**

- `appsec-review.toml:2409-2512`; config loader generic job/step/task settings and typed-setting dispatch; runtime registry, dataset declarations (`datasets.py:1-160`), topology (`1-150`), Dagster task pools (`133-155`).
- Accepted catalog loader (`jobs/job_evidence_collection/job.py:80-255`); tool-input declarations (`tool_inputs.py:220-277`).
- Retrieval core (`1-180`, CI query `1023-1084`), index verification (`391-555`), source-location model (`145-230`); CI-trust indexing (`855-1005`), prioritization CI lead loader (`310-390`), tagging producer identification (`425-475`).
- Container executor result/output-limit/guardian branches; execution-safety classes and failure paths; interchange/control schema boundaries.
- `deploy/dagster/bin/ops_tests.py` selection/command/report/execution sections; test map CI row; guideline/TODO/history/search excerpts described above.
- Persisted focused test report and timing database. An early broad reference search incidentally returned run-file names only; no run-owned review payloads were read or used as validation.

**Material unread/unexecuted scope:**

- No external Zizmor/actionlint/Checkov implementation, actual native stdout corpus, live image pin/digest, controller/provider semantics, or real container resource enforcement was validated.
- No current-run handoff, source evidence, scorer/answer key, production pipeline, integration/live test, or manual content acceptance was opened/executed.
- Unit graph tests use synthetic accepted catalogs and fake execution. Full JobRunner input-admission receipts, shared artifact provenance, unit checkpoint reuse, resumed sibling scheduling, source mutation/custody races, and full downstream consumer execution were not exercised.
- No exhaustive source-location semantic/schema validation, all-consumer schema audit, all-provider malformed-native matrix, regex false-positive/negative benchmark, hierarchy corpus, or broad test suite was run.
- All declared tasks were read/traced; the remaining gaps concern shared-runtime depth, native tools and real output quality, not an omitted declared branch.
- The six current findings require focused fixes/regressions and later separately authorized native/manual validation. This read-only assignment deliberately made none of those changes.

## Final custody check

The final read-only factory inspection confirmed **51 units / seven steps**. Removed only this
audit's two disposable pytest fixture directories and their two synthetic host-pin files, named
above; retained the log/JUnit/collection/report/timing evidence. The in-memory probe path never
existed. Inspected root entries; no root-level output was created by this work, and unrelated
pre-existing material was left untouched.

Final `git rev-parse HEAD` remained **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`** on **main**.
`git status --porcelain` was empty and `git diff --check` exited 0. The sole audit deliverable
is this session artifact; no repository source, test, documentation or configuration file was edited.
