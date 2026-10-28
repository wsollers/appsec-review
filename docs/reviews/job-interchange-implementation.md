# Job interchange implementation record

Status: shared contracts, runtime publication/admission, concrete native provenance, operational
consumers, and receipt-derived metrics are integrated in source. This record reconciles parent
checkpoint `4798b33a`, metrics checkpoint `7820273f`, runtime hardening `177446e3`/`59d799ef`,
consumer follow-up `ca5b4240`, and native failure-path follow-up `c1aed046`. Parent producer
reconciliation `68899ae5` separates analysis-plan numeric counts from typed dispositions.
Final consolidated parent regression results remain pending; this is not live deployment acceptance.

## Settled decisions

1. Keep one common `appsec-review/job-handoff/2` envelope and domain-owned outputs. Preserve flat
   `outputs`, artifact references, prior identities, and immutable index manifests; add no transport,
   database, or universal scanner payload.
2. Separate admission, framework execution, native producer status, and coverage. Accepted partial
   evidence remains useful; failed execution is rejected, and empty/disabled/failed/unavailable
   coverage is never evidence that a target is clean.
3. Keep the resume source fingerprint separate from evidence `target_snapshot`. Resolve strict
   upstream evidence by verification and managed evidence by authenticated unique binding;
   conflicting verified origins fail rather than selecting whichever appears first.
4. Bind exact input-manifest, dataset-contract, configuration, upstream, and component identities
   through the shared canonical input-set hash. Structural decoding is distinct from byte,
   claim, required-output, and accounting admission.
5. Put detailed unit outcomes and producer gaps in a referenced `appsec-review/job-outcomes/1`
   artifact. Derive and reconstruct it from verified task terminal receipts and declared producer
   fields, not recursively interpreted scanner payloads.
6. Preserve accepted `handoff.json`/`outcomes.json` and pointers. Failed diagnostics use separate
   `rejected-handoff.json`/`rejected-outcomes.json`; they never become accepted/latest evidence.
7. Retain detached, content-addressed native parser inputs and original result selectors. Retention
   attests retained bytes, not scanner origin. Distinct selectors/invocations survive normalized
   observation collapse; identical reference values may coalesce.
8. Reuse existing source-location and bounded SQLite/shard retrieval contracts. Common observation
   metadata adds a closed, safe projection without exposing raw reports or weakening ordinary
   payload redaction. Missing legacy provenance is a named gap.
9. Derive interchange metrics from verified publication and shared-receipt identities. Use closed
   dimensions, deduplicate events, retain completeness/integrity gaps, and never turn scanner
   observation volume into confirmed finding counts.

## Four implementation chunks

The shared dependency was committed first as `56f9e98e`: closed enums, wire records,
canonical identity helpers, and the runtime-owned native-output dataset namespace.
`bc508647` subsequently made serialization handle immutable mapping values without changing
the wire shape. Each implementation chunk used an isolated checkout and explicit file ownership.

| Chunk | Actual implementation |
| --- | --- |
| Runtime | `runtime/handoff.py` builds and verifies outcomes; runner publication emits `/2`, immutable rejected diagnostics, and handoff lifecycle events; resume rejects `/1` with `handoff_schema_changed`; storage admission binds effective target identity. Runtime implementation `9df23313` was integrated in `92f9aabc`. |
| Native scanner provenance | `provenance.py` retains, selects, verifies, and validates native results; static evidence, CodeQL SARIF, and produced-artifact scanners attach common metadata and publication receipts. Native integration checkpoint `e60aca51`. |
| Consumers and metrics | Operational handoff readers use common decoding and full admission; retrieval preserves validated common semantics/reference namespaces and projects explicit gaps for older observations. Integration `12266966` and projection reconciliation `02bf8118`; metrics `7820273f` adds run-metrics `/5` and interchange `/1`. |
| Documentation and schema | `6cd0c300` adds the offline Draft 2020-12 schema, executable identity examples, migration and operations guidance; follow-ups preserve immutable accepted history and document final receipt keys. This record and source reconciliation complete the documentation chunk. |

Parent integration owns cross-chunk wiring and full regression. No chunk pushes or opens a PR
as part of this local implementation handoff.

## Reconciliations against source

The accepted envelope remains extensible; shared references, observation metadata, coverage,
unit outcomes, and producer gaps are closed. The JSON Schema uses local references only.
Artifact bytes, input-set equality, unique artifact paths, selector resolution, topology and
coverage accounting remain application checks, not properties implied by schema validation.

Runtime hardening `177446e3` binds actual frozen configuration files as artifacts, distinguishes
source identity metadata from declared run-artifact references, and completes required-index and
input-manifest consumption before freezing publication closure. Publication I/O failures trigger
restoration attempts for both accepted/latest pointers; a rollback error is an explicit note on
the original failure, not silently reported success. Mixed successful scopes with unavailable
subscopes remain partial rather than making the entire successful unit unavailable.

Final runtime reconciliation distinguishes scoped binary `run_path` from display `path` and keeps
source inventories as source metadata even for target-relative `data/*` paths. Canonical prepared
claims and reused dispatch bindings verify in strict mode as well as managed mode. Malformed
producer arrays fail accepted accounting but produce safe rejected diagnostic gaps. Idempotent
finalization verifies accepted immutable state before reuse. Analysis-plan counters are named
`disposition_counts`; `dispositions` remains a typed array rather than accepting a count map.

`tests/handoff_fixture.py` now creates actual synthetic task result/status receipts, claim,
frozen configuration, result publication, and canonically reconstructed outcomes. It does not
silently convert production `/1` handoffs or substitute hashes for changed artifacts.
The architecture example separately labels its accepted document as a wire-only synthetic fixture;
operational publication still uses the runtime.

Static evidence uses `appsec-review/static-tool-evidence/2` and `static-evidence/4`. CodeQL uses
`appsec-review/codeql-sarif-normalizer/3`; database/query checkpoint identities stay unchanged.
Produced-artifact records retain `appsec-review/artifact-security-record/2` and observation `/1`,
with findings `/2`, parser `/3+<policy-identity>`, and normalizer `/2`.

The final hardening does not change the settled root format versions:

| Root format | Versioned schema |
| --- | --- |
| Shared publication/accounting | `appsec-review/job-handoff/2`, `appsec-review/job-outcomes/1` |
| Shared observation/provenance | `appsec-review/observation/1`, `appsec-review/native-result-reference/1`, `appsec-review/producer-gap/1` |
| Input identity | `appsec-review/job-inputs/1` |
| Retention/validation receipts | `appsec-review/native-output-retention/1`, `appsec-review/observation-provenance-validation/1` inside `appsec-review/shared-receipt/1` |
| Producer domain publications | `appsec-review/static-tool-evidence/2`, `appsec-review/codeql-analysis-handoff/1`, `appsec-review/artifact-security-analysis/1` |
| Produced-artifact domain records | `appsec-review/artifact-security-record/2`, `appsec-review/artifact-security-observation/1` |
| Metrics | `appsec-review/run-metrics/5`, `appsec-review/interchange-metrics/1` |

Artifact parser-input retention is distinct from diagnostic stream capture:
`parser_input_limit_bytes = 67108864` is a positive configured bound. Overflow is explicit
incompleteness/coverage loss, not an unretained complete report presented as verifiable provenance.
Partitioned static scans cite original invocations; CodeQL cites original SARIF result pointers;
BLint finding provenance cites its original findings report rather than only the assembled report.
Failure, timeout, and no-package paths retain bounded available reports with their actual
completeness. Failed CodeQL SARIF remains diagnostic-only, not normalized findings. Artifact
`SKIPPED_NA` paths retain native/execution closure; diagnostic truncation and missing execution
provenance stay explicit. Compact Grype/Syft/BLint projections keep raw result identities without
embedding bulky native records. Empty JSON fails parsing, and source hashes are checked before
static shard reuse. Native lifecycle events explicitly carry the publication owner's actor
identities; reference/byte work counters include verified reuse consumption, not fresh execution.

The common retrieval projection preserves the semantic `secret` class and validated selectors
and references. Arbitrary payload fields remain redacted. A malformed common record fails;
an absent common record can receive a legacy semantic projection only with unavailable provenance.
This does not make old handoffs operationally admissible.

Metrics consume `HANDOFF_*.handoff_reference`, `NATIVE_OUTPUT_RETAINED.retention_receipt`, and
`OBSERVATION_PROVENANCE_VALIDATED.provenance_receipt`. Receipt computation, bytes, actor identity,
dependencies, and publication accounting are checked before rollup. Reference counts differ from
distinct artifact counts/bytes; identical reference coalescing differs from preserving distinct
observation-to-result edges. Reuse is not fresh scanner execution.

## Verification and limits

Local focused verification at source checkpoint `0369ac27` (parent `4798b33a`, the exact
`7820273f` metrics patch, and final runtime/consumer/native patches listed above):
**237 passed, 2 skipped** across `test_interchange_contract`,
`test_interchange_schema`, `test_handoff_fixture`, `test_handoff_interchange`,
`test_native_result_provenance`, and `test_interchange_consumers`. The two skips require actual
Windows symlink privileges. The suite includes offline schema checks and all five executable
architecture example documents.
The earlier pre-hardening checkpoint `ad752a42` passed 201 tests with the same two symlink skips;
these are checkpoint-specific results, not additive totals.

The initial documentation-only pass also validated 50 positive/negative shared-record cases
and local links in owned changed pages. The documentation/skill/docs-sync test group had
10 passes and two known environment/baseline failures: absent untracked
`targets/appsec-multi-vuln/support/project-matrix.json` and `targets/appsec-multi-vuln/README.md`
links, and Windows `WinError 1314` in the runtime-skill symlink rejection test. Neither was
repaired by changing unrelated documentation, target checkouts, or security checks.

Final parent regression results will be recorded separately from these local results. No live
scanner images, real target review, Dagster deployment acceptance, or performance threshold is
established by synthetic/unit verification. Native provenance is implemented for the concrete
three-lane slice, not universally for every producer. Retention computations do not attest
scanner origin; protected raw output remains outside inference retrieval.

No external standards exporter is included. SARIF remains native CodeQL ingestion. Any future
standards export must be a derived accepted-evidence view; OpenVEX product-impact statements
require explicit product/version/vulnerability identity and evidence-bound adjudication, never
`not_affected` inferred from zero, failed, disabled, inventory-only, or truncated results.
CycloneDX and SPDX remain specialty SBOM formats, not replacements for the domain outputs.

Contract and operational details: [job interchange](../architecture/job-interchange.md),
[telemetry](../architecture/telemetry.md#interchange-instrumentation), and
[metrics](../operations/metrics.md#interchange-troubleshooting).
