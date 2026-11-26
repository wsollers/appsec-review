---
title: "final_report_publication"
kind: "operations"
subsystem: "reporting and metrics"
status: "current"
jobs: ["job_final_report_publication"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---

# final_report_publication

## Purpose

Publish deterministic JSON, Markdown, HTML and executive PDF projections of the accepted final gate. The report
separates publishable confirmed findings, verification backlog, withheld packages, coverage and
completion limitations. It does not reassess vulnerabilities, upgrade assurance, resolve findings
from build checks or turn a publication status into permission to ship.

<!-- generated:begin job=job_final_report_publication -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

final_report_publication

Job: `job_final_report_publication`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_report_publication/job.py#L220) |
| `load` | `load.accepted_gate` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_report_publication/job.py#L104) |
| `report` | `report.assemble` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_report_publication/job.py#L118) |
| `report` | `report.render` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_report_publication/job.py#L171) |
| `report` | `report.render_pdf` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_final_report_publication/job.py#L198) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_final_publication_gate` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_final_publication_gate` | `publication_gate_decisions` | `appsec-review/final-publication-gate/2` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `final_report_publications` | `acceptance` | `appsec-review/final-report/4` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `final_report_sarif` | `report` | `application/sarif+json;version=2.1.0` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `final_report_sarif_accounting` | `report` | `appsec-review/sarif-export-result/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | `tests/test_final_report.py::test_report_json_is_schema_valid_and_contains_the_required_sections` |
| integration | None declared |
| live | None declared |
| unit | `tests/unit/reporting/test_sarif_projection.py`<br>`tests/unit/reporting/test_sarif_export.py`<br>`tests/unit/job_final_report_publication/test_report_outcomes.py`<br>`tests/test_final_report.py::test_schemas_are_valid_draft_2020_12_with_the_final_report_id`<br>`tests/unit/job_final_report_publication/test_contract_and_settings.py`<br>`tests/unit/job_final_report_publication/test_job_units.py`<br>`tests/unit/job_final_report_publication/test_report_and_render.py`<br>`tests/unit/job_final_report_publication/test_report_custody.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_final_publication_gate`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_final_report_publication"]
  producer0["job_final_publication_gate"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_final_publication_gate"]
  input1["publication_gate_decisions"]
  input_schema1["appsec-review/final-publication-gate/2"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  output0["final_report_publications"]
  output_schema0["appsec-review/final-report/4"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["final_report_sarif"]
  output_schema1["application/sarif+json;version=2.1.0"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["final_report_sarif_accounting"]
  output_schema2["appsec-review/sarif-export-result/1"]
  job --> output2
  output2 -. schema .-> output_schema2
```

<!-- generated:end -->

## Process

The [handler](../../src/appsec_review/jobs/job_final_report_publication/job.py) uses the certified
[gate reader](../../src/appsec_review/jobs/job_final_publication_gate/verify.py),
[report projection](../../src/appsec_review/jobs/job_final_report_publication/report.py) and
[Markdown renderer](../../src/appsec_review/jobs/job_final_report_publication/render.py).

### `load`

1. In `load.accepted_gate`, require the accepted gate handoff to match the attempt's upstream pin.
2. Verify its document and all certified bindings against the gate/review schemas. Retain gate
   handoff/document references, review status, package counts and binding count.
3. Fail on missing or changed accepted material; do not discover substitute attachments.

### `report`

1. In `report.assemble`, read the bound gate and verified configuration-profile identity.
   Build report sections from certified gate data without changing package state, scoring,
   independence, shipment or nonexecution assurance.
2. Validate the report schema and write attempt-owned `final-report.json`. Keep publishable
   findings, verification backlog and withheld records in separate sections. The same task writes
   protected `findings.sarif` and `sarif-export-result.json`, retaining export omissions and the
   gate's scoped gap records.
3. In `report.render`, render Markdown from that JSON and the gate-certified private format
   references using configured evidence/gap display bounds. Load only the gate-certified dossier JSON for executive HTML's bounded narratives,
   using the same projection as executive LaTeX. Require repeat rendering to produce identical text.
4. In `report.render_pdf`, render the executive LaTeX source with gate-bound dossiers and, when
   configured, invoke the pinned PDF tool. Unknown metrics remain N/A in the source; the receipt
   distinguishes rendered, disabled and failed outcomes.

Executive HTML/PDF use the [technical report presentation](final-report.md#the-executive-pdf):
compact summary, technical finding narratives, per-finding attack-path evidence/unknowns, separate
backlog/withheld packages, and coverage/provenance. The PDF's executive-only mounted skeleton uses
pageable prose/tables rather than the shared diagnostic renderer's cover and radar. Missing
source-resolved ordered calls, verified advisory linkage, CVSS vectors and date-pinned FIRST EPSS
are explicit unavailable states, never inferred from labels or filled with mockup data.
The separate telemetry report, scoring/adjudication policy, model settings and producer contracts
are unchanged. The three actual executive template files are hash-bound in its PDF receipt.

Optional SARIF enrichment is reported separately from completion gaps. The existing SARIF
properties bag holds `optional_capability_limitations`: at most one `codeFlows` and one `fixes`
limitation per supplied finding, each with `finding_id`, `capability` and a bounded reason
(300 characters maximum). The list is deterministic and covered by the SARIF hash and
publication's byte-for-byte reassembly. Removing its metadata fails publication verification.
The export-result schema and telemetry counters are unchanged: measured emitted-codeflow/fix
counts remain zero when none were exported, not counts of review failures.

Absent ordered traces, unavailable or unqualified fixes, absent exact patches and intentionally
redacted/truncated patch projections are optional limitations. Missing required validation/patch
bindings, ambiguous validation records, unsupported required patch formats, omitted whole finding records and real gate gaps
remain completion gaps; changed or incoherent bound material remains an integrity failure.
This is an explicit classification at the adapter, not a filter suppressing every omission-like
gap name. Qualified exact fixes still export with their original assurance.

The current report is `final-report/4` with `security-radar-tracker/2` (T-5088, T-5139, T-5140). Unknown
exposure/inspection/corroboration and undefined derived metrics are `null` with named reasons, displayed
as **N/A** across formats and omitted from chart geometry. Measured zero remains numeric.
Advisory reachability likewise remains unavailable without a gate-certified measurement; neither
finding confirmation nor imported packages is substituted for that missing input.
The gate supplies no per-domain exposure/inspection telemetry; package density and lane-B
coverage-cell counts cannot substitute for it, and report assembly gains no new upstream read.
Accepted package counts likewise cannot establish scanner-lead corroboration. Missing corroboration
is a metric-local `corroborated_leads_unknown` reason, not a change to independently measured
coverage or an inferred zero. The known package bucket counts remain separate.
Unconfirmed backlog and withheld packages remain gaps even when an explicit population is
fully inspected. Active chains use certified `component_claim_ids` and count each publishable
member once without changing standalone severity. See
[domain coverage and legacy reads](final-report.md#domain-coverage-and-unknown-measurements-t-5088).

All formats retain the report's certified `attack_chain_cards`, including composed severity and
gap counts. They never substitute member severity. Historical absence of cards uses an unrated
fallback; an explicit empty card list stays empty. HTML and PDF-source rendering fail on
changed, missing, malformed or identity-mismatched claimed dossiers. A pure render without loaded
dossiers retains the certified reference count and names the not-loaded narrative gap.
This does not expose protected source excerpts, patch text or generated payloads.

Executive verification wording follows the recorded `independence.independent` flag, separately
from the unchanged accepted finding state. An explicit false flag never becomes “yes” merely
because state is `confirmed`; absent independence is unknown. Same-provider/model verification
can still be independent under R6. Model distinctness remains a separate ship-block condition.
The contradictory confirmed/false fixture is supported by the finding/gate schemas and serializers;
ordinary R5 adjudication requires independence to confirm and otherwise retains supported evidence
in the backlog. This renderer qualification does not establish a reachable contradictory accepted
ledger, change that policy or introduce another verifier (FR-U01 / T-5238).

Private rendering receipt `/2` adds exact Markdown/HTML references without expanding the public
four-key dossier map. Both the receipt and every additional reference must belong to the
accepted gate binding set. Legacy `/1` is read without certifying absent formats or guessing
sidecar paths. JSON keeps the receipt link; Markdown/HTML/LaTeX list only verified references.
See [private format custody](dossier-publication.md#private-format-custody).

### `acceptance`

1. In `acceptance.publish_handoff`, reverify the gate snapshot and report schema.
2. Re-render Markdown from JSON plus its certified format references and HTML/LaTeX from JSON plus the same bound dossier projection;
   require byte equality and require report provenance to name the loaded accepted gate handoff.
3. Publish hash-bound references with unchanged statuses, counts and limitations. The handoff
   item count is publishable plus backlog, not the total including withheld.

## Dataflow

```mermaid
flowchart LR
  job["job_final_report_publication"] --> load["load.accepted_gate"]
  gate["job_final_publication_gate / publication_gate_decisions"] --> load
  load --> assemble["report.assemble"]
  assemble --> json["final-report.json"]
  assemble --> sarif["findings.sarif + sarif-export-result.json"]
  json --> render["report.render"]
  render --> md["final-report.md"]
  load --> dossier["Hash- and identity-checked dossier JSON"]
  load --> formats["Certified private receipt + format refs"]
  dossier --> render
  formats --> render
  render --> html["final-report.html"]
  dossier --> pdf["report.render_pdf"]
  formats --> pdf
  json --> pdf
  pdf --> tex["final-report.tex / PDF outcome receipt"]
  json --> accept["acceptance.publish_handoff"]
  md --> accept
  html --> accept
  tex --> accept
  sarif --> accept
  accept --> out["final_report_publications"]
  gate -. "gap / not_run / notice retained" .-> accept
  accept -. "binding or rerender mismatch" .-> reject["reject publication"]
```

The [input contract](../architecture/job-input-contracts.md#admission-and-read-receipts) confines
this job to certified artifacts. Rendering does not grant payload retrieval access or bypass
[signing enforcement](signing.md).

## Gaps

The projection retains the gate's limitation IDs and statements unchanged in report JSON.
SARIF accounting carries each `gap` limitation as a `producer-gap/1` record, scoped by that
limitation ID; it supplies no new retryability classification. Publication reuses those records,
not an additional string copy of each gate limitation. PDF-unit gaps likewise retain their
canonical records when forwarded to publication, so runtime outcome aggregation counts each once.
The [gate gap table](job_final_publication_gate.md#gaps) names those causes.
`not_run` and `notice` remain separate report limitations. In particular,
`compile_only_nonexecution` is not a claim that runtime checks passed.

Ledger `gap_ids`, gate limitation counts, capability counts, radar-domain gaps and named gap rows
describe different populations and are not additive. For example, `review_degraded` and
`gaps_recorded` may both describe the same ledger population without duplicating ledger identities.
Repeated records for one ledger gap already collapse in the ledger; different subject scopes
remain different gaps, even with identical reason text. The T-5227 repair removes a proved
publication/forwarding duplication, not those distinct scope summaries or CodeQL seed counters.

Radar gap reasons describe unavailable domain measurements separately from the gate's
canonical producer limitations. `surface_exposure_unknown`, `inspected_units_unknown`,
`no_domain_coverage_bound`, `uninspected_exposed_units`, `verification_backlog_unconfirmed`
and `withheld_packages` prevent unavailable or unresolved scope from becoming verified-no-findings.
An aggregate confidence value without all domain percentages is N/A with
`domain_coverage_unknown`. Historical report `/2` and radar `/1` remain readable under their
original schemas and are labelled legacy estimates; no accepted artifact is rewritten.

Gate/reference corruption, schema mismatch and Markdown unequal to a fresh rendering raise
integrity errors and prevent publication. Use the handoff's verified
[canonical outcomes](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope)
for walk counts, not repeated Markdown gap labels. The accepted handoff's `pdf` field carries
the renderer receipt's actual outcome, not the pre-render declaration in `final-report.json`.

## Acceptance

1. **A. Inputs:** Compare the accepted gate handoff/document hash with the claim and report
   provenance. Verify the bound configuration profile and every certified attachment reference.
2. **B. Independent comparison:** Independently count gate bucket memberships and compare with
   report findings, backlog and withheld IDs. Compare state, score, ship-block and limitation
   fields with the gate. Re-render Markdown with the frozen settings and compare exact bytes;
   verify handoff item count excludes withheld.
3. **C. Gaps:** Reconcile canonical outcomes with the gate's gap limitations and ledger/coverage
   counts. Record presentation truncation and `not_run`/notice limitations separately.
   Publication with limitations is not a clean review.
4. **D. Baseline:** Save an authorized `stepwise.py accept` baseline and corpus namespace, with
   gate, JSON and Markdown hashes, bucket counts and display settings. Distinguish presentation
   changes from accepted-evidence changes on the next comparison.

## Resume and invalidation

The job has no model, independent result cache, or sub-job unit salvage. Whole-job
[runtime reuse](../architecture/jobs-and-runtime.md#wave-1-resumability) binds the accepted gate
pin, configuration (up to compatible `[operational.*]` tuning), dataset contract, target/input and
component identities; changed gate bytes or material display settings invalidate the report without
re-adjudicating the review, and any rerun re-executes as a whole in a fresh
`attempts/<attempt_id>/` workspace, revalidating bindings and rerendering Markdown/HTML/PDF. See
[job-local operational tuning](job-tuning.md) and [final-report](final-report.md#tuning-and-whole-job-recovery-job_final_report_publication).
