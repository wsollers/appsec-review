---
title: "Document issue analysis"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_document_issue_analysis"]
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# Document issue analysis

`job_document_issue_analysis` runs after accepted review package assembly in `start`, `resume`,
and the Dagster `wave1_review` graph. Its single `analysis.map_and_adjudicate` unit verifies the
accepted package handoff and complete package set, then maps literal declared routes to
hash-checked source registrations. Bounds are typed in `appsec-review.toml`.

Read its accepted handoff at
`runs/<run-id>/data/jobs/job_document_issue_analysis/latest.json`; follow the verified handoff
artifact reference to `data/shared/objects/<exact-byte-sha256>`. The pointer is navigation, not
evidence: verify the handoff and its pinned artifacts. New attempts record computation or reuse
in `attempts/<attempt>/shared/document-issues/<computation-fingerprint>.json`, preserving the
original producer and the consuming invocation separately. Legacy
`data/document-issues/<content-sha256>/ledger.json` artifacts remain readable in place.
The ledger's internal `content_sha256` covers its JSON body without that field and is distinct
from the object store's exact-byte SHA-256. The ledger keeps
document evidence, source mapping, proof obligations, mapping ambiguity, and coverage gaps.
It is private candidate material. `findings` and `scoring_inputs` remain empty because this
document-candidate path does not commission independent review or finding publication; the
separate general inference and publication jobs already exist. See the
[authored job contract](job_document_issue_analysis.md). An empty finding list says nothing about target
security, so the job is always `COMPLETED_WITH_GAPS` and its first named gap says so. Changed accepted source bytes, package bytes, or handoff hashes stop the job rather
than creating a clean result.

## API declaration drift

The same unit recomputes `data/document-issues/<attempt-id>/drift-issues.json` on every
attempt, including ledger-cache hits. This separate `appsec-review/document-drift-issue/1`
artifact contains provisional navigation leads, not findings. Its receipt records
`specs_parsed`, `handlers_scanned`, mismatch counts and named coverage gaps.

Drift reads the accepted `job_target_catalog` documents' `document_kind`, `subtype`,
`fields` and exact source locations. Operation records are grouped by path, accepted
file hash and format before parsing. Source/document aliases share one hash-verified
byte read; each emitted operation cites its matching accepted document record, not
an arbitrary record from the same file. Distinct specifications keep distinct drift
identities. Conflicting accepted hashes or changed bytes stop analysis.

`max_source_files` bounds distinct attempted files across both source and document
reads, including failed reads; document-only inputs cannot bypass it.
`max_source_file_bytes` bounds each read. Parsing reuses the catalog's bounded
composition/tokenization (64 nesting levels, 200,000 events/tokens per specification).
Missing, oversized, undecodable, unsafe and truncated inputs, upstream catalog gaps,
parse failures and unresolved references remain named gaps. References are never
fetched and target code is never executed. A parse failure does not increment
`specs_parsed`; an empty result never implies complete coverage.

Literal registration/annotation heuristics cover the nine supported language families.
Guards, role arguments and anonymous annotations are local to the registration, its
attached PHP fluent middleware, or its annotation group. Comment-only separators do
not detach annotations; actual declarations and unrelated statements still end the group.
Nested registrations inside JavaScript, Go or PHP callbacks do not supply guards to the
outer registration. Rust lifetimes remain code, distinct from character/string literals.
Unrelated routes, comments, strings and early-file tokens are not global middleware.
Effective enforcement, dynamic mounts and handler behavior
remain explicitly unresolved. OpenAPI security alternatives retain anonymous options
and operation overrides; optional authentication does not become an auth mismatch.
Permitted `x-*` extension keys in OpenAPI `paths` are ignored, not rejected as routes.
HTTP method and same-line occurrence participate in matching, so documented GET cannot
hide POST and repeated registrations cannot become a unique ledger mapping.
An `ANY` registration leaves method coverage unresolved, rather than proving every
method documented. GraphQL root types and protobuf package/service/RPC context use the
canonical interface parser; implementation mapping for these non-HTTP operations is
an explicit gap, not an invented HTTP route.

## Bounded inference delivery

The ledger and drift payloads remain artifact-only. A separate `document_navigation` dataset
projects provisional mapping summaries and drift records into `precomputed/document-issues`,
queryable through `query_doc_drift` and `query_precomputed(query_set="document_context")`.
The producer publishes the shard, checkpoint and
`data/document-issues/<attempt-id>/retrieval-manifest.json` with exact hashes. The manifest
inherits the analyzed input set; the existing attempt-manifest merger supplies it to inference
after document analysis, without a new indexing/package-assembly dependency.

`max_source_files` also bounds projected records; the existing fact contract bounds each
record's evidence references to 32. Truncation is named, not clean coverage. Records retain
source/document identities, source-shard/file hashes, original payload hashes and analyzed
manifest identity. Consumers retain actual admitted-shard read receipts. A changed shard or
manifest fails closed; ordinary declaration-context shards alone produce a missing-drift gap.

Inference attaches matching source-unit records as bounded `control_context` without a control
assessment or scanner lead. The view marks them `provisional_navigation_lead`; existing
package/context bounds and hunt selection still apply, with explicit omission gaps. Unmapped
records remain queryable but cannot invent an implementation unit. No new tool or raw-stream
lookup is granted, and the original private ledger never enters confirmed findings or scores.


## Tuning and whole-job recovery: `job_document_issue_analysis`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.max_source_file_bytes` | `1048576` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_source_files` | `20000` | coverage | positive integer; exact parser/cross-field bounds† |

† The [executing job/parser](../../src/appsec_review/jobs/job_document_issue_analysis/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.analysis.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
