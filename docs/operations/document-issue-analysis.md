---
title: "Document issue analysis"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_document_issue_analysis"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
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

Both ledger and drift remain artifact-only. Their delivery to inference is tracked by
[T-5131](../TODO.md#t-5131-deliver-document-drift-through-the-actual-inference-retrieval-path);
declared consumption alone is not evidence that inference received them.
