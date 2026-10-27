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
It is private candidate material. `findings` and `scoring_inputs` are empty until independent
review and finding publication are implemented. An empty finding list says nothing about target
security, so the job is always `COMPLETED_WITH_GAPS` and its first named gap says so. Changed accepted source bytes, package bytes, or handoff hashes stop the job rather
than creating a clean result.
