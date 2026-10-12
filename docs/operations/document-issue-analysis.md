# Document issue analysis

`job_document_issue_analysis` runs after accepted review package assembly in `start`, `resume`,
and the Dagster `wave1_review` graph. Its single `analysis.map_and_adjudicate` unit verifies the
accepted package handoff and complete package set, then maps literal declared routes to
hash-checked source registrations. Bounds are typed in `appsec-review.toml`.

Read its accepted handoff at
`runs/<run-id>/data/jobs/job_document_issue_analysis/latest.json`; follow the verified handoff
artifact reference to `data/document-issues/<content-sha256>/ledger.json`. The ledger keeps
document evidence, source mapping, proof obligations, mapping ambiguity, and coverage gaps.
It is private candidate material. `findings` and `scoring_inputs` are empty until independent
review and finding publication are implemented. An empty finding list says nothing about target
security. Changed accepted source bytes, package bytes, or handoff hashes stop the job rather
than creating a clean result.
