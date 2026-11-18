---
title: "Task plan T-172: Index threat models OWASP control gaps document drift and build mitigations"
kind: "task"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_document_issue_analysis", "job_inference_security_review", "job_owasp_control_assessment", "job_post_build_security_assessment", "job_review_data_indexing", "job_sanitizer_build", "job_threat_model_generation"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Task plan T-172: Index threat models OWASP control gaps document drift and build mitigations

This plan implements **T-172** (`docs/TODO.md`): eliminating remaining dead-end analytical
producers by indexing threat-model trust boundaries (`job_threat_model_generation`), verified OWASP
ASVS control gaps (`job_owasp_control_assessment`), API/schema documentation drift
(`job_document_issue_analysis`), post-build binary hardening posture
(`job_post_build_security_assessment`), and sanitizer readiness metadata (`job_sanitizer_build`)
into `job_review_data_indexing` and `RetrievalCore` so downstream inference and reporting consume
every coherent signal.

## Problem and motivation

- `job_document_issue_analysis` previously had **zero downstream consumers** (`CONSUMED BY: none`)
  and detected mostly generic prose markers instead of high-value security drift between API
  specifications (OpenAPI/Swagger, GraphQL, Protobuf, security READMEs) and actual route handlers.
- `job_threat_model_generation` synthesized trust boundaries, attacker capabilities, and crown-jewel
  assets only *after* inference review or outside the indexed shards, preventing Lane B hunters and
  attack-chain analysts from querying trust boundaries during review.
- `job_owasp_control_assessment` projected unassessed rows into packages instead of indexing only
  subject-bound, verified `absent`/`weak` control gaps as actionable hunt obligations (`T-5006`,
  `T-5009`).
- `job_post_build_security_assessment` binary hardening deficits (missing `PIE`, `NX`, `Full RELRO`,
  stack canaries, `CFI`/`Fortify`) were under-connected to native memory-corruption exploitability
  scoring.

## Technical design and dataflow changes

1. **Upgrade `job_document_issue_analysis` to API/auth/spec drift detection:**
   - Extract declared endpoints, authentication schemes, role requirements, and input constraints
     from OpenAPI/Swagger (`openapi.yaml`/`.json`), GraphQL schemas, `.proto` service definitions,
     and security docs, cross-referencing `job_tree_sitter_ast` route/handler symbols to emit
     concrete spec-vs-implementation drift records (for example documented-authenticated endpoint
     missing auth middleware in code, or undocumented admin/debug route).
2. **Pre-review / dual-phase threat-boundary indexing (`job_threat_model_generation` &
   `job_review_data_indexing`):**
   - Derive structural trust boundaries, untrusted entry surfaces, data stores, and privilege tiers
     deterministically from catalog + CPG/CFG + CI/config facts for indexing into `RetrievalCore`,
     while enriching final threat-model diagrams with verified findings during final reporting.
3. **Verified OWASP control-gap projection (`job_owasp_control_assessment`):**
   - Filter indexed `control_evidence` strictly to assessed, subject-bound verdicts, promoting
     verified `absent` and `weak` ASVS controls into structured `control_gap` hunt obligations and
     executive compliance summaries.
4. **Complete shard registration in `job_review_data_indexing` & `RetrievalCore`:**
   - Ensure every shard carries `producer.job` (`T-164`) and register queryable precomputed/domain
     projections for `threat_model`, `owasp_controls`, `document_issues`, `build_security`, and
     sanitizer readiness metadata.

## Schema and telemetry specification

```text
New / updated versioned schemas:
- appsec-review/document-drift-issue/1     (spec_source_id, handler_source_id, drift_kind, auth_mismatch)
- appsec-review/owasp-control-gap/1        (asvs_id, model verdict: not_satisfied, resolving subject_spans[])
- appsec-review/threat-boundary-index/1    (trust_zones[], entry_surfaces[], privilege_transitions[])

Telemetry & metrics recorded per attempt:
- indexing.shards_registered_by_producer, indexing.entities_indexed_by_domain
- doc_drift.specs_parsed, doc_drift.handler_mismatches_found
- owasp.controls_assessed, owasp.verified_gaps_indexed, build_security.unhardened_binaries_count
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Update [`../operations/review-data-indexing.md`](../operations/review-data-indexing.md),
   [`../operations/document-issue-analysis.md`](../operations/document-issue-analysis.md),
   [`../operations/owasp-control-assessment.md`](../operations/owasp-control-assessment.md),
   [`../operations/threat-model-generation.md`](../operations/threat-model-generation.md),
   [`../operations/post-build-security-assessment.md`](../operations/post-build-security-assessment.md),
   `docs/docs-ledger.json`, and run `scripts/generate-docs.py` (confirming `job_document_issue_analysis`
   now shows `CONSUMED BY: job_review_data_indexing`).
2. **Full indexing for downstream inference:** Verify every new shard is registered in the
   accepted index manifest with `producer.job` and queryable via `query_precomputed`,
   `query_build_security`, `query_dataset_inventory`, and `resolve_evidence`.
3. **Fast, isolated unit tests (`<10s`):** Add code-level unit tests under
   `tests/unit/job_document_issue_analysis/`, `tests/unit/job_review_data_indexing/`, and
   `tests/unit/job_owasp_control_assessment/` covering OpenAPI-vs-handler auth drift, shard
   `producer.job` enforcement, OWASP `absent`/`weak` filtering, and `RetrievalCore` queries—`<10s`
   per test, zero external dependencies.
4. **Common querying & indexing skills doc alignment:** Reconcile the new precomputed domains and
   query patterns in [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md).
5. **Frontier prompting, roles & skills alignment:** Document how `hunter`, `independent_verifier`,
   and `owasp_assessor` consume indexed trust boundaries, OWASP control gaps, and spec drift as
   leads requiring source-line proof (`governing-rules.md`).
6. **Metrics & telemetry:** Record per-domain entity counts, spec-drift hit counts, and assessed
   OWASP control ratios.
7. **Proper schema versioning:** Validate `document-drift-issue` v2, `owasp-control-gap` v2, and
   `threat-boundary-index` v1 at publication with replay compatibility.
