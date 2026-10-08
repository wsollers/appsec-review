# OWASP control-assessment workbench

The rebuilt workbench is a bounded, evidence-backed stage between accepted component/evidence/build
indexes and final finding-package synthesis. It assesses controls; it does not certify compliance.

## Authority and source model

`appsec-review.toml` pins the catalog path, canonical catalog SHA-256, upstream repository, immutable
commit, version/ref, and license for ASVS 5.0.0, MASVS 2.1.0, MASTG 2.0.0, OWASP API Security Top
10 2023, and OWASP Top 10 2025. ASVS and MASVS are the only control authorities. MASTG supplies
supporting mobile test procedures. The Top 10 catalogs provide risk/domain routing context and
cannot satisfy or replace a control.

The checked catalogs are intentionally small qualification fixtures. Every run-owned standards
manifest reports that limitation and a live-refresh gap. The workbench never fills missing control
text from model memory. Replacing a fixture requires a separately reviewed, normalized full catalog
with stable identities and an updated canonical hash in central TOML.

## Data flow and resumability

The visible stages are:

1. standards ingestion and profile selection;
2. bounded component characterization from accepted indexes;
3. a complete control × component applicability matrix;
4. deterministic batching and compact finding-package assembly;
5. four independent validator cells using the `owasp_validator` pool;
6. independent-verification/adjudication;
7. deterministic exactly-once join; and
8. immutable shard and handoff publication.

Each batch is fingerprinted from its exact applicability rows, component, domain, evidence mode,
required tools, assignment, and limits. A worker failure maps its rows to scoped `not_assessed`
gaps. Other cells remain valid. Re-running the failed cell with the same fingerprint is a bounded
resume, not a new assessment boundary.

## Characterization and applicability

Components, not individual files, are the classification unit. Deterministic signals run first.
Optional inference receives only bounded metadata and resolving citations; it cannot recursively
scan the target. Classifications retain target/project/component identity, confidence, ambiguity,
negative-evidence limits, citations, and input fingerprints.

ASVS is routed only to application/API/server, web, identity, and administrative application
components. MASVS/MASTG is routed only to Android/iOS components. Mixed repositories can therefore
select both standards without applying either standard to the wrong component. Technical
`not_applicable` requires a positive classification citation and a reason. Absence produces
`cannot_determine`, never N/A. Unauthorised runtime/manual obligations are
`unsupported_missing_evidence` and become explicit requests/gaps.

## Worker boundary and result trust

A finding package contains exact selected control text, one bounded component context, resolving
evidence references/excerpts, tool observations, allowed retrieval tools, proof obligations, and
prohibited claims. It never contains the target tree. Model output remains a proposed observation.
Validators must resolve citations to source lines or hash-pinned run artifacts before accepting a
control result. Static evidence cannot discharge dynamic or manual obligations. High, Critical, or
ship-blocking observations remain pending until an independent reviewer confirms them with cited
evidence. Conflicts and dissent remain in the joined result.

## Guidance and configuration placement

- Shared authority: `pipeline/prompt-fragments/governing-rules.md` only.
- Role responsibilities and optional domain viewpoints: `pipeline/guidance/registry.json`.
- Bounded questions: generated task records inside finding packages.
- Model, reasoning, token budgets, timeouts, retries, batch/component limits, worker counts, pool
  concurrency, and selected profiles: `appsec-review.toml`.
- Exact composed bundles: `runs/<run-id>/data/guidance/<bundle-sha256>/`.

Role/persona entries cannot carry authority fields. Assignment deterministically chooses one role
and zero or one persona; there is no persona per control.

## Immutable indexes and retrieval

The workbench publishes independently fingerprinted `standards`, `component-classification`,
`applicability`, `validation-work`, `finding-package`, and `control-result` JSON shards, then joins
them through one run-owned accepted manifest. The query adapter scopes by standard, version,
profile, control, component, project, evidence mode, validator, batch, disposition, and shard. Every
response carries run/index identity, pagination, truncation, ambiguity, and coverage gaps.

Component-specific fingerprints prevent a changed component from invalidating unrelated component
shards. Global standards, profile, configuration, retrieval-manifest, model, parser, and guidance
identities are still visible in dependent publications.
