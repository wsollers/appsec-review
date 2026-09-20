# schemas

`intake.schema.json` defines Phase 1 identity, scope, native applicability and planned-job output.
The shared adapter additionally recomputes semantic expectations and validates provenance/freshness
before accepting or reusing an intake artifact; schema validity alone is insufficient.

JSON Schema for the common finding/evidence/interjob-transfer format (added 2026-09-19):

- `evidence-citation.schema.json` -- the atomic citation unit (tool output, source file, upstream lane, manual diagnostic, or reference data), with an optional content hash for stale-evidence detection.
- `finding.schema.json` -- one claim: standard_refs (CWE/ASVS/CIS/ATT&CK/CAPEC, all optional), evidence_citations, a taxonomy-scoped classification (see verdict-taxonomies.json), attack_scenario narrative (no remediation code -- that's 11-remediation-proposal's job), and requires_executed_verification/executed_verification for the executed-vs-manual-confidence question raised in the harness doc.
- `lane-status.schema.json` -- forward-looking replacement shape for a lane's status.json, with findings[]/artifacts_read[] as the intended single source of truth (no separate freehand tally to drift from the real content -- see the 07/08 scenario-count bug). additionalProperties:true and findings/artifacts_read optional-but-validated-if-present during migration; existing lanes 00-09/13/15 predate this and are not expected to already conform.
- `handoff-transfer.schema.json` -- what create_handoff.py should validate before naming an upstream artifact as available in a ## Upstream Outputs section (the "validate on read" half of the schema-validator wiring).
- `worker-result-envelope.schema.json` -- the versioned terminal result shared by deterministic, container, persona, pool, controller, and supplied-decision workers. Cross-field skip, gap, retry, acceptance, and supersession rules are enforced by `worker_result.py`; `validate_job_output.py` adds run/job ownership, input freshness, in-attempt artifact hashes, registry-required files, and exact-edge skip authorization.
- `ossf-scorecard-results.schema.json` -- normalized published-results ingestion records. Contract-specific validation additionally ties records to staged requests and raw response hashes.
- `verdict-taxonomies.json` -- not a JSON Schema itself, a curated registry of named verdict vocabularies (adversarial-verdict, static-hardening, memory-safety-disposition, cve-reachability) that finding.classification is checked against, keyed by finding.classification_taxonomy. Different lane families genuinely need different verdict language; this keeps that real difference structured instead of forcing one global enum or letting each lane's prose drift independently.

Composable review schemas (added for the registry/worklist layer):

- `repository-partition-map.schema.json` -- coarse repository areas, evidence, developer/DevOps/SRE review routes, relationships, scope dispositions, and inventory coverage gaps. Cross-record IDs, path containment, and semantic claim rules remain job-validator responsibilities.
- `project-discovery.schema.json` -- project roots, manifests, lockfiles, candidate build environments, bounded command plans, evidence citations, and explicit coverage gaps. It describes supplied project analysis; it does not make persona dispatch executable.
- `persona.schema.json` -- reusable reviewer stance, assumptions, inputs, outputs, and hard boundaries.
- `role.schema.json` -- reusable work function such as intelligence extraction, standards validation, or platform hardening validation.
- `domain.schema.json` -- reviewed surface, common failure modes, standards context, and evidence hints.
- `tooling-profile.schema.json` -- allowed evidence/actions and claim limits, including static-only boundaries.
- `output-contract.schema.json` -- required files, status fields, validation rules, and an optional
  one-artifact result-schema identity plus an optional claim-class declaration for a composed job.
  Optional declarations preserve historical contract readability.
- `job-template.schema.json` -- dispatchable lane job composition.
- `standard-control.schema.json` -- per-control standard record with upstream source lineage.
- `standards-worklist.schema.json` -- per-component or per-platform checklist work items.
- `reference-source-lock.schema.json`, `reference-snapshot-manifest.schema.json`, and
  `reference-snapshot-file.schema.json` -- immutable OWASP/OpenCRE source selection, file hashes,
  license identity, extraction lineage, counts, and offline validation receipts.
- `standard-selection.schema.json` -- named engagement approval and exact snapshot/profile pinning.
- `nvd-snapshot-manifest.schema.json`, `nvd-current-pointer.schema.json`, and
  `nvd-writer-lease.schema.json` -- immutable NVD JSON 2.0 lineage, atomic last-good publication,
  and singleton writer diagnostics.
- `owasp-control-record.schema.json`, `owasp-test-record.schema.json`, and
  `owasp-context-record.schema.json` -- assignable ASVS/MASVS controls, MASTG tests, and Top 10
  routing context without implying a target verdict.
- `opencre-crosswalk-record.schema.json` and `owasp-source-citation.schema.json` -- OpenCRE
  navigation/deduplication records and exact raw snapshot citations. Crosswalks are not proof.
- `component-tag-cloud.schema.json` -- component tags used to route standards and persona work.
- `intelligence-payload.schema.json` -- scrubbed doc/test/API intelligence facts with source lineage.
- `design-parity-manifest.schema.json`, `design-parity-job.schema.json`, and `design-parity-capability.schema.json` -- the machine inventory that generates the lifecycle/readiness views and reconciles design claims with executable repository state.

Validated by `appsec-review-process/schema_validate.py` (a small dependency-free JSON-Schema-subset
engine -- type/required/properties/additionalProperties/enum/const/pattern/items/minItems/$ref --
plus the classification/classification_taxonomy cross-check against verdict-taxonomies.json that
plain JSON Schema can't express cleanly). No external `jsonschema` pip dependency, consistent with
the rest of appsec-review-process/*.py.

Still stub-only, unrelated to this effort, pending the foundational orchestrator layer: `lane-contract`
(per-lane YAML contract under contracts/), `component-purpose-map`, `index-manifest`,
`compile-command-audit`, `patch-policy`, `review-events` (the orchestrator's ledger/hash-chain event
shape). Those need orchestrator/ to exist first; the four files above do not -- they're usable by
review_cli.py/create_handoff.py today.
