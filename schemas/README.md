# schemas

`intake.schema.json` defines Phase 1 identity, scope, native applicability and planned-job output.
The shared adapter additionally recomputes semantic expectations and validates provenance/freshness
before accepting or reusing an intake artifact; schema validity alone is insufficient.

JSON Schema for the common finding/evidence/interjob-transfer format (added 2026-09-19):

- `evidence-citation.schema.json` -- the atomic citation unit (tool output, source file, upstream lane, manual diagnostic, or reference data), with an optional content hash for stale-evidence detection.
- `finding.schema.json` -- one claim: standard_refs (CWE/ASVS/CIS/ATT&CK/CAPEC, all optional), evidence_citations, a taxonomy-scoped classification (see verdict-taxonomies.json), attack_scenario narrative (no remediation code -- that's 11-remediation-proposal's job), and requires_executed_verification/executed_verification for the executed-vs-manual-confidence question raised in the harness doc.
- `lane-status.schema.json` -- forward-looking replacement shape for a lane's status.json, with findings[]/artifacts_read[] as the intended single source of truth (no separate freehand tally to drift from the real content -- see the 07/08 scenario-count bug). additionalProperties:true and findings/artifacts_read optional-but-validated-if-present during migration; existing lanes 00-09/13/15 predate this and are not expected to already conform.
- `handoff-transfer.schema.json` -- what create_handoff.py should validate before naming an upstream artifact as available in a ## Upstream Outputs section (the "validate on read" half of the schema-validator wiring).
- `verdict-taxonomies.json` -- not a JSON Schema itself, a curated registry of named verdict vocabularies (adversarial-verdict, static-hardening, memory-safety-disposition, cve-reachability) that finding.classification is checked against, keyed by finding.classification_taxonomy. Different lane families genuinely need different verdict language; this keeps that real difference structured instead of forcing one global enum or letting each lane's prose drift independently.

Composable review schemas (added for the registry/worklist layer):

- `repository-partition-map.schema.json` -- coarse repository areas, evidence, developer/DevOps/SRE review routes, relationships, scope dispositions, and inventory coverage gaps. Cross-record IDs, path containment, and semantic claim rules remain job-validator responsibilities.
- `persona.schema.json` -- reusable reviewer stance, assumptions, inputs, outputs, and hard boundaries.
- `role.schema.json` -- reusable work function such as intelligence extraction, standards validation, or platform hardening validation.
- `domain.schema.json` -- reviewed surface, common failure modes, standards context, and evidence hints.
- `tooling-profile.schema.json` -- allowed evidence/actions and claim limits, including static-only boundaries.
- `output-contract.schema.json` -- required files, status fields, and validation rules for a composed job.
- `job-template.schema.json` -- dispatchable lane job composition.
- `standard-control.schema.json` -- per-control standard record with upstream source lineage.
- `standards-worklist.schema.json` -- per-component or per-platform checklist work items.
- `component-tag-cloud.schema.json` -- component tags used to route standards and persona work.
- `intelligence-payload.schema.json` -- scrubbed doc/test/API intelligence facts with source lineage.

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
