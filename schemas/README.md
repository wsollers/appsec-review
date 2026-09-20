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
- `owasp-intel-lane-in-request.schema.json`, `owasp-run-artifact-ref.schema.json`,
  `owasp-input-manifest.schema.json`, and `owasp-input-gaps.schema.json` -- the T03 OWASP workbench admission request, hash-pinned
  run-owned artifact references, and accepted raw/derived intelligence manifest. The contract is
  static/offline, rejects dynamic/network/mutation permissions, treats indexes as locators, and
  records stale-but-valid NVD as a gap rather than control or finding proof.
- `owasp-applicability-request.schema.json`, `owasp-applicability-citation.schema.json`,
  `owasp-applicability-signal.schema.json`, `owasp-applicability-decision.schema.json`, and
  `owasp-applicability-override.schema.json` -- the T04 request and closed decision primitives.
  They require typed positive signals, canonical citations, named authority, and an append-only
  assigned-reviewer override chain; absence is deliberately not a signal type.
- `owasp-applicability-row.schema.json`, `owasp-applicability-model.schema.json`,
  `owasp-applicable-controls.schema.json`, and `owasp-applicability-gaps.schema.json` -- the complete
  selected-control/component applicability matrix, its dispatch-eligible projection, and unresolved
  gaps. Cross-record validation enforces full Cartesian coverage, technical-N/A sufficiency,
  scope-owner-only `out_of_scope`, override continuity, bounded rescope actions, and exact T03
  lineage. These artifacts do not assess control satisfaction or establish findings.
- `owasp-batch-config.schema.json`, `owasp-batch-routing-rule.schema.json`, and
  `owasp-batch-request.schema.json` -- the T05 versioned limits, per-run deterministic proof-routing,
  exact T04 input, and component-group context. Limits are accepted only with a matching tracked
  qualification fixture; dynamic routes are request-only and manual observation is not authorized.
- `owasp-batch-proof-obligation.schema.json`, `owasp-crosswalk-lineage.schema.json`,
  `owasp-validation-worklist.schema.json`, and `owasp-batch-manifest.schema.json` -- routed proof
  obligations, pinned OpenCRE navigation lineage, complete one-row accounting, and
  bounded batch fragments. Cross-record validation enforces catalog hashes, pinned MASTG links,
  ordered routing specificity, limits, domain/evidence/tool/persona separation, mixed-mode joins,
  and the no-silent-skip invariant. Every T05 batch remains non-dispatchable and execution-disabled.
- `owasp-validator-handoff-request.schema.json`, `owasp-validator-handoff-config.schema.json`,
  `owasp-validator-handoff.schema.json`, and `owasp-validator-handoff-set.schema.json` -- the T06
  exact T05 input reference, versioned closed tool policy, one immutable non-dispatching handoff per
  batch, and complete batch-to-handoff accounting. Handoffs carry accepted T03/T04/T05 lineage,
  source/config/prompt/composition hashes, exact fragments and proof obligations, component evidence
  roots, allowed/prohibited tools and actions, authorization/claim boundaries, future result/intercom
  paths, and failure semantics. Static contracts do not authorize dispatch; dynamic contracts are
  inert request-authoring only, and manual observation remains blocked.
- `owasp-dynamic-execution-blocked-receipt.schema.json` -- the T06 fail-closed receipt for an
  explicit execute/launch request against a dynamic request-only batch. It records
  `dynamic_execution_disabled` and that no target contact or mutation occurred; it is not a launcher.
- `design-parity-manifest.schema.json`, `design-parity-job.schema.json`, and `design-parity-capability.schema.json` -- the machine inventory that generates the lifecycle/readiness views and reconciles design claims with executable repository state.

Threat-workbench schemas (ADR-0008 task T02, added 2026-09-20; schemas only -- no worker, contract,
registry record or validator is implemented by these files):

- `integrated-threat-model.schema.json` -- the canonical `03-threat-model-dfd-stride` result: DFD substrate (elements, flows, trust boundaries) plus typed overlays (data classes, deployment zones, abuse scenarios, attack trees, STRIDE hypotheses and per-flow STRIDE coverage), assumptions, gaps, rescope triggers, per-workcell coverage and preserved dissent. Every object is closed and every declared field is required (nullable where optional), so there is no field that can carry verified status, final severity, runtime exposure, compliance verdict, intent or remediation status. `OBSERVED_EXPOSURE` is schema-valid on purpose so the lane validator (T08) can reject it by name.
- `threat-model-*.schema.json` (citation, element, flow, trust-boundary, data-class, deployment-zone, abuse-scenario, attack-tree, stride-hypothesis, assumption, gap) -- the per-family record shapes, split into sibling files because `schema_validate.py` resolves `$ref` by filename only. Shared by the integrated model and by cell results.
- `threat-workbench-cell-result.schema.json` -- one persona workcell instance's terminal contribution: identity and prompt/model hashes, envelope terminal status, inputs read, a typed `model_delta`, and authored intercom record ids.
- `threat-workbench-intercom-record.schema.json` -- one append-only intercom record with author, target, subject ids, citations, status, resolution and a hash chain. Deliberately no `updated_at`.
- `threat-workbench-wave-manifest.schema.json` -- the frozen per-wave rendezvous manifest: expected instances (selected or omitted with reason) and hashed terminal results. The only channel between waves.

Cross-record id resolution, the completeness invariant, index-only citation rejection and claim-limit checks are lane-validator responsibilities, not expressible here.

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
