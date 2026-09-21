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
- `critical-findings-sarif.schema.json` -- the exact SARIF 2.1.0 document emitted by `critical_findings_sarif.py`, a standalone registered format-transform job and deliberately not a `full_review` graph node (`docs/critical-findings-sarif-job.md`). Identity, level, location and structure are pinned; free-text copied verbatim from the validated finding document is intentionally unconstrained. Conversion success is never proof that a finding was verified.
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
- `owasp-control-assessment-request.schema.json`, `owasp-control-assessment-result.schema.json`,
  `owasp-proof-obligation-result.schema.json`, and
  `owasp-assessment-evidence-citation.schema.json`, plus
  `owasp-control-assessment-validation.schema.json` -- the T07 exact T06-member request, immutable
  accepted batch result, per-obligation outcomes, and canonical evidence/counterevidence records.
  Cross-record validation enforces exact fragment/target/component/control/obligation coverage,
  newest accepted handoff identity, evidence-mode sufficiency, canonical dereference, freshness,
  test-environment limits, contradictions, terminal-state mapping, closed tool/action use, and
  parser/static-analysis lineage. Schema validity alone does not make candidate evidence sufficient.
- `owasp-dynamic-test-candidate.schema.json` and
  `owasp-candidate-verification-route.schema.json` with their corresponding `*-set` schemas --
  inert proposed T07 follow-up contracts. They
  cannot authorize or record execution, contact or mutate a target, create a finding, or assign
  severity. Manual observation remains unauthorized.
- `owasp-intercom-append-request.schema.json`, `owasp-intercom-message.schema.json`,
  `owasp-intercom-citation.schema.json`, `owasp-intercom-ledger.schema.json`, and
  `owasp-intercom-validation.schema.json` -- the T08 exact-head append request, accepted message,
  canonical citation, immutable full-ledger snapshot, and validation receipt. Cross-record
  validation pins the newest T06 handoff and optional newest T07 result, enforces deterministic
  message IDs and sequence/hash-chain continuity, separates locators from canonical citations, and
  rejects authority expansion, prohibited claims, secrets, undeclared tools/actions, and
  dynamic/manual execution. Messages are untrusted communication records, never evidence.
- `owasp-dynamic-request-publication.schema.json`, `owasp-dynamic-manual-request.schema.json`,
  `owasp-dynamic-request-transition.schema.json`, `owasp-dynamic-request-ledger.schema.json`,
  `owasp-dynamic-request-validation.schema.json`, and
  `owasp-dynamic-execution-disabled-receipt.schema.json` -- the T09 offline request operation,
  accepted lifecycle version, separately supplied external-state authority shape, immutable
  version ledger, validation receipt, and fail-closed execute/launch receipt. Cross-record
  validation binds exact independently checked T06/T07/T08 lineage, protected deduplication
  dimensions, proof-obligation identities, prior accepted version/hash, legal transition and
  explicit authority. The baseline itself publishes only proposed, canceled, or blocked state;
  manual observation is always blocked. Other states require an exact artifact from a newest
  accepted external producer but do not
  mean T09 authorized or performed work, accepted evidence, changed T07, or contacted a target.
- `design-parity-manifest.schema.json`, `design-parity-job.schema.json`, and `design-parity-capability.schema.json` -- the machine inventory that generates the lifecycle/readiness views and reconciles design claims with executable repository state.

Threat-workbench schemas (ADR-0008 task T02, added 2026-09-20; schemas only -- no worker, contract,
registry record or validator is implemented by these files):

- `integrated-threat-model.schema.json` -- the canonical `03-threat-model-dfd-stride` result: DFD substrate (elements, flows, trust boundaries) plus typed overlays (data classes, deployment zones, abuse scenarios, attack trees, STRIDE hypotheses and per-flow STRIDE coverage), assumptions, gaps, rescope triggers, per-workcell coverage and preserved dissent. Every object is closed and every declared field is required (nullable where optional), so there is no field that can carry verified status, final severity, runtime exposure, compliance verdict, intent or remediation status. `OBSERVED_EXPOSURE` is schema-valid on purpose so the lane validator (T08) can reject it by name.
- `threat-model-*.schema.json` (citation, element, flow, trust-boundary, data-class, deployment-zone, abuse-scenario, attack-tree, stride-hypothesis, assumption, gap) -- the per-family record shapes, split into sibling files because `schema_validate.py` resolves `$ref` by filename only. Shared by the integrated model and by cell results.
- `threat-workbench-cell-result.schema.json` -- one persona workcell instance's terminal contribution: identity and prompt/model hashes, envelope terminal status, inputs read, a typed `model_delta`, and authored intercom record ids.
- `threat-workbench-intercom-record.schema.json` -- one append-only intercom record with author, target, subject ids, citations, status, resolution and a hash chain. Deliberately no `updated_at`.
- `threat-workbench-wave-manifest.schema.json` -- the frozen per-wave rendezvous manifest: expected instances (selected or omitted with reason) and hashed terminal results. The only channel between waves.

Cross-record id resolution, the completeness invariant, index-only citation rejection and claim-limit checks are lane-validator responsibilities, not expressible here.

Permission-capability schemas (backlog batch B11; model and validator only -- no worker, launcher,
graph, manifest or handoff consumes them yet, see `docs/permission-capabilities.md`):

- `permission-capability.schema.json` -- versioned capability *definition* (closed kind enum: target execution, fixed network destination, dynamic testing, debugger/ptrace, credential use, package restore, target mutation), its required typed parameters and `default_decision: DENY`. Records live in `appsec-review-process/registry/permission-capabilities/`.
- `permission-capability-parameters.schema.json` and `permission-capability-entry.schema.json` -- the closed, all-nullable exact parameter set (one scheme/host/port, one repository-relative path, a `cred:` reference id and never a value) and one capability instance with its required `origin`. `kind` and `origin` deliberately admit unknown and target-controlled values so `permission_capabilities.py` can reject them by name.
- `permission-requirement.schema.json` -- the exact capabilities one job requires.
- `permission-grant.schema.json` -- an ALLOW or DENY from a named human authority with issue/expiry timestamps, bound to one run and source snapshot (optionally one job).
- `permission-decision.schema.json` and `permission-decision-ui.schema.json` -- the GRANTED/DENIED decision with named reasons, the exact capability set and `fingerprint_material`, and its UI-safe projection.

Wildcard/widening detection, origin trust, staleness, conflict resolution, per-kind parameter exactness and secret rejection are `permission_capabilities.py` responsibilities, not expressible here.

Tool-instance aggregate schemas (ADR-0010 task V03, added 2026-09-20; shapes and a read-only
validator only -- no worker, contract, registry record or graph node consumes them yet; V04, V05, V07
and D09 reference them, V10-V13 emit them):

- `tool-results.schema.json` -- a family node's `outputs/tool-results.json`: one entry per
  attempt-bearing tool instance (ADR-0010 G1 = B) with tool id, its own attempt id, a terminal status
  pinned to the v1.0 envelope terminal set, identity, `argv`, exit semantics, output file hashes and a
  record count. `job_id` is a pattern, not a const, so every ADR-0010 node and D09's `02-source-sast`
  use the same file unchanged.
- `tool-instance-result.schema.json` and `tool-instance-identity.schema.json` -- the per-instance
  sibling shapes. Identity names an image by repository plus registry-resolved `sha256:` digest and
  has no tag field, so `:local` / `:latest` cannot be written; a `deterministic_python` instance
  carries an executable hash instead. Rule-pack / policy-bundle / database / reference-table
  identities each carry a sha256; `redactor` is nullable until V06 lands. `argv` is an array; there is
  no `command` or `shell` field. Exit semantics record the exit code, a closed `exit_meaning`, and
  the exact non-zero codes that mean "findings present" for that tool -- the fact the legacy runner
  hid behind `|| true`.
- `scan-coverage.schema.json` -- `outputs/coverage.json`: per-tool applicability, candidate /
  analyzed / not-analyzed / unsupported input counts with bounded path lists and closed reason codes,
  and the node's named gaps (closed `kind` enum).
- `applicability-probe-receipt.schema.json` -- the G5 detector-probe receipt: probe identity,
  snapshot identity, files examined, and per tool the detectors, patterns searched and matching-input
  counts. It is the supporting evidence for skip reason `not-applicable-no-matching-inputs`.

No field in this set can hold a raw match line: every string is a const, an enum or an anchored
whitespace-free pattern (paths are percent-encoded), and there is no message, snippet or free-text
field. The cross-record rules live in `appsec-review-process/tool_instance_shapes.py`
(`validate_node_aggregate`, every input required): a node cannot be `OK` with a non-`OK` instance or
any gap, cannot be `OK_WITH_GAPS` without a validated hashed output and a named gap for every
non-`OK` instance, cannot be `SKIPPED` without a receipt showing zero inputs for every declared
tool, and tool ids must agree across the node's declared tools and all three documents. That proves the documents
agree with each other; it cannot prove an output's `sha256`, `bytes` or existence, which are
statements about files. `verify_outputs_on_disk(tool_results, attempt_root)` (attempt root required)
binds them: every listed output stays inside the attempt, is a regular non-linked file with exactly
the listed size and hash, and is listed exactly once. Output paths must be normalized (no `.`,
`..`, empty or leading-slash segments), and ownership is keyed on the file's identity (device and
inode, else the resolved path), so an alias, a hard link or a different-case name cannot give one
file two owners. A worker calls both before
publication.

Vendor pre-pass result contracts (ADR-0010 tasks V04, V07 and V05, added 2026-09-20; schemas,
contract records and pure validator modules only -- no worker emits them, no graph node is declared
(V02) and `validate_job_output.py` has no claim-class policy or dispatch entry for any of the nine
contracts yet, so the shared validator does not accept them today). Every contract requires
`manifest.json`, `status.json`, `outputs/tool-results.json` and `outputs/coverage.json` (the V03
shapes above); V04 and V07 also require `outputs/redaction-receipt.json` (V06). All declare the three
`forbidden_promotions` `finding`, `severity` and `runtime-state`. All objects are closed and every
string is a const, an enum or a `\Z`-anchored pattern: there is no message, snippet, value or
free-text property.

- `secrets-inventory.schema.json` (+ `-entry`) -- `outputs/secrets-inventory.redacted.json`, claim
  class `secret_exposure_lead`. Entries are location fingerprints: tool, rule id, a closed
  `data_class` label (not `secret_kind` -- the redactor redacts the value under any secret-ish key
  name), confidence, path and line range, citation. No property exists for a value, a fragment, a
  per-value hash, a length, a column or line text. The node is always applicable, so `SKIPPED` is
  never a permitted status.
- `iac-config-evidence.schema.json` (+ `iac-config-rule-hit`, `iac-config-base-image-inventory`) --
  `outputs/iac-config-evidence.json` and `outputs/base-image-inventory.json`, claim class
  `declared_configuration_evidence`; also requires `outputs/applicability-probe-receipt.json`.
  Records are `rule_hits` (rule, closed category, resource address), not findings and not tool
  messages, which embed resource values; base images are `FROM` references as declared, split into
  closed fields. `OBSERVED_EXPOSURE` is schema-valid on purpose so the validator rejects it by name.
- `container-image-inventory.schema.json` (+ `-image`, `-config`) -- G8 = A, claim class
  `supplied_image_static_evidence`, probe receipt `outputs/container-image-applicability.json`. The
  only representable image source is a supplied archive (staged path plus sha256): there is no
  registry, pull, container-id or runtime property. Environment variable names only, never values;
  entrypoint and command are an executable plus an argument count.
- `mobile-sast.schema.json` (+ `-rule-hit`) -- G6 = A, claim class `mobile_static_lead`. The node
  carries its own platform-marker probe; its receipt `outputs/mobile-applicability.json` is a
  required file for every status including `SKIPPED`. A hit is a rule id, a closed category and a
  hashed source location.
- `binary-hardening.schema.json` (+ `-binary`) -- G7 = A, claim class
  `binary_hardening_property_evidence`, probe receipt `outputs/binary-hardening-applicability.json`.
  Closed format enum (`pe`, `elf`, `macho`, `unsupported`) and one closed verdict per mitigation
  (`present`, `absent`, `not-applicable-for-format`, `not-assessed`). There is deliberately no
  roll-up field and no `pass` value; verdicts are static properties of a supplied file, not
  statements about a built artifact or a running process.
- `sbom-inventory.schema.json` (+ `-component`, `-citation`, `-upstream-binding`),
  `sca-vulnerability-match.schema.json` (+ `-record`, `-database`, `-database-identities`,
  `-coverage-gaps`, `-gap-summary`), `license-inventory.schema.json` (+ `-record`) and
  `dependency-lifecycle.schema.json` (+ `-entry`, `-reference-table-identity`, `-reference-table`)
  -- the V05 SBOM-family contracts (ADR-0010 M1-M5; see `docs/sbom-family-contracts.md`). No
  severity, score, reachability, exploitability, fix or legal-conclusion property exists. An SCA
  match carries the database identity per citation, `match_basis` is `purl | cpe`, aliases are
  collapsed, and every SBOM component is either `evaluated` or a record in `sca-coverage-gaps.json`
  with a closed reason; `coverage-gap-summary.json` is the M5 aggregate. Age fields follow M4.
  Lifecycle `supported`/`end-of-life` exists only with the citing `table_row`.
  `02-license-scan` depends on `02-sbom-inventory`.

Receipt-first verification, cross-document header and status agreement, id resolution, caller
bindings, on-disk re-derivation (hashes, sizes, binary format from leading bytes) and sanitized
error text live in `appsec-review-process/secrets_iac_contracts.py`,
`container_mobile_binary_contracts.py` and `sbom_family_contracts.py`, which compose V03's
`validate_node_aggregate` / `verify_outputs_on_disk` and V06's `verify_receipt`; none of it is
expressible here. Known limit: `rule_id`, resource addresses and image repository/tag fields can
hold a short identifier-shaped string, so rule ids must come from a pinned rule pack, never from a
target's own tool configuration.

Evidence-index metrics (ADR-0010 G10 = B, task V15; consumed by `02-evidence-index`, see
`docs/evidence-index-metrics.md`):

- `evidence-index-metrics.schema.json` -- the `metrics` member of an `02-evidence-index`
  `manifest.json`, not a separate file: aggregate file, byte and line counts of the indexed
  snapshot by closed scope, closed language and content class, with `overall`, `by_scope` and
  `by_language` verified as projections of `groups`. Closed objects, every property required; no
  per-file record, path, timestamp, host path, tool version or duration. `descriptive_only` is the
  literal `true`: metrics are not evidence of coverage or analysis and introduce no claim class. The
  contract declares the member under the additive `member_schemas` key with `metrics_sha256` as its
  digest over one canonical byte form; projection, digest and snapshot binding are
  `evidence_store.check_metrics` responsibilities.

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

Redaction receipt (ADR-0010 Decision G9-A, task V06; module and validator only -- no worker,
publication runtime or `02-evidence-index` code consumes it yet, see `docs/evidence-redaction.md`):

- `redaction-receipt.schema.json` -- the `redaction-receipt.json` that `appsec-review-process/evidence_redaction.py` writes last into the directory it redacted: redactor identity (module version plus ruleset sha256), the required fail-closed policy, the limits in force, per-file records (path, `unchanged`/`redacted`/`withheld`, withheld reason, parser mode, hashes, redaction counts by kind, pre-existing markers), totals, the `unredacted_file_in_published_set: false` statement and `receipt_sha256`. Closed objects, every property required. Deliberately no property for a value, fragment, per-value hash, value length, line text or timestamp, and `source_sha256` is non-null only for an unchanged file (a source hash of a redacted file is an oracle for the removed value).

Disposition consistency, totals, ordering, the exact published file set and the fixed-point re-run over published bytes are `evidence_redaction.verify_receipt` responsibilities, not expressible here. `receipt_sha256` is an integrity check, not an authenticator.

SCA vulnerability-database identity (vendor pre-pass V09, ADR-0010 G3; resolver only -- no worker,
graph, manifest or contract consumes it yet, see `docs/sca-nvd-snapshot-binding.md`):

- `vulnerability-database-identity.schema.json` -- the verified identity of the published NVD snapshot that `02-sca-vulnerability-match` fingerprints and publishes as `outputs/vulnerability-database-identity.json`: snapshot id and chain, manifest and content sha256, retrieval timestamp and cursor, file count and bytes, age and the job's age policy (`no-limit` by default, or `within-limit` of a `max_age` the job set; a snapshot older than that limit is `FAILED` and has no identity record -- ADR-0010 M4; schema id `/2`), `match_basis: cpe` (true of the NVD database; the SCA match-record basis is V05's) and mandatory limitations. Since ADR-0010 M1 this database is no longer the SCA matcher's source; it serves `06-cve-reachability` enrichment and cross-checking. Closed, every property required. Produced only by `appsec-review-process/sca_nvd_snapshot.py` after a full offline re-hash; the hash, chain, containment and age-policy checks are that module's responsibility, not expressible here. It reads `nvd-current-pointer.schema.json` and `nvd-snapshot-manifest.schema.json` unchanged.

Pinned-container argv adapter (backlog batch B13; adapter and validators only -- no lifecycle worker,
graph, manifest or launcher consumes it yet, see `docs/pinned-container-adapter.md`):

- `container-image.schema.json` -- one registered image identity under `appsec-review-process/registry/container-images/`: fully qualified `repository` and immutable `sha256:` `digest` (index or manifest), purpose and provenance. There is deliberately no tag property and the repository pattern admits no tag.
- `pinned-container-request.schema.json` -- everything a caller may say to `container_execution.run_container`: run/job/attempt identity, `{image_id, digest}`, an `argv` array, an allow-listed `environment`, read-only `target_mounts` (`/workspace` or `/inputs/<name>`), run-owned `scratch_path`/`log_path`, `network` (`none` or exact granted destinations), the B11 `permission` block (`$ref` to the requirement, grant and decision schemas) and seven required integer `limits`. Closed, every property required; no property for a docker option, capability, device, user, working directory or writable target.
- `pinned-container-result.schema.json` -- the `container-result.json` written last into the log directory: adapter/boundary identity and `boundary_sha256`, request/image/permission hashes, run-owned container name, `execution_status` with a closed `cause` enum, exit code, timestamps, stream byte counts, the hashed log-file list (`request.json`, the child runner's four files and the adapter's `observation.json`), `container_removed` and `result_sha256`. No container output, docker error text or free text.

Argv/limit/port bounds, path identity (device+inode), registry resolution, the permission gate, status-by-cause consistency and the on-disk re-derivation (the whole recorded docker argv against one built from caller-supplied host facts, `events.jsonl` against `command.json`, retained logs against `observation.json`'s stream hashes, and `cause`/`exit_code` re-derived from both records) are `container_execution.py` responsibilities (`request_errors`, `checked_mount_sources`, `verify_container_result`), not expressible here. `result_sha256` is an integrity check, not an authenticator.

Persona invocation adapter (backlog batch B14; dispatch protocol and validators only -- no model
client, and no lifecycle persona job, graph, manifest or launcher consumes it yet, see
`docs/persona-invocation-adapter.md`):

- `persona-invocation-request.schema.json` -- everything a caller may say to `persona_invocation.run_invocation`: run/job/attempt identity, `invocation_role`, the pinned `invoker_id`, `outer_prompt` `{path, sha256, bytes}`, the `persona` composition (job template, persona, role, domain, tooling profile and output contract ids with record hashes), `model`, derived `tools` ids, seven required integer `budget` limits, exact `readable_inputs` (roles `handoff`, `evidence`, `reference`, `producer_output`, `producer_result`), run-owned `output_root`/`log_path`, allowed and prohibited claim classes, `producers` for the independence rule, the B11 `permission` block (`$ref` to the requirement, grant and decision schemas) and `permission_fingerprint_sha256`. Closed, every property required; no property for prompt text, a free-text tool, an absolute path, a permission string or a default model.
- `persona-model-identity.schema.json` -- `{provider, family, model_id, snapshot}`, all required. `persona-invocation-file.schema.json` -- `{path, sha256, bytes}` for one file by its single relative spelling.
- `persona-invoker-output.schema.json` -- the untrusted `invoker-output.json` an invoker writes last into the output root: identity echo, `usage`, `tool_calls`, every output file, claims with class, statement and citations, `verified_invocations`, location-only `injection_suspected` and `limitations`.
- `persona-invocation-record.schema.json` -- the adapter's `invocation.json`: request and package hashes, invoker id, call outcome, timestamps, the adapter's own scan of the output root and the two change flags. No invoker text.
- `persona-invocation-result.schema.json` -- the `invocation-result.json` written last into the log directory: adapter and independence-rule identity, `persona_id`, request/package/prompt/composition/input/permission hashes, model, `execution_status` with a closed `cause` enum, outcome, the re-derived output list, manifest hash, usage, emitted claim classes, the hashed log-file list and `result_sha256`. No prompt, evidence or invoker text. Budget limits are named `*_unit_limit`, not after the provider's word for them, because the evidence redactor replaces the value under any secret-looking key name.

Budget bounds, the model allow-list and alias rule, registry composition, derived tool ids and the claim-class ceiling, path identity (device+inode, one spelling), the independence rule and the binding of each declared producer to its pinned `invocation-result.json` bytes, the permission gate, the lexical prohibited-claim rules, cause precedence and the on-disk re-derivation (agreement of the result, `invocation.json`, the invoker manifest and the output root) are `persona_invocation.py` responsibilities (`request_errors`, `resolve_request`, `derive_output`, `verify_invocation_result`), not expressible here. `result_sha256` is an integrity check, not an authenticator.

Resource pool state (backlog batch B15; qualification evidence only -- no worker, graph, manifest or
launcher consumes it, see `docs/resource-pools.md`):

- `resource-pool-state.schema.json` -- the document `appsec-review-process/resource_pools.py state` writes for a Dagster instance: declaration hash, Dagster version, the default pool limit and slot-release setting (expected and observed), the unchanged outer run-queue limits, the six pools in declared order with expected and observed limit, `from_default`, claimed slots, pending steps and a closed `state` enum (`OK`, `MISSING`, `DEFAULTED`, `DRIFT`), undeclared pools, every registered op as pooled or `unassigned` with a closed reason, the named Dagster runs with each pooled step's start and end, `pooled_steps_recorded` (false means the document is not contention evidence), the largest observed overlap per pool, errors, `result` and `state_sha256`. Closed, every property required; no property for log text, run configuration or an environment value.

Unique JSON keys and finite numbers, the declaration hash (the verifying `resource_pools.py`), the pinned Dagster version, pool ids and limits, the state of each pool, non-negative counts and step times, claimed slots within the limit, declared step pools, single listing of each (job, op), run id and step key, `pooled_steps_recorded`, the overlap sweep, engagement serialization of pooled steps, the error list and the result are checked or re-derived from the bytes on disk by `resource_pools.verify_state_file`, not expressible here. `state_sha256` is an integrity check, not an authenticator.
