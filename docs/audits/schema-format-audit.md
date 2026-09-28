# Schema value-format audit

Date: 2026-09-28. Repo HEAD: `24cb06de` (main). Read-only audit, nothing in the repo was changed.
Scope: 316 files in `schemas/`, 80 files in `appsec-review-process/registry/output-contracts/`, `job-graph.json`, `worker-result-contract.json`, and the non-test `appsec-review-process/*.py` (183 modules).
Method: walked every schema with a script (pattern, format, enum, const, numeric keywords, grouped by property name), grepped the writers, and ran `schema_validate.validate` in memory against small probe instances. I also read a few `runs/**/accepted.json` pointers, read-only.

The motivating bug (`derive_plan` `generated_at`) is already fixed in `bc3b9dd7`. `full_review_input_assembly.py:414-421` now normalizes the stamp and calls `validate_document` before `atomic_json`. The other items in this report are still present at HEAD.

---

## Summary: top 10 risks

| # | Risk | Likelihood | Blast radius | Where |
|---|------|-----------|--------------|-------|
| 1 | **The claim-review stages will BLOCK on real runs.** `claim_reviewer_pool.prepare` passes the upstream `accepted.json["accepted_at"]` straight in as `now` for the permission model and as the pool clock. `permission_capabilities` rejects anything that is not whole-second `Z`. Every real pointer has micros and `+00:00` (212 of 212 sampled under `runs/`). The tests hide this because they use the fixture `"2026-09-27T12:00:00Z"`. | Near certain | Stages 07/08/09 on `full_review` | `claim_reviewer_pool.py:185,205,289` -> `persona_dispatch.py:150-163` -> `permission_capabilities.py:80,365-367`; writer `publish_job_output.py:351` via `execution_state.py:31-32`; test `tests/test_claim_reviewer_pool.py:63,79,103` |
| 2 | **The in-house validator ignores most constraint keywords.** `schema_validate.validate` enforces only type/required/properties/additionalProperties/enum/const/pattern/items/minItems/$ref. It silently skips `minLength` (250 uses in 70 schemas), `minimum` (144 in 52), `uniqueItems` (39 in 17), `maxItems` (23), `maximum` (19), `maxLength` (14), `format` (8), `if`/`then`/`allOf`/`oneOf`. Writers therefore pass checks that a standard validator or a consumer would fail. Probes confirmed that `maximum`, `uniqueItems`, `minLength`, `format` and `anyOf` are all ignored. | Certain (latent) | Every schema-gated write | `appsec-review-process/schema_validate.py:78-122` |
| 3 | **The accepted pointer has no schema, and its timestamp format depends on the writer.** `accepted-worker-result/1.0` exists only as a Python constant. `accepted_at`/`updated_at` are `datetime.isoformat()` (micros, `+00:00`) in `publish_job_output.py:144,149,240,302,351`, `dependency_workers.py:897,903` and the owasp_* modules. Consumers each re-parse or normalize the value on their own, and one does not (see #1). | High | Every downstream consumer of `accepted.json` | `publish_job_output.py:18` (constant only), `persona_tool_pool_lifecycle.py:41-49` (local normalizer), `evidence_assembly_runtime.py:138-139` (local normalizer) |
| 4 | **The `sha256:` prefix is inconsistent for one semantic field.** 364+122 pattern uses require `sha256:`+hex, 128+37 require bare hex, and 14 accept either `(sha256:)?`. 17 property names disagree across schemas: `accepted_pointer_sha256` has 5 variants, and `artifact_sha256`, `input_fingerprint`, `manifest_sha256`, `result_sha256`, `ruleset_sha256`, `source_sha256`, `config_sha256`, `prompt_sha256`, `raw_sha256`, `lock_sha256`, `composition_sha256`, `config_digest`, `permission_receipt_sha256`, `previous_entry_hash`, `input_manifest_sha256` and `source_fingerprint` each have 2-4. `execution_state.digest`/`file_hash` return bare hex, and about 25 modules re-prefix it with their own `_sha()`. About 15 sites strip or re-add the prefix ad hoc. A missed strip makes an equality check fail, not a schema check. | High | Cross-lane bindings (OWASP <-> claim/synthesis), hash-chain equality | `execution_state.py:72-78`; `dependency_workers.py:325,341,415,844,851,902`; `owasp_join_publisher.py:118-119`; `report_input_assembly.py:392`; `threat_model_core.py:121`; `vendor_evidence_workers.py:368,380,393` |
| 5 | **There are six timestamp regex variants plus unconstrained fields, and the canonical form points in opposite directions.** Examples: `resource-pool-state.schema.json` *requires* `+00:00` with optional micros, `vulnerability-database-identity` requires `.mmmZ`, and `generated_at` alone has 3 incompatible patterns plus 2 unconstrained schemas. A fix to "the" timestamp format in `execution_state.now()` would break `resource_pools` (`resource_pools.py:637`). | Medium | Any field copied across lanes (`generated_at`, `evaluated_at`, `issued_at`, `retrieved_at`) | see inventory §1 |
| 6 | **Timestamp passthrough into strict clocks.** `control_lane_orchestration.py:62,97,107,114` uses `value["generated_at"]` as the persona or container clock (`_TS_RE` Z-only in `persona_invocation.py:175`, `container_execution.py:161`, `owasp_dispatch.py:103`). This is safe today only because the single producer (`persona_tool_pool_lifecycle.py:298`) normalizes first. A second producer that copies an `accepted_at` would repeat #1. | Medium | Pool and merge lanes | as cited |
| 7 | **The `$` anchor accepts a trailing newline.** The validator uses `re.match`, and Python's `$` matches before a final `\n`. 776 patterns in 194 schemas end in `$` (531 in 61 schemas use `\Z`). `"...Z\n"` passes the plan's `generated_at` (probe confirmed). `\Z` in turn is not portable: in ECMA-262/ajv it is an error or a literal `Z`. | Low-med | Identifiers and paths copied into filenames or argv | all `$` patterns |
| 8 | **Skip-reason and status enums live in 4+ places with no single source.** The skip reasons are in `worker-result-contract.json` (`skip_reasons`, not enforced), `job-graph.json` (`allowed_skip_reasons`, 140 edge entries, enforced per edge), Python constants (`analysis_feature_lifecycle.SKIPS`, `ir_evidence.SKIP_REASON`, `tool_instance_shapes.SKIP_REASON`), and `evidence-skip.schema.json` (`^not-applicable-[a-z0-9-]+$`). The envelope schema has `skip_reason: string|null`. Applicability tokens `SKIPPED_NA_EMPTY_SCOPE` and `SKIPPED_NA_NO_CANDIDATES` exist only in Python, while the receipt schema enum is `APPLICABLE|SKIPPED_NA`. | Medium | Silent drift | §3 |
| 9 | **Local `#/$defs/...` refs crash the validator.** `SchemaStore.load("#/$defs/x")` strips to `""`, and `read_text()` on the schemas directory then raises `IsADirectoryError` (probe confirmed). This is latent today because the only such refs (`debug-symbol-index.schema.json`, `threat-model-reconciliation.schema.json`) sit in `$defs` that nothing references. It also means **those `$defs` constraints are dead**: they are never enforced. | Low now, high on first use | `debug-symbol-index`, `threat-model-reconciliation` | `schema_validate.py:38-44` |
| 10 | **Identifier regexes disagree for the same field.** `run_id` has 7 variants (lengths 96/120/unbounded, with and without `.`), `attempt_id` has 8, `job_id` has 6, `image_id` has 6, and `persona_id`/`role_id`/`domain_id`/`tooling_profile_id` are unbounded in one family and `{0,95}` in another. `execution_state.identifier` (`execution_state.py:35-40`) admits 120 chars without `.`, so 97-120-char ids pass the writer and fail `tool-results`, `scan-coverage` and similar. | Low-med | Dispatch and pool records | §1 identifiers |

Next tier: `format: date-time` appears in 4 schemas (`nvd-*`, `build-image`) and is never checked. `human-signoff-entry` `issued_at`/`signed_at` are `minLength: 1` only, so in practice they are unconstrained. `severity` has 3 casings. `confidence` appears with and without `unknown`. `age_seconds` is `integer` in 3 schemas and `number` in 1. Canonical-JSON digests use different `json.dumps` settings (`claude_cli_invoker.py:1059` `default=str`; `source_sast_language_adapters.py:88` default separators).

---

## 1. Format inventory by kind

Counts are pattern *uses* / distinct files over the 397 schema-like files. There are 182 distinct pattern strings and 1315 uses in total.

### 1.1 Timestamps (instant)
| Variant | Uses/files | Files (examples) |
|---|---|---|
| `^YYYY-MM-DDTHH:MM:SSZ\Z` | 12 / 8 | persona-invocation-record/result, pinned-container-result (`started_at`, `finished_at`), dependency-database-snapshot, sca-vulnerability-match-database-identities (`data_timestamp`, `evaluated_at`), dependency-lifecycle-reference-table-identity, owasp-dispatch-attempt (`decided_at`), sbom-inventory (`generated_at`) |
| `^YYYY-MM-DDTHH:MM:SSZ$` | 9 / 5 | full-review-input-plan (`generated_at`), permission-decision(-ui) (`evaluated_at`, `expires_at`), permission-grant (`issued_at`, `expires_at`), test-execution-control (`authorization_time`) |
| `^...:SS\.[0-9]{3}Z\Z` (millis) | 3 / 1 | vulnerability-database-identity (`evaluated_at`, `retrieved_at`) |
| `^...:SS(\.[0-9]{1,6})?\+00:00\Z` (micros, offset) | 1 / 1 | resource-pool-state (`generated_at`) |
| `format: date-time` (not enforced) | 7 / 4 | nvd-snapshot-manifest (`captured_at`), nvd-writer-lease (`heartbeat_at`, `lease_expires_at`), nvd-current-pointer (`published_at`), build-image (`validated_at`) |
| `type: string` with no format | ~32 fields / ~20 files | worker-result-envelope and threat-workbench-cell-result (`started_at`, `finished_at`), owasp-* (`admitted_at`, `assessed_at`, `captured_at`, `decided_at`, `ended_at`, `produced_at`, `occurred_at`, `published_at`, `issued_at`), handoff-transfer and owasp-applicability-model (`generated_at`), threat-workbench-wave-manifest (`frozen_at`), standard-selection (`approved_at`), ossf-scorecard-results and reference-snapshot-manifest (`retrieved_at`), human-signoff-entry (`issued_at`, `signed_at`: minLength only) |
| epoch `number` | 2 fields | resource-pool-state `started`, `ended` |

The same field name carries different formats in different schemas: `generated_at` (3 patterns + 2 unconstrained), `evaluated_at` (3), `issued_at` (Z / unconstrained / minLength), `retrieved_at` (millis / unconstrained), `started_at` and `finished_at` (Z / unconstrained), `decided_at`, `captured_at`, `published_at` (date-time / unconstrained).

### 1.2 Dates
`^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z`: 5 uses / 4 files (dependency-lifecycle-entry/reference-table `eol_date`, `as_of`).

### 1.3 SHA-256 digests
| Variant | Uses/files |
|---|---|
| `^sha256:[0-9a-f]{64}$` | 364 / 101 |
| `^sha256:[0-9a-f]{64}\Z` | 122 / 47 |
| `^[0-9a-f]{64}$` | 128 / 56 (+1 `^[a-f0-9]{64}$` in intake) |
| `^[0-9a-f]{64}\Z` | 37 / 19 |
| `^(sha256:)?[0-9a-f]{64}$` (tolerant) | 14 / 7 (claim-ledger-entry/input/citation, claim-lifecycle-actor/producer) |
| `^(?:ref@)?sha256:[0-9a-f]{64}\Z` (image digest) | 1 |
| `^sha256-[0-9a-f]{16}$` / `\Z` (snapshot id, truncated) | 8 / 7 + 3 / 1 |
| `$ref: analysis-hash.schema.json` / `threat-model-reconciliation-sha.schema.json` / `#/$defs/sha` / `#/$defs/hash` | shared-def attempts: 3 competing mini-libraries |

Of the prefixed/bare patterns: 154 are strict-prefix, 68 are bare, and 4 are tolerant. The OWASP family (owasp-batch-*, owasp-control-*, owasp-input-manifest*, owasp-validator-handoff, owasp-dispatch-*) and the dependency and IaC `ruleset_sha256` are **bare**. The claim, synthesis, binary, IR, persona and pool families are **prefixed**. The claim-ledger family is **tolerant**. Fields that disagree are listed in Risk #4.

Other hex ids: `^[0-9a-f]{32}\Z` (14/10, instance and attempt ids), `^[0-9a-f]{40}$`/`\Z` (git sha, 3), `^[0-9a-f-]{36}\Z` (uuid, 1), `appsec-[0-9a-f]{32}`, plus about 20 prefixed hash-derived ids (`claim-`, `signoff-`, `event-`, `remediation-` with 24 hex; `lead_`, `blead_`, `sym_`, `fn_`, `edge_`, `triage_`, `intel_`, `locked-` with 16 hex; `hyp_`, `intercom-`, `dynamic-request-` with 20 hex; `cpg_`, `derived_`, `synthetic-`, `act-` with 24 hex). `lead_id` appears 3 ways (`blead_`, `lead_ ... $`, `lead_ ... \Z`).

### 1.4 Identifiers (slug-like)
| Variant | Uses/files |
|---|---|
| `^[a-z0-9][a-z0-9-]*$` (unbounded) | 82 / 26 |
| `^[0-9A-Za-z][0-9A-Za-z._-]{0,95}\Z` | 44 / 25 |
| `^[a-z0-9][a-z0-9-]{0,95}\Z` | 35 / 7 |
| `^[A-Za-z0-9][A-Za-z0-9_-]{0,119}\Z` | 34 / 15 |
| `^[0-9a-z][0-9a-z._-]{0,95}\Z` / `$` | 21 / 14 + 14 / 5 |
| `^[0-9A-Za-z][0-9A-Za-z._-]*$` (unbounded) | 16 / 7 |
| `^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$` | 13 / 6 |
| `^[a-z][a-z0-9_]{0,63}\Z` (claim classes) | 12 / 6 |
| `^[0-9A-Za-z][0-9A-Za-z._-]{0,95}$` | 10 / 6 |
| `^[A-Za-z0-9][A-Za-z0-9_-]{0,119}$` | 9 / 7 |
| `^[a-z0-9][a-z0-9-]{0,63}\Z`, `{0,39}\Z`, `{0,79}$`, `{0,159}$`, `^[0-9a-z][0-9a-z-]*$`, `^[0-9a-z][0-9a-z-]{0,95}$/\Z`, `^[A-Za-z0-9][A-Za-z0-9_-]{0,95}\Z`, `^[A-Za-z0-9:+._-]{1,120}\Z`, `^[A-Za-z0-9._-]{1,128}$` | 3-8 each |

By field: `run_id` 7 variants, `attempt_id` 8, `job_id` 6, `image_id` 6, `persona_id`/`role_id`/`domain_id`/`tooling_profile_id`/`job_template_id` 2 each (unbounded vs `{0,95}\Z`), `group_id` 2, `lane` 2, `pool_id` 2 (`\S{1,200}` in resource-pool-state), `instance_id` 2, `tool_id` 4, `producer` 2, `snapshot_id` 3, `record_id` 6, `gap_id` 4, `hit_id` 2, `entry_id` 2, `component_id` 2, `claim_id` 2.

Ordinal ids: `SC-`, `VM-`, `LI-`, `DL-`, `SI-`, `IC-`, `BI-`, `RA-`, `VG-` + 6 digits (consistent). External ids: `CWE-`, `CAPEC-`, `CCI-`, `V-`, `SV-...r..._rule`, `SRG-`, `T####(.###)`, `MASTG-TEST-####`, NIST `XX-n(n)`, purl, cpe 2.3.

### 1.5 Paths
18 distinct path patterns for `path` alone. Examples:
- `^[A-Za-z0-9._+@%~,-][A-Za-z0-9._+@%~,/-]{0,1023}\Z` (8 files), the same with `$` (2), and with a `(?!.*[0-9A-Fa-f]{32})` redaction lookahead (3)
- `^[A-Za-z0-9._ /-]{1,512}\Z` (allows space, 5)
- `^[^/\\][^\r\n]{0,1023}$/\Z` (3)
- `^(?!/)(?![A-Za-z]:)(?!.*(^|/)\.\.(/|$)).+$` (1, the only one that rejects `..`)
- `^[^\\\u0000-\u001f]+$`, `^[^/\\](?:[^\\]*[^/\\])?$`, `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(/...){0,7}\Z` (log_path)
- plus fixed-shape paths (`requests/*.json`, `results/*.json`, `instances/<32hex>/...`, `presentation/...`)

Traversal protection (`..`) is inconsistent. Most variants allow `a/../b`.

### 1.6 Versions
- `module_version`: `^[0-9]+\.[0-9]+\.[0-9]+\Z` (5), `^[0-9]{1,4}(\.[0-9]{1,4}){2}\Z` (3), `$` form (1)
- `version`: 7 variants, including an integer `version` in the owasp-dynamic ledger
- `tool_version`: 2
- schema ids: `appsec-review-process/<name>/[0-9]+\.[0-9]+` (2) vs `appsec-review/<name>/1.0` consts (most)
- permission model `^[0-9]{1,4}\.[0-9]{1,4}$` (4)

### 1.7 Numerics
There are 263 numeric properties. Nothing uses `multipleOf` or `exclusive*`, and there are no 0-1 vs 0-100 percentage fields (no float scores at all). The only float fields are `duration_seconds`, `elapsed_seconds`, resource-pool `started`/`ended` (epoch), and `age_seconds` (**number** in owasp-input-manifest, **integer** in 3 others). `score` is `integer` with 0..10 (fuzz-target-triage) or 0..16 (scored-priority, synthesis-report), and unbounded nullable in synthesis-l08-record. About 20 count fields have `minimum: 0` in one schema and no minimum in another. For example, the owasp-control-status-matrix counters are `minimum 0` while the synthesis-report copies have none. Every `minimum`/`maximum` is unenforced (Risk #2).

### 1.8 Ordering and uniqueness
- `uniqueItems: true` on 23 property names (39 uses). None is enforced.
- Order stated only in descriptions: build-index `signals`/`units` ("ordered by ..."), evidence-index-metrics `snapshot` ("sorted list"), and ordinal ids (`BI-`, `IC-`, `SI-` "in document order"). There is no machine check. Writers sort explicitly in some places (`full_review_input_assembly.py:418-419`).

### 1.9 Enums and consts
186 enum-bearing property names, 334 distinct enum sets. Drift is listed in §3.

---

## 2. Writer/schema mismatch risks (ranked)

**R1. `claim_reviewer_pool` accepted_at -> permission `now` (CONFIRMED by code path).**
- Writer: `publish_job_output.py:351` `"accepted_at": now()`, where `execution_state.py:31-32` returns `datetime.now(timezone.utc).isoformat()` (e.g. `2026-09-28T14:13:25.457997+00:00`). All 212 sampled real pointers use this shape.
- Consumer: `claim_reviewer_pool.py:185` `evaluated_at = pointer["accepted_at"]` -> `:174` `persona_dispatch._permission_block(..., now=evaluated_at)` -> `permission_capabilities.py:365-367` `TS_RE.fullmatch` -> `PermissionModelError("context.now is malformed")`.
- The same value is used as the pool clock (`:289`), which `persona_invocation._now` rejects (`persona_invocation.py:875-879`), and it is written into the pool spec inputs (`:205`).
- Path: dagster `claim_review_lifecycle_op` (`dagster_workflow.py:668-676`) for 07/08/09.
- Fix pattern already in repo: `persona_tool_pool_lifecycle._permission_timestamp` (`:41-49`).

**R2. Accepted pointer timestamp shape is producer-defined and has no schema.**
- Isoformat producers: `publish_job_output.py:144,149,240,302,351,480`; `dependency_workers.py:897,903`; `owasp_applicability.py:604,647`; `owasp_batching.py:596,635`; `owasp_dynamic_requests.py:544,608`; `owasp_intercom.py:435,506`; `owasp_lane_in.py:442,480`; `owasp_validator_handoff.py:699,737`; `owasp_validator_result.py:673,742`; `nvd_feed.py:472`; `deterministic_child.py:116,222`.
- `full_review_input_assembly.py:583,695` sets `accepted_at` to `finished_at`, which is Dagster `now()` (isoformat).
- Demo fixtures use `Z` (`demo_report_fixture.py:69`, `retained_happy_path_demo.py:55`), so tests exercise a shape production never emits.

**R3. `generated_at` family.**
- `owasp_applicability.py:511` writes `instant.isoformat()` into owasp-applicability-model (unconstrained).
- `owasp_lane_in.py:365` writes `admitted_at` as isoformat.
- `generate_implementation_status.py:271` uses isoformat.
- `resource_pools.py:637` relies on the isoformat shape (its schema requires `+00:00`).
- Any consumer that copies one of these into `sbom-inventory`, `full-review-input-plan` or a permission `now` fails late. Today `dependency_workers._timestamp` (`:125-128`) hard-rejects non-Z `generated_at`. It is protected only because `dependency_orchestration.py:199` copies the plan's already-normalized stamp.
- `analysis_feature_lifecycle.py:128,157` uses the SCA envelope `finished_at` as the downstream `generated_at`. That works today only because `dependency_workers.py:873-876` stamps envelopes with the Z request time. An envelope produced via `publish_job_output` (isoformat `finished_at`, which `worker-result-envelope` does not constrain) would break 06-cve-reachability's `_timestamp` check.

**R4. `control_lane_orchestration` clock passthrough.**
`control_lane_orchestration.py:62,97,107,114` uses `value["generated_at"]` as the clock and as `started_at`/`finished_at` for persona and evidence-quorum. There is a single producer today (`persona_tool_pool_lifecycle.py:298`, normalized).

**R5. Bare vs prefixed hashes on accepted pointers.**
- `envelope_sha256` is bare in every pointer writer: `publish_job_output.py:301,349`, `full_review_input_assembly.py:582,694`, `dependency_workers.py:902` (explicit `.split(":",1)[1]`).
- Schemas that bind the pointer's hash as `envelope_sha256` are mostly prefixed, e.g. `debug-symbol-index $defs/native`, `threat-model-reconciliation-binding`, binary-evidence-*.
- Each consumer must re-prefix, as `full_review_input_assembly.py:407` does with `HASH + file_hash(...)`.
- The OWASP family stores bare `accepted_pointer_sha256` while claim, synthesis and IR store it prefixed, and `owasp_join_publisher.py:118-119` bridges them by hand.
- `claim-ledger-*` tolerant patterns mean a chain can contain both forms. `previous_entry_hash` is tolerant in claim-ledger-entry and strict in human-signoff-entry, so a chain-link equality check against a recomputed `"sha256:"+digest` fails when the stored value is bare.

**R6. Z-only runtime regexes duplicated in Python.**
`container_execution.py:161`, `persona_invocation.py:175`, `owasp_dispatch.py:103`, `permission_capabilities.py:80`, `dependency_workers.py:126` and `automatic_evidence_inputs.py:61-65` are 6 local copies of the timestamp contract, and 2 of them lack an end anchor (`permission_capabilities.TS_RE` relies on `fullmatch`, which is fine, but the module-level regex is unanchored).
Producers use 3 idioms for the same Z form:
- `strftime("%Y-%m-%dT%H:%M:%SZ")` in about 20 modules
- `replace(microsecond=0).isoformat().replace("+00:00","Z")` in `review_cli.py:53`, `run_process.py:23`, `claude_binary_resolver.py:60`, `model_version_registry.py:71`
- `time.strftime(..., gmtime())` in `claude_cli_invoker.py:1213` and `phase1.py:240`

`nvd_feed.py:48` and `sca_nvd_snapshot.py:217` emit millisecond `Z`, which matches only `vulnerability-database-identity`.

**R7. Identifier length and charset drift.**
`execution_state.identifier` (`execution_state.py:35-40`) allows `[A-Za-z0-9][A-Za-z0-9_-]{0,119}`. `attempt_id` in full_review is the Dagster run id (a UUID, 36 chars: `dagster_workflow.py:508`). That passes most variants but fails `owasp-dispatch-*` `^[0-9a-f]{32}\Z` if a Dagster run id is ever used there. `run_id` longer than 96 chars passes the writer and fails 21 schemas.

**R8. Status token mismatch in applicability.**
`persona_tool_pool_lifecycle.py:160` (`SKIPPED_NA_EMPTY_SCOPE`) and `claim_reviewer_pool.py:206` / `claim_review_lifecycle.py:182` (`SKIPPED_NA_NO_CANDIDATES`) are internal `inputs` values. If any of them is ever copied into `analysis-applicability-receipt` or `claim-review-pool-receipt` (`decision` enum `APPLICABLE|SKIPPED_NA`), validation fails.

**R9. Enum casing across lanes.**
Severity has 3 casings (`Critical/High/...` in critical-findings-sarif, `CRITICAL/HIGH/...` in synthesis-report, `high/medium/low` in disa-control-record). Any mapping from synthesis to SARIF needs an explicit table (check `critical_findings_sarif.py` and `synthesis_sarif.py`).

---

## 3. Duplicated enums

| Concept | Locations | Drift found |
|---|---|---|
| Execution status | `worker-result-contract.json.execution_states.terminal`, `worker-result-envelope.schema.json.execution_status`, `tool_instance_shapes.NODE_STATUSES` (no UNRESOLVED), `sbom_family_contracts.NEVER_SKIPS`, `secrets_iac_contracts.NEVER_SKIPS/CAN_SKIP`, `validate_job_output._UPSTREAM_STATUSES`; per-result `status` enums in 27 variants (`OK/OK_WITH_GAPS` ×13, `+SKIPPED` ×8, `OK_WITH_GAPS/SKIPPED` ×2), `persona-invocation-result`/`pinned-container-result` `BLOCKED/CANCELED/FAILED/OK`, `owasp-control-assessment-result.state` adds `INVALID`/`TIMED_OUT` | Subsets are intentional but hand-maintained. Nothing asserts subset-of-contract. |
| Skip reasons | `worker-result-contract.json.skip_reasons` (11), `job-graph.json` `allowed_skip_reasons` (140 edge entries, 11 values), `analysis_feature_lifecycle.SKIPS`, `ir_evidence.SKIP_REASON`, `tool_instance_shapes.SKIP_REASON`/`vendor_evidence_workers.SKIP`, `evidence-skip.schema.json` pattern `^not-applicable-[a-z0-9-]+$`, envelope `skip_reason: string|null` | Today the sets match. `no-debug-symbols`, `not-requested` and `not-requested-no-scorecard-projects` violate the evidence-skip pattern. The contract list is not used by `worker_result.validate_worker_result` (`worker_result.py:31-46`), which checks only the edge list. |
| Applicability decision | `analysis-applicability-receipt`/`claim-review-pool-receipt` `APPLICABLE|SKIPPED_NA`, `osv-applicability-receipt` `EXECUTE|SKIPPED_NA`, Python `SKIPPED_NA_EMPTY_SCOPE`, `SKIPPED_NA_NO_CANDIDATES`, `OSV_SKIPPED_NA_NO_PURL_COMPONENTS` (`dependency_workers.py:669`), full-review plan `skipped[].status: "SKIPPED_NA"` | 3 vocabularies |
| OWASP applicability | `owasp_applicability.STATUSES` (4, no `out_of_scope`) vs `owasp-applicability-row`/`-status-row`/`-dispatch-row` (5, with `out_of_scope`), `owasp_applicability.py:500` builds counts for 5 values, `owasp-batch-manifest` (2), deployment-hardening/worklists (4), `scan-coverage.applicability` (`applicable`/`not-applicable-no-matching-inputs`) | The Python constant is missing `out_of_scope` |
| Claim status | `claim_ledger.STATUSES` = claim-ledger-entry = claim-decision-ledger (7) | In sync (3 copies) |
| Dynamic request states | `owasp_dynamic_requests.STATES` = owasp-dynamic-manual-request.state | In sync (2 copies) |
| Pool rendezvous states and reasons | `pool_rendezvous.STATES/REASONS_BY_STATE` vs `pool-rendezvous-instance.state` (11) and the `^[A-Za-z_]{1,40}\Z` reason pattern | Reasons are not enumerated in the schema |
| Empty-pool reasons | `pool_specification.EMPTY_POOL_REASONS` vs pool schemas | Python only |
| Resource-pool unassigned reasons | `resource_pools.UNASSIGNED_REASONS` = resource-pool-state.reason | 2 copies |
| SCA gap reasons | `sbom_family_contracts.GAP_REASONS` = sca-vulnerability-match-coverage-gaps = gap-summary | 3 copies |
| Worker kind | contract (6) = envelope (6); `design-parity-job.mode` (7, adds `none`, `supplied_artifact`, drops `supplied_human_decision`); pool (2) | design-parity drift |
| Severity | 3 casings (see R9) | drift |
| Confidence | `high/medium/low` ×19 vs `+unknown` ×8 | drift |
| Priority | `P0..P3` (synthesis-report) vs `+NOT_SCORED/UNRESOLVED` (scored-priority, synthesis-l08) | narrowing without a mapping |
| Ecosystem | 13-value set ×4 vs container-image-inventory 11-value set (`other`, `rpm`, no `conan`/`composer`/`generic`) | drift |
| Binary format / RELRO | binary-hardening `elf/macho/pe/unsupported`, `absent/present/...` vs binary-triage `ELF/MACHO/PE/UNKNOWN/WASM`, `FULL/NONE/PARTIAL/UNKNOWN` | different vocabularies for the same fact |
| Evidence mode | 4 incompatible sets (worklists, citation, dynamic request, batch proof-obligation vs routing rule; the latter lacks `manual_inspection`) | drift |
| Env allowlist | `pinned-container-request` (8) vs `pool-worker-group`/`test-execution-control` (6) | drift |

---

## 4. Unvalidated writes (write now, validate later or never)

Pattern: `atomic_json(attempt / result_name, result)` inside `execute()`, with schema validation only in `publish_validated`/`validate_job_output`, at reuse, or by a downstream lane. Failures then surface after the attempt directory already holds the artifact, or in a different Dagster op.

**full_review path (highest priority):**
- `publish_job_output.py:144,149,240,302,351`: `latest.json`, `accepted.json` and `status.json` have **no schema at all** (constant `ACCEPTED_SCHEMA` only).
- `full_review_input_assembly.py:583,695`: the accepted pointer (same as above) carries isoformat `accepted_at`.
- `dependency_workers.py:895-904`: `latest.json` and `accepted.json` are written with `write_bytes(_canonical(...))`, with no schema and a bare `envelope_sha256`.
- `analysis_feature_lifecycle.py:218-221` (05-native-memory, 06-cve-reachability, 13-fuzz-target-triage): mutates `result["status"]`/`gaps` and then writes. Schema validation happens at `:172`, on reuse and consume only. Permission, lineage and applicability receipts are written with no check at write time (applicability is checked at `:190` on reuse).
- `control_feature_lifecycle.py:487-489`: result, permission and lineage are written before any check.
- `binary_evidence_core.py:509-515`: result is written, and `validate_document` runs only in `_validate_attempt` (`:466-473`) later.
- `static_intelligence_core.py:312-318` and `ir_evidence.py:676,722,728` follow the same pattern.
- `claim_lifecycle_core.py:528-529`: output and permission.
- `intake.py:218`: `outputs/intake.json`, the root of the whole graph.
- `report_input_assembly.py:552` is fine because `assemble()` validates at `:544-545` before `run()` writes.
- `synthesis_report.py:409`: `report.json`/trace; `synthesis_report_presentation.py:207,220`; `critical_findings_sarif.py:188`; `synthesis_sarif.py:100`.
- `deterministic_pool_merge.py:67`, `evidence_quorum.py:20,34`, `dynamic_rescope.py:21`, `remediation_retest.py:27`, `completeness_audit.py:15`, `completeness_feedback.py:21`, `synthetic_hypothesis_resynthesis.py:20`: the `run(…, output)` helpers write directly.

A heuristic AST scan found 358 `atomic_json` calls with no validate-like call earlier in the same function. Many are status and scratch files. The list above holds the result-bearing ones. Because of Risk #2, even validated writes are only partly checked.

---

## 5. Proposal (not implemented)

### 5a. `schemas/common/formats.schema.json`
```json
{
  "$id": "common/formats.schema.json",
  "$defs": {
    "utc_second":     {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "maxLength": 20},
    "utc_millis":     {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", "maxLength": 24},
    "utc_date":       {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$", "maxLength": 10},
    "sha256_ref":     {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$", "maxLength": 71},
    "sha256_hex":     {"type": "string", "pattern": "^[0-9a-f]{64}$", "maxLength": 64},
    "git_sha1":       {"type": "string", "pattern": "^[0-9a-f]{40}$", "maxLength": 40},
    "hex128_id":      {"type": "string", "pattern": "^[0-9a-f]{32}$", "maxLength": 32},
    "slug":           {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,95}$", "maxLength": 96},
    "token_id":       {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,119}$", "maxLength": 120},
    "dotted_id":      {"type": "string", "pattern": "^[0-9A-Za-z][0-9A-Za-z._-]{0,95}$", "maxLength": 96},
    "run_id":         {"$ref": "#/$defs/token_id"},
    "attempt_id":     {"$ref": "#/$defs/token_id"},
    "job_id":         {"$ref": "#/$defs/token_id"},
    "registry_id":    {"$ref": "#/$defs/slug"},
    "semver":         {"type": "string", "pattern": "^[0-9]{1,4}\\.[0-9]{1,4}\\.[0-9]{1,4}$", "maxLength": 14},
    "schema_version": {"type": "string", "pattern": "^[0-9]{1,4}\\.[0-9]{1,4}$"},
    "rel_path":       {"type": "string", "maxLength": 1024,
                       "pattern": "^(?![/\\\\])(?![A-Za-z]:)(?!.*(^|/)\\.\\.(/|$))[A-Za-z0-9._+@%~,-][A-Za-z0-9._+@%~,/-]*$"},
    "nonneg_int":     {"type": "integer", "minimum": 0},
    "port":           {"type": "integer", "minimum": 1, "maximum": 65535},
    "bytes":          {"type": "integer", "minimum": 0},
    "seconds":        {"type": "number", "minimum": 0},
    "execution_status": {"enum": ["OK","OK_WITH_GAPS","SKIPPED","BLOCKED","FAILED","CANCELED","UNRESOLVED"]},
    "acceptance_status":{"enum": ["CURRENT","NOT_ACCEPTED","SUPERSEDED"]},
    "skip_reason":    {"enum": ["<generated from worker-result-contract.json skip_reasons>"]},
    "applicability_decision": {"enum": ["APPLICABLE","SKIPPED_NA"]},
    "confidence":     {"enum": ["high","medium","low","unknown"]},
    "severity":       {"enum": ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
  }
}
```
Decisions embedded here:
- `utc_second` is **the** instant format. `utc_millis` is kept only for NVD provenance.
- `resource-pool-state` moves to `utc_second` (with a `+00:00` alias accepted for one release).
- Hash fields named `*_sha256`, `*_fingerprint`, `*_digest` and `*_hash` all use `sha256_ref`. `sha256_hex` is allowed only for embedded third-party formats, such as the OWASP handoff wire format if it must stay bare, and those fields must be renamed `*_sha256_hex` so the name carries the form.
- Pick `$` (standard) and make the validator use `re.fullmatch` so trailing-newline acceptance goes away, instead of `\Z`, which is non-portable.

Prerequisites in `schema_validate.py`:
1. Support `common/…#/$defs/name` and local `#/$defs/name` refs (JSON Pointer resolution).
2. Use `fullmatch` for patterns.
3. Implement `minLength`/`maxLength`/`minimum`/`maximum`/`uniqueItems`/`maxItems`/`anyOf`/`oneOf`/`allOf`/`if`/`then`.
4. **Fail closed on unknown keywords**, so the subset can't silently shrink again.

### 5b. Python helper API: `appsec-review-process/formats.py`
```python
# canonical producers
def utc_now() -> str                                     # "2026-09-28T14:13:25Z"
def utc_second(value: str | datetime) -> str             # lossless-normalize any tz-aware ISO-8601 -> utc_second; raise on naive
def utc_millis(value: str | datetime) -> str
def sha256_ref(data: bytes | Path | Any) -> str          # bytes/file/canonical-JSON -> "sha256:<hex>"
def sha256_hex(ref: str) -> str                          # "sha256:<hex>" | "<hex>" -> "<hex>" (validated)
def as_sha256_ref(value: str) -> str                     # "<hex>" | "sha256:<hex>" -> "sha256:<hex>" (validated)
def canonical_json(value) -> bytes                       # one json.dumps(sort_keys, (",",":"), ensure_ascii=True) + "\n"
def digest(value) -> str                                  # sha256_hex(canonical_json(value)) - single implementation
# validators (mirror $defs 1:1; generated from formats.schema.json at import)
def check(kind: str, value) -> None                      # raises FormatError(kind, value)
FORMATS: Mapping[str, re.Pattern]                        # loaded from schemas/common/formats.schema.json
# write-time gate
def write_validated(path: Path, doc: dict, schema: str, *, canonicalize: bool = True) -> None
    # canonicalize (5c) -> validate_document -> atomic_json; raise Blocked on error
```
Replace `execution_state.now()` with `formats.utc_now()` everywhere, and give `accepted.json`/`latest.json` a schema (`accepted-worker-result.schema.json`) written through `write_validated`.

### 5c. Canonicalizations
**Safe to apply automatically at write time** (lossless, or loss is semantically irrelevant and documented):
- Tz-aware ISO-8601 -> `utc_second`, only when the value is a *record time* (generated/accepted/updated/started/finished) and sub-second precision was never promised. Truncate, never round.
- `+00:00` or other offsets -> `Z` after converting to UTC.
- Bare 64-hex -> `sha256:` prefix for fields typed `sha256_ref`, and prefix stripping for `sha256_hex`.
- Uppercase hex -> lowercase for digests.
- Enum casing, only through an explicit alias table per enum (e.g. `High` -> `HIGH`), never by generic `.upper()`.
- Sorting arrays whose schema declares an order key, and deduping `uniqueItems` arrays of scalars, only where the description says order carries no meaning.

**Must fail (never auto-fix):**
- Naive datetimes (no tz).
- Unparseable timestamps.
- Timestamps where sub-second precision is data (NVD `retrieved_at`/`evaluated_at` millis, lease heartbeats).
- Hashes of the wrong length or alphabet.
- `sha256-<16hex>` truncated ids used where a full digest is expected.
- Identifier too long or with an illegal char (truncation changes identity).
- Path traversal, absolute paths, or backslashes.
- Unknown enum values, including unknown skip reasons and `SKIPPED_NA_*` tokens leaking into receipt enums.
- Numeric out of range, float where integer is required (no rounding), `bool` for int.
- Duplicates in `uniqueItems` arrays of objects.
- Any value in a hash-bound (already-fingerprinted) document. Canonicalize *before* fingerprinting, never after.

### 5d. Lint rule: `tools/lint_schema_formats.py` (CI + pre-commit)
1. For every `pattern` in `schemas/**/*.json` other than `schemas/common/formats.schema.json`, fail if it is equal (after `\Z`->`$` normalization) or near-equal to a common `$defs` pattern. Near-equal means the same regex with different length bounds or anchors. Require `{"$ref": "common/formats.schema.json#/$defs/<kind>"}` instead.
2. Fail on any property whose name matches `(_at|_time|timestamp)$` unless it `$ref`s `utc_second`/`utc_millis`. Also fail on `*_sha256|*_digest|*_hash|*fingerprint` unless it `$ref`s `sha256_ref` or `sha256_hex`, and require the `_hex` name suffix for the bare form. Do the same for `run_id|attempt_id|job_id` and the `*_id` registry ids.
3. Fail on `format: date-time` (unenforced) and on `\Z` anchors.
4. Fail on any `enum` whose value set overlaps at least 50% with a common enum (`execution_status`, `skip_reason`, `applicability_decision`, `severity`, `confidence`) but is not a `$ref`, or an explicit `allOf` narrowing of it.
5. Python side: grep-lint forbidding `isoformat()` and `strftime("%Y-%m-%dT` in `appsec-review-process/*.py` outside `formats.py`, forbidding `"sha256:" +`, `.split(":", 1)[1]` and `removeprefix("sha256:")` outside `formats.py`, and forbidding module-level `_TS_RE`/`TS_RE`/`SHA_RE` definitions.
6. Cross-check: every string literal matching `^(not-applicable|not-requested|SKIPPED_NA)` in Python must appear in the generated `skip_reason`/`applicability_decision` enum. Every `job-graph.json` `allowed_skip_reasons` value must appear in `worker-result-contract.json`.
7. Test fixture guard: fixtures that write `accepted_at` must be produced through `formats.utc_now()` or a fixture helper, so tests can't use a shape that production never emits (the cause of R1).
