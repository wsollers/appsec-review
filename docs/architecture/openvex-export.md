# OpenVEX findings export

Status: **implementation being adapted to the certified gate/2 boundary**. The user explicitly
selected standalone post-gate export and preservation of gate-only report/2 publication.
This supersedes this original design's proposed OpenVEX report links and optional-tail fan-in;
pre-gate PoC/remediation/dossiers must remain unchanged.

The original design below is retained during reconciliation,
not evidence of a completed review or deployment. Focused-unit, packaging and manual-validation
scope is recorded in [the implementation record](../reviews/openvex-export-implementation.md).

The original design was reconciled against
`2ee310f05b12bdcdf5baa4deb2b3b5c628330678` (Merge correlated OWASP and review-flow telemetry),
which contains the originally required baseline `fcac43068d17f139a9d94393b03fe128c6127f12`.
Both ancestry checks passed in the design agent's isolated worktree.

The coordinator selected a small v1: explicit immutable pre-run TOML issuer/action inputs,
reviewed-source-snapshot products, and the existing accepted-handoff lifecycle. There is no
new approval intake, per-finding consent workflow, generic runtime identity hook, or mutable
post-run configuration. This document does not authorize public disclosure.

## 1. Goal and non-goals

Add a deterministic, model-free `job_openvex_export`, downstream of the accepted final
publication gate, producing OpenVEX v0.2.0 `affected` statements for **all and only the
gate's publishable confirmed findings**. An operator explicitly supplies the person or
organization issuing those assertions and a common action statement applicable to all
exported findings. Missing required enabled-job inputs are configuration errors, not an
empty export or an excuse to invent advice.

OpenVEX is a compact vulnerability/product/impact-status exchange, not a lossless review
report. Retain scores, independence, ship-block policy, coverage, limitations, and resolving
statement-to-evidence mappings in a hash-bound companion manifest. A dossier, attack chain,
PoC, successful compilation, or exploit execution is not required for `affected`.

V1 does not add remediation generation/planning/validation, SBOM generation, signing/key
infrastructure, automatic uploading/publication, release ranges, exploit execution, chain
composition, external vulnerability-ID inference, or `not_affected`, `fixed`, and
`under_investigation` workflows. Export success is not a clean verdict or shipping approval.

## 2. Current source evidence

These are observed implementation contracts, not assumptions from older design documents.

| Surface | Observed behavior and consequence |
| --- | --- |
| `jobs/job_final_publication_gate/verify.py`, `classify.py`, `job.py` | Re-verify accepted review artifacts, ledger/projection, packages, scores, both lead and hunt package-manifest hashes, and ship-block accounting. Every package is in `publishable`, `verification_backlog`, or `withheld`. Export must not bypass withholding. |
| `docs/schemas/inference-security-review/finding-package.schema.json` | `finding-package/2` holds confirmed/supported state, resolving evidence IDs, scoring references, independence, ship-block information, and only `safe_regression_artifact` under remediation inputs. It has no accepted action advice or approved release-product mapping. |
| `jobs/job_inference_security_review/job.py` | `scope.accept_manifest` publishes `accepted-scope.json` with `target_snapshot`, `manifest_sha256`, and `manifest_path`. Bind that artifact explicitly; do not assume the gate already binds every scope artifact. |
| `jobs/job_final_report_publication/job.py`, `report.py` | Report is a deterministic gate projection. It separately reads an accepted optional PoC handoff and does not display stale PoC output. |
| `jobs/job_poc_generation/inputs.py` | Reuses the gate's review verifier and resolves accepted scope through the accepted review job handoff. Useful prior art, not a required exporter dependency. |
| `jobs/job_poc_generation/` | Writes developer test functions and validates/compiles them. It never links or executes them. `compile_verified` is not exploitation; `compile_failed` does not refute a finding. |
| Job registry and job package directories | No attack-chain, remediation, or dossier publisher exists at the reconciled base. Do not design against fictional accepted manifests for those surfaces. |
| `jobs/job_review_intake/job.py`, `jobs/job_target_acquisition/job.py` | Intake may copy acquisition provenance into the run; direct local targets can lack repository/commit provenance. Accepted snapshot identity is always the fallback, not a guessed Git commit. |
| `runtime/runner.py`, `resume.py`, `job.py` | Full resolved configuration is immutable per run. Resume already checks settings, upstream handoff hashes, declared component releases, artifacts, and validation identities. No new runtime cache framework is needed. |
| `jobs/bound_artifacts.py`, `indexing/store.py` | Reuse accepted-handoff and run-relative hash-bound artifact readers. A corrupt/unsafe existing pointer must not masquerade as an absent job. |
| `observability/events.py`, `spans.py`, `telemetry.py` | Run-owned JSONL, operation spans, deterministic metrics; latest base also adds correlated OWASP/review-flow metrics. No Prometheus/OTel service is required. |

Paths in the table are relative to `src/appsec_review/` except explicitly named `docs/` paths.
Gate `review.configuration_sha256` is the semantic inference-review-settings hash from
`semantic_settings_sha256`, **not** the entire frozen `resolved.json` hash. Store them as
`review_settings_sha256` and `resolved_config_sha256` respectively in new export provenance.

## 3. Verified upstream specification and validation pin

On 2026-10-28, read the official
[OpenVEX specification](https://raw.githubusercontent.com/openvex/spec/main/OPENVEX-SPEC.md)
and [JSON schema](https://raw.githubusercontent.com/openvex/spec/main/openvex_json_schema.json).
Upstream `main` resolved to `61b5f885d0f481f48683c93345e49ef1a6e9fdff`; pin these exact raw bytes:

| Upstream file | Bytes | SHA-256 |
| --- | --- | --- |
| `OPENVEX-SPEC.md` | 30580 | `9375415ccb351260a998864cbeebbaff1808d1b09a306919b79cc75e5519f884` |
| `openvex_json_schema.json` | 12659 | `9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238` |

Immutable sources:
[specification at the pin](https://raw.githubusercontent.com/openvex/spec/61b5f885d0f481f48683c93345e49ef1a6e9fdff/OPENVEX-SPEC.md),
[schema at the pin](https://raw.githubusercontent.com/openvex/spec/61b5f885d0f481f48683c93345e49ef1a6e9fdff/openvex_json_schema.json).
Vendor the schema unchanged at
`docs/schemas/openvex-export/upstream/openvex-v0.2.0.schema.json`; an adjacent
`upstream.lock.json` records upstream repository, commit, URLs, source hashes and license
attribution. Check licensing before redistribution. Pin updates are reviewed changes, not
runtime downloads. Package the verified schema/lock for installed runtime use, including a
wheel-resource test. The run manifest records the schema and exporter validation-profile hashes.

Requirements relevant to v1:

1. Emit UTF-8 JSON with exact `@context: "https://openvex.dev/ns/v0.2.0"`.
2. Document `@id`, `author`, `timestamp`, `version`, and `statements` are required.
   `author` MUST identify an individual or organization; automation belongs in `tooling`.
3. An `affected` statement MUST have `action_statement`. The upstream schema accepts blank
   strings; v1 semantics do not.
4. A complete standalone statement needs vulnerability identity, at least one product, status,
   and time. The schema alone permits missing/empty `products`; v1 does not.
5. `statements` has `minItems: 1`: zero eligible findings produce `no_statements`, not an
   invalid OpenVEX document containing an empty array.
6. Document/statement/vulnerability/product objects prohibit unknown properties. Do not add a
   local `schema` tag, scores, evidence objects, policy or disclosure fields to OpenVEX.
7. CVEs are optional. An understood stable internal vulnerability ID is valid; CWE is a
   weakness class, not vulnerability identity.
8. Modified documents require version increments. V1 uses new content-addressed document IDs
   for new content and never modifies a previously issued ID.
9. `not_affected` needs an allowed justification or impact statement. `fixed` must concern
   specifically fixed product versions. Neither is emitted in v1.

Use the already declared `jsonschema` dependency with `Draft202012Validator` and a closed
local `referencing.Registry`. Explicitly reject remote `$ref` resolution and never retrieve
the JSON-LD context. Do not use the review `SchemaSet` for the upstream schema: it lacks
`anyOf`, treats `format` as annotation, and expects a different schema layout.
In addition to schema validation, explicitly validate RFC3339 timestamps and emitted
restricted ASCII URI/IRI forms; do not assume optional format-checker packages are installed.

## 4. Numbered implementation decisions

1. **Eligibility:** the accepted gate is authoritative. Export every package in `publishable`
   only when its accepted state is `confirmed`; disagreement is integrity failure.
2. **Statuses:** only `affected`. Supported findings, refuted/contradicted claims, unreachable
   observations, missing coverage, absent/failed PoCs and compile results imply no other
   OpenVEX status. Do not create statements for ledger claims lacking gate packages.
3. **Issuer/action:** explicit typed TOML fields, frozen before the run. The operator owns the
   issuer assertion and exact common action text. There is no synthesized mitigation,
   automatic target-guidance discovery, title-to-advice conversion, or silent fallback.
4. **Product:** one reviewed source-snapshot/configuration product for the reviewed system.
   An accepted source snapshot is not a shipped artifact, release range, or artifact digest.
5. **Evidence:** scores, independent verification, ship-block status and limitations remain
   separate dimensions in the companion. Missing values never become zero or low risk.
6. **Optional proof:** PoCs/chains/dossiers are optional linked evidence, never conditions for
   affected. Existing gate withholding remains unchanged; do not "repair" it in this feature.
7. **Privacy:** generate protected local artifacts only. Enabling export is a deliberate
   issuer/operator action, not approval to publish files externally.
8. **Empty/error:** genuinely zero eligible findings produce accepted `no_statements` with a
   named gap. Missing enabled settings, invalid input, stale state, tamper or bounds failure
   fail closed, not as empty success or row-level skip.
9. **Replay:** canonical bytes depend on accepted pins, frozen policy, schema and exporter
   release. No wall clock, attempt serial, PID or runtime timing enters artifact identity.
10. **Integration:** existing gate/upstream handoff dependencies invalidate export/report.
    No mutable approval store, runtime identity hook, or new acceptance job.
11. **Dispatch:** disabled by default; disabled means no automatic or manual dispatch in v1.
    Configure and enable before run creation. No new exception in `MANUAL_JOB_IDS`.
12. **Publication:** only the existing runner accepts the handoff after final byte/schema/
    semantic/accounting checks. A file or telemetry event is not proof of acceptance.

## 5. Safe immutable issuer/action inputs

The following operator-owned fields are required when enabled:

| Field | Typed contract |
| --- | --- |
| `author_kind` | Exactly `individual` or `organization`; never `tool`, model or bot. |
| `author` | Nonblank bounded person/organization name or identifier; the operator asserts issuance authority. Do not infer the repository owner or claim supplier endorsement. |
| `role` | Optional nonblank role, omitted from OpenVEX when empty. No automatic "supplier" role. |
| `action_statement` | Exact operator-authored plain text applying accurately to **all** exported findings for the reviewed product. Nonblank, bounded, no template placeholders or executable markup. |
| `repository_iri` | Explicit stable absolute `https:` or `urn:` identity for the reviewed repository/system, not a local path, branch, credential-bearing URL, or product release. |

Selecting a kind cannot mechanically prove a named author is a real organization/person.
Document the trust boundary: the operator owns this assertion; v1 adds no identity
verification or signature infrastructure. Reject obvious tool-only identities, empty/unsafe
values and unsupported kind, but do not claim a heuristic proves organizational authority.

Never manufacture "upgrade", "investigate", or "no fix available" advice. An issuer may write
an accurate statement that no remediation is yet available, but the exporter must not choose
that fallback. If no accurate common action statement can be approved for all publishable
findings, the operator cannot enable this v1 export for that run; per-finding advice is a
future schema/workflow, not an implicit partial-export switch.

Reject NUL, unsafe controls, detected embedded credentials, unresolved template markers,
and text exceeding UTF-8 byte bounds. Preserve accepted text exactly; do not silently redact,
truncate or normalize it into different advice. Detection cannot prove text contains no
secrets: explicit operator review remains necessary. Read no target-owned settings or advice.

The full configuration and its hash are already frozen under `data/configuration/`.
Do not edit them after review, add runtime overrides, or accept an unpinned advice file.
Changing author/action/repository policy requires a new run. Existing pre-feature runs
cannot acquire new settings by modifying their stored configuration.

## 6. Product and vulnerability identities

V1 deliberately uses the same reviewed-source product for all eligible findings. This asserts
impact in the accepted reviewed system snapshot/configuration, not that every released build
contains exploitable code. Store a human-readable scope qualification in both OpenVEX's fixed
status note and the companion.

Resolve `target_snapshot` through accepted scope and its verified manifest. Never run Git,
scan a target, or fingerprint the current checkout during export. `repository_iri` is an
explicit operator assertion; when accepted acquisition provenance supplies repository identity,
require agreement rather than silently overriding it. Record whether repository identity is
`operator_declared` or `accepted_acquisition`. If acquisition provenance does not exist, do not
invent a commit: the accepted snapshot digest is the exact identity.

Use one source-product IRI:

```text
urn:appsec-review:source-snapshot:<H(repository_iri)>:<target_snapshot>:<resolved_config_sha256>
```

`H` is full lowercase SHA-256 over existing `storage.canonical_json` bytes. Validate snapshot
and configuration values against their existing contracts before embedding them. Using the
full frozen configuration identity conservatively distinguishes build/profile differences,
not merely inference settings. Include
`repository_iri`, snapshot, accepted manifest, both package-manifest hashes, observed build/
configuration qualifications and full resolved configuration reference in the companion.
Do not use the whole frozen config hash as a product artifact hash; it is provenance.

A version-specific purl from a verified SBOM is preferable **when there is an accepted
mapping of that exact product/artifact to this reviewed snapshot/configuration**. Current
code does not establish a general SBOM-to-reviewed-system mapping, so the minimum v1 emits
the source-snapshot IRI only. Do not promote dependency purls or scanner package names to
top-level products. Verified SBOM product mapping can be added later without inventing
release ranges; it is not required to complete this slice.

V1 emits no product `hashes`, `identifiers` or `subcomponents`. A snapshot/Git/configuration/
review-package/SBOM file hash is not a hash of a shipped product. Future `hashes.sha-256`
must be measured from the exact named artifact, not copied from an unrelated identity.

Vulnerability `name` and `@id` are the same internal URI:

```text
urn:appsec-review:vulnerability:<H(["openvex-vulnerability/1", repository_iri, target_snapshot, claim_id])>
```

This is stable for the same accepted claim/snapshot/repository identity, not a promise of
global cross-run deduplication after claim/evidence identities change. V1 does not infer a
CVE or emit aliases/descriptions from titles, CWE tags or dependency observations.
CVE mappings are optional future explicit accepted input, not a prerequisite for export.

## 7. Timestamp, version and canonical serialization

Use existing `storage.canonical_json`: sorted object keys, compact separators, UTF-8
(`ensure_ascii=False`), and one trailing LF. Reject non-finite numeric values before
serialization. Domain-separate identity hashes with the literal versioned tags below.

The issuer's pre-run enablement delegates issuance of the impact assertions to gate
acceptance. Use the accepted gate job handoff's `completed_at` as the document and statement
timestamp, normalized to UTC with six fractional digits and `Z`. This is the time of the
accepted assertion being serialized, not the current export file-write time or a claimed
exploit execution time. Record `timestamp_source: gate_handoff.completed_at` in the companion.
Require a valid aware timestamp; never fall back to `datetime.now()`.
Omit optional `action_statement_timestamp` because no independent action-issuance time is
established by current configuration. Runtime job/log times remain operational metadata.

Emit one statement per publishable finding, sorted by `finding_package_id`, with exactly
one product, `status: affected`, `version: 1`, explicit normalized timestamp, internal
vulnerability, exact common action, and fixed status note:

```text
Applies only to the reviewed source snapshot and observed configuration, not an inferred
released artifact or version range. Review confirmation is not proof of exploit execution.
Review limitations and resolving evidence are retained in the companion manifest.
```

The actual fixed note is a single string with ordinary spaces, not inserted line breaks.
No finding titles, advice source, evidence IDs, scores, source snippets or PoC outcomes are
interpolated. Duplicate package/claim identities or conflicting logical pairs fail; do not
silently coalesce findings or discard evidence.

Statement ID:

```text
urn:appsec-review:statement:<H(["openvex-statement/1", author, statement_without_id])>
```

Document body: exact context, author, optional role, normalized timestamp, `version: 1`,
declared exporter release in `tooling`, and sorted statements. Omit `last_updated`.
Document ID:

```text
urn:appsec-review:openvex:<H(["openvex-document/1", document_without_id])>
```

There is no self-reference or manifest hash inside the hashed OpenVEX body. Identical accepted
pins/settings/schema/release produce byte-identical OpenVEX across scheduling orders/retries.
Changes to timestamp, advice, product, author, findings or tooling create a new content-addressed
document ID, still version 1. Never overwrite an ID's bytes or reissue changed content under
it. V1 has no mutable document series, automatic retraction, or cross-run supersession registry.

Companion provenance includes run-relative upstream artifact paths; it may differ after new
upstream attempts even if the OpenVEX semantic content does not. Test document-byte equality
separately from changed runtime handoff/manifest provenance.

## 8. Job algorithm and handoff contract

New package: `src/appsec_review/jobs/job_openvex_export/`.
No model/provider/skill/executor parameter, subprocess, container or target access.
`CONSUMES = ("job_final_publication_gate", "job_inference_security_review")`;
additional gate-bound references remain transitive evidence, not a PoC dependency.

| Unit | Contract |
| --- | --- |
| `load.verify_inputs` | Pin and re-verify accepted gate/review/scope/configuration and bounds; write `verified-inputs.json`. |
| `export.assemble` | Depends on load; assemble canonical `openvex.json` if nonempty, `openvex-manifest.json`, and `openvex-result.json`. |
| `acceptance.publish_handoff` | Depends on both; re-prove input pins, all output bytes, schemas, semantics and exact accounting; return the repository handoff result. |

Algorithm:

1. Read accepted gate with `accepted_handoff`; require correct job/schema/run and published
   item count. Missing required gate fails. Inspect existing pointer safety so symlink/corrupt
   pointers do not become "not run." Re-hash every gate binding using existing bound readers.
2. Use `load_accepted_review`, then rebuild
   `classifier.gate_document(..., classifier.classify(...))` and require exact equality with
   accepted gate. This catches stale review/gate pairings, bad state/bucket/score/ship-block
   projections, non-exact accounting and both package-manifest identity mismatches.
3. Resolve `scope.accept_manifest` via the bound accepted review job handoff. Validate its
   run/schema/manifest identity, bind its artifact, and verify the referenced accepted manifest
   through existing manifest verification. Read only bounded metadata, never target files.
4. Verify `resolved_configuration_identity` and bind frozen configuration manifest/resolved
   bytes. Read typed exporter settings from that run, validate enabled issuer/action inputs
   even when zero packages exist, and keep full configuration versus review settings distinct.
5. Account every gate package. Only publishable confirmed packages become affected.
   Unrated severity, pending distinct verification, incomplete review or judge disagreement do
   not override gate eligibility; preserve their accepted limitations and policy separately.
6. Use gate-bound evidence links only. PoC/chain/dossier availability is not a filter.
   Current gate unavailable-input reasons remain named limitations; do not probe unrelated
   live PoC/chain output. Report's existing optional PoC behavior remains independent.
7. Validate and write outputs under the existing attempt layout. Zero eligible findings
   means no `openvex.json` file/reference, only explicit result/companion accounting.
8. Before acceptance, re-read accepted gate/review pointers and require original pins, re-hash
   inputs and outputs, reassemble and compare canonical bytes. A concurrent change fails the
   attempt. The runner alone publishes its accepted handoff/latest pointer.

Reuse `artifact_ref`, `read_bound_json`, `resolve_bound`, `accepted_handoff`, typed settings
patterns and protected storage writers. A small public `verify_accepted_gate` helper inside
export inputs is acceptable; avoid a general refactor of PoC/review internals.
Do not mutate finding-package/2, adjudication, claim ledger, or gate buckets.

## 9. Exact accounting, output schemas and integrity

Each gate package appears exactly once in sorted companion rows, with gate bucket/state,
disposition `included` or `excluded`, and exactly one reason:

```text
included
gate_verification_backlog
gate_withheld
```

The two exclusion reasons correspond only to the gate buckets; preserve gate withheld
reasons as additional context. There are no missing-advice/product/issuer exclusions:
those are enabled configuration/verification failures. Non-package ledger states remain
in review accounting, not fictitious VEX statements.

Validate sets and counts, not counts alone:

```text
gate_total = gate_publishable + gate_verification_backlog + gate_withheld
gate_total = included_findings + excluded_findings
included_findings = gate_publishable = statement_count
excluded_findings = backlog_exclusions + withheld_exclusions
statement_count = number of unique statement IDs = number of statement mappings
```

Each included package maps to exactly one statement, each statement to exactly one package
and the one reviewed-source product. Confirmed withheld findings remain excluded.

Result `outcome`:

| Value | Meaning / runtime disposition |
| --- | --- |
| `exported` | Nonempty valid document, no gate `kind: gap` limitations; `SUCCEEDED`. Gate not-run limitations are still retained. |
| `exported_with_gaps` | Nonempty valid document with gate gap limitations; `COMPLETED_WITH_GAPS`. |
| `no_statements` | No publishable confirmed gate packages, including empty gate/all backlog/all withheld; no VEX file, null reference, named non-clean gap, `COMPLETED_WITH_GAPS`. |

`disabled`, `not_run`, `failed`, `stale` are dispatch/consumer states, not accepted export
outcomes or vulnerability statuses. Invalid settings/schema/evidence, tamper, stale gate,
timeout and bound exceedance fail the whole attempt with no new accepted handoff; never
skip an invalid row, truncate to a plausible subset or convert failure into `no_statements`.

New schemas under `docs/schemas/openvex-export/`:
`common.schema.json`, `manifest.schema.json` (`appsec-review/openvex-export-manifest/1`),
and `result.schema.json` (`appsec-review/openvex-export-result/1`).
Register those identities plus `appsec-review/openvex-export-handoff/1` in
`jobs/engineering_contracts.py`. All local objects are closed and bounded.

Companion required sections:

| Section | Contents |
| --- | --- |
| Provenance | Run, exporter release/validation profile, schema pin, gate/review job+document refs, accepted scope/manifest refs, snapshot/repository source, both package-manifest identities, ledger/projection/ship-block policy hashes, separately named review settings/full configuration hashes. |
| Review context | Verbatim accepted review status/accounting, coverage summary, limitations/gap IDs, ship-block summary, distinct-verification warning. Never blend score dimensions or reinterpret missing values. |
| Products | Source snapshot IRI, repository identity basis, observed configuration/build qualifications and explicit source-not-release statement. |
| Packages | Sorted package ref/hash, claim/adjudication/verification IDs, bucket/disposition/reason, statement ID or null, accepted score projections+refs, independence, ship-block projection, direct/analyst-assessed evidence relation IDs and gaps. |
| Statement mapping | Statement ID, canonical array index, vulnerability/product identities, source package/claim ref, action settings identity, resolving evidence refs. |
| Outputs/accounting | OpenVEX `{path, sha256, size_bytes}` or null, exact count identities, zero-filled exclusion counts, outcome and internal disclosure classification. |
| Bindings | Sorted deduplicated run-relative references sufficient to resolve everything above, including the gate/review evidence artifacts, scope, frozen config and schema pin. |

Evidence IDs resolve through the bound ledger projection and its referenced evidence; they
are not free-floating URLs. The companion contains no source snippets, secrets, prompts,
model output, PoC code, binaries, or full dossiers. Optional proof links are hash-bound
references, never execution claims.

Avoid hash cycles: serialize OpenVEX first; manifest hashes it but not itself; result hashes
manifest/document; runtime handoff hashes result and transitively binds artifacts.
Hash binding is integrity, not a signature or proof of issuer identity.

`openvex-result.json` contains exactly local schema/run/outcome, gate identity, manifest
reference, OpenVEX reference/null, statement/included/excluded counts, and named gaps.
The acceptance unit returns `schema`, `artifact` pointing to result, `item_count` equal to
statement count, `gaps`, and `terminal_status`. This respects the runner's handoff-output
allowlist: consumers read the result, not invented top-level handoff fields.

Dataset declarations use family `inference_review`, disposition `protected`, sensitivity
`sensitive`, sanitized-metadata query route and named exception reason:

| `output_kind` | Claimed files |
| --- | --- |
| `openvex_verified_inputs` | Load-unit artifacts and run-local pinned schema/lock copies. |
| `openvex_documents` | Only assembled `openvex.json`. |
| `openvex_export_accounting` | Manifest/result and acceptance artifacts. |

Use nonoverlapping exact attempt patterns. Runtime receipt/log files retain existing claims.
Absent document inventory is `unavailable` with `no_statements`/disabled/failure reason, not
empty indexed success. No new finding index, content-retrieval route or public download path.

## 10. Central typed configuration and bounds

Checked-in defaults:

```toml
[jobs.job_openvex_export]
name = "openvex_export"
workers = 1

[jobs.job_openvex_export.settings]
enabled = false
author_kind = "organization"
author = ""
role = ""
action_statement = ""
repository_iri = ""
max_packages = 10000
max_bindings = 30000
max_artifact_bytes = 67108864
max_total_input_bytes = 536870912
max_document_bytes = 33554432
max_manifest_bytes = 134217728
max_action_bytes = 8192
max_identifier_bytes = 2048
timeout_seconds = 120

[jobs.job_openvex_export.steps.load]
workers = 1
[jobs.job_openvex_export.steps.load.tasks.verify_inputs]

[jobs.job_openvex_export.steps.export]
workers = 1
[jobs.job_openvex_export.steps.export.tasks.assemble]

[jobs.job_openvex_export.steps.acceptance]
workers = 1
[jobs.job_openvex_export.steps.acceptance.tasks.publish_handoff]
```

Implement frozen `OpenVexExportSettings` in the job's `settings.py`, parsed at config load
and revalidated at admission. All displayed keys are required; unknown keys, bool-as-int,
unsupported kinds and invalid nonempty inputs are errors even when disabled. Empty issuer/
action/repository values are allowed only while disabled. Require gate and review enabled
when automatic export is enabled; fail configuration explicitly if prerequisites are absent.

Displayed numeric defaults are schema hard maxima; operators may lower positive bounds.
Require `max_packages <= 10000`, individual input bound <= total input bound, and validate
actual UTF-8 byte sizes, unique reference count and aggregate unique input bytes.
No silent truncation. Enforce fixed local JSON depth <= 32 and bounded parsing before
unrestricted recursive schema work; reject duplicate keys/non-finite values in new documents.
Existing upstream readers remain the authority for their established schemas.

Use monotonic deadlines checked between bounded reads/validation/assembly phases and existing
resource admission where applicable. No retry loop for bad evidence. Use the central declared
exporter component release (or established platform release convention), schema and validation
identity in existing resume contracts; missing declarations must not silently allow reuse.
Do not configure arbitrary schema/context URLs, statuses, model settings, public destinations
or general remediation tools.

## 11. Orchestration, CLI and final-report integration

Register export in `runtime/registry.py`, CLI `POST_INDEX_JOB_IDS`, target-independent launch
policy and `orchestration/topology.py`. It follows gate; report remains the single terminal.
Optional PoC/export are siblings for Dagster; direct CLI runs them sequentially:

```text
review -> gate -> optional OpenVEX --+
             \-> optional PoC -----+-> final report
```

The report waits on each enabled optional tail, or directly on gate when neither is enabled.
Export reads gate/review, not PoC; report continues its separate compile-only PoC projection.
No exporter/report dependency cycle. Direct graph ordering, Dagster dependencies, standalone
upstream handoffs and resume propagation must agree for all four enabled combinations.
Do not create a PoC evidence prerequisite for affected.

Standalone invocation after enabling in original run configuration:

```text
appsec-review run job_openvex_export --run-id <id> --upstream-from-run
appsec-review run job_final_report_publication --run-id <id> --upstream-from-run
```

Disabled export stays outside automatic dispatch and is refused manually; no new
`MANUAL_JOB_IDS` exception. Original frozen settings apply. Existing accepted-handoff
dependencies and job settings/release identities provide cache invalidation; change no
generic runtime claim/hook machinery.

Add optional closed `openvex_export` to final-report JSON schema/builder/Markdown and export
to report `CONSUMES`. Keep `/1` only as an additive optional block preserving historical
reports; old required fields and review/ship-block semantics remain unchanged.

| Consumer state | Required behavior |
| --- | --- |
| `disabled` | Frozen export setting false; no new review gap merely for disabling. No OpenVEX file lookup or link. |
| `not_run` | Enabled but no accepted export, e.g. standalone report dispatched early; explicit missing-export publication limitation, no file link. |
| `available` | Current nonempty accepted export; verify its handoff/result/manifest/document, schemas, bytes and exact gate/review/config identity; show counts and local hashes/refs. |
| `no_statements` | Current accepted empty export; explicit zero/reasons, companion link, no document link, not a clean verdict. |
| `stale` | Valid export belongs to another gate/review/config/release; do not link document, explain rerun is needed. |
| Export failure | Not an accepted report-block state: normal graph execution stops at the failed export and does not produce a refreshed report. Existing runtime failure receipts/events expose the failure. |

Normal enabled export failure blocks report completion in both orchestrators. No global
fail-open behavior or new latest-failure receipt viewer is introduced. A standalone report
may describe missing/stale accepted export state but cannot represent a failed attempt as a
new accepted export. A previous immutable accepted export remains usable only if all current
gate/review/configuration/release pins and bytes still match; link its exact accepted handoff,
never claim it is the failed attempt's output. Changed-input or corrupt prior outputs are not
fallbacks. Corrupt handoffs/manifests/documents are report integrity failures, not caught
"not run"/stale success.
Availability gaps affect publication limitations/completion, not claim state, gate counts or
ship-block decisions. Never infer acceptance from file presence or a telemetry event.

## 12. First-class telemetry and metrics

Reuse `unit.job.events`/`PipelineLog`, `operation_span` and run-owned metrics aggregation.
Do not add an exporter SDK/network endpoint. Preserve existing correlated OWASP/review-flow
sections. Add `openvex` with semantics `appsec-review/openvex-metrics/1` as an additive metric
section; it is not proof that the target is safe or a handoff was accepted.

### Events

| Exact event | Emission and bounded details |
| --- | --- |
| `OPENVEX_EXPORT_STARTED` | Fresh attempt only: invocation/input-identity correlation, no sensitive content. |
| `OPENVEX_INPUTS_VERIFIED` | Package/bucket/binding counts, logical bound bytes and input hashes. |
| `OPENVEX_EXPORT_ACCOUNTED` | Included/excluded findings, statements/products, zero-filled exclusion counts and gate gap count. |
| `OPENVEX_EXPORT_COMPLETED` | Output validation completed: outcome, document-present flag, byte counts/hashes, result reference and measured duration. Runtime acceptance still must succeed. |
| `OPENVEX_EXPORT_FAILED` | Closed reason/phase and measured duration if available; re-raise the typed failure. |

Closed failure reasons: `configuration_invalid`, `input_missing`, `input_stale`,
`input_tampered`, `identity_conflict`, `schema_invalid`, `semantic_invalid`, `bound_exceeded`,
`timed_out`, `io_error`, `internal_error`.
Phases: `load`, `assemble`, `validate`, `accept`.
Known exceptions map deliberately; unexpected errors become `internal_error` and propagate,
not swallowed success. Reuse normal protected/sanitized diagnostics, never raw exception text
as a metric label. Admission failures before domain start are counted from runtime `JOB_FAILED`.

Use operation stages `openvex.verify_inputs`, `openvex.assemble`, `openvex.validate`,
`openvex.accept`. Runtime timing/resource samples belong only in logs/receipts/metric summary,
never deterministic document/manifest/result. Inclusive resources are not additive exclusive
work. Use existing `invocation_id` lifecycle deduplication; one terminal per fresh attempt.
An interrupted attempt has missing-terminal accounting, not fabricated duration/success.

### Exact metric contract

Named counters/histograms are fields in run-owned summary JSON, not a new service:

| Name | Type and allowed labels | Meaning |
| --- | --- | --- |
| `openvex_export_attempts_total` | Counter; `outcome = exported/exported_with_gaps/no_statements/failed` | One terminal fresh attempt, reconciled with runtime terminals. |
| `openvex_export_reuses_total` | Counter; no labels | Runtime `JOB_REUSED`, no fresh duration sample. |
| `openvex_export_failures_total` | Counter; closed `phase`, closed `reason` | Failures including pre-domain admission failure. |
| `openvex_export_statements_total` | Counter; `status = affected` | Accepted fresh statements only; explicit zero for accepted empty result. |
| `openvex_export_findings_total` | Counter; `disposition = included/excluded`, `reason = included/gate_verification_backlog/gate_withheld` | Every gate package once per accepted fresh result. |
| `openvex_export_document_bytes_total` | Counter; no labels | Actual canonical document bytes from accepted fresh nonempty results. |
| `openvex_export_duration_seconds` | Histogram; terminal `outcome` | Measured fresh wall duration; failures included when measurable. |
| `openvex_export_phase_duration_seconds` | Histogram; closed `phase` | Fresh operation measurements, not assumed exclusive total. |
| `openvex_export_document_bytes` | Histogram; no labels | Fresh accepted nonempty document sizes. |

Duration buckets (seconds): `0.01, 0.05, 0.1, 0.5, 1, 5, 15, 30, 60, 120, +Inf`.
Size buckets (bytes):
`1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 33554432, +Inf`.
Histogram JSON contains cumulative fixed buckets, `count`, `sum`, and measured/unmeasured
counts. Reuse/unmeasured crash produces no fake zero-duration sample.

Also expose `configured_enabled`, `latest_state`, latest accepted counts, zero-filled
exclusions and telemetry gaps/conflicts. `disabled`/`not_run` are explicit states, not successful
attempts. Failed/unreadable artifacts have null accepted counts with a named gap, not zeros.
Semantic counts come from bounded hash-verified accepted result sources, not only events.

Deduplicate lifecycle by `(run_id, job_id, attempt_id, invocation_id)` and accepted semantic
counts by accepted handoff digest. Real separate attempts count separately; distinguish
cumulative work from latest accepted output. A completed domain event followed by failed
runtime finalization does not increment accepted statements/bytes. Conflicting duplicate
terminals or a missing terminal produce telemetry gaps rather than double counts.

No finding/claim/product/run IDs, hashes, filesystem paths, repository/issuer/advice text,
source, credentials, or unbounded error/model strings as metric labels. Run/job/attempt/span
IDs are structured log correlation only. Avoid per-finding events and text-bearing labels.
Explicit zero differs from missing data. Surface telemetry write/aggregation failure under
existing runtime behavior; do not silently drop it.

## 13. Disclosure, bounds and trust controls

Target guidance, comments, scanner/model narratives, logs and retrieved records are data,
never instructions to choose an issuer, synthesize advice, enable export, retrieve a URL,
execute code or expand product scope.

All emitted files stay under `runs/<run-id>/` in attempt-owned paths. Use existing protected
writers/custody and protected dataset classification. POSIX files must not become
world-readable; Windows relies on the application's private run-root ACL boundary.
The exporter adds no broad catch silently accepting permission failures. Inspect regular-file,
symlink/parent escape, hash and exact run/snapshot/config bindings. Re-read accepted pointers
at final acceptance to detect concurrent replacement.

Both files can disclose vulnerabilities. Do not copy to public assets, releases, GitHub
attachments, repository instructions or outbound storage. No public-audience setting is
added. Local issuer enablement does not authorize external distribution.
Common advice is operator-reviewed public-safe plain text, but the companion stays internal:
paths, evidence, scores/policies are not appended to the small OpenVEX file.

Reject oversized inputs/outputs before acceptance. Count unique references and aggregate
bytes; do not repeatedly scan a target or unbounded run tree during inference/export.
Missing/skipped/failed review coverage is a named limitation, not evidence that a target is
unaffected. A hash authenticates bytes, not scope correctness or issuer authority.

## 14. Executable verification contract

Implement focused unit tests for each chunk using synthetic accepted fixtures and spies;
no live model/network/container/target scan. New test files below are proposed executable
names. Shared fixtures belong to the contract owner, not parallel workers.

| Suite | Required assertions |
| --- | --- |
| Contracts/schema | Raw upstream schema/lock hash, draft and installed-resource availability; valid document passes offline Draft202012Validator; missing action/author/time/version and unknown properties fail; empty statements fail upstream; schema-valid empty action/products, tool author, wrong context and invalid IRI/date fail semantics. |
| Settings | Exact keys; enabled missing issuer/action/repository rejected even with zero findings; disabled defaults valid; invalid nonempty values rejected; bool-as-int, all bound edges and one past; byte-vs-character limits; no provider/model/reasoning keys; task topology and prerequisites exact. |
| Inputs/products | Re-prove gate equals classifier output; both package-manifest hashes, ledger/scores/policy/scope/config pins; operator-declared repo versus matching/mismatching accepted acquisition; source identity not Git/branch/release; no guessed artifact hashes/purls; no current-target access. |
| Selection/accounting | Mixed publishable confirmed, supported backlog, confirmed withheld: each counted once, only publishable affected; state/bucket contradiction fails; missing severity/distinct verification and incomplete review retain original limitations without altering eligibility. |
| Unsupported statuses | Refuted/contradicted/unreachable observations, PoC absence/failure/compile success or failed/skipped coverage never create not_affected/fixed/under_investigation; supported does not become affected. No PoC/chain/dossier prerequisite. |
| Empty/limits | Zero packages/all backlog/all withheld yield accepted no_statements, null ref, absent VEX file, explicit gap and exact zeros/reasons. Invalid config is not no_statements. Output/input/ref/timeout boundary failures create no accepted subset or empty success. |
| Identity/replay | Permute input list/map/binding order and runtime scheduling; same pins produce identical bytes/IDs; valid UTC normalization, trailing LF/UTF-8; changed advice/author/product/gate timestamp/release changes identity; old ID not overwritten; no self-hash cycle or duplicate statements. |
| Integrity | Tamper gate pointer/doc, review handoff, lead/hunt manifests, scope, accepted manifest, ledger/projection, package/score/policy, frozen configuration, schema pin and each output separately. Cross-run/symlink/escape, changed pointer between load/accept and stale gate after review rerun fail closed; no broad skip or stale fallback. |
| Report/CLI/topology units | Disabled excluded/refused manually; all four PoC/export combinations retain one report terminal; no cycles/PoC dependency in export; standalone upstream sets exact; available/empty/not-run/stale blocks correct; failed export blocks normal report completion, no changed-input fallback; corrupt export fails report; historical reports remain valid; review/ship-block dimensions unchanged. |
| Inventory/privacy | All emitted datasets claimed once/protected; absent doc reason correct; no source/advice/secrets/PoC code in events/metric labels; only metadata route; no automatic upload or external schema/context fetch. |
| Metrics | Fresh/reused/failed/empty exact counts; accepted-only bytes/statements; exclusion sum exact; zero vs unavailable; histogram boundary/cumulative counts; duplicate/conflicting terminals, torn log and pre-domain/missing-terminal accounting; same log deterministic summary; timing absent from deterministic artifacts. |

Use doubles that fail on inference, source traversal, Git/subprocess/container calls and URL
retrieval. Assert required output shape and exact byte-size thresholds, not merely a validator
returning true.

### Focused unit-test commands

Follow current `AGENTS.md` and multi-session coordination before testing. Prefer a Linux/WSL
Linux-filesystem worktree and its own editable virtual environment; native Windows requires
the user's explicit session permission. Confirm `appsec_review.__file__` is inside the tested
worktree. Install dependencies only after a selected command reports missing dependencies or
a dependency manifest changes. Keep all disposable state under the unique listed basetemp.

The following POSIX commands are the implementation contract; explicitly authorized Windows
sessions substitute `.\.venv\Scripts\python.exe` and Windows filesystem separators:

```text
.venv/bin/python -m pytest -q tests/test_openvex_contracts.py tests/test_openvex_settings.py --basetemp=test/tmp/openvex-contracts
.venv/bin/python -m pytest -q tests/test_openvex_inputs.py --basetemp=test/tmp/openvex-inputs
.venv/bin/python -m pytest -q tests/test_openvex_projection.py --basetemp=test/tmp/openvex-projection
.venv/bin/python -m pytest -q tests/test_openvex_metrics.py tests/test_review_metrics.py --basetemp=test/tmp/openvex-metrics
.venv/bin/python -m pytest -q tests/test_openvex_job_units.py tests/test_openvex_report_units.py tests/orchestration/test_topology.py tests/test_config.py tests/test_job_selection.py --basetemp=test/tmp/openvex-integration-units
.venv/bin/python -m pytest -q tests/test_documentation.py tests/test_skill_separation.py tests/test_docs_sync.py --basetemp=test/tmp/openvex-docs
```

The integration owner adds focused cases in existing registry/launch/CLI/publication unit
files as appropriate, inspecting markers/fixtures before selecting tests. Do not call a
scripted whole review chain a unit test simply because it uses no network.

### Manual integration/acceptance still required

Current repository guidance reserves integration, acceptance and live Dagster validation to
the user unless explicitly requested. Specify, but do not automatically execute:

```text
.venv/bin/python -m pytest -q tests/test_openvex_export_chain.py tests/test_final_report.py --basetemp=test/tmp/openvex-chain
.venv/bin/python -m pytest -q tests/orchestration/dagster/test_openvex_export.py --basetemp=test/tmp/openvex-dagster
```

The first drives a scripted accepted review -> gate -> export -> report through the actual
runner, asserting accepted hashes, replays/tamper rejection and unchanged optional compile-only
PoC behavior. The second verifies in-process and multiprocess graph tail fan-in and
enabled-export failure blocking. Network/model/container must remain disabled.
Report exact tested commit, commands, results, environment gaps and outstanding manual checks;
unit success is not a claim that integration/acceptance ran. No full-suite default.

Definition of done: correct affected-only scope/advice; offline schema+semantic validity;
exact non-clean empty/error accounting; tamper/stale/replay guarantees using existing
lifecycle; CLI/graph/report/inventory parity; protected disclosure; measured/tested telemetry;
all focused units pass; docs truthful about what is implemented and manually unverified.

## 15. Ownership partition and coordinator handoff

The coordinator owns integration decisions and shared-file arbitration. Each agent starts in
an isolated app worktree containing an exact supplied contract commit, confirms ancestry with
`git merge-base --is-ancestor <contract-commit> HEAD`, commits with the required coauthor,
does not push, and reports branch/commit/APIs/tests/deviations. This design agent starts no
other agents and changes only this document.

### Wave 0: shared contract, one owner

Own new `job_openvex_export/contracts.py`, `settings.py`, `__init__.py`,
`jobs/engineering_contracts.py`, local/upstream schema files/lock,
`tests/test_openvex_contracts.py`, `tests/test_openvex_settings.py` and
`tests/openvex_support.py`. Freeze enums, typed records, schema hashes, identity helpers,
text/bounds/errors, settings and fixture shapes before parallel implementation.
Do not add a half-working registry entry. Contract tests import no unimplemented chunks.

Public API contract:

```text
verify_inputs(run_root, settings, repository_root) -> VerifiedInputs
assemble_export(verified_inputs, settings, exporter_release) -> ExportBundle
validate_export(bundle, verified_inputs, settings) -> None
load_export_for_report(run_root, gate_reference, resolved_config_sha256) -> ExportReportView
aggregate_openvex_metrics(run_root, validated_events) -> Mapping
build_job(repository_root=None) -> Job
```

`VerifiedInputs` is immutable verified state, not unvalidated free-form dictionaries.
`ExportBundle` holds document/null, companion/result bodies and canonical bytes; pure assembly
does not write or emit events. Filesystem access uses platform `Path`; artifact wire paths
remain the repository's existing run-relative POSIX format. Proper enums/guards/types, no
unnecessary casts or new generic framework.

### Wave 1: independent files after contract commit

| Chunk | Exclusive files | Deliverable / command |
| --- | --- | --- |
| Input verification | New `job_openvex_export/inputs.py`; `tests/test_openvex_inputs.py` | Accepted gate/review/scope/config verifier, bounded identity resolution and source-product provenance. Run `openvex-inputs` selector. |
| Projection/validation | New `job_openvex_export/projection.py`, `validation.py`; `tests/test_openvex_projection.py` | Pure canonical document/manifest/result assembly, exact selection/accounting/IDs and offline schema/semantic validation. Run `openvex-projection` selector. |
| Telemetry | New `job_openvex_export/metrics.py`; `observability/telemetry.py`; `tests/test_openvex_metrics.py` | Bounded event/metric contracts, summaries, counters/histograms, artifact-backed accepted totals and failure/empty/reuse accounting. Run `openvex-metrics` selector. No changes to runtime/events/spans internals. |

Chunks import the frozen contracts, never edit them silently. Contract concerns return to
its owner. Coordinator merges one verified chunk at a time, checking file ownership and the
combined focused unit set.

### Wave 2: final integration, one owner after Wave 1

Own new `job_openvex_export/job.py`, `datasets.py`, `reporting.py`; central
`appsec-review.toml`, `config/loader.py`, `runtime/registry.py`, target-independent declarations
in `runtime/launch.py`, `orchestration/topology.py`, only necessary Dagster adapter wiring,
`cli.py`, final-report package/schema, installed-schema packaging in `pyproject.toml`,
inventory expectations if needed, and all integration/report unit tests.
No generic changes to `runtime/job.py`, `runner.py` or `resume.py`.

This owner alone wires accepted handoffs, event emission, resource deadlines, protected writes,
standalone/automatic topology, report states, schema resources and publication audit. It
alone adjusts existing registry/config/CLI/report/inventory assertions. Own new
`tests/test_openvex_job_units.py`, `tests/test_openvex_report_units.py`,
`tests/test_openvex_export_chain.py`, and
`tests/orchestration/dagster/test_openvex_export.py`. Run focused units automatically;
write and report manual acceptance selectors without claiming they ran.

### Documentation agent after the design

The coordinator starts the requested documentation agent with this exact design commit and
eventual contract/implementation commits. It may draft proposed docs during implementation,
but reconciles against merged source before calling them shipped.
Proposed exclusive files: `docs/operations/openvex-export.md`, relevant navigation in
`docs/agent-reader.md`, `docs/operations/final-report.md`, `docs/operations/metrics.md`, and
README feature/CLI notes. Coordinator arbitrates overlaps and updates this design's status
after implementation; do not edit `docs/docs-sync.json` without the full prescribed pass.

Required diagrams: accepted-gate/config trust/data flow to OpenVEX+protected companion;
optional PoC/export tail fan-in; nonempty/empty/failure report-state flow.
Document issuer/action setup, source-not-release identity, immutable-run restriction,
disabled/manual refusal, internal-only disclosure, validated example, metrics and compile-only
PoC distinction. Run the `openvex-docs` selectors.

### Remaining choices and final landing

No open product choice blocks the narrowed v1. Operators must supply the actual issuer,
accurate common action statement and stable repository/system IRI for each enabled run;
the design deliberately supplies no fake defaults. Per-finding actions, verified released
artifact/purl mapping, stronger issuer authentication/signing and external publication are
future product decisions, not implementation assumptions.

Design-only handoff is one commit modifying this document only. The coordinator owns
subsequent implementation/docs agents, merged focused unit verification and the user's
requested local-main merge/commit. This agent does not touch local main, push or create a PR.

## 16. Implementation reconciliation

- The three units, typed central settings, registry, direct CLI/Dagster topology, protected
  datasets, optional final-report states, offline validation and accepted-only metrics are
  implemented. The disabled exporter is not a manual-dispatch exception. Enabled PoC and
  OpenVEX jobs are independent gate tails, both awaited by the final report.
- `VerifiedInputs.input_inventory` contains durable immutable evidence and the eight run-owned
  schema/license/lock snapshots. Exact job `latest.json` admission pointers and
  `data/indices/accepted.json` remain measured, bounded and reproved within input verification,
  but are not persisted as durable evidence. This permits valid upstream reruns to make an
  old export stale without falsely treating its historical bytes as tampered.
- Acceptance rechecks the original current gate/review boundary and exact canonical outputs.
  The historical accepted-output reader also rehashes every runtime-declared artifact and
  rejects duplicate artifact paths. The current report reader additionally re-proves upstream
  authority; stale, absent and disabled states expose no old output links or invented counts.
- The timeout covers the original runtime claim's attempt start across units. Completion is
  emitted only after final result reading and the deadline check; a domain completion still
  does not establish runtime acceptance.
- The review handoff's closed consumer vocabulary additionally names `job_openvex_export`;
  existing four-consumer handoffs remain schema-valid. Finding-package/2, adjudication,
  finding states, gate eligibility and ship-block policy are unchanged.
- The wheel includes all pinned exporter resources and final-report schema dependencies.
  Installed-only pure assembly and offline validation work without source resources. A full
  job still requires the existing application guidance and upstream review resources; this is
  not a new self-contained application distribution.
- Focused handler tests use small hash-bound run artifacts with an explicitly doubled upstream
  review authority, not a fabricated claim that an entire real review chain was exercised.
  Full integration, acceptance and live Dagster validation remain manual and unexecuted.
  The concrete delivered selectors are listed in the implementation record rather than the
  provisional test filenames in the ownership plan above.
