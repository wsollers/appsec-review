---
title: "Job interchange and native-result provenance"
kind: "architecture"
subsystem: "runtime interchange"
status: "current"
jobs: []
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Job interchange and native-result provenance

The shared contracts are implemented in
[`interchange.py`](../../src/appsec_review/interchange.py). Runtime publication, operational
consumers, receipt-derived metrics, and the static-evidence, CodeQL, and produced-artifact provenance
slice are integrated. The presence of a type or schema does not establish that every producer
uses native provenance or that a deployment has been accepted. See the
[implementation record](../reviews/job-interchange-implementation.md).

The [JSON Schema](../schemas/job-interchange.schema.json) uses Draft 2020-12 and local `$ref`s only.
Its root accepts a handoff, outcomes document, common observation metadata, native-result reference,
or producer gap.
`$defs` also exposes artifact references, selectors, coverage, and unit outcomes. The schema
describes serialized records, including explicit null/default fields, not Python constructor
arguments. Validate offline with an installed Draft 2020-12 validator; the schema's `$id` is an
identifier, not a required network resource.

## One envelope, domain-owned outputs

`appsec-review/job-handoff/2` retains the existing flat `outputs`, `artifacts`, upstream/configuration
hashes, implementation/schema/validator/tool identities, timestamps, and resolving paths. It adds
explicit `run_id`, `target_snapshot`, `execution_status`, `input_manifest`,
`dataset_contract_sha256`, `input_set_sha256`, `coverage`, and `outcomes`. It does not wrap every
job's output in a scanner-shaped document or replace existing index manifests.

| Field | Meaning |
| --- | --- |
| `status` | Admission: `ACCEPTED` or `REJECTED`; never a vulnerability verdict |
| `execution_status` | Framework execution: `SUCCEEDED`, `FAILED`, or `SKIPPED` |
| `completion_status` | Existing producer/runtime terminal status, retained independently |
| `source_fingerprint` | Resume/source-input identity; not interchangeable with evidence snapshot identity |
| `target_snapshot` | Evidence target identity against which catalog-backed locations resolve |
| `input_manifest` | Exact `{path, sha256, size_bytes}` reference or explicit `null` |
| `dataset_contract_sha256` | Identity of the applicable dataset contract |
| `input_set_sha256` | Canonical hash of the shared input projection, not a hash of the whole handoff |
| `coverage` | Closed `{disposition, gap_count, retry_required}` summary |
| `outcomes` | Handoff-bound reference to detailed `outcomes.json`; required for accepted publications |

An accepted publication can have partial, unavailable, not-applicable, or policy-skipped coverage.
`complete` requires zero gaps and no retry. A failed framework execution cannot be accepted.
Diagnostic publications use separate `rejected-handoff.json` and `rejected-outcomes.json` files,
remain `REJECTED`, and never update accepted/latest pointers. They preserve any already-published
accepted `handoff.json` and `outcomes.json` bytes.
Acceptance verifies a publication contract; it does not certify complete analysis or a clean target.

The detailed `appsec-review/job-outcomes/1` artifact accounts for `UnitOutcome` and `ProducerGap`
records instead of growing the common envelope with every unit result. A unit names its execution
and native producer status, coverage disposition, result/status references, and gap IDs. A gap
names its stable hash ID, closed code, optional unit/scope, reason, retryability, and resolving
artifact references. Missing, blocked, failed, empty, unparsed, truncated, and unresolved evidence
remain distinguishable. A producer status outside `interchange.ProducerStatus` rejects a new
publication (see the control layer below); in diagnostic reconstruction of an older attempt it
classifies as unavailable, never complete.

The outcomes root is `{schema, run_id, job_id, attempt_id, target_snapshot, units, gaps, coverage}`.
`units` and `gaps` are arrays of serialized shared records; `coverage` is the same summary bound by
the handoff. In [`runtime/handoff.py`](../../src/appsec_review/runtime/handoff.py),
`build_outcomes` derives accounting from the claim's unit topology, verified task terminal receipts,
and explicitly declared producer status/gaps, not arbitrary nested tool payloads or narrative text.
Producer `dispositions` is a typed array of scope records, not a numeric count map. The target
analysis plan uses `disposition_counts` for selected/skipped scanner and model-call counts.
Malformed producer arrays reject acceptance; diagnostic reconstruction records unavailable
coverage and `unknown_producer_status` without treating invalid declarations as success.
`verify_outcomes(run_root, handoff)` reconstructs that document and requires canonical equality;
`verify_handoff_integrity(run_root, handoff, accepted_only=True)` also verifies frozen configuration,
claim/input/dataset identities, result binding, and required outputs. Both are separate from
structural decoding. `INVALID_COMPILE_DATABASE` and `BLOCKED_BY_COMPILE` are nonretryable;
verified `coverage.retry_required` drives producer retry planning.

Publication binds the frozen `data/configuration/manifest.json`, `resolved.json`, and
`appsec-review.toml` files as run artifacts. Source inventory path/hash fields and exact frozen
source-layer identities are metadata, not authority to open external paths. Declared run-artifact
fields and run `data/` references still require safe resolution and exact byte verification.
Source inventories remain source data even when a target-relative filename starts with `data/`.
For scoped binary results, explicit `run_path` selects the retained run bytes; a display `path`
does not replace that identity.
Required-index preflight and input-manifest consumption finish before the publication freezes its
artifact closure. If later publication I/O fails, the runtime attempts to restore both the job
latest pointer and accepted-index pointer; rollback errors are attached to the original failure.

## The control layer beneath the envelope

The envelope above is one shape for every job and byte-verified. The records beneath it that every
consumer reads form the **job control layer**, and they are standardized and validated the same way
(`docs/schemas/job-control.schema.json`, `src/appsec_review/interchange.py`):

| Record | Schema id | Where | Contract |
| --- | --- | --- | --- |
| Task receipt | `appsec-review/task-receipt/1` | `steps/<step>/tasks/<task>/status.json` | closed keys; `status` in `RUNNING`/`SUCCEEDED`/`FAILED`/`SKIPPED`; binds `result_sha256` |
| Attempt status | `appsec-review/attempt-status/1` | `attempts/<attempt>/status.json` | `RUNNING` at claim, then the terminal attempt status |
| Unit execution | `appsec-review/unit-execution/2` | `attempts/<attempt>/result.json` | the only version written; `/1` is read for older attempts |
| Unit output | `appsec-review/unit-output/1` | the control fields of a unit's `result.json` | `interchange.UNIT_OUTPUT_KEYS` is exactly what the runner projects into handoff `outputs` |
| Producer status | `interchange.ProducerStatus` | `terminal_status` and `dispositions[].terminal_status` | **closed**: nineteen words; anything else (`NOT_RUN`, `NOT_REQUESTED`, `REUSED`, ...) is a payload fact (`mode`, `availability`, `probe_disposition`), never a status |
| Producer gap | `appsec-review/producer-gap/1` | `gaps[]` of a unit result | `interchange.producer_gap(code, reason, unit_id=, scope_id=, retryable=, evidence_refs=)`; free text is tolerated only for jobs listed in `tests/test_gap_contract.py` |

Validation happens at publication: `build_outcomes` runs `interchange.validate_unit_output` over
every succeeded unit result, and a violation **rejects the attempt** (`rejected-handoff.json`,
`REJECTED`, no `latest.json`) instead of publishing it with an `unknown_producer_status` gap. A job
with `Job.strict_gaps = True` is also rejected when a gap is not a `producer-gap/1` record. Older
accepted attempts remain verifiable as recorded; the vocabulary is enforced on new publications.

Consumers read producers through one path, `runtime.consume.accepted_upstream(run_root, job_id)`.
Inside an attempt it requires a typed `Job.contract` handoff declaration and resolves only the
digest admitted in `claim.upstream_handoffs`. `claim.consumable_handoffs` is availability metadata,
not authority; accepted topology ancestors grant no read permission. Explicit empty supply remains
empty, while an unspecified standalone supply selects declared inputs through typed admission.
The reader records actual access through `input_read_scope`; supplied-but-unread inputs stay unread,
and observation never asserts citation. Foreign-run reads and caught permission errors fail closed.
Outside any runtime scope, operator tooling follows the verified pointer and reports `pinned=False`.
`accepted_latest` is restricted to the active job's own cache or unscoped operator tooling.
No job reads another producer's `latest.json` directly. `CONSUMES` is derived from the typed
contract; parity tests verify registered producers and graph scheduling without turning scheduling
into evidence permission.

The closed task-receipt schema includes `input_consumption` on both successful and failed typed
units. Its closed `input-reads/1` document and read records preserve producer, output, schema,
channel, authority and pinned identities with `read=true`, `cited=null` and
`citation_observation=not_observed`. Failed receipts also retain their measured `duration_ms`.
The root schema's `oneOf` reserves task-receipt and attempt-status schema IDs for their own
branches. A malformed reserved receipt cannot fall through as a permissive unit-output payload.

## Validation and identity boundaries

JSON Schema checks fields, types, enum values, canonical run-relative artifact path syntax,
lowercase SHA-256 shape, and closed shared records. It deliberately leaves the envelope extensible
and `outputs`, `tool_identity`, and producer payloads domain-owned. Source locations continue to
use `appsec-review/source-location/1` and `SourceLocation` in
[`retrieval/model.py`](../../src/appsec_review/retrieval/model.py); this contract introduces no
competing location format.

Schema validation is not byte admission. `decode_handoff` also checks the input-set hash, unique
artifact paths, exact membership of manifest/outcomes references in `artifacts`, expected run/job
identities, and any `evidence_target_snapshot` extension against `target_snapshot`.
Filesystem admission must additionally verify safe resolution, size and digest, immutable producer
identity, upstream binding, outcomes consistency, and selector resolution. A reversed/out-of-bounds
byte selector or a syntactically valid but nonexistent JSON pointer is not accepted evidence.
Neither schema shape nor a correct hash proves a scanner ran or that its result is true.

Strict assurance re-verifies referenced evidence at the trust boundary. Managed assurance requires
an authenticated, unique accepted evidence-target binding; it must not select an arbitrary upstream
snapshot or silently substitute a source fingerprint. Verified upstream disagreement is an
integrity failure in either mode.

Prepared claims compare canonical dispatch identity with persisted preparation in strict and
managed modes; managed claims additionally authenticate it. Reused claims reverify accepted
handoff bytes, run/job/attempt/target/upstream identities, and admission at dispatch.
An idempotent finalization retry revalidates the immutable accepted handoff before reuse; it does
not rewrite accepted history or grant freshness based on a pointer alone.

The input-set projection contains `resolved_config_sha256`, `job_config_sha256`,
`source_fingerprint`, `target_snapshot`, `input_identity`, `dataset_contract_sha256`,
`upstream_handoff_sha256`, `implementation_identity`, `schema_identity`, `validation_identity`,
`tool_identity`, and `input_manifest_sha256` (null when no manifest exists). The helper hashes
canonical UTF-8 JSON with sorted keys, compact separators, non-ASCII preserved, and NaN forbidden,
under `{"schema":"appsec-review/job-inputs/1","identity":<projection>}`.
Use the shared helper rather than independently reimplementing this projection.

### Evidence header, evidence body and the content identity

Every published `appsec-review/job-handoff/2` document is partitioned into an **evidence header**
(provenance, never part of any identity) and an **evidence body** (what the attempt produced). The
document stays flat; this partition is the definition, and `runtime/equivalence.py` implements it.
Two accepted attempts of a job are **equivalent upstreams** when their bodies hash equal, whatever
their attempt ids, timestamps or paths. A handoff without the hash is never equivalent to anything.

| Part | Fields |
| --- | --- |
| Header | `schema`, `run_id`, `job_id`, `attempt_id`, `status`, `started_at`, `completed_at`, `implementation_identity`, `schema_identity`, `validation_identity`, `tool_identity`, `resolving_paths`, `artifacts` (the path map), `outcomes` (reference), `input_manifest` (reference), `input_identity`, `input_set_sha256`, `upstream_handoff_sha256`, `resolved_config_sha256`, `job_config_sha256`, `source_fingerprint`, `target_snapshot`, `content_sha256` |
| Body | `outputs` (every string with this attempt's `attempts/<attempt_id>/` normalised to `attempts/@/`), `unit_outputs` (the complete unit results, `result.json` `outputs`, normalised the same way), `artifact_content` (sorted `[sha256, size_bytes]` pairs of the attempt-root files, see below), `coverage`, `completion_status`, `execution_status`, `gaps` (the `producer-gap/1` records of `outcomes.json`), `dataset_contract_sha256`, `evidence_target_snapshot`, `upstream_content_sha256` (`{producer: content_sha256}` of every pinned upstream handoff) |

`content_sha256` is the SHA-256 of the canonical JSON (sorted keys, compact separators, UTF-8) of
`{"schema": "appsec-review/handoff-content/2", "body": <body>}`. It is an optional header field;
its presence is the version signal, and the schema pattern-checks it. The runner emits it only on an
accepted handoff whose every pinned upstream carries one, so equivalence is transitive: a changed
grandparent changes every descendant's hash. `artifact_content` covers the files under the attempt
root except the runtime's own bookkeeping, which embeds attempt ids, timestamps or dispatch
identity: `claim.json`, `status.json`, `published.json`, `outcomes.json`, `result.json`,
`revalidation.json`, and everything under `logs/`, `events/`, `steps/` (unit receipts carry
timestamps; the unit results themselves are the body's `unit_outputs`) and `shared/` (computation
receipts, whose objects are referenced from `outputs`). Artifacts outside the attempt root (the frozen configuration, the
input manifest) are run-level and belong to the header.

Rules: nothing hashes a file including its own header; a file-level hash (`handoff_sha256` in
`latest.json`, `upstream_handoff_sha256` pins, `verify_handoff`) stays a whole-file hash and is
used for binding and admission, never for equivalence. **A field moving between header and body is
a content-identity change** and must come with a note in this section (and a new
`handoff-content` schema id). Interim rule: artifact identity by content pairs and attempt-path
normalisation stand in for artifacts referenced by content hash throughout the body.

Content-identity changes: <!-- historical:begin -->`handoff-content/1`<!-- historical:end --> hashed only the `outputs` projection, so a unit whose
evidence lives in its result document alone (no interchange output keys) hashed equal across
different results; `/2` adds `unit_outputs`. Handoffs carrying a `/1` identity are never equivalent
to `/2` ones because the hashes differ.

New typed attempts embed `appsec-review/job-contract/1` in `appsec-review/attempt-datasets/3`.
The existing dataset-contract identity therefore invalidates reuse after an input/dispatch contract
change. Dataset `/1` and `/2` remain readable for historical accounting, without inventing their
missing read provenance. `claim.json` records admitted availability/supply; existing hash-bound
unit status receipts carry `appsec-review/input-reads/1`. These record reader access, not model
citation or use in reasoning. See [job input contracts](job-input-contracts.md).

## Native result and common observation

`appsec-review/native-result-reference/1` binds a retained immutable file by path/hash/size to a
specific original result and parser identity. Its selector is `document` with null value,
`json_pointer` with an RFC 6901 pointer, `xml_ordinal` with `{element, ordinal}`, or `byte_range`
with `{start, end}`. Execution and retention receipt references are explicit references or null;
`complete` describes retained-result completeness, not total scanner coverage.

[`provenance.py`](../../src/appsec_review/provenance.py) provides `retain_native_output`,
`select_native`, `verify_native_reference`, `common_metadata`, and
`validate_observation_provenance`. Retention detaches the exact parser-input bytes into
`data/shared/objects/<sha256>` and records an immutable `shared/native-output` receipt.
Operational native verification requires that content-addressed path and a verified retention
receipt, even though a missing receipt is representable as null in the pure wire type.
`verify_native_reference(..., resolve=True)` resolves a selector; publication validates observation
selectors once against retained bytes instead of reparsing scanner reports during inference.
XML ordinals are zero-based among elements with the exact expanded XML tag. Byte ranges use
start-inclusive, end-exclusive offsets.

A retention receipt proves what the application retained, not scanner origin. Execution evidence
and scanner identity are separate. Partitioned/merged output must cite each original invocation
and original result selector, not pretend a synthesized aggregate came directly from the scanner.
Normalization coalesces identical native-reference values, but retains distinct selectors and
invocation identities supporting a collapsed observation. Deduplicating storage must not discard
those distinct provenance edges. The pure wire schema also permits repeated reference entries.
Capture or normalization bounds require explicit truncation/completeness and coverage gaps.

Bounded reports available after a failed or timed-out invocation are retained as incomplete
diagnostic evidence. A failed CodeQL action's SARIF is diagnostic-only and produces no normalized
finding observations. A no-package or `SKIPPED_NA` result retains its available native/execution
reference closure without becoming security-negative evidence. Empty scanner JSON is a parser
failure, not an empty successful result.

`appsec-review/observation/1` is common metadata attached to a domain-owned record. It contains:
`observation_class`, `record_kind`, scanner/rule identity, `reported_severity`, `evidence_refs`,
`gap_ids`, and `payload_schema`. Severity preserves normalized `value` and nonempty native value,
basis, and mapping rule. Classes distinguish SAST, secret, dependency, configuration, inventory,
binary, diagnostic, and other evidence; record kinds distinguish finding-shaped scanner output,
scan summaries, and observations. Even `record_kind = "finding"` is not adjudicated confirmation.
Empty evidence references are structurally possible; they are not proof of provenance.

Retrieval prefers validated common metadata for scanner, rule, severity, and class. Legacy
indexed observations without it receive a semantic projection with empty native references and
an explicit `provenance_unavailable` gap; malformed common metadata fails rather than falling
back. This is not permission to admit a legacy `/1` handoff. The closed common projection
preserves the semantic `secret` class and safe canonical reference/selector fields while ordinary
payload redaction remains unchanged.
Bytecode-analysis findings classify as `source_sast`; inventory and scanner diagnostics remain
separate observation classes/record kinds.

The concrete provenance slice covers static evidence collection, CodeQL SARIF normalization, and
produced-artifact scanners. Producer-specific paths outside that slice remain named provenance
gaps until implemented and verified. Do not infer universal scanner coverage from the common type.

## Constructing self-consistent examples

This example constructs actual reference and input hashes from bytes. It first creates a
**rejected diagnostic**, then a self-consistent **accepted wire fixture** with explicit unavailable
coverage and a provenance gap. The fixture uses synthetic native bytes; it does not persist files,
claim that a scanner ran, or grant operational admission. Real accepted publication requires
run-owned bytes, valid producer outputs, and all runtime admission checks.

```python
import hashlib
import json

from appsec_review.interchange import (
    ArtifactReference, CoverageSummary, NativeResultReference, ObservationMetadata,
    ProducerGap, ResultSelector, UnitOutcome, decode_handoff, gap_id,
    handoff_input_projection, input_set_sha256,
)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

native_bytes = canonical({"results": [{"ruleId": "example.rule", "level": "warning"}]})
native = NativeResultReference(
    artifact=ArtifactReference(
        "data/example/native.json",
        hashlib.sha256(native_bytes).hexdigest(),
        len(native_bytes),
    ),
    selector=ResultSelector("json_pointer", "/results/0"),
    parser_identity="example-json-parser/1",
    execution_reference=None,
    retention_receipt=None,
    complete=True,
)
gap = ProducerGap(
    gap_id=gap_id({"unit": "example-unit", "reason": "synthetic input; no execution receipt"}),
    code="provenance_unavailable", unit_id="example-unit", scope_id=None,
    reason="Synthetic input; no scanner execution receipt", retryable=False,
    evidence_refs=(native.artifact,),
)
observation = ObservationMetadata(
    observation_class="source_sast",
    record_kind="finding",
    scanner="example-scanner",
    rule_id="example.rule",
    reported_severity={
        "value": "medium", "native": "warning",
        "basis": "example mapping only", "rule": "example-level-map/1",
    },
    evidence_refs=(native,),
    gap_ids=(gap.gap_id,),
    payload_schema="example/scanner-record/1",
)
handoff = {
    "schema": "appsec-review/job-handoff/2",
    "run_id": "example-run", "job_id": "example-job", "attempt_id": "example-attempt",
    "status": "REJECTED", "completion_status": "FAILED", "execution_status": "FAILED",
    "outputs": {}, "artifacts": [], "upstream_handoff_sha256": {},
    "resolved_config_sha256": digest({"config": "example"}),
    "job_config_sha256": digest({"job_config": "example"}),
    "source_fingerprint": "example-resume-source",
    "target_snapshot": "example-evidence-snapshot",
    "implementation_identity": "example-implementation/1",
    "schema_identity": "example-job/1", "validation_identity": "example-validator/1",
    "tool_identity": {}, "input_identity": None, "input_manifest": None,
    "dataset_contract_sha256": digest({"dataset_contract": "example"}),
    "coverage": {"disposition": "unavailable", "gap_count": 1, "retry_required": True},
    "outcomes": None, "resolving_paths": {},
    "started_at": "2026-10-28T15:00:00Z", "completed_at": "2026-10-28T15:00:01Z",
}
handoff["input_set_sha256"] = input_set_sha256(handoff_input_projection(handoff))
decode_handoff(handoff, run_id="example-run", job_id="example-job", accepted_only=False)
coverage = CoverageSummary("unavailable", 1, False)
outcome = UnitOutcome(
    unit_id="example-unit", execution_status="SUCCEEDED", producer_status=None,
    coverage_disposition="unavailable", result_reference=native.artifact,
    status_reference=None, gap_ids=(gap.gap_id,),
)
outcomes = {
    "schema": "appsec-review/job-outcomes/1",
    "run_id": handoff["run_id"], "job_id": handoff["job_id"],
    "attempt_id": handoff["attempt_id"], "target_snapshot": handoff["target_snapshot"],
    "units": [outcome.as_dict()], "gaps": [gap.as_dict()], "coverage": coverage.as_dict(),
}
outcomes_bytes = canonical(outcomes)
outcomes_ref = ArtifactReference(
    "data/example/outcomes.json", hashlib.sha256(outcomes_bytes).hexdigest(),
    len(outcomes_bytes),
)
accepted = {
    **handoff, "status": "ACCEPTED", "execution_status": "SUCCEEDED",
    "completion_status": "COMPLETED_WITH_GAPS",
    "artifacts": [native.artifact.as_dict(), outcomes_ref.as_dict()],
    "outcomes": outcomes_ref.as_dict(), "coverage": coverage.as_dict(),
}
accepted["input_set_sha256"] = input_set_sha256(handoff_input_projection(accepted))
decode_handoff(accepted, run_id="example-run", job_id="example-job")
print(json.dumps({
    "diagnostic_handoff": handoff, "accepted_handoff": accepted, "outcomes": outcomes,
    "native_result": native.as_dict(),
    "common_observation": observation.as_dict(),
}, indent=2))
```

Validate each printed document separately against the schema root, not the illustrative outer
object. `outcomes_ref` hashes exactly `outcomes_bytes`, not an independently pretty-printed copy.
For operational publication use the runtime publisher, not this fixture or a manual status edit.

## Migration, retrieval, and standards

Handoff `/1` is not operationally admitted or resumed as `/2`. Preserve historical attempt files,
plan a rerun with `handoff_schema_changed`, and rebuild affected downstream publications. Never
edit the old JSON, synthesize missing identities, or silently upgrade an accepted pointer.
CodeQL normalization/provenance invalidation is separate from database creation: a normalizer-only
change must not invalidate an otherwise valid database checkpoint.

The transport and storage model are unchanged: immutable SQLite shards, accepted manifests, and
bounded paginated retrieval. Index safe native-output metadata and resolving references, not
protected report bodies. A path is not a new inference file-reading capability. Existing catalog
hashes still bind source excerpts; raw reports, credentials, and secret values remain protected.
See [indexing](indexing-and-query-reuse.md), [telemetry](telemetry.md), and
[metrics operations](../operations/metrics.md).

No external exporter is added by this slice. SARIF remains native CodeQL ingestion; standards
exports, when implemented, are derived views of accepted evidence, not replacements for job
receipts. OpenVEX product-impact statements require explicit product/version/vulnerability
identity and evidence-bound adjudication. Zero results, disabled/failed tools, inventory, and
truncation never imply `not_affected`. CycloneDX and SPDX remain specialty SBOM formats, not
universal replacements for the domain payloads.
