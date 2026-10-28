# OpenVEX shared contracts

These are **Wave 0 contracts, not an installed exporter**. No registry, dispatch, TOML,
runtime, report, telemetry aggregation or installed-resource wiring is introduced here.
The export design is [OpenVEX findings export](../../architecture/openvex-export.md).
For upstream publication contracts, the later
[evidence-completion architecture](../../architecture/evidence-completion-and-remediation.md)
is authoritative: accepted review `/3`, one gate `/2` after completion producers, and a
gate-only report `/2`. These shared contracts are reconciled against exact candidate
`7f4c9b0a1e099fd507c33611f78c2cc890f05a5f`; they do not implement or alter that graph.

The official OpenVEX v0.2.0 schema is retained byte-for-byte under `upstream/`, at commit
`61b5f885d0f481f48683c93345e49ef1a6e9fdff`. Its SHA-256 is
`9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238`.
The pinned upstream LICENSE is CC0-1.0; `upstream/upstream.lock.json` retains source URLs,
byte hashes, sizes and OpenVEX contributor attribution. No runtime download is permitted.

## Public Python boundary

`src/appsec_review/jobs/job_openvex_export/contracts.py` imports no unimplemented chunks.
All records are frozen/slotted. JSON object fields are copied recursively into immutable
mapping proxies and tuples; `json_body(value)` returns a detached ordinary JSON projection.
`canonical_bytes(value)` validates finite JSON/depth and delegates to `storage.canonical_json`
(UTF-8, sorted compact keys, trailing LF). Do not pass mapping proxies directly to
`storage.canonical_json`, mutate accepted state, or treat a constructor as evidence that
filesystem custody/acceptance was checked.

| Record | Exact fields |
| --- | --- |
| `ArtifactRef` | `path: str`, `sha256: str` |
| `SizedArtifactRef(ArtifactRef)` | Adds measured `size_bytes: int`; `.reference` returns the path/hash-only record |
| `ExportProvenance` | `gate_handoff`, `gate`, `review_handoff`, `review`, `accepted_scope`, `accepted_manifest`, `configuration_manifest`, `resolved_configuration`: `ArtifactRef`; `review_settings_sha256`, `lead_package_manifest_sha256`, `hunt_package_manifest_sha256`, `ledger_head_sha256`, `projection_sha256`, `ship_block_policy_sha256`: `str` |
| `SourceIdentity` | `repository_iri: str`, `repository_identity_basis: RepositoryIdentityBasis`, `target_snapshot: str`, `acquisition: ArtifactRef \| None`, `qualifications: tuple[str, ...]` |
| `VerifiedFinding` | `projection: JsonObject` (exact accepted gate finding row), `score_refs`, `evidence_refs: tuple[ArtifactRef, ...]`; properties `finding_package_id`, `claim_id`, `bucket`, `reference` |
| `VerifiedInputs` | `run_id: str`, `provenance: ExportProvenance`, `source: SourceIdentity`, `gate_completed_at: str`, `settings_sha256: str`, `gate: JsonObject` (entire exact accepted gate), `findings: tuple[VerifiedFinding, ...]`, `input_inventory: tuple[SizedArtifactRef, ...]` |
| `ExportBundle` | `document: JsonObject \| None`, `manifest`, `result: JsonObject`; `document_bytes: bytes \| None`, `manifest_bytes`, `result_bytes: bytes`; `document_ref: SizedArtifactRef \| None`, `manifest_ref`, `result_ref: SizedArtifactRef` |
| `ExportReportView` | `state: ExportReportState`, `outcome: ExportOutcome \| None`, `handoff: ArtifactRef \| None`, `result`, `manifest`, `document: SizedArtifactRef \| None`, `statement_count`, `included_findings`, `excluded_findings: int \| None`, `gaps: tuple[str, ...]` |

Reference, provenance, source, verified-finding and verified-input records provide
`to_json()` and strict `from_mapping(value)`. Provenance additionally exposes
`resolved_config_sha256` (the resolved configuration **file** hash, not the semantic
inference settings hash) and `references`. Its JSON includes that explicit derived hash.
Verified inputs expose `total_input_bytes` and serialize with
`appsec-review/openvex-verified-inputs/1`. Inventory paths are unique and sorted, cover
every provenance/gate/finding/score/evidence reference and are bounded individually and
in aggregate. Gate inputs and every nested capability/attachment reference must also
belong to the gate's certified bindings; merely adding them to the input inventory does
not confer gate authority. The gate schema must be the current central `/2` identity;
legacy `/1` and its `unavailable_inputs` projection are not accepted.
The input implementation must additionally enforce **lower configured**
bounds, all accepted hashes/schemas/cross-identities and current pointer custody.
Synthetic record construction is not an acceptance API.

The Wave 1 implementation signatures are:

```python
verify_inputs(run_root, settings, repository_root) -> VerifiedInputs
assemble_export(verified_inputs, settings, exporter_release, *, output_prefix: str) -> ExportBundle
validate_export(bundle, verified_inputs, settings) -> None
```

`output_prefix` is an explicit run-relative POSIX directory, never inferred from the
filesystem. `output_reference(output_prefix, filename, payload)` permits only
`openvex.json`, `openvex-manifest.json`, `openvex-result.json`. Serialize document first,
manifest second (binding document), result last (binding manifest/document); no self hash.
The result reference is supplied by the bundle, not included in its own body.
Only genuine zero eligible findings permit an absent document, with zero included/
statement counts, no statement mappings and the named
`openvex_no_publishable_confirmed_findings` gap. No other accepted status can omit it.

Identity helpers are `source_product_id(repository_iri, target_snapshot,
resolved_config_sha256)`, `vulnerability_id(repository_iri, target_snapshot, claim_id)`,
`statement_id(author, statement_without_id)`, `document_id(document_without_id)`,
`json_sha256(value)`, `domain_sha256(domain, value)`, and
`exporter_tooling(exporter_release)`. They implement the design's exact versioned domain
tags; statement/document self IDs are rejected. `normalize_timestamp(value)` uses only
accepted input time, never a clock. It requires known RFC3339 offsets and precision of at
most six fractional digits, rejecting unknown `-00:00` or lossy submicrosecond inputs.
Accepted handoffs already use microsecond precision.

`ExportError(message, *, reason: ExportFailureReason, phase: ExportPhase)` subclasses
`IntegrityError`. Only the closed reason/phase enums are metric labels. Diagnostics
remain protected data; exceptions must propagate, preserving causes when wrapped.
`ExportOutcome`, `VexStatus` (only `affected`), `GateBucket`, `FindingState`,
`Disposition`, `DispositionReason`, `AuthorKind`, `RepositoryIdentityBasis` and
`ExportReportState` are closed string enums. Event names, histogram finite boundaries,
schema identities/pins, validation-profile hash, filenames, fixed status note, timestamp
source, component name and all hard bounds are exported constants. Histogram consumers
append their cumulative `+Inf` bucket; it is not a JSON nonfinite number.

## Settings and trust

`OpenVexExportSettings.from_mapping(value)` requires exactly the design v1 keys, even
when disabled. Constructor defaults are the documented disabled defaults, not config
loader fallbacks. Direct construction and `dataclasses.replace` revalidate too.
`to_mapping()`, `settings_sha256()`, `require_enabled()` and
`validate_prerequisites(*, gate_enabled: bool, review_enabled: bool)` are public.
The semantic settings hash is domain-separated over every exact field, including bounds;
it is not the full frozen resolved-configuration hash.

Enabled settings require an explicit individual/organization issuer, exact accurate
common action and absolute ASCII HTTPS/URN repository/system identity. Disabled settings
alone permit empty issuer/action/repository fields; role is optional in either state.
Nonempty invalid values always fail. Checks reject bool-as-int, excess UTF-8 bytes,
unsafe controls, common credentials/template markers/markup and obvious tool-only
issuer names, without altering accepted text. Action may retain ordinary LF/tab
formatting. URI checks prohibit credentials, query/fragment, branch/commit URL forms,
invalid escapes and encoded controls. Numeric hard maxima are the checked-in defaults;
operators may lower positive bounds. An individual input must fit the total input bound.

The operator, not heuristics, asserts issuer authority and reviews advice/secret safety.
Naming an author is not identity verification or a signature. No fallback advice,
repository inference, target guidance, external publication or post-run approval exists.

## Local wire shapes and offline resources

`common.schema.json`, `manifest.schema.json` and `result.schema.json` define closed,
bounded local objects. Manifest contains provenance, exact accepted review context,
one source-snapshot product, every gate finding once, statement mappings, document/null,
exact accounting and sorted path/hash bindings. The closed `review_context` now requires
the exact gate `/2` `capabilities` and `attachments` in place of the removed `/1`
`unavailable_inputs`, including compile-only nonexecution assurances and limitations of
kind `notice`. Notices are preserved but do not become review gaps. Local OpenVEX
manifest/result identities remain `/1` in this contracts-only pre-integration base; the
validation-profile digest changes to bind the corrected context and upstream schema pins.
No previously issued runtime export is being migrated.
Package rows nest the **unchanged**
accepted `finding_projection` with explicit `score_refs`, `evidence_refs`, disposition,
reason and statement ID/null. Statement mappings bind package/claim, claim ledger,
projection, settings, product/vulnerability IDs and resolving evidence references.
Result contains exactly schema/run/outcome, gate identity, manifest/document refs,
statement/included/excluded counts and named gap tokens.

Semantic validation still must prove set/count equalities, bucket/state compatibility,
reference resolution, current accepted identities, fixed affected-only fields, explicit
timestamp/URI validity, and exact canonical reassembly. Upstream schema validity alone
is insufficient; the pin deliberately accepts blank actions, empty products and strings
with unchecked formats. `parse_json_bytes(payload, *, max_bytes)` is available for new
local documents: it checks byte/depth bounds before recursive JSON parsing, then rejects
duplicate keys, nonfinite values, non-object roots and invalid UTF-8. Existing upstream
readers retain their own authority.

Install resources below `share/appsec-review/schemas/openvex-export/`, with `upstream/`
retained, **and** these transitive unchanged resources at sibling `final-report/`:

```text
final-report/common.schema.json
final-report/final-publication-gate.schema.json
final-report/final-report.schema.json
```

The third resource is necessary because gate `/2` common definitions reference the
report `/2` PoC attachment item schema. It does not introduce a report data dependency.
`SCHEMA_SHA256` pins all seven schema files; `VALIDATION_PROFILE_SHA256` incorporates
those pins and the versioned profile. The final-report resources are the original,
deliberately changed source bytes, not normalized copies; the OpenVEX upstream schema,
license and lock are unchanged. Load schemas into an explicit offline
`referencing.Registry` and reject unknown resources; never use the review `SchemaSet`
for upstream OpenVEX or retrieve the JSON-LD context. Packaging and the actual installed
wheel-resource test belong to integration; Wave 0 tests exercise the offline registry
against the same synthetic installed directory layout.

## Test fixtures and verification

`tests/openvex_support.py` exports `settings_mapping(*, enabled=False, **overrides)`,
`enabled_settings(**overrides)`, `fixture_id(prefix, seed)`, `fixture_ref(name)`,
`make_verified_inputs(buckets=("publishable",), *, settings=None, review_gap=False,
run_id="run-openvex-fixture", gate_completed_at="2026-10-28T10:00:00-04:00",
completion_attachments=False)`,
`example_bundle(inputs=None, settings=None, *, output_prefix=OUTPUT_PREFIX,
exporter_release=RELEASE)`, `schema_registry(schema_root=SCHEMAS)` and
`schema_validator(name, schema_root=SCHEMAS)`.
Fixtures are small, deterministic, schema-valid **synthetic in-memory verified-boundary
examples**, not disk fixtures that claim to pass real acceptance/custody verification.
`buckets` supports empty, all backlog/withheld, mixed and repeated bucket cases;
`review_gap=True` retains an explicit review limitation. Example identities/advice exist
only in test support, never as production defaults. The default fixture binds both
lead/hunt package-set and manifest references plus the review-owned chain manifest even
when chain scope is empty. `completion_attachments=True` requires at least two
publishable findings and adds a qualified chain, compile-failed PoC, manual remediation
planning/validation and dossier projections with exact per-capability counts and nested
artifact references. These attachments never change accepted finding state or OpenVEX
eligibility. All original public record fields and function signatures remain unchanged;
only the synthetic fixture has the additional optional keyword.

Focused Windows unit command (explicitly authorized for this isolated worktree):

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_openvex_contracts.py tests\test_openvex_settings.py --basetemp=test/tmp/openvex-contracts-gate2
```

Integration, acceptance and live Dagster runs remain manual. Unit boundary examples
establish neither real-run acceptance nor runtime/report/metrics integration.
