# Native vendored dependency discovery and SPDX enrichment

## Status, scope, and decisions

This is an implementation design, not a claim that the feature already exists or that its tests
have passed. It was checked against baseline `fcac43068d17f139a9d94393b03fe128c6127f12`;
`git merge-base --is-ancestor <baseline> HEAD` returned zero, and HEAD equaled the baseline.
This design changes only this document. Implementation has two file-disjoint chunks and a final
coordinator-owned integration gate below.

1. **SPDX is the organization's SBOM standard.** Every new generated, converted, edited,
   enriched, or test SBOM in this work is **SPDX 2.3 JSON**, validated against its actual,
   locally pinned official JSON schema. Do not introduce CycloneDX output, fixtures, or a new
   CycloneDX path. Unrelated existing scanners and fixtures are not rewritten.
2. **Enrich, do not replace working scanners.** Keep the existing source Syft JSON output and
   Grype input contract unchanged. Discover native dependencies independently, convert the
   accepted Syft source inventory to SPDX using the existing image, and publish an enriched,
   separately accepted SPDX document. Do not feed inferred versions back into vulnerability
   scanners.
3. **No new image or Python dependency is needed.** Reuse `tool-syft` for conversion;
   Python standard-library code handles discovery and deterministic merging, and the existing
   `jsonschema` dependency handles validation. A host-side schema resource is data, not a new
   package or worker instruction.
4. **No successful native build is required for source discovery.** Read the accepted target
   file catalog even when there are no native receipts, headers are the only native input, or
   accepted build receipts describe skipped/failed work. Compiler and loader evidence enrich
   discovery; they are not its entry gate.
5. **Evidence precedes identity.** Retain exact file/receipt hashes and locations for each claim.
   A path name, linker flag, copyright notice, filename version, or ABI suffix is not sufficient
   to establish an upstream package release.
6. **Bounded deterministic parsers, not additional inference.** No new model call, target script
   execution, compiler/preprocessor execution, directory walk during inference, network lookup,
   archive expansion, or host SDK scan is part of this slice. Existing repository inference
   remains review context and cannot upgrade package/version corroboration.
7. **Partial is explicit.** Missing inputs, unsupported parsing, conflicting identities, skipped
   coverage, deterministic limits, conversion failures, and integrity failures have distinct
   outcomes. Empty inventories are successful only when their applicable coverage completed.

Related existing architecture: [dependency intelligence](dependency-intelligence.md),
[retrieval surfaces](retrieval-surfaces.md), and [telemetry](telemetry.md).

## Verified implementation starting points

Repository-relative paths in this document identify code, not target-owned instructions.

| Existing file / symbol | Reuse or necessary extension |
| --- | --- |
| `src\appsec_review\jobs\job_dependency_intelligence\native.py::parse_native_candidates` | Already handles `-l`, library files, frameworks, ELF loader dependencies/SONAMEs, and parsed `.pc`/CMake metadata. It skips include directories. Preserve its existing callable interface and legacy evidence while adding the new discovery path. |
| `job_dependency_intelligence\job.py::_target_dependencies`, `_accepted_job`, `_safe_read`, `_native_inputs`, `build_job` | Existing accepted-input and task boundaries. `_native_inputs` currently reads only build-workspace `.pc`/CMake metadata; add catalog-based source inputs instead of expanding a filesystem walk. `_safe_read` alone is not a sufficient new-input acceptance check: verify publication membership, snapshot, size, and every path component as well as digest. |
| `job_evidence_collection\job.py::load_target_catalog` | Existing authenticated route to `ScanCatalog.files`, source fingerprint, compile-command catalog, target artifacts, and catalog handoff hash. For original catalog exclusions/gaps also verify/read its accepted repository-partition artifact. Do not assume `ScanCatalog.target_artifact_gaps` is the complete source coverage record. |
| `job_target_catalog\job.py::partition`; `jobs\cataloging.py::inventory` | Partition contains `{path, sha256, size_bytes, language, ...}` records, target-artifact references, configured exclusions, and named inventory gaps. Its existing bounds can exclude files before this feature runs; inherit those gaps. |
| `job_language_build\job.py::load_accepted_language_build`; `job_artifact_indexing\job.py::load_accepted_artifact_index` | Accepted protected compile/link receipts, workspace manifests, and artifact identities. The latter is exported by the artifact-indexing package. Consume the actual accepted artifact index, not just its handoff hash. |
| `job_evidence_collection\adapters.py::_syft_parser`; `evidence.py::build_envelope` | Both currently lose structured package version/purl/repository data. Extend both layers; fixing only the adapter still loses the fields. Bump parser/normalizer identities so old evidence/checkpoints cannot pretend to contain the new fields. |
| `job_dependency_intelligence\job.py::_evidence_packages` | Currently reads accepted Syft observation shards, but returns no source-inventory coverage disposition. Recover the exact source Syft JSON through its accepted scan/envelope publication for conversion, retaining the indexed observation association. A failed/missing source inventory must not become an unexplained empty package list. |
| `job_dependency_intelligence\resolution.py::normalize_dependencies` | Reads only top-level version/constraint, not `metadata.version`. Fix the metadata-version path with the corroboration rules below. Its name-only native grouping can conflate copies; preserve root-scoped native candidates. Never lowercase an entire purl to construct a new identity. |
| `job_dependency_intelligence\job.py::publish_context`, `publish_handoff`, `load_accepted_dependency_intelligence`; `datasets.py` | Existing inventory shard, artifact declaration, and accepted-loader extension points. Extend the existing handoff additively; legacy accepted documents without the new optional publication remain readable. A document advertising an SPDX publication must pass the new strict checks. |
| `retrieval\model.py::{EntityKind, SourceLocation, RelationKind}`; `retrieval\core.py::{find, trace, read_excerpt, resolve_evidence}` | Existing dependency, tool-observation, evidence-artifact, source-location, and derivation surfaces suffice. No new MCP operation, entity enum, or generic filesystem read API is necessary. |
| `storage\shared.py::{safe_path, verify_reference, put_bytes}` | Reject traversal and symlinks in every path component, verify run references, and retain bounded detached workspace evidence. Use these rather than checking only the final resolved file's symlink flag. |
| `observability\events.py::{PipelineLog, EventLog}`; `spans.py::operation_span`; `telemetry.py::{aggregate_run_metrics, _receipt_json}` | Existing correlated events, measured stages, safe receipt loading, and summary aggregation. Add a dedicated native-SBOM summary, not unbounded names/paths in metrics. |
| `runtime\runner.py` reuse events; `orchestration\topology.py::wave_dependencies` construction | Existing `JOB_REUSED`/`TASK_REUSED` accounting and dependency ordering. Do not add a new cache or rewrite runner reuse. Preserve topology unless a demonstrated acceptance test needs a narrowly scoped change. |

`job_dependency_intelligence\inference.py` resolves a repository for one already-discovered
candidate; it is not source discovery. No runtime skill or prompt needs modification or loading.

## Existing image capability and verification

`containers\tools\syft\tool.toml` pins Syft **1.52.0**, executable
`/opt/tool/bin/syft`, Linux/amd64, no networking, read-only target/root filesystem, and bounded
resources/output. Its Dockerfile copies a hash/size-locked release asset; it does not install an
SBOM editor. `containers\tools\syft\assets.lock.json` and `containers\catalog.toml` are the
existing image integration, and must not be repinned by a session that did not build the image.

The coordinator reported a working local Docker daemon and an existing
`appsec-review/tool-syft:1.52.0` image:
`sha256:500039699651788b20d588790830c4e5b3b6c1f8a77e1855c0ad36a84adf5c65`.
It ran `syft version` and `syft convert --help` successfully, confirming SPDX JSON support.
This is capability evidence, not yet an end-to-end enrichment smoke result.

Implementation must execute and retain a smoke receipt for:

```text
/opt/tool/bin/syft convert /inputs/syft.json --output spdx-json=/scratch/baseline.spdx.json
```

Run through `ContainerExecutor`/`ExecutionRequest` with the catalog-resolved image identity,
not a shell string or unverified tag. Mount only the accepted input JSON read-only and a
run-owned scratch directory read-write; do not mount or rescan the target. Existing executor
safety/resource policy remains in force. Assert the resulting `spdxVersion` is `SPDX-2.3`;
do not assume a formatter default without testing the pinned release. Inject a converter
callable for unit tests. Do not change the existing source scan's `json=/scratch/output.json`
or Grype's `/inputs/syft.json`.

No new Dockerfile, image build, SBOM editing binary, or dependency installation is justified.
If the existing image is missing on another host, build **that image** with the established
`containers\build-all.ps1 build tool-syft` path and run the SPDX-specific smoke. The existing
generic Syft fixture smoke is not evidence that this SPDX contract passed; leave unrelated
existing fixtures alone and add the focused smoke to this feature's tests.

## Input custody and bounded discovery

### Accepted input set

The input set is the accepted target catalog, accepted language-build receipts, accepted
artifact index, and accepted source Syft evidence. For each, resolve the framework's accepted
handoff and its publication membership, verify source fingerprint and reference hash/size,
then verify the nested referenced artifact before use. Do not trust a `latest.json` path by
itself, arbitrary JSON embedded in a receipt, or an adjacent unaccepted file.

Source inputs always come from catalog-listed files. Workspace inputs always come from an
accepted workspace manifest and are hash-checked before copying selected bytes to a run-owned
content object. Command evidence references the accepted protected-command artifact and row
selector; loader evidence references the accepted artifact/receipt and structured field.
Every selection is ordered by canonical logical root, domain, and relative path.

An accepted language handoff with zero native receipts is valid input: discover from catalog
headers and metadata. No `receipt.terminal_status == SUCCEEDED` condition gates catalog
discovery. Preserve accepted upstream build failure/skipped gaps. A genuinely absent or
unaccepted required framework handoff is an admission failure, not permission to inspect
mutable build output. If orchestration blocks the job before execution, report it as blocked
coverage rather than claiming source discovery ran.

### Selection and path rules

1. Index the finite accepted file list in memory; do not call `rglob`, `os.walk`, `find`, or a
   compiler on the target from this feature.
2. Parse compiler/linker argv as data. Recognize joined and split `-I`, `-isystem`, `-iquote`,
   `-idirafter`, `-L`, `/I`, `/external:I`, and `/LIBPATH:` as path hints, plus the existing
   library/framework forms. Resolve relative paths against the protected row's accepted
   working-directory mapping. Map `/target/...` and captured workspace paths only through an
   authenticated mount/workspace mapping. Unmapped absolute SDK/system paths produce
   `unmapped_path`; never open them on the host. Output arguments are not dependencies.
3. Do not execute or recursively read response files. Preserve `@file` observations as
   `unsupported_response_file` coverage unless an accepted expanded argv already exists.
   A library search directory is a hint, not proof all its libraries were linked.
4. Independently select catalog headers (`.h`, `.hh`, `.hpp`, `.hxx`, `.inc`) and supported
   metadata basenames: `LICENSE*`, `COPYING*`, `NOTICE*`, `README*`, `VERSION*`, `version.txt`,
   `*.pc`, and `*Config.cmake`/`*-config.cmake`, case-insensitively. Inspect bounded eligible
   records outside conventional vendor directories too. `vendor`, `vendors`, `third_party`,
   `third-party`, `external`, `deps`, and `dependencies` are useful root hints, not prerequisites.
5. A conventional vendor child, explicit mapped include/library root, or self-identifying
   header directory establishes a candidate locality. A header can establish a candidate at
   its own directory without a build. Associate supporting metadata from that directory
   and its bounded nearest cataloged ancestors, stopping at an established package root;
   never attach a repository-wide LICENSE/README to every nested package.
6. Prefer the longest matching established root. Ambiguous overlapping roots retain separate
   candidates and a gap instead of silently assigning ownership. Retain nested vendored
   packages independently. Root path names alone produce inferred names, never corroboration.
7. Before every read: validate canonical relative paths, reject symlinks in every component,
   check accepted size against remaining budgets, read at most allowed size plus one, and
   hash the bytes actually read. Check equality with accepted size and digest. Do not
   `read_bytes()` an unchecked file and truncate it afterward.

Only supported bounded literal recognizers run. Initial recognizers cover:

- self-identifying version strings such as `ZLIB_VERSION`, `SQLITE_VERSION`,
  `OPENSSL_VERSION_STR`/literal `OPENSSL_VERSION_TEXT`, and `PNG_LIBPNG_VER_STRING`;
- `BOOST_LIB_VERSION` and documented packed `BOOST_VERSION`, using explicit decoding tests;
- generic literal `FOO_VERSION "x.y.z"` and a matching
  `FOO_VERSION_MAJOR`/`MINOR`/`PATCH` numeric tuple, with inferred identity until corroborated;
- `.pc` name/version/URL and literal CMake package metadata, without evaluating CMake;
- narrow anchored README/NOTICE/VERSION self-declarations such as `Package:`, `Version:`,
  `Repository:`, or a project title with an explicit release version.

Plain LICENSE/copyright names and URLs remain observations; they do not prove package identity,
license choice, upstream repository ownership, or a release. Do not extract arbitrary prose
numbers. Do not evaluate macro expressions, includes, conditional compilation, or old OpenSSL
hex encodings without a tested recognizer; emit `unsupported_metadata` when such a selected
identity-bearing construct cannot be interpreted. Preserve UTF-8 byte offsets separately from
line numbers, including CRLF and non-ASCII cases.

Artifact filenames and accepted loader names remain useful inferred candidates. In particular,
`libssl.so.3`, `libz.so.1.2.13`, Mach-O install names, framework names, import libraries, and DLL
names **do not establish package release versions**. A filename resembling `foo-1.2.3.a` may
yield a version hint, not `versionInfo`. Do not execute binaries or add PE/Mach-O parsers in
this slice; missing loader formats remain named gaps.

## Shared records and public API

Before splitting implementation, the coordinator creates and commits the small shared
`src\appsec_review\jobs\job_dependency_intelligence\native_sbom_contracts.py` module.
It contains frozen bounds records, closed statuses/gap kinds, `TypedDict` JSON records, and
identity helpers only: no I/O, config loading, discovery, merging, logging, or schema loading.
Both chunks import it and neither edits it. All JSON records below use canonical relative
POSIX paths on disk, following existing storage contracts; host `Path` use remains portable.

### Records

- `ArtifactRef = {path: str, sha256: str, size_bytes: int}`.
- `NativeFile = {domain: "target" | "workspace", root_id: str, path: str,
  sha256: str, size_bytes: int, upstream: ArtifactRef, backing: ArtifactRef | None}`.
  `root_id` identifies the authenticated target/workspace, not a guessed package.
  Workspace `backing` is a detached exact-byte run object; target files resolve against the
  accepted target snapshot. Distinguish logical source path from backing artifact path.
- `NativeEvidence = {evidence_id, kind, value, source_fingerprint, domain, root_id,
  path, sha256, upstream, backing, selector}`. Text selectors have zero-based half-open
  `start_byte/end_byte` and one-based inclusive `start_line/end_line`; structured selectors
  have a bounded JSON pointer and optional protected command id/argv hash or artifact id.
  A claim must have at least one resolving selector. Identity hashes the complete canonical
  evidence record excluding `evidence_id`; duplicate evidence is deduplicated.
- `Claim = {value: str | None, status: "unknown" | "inferred" | "corroborated" |
  "conflicted", evidence_ids: list[str], alternatives: list[str]}`.
- `NativeCandidate` retains the existing `candidate_id`, `native_name`, `observations`,
  `metadata`, and `repository` fields, and adds `package_root`, `root_id`,
  `identity: Claim`, `release: Claim`, `upstream: Claim`, and `evidence_ids`.
  New candidate ids hash `(source_fingerprint, root_id, package_root, normalized native name)`,
  not name alone. An unmapped linker-only candidate has a distinct command-scoped root.
  Legacy `parse_native_candidates` ids remain supported for its existing callers.
- `CoverageGap = {kind, scope, detail, evidence_ids}`. Closed kinds for this extension:
  `input_missing`, `upstream_partial`, `unmapped_path`, `unsupported_response_file`,
  `unsupported_metadata`, `decode_failed`, `read_failed`, `bounds`, `ambiguous_root`,
  `identity_conflict`, `version_conflict`, `repository_conflict`,
  `sbom_conversion_failed`, `sbom_validation_failed`, `artifact_inventory_not_merged`.
  Integrity/admission errors are exceptions, not gaps that silently permit changed bytes.
- `DiscoveryResult = {schema: "appsec-review/native-discovery/1", candidates, evidence,
  gaps, coverage, metrics}`. Coverage records counts for eligible/selected/read/unsupported/
  omitted files, scanned roots, input command/artifact availability, configured exclusions,
  and inherited catalog gaps. Metrics are nonnegative counters, not security conclusions.
- `SpdxBaseline = {document: Mapping[str, Any], artifact: ArtifactRef,
  source_artifact: ArtifactRef, tool_identity: Mapping[str, str]}`.
- `SbomResult = {document: Mapping[str, Any], provenance: Mapping[str, Any],
  gaps: list[CoverageGap], metrics: Mapping[str, int]}`. The provenance schema is
  `appsec-review/native-sbom-provenance/1`; it maps every emitted package SPDXID to baseline
  package selectors and/or native candidate/evidence ids, merge decisions, and conflicts.
  It also records exact input identities, algorithm/schema identities, and coverage.

### Pure functions owned by the core chunk

```python
def discover_native_dependencies(
    *, source_fingerprint: str, files: Sequence[NativeFile],
    invocations: Sequence[Mapping[str, Any]],
    artifacts: Sequence[Mapping[str, Any]],
    read_file: Callable[[NativeFile, int], bytes], bounds: NativeBounds,
) -> DiscoveryResult: ...

def build_spdx(
    *, source_fingerprint: str, created: str,
    baselines: Sequence[SpdxBaseline], discovery: DiscoveryResult,
    input_identities: Sequence[ArtifactRef], bounds: SbomBounds,
) -> SbomResult: ...

def validate_spdx(document: Mapping[str, Any], *, bounds: SbomBounds) -> None: ...
```

`created` is a validated UTC timestamp from the accepted catalog framework handoff's
`started_at`, not wall-clock time at serialization. The input identity includes that handoff.
`read_file` is the integration chunk's authenticated bounded reader; the core additionally
checks returned byte length and digest and computes text selectors. It must not enumerate
additional paths. Each invocation/artifact supplied to the core carries an authenticated
`evidence_source: {artifact: ArtifactRef, json_pointer: str}` added by integration. This is
required for new structured evidence, even when a legacy parser also supplied an argv hash.

Invalid caller records/bounds raise `ValueError`; accepted-byte mismatch raises a distinct
`NativeInputIntegrityError` defined in the shared contract. Ordinary bounded read/decode
failures become scoped gaps without discarding other candidates. A schema-invalid final SPDX
document raises `SpdxValidationError`; no accepted SPDX artifact is returned.

The integration-owned converter interface is:

```python
def convert_syft(source: ArtifactRef, *, unit: UnitContext) -> SpdxBaseline: ...
```

Inject it into `build_job` as an optional `syft_converter` callable. Conversion tests use an
in-memory fake with run-owned artifact references; the separate smoke uses the real image.
Only one source baseline is required now; the sequence contract allows later accepted
artifact baselines without changing core merge semantics.

## Corroboration and deterministic conflict policy

Treat identity, release version, and upstream as separate claims.

- A literal authoritative package declaration (`.pc` name/version) or a known self-identifying
  package header can corroborate that field at its root. Generic macro prefixes, directory
  names, binary names, linker flags, and unrelated document mentions remain inferred.
- A generic identity/version becomes corroborated only when independent roles at the same
  unambiguous root agree: for example a self-declaration in README plus a matching version
  header. Repeated copies of the same line/hash or header aliases are not independent.
- A supported explicit repository declaration is an observed upstream claim. Keep a general
  homepage distinct from a repository. Only the existing public-host repository canonicalizer
  can supply a supported repository identity. Model-supplied repositories remain inferred;
  neither a URL nor model confidence proves that vendored bytes match upstream.
- Within one root, retain all competing values and evidence. Equal-strength incompatible
  releases set `release.status = conflicted`, `release.value = None`, and produce a gap.
  Do not choose the highest version, last parsed field, or highest confidence.
- Different roots/copies remain distinct native instances, even with the same name.
  Preserve every instance through normalization; do not overwrite a previous `native_candidate`.
  Keep the legacy singular field for old callers and an additive sorted candidate collection
  where observations genuinely coalesce.
- Pass top-level `version` to normalization only for a corroborated, nonconflicting release.
  Support the existing parsed `.pc` `metadata.version` path without dropping it; new inferred
  metadata versions must not be promoted by a fallback. Manifest constraints remain constraints,
  not resolved release versions.

For SPDX merging:

1. Preserve all accepted baseline package/file/snippet records and their valid relationships;
   keep the raw Syft JSON and converted baseline SPDX as exact-byte provenance.
2. Match only on an exact observed purl including version/qualifiers, or a corroborated same
   package identity/release with corroborating upstream/root association. Preserve purl case
   and qualifiers. Name similarity alone never merges scanner and native records.
3. Equivalent baseline package identities can merge only when identity fields agree and the
   merge retains every original field/evidence value. If ambiguous, retain separate records.
   Remap relationships to the retained SPDXIDs and deduplicate exact duplicate relationships.
4. Never overwrite a nonempty baseline release/purl with a native guess. A native observation
   disagreeing with a matched baseline becomes an explicit conflict and retains the original
   baseline record plus a separate root-scoped candidate when needed. Do not manufacture a
   corroborated association merely to force a merge.
5. A native candidate not safely matched becomes a separate package with its observed name.
   `versionInfo` is omitted unless the release is corroborated. Do not fabricate purls, CPEs,
   download URLs, source commits, package checksums, SPDX license expressions, or vulnerability
   matches. Explicitly mark inferred identity/version/upstream states in bounded `sourceInfo`
   and in the provenance sidecar.
6. Sort inputs, evidence, package records, relationships, and annotations by canonical keys.
   Native package SPDXIDs derive from candidate identity; baseline element ids derive from
   their canonical original record without transient document namespace/creation time.
   Identical duplicate baseline elements share a mapping; conflicting duplicate original
   SPDXIDs are invalid input. Rewrite all element references, including relationships,
   `documentDescribes`, file dependencies, and snippet source/pointer references.
   Keep valid `DocumentRef-...:SPDXRef-...` references bound to their retained external-document
   checksum declarations; do not fetch them.
7. Keep existing license identifiers and extracted licensing information intact. Do not
   infer a declared license from the first LICENSE text. Conflicting baseline license
   information is not silently reconciled.
8. A bound may omit further **native additions** in stable order with a gap. It must not
   silently truncate accepted baseline SPDX records or produce dangling references. A baseline
   exceeding parse/element/output bounds fails this new publication with diagnostics.

## SPDX document, validation, and publication

### Standard document

Publish `enriched.spdx.json` as actual SPDX JSON, not an internal handoff renamed to `.spdx`.
Required document values include:

- `spdxVersion: "SPDX-2.3"`, `dataLicense: "CC0-1.0"`,
  `SPDXID: "SPDXRef-DOCUMENT"`, and a stable descriptive `name`;
- `documentNamespace: "https://appsec-review.invalid/spdx/<content-key>"`, an opaque
  identifier derived from accepted input hashes, source fingerprint, resolved bounds,
  stable creation timestamp, and algorithm/schema identities; no network dereference;
- `creationInfo.created` from the accepted timestamp above, and creators including
  `Tool: appsec-review-native-sbom/1` and retained pinned baseline tool creators.

A newly added native package uses `SPDXRef-Native-<digest>`, `name`,
`downloadLocation: "NOASSERTION"`, `filesAnalyzed: false`,
`licenseConcluded: "NOASSERTION"`, `licenseDeclared: "NOASSERTION"`, and
`copyrightText: "NOASSERTION"`. Unknown means `NOASSERTION`, not `NONE`.
Use an observed valid purl only as a PACKAGE-MANAGER/purl external reference.
Package metadata does not establish a download location. A library-file digest does not
establish a complete upstream package checksum. No package verification code is generated
for `filesAnalyzed: false`.

Add document `DESCRIBES` relationships for inventory packages; do not invent dependency edges
from colocation or include-directory presence. A bounded package `sourceInfo` identifies its
candidate and corroboration states and the provenance artifact's logical publication name.
The sidecar maps this to exact evidence. Avoid a circular hash: serialize document and sidecar
independently, then bind both final hashes in the handoff/manifest. Do not put either final
hash inside the other document.

### Actual validation

Vendor the official SPDX 2.3 JSON schema from the SPDX specification **v2.3 release**, with
its upstream license/provenance and recorded SHA-256, under the dependency-intelligence
package's `schemas` resources. Include all required local schema references if any.
Load via `importlib.resources`; package the resource in `pyproject.toml`.
Use existing `jsonschema` with its declared dialect and a closed local reference registry;
network reference resolution is forbidden. Schema identity/hash participates in fingerprints.
Do not substitute a homegrown required-key validator for the actual standard schema.

Additionally enforce semantics the schema alone cannot prove: unique valid SPDXIDs,
`SPDXRef-DOCUMENT`, no dangling local relationships/snippet/file/package references,
valid external-document bindings, and every provenance mapping pointing to an emitted package
and known evidence. Verify preserved license references, no unsupported asserted native
release, bounded fields/element counts/encoded bytes, and exact spec version. Validate the
baseline before merging and the enriched document before atomic publication. Negative tests
must show both schema and referential-integrity rejection.

### Job and accepted artifacts

Keep the current task order through `scorecards.fetch`. Add:

```text
publication.publish_sbom
    inputs: inputs.load_accepted, resolution.detect_dependencies
publication.publish_context
    existing inputs plus publication.publish_sbom
acceptance.publish_handoff
    existing inputs plus publication.publish_sbom
```

`publish_sbom` converts the accepted raw source Syft inventory and calls `build_spdx`.
Discovery/SPDX uses deterministic pre-inference claims; it must not wait on or promote
repository model results/Scorecard results. The native discovery result is retained by
`resolution.detect_dependencies` before inference. Update both TOML task ordering and Python
`TOPOLOGY` together.

Under this attempt's existing unit artifacts directory publish:

```text
native-discovery.json
baseline.spdx.json                 # only if conversion succeeded
enriched.spdx.json                 # only after successful validation
native-sbom-provenance.json
native-sbom-metrics.json
```

The handoff adds optional `native_discovery` and `sbom` fields. `sbom` contains:

```text
format = "spdx-json"
spec_version = "2.3"
status = "SUCCEEDED" | "COMPLETED_WITH_GAPS" | "FAILED"
artifact = ArtifactRef | null
baseline = ArtifactRef | null
provenance = ArtifactRef
metrics = ArtifactRef
input_fingerprint = sha256
schema_sha256 = sha256
gaps = [CoverageGap, ...]
```

Add artifact-only dataset declarations for the discovery/provenance/metrics publications and
the SPDX baseline/enriched documents. Framework acceptance must inventory every advertised
artifact, including detached evidence backings. The accepted loader verifies membership,
containment/no symlink, size, digest, snapshot, fingerprint consistency, schema validation,
and provenance references. Test removal/tampering of each advertised identity, not only
index manifest tampering. Old handoffs without these optional fields remain readable; a new
advertised failed publication may have no SPDX artifact, but may not claim success.

Missing/failed source Syft conversion can still yield a valid **native-only** SPDX document
with an explicit baseline coverage gap and `COMPLETED_WITH_GAPS`. No native candidates plus a
successful empty baseline yields a valid zero-package document. Both source coverage and
native coverage missing/failed must not yield an apparently complete empty SBOM. Integrity
violations abort admission; final schema/output validation failures produce diagnostics and
`sbom.status = FAILED` with no accepted enriched artifact. Existing dependency/Scorecard
context can still publish with `COMPLETED_WITH_GAPS`; infrastructure exceptions remain job
failures and must not be broadly swallowed.

Scope of the first baseline is the existing accepted **source-directory Syft** inventory.
Existing artifact Syft/Grype scans are unchanged. Accepted artifact filename/loader evidence is
used by native discovery, but separately produced artifact Syft inventories are not silently
claimed merged. Record `artifact_inventory_not_merged` when such inventory coverage is relevant;
adding it later requires an explicit accepted upstream dependency, not scraping run paths.

### Downstream retrieval

In the existing `dependency-intelligence` inventory shard:

- Preserve new candidate/claim states, normalized versions, source/evidence references, and
  discovery gaps on `DEPENDENCY_PACKAGE` entities. Scope identities so same-name native
  copies do not collapse solely because `version` is unknown.
- Add `TOOL_OBSERVATION` entities for resolving native evidence. Target text evidence has
  an exact `SourceLocation` using accepted file hash and line/byte span. Workspace/loader/
  command evidence points to run-owned `EVIDENCE_ARTIFACT` entities with exact references
  and selectors, not a mutable workspace source location.
- Connect dependency to evidence with `DERIVED_FROM`, and evidence to source with
  `OBSERVED_AT` where applicable. Add an `EVIDENCE_ARTIFACT` for the enriched SPDX document
  and one for its provenance sidecar, linked to the represented package/evidence context.
  Relationship exactness describes the evidence mapping, not certainty of package identity.
- Add separate coverage rows for `native-source-discovery`, `source-syft-baseline`, and
  `native-spdx-publication`, including zero-input and partial cases.

Existing `find/search index=inventory kind=dependency_package`, `trace`, `resolve_evidence`
on the evidence entities, and `read_excerpt` on target-backed observations are sufficient.
The accepted Python loader exposes verified artifact references for consumers needing the
whole standard document. Do not add arbitrary artifact reading to MCP. Include sorted accepted
input hashes, resolved bounds, discovery/merge identities, schema hash, and converter image
identity in the index/publication fingerprint; the current upstream-handoff-only fingerprint
is insufficient for these new semantics.

The existing dependency advisory lookup stays an unverified review lead. This work does not
evaluate affected release ranges or convert SBOM discovery into security findings.

## Central deterministic bounds

All values come from `jobs.job_dependency_intelligence.settings` in `appsec-review.toml`,
are validated before execution, and are included in resolved configuration/fingerprints.
Reuse existing settings rather than introduce conflicting limits:

| Setting | Initial value / semantics |
| --- | --- |
| `native_candidate_limit` | existing `10000`; enforce globally across every discovery source, including artifacts/metadata, not only before each argv |
| `command_token_limit` | existing `4096`; truncation has a scoped gap |
| `metadata_file_limit` | existing `10000`; selected source/workspace metadata/header reads combined |
| `metadata_bytes_per_file` | existing `1048576`; reject oversized files before allocation |
| `native_source_bytes_limit` | new `67108864`; aggregate bytes read/copied for this discovery |
| `native_root_limit` | new `2048`; distinct selected locality roots |
| `native_evidence_limit` | new `50000`; global retained evidence |
| `native_evidence_per_candidate` | new `32`; retained evidence ids, with omissions counted |
| `native_field_bytes` | new `4096`; scalar fields/selectors, truncation never changes identity silently |
| `native_path_chars` | new `512`; canonical logical path/hint bound |
| `sbom_input_bytes` | new `16777216`; each accepted Syft/SPDX input, also bounded before JSON parsing |
| `sbom_element_limit` | new `100000`; combined package/file/snippet/relationship/extracted-license elements |
| `sbom_output_bytes` | new `33554432`; each canonical standard/provenance publication |
| `sbom_conversion_timeout_seconds` | new `120`, capped by existing Syft tool policy |

`NativeBounds` and `SbomBounds` receive explicit values; no divergent production defaults in
parser signatures. Existing `dependency_limit` still limits the downstream normalized inventory.
Use configured budgets over a sorted finite list, not elapsed time, for selecting source
coverage. Runtime converter timeout is separately recorded and never described as deterministic
source coverage. Counts of omitted items and reasons survive even if detail lists are bounded.
Do not enlarge upstream catalog limits or exclusions in this change.

## Telemetry and metric correctness

Wrap source discovery and SPDX publication in existing `operation_span` stages
`native-sbom.discovery` and `native-sbom.publication`. Existing events provide run/job/attempt/
unit/span correlation and duration/resource measurements, including failure finalization.
Use ordinary span status for partial work (`COMPLETED_WITH_GAPS`) and failure (`FAILED`).
Do not report process-inclusive CPU as additive task CPU or unavailable Windows I/O as zero.

Write a bounded `appsec-review/native-sbom-metrics/1` receipt and emit
`NATIVE_SBOM_RESULT` referencing its exact hash/size. It carries semantic counters:

- input files eligible/selected/read/unsupported/omitted, bytes read, roots inspected;
- commands available/processed/truncated and accepted artifacts inspected;
- candidates total and identity/release counts by `unknown/inferred/corroborated/conflicted`;
- baseline package count, native additions, exact merges, unresolved matches, conflicts;
- output package/relationship counts, output bytes, gaps by closed kind;
- discovery, baseline-conversion, and SPDX-publication dispositions, and validation outcome.

Keep attempted-work counters distinct from resulting inventory counts. Do not use a count of
inferred candidates as a count of verified packages. Do not log raw source text, full argv,
repository URLs, or package names as metric dimensions. Duration and volatile execution
identities belong in telemetry receipts, not the content-derived SPDX/provenance identity.

Add `native_sbom` to `aggregate_run_metrics` using verified receipts, following `_receipt_json`
and existing specialized metric sections. Deduplicate identical receipt/event identities;
conflicting duplicates and corrupt/missing receipts produce accounting gaps, not zeros.
Report attempt outcomes separately and use only the selected accepted publication for current
inventory totals; do not sum inventories from retries.

Use the existing runner's `JOB_REUSED`/`TASK_REUSED` events to count reuse of this job/publication.
Do not rerun discovery/conversion or manufacture a new successful work event for reuse.
Resolve current inventory metrics through the verified accepted publication when work was reused;
report fresh work zero, reused publication count separately, and unknown original resource
measurements as unavailable. If a failed attempt never reached a metrics receipt, derive its
failure from lifecycle events and mark domain counters unavailable. A missing receipt is not a
successful zero. No new cache or generic runner instrumentation is necessary.

## Implementation ownership and sequence

The coordinator owns this design, the initial shared contract module, and final integration.
The design assignment itself does not authorize implementation commits or pushes. For a later
authorized implementation, agree the shared module first, then commit that contract locally
before agents branch so they use the same API. Pass its exact commit and require ancestry
verification. Do not push, open PRs, move the base branch, or edit host image pins unless separately
authorized. Use isolated worktrees and checkout-local environments.

### Chunk A — core discovery and SPDX algorithms

Own only:

- new `job_dependency_intelligence\discovery.py` and `sbom.py`;
- existing `job_dependency_intelligence\native.py` and `resolution.py`;
- package `schemas\` SPDX 2.3 resources and their upstream provenance/license;
- new `tests\test_native_discovery.py` and `tests\test_native_spdx.py`.

Implement the three pure functions above, exact evidence offsets, conservative literal
recognizers/root grouping, global limits, normalization preservation/version fix,
deterministic SPDX merge/id/reference remapping, offline official-schema validation, and
semantic validation. Keep existing public signatures working. Do not edit `job.py`, config,
dataset declarations, package exports, telemetry, generic evidence adapters, or shared contract.

Tests use supplied bytes/records only and do not require Docker, a model, runtime skills,
network, or real target checkouts.

### Chunk B — accepted-input/job/config/retrieval/telemetry integration

Own only:

- `job_dependency_intelligence\job.py`, `datasets.py`, and `__init__.py`;
- `job_evidence_collection\adapters.py` and `evidence.py`;
- `observability\telemetry.py`;
- `appsec-review.toml` and `pyproject.toml` for settings/schema packaging;
- new `tests\test_native_sbom_job.py`, `test_native_sbom_metrics.py`, and
  `test_native_sbom_image.py`;
- narrowly related assertions in existing `tests\test_dependency_intelligence.py` and
  evidence-normalization tests, preserving their original regression coverage.

Implement bounded authenticated input gathering, detached workspace evidence, exact accepted
Syft raw-output recovery and conversion, structured Syft field preservation, configuration/
topology, dataset and artifact acceptance, retrieval graph, semantic metrics, and reuse/failure
accounting. B may scaffold against the committed contract and use fakes while A works, but
**final integration must follow A**. Do not recreate A's discovery/merge logic in the job.
No new upstream artifact-scanner dependency or generic runner/MCP change is needed.

If either chunk discovers a contract problem, report it to the coordinator; do not edit the
other owner's files. The coordinator resolves shared contracts before updating both agents.

## Verification gates

All new SBOM fixtures and expected documents use SPDX 2.3 JSON. Existing unrelated SBOM
fixtures stay unchanged. Use `test\tmp\<unique-chunk>` for pytest scratch state; do not override
the repository cache location. Verify the environment imports this checkout before testing.

### Core test matrix

| Case | Required assertions |
| --- | --- |
| Buildless/header-only vendored tree, no CMake/Conan or commands | Known header plus scoped README/VERSION corroborates identity/release; exact hash, CRLF/UTF-8 byte and line ranges resolve; no successful build prerequisite |
| Arbitrary non-vendor directory | Header/literal metadata discovery still works; repository-wide LICENSE is not attached as package ownership |
| Joined/split GCC/Clang/MSVC path flags | Correct mapped root, outputs ignored, unmapped host SDK paths never read; response files gap without execution |
| Link flags, artifacts, loader metadata | Existing detections survive; `libfoo.so.1.2.3` never sets release `1.2.3`; artifact/command evidence has resolving accepted selectors |
| Literal and packed macros | Supported encodings compose exactly; arbitrary expressions/conditional ambiguity are not evaluated |
| Two copies, nested package, competing versions/upstreams | Roots retained, conflicts explicit, no last-write-wins or cross-root borrowing |
| Every configured limit | Stable retained prefix, exact omission counters, scoped gap; artifact/metadata additions cannot bypass candidate bound |
| Malformed/unreadable/oversize text | Independent evidence survives; no unbounded read; decode/read gaps distinct from integrity mismatch |
| Native `.pc` version through normalization | Version survives when corroborated; guessed `metadata.version` does not become an asserted release |
| SPDX baseline plus native merge | Baseline fields/license/file relationships preserved; purl case/qualifiers preserved; unknown versions omitted; all sidecar evidence retained |
| Baseline/native disagreement and duplicate identity | No silent overwrite; separate packages or explicit conflict; complete id/reference remapping |
| Deterministic replay and permuted inputs | Identical canonical SPDX/provenance bytes and identity for the same accepted material/timestamp/bounds |
| Zero packages and missing baseline | Valid zero-package SPDX when coverage complete; native-only publication explicitly partial when baseline unavailable |
| Invalid SPDX/schema/reference | Actual official-schema rejection, dangling refs/duplicate ids/LicenseRefs rejected, output-byte/element bounds enforced |

### Integration and telemetry test matrix

1. Build a minimal accepted catalog + empty/native-failed language receipt fixture + accepted
   empty artifact index + source Syft evidence; run the job with fake inference/Scorecard/
   converter. Assert accepted SPDX, direct-source evidence retrieval, normalized release,
   package root separation, coverage, and zero security findings.
2. Exercise structured Syft fields through **adapter, envelope, observation index, and
   dependency loader**. Version/purl/repository and exact raw-input selectors must survive
   all layers, not just a parser unit test.
3. Tamper with catalog/source bytes, protected receipt, workspace backing, source Syft JSON,
   converted SPDX, enriched SPDX, provenance, metrics, and accepted membership; assert rejection.
   Test traversal, Windows drive/UNC input, and intermediate-directory symlink escape where
   the host supports creating symlinks.
4. Test baseline conversion unavailable/timeout/malformed output, source discovery partial,
   schema-invalid final output, complete zero, and infrastructure failure. Publication status,
   artifact presence, gap kinds, operation terminal events, and aggregate dispositions must agree.
5. Assert semantic counters and aggregate receipts for success, partial, failed, and true-zero
   runs. Corrupt/missing receipts and contradictory duplicate result events produce accounting
   gaps; duplicate identical events do not double count.
6. Resume/reuse accepted work: no read callback or converter invocation, same accepted SPDX hash,
   inventory counted once, fresh work zero, reuse counted separately. Retry after failure must
   not combine old inventory totals with the new accepted result.
7. With the verified local image, convert a tiny run-owned Syft inventory to SPDX JSON under the
   existing executor policy; validate exact SPDX 2.3 output, enrich, validate again, and retain
   execution/image/input/output hashes. Missing Docker is a reported skipped image-validation
   gap, not evidence that the image path passed.

Suggested focused commands after implementation, with the coordinator's checkout-local
environment (PowerShell):

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_native_discovery.py tests\test_native_spdx.py --basetemp=test\tmp\native-sbom-core
.\.venv\Scripts\python.exe -m pytest -q tests\test_native_sbom_job.py tests\test_native_sbom_metrics.py tests\test_native_sbom_image.py tests\test_dependency_intelligence.py --basetemp=test\tmp\native-sbom-integration
```

The final coordinator gate runs core plus integration **on the combined tree**, existing
evidence-collection, artifact-indexing, dataset-audit, retrieval, pipeline-log, and topology/config
regressions selected by changed imports/contracts, then compares any wider failures with the
baseline. Report exact commit/tree, test commands, pass/fail/skip counts, image receipt, and gaps.
Do not state “tested” from independently passing chunks alone. The parent reported its baseline
`python -m pytest` initially lacked pytest and is creating its own checkout-local `.venv`;
that environmental failure is not a feature regression or permission to borrow another checkout.

## Main correctness risks and deliberate exclusions

- **False identity/version:** aliases, packed macros, broad README regexes, ABI suffixes, and
  multiple copies can silently corrupt vulnerability matching. Prefer explicit uncertainty.
- **Custody:** hash-checking only a final path, trusting unaccepted scanner files, mutable
  workspaces, or copying evidence without binding its artifact breaks resolving evidence.
- **Normalization loss:** a correct parser is insufficient if envelope/normalizer/index layers
  discard version, claim state, root, or provenance. End-to-end tests are mandatory.
- **Standard compliance:** SPDX schema validity is necessary, not sufficient; dangling ids,
  wrong `NOASSERTION` semantics, invented package checksums, and missing license references
  need semantic tests.
- **Nondeterminism:** converter timestamps, id ordering, conflicting metadata iteration,
  model results, host absolute paths, and elapsed-time selection cannot enter canonical identity.
- **Coverage laundering:** catalog omissions, disabled/missing source inventory, unsupported
  binaries, failed conversion, and unmeasured reused work cannot become successful zero counts.
- **Regression:** Grype continues consuming the original Syft JSON, exposure logic remains
  conservative, repository inference remains nonexact, and advisories remain unverified leads.

This slice does not promise complete native composition, preprocessing/conditional resolution,
binary fingerprint databases, network source matching, source-equivalence verification,
transitive dependency edges, automatic license identification, SBOM signing, VEX, SPDX 3.x,
or replacing existing vulnerability scanners. Each absent capability is separate from the
bounded coverage this feature actually publishes.
