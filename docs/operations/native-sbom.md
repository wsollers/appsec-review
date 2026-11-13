---
title: "Native SPDX inventory"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_dependency_intelligence"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Native SPDX inventory

`job_dependency_intelligence` enriches the accepted source Syft inventory with bounded native
dependency observations and publishes **SPDX 2.3 JSON**. It does not require CMake, Conan, or a
successful native build. Cataloged headers and package documents can identify header-only and
vendored source dependencies. The [design](../architecture/native-sbom.md) defines evidence,
corroboration, conflict, and merge rules.

## Outputs and acceptance

The dependency-intelligence handoff retains `raw_native_discovery`, `native_curation`,
`native_metadata`, effective `native_discovery`, and `sbom`. Resolve it
through `load_accepted_dependency_intelligence(run_root)`, rather than searching attempt
directories. The loader verifies accepted artifact membership, exact bytes, the pinned SPDX
schema, package references, metrics, and native evidence bindings. Legacy handoffs without
the new fields remain readable.

The publication unit retains `baseline.spdx.json` when conversion succeeds,
`enriched.spdx.json` after validation, `native-sbom-provenance.json`, and
`native-sbom-metrics.json`. Discovery is retained separately as `native-discovery.json`.
The provenance maps emitted package SPDXIDs to source evidence and/or original baseline
records. Only corroborated, nonconflicting native releases become `versionInfo`; unknown
licenses, copyright, and download locations are `NOASSERTION`. ABI suffixes and filename
versions are hints, not confirmed package releases.

Between discovery and publication, model-assisted curation identifies libraries and separate
inferred SDK families; root-scoped investigation selects bounded catalog files and proposes
independently cited metadata. Models do not browse or execute search patterns. Deterministic
literal checks, exact citations and input custody establish corroboration, not model confidence.
Unavailable/invalid inference preserves conservative candidates and reports gaps. Versions
are never propagated between bundled components or vendored copies.

Accepted compiler/linker captures inside other build families, including Python extensions,
also contribute evidence. Protected normalized command/artifact rows retain their original
accepted-source references. Target observations resolve through `find`, `resolve_evidence`,
and `read_excerpt`; workspace text resolves to exact detached run artifacts, never a mutable
workspace or a guessed target-source path.

The `sbom.status` is independent of repository inference and Scorecard coverage:

| Status | Meaning |
| --- | --- |
| `SUCCEEDED` | An SPDX document passed validation and applicable inventory coverage completed. An empty inventory can be a genuine zero. |
| `COMPLETED_WITH_GAPS` | A valid document exists, but named coverage is incomplete. Missing/failed source conversion can produce a native-only document. |
| `FAILED` | No enriched SPDX artifact is accepted. Diagnostics, provenance, and metrics remain available. Infrastructure or accepted-input integrity failures fail the job instead. |

Never interpret a partial or unavailable inventory as proof that no dependency exists.
Separate artifact-scanner SBOMs are not yet merged into this source inventory; artifact names
and accepted loader evidence still contribute native candidates, with that limitation named.
The original Syft JSON remains the internal scanner interchange for Grype; inferred native
versions are not injected into vulnerability matching.

## Bounds and image

Settings live only under `jobs.job_dependency_intelligence.settings` in `appsec-review.toml`.
The existing candidate, command-token, metadata-file, and per-file byte limits apply globally.
Additional settings bound aggregate source bytes, roots, evidence, evidence per candidate,
fields, paths, accepted JSON input bytes, publication bytes, elements, and conversion timeout. Increase a bound
only after examining its omission counts and scoped gaps. Bounds are part of publication and
index identity.

`settings.native_inference` contains `enabled`, `batch_candidates`, `max_payload_bytes`,
`max_calls`, `component_limit`, `group_limit`, `files_per_root`, `bytes_per_file`,
`source_bytes_limit`, and `field_bytes`. All limits are positive typed integers. `max_calls`
includes physical retries per stage; component limits never erase mandatory fallback records.
Both native stages reuse `settings.model` provider/model/reasoning/token/timeout/retry settings.
Disabling native inference retains deterministic discovery and explicitly unresolved coverage.
There is no separate model SDK or new SBOM image.

Only independently corroborated metadata becomes a new SPDX assertion. Supplier syntax and
download URLs must be representable; the current license writer accepts common single SPDX
identifiers, not general compound expressions or custom license text. Unsupported values stay
in the claim records with a publication gap. Different existing baseline assertions are retained,
not overwritten. Dynamic manifests, binary plists and ambiguous ownership remain named gaps.

Reuse `appsec-review/tool-syft:1.52.0`. It already generates and converts SPDX; no additional
SBOM image is required. Conversion uses the existing container executor, a catalog-resolved
image, no network, an exact read-only source JSON mount, an empty target mount, and bounded
run-owned scratch. If the image is missing, build the existing image:

```powershell
containers\build-all.ps1 build tool-syft
```

Conversion staging uses a deterministic short path under `data/native-sbom/` inside the run;
this avoids Docker Desktop I/O failures binding deeply nested Windows task directories.
`sbom.conversion` retains hash/size-bound staged input, execution, stdout, and stderr references.
The official schema and license are Git byte-pinned and included in built Python packages.

No target script, preprocessor, executable, response file, or macro expression is executed
by native discovery. Unmapped absolute SDK paths are not read from the host.

## Telemetry and verification

Operation spans `native-sbom.discovery`, `native-sbom.curation`, `native-sbom.metadata`, `native-sbom.conversion`, and
`native-sbom.publication` retain duration, terminal disposition, and the existing process
resource measurements. `NATIVE_SBOM_RESULT` references a hash/size-bound metrics receipt.
`aggregate_run_metrics(run_root)["native_sbom"]` separates attempted work and outcomes from
the current accepted inventory. It reports candidates by claim state, coverage/omissions,
merges/conflicts, output counts, conversion/validation status, and gaps. No package names,
source text, or full argv are metric dimensions.

`native_sbom.inference` reports stage receipts, accepted stage inventories, fresh/reused work,
curation/SDK counts, roots/files/bytes investigated, version/PURL claims and corroboration,
conflicts, omissions, physical model calls/failures, known token usage and unknown-usage calls.
Every attempt's request, response and usage receipt is hash-bound; unavailable usage is null
in attempt records and `usage_complete` is false, not an asserted zero-token call.

Retries do not sum inventories. Job/task reuse does not manufacture fresh work. Missing,
corrupt, or contradictory receipts produce accounting gaps and unavailable counters, not
successful zeros. Windows process I/O or resource timing that cannot be attributed remains
unavailable; it is not reported as zero.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_native_component_curation.py tests\test_native_metadata_investigation.py tests\test_native_inference_runtime.py tests\test_native_inference_wiring.py tests\test_native_discovery.py tests\test_native_spdx.py tests\test_native_sbom_metrics.py tests\test_skill_separation.py --basetemp=test/tmp/native-sbom-unit
```

Use a checkout-local Linux/WSL environment for definitive checks, with the equivalent
`.venv/bin/python -m pytest` command. The new wiring tests exercise focused handlers and
validators with a fake external model boundary, not a full pipeline/review.
Integration, acceptance, live-model, real-image and Dagster review validation are separate,
manual user-owned checks; the inference extension has not run them.

When explicitly requested, `tests/integration/test_native_sbom_image.py` performs real offline Syft-to-SPDX conversion through the executor and then
validates enrichment against the pinned official SPDX schema. Missing Docker/image produces
an explicit skip, not a passed image claim.
