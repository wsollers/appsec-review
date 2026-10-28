# Native SPDX inventory

`job_dependency_intelligence` enriches the accepted source Syft inventory with bounded native
dependency observations and publishes **SPDX 2.3 JSON**. It does not require CMake, Conan, or a
successful native build. Cataloged headers and package documents can identify header-only and
vendored source dependencies. The [design](../architecture/native-sbom.md) defines evidence,
corroboration, conflict, and merge rules.

## Outputs and acceptance

The existing dependency-intelligence handoff adds `native_discovery` and `sbom`. Resolve it
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

Operation spans `native-sbom.discovery`, `native-sbom.conversion`, and
`native-sbom.publication` retain duration, terminal disposition, and the existing process
resource measurements. `NATIVE_SBOM_RESULT` references a hash/size-bound metrics receipt.
`aggregate_run_metrics(run_root)["native_sbom"]` separates attempted work and outcomes from
the current accepted inventory. It reports candidates by claim state, coverage/omissions,
merges/conflicts, output counts, conversion/validation status, and gaps. No package names,
source text, or full argv are metric dimensions.

Retries do not sum inventories. Job/task reuse does not manufacture fresh work. Missing,
corrupt, or contradictory receipts produce accounting gaps and unavailable counters, not
successful zeros. Windows process I/O or resource timing that cannot be attributed remains
unavailable; it is not reported as zero.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_native_discovery.py tests\test_native_spdx.py tests\test_native_sbom_job.py tests\test_native_sbom_metrics.py tests\test_native_sbom_image.py --basetemp=test/tmp/native-sbom
```

The image test performs real offline Syft-to-SPDX conversion through the executor and then
validates enrichment against the pinned official SPDX schema. Missing Docker/image produces
an explicit skip, not a passed image claim.
