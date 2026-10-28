# Native SPDX enrichment implementation

## Outcome and boundaries

The dependency-intelligence job now discovers vendored and header-only native dependencies
from accepted source catalogs, protected compiler/linker arguments, workspace metadata,
library filenames, and accepted loader facts. Discovery does not require CMake, Conan, or a
successful build. Native captures inside other build families are included.

The new public SBOM is **SPDX 2.3 JSON**. Existing source Syft JSON and Grype interchange are
unchanged. Literal hints do not become asserted package releases: only corroborated,
nonconflicting releases receive `versionInfo`. Different vendored copies remain scoped;
ambiguous matches and incompatible exact identities retain explicit gaps.

See the [design](../architecture/native-sbom.md) and
[operator guide](../operations/native-sbom.md).

## Commit and ownership record

Starting baseline: `fcac43068d17f139a9d94393b03fe128c6127f12`.
Shared frozen contracts and design: `e908325e045c721aacb5f465c9867c5f89791a9a`.
Each child verified that contract commit was an ancestor before implementing its owned files.
No child changed the contract. Work used isolated worktrees and checkout-local environments.

| Chunk | Implementation commit | Ownership |
| --- | --- | --- |
| Discovery | `7fed2f0625f430dfe1b227fb5418859e85d91330` | `discovery.py`, `resolution.py`, discovery tests; existing `native.py` remained unchanged |
| SPDX | `0b6205b56ec875281875200db0432e60cb945bcb` | `sbom.py`, official schema/license/provenance resources, SPDX tests |
| Metrics | `f89dea0129e49d3bb981bc3c52e8ecaa07b92e71` | `telemetry.py`, native-SBOM metric tests |
| Coordinator integration | `2e2ed0535395e2b28752cbb8ca73fa19634c3593` | Accepted inputs, job/config/dataset wiring, Syft adapter/envelope preservation, package exports/data, retrieval, end-to-end and real-image tests |

Chunks were merged locally, without rebasing or editing another session's checkout.
The byte-preservation prerequisite is `6a03b47b`; SPDX and discovery merge commits are
`e9beddc9` and `6ed9419d`. Nothing was pushed and no pull request was opened.

## Integration reconciliations

- The original core/integration split became three isolated child chunks plus coordinator
  integration, keeping shared hotspots single-owned.
- Generic accepted framework output filtering does not retain `scanner_output`. The Syft
  envelope now carries an exact `source_inventory` reference bound to both its raw artifacts
  and accepted framework membership.
- Structured discovery selectors address actual fields in protected, content-addressed
  normalized rows. Each row retains its original accepted artifact/JSON-pointer association.
  This avoids treating a build artifact's run path as its workspace-relative library path.
  Original and expanded argument hashes remain verified; no response file is executed.
- Target text evidence has exact source locations and `OBSERVED_AT` links to self-contained
  source-span entities. The inventory shard passes relation-closure validation without
  inventing duplicate upstream source-file records. Workspace text retains detached exact
  bytes and run-artifact selectors; it is not misrepresented as target or shipped source.
- The accepted publication, provenance sidecar, and metric receipt share the successful
  semantic input fingerprint. Converter timestamp/namespace volatility is excluded by the
  core, while exact original/converted identities remain in provenance.
- The official SPDX schema is vendored unchanged and checked offline against SHA-256
  `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b`.
  `.gitattributes` preserves schema/license bytes on Windows; package-data inclusion was
  checked with a real setuptools `build_py` build.
- Real acceptance found that Docker Desktop returned I/O errors for deeply nested task bind
  mounts. Conversion now stages exact source bytes under a short deterministic run-owned
  `data/native-sbom/` path. Its staged input, execution, stdout, and stderr references remain
  accepted and hash/size-bound.
- Infrastructure and accepted-input integrity failures abort the job. A reported tool
  conversion failure may instead publish valid native-only SPDX with named gaps. Schema
  failure retains failed diagnostics and metrics without an accepted enriched document.
- Attempted work and current inventory are separate. Retry counts never become summed
  inventories; reuse creates no fresh discovery/conversion work. Failed, missing, or corrupt
  accounting cannot appear as a successful zero. Existing measured operation spans remain
  the timing/resource authority; missing domain-receipt timing is explicitly unavailable.

## Verification

Child handoffs reported 94 new discovery cases, 108 SPDX cases, and 80 new metric cases.
Coordinator acceptance covered buildless discovery, complete-zero inventory, distinct
workspace copies, compiler captures inside Python builds, exact structured selectors,
target excerpt/evidence retrieval, inherited coverage gaps, publication byte bounds,
conversion failures, schema failures, integrity rejection, accepted membership, and reuse.

At integration commit `2e2ed0535395e2b28752cbb8ca73fa19634c3593`, the final affected-suite
run completed with **435 passed, 4 skipped, 2 pre-existing Windows failures, 1 deselected**
in 188.60 seconds. Every new discovery/SPDX/publication/telemetry test passed except the two
explicitly skipped Windows symlink-creation cases. The deselected case is the unchanged
dependency-loader stale error-message assertion listed below; it was run and reproduced
before exclusion.

The two final failures were
`test_standalone_managed_retrieval_keeps_admission_through_manifest_loading`
(`managed evidence admission requires verified POSIX custody`) and
`test_loader_rejects_wrong_audience_and_symlinked_runtime_skill` (Windows error 1314).
Both were independently reproduced against the exact baseline archive with that archive's
own editable environment. No admission check, skill-separation rule, or symlink protection
was weakened.

```powershell
.\.venv\Scripts\python.exe -m pytest `
  tests\test_native_discovery.py tests\test_native_spdx.py `
  tests\test_native_sbom_job.py tests\test_native_sbom_metrics.py tests\test_native_sbom_image.py `
  tests\test_dependency_intelligence.py tests\test_review_metrics.py tests\test_config.py `
  tests\test_retrieval_core.py tests\test_retrieval_interfaces.py tests\test_retrieval_artifacts.py `
  tests\test_skill_separation.py -q --tb=short `
  -k "not test_accepted_publication_verifies_handoff_index_and_hashes" `
  --basetemp=test/tmp/native-sbom-final
```

The real-image test performs offline conversion through the existing `ContainerExecutor`,
enriches the result, and validates both documents against the official schema.
It is not a mocked image claim.
The tested existing Syft 1.52.0 image is
`sha256:500039699651788b20d588790830c4e5b3b6c1f8a77e1855c0ad36a84adf5c65`.
No new image, tool pin, lock file, or runtime dependency was required.
The final execution receipt SHA-256 was
`427e39c71cd898da2dc23a0627a48bd446f90cfc95482c5c4fb66e2d08cd95c1`;
it recorded exit code 0, network `none`, and user `10001:10001`.

Known pre-existing limitations were measured separately:

| Suite | Result before final acceptance | Existing limitation |
| --- | --- | --- |
| Evidence collection, artifact custody, configuration, pipeline log | 105 passed, 6 failed | SEI CERT locked bytes differ after Windows CRLF checkout; two `os.mkfifo` cases are unsupported; two symlink cases lack Windows privilege; stale `_list_parser` test import |
| Dependency intelligence | 25 passed, 1 failed | Stale expected error text `index integrity mismatch`; actual existing loader says `target evidence integrity mismatch` |
| Engineering-signal integration and log | 17 passed, 1 skipped, 2 failed | Stale operator/direct-graph and registered-job-count documentation assertions; both failures reproduced against an exact baseline archive with its own environment |

One initial combined run also encountered a transient Windows atomic-replace permission error
in a metric fixture; its exact isolated rerun passed. New symlink-specific tests explicitly
skip when Windows denies actual symlink creation rather than weakening storage checks.

## Intentional remaining limits

Discovery uses conservative bounded literal recognizers, not general source execution or
arbitrary build-system evaluation. Unsupported syntax, missing loader metadata, exclusions,
ambiguous roots, and bound omissions remain named coverage gaps. Separate artifact-scanner
SBOMs are not yet merged into the accepted source inventory. Inferred native versions are
not vulnerability applicability assertions, and repository/Scorecard inference stays review
context rather than upgrading native evidence.
