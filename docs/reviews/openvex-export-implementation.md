# OpenVEX findings export implementation

Status: pre-transition implementation verified; gate/2 adaptation in progress, not landed.
The user explicitly selected standalone post-gate OpenVEX with gate-only report/2. Original
report links/fan-in below describe the superseded /1 implementation, not the target architecture.
This record describes feature implementation and
verification, not an accepted application-security review or authorization to disclose findings.
The [architecture contract](../architecture/openvex-export.md) and
[operator guide](../operations/openvex-export.md) describe configuration and operation.

## Delivered boundary

- `job_openvex_export` is a deterministic, model-free consumer of the accepted publication gate
  and inference review. Its three units verify inputs, assemble canonical outputs, then re-prove
  the boundary before the runtime can accept its handoff. No target, network, subprocess,
  remediation generator, new approval intake, signature infrastructure or publisher was added.
- All and only gate-publishable confirmed findings become OpenVEX v0.2.0 `affected` statements.
  Backlog and withheld findings remain exact companion exclusions. Scores, independence,
  ship-block policy, limitations and resolving evidence remain in the companion rather than
  being misrepresented as OpenVEX status. PoCs, chains and dossiers are not prerequisites.
- Immutable pre-run configuration names the issuer, accurate common action and stable repository
  IRI. Products identify the reviewed source snapshot and full resolved configuration, not a
  guessed release, distribution or purl. Accepted acquisition provenance does not automatically
  prove the operator's repository IRI for multi-component or Perforce systems.
- Protected attempt-local outputs include verified inputs, eight pinned schema/license/lock
  snapshots, manifest, result and a VEX document only when nonempty. Zero eligible findings
  produce `no_statements`, a null document reference and a named non-clean gap, not an empty
  safety assertion. Hashes retain exact bytes and line endings.
- Durable input inventory excludes mutable job latest pointers and the accepted-index admission
  pointer. Verification still measures, bounds and reproves them internally. Immutable handoffs,
  scope, configuration, ledger, projection and resolving evidence remain durable bindings.
  A valid new upstream pointer therefore makes a historical export stale rather than corrupt.
- The accepted reader validates canonical reassembly, runtime metadata, artifact custody,
  duplicate artifact paths and all bound bytes. The current report reader additionally checks
  current upstream authority and the exact report gate. Corrupt output is an integrity failure,
  not a missing/stale fallback.
- Disabled manual dispatch is refused. Enabled OpenVEX and PoC jobs are independent gate tails;
  the final report waits for every enabled tail in both direct and Dagster topology. Optional
  report states have nullable references/counts and do not alter claims, gate eligibility or
  ship-block decisions.
- Domain events and operation spans have closed phase/reason labels. Accepted semantic metrics
  require runtime acceptance and the full reader, not file presence or a domain completion.
  Known execution counts survive later output tamper while semantic totals become unknown.
  Histograms distinguish missing timing from measured zero; empty output has no document-size
  sample. The original attempt deadline also covers final output reading.

## Implementation history

| Boundary | Commit |
| --- | --- |
| Approved narrowed design | `e0deaabde21e8a76d5f5c7a91fd974e829539f60` |
| Frozen records, settings, schemas and fixtures | `d6a36c9b3576f5722d548843be764c5f308e4ec4` |
| Strict original RFC3339 offset validation | `62b28fabdea5ba087dd1bb37cb6cf258cc2bb93b` |
| Accepted input verification | `08f618c9d68bbe5b4e8f1533cf31f86e5803ceb5` |
| Pure projection and offline semantic validation | `608dadf6038dddfa2e3c7a187957a56d6637d581` |
| Accepted-only telemetry, including correlation corrections | `829e99a158daa3166ac0f77e7175b5c1540ee9f9` |
| Durable evidence versus live admission pointers | `1c6bda4624ab9f75556641413bca7110bdcb4b45` |
| Job, report, configuration, topology and packaging integration | `5d2d1a44eaae5cc5939d36fa463036185d3ece13` |
| Final operator documentation and diagrams | `71b608dea651bc73c9c4a0459a80faf250a89431`, `3923193470cc866d9fa6813fc79344dd672d0c11` |
| Output custody after descriptor/path reproof | `1292a2036694f42abe5193e699a4a6bf894e62cf` |
| Nullable undeclared runtime release metadata | `9d4d49d9e06801b847552432cfe75e74947c30bc` |

The review handoff consumer enum additionally permits the exporter, without invalidating existing
four-consumer handoffs. Finding-package/2 and gate policy were not changed. The input-source matrix,
protected dataset declarations and downstream inventory exclusions name the new producer.
Two touched portable files had committed CRLF bytes (`indexing/input_matrix.py` and
`tests/test_review_data_indexing.py`); they were normalized to required LF. No schema pin was
regenerated to accommodate newline conversion.

## Focused verification

Native Windows work and focused unit tests were explicitly authorized for the isolated feature
sessions. The editable import was confirmed inside the coordinator checkout; no shared main
checkout, target checkout or other session's environment was used.

On `5d2d1a44eaae5cc5939d36fa463036185d3ece13`, the combined focused command below passed
**509 tests in 284.41 seconds**. The same combined selector set with two custody regressions
passed **511 tests in 281.89 seconds** on `1292a2036694f42abe5193e699a4a6bf894e62cf`.
After correcting nullable runtime identity in the production reader and fixture, all **41**
affected job/report/wiring units passed in **224.38 seconds** on
`9d4d49d9e06801b847552432cfe75e74947c30bc`. These are /1-baseline results, not /2 evidence.

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_openvex_contracts.py tests\test_openvex_settings.py `
  tests\test_openvex_inputs.py tests\test_openvex_projection.py `
  tests\test_openvex_metrics.py tests\test_openvex_report_units.py `
  tests\test_openvex_job_units.py tests\test_openvex_report_job_units.py `
  tests\test_openvex_wiring.py tests\orchestration\test_topology.py `
  tests\test_owasp_telemetry.py `
  tests\test_review_data_indexing.py::test_input_source_matrix_matches_design_document_and_registry `
  tests\test_review_data_indexing.py::test_downstream_review_consumers_are_registered_as_planned_producers_by_name `
  tests\review\test_inference_review_schemas.py::test_handoff_partitions_remediation_intake_from_the_verification_backlog `
  tests\review\test_inference_review_schemas.py::test_handoff_accepts_exact_accounting_only `
  tests\test_inventory_resume.py::test_registry_exposes_downstream_file_contracts `
  tests\test_final_report.py::test_registry_topology_and_terminal_job `
  tests\test_final_report.py::test_cli_graph_places_the_new_jobs_after_the_review `
  --basetemp=test\tmp\openvex-final-committed
```

The handler tests use actual small hash-bound files and production exporter/report handlers.
`AcceptedInputDisk` explicitly doubles only upstream `load_accepted_review`; it does not pretend
to establish a complete real accepted-review chain. Pure fixtures likewise are synthetic
verified-boundary examples, not proof of filesystem admission.

A rebuilt wheel at `1292a2036694f42abe5193e699a4a6bf894e62cf` was force-installed in an isolated
environment. Python `-I` confirmed that imports and schema resources came from that environment,
verified all six schema pins plus lock/license, checked packaged exporter modules, and executed
canonical one-statement assembly and semantic validation using a serialized synthetic fixture.
No source-schema fallback or remote retrieval was used. This is a packaging/pure-boundary check,
not full installed job execution.

## Failures and qualifications

- An initial wheel build lacked the already-declared `setuptools>=75` backend. Restoring that
  build dependency resolved it; no application dependency or pin was loosened.
- An exploratory standalone job import without application resources failed in the existing
  upstream inference guidance import because `pipeline/guidance/registry.json` was unavailable.
  The narrowed installed-only projection/schema check passed. The application still requires
  its configured guidance and upstream review resources; a self-contained wheel application
  was neither implemented nor verified.
- The documentation agent's mixed focused command passed 208 tests and hit two known environment
  failures: an untouched build-environments document links to the user-owned absent target's
  `support/project-matrix.json` and `README.md`; the runtime-skill symlink rejection test cannot
  create a Windows symlink without privilege (`WinError 1314`). Owned-page link/fence/LF checks,
  the documented full configuration example, exact default/bound parity and schema-pin probes
  passed. Targets and test assertions were not weakened.
- Early coordinator fixture failures exposed missing synthetic runtime metadata/configuration
  schema and mutable admission pointers in durable evidence. The fixture was corrected and the
  pointer defect fixed in production before the passing combined command. No failure was turned
  into `no_statements`.
- A pre-existing final-report implementation-identity assertion expects a source fingerprint
  where the declared-release framework returns `None`. It was not used to change generic runtime
  identity or release semantics. Related registry, CLI, report and reuse boundaries have focused
  coverage; the entire legacy final-report chain was not run.

## Manual validation still required

Integration, acceptance, live Dagster and the full test suite were not run. Passing focused
units does not establish these checks. The user owns:

1. A fresh enabled run with a complete real accepted review/gate chain, checking nonempty, mixed
   and genuinely empty export accounting, then report publication against that exact gate.
2. Direct CLI versus live Dagster execution with both optional tails enabled, including a failed
   export, stale upstream rerun and report refresh. No older artifact may become an absent or
   clean success.
3. Actual runtime reuse/failure/deadline event correlation and post-acceptance metrics refresh.
   The ordinary runtime snapshot precedes `HANDOFF_ACCEPTED`; the report tail or existing metrics
   command must refresh accepted semantic totals afterward.
4. Private POSIX custody and concurrent mutation checks on the supported Linux/WSL application
   filesystem, not an NTFS assumption inferred from authorized Windows unit work.
5. Any full installed application deployment with its existing guidance and upstream schema
   resources, and any external publication/security disclosure process.

No target execution, exploit execution, external publication, push or PR was part of this work.
Local-main landing is delegated to the previously agreed sole integration owner after the final
source and documentation handoff; `docs/docs-sync.json` is intentionally unchanged.
