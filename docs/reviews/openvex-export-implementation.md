# OpenVEX findings export implementation

Status: standalone gate/2 adaptation verified against exact completed main `c47e3fea`.
Local-main landing is coordinated separately from the source verification recorded here.
The user explicitly selected standalone post-gate OpenVEX with gate-only report/2. The original
/1 verification is retained as historical evidence, not proof of the adapted implementation.
This record describes feature implementation and
verification, not an accepted application-security review or authorization to disclose findings.
The [architecture contract](../architecture/openvex-export.md) and
[operator guide](../operations/openvex-export.md) describe configuration and operation.

## Delivered boundary

- `job_openvex_export` is a deterministic, model-free consumer of the accepted publication gate/2
  and inference review/3. Its three units verify inputs, assemble canonical outputs, then re-prove
  the boundary before the runtime can accept its handoff. No target, network, subprocess,
  remediation generator, new approval intake, signature infrastructure or publisher was added.
- All and only gate-publishable confirmed findings become OpenVEX v0.2.0 `affected` statements.
  Backlog and withheld findings remain exact companion exclusions. Scores, independence,
  ship-block policy, limitations and resolving evidence remain in the companion rather than
  being misrepresented as OpenVEX status. PoCs, chains and dossiers are not prerequisites.
  Certified capabilities and attachments, including qualified chains, compile-failed PoCs,
  manual remediation and dossiers, retain their exact context without changing eligibility.
  Capability notices are not invented review gaps.
- Immutable pre-run configuration names the issuer, accurate common action and stable repository
  IRI. Products identify the reviewed source snapshot and full resolved configuration, not a
  guessed release, distribution or purl. Accepted acquisition provenance does not automatically
  prove the operator's repository IRI for multi-component or Perforce systems.
- Protected attempt-local outputs include verified inputs, nine pinned schema/license/lock
  snapshots, manifest, result and a VEX document only when nonempty. Zero eligible findings
  produce `no_statements`, a null document reference and a named non-clean gap, not an empty
  safety assertion. Hashes retain exact bytes and line endings.
- Durable input inventory excludes mutable job latest pointers and the accepted-index admission
  pointer. Verification still measures, bounds and reproves them internally. Immutable handoffs,
  scope, configuration, ledger, projection and resolving evidence remain durable bindings.
  A valid new upstream pointer therefore makes a historical export stale rather than corrupt.
- The accepted reader validates canonical reassembly, runtime metadata, artifact custody,
  duplicate artifact paths and all bound bytes. The latest/operator reader additionally checks
  current upstream authority. Historical accepted semantic totals are independently verified and
  deduplicated by accepted handoff digest; they do not depend on remaining the current export.
  Corrupt output is an integrity failure, not a missing/stale fallback.
- Disabled manual dispatch is refused. PoC generation, remediation planning, validation and
  dossier publication remain before the single certified gate. Enabled OpenVEX and the final
  report are independent post-gate consumers. The report consumes only the gate: there are no
  OpenVEX report fields, links or fan-in dependencies.
- Input admission uses bounded review/3 preflight and the shared accepted gate/2 snapshot reader.
  Every nested certified reference is measured and bound. Snapshot consumers never rediscover
  optional producer latest heads; corrupt live optional heads cannot replace certified context.
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
| Original /1 job/report integration, superseded by standalone gate/2 | `5d2d1a44eaae5cc5939d36fa463036185d3ece13` |
| Final operator documentation and diagrams | `71b608dea651bc73c9c4a0459a80faf250a89431`, `3923193470cc866d9fa6813fc79344dd672d0c11` |
| Output custody after descriptor/path reproof | `1292a2036694f42abe5193e699a4a6bf894e62cf` |
| Nullable undeclared runtime release metadata | `9d4d49d9e06801b847552432cfe75e74947c30bc` |
| Strict gate/2 contracts and seven-schema closure | `f4f746bf6115bb812b5dd1bbc5f84788a97949db` |
| Shared accepted-gate snapshot reader, reused by gate-only reporting | `090bb4026a976e8a1b3e3f4d154e056d2539a0e5` |
| Exact certified-context projection and semantic validation | `e6d6444212533fcdacb65785535a2814946baff9` |
| Standalone graph, CLI and consumer-inventory assertions | `212f21a83430bb501ebe0ea2130c97d9547280ae` |
| Standalone documentation and diagrams | `5edc1d7d2ca6fc1c468f81ce4f5fb33477a24329` |
| Bounded review/3 and accepted gate/2 input verification | `2f467134a92b0e2ebc95fa3ffc67fe6655e90b83` |
| Assembled-feature documentation status and packaging qualifications | `03a8d4e54229927442a07bddded975c84e0b5465` |
| Exact completed-main merge, preserving host pins and SBOM/debug telemetry | `b0d53c457bd2ed871aa99da3b530782173c70550` |
| Combined 44-job / 145-dataset inventory, including protected export | `870d4789aa3a74c974928e06a7d9cafa86157aa8` |

The review handoff consumer enum additionally permits the exporter, without invalidating existing
four-consumer handoffs. Finding-package/2 and finding eligibility policy were not changed by
OpenVEX. The input-source matrix,
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

The following is the historical /1 selector set. Its OpenVEX report-specific files were removed
when the user selected gate-only reporting; it is not the current /2 command.

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

The handler tests use actual small hash-bound files and production exporter handlers.
`AcceptedInputDisk` explicitly doubles only upstream `load_accepted_review`; it does not pretend
to establish a complete real accepted-review chain. In the adapted fixture the real accepted-gate
reader, classifier and bounded custody/configuration/index readers run normally. Its chain
certificate is synthetic, not real actor/ledger-policy proof. Pure fixtures likewise are synthetic
verified-boundary examples, not proof of filesystem admission.

A rebuilt wheel at `1292a2036694f42abe5193e699a4a6bf894e62cf` was force-installed in an isolated
environment. Python `-I` confirmed that imports and schema resources came from that environment,
verified all six schema pins plus lock/license, checked packaged exporter modules, and executed
canonical one-statement assembly and semantic validation using a serialized synthetic fixture.
No source-schema fallback or remote retrieval was used. This is a packaging/pure-boundary check,
not full installed job execution.

### Certified gate/2 adaptation

The shared authority extraction preserves the existing report snapshot proof rather than
introducing a competing certificate validator. `load_accepted_gate` authenticates the accepted
handoff and gate document with the final-report schema set; `verify_gate_snapshot` rechecks
certified membership and bound bytes under inputs, capabilities and attachments. Reporting
delegates to that same reader and still consumes only the gate. The exporter performs bounded
preflight before authority and rereads bytes/current core pointers afterward.

The adapted disk fixture includes content-addressed lead/hunt lane packages and a review-owned
chain manifest. Selected chain actors' original receipts are bounded; unused chain cells are not
silently admitted. Core review and full resolved-configuration references must remain a subset
of certified gate bindings. Removed gate/1 fields are rejected, not adapted.

Recorded focused results before final main reconciliation:

| Exact source | Scope and result |
| --- | --- |
| `f4f746bf6115bb812b5dd1bbc5f84788a97949db` | Child-reported contracts/settings: 180 passed; five upstream pure schema/publication cases passed |
| `090bb4026a976e8a1b3e3f4d154e056d2539a0e5` | Shared snapshot authority, publication and strict contracts/settings: 240 passed |
| `e6d6444212533fcdacb65785535a2814946baff9` | Child-reported projection/contracts/settings: 306 passed |
| `212f21a83430bb501ebe0ea2130c97d9547280ae` | Standalone topology, CLI and consumer inventory: 22 passed |
| `b0540ab6dfcb4aae15a19c09e9c560b7379a7d9c` | Merged documentation/source-matrix consistency: one passed |
| `2f467134a92b0e2ebc95fa3ffc67fe6655e90b83` | Child-reported input verifier/contracts/settings: 300 passed in 62.74 seconds |
| `e628041cd734d854e749aa4e373bdc718d9a7363` | Combined coordinator exporter, shared snapshot, publication, topology and directly affected consumer units: 614 passed in 287.36 seconds |
| `870d4789aa3a74c974928e06a7d9cafa86157aa8` | Final main-reconciled exporter/completion/inventory, native SBOM and debug metrics, review schemas and resume declarations: 734 passed, two Windows symlink-privilege skips in 302.15 seconds |

The combined /2 command on the committed source above was:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -x `
  tests\test_openvex_contracts.py tests\test_openvex_settings.py `
  tests\test_openvex_inputs.py tests\test_openvex_projection.py `
  tests\test_openvex_metrics.py tests\test_openvex_job_units.py `
  tests\test_openvex_wiring.py tests\test_gate_snapshot.py `
  tests\orchestration\test_topology.py tests\test_owasp_telemetry.py `
  tests\test_completion_publication.py `
  tests\test_review_data_indexing.py::test_input_source_matrix_matches_design_document_and_registry `
  tests\test_review_data_indexing.py::test_downstream_review_consumers_preserve_certified_completion_order `
  tests\test_final_report.py::test_registry_topology_and_terminal_job `
  tests\test_final_report.py::test_disabled_completion_jobs_make_the_review_terminal `
  tests\test_final_report.py::test_cli_graph_places_the_new_jobs_after_the_review `
  tests\test_final_report.py::test_review_data_indexing_does_not_audit_its_own_consumers `
  tests\test_final_report.py::test_datasets_and_handoff_contracts_are_declared `
  --basetemp=test\tmp\openvex-gate2-combined
```

The final main-reconciled command retained every selector above, added the following files/cases,
and used `--basetemp=test/tmp/openvex-main-final`:

```text
tests\test_completion_wiring.py
tests\test_native_sbom_metrics.py
tests\test_debug_symbol_metrics.py
tests\review\test_inference_review_schemas.py::test_handoff_partitions_remediation_intake_from_the_verification_backlog
tests\review\test_inference_review_schemas.py::test_handoff_accepts_exact_accounting_only
tests\test_inventory_resume.py::test_registry_exposes_downstream_file_contracts
```

The two skips are the existing file/directory variants of
`test_every_metrics_path_symlink_component_is_rejected` in `test_native_sbom_metrics.py`.
A separate `-rs` run reproduced `WinError 1314` for both. They are named Windows environment
gaps, not passing Linux custody evidence; no skip or assertion was added or weakened.

At `212f21a83430bb501ebe0ea2130c97d9547280ae`, a rebuilt wheel was force-installed in the
coordinator's isolated environment. Python `-I` confirmed installed-only module/resource paths,
all seven offline schema resources plus license/lock, transitive report PoC-item resolution,
canonical one-statement assembly and semantic validation with serialized synthetic gate/2
inputs. Exact capabilities replaced `unavailable_inputs` in the checked companion. This is
packaging/pure-boundary evidence, not real installed-job or whole-chain acceptance.

The installed-only check was repeated successfully on main-reconciled source
`870d4789aa3a74c974928e06a7d9cafa86157aa8`. In addition to canonical assembly/validation
and all seven offline resources, the rebuilt wheel's verifier, projector, contracts and shared
gate-reader module bytes were compared with that exact checkout. No installed whole-job or
real-run acceptance claim follows from this packaging check.

Completed main `c47e3fea5023011e9e6c6d0dbd4095d0a691561c` is an ancestor through an
ordinary merge, not a rebase or separate completion landing. Semantic comparison proves its
entire central configuration is unchanged except for the exporter table and declared release.
Host catalog pins are semantically identical; the CodeQL asset-lock bytes match exactly.

## Failures and qualifications

- An initial wheel build lacked the already-declared `setuptools>=75` backend. Restoring that
  build dependency resolved it; no application dependency or pin was loosened.
- An exploratory standalone job import without application resources failed in the existing
  upstream inference guidance import because `pipeline/guidance/registry.json` was unavailable.
  The narrowed installed-only projection/schema check passed. The application still requires
  its configured guidance and upstream review resources; a self-contained wheel application
  was neither implemented nor verified.
- The documentation alignment agent's mixed focused command passed 202 tests and hit two known environment
  failures: an untouched build-environments document links to the user-owned absent target's
  `support/project-matrix.json` and `README.md`; the runtime-skill symlink rejection test cannot
  create a Windows symlink without privilege (`WinError 1314`). Owned-page link/fence/LF checks,
  the documented full configuration example, exact default/bound parity and schema-pin probes
  passed. Its status-only follow-up on `e628041c` plus documentation edits passed 23 tests and
  reproduced only the existing missing-target-link failure. The final nine-page audit checked
  313 links/anchors, four Mermaid blocks and LF bytes. Targets and test assertions were not
  weakened.
- Early coordinator fixture failures exposed missing synthetic runtime metadata/configuration
  schema and mutable admission pointers in durable evidence. The fixture was corrected and the
  pointer defect fixed in production before the passing combined command. No failure was turned
  into `no_statements`.
- During /2 reconciliation, obsolete fixtures reproduced removed `unavailable_inputs` access and
  old report-tail topology assertions. The projection and assertions were retargeted to the
  approved certified-gate architecture, without weakening certificate verification or restoring
  /1 adapters. An incorrectly named documentation selector selected no tests; the exact existing
  source-matrix selector was then run and passed.
- The exact-main smoke command first passed 39 units and exposed the newly merged completion
  inventory's missing exporter row. The authoritative registry was measured at 44 jobs and
  145 dataset kinds; its table, protected declarations and obsolete contracts-only status were
  updated without weakening the inventory regression.
- Preservation probes initially overconstrained the intended delta by omitting the exporter
  release declaration and requiring raw equality for the unchanged catalog's inherited working
  CRLF bytes. The corrected probe compares full TOML semantics after removing only the two
  intended additions and verifies byte-pinned CodeQL lock bytes. No host pin or evidence hash
  was rewritten to satisfy a probe.
- A pre-existing final-report implementation-identity assertion expects a source fingerprint
  where the declared-release framework returns `None`. It was not used to change generic runtime
  identity or release semantics. Related registry, CLI, report and reuse boundaries have focused
  coverage; the entire legacy final-report chain was not run.

## Manual validation still required

Integration, acceptance, live Dagster and the full test suite were not run. Passing focused
units does not establish these checks. The user owns:

1. A fresh enabled run with a complete real accepted review/3 and gate/2 chain, checking nonempty,
   mixed and genuinely empty export accounting, with gate-only report publication independent of
   the export.
2. Direct CLI versus live Dagster execution with pre-gate completion producers and post-gate
   export/report consumers, including a failed export, stale upstream rerun and explicit operator
   state refresh. No older artifact may become an absent or clean success.
3. Actual runtime reuse/failure/deadline event correlation and post-acceptance metrics refresh.
   The ordinary runtime snapshot precedes `HANDOFF_ACCEPTED`; a later snapshot or the existing
   metrics command must refresh accepted semantic totals afterward. Gate-only reporting is not
   an export-completion barrier.
4. Private POSIX custody and concurrent mutation checks on the supported Linux/WSL application
   filesystem, not an NTFS assumption inferred from authorized Windows unit work.
5. Any full installed application deployment with its existing guidance and upstream schema
   resources, and any external publication/security disclosure process.

No target execution, exploit execution, external publication, push or PR was part of this work.
Local-main landing is delegated to Merge monitor. The exact completed main SHA supplied by both
integration owners is merged into the feature branch without rebasing before the final clean
handoff; there is no separate duplicate completion landing.
`docs/docs-sync.json` is intentionally unchanged.
