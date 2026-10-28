# OpenVEX findings export implementation

Status: standalone gate/2 export landed on local main `83e67b23`; the user-directed automatic
generation follow-up is verified at `74d93127`, with current runtime handoff/2 compatibility
integrated through `2099e277`. Its local-main landing is coordinated separately
from the source verification recorded here.
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
- New runs generate and verify protected local files automatically. Frozen defaults identify the
  generating tool, provide conservative investigation/remediation text, and derive a local
  repository namespace from the accepted source snapshot. No issuer or repository setup is
  required. Explicit individual/organization, action and repository overrides remain available.
  Products identify the reviewed source snapshot and full resolved configuration, not a guessed
  release, distribution or purl. Accepted acquisition provenance does not automatically prove an
  operator's repository IRI for multi-component or Perforce systems. Default tool authorship is
  a local schema-validated projection, not a claim of supplier issuance or compliance with the
  specification's individual/organization author requirement.
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
- Explicit opt-out is respected and disabled manual dispatch is refused. Frozen historical
  disabled runs are not rebound to new defaults. PoC generation, remediation planning, validation and
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
| Original standalone feature landed on local main | `83e67b23d94433a002b09d65a2d620673ebe54a5` |
| User-directed automatic local generation and no-setup defaults | `74d931273a383f2f33bac90d3569a070a0ef612d` |
| Concurrent common-interchange main merged without rebasing | `3ad1fe270bae24dc126b80e5e37bd5aa8c0c129c` |
| Bounded common handoff/2 admission and authentic fixtures | `2570db57c23f097ec3525e327965965eda0c944c` |
| Historical export proof through immutable common runtime accounting | `2099e2777b4897fbaf1499d3f0fca8ae970f6622` |

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

## Automatic-generation follow-up

The user explicitly replaced opt-in generation with automatic post-run generation and
verification. At `74d931273a383f2f33bac90d3569a070a0ef612d`, both checked-in TOML and immutable
typed defaults enable the exporter without setup. The issuer is truthfully labelled as the
`AppSec Review` tool with an automated-local-review role, rather than inventing a human or
supplier. The pinned upstream schema accepts that author string, but the OpenVEX specification
requires an individual or organization author: automatic files are qualified local projections,
not an authenticated supplier advisory or a claim of full issuer-specification conformance.
Operators can explicitly configure their issuer before a new run without blocking local
generation by default.

An empty configured `repository_iri` resolves to
`urn:appsec-review:source:<accepted_source_snapshot_sha256>` with basis `source_snapshot`.
The verifier still authenticates and binds accepted acquisition evidence when present; it does
not copy an external acquisition URL into this local namespace. Explicit repository overrides
retain strict acquisition matching. All product identities still include the full frozen
configuration. The default action calls for reviewing/remediating the confirmed findings and
validating fixes; it does not assert that a remediation or release exists.

This deliberately extends the local common-schema identity enum, not its line endings. Its
raw-byte pin is now `a90bbf40647f6652d2439885b9e446471aadbc6c534d342881ea34f85f737f29`;
the validation profile is
`9ff5d5446567181831922d9d8ca3de7d36be55328fb30a92133c5e3d4565cd2e`.
Other schema/license/lock pins are unchanged. The declared exporter release is
`openvex-export-2`; historical evidence above remains attributed to its original release and
pin set. Frozen historical configuration is not rewritten or retroactively enabled.

On the exact committed source, the requirement-focused smoke command passed **325 tests in
43.01 seconds**. It covers the four shipped profiles, no-setup source identity with and without
accepted acquisition (including a non-public Git spelling), identity substitution refusal,
canonical schema validation, and actual production handlers generating, verifying and accepting
both affected output and empty `no_statements` output. An initial run exposed a synthetic
organization fixture inheriting the new tool role; its original explicit empty role was
restored rather than weakening the production assertion.

The broader directly affected unit command passed **547 tests in 310.92 seconds** on
`74d93127`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_openvex_contracts.py tests\test_openvex_settings.py `
  tests\test_openvex_inputs.py tests\test_openvex_projection.py `
  tests\test_openvex_metrics.py tests\test_openvex_job_units.py `
  tests\test_openvex_wiring.py tests\orchestration\test_topology.py `
  tests\test_gate_snapshot.py `
  tests\test_final_report.py::test_registry_topology_and_terminal_job `
  tests\test_final_report.py::test_cli_graph_places_the_new_jobs_after_the_review `
  --basetemp=test/tmp/openvex-automatic-focused
```

An actual wheel was rebuilt with the existing backend, installed in its own scratch virtual
environment, and checked under Python `-I`. Installed-only module/resource paths, all seven
offline schemas plus license/lock, transitive report PoC-item resolution, the new profile,
and exact verifier/settings/contracts/projector/validator module bytes were verified.
Serialized synthetic gate/2 inputs produced byte-identical affected and `no_statements`
outputs under automatic defaults. Missing declared validator dependencies were first exposed
by the isolated import; installing them inside that environment resolved it, and `pip check`
then reported no broken requirements. An exploratory probe incorrectly assumed the report
item used `$defs`; the actual pinned `properties/poc_outcomes/properties/items/items` pointer
was resolved successfully. None of this is a full installed job, genuine accepted review,
integration, acceptance, live Dagster or POSIX-custody result.

Generation remains model-free and local/protected. Eligibility, acceptance authority, metrics
semantics, pre-gate completion, and independent post-gate export/gate-only reporting are
unchanged. No host pins, targets, signature infrastructure, disclosure or external publication
were changed.

Documentation commit `b9c76f9dcb683ec46e5c41d9f89aec2200464030` reconciles eleven operative
pages and diagrams with this policy. Its targeted default-policy/handler/documentation command
passed 148 cases and reproduced only the known untouched missing-target-link failure described
below. The documentation agent checked 557 local links/anchors, five Mermaid blocks, LF,
both full TOML examples, the complete architecture job table, all nine raw pins and the new
profile. The parent fast-forwarded that exact tip and confirmed no production/config/test/schema
delta from `74d93127`. On `b9c76f9d`, the following final assembled-source command passed
**320 tests in 18.23 seconds**:

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_openvex_contracts.py tests\test_openvex_settings.py `
  tests\test_openvex_projection.py tests\test_openvex_wiring.py `
  --basetemp=test/tmp/openvex-automatic-final-pure
```

These are focused unit and packaging results, not a new whole-chain or live validation claim.
The source/schema bytes tested by the broader 547-case command and installed wheel are identical
after the documentation fast-forward.

### Concurrent runtime-interchange reconciliation

Before landing the automatic policy, local main advanced to
`d4cd9737826f87a771a0f5cd72b526c6907ca4fa`, introducing strict common `job-handoff/2`
envelopes and byte-verified outcome accounting. It was merged without conflicts or rebasing
at `3ad1fe27`. An initial focused input unit reproduced the now-obsolete exporter fixture's
`job-handoff/1` rejection by the real common reader; this was a named compatibility failure,
not an empty-output success.

The bounded input owner adapted admission at `2570db57` to the common decoder and reader.
Sized artifacts and the claim/result/outcome/task/shared-receipt closure are measured before
shared authority reads them, then reproved. The same fixture API now uses the shared synthetic
handoff publisher with frozen configuration, real hash-bound accounting, preserved caller
timestamps and explicit attempt identities. Only the existing upstream review-ledger authority
spy remains; the common handoff and certified gate authorities are real.

The parent historical reader at `2099e277` uses the common decoder and immutable runtime
integrity verifier, including exact claim/upstream, result, task receipts and outcome-accounting
proof. It bounds the combined export/runtime inventory and checks every declared artifact
before and after authority verification. It does not substitute current latest pointers for
historical authority. Legacy or incomplete common envelopes and rehashed claim/accounting
tamper are rejected. The common runtime's string `"undeclared"` identity replaces the old
nullable fixture identity; the earlier nullable-identity history above is not a current
handoff/2 contract. No legacy compatibility adapter or shared-runtime relaxation was added.

The input owner's exact-tip command passed **321 tests in 300.36 seconds** on `2570db57`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_openvex_inputs.py tests\test_openvex_contracts.py tests\test_openvex_settings.py `
  --basetemp=test/tmp/openvex-inputs-handoff2
```

On the merged `3ad1fe27` source with historical-reader edits still pending, automatic-export
pure/common-runtime checks passed **513 tests,
one skipped in 97.08 seconds**:

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_openvex_contracts.py tests\test_openvex_settings.py `
  tests\test_openvex_projection.py tests\test_openvex_metrics.py tests\test_openvex_wiring.py `
  tests\orchestration\test_topology.py tests\test_interchange_contract.py `
  tests\test_handoff_fixture.py tests\test_handoff_interchange.py `
  --basetemp=test/tmp/openvex-automatic-interchange-pure
```

The existing native symlink-reference test was rerun with `-rs`: it skips because the Windows
host does not grant symlink creation (`WinError 1314`), not because custody validation passed.
On exact `2099e277`, default settings/wiring/metrics, completion topology, opt-out and docs-sync
checks passed **229 tests in 19.40 seconds**:

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_openvex_settings.py tests\test_openvex_wiring.py tests\test_openvex_metrics.py `
  tests\test_completion_wiring.py tests\test_docs_sync.py `
  tests\test_final_report.py::test_registry_topology_and_terminal_job `
  tests\test_final_report.py::test_disabled_completion_jobs_make_the_review_terminal `
  tests\test_final_report.py::test_cli_graph_places_the_new_jobs_after_the_review `
  --basetemp=test/tmp/openvex-handoff2-final-surfaces --tb=short
```

An actual wheel was rebuilt again on exact `2099e277`, installed with its declared dependencies
in a fresh isolated environment, and passed `pip check` plus the Python `-I` resource/projection
probe. It verifies all six exporter module byte identities (including the adapted input and
historical readers), the unchanged seven-schema/nine-resource closure and profile, transitive
report PoC definition, and byte-identical affected/empty automatic projections. This remains
installed-only packaging and pure-projection proof, not a fully installed application/job run.

The combined actual production-handler and shared certified-snapshot consumer command passed
**45 tests in 602.57 seconds**. It began on `2570db57` with the parent reporting/job-unit
changes present; those exact source/test bytes were then committed unchanged as `2099e277`.
It covers fresh default generation, canonical acceptance, current versus historical authority,
runtime artifact/accounting corruption, metrics authority and gate-snapshot isolation:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -x `
  tests\test_openvex_job_units.py tests\test_gate_snapshot.py `
  --basetemp=test/tmp/openvex-automatic-handoff2-consumers --tb=short
```

An exact committed-tip recheck on `2099e277` passed **five tests in 112.89 seconds**, running
the default nonempty/empty handlers and fully rehashed common-envelope/claim/outcome negatives:

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_openvex_job_units.py::test_checked_in_defaults_generate_verify_and_accept_without_setup `
  tests\test_openvex_job_units.py::test_historical_reader_requires_authentic_common_envelope_accounting `
  --basetemp=test/tmp/openvex-handoff2-exact-defaults --tb=short
```

The merged central configuration was compared semantically with exact main `d4cd9737`: the
only differences are five intentional automatic-export default values and its release
declaration. The new parser bound, host/compiler/image pins and all other configuration are
preserved. Catalog and CodeQL asset-lock files match that main exactly in Git. Documentation,
test and packaging scratch created by this follow-up is removed before the clean landing
handoff. Main integration does not add integration, acceptance, live Dagster or Linux custody
evidence; those manual gaps remain below.

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
