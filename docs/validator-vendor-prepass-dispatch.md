# Validator Dispatch For The Vendor-Prepass Contracts

`appsec-review-process/validate_job_output.py` dispatches the nine ADR-0010 family contracts to
their own verifiers: V04 `secrets-inventory`, `iac-config-evidence`; V07
`container-image-inventory`, `mobile-sast`, `binary-hardening`; V05 `sbom-inventory`,
`sca-vulnerability-match`, `license-inventory`, `dependency-lifecycle`.

Those verifiers take no optional safety input. This page says where the validator gets each
required argument. The rule is one sentence: **no caller fact is read from the attempt under
validation.** A fact with no authoritative source fails closed with a named error; the verifier is
never skipped in favour of the generic schema check.

## Entry points

| Function | Role |
|---|---|
| `validate_job_output(..., *, orchestration)` | The acceptance entry point. `orchestration` is a required keyword with no default: `OrchestrationFacts(dagster_run_id, source_snapshot_sha256, now)` or the explicit `NO_ORCHESTRATION_FACTS`. |
| `validate_vendor_prepass_attempt(attempt_root, contract, *, run_id, job_id, attempt_id, node_status, orchestration)` | Assembles the caller facts and runs the contract's verifier. Every argument is required. `[]` means the verifier ran and accepted. |
| `validate_contract_result(attempt_root, contract, *, run_id, ...)` | Unchanged signature. The GENERIC layer only (result schema, secret check, claim class). For a vendor-prepass contract it is not acceptance on its own: it knows no caller fact and does not look at the redaction receipt. |
| `publish_job_output.publish_validated(..., orchestration=NO_ORCHESTRATION_FACTS)` and `validate_published(...)` | Pass the facts through. The default is the FAIL-CLOSED value: without facts no vendor-prepass contract can be published or re-admitted. |

With `NO_ORCHESTRATION_FACTS` every one of the nine returns
`<contract> cannot be validated: the caller supplied NO_ORCHESTRATION_FACTS; ...` and nothing in
the attempt is parsed. Every other contract ignores `orchestration`.

## Where each fact comes from

| Verifier argument | Contracts | Authoritative source |
|---|---|---|
| `attempt_root` | all | The caller's argument. `validate_job_output` requires its directory name to equal the envelope's `attempt_id`. |
| `expected_header.run_id` | V07, V05 | Envelope `run_id`, which `validate_job_output` binds to the caller's `expected_run_id`; the attempt must also sit inside the run directory of that name. |
| `expected_header.attempt_id` | V07, V05 | Envelope `attempt_id`, bound to the attempt directory's name. |
| `expected_header.job_id` | V07, V05 | The owning module's policy table (`CONTRACT_POLICIES[...]["job_id"]`, V07 `CONTRACTS[...]["job_id"]`). The envelope's `job_id` must equal it, or the contract is being presented by the wrong job. |
| `expected_header.source_snapshot_sha256` | V07, V05 | `OrchestrationFacts.source_snapshot_sha256`. **The worker envelope has no such field** (V07's docstring says it does), and no run-level record defines how the intake snapshot identity is derived, so the caller states it. See "Known limits". |
| header of the result document | all nine, incl. V04 | V04's verifier takes no expected header: it proves the documents agree with EACH OTHER. After any verifier accepts, the dispatch compares the result's `run_id`, `job_id`, `attempt_id` and `source_snapshot_sha256` with the facts above. |
| `expected_dagster_run_id` | all | `OrchestrationFacts.dagster_run_id`: the orchestrator run that PRODUCED the attempt. Not in the envelope. |
| `node_status` | all | Envelope `execution_status`. |
| `declared_tool_ids` | all | `VENDOR_PREPASS_NODES` in the validator, pinned from the adopted ADR-0010 fixture (`docs/proposals/vendor-prepass/job-nodes.proposal.json`). No job template or tooling profile registers these tools yet (V10-V12); a test fails on drift from the fixture and from every suite's goldens. |
| `permitted_node_statuses` | all | V04: `CONTRACT_POLICIES[...]["permitted_node_statuses"]`. V05: `NEVER_SKIPS`. V07 exports no table: `tool_instance_shapes.NODE_STATUSES`. A test ties all nine to the fixture's `permitted_terminal_statuses`. `SKIPPED` additionally needs the graph edge (below). |
| `on_unhandled`, `limits` | all | The validator is the receipt's CONSUMER: `REDACTION_POLICY = "refuse"`, `REDACTION_LIMITS = evidence_redaction.DEFAULT_LIMITS`. An attempt sealed under `withhold` is rejected. |
| `tool_outputs_root` | V04, V05 | `data/jobs/<job_id>/` of the run, derived from where the attempt is. The attempt must be at `<run>/data/jobs/<job_id>/<scope>/attempts/<attempt_id>` inside the run whose directory is named `run_id` and holds `inputs/artifact-manifest.json`; anything else fails closed. (V07 resolves tool outputs against the attempt itself.) |
| `source_root` / V07 `inputs_root` | `sbom-inventory`, `license-inventory`, `mobile-sast`, `binary-hardening` | `_source_root`: `target.repo_path` of the run's `inputs/artifact-manifest.json`, as for `project-discovery`. |
| V07 `inputs_root` | `container-image-inventory` | `<run>/inputs`, the run's staged inputs. |
| `sbom_attempt_root` + `expected_sbom`, `license_attempt_root` + `expected_license` | `sca-vulnerability-match`, `license-inventory`, `dependency-lifecycle` | The SAME run's `data/jobs/<upstream job>/<scope>/accepted.json`. `attempt_id` and `sha256` (`"sha256:" + hashes[<result artifact>]`) come from the POINTER. The pointer must be the accepted common format, name this run and job, be `OK`/`OK_WITH_GAPS`, be the newest attempt (`latest.json`), and the attempt tree and envelope must still hash to what the pointer recorded. No accepted upstream is a blocking error, never a skip. |
| `expected_databases` | `sca-vulnerability-match` | **Fails closed until V18.** `vulnerability_database_bindings(run_root)` raises. |
| `reference_table_path`, `expected_reference_table` | `dependency-lifecycle` | **Fails closed; no task owns the table yet.** `lifecycle_reference_table_binding(run_root)` raises. |
| `max_age` | SCA, lifecycle | `job_max_age(contract_id)` returns `NO_AGE_LIMIT` explicitly (ADR-0010 M4). Nothing in the run inputs, launch request or registry carries a job-set limit today. |
| `now` | SCA, lifecycle | `OrchestrationFacts.now`. Only the command line reads the wall clock. |

For V04 and V05 the registry record is also checked with the module's
`contract_declaration_errors`, so a registry copy that dropped the receipt cannot weaken validation.

## Order

For the nine contracts `validate_job_output`:

1. checks the envelope, the artifact list and hashes (files are hashed, never parsed);
2. runs `validate_vendor_prepass_attempt`. The verifier checks the redaction receipt against the
   published bytes before it parses anything;
3. **only if that returned nothing** parses `status.json` (`_status_errors`) and the result
   artifact (`validate_contract_result`: schema, `_secret_errors`, `_claim_class_errors`).

If the verifier, or the assembly of its facts, reports anything, step 3 does not run: no file of
the attempt is parsed by the validator and only the verifier's non-echoing errors describe the
attempt. The generic schema check echoes offending values, which is why it must not see a
document the receipt has not cleared. The three older contracts keep their path exactly:
`_status_errors`, then `validate_contract_result`.

## What fails closed today

| Contract | Error | Until |
|---|---|---|
| `sca-vulnerability-match` | `sca-vulnerability-match cannot be validated: no Grype DB / OSV consumer binding exists (V18)` | V18 |
| `dependency-lifecycle` | `dependency-lifecycle cannot be validated: no dependency-lifecycle reference-table publisher or consumer binding exists` | a reference-table publisher and binding (unowned) |
| any of the nine, `SKIPPED` | `02-evidence-assembly does not have exactly one dependency edge from <job>` and the skip reason is not authorized | V02 |
| any of the nine, published through `publish_job_output` without facts | `... the caller supplied NO_ORCHESTRATION_FACTS ...` | the worker passes `orchestration=` (V10-V12) |

## How V18 plugs in

Replace the body of `vulnerability_database_bindings(run_root)` so that it returns
`{"grype-db": {...}, "osv": {...}}` (the five `DATABASE_FIELDS` each) from V18's binding, which
re-verifies the databases offline on every call. Replace `lifecycle_reference_table_binding`
likewise with `(path, {"table_id", "version", "sha256", "as_of"})`. If a job-set `max_age` gets an
authoritative home, read it in `job_max_age`. Nothing else changes; the tests already run both
verifiers end to end with the seam filled (`bindings()` in the test module).

## After V02

Nothing in the validator changes. Non-SKIPPED validation never consults the graph node. A SKIPPED
attempt is accepted once `02-evidence-assembly` has an edge from the job whose
`allowed_skip_reasons` lists `not-applicable-no-matching-inputs`, and the caller names that
consumer (`--consumer-job 02-evidence-assembly`).

## Known limits

- `source_snapshot_sha256` and `dagster_run_id` are stated by the calling code. They are outside
  the attempt's documents, but the publisher runs in the worker process; no run-level record yet
  defines the snapshot identity, and `accepted.json` does not record the producing orchestrator
  run. Reuse (`validate_published(..., reuse=True)`) therefore needs the caller to know the
  PRODUCING run id.
- The upstream pointer's input fingerprint is not re-checked: the validator has no authoritative
  expected fingerprint for another job. The upstream attempt is bound by tree hash to what was
  accepted, not re-validated.
- `publish_job_output.persist_terminal_current` writes a canonical `status.json` with `job`,
  `started_at`, `ended_at` and `fingerprint`. All three verifiers reject unregistered status
  fields, so a vendor-prepass worker cannot publish through that helper as it stands.
- V07 exports no claim-class or permitted-status table; its three claim classes are typed in the
  validator and tied to the ADR fixture and the records by a test.
