# OpenVEX findings export

Implemented in `5d2d1a44eaae5cc5939d36fa463036185d3ece13`. This guide describes the
local exporter, configuration, report projection and telemetry at that commit; it does not
establish integration, acceptance or live Dagster validation. The
[design](../architecture/openvex-export.md) records the scope and trust decisions.

## What this export means

`job_openvex_export` serializes OpenVEX v0.2.0 without a model, target scan,
subprocess, container, network lookup or vulnerability reassessment. It exports **all and
only the accepted final publication gate's publishable confirmed packages**, one `affected`
statement per package. Supported packages in the verification backlog and withheld packages
are accounted for in the companion, not exported as statements. A confirmed withheld package
is still excluded. No package is silently skipped to produce a partial export.
PoC, attack-chain and dossier availability are not eligibility requirements. The exporter
does not generate, plan or validate remediation, or add a remediation job.

Only `affected` is supported. Missing coverage, an empty review, an unreachable observation,
refutation or PoC absence/failure cannot produce `not_affected`, `fixed` or
`under_investigation`. Review confirmation does not mean an exploit was executed, and export
success does not mean a product is clean or approved to ship. Scores, independence,
ship-block decisions and coverage remain separate dimensions, preserved without reinterpretation.

## Trust and data flow

The exporter reads accepted, hash-bound run artifacts, not the current target checkout
or advice in target-owned guidance. It re-verifies the gate against the accepted review,
including package accounting, evidence and both package manifests; resolves accepted scope;
and binds the full frozen configuration separately from the semantic review-settings hash.

```mermaid
flowchart TD
    Operator["Operator: issuer, common action, repository identity"] --> Config["Frozen pre-run configuration"]
    Review["Accepted review, ledger, packages and evidence"] --> Gate["Accepted publication gate"]
    Scope["Accepted scope and source manifest"] --> Verify["Verify inputs and exact identities"]
    Config --> Verify
    Review --> Verify
    Gate --> Verify
    Schema["Pinned local upstream schema and validation profile"] --> Assemble["Assemble and validate canonical bytes"]
    Verify --> Assemble
    Assemble --> Vex["openvex.json: nonempty affected statements only"]
    Assemble --> Companion["Protected companion: evidence, limits and accounting"]
    Vex --> Result["openvex-result.json: hashes, counts and outcome"]
    Companion --> Result
    Result --> Accept["Recheck pins and bytes; runner accepts handoff"]
    Accept --> Report["Final report: verified local references"]
```

Validation pins eight local resources: six schemas, the upstream license and its lock.
The loader uses the source schema directory when present, otherwise installed wheel resources;
an existing corrupt/incomplete source copy fails rather than falling back to another copy.
It never retrieves a schema or the JSON-LD context during export.
Installed-resource fallback supports offline schema validation and pure projection, not a
self-contained installed application. Job execution still requires the configured application
checkout and guidance resources, including `pipeline/guidance/registry.json`; schema-resource
availability does not establish full installed-job execution.
Schema validation alone is insufficient: nonblank action, a real product identity,
timestamp/IRI rules, exact membership and source/configuration bindings also require semantic
validation. Hash binding protects byte integrity; it is not a signature or verification of
the issuer's authority.

Mutable gate/review/intake `latest.json` pointers and the exact `data/indices/accepted.json`
pointer are bounded and rechecked during input admission, but are **not durable exported
evidence bindings**. Immutable accepted handoffs, manifests, index shards and other input
bytes remain bound. A valid newer upstream pointer therefore makes an old export stale
for current reporting, without corrupting its historical immutable evidence.

## Configure before creating a run

The checked-in job is **disabled by default**. Automatic dispatch omits it,
and manual dispatch while disabled is refused; unlike the optional PoC job, there is no
manual disabled-job exception. Enable it only in the configuration used to create the run,
with the publication gate and inference review also enabled.

The following settings example is valid for the typed loader. Replace the settings in
the existing central job table; the checked-in job/step/task topology remains required.
Replace the illustrative issuer, action and repository identity with reviewed values that
accurately apply to the entire export. This example does not authorize real issuance.

```toml
[jobs.job_openvex_export.settings]
enabled = true
author_kind = "organization"
author = "Example Security Team"
role = "" # Optional; no supplier role is inferred.
action_statement = "Do not deploy the reviewed snapshot until the confirmed findings have been remediated and validated."
repository_iri = "https://example.invalid/reviewed-system"
max_packages = 10000
max_bindings = 30000
max_artifact_bytes = 67108864
max_total_input_bytes = 536870912
max_document_bytes = 33554432
max_manifest_bytes = 134217728
max_action_bytes = 8192
max_identifier_bytes = 2048
timeout_seconds = 120
```

The disabled defaults use `enabled = false`, `author_kind = "organization"` and empty
`author`, `role`, `action_statement` and `repository_iri`. The numeric values above are the
checked-in defaults and hard maxima; positive lower bounds are permitted. They are UTF-8 byte
limits where named as bytes, not character counts. Individual input size cannot exceed total
input size. JSON depth is bounded to 32, and result JSON has a fixed 1 MiB limit.
Unique references/aggregate input bytes are measured rather than silently truncated.
The job enforces its attempt deadline at unit boundaries, with monotonic checks during
bounded reads and processing. Exceeding a bound or timeout fails the attempt.

| Input | Operator responsibility |
| --- | --- |
| `author_kind`, `author` | Identify an `individual` or `organization` that authorizes issuance. A tool/model/bot is not the author. Selection does not verify real-world authority or imply supplier endorsement. |
| `role` | Optional nonblank role when supplied; empty means omitted from OpenVEX. |
| `action_statement` | Supply exact, nonblank plain text accurate for **every** exported finding. No model-generated fallback, per-finding override or post-run approval intake exists. |
| `repository_iri` | Supply the reviewed system's stable absolute ASCII `https:` or `urn:` identity, not a local path, branch, credential-bearing URL or release range. Query/fragment and branch/commit URL forms are rejected. It must agree when accepted acquisition provenance establishes a repository IRI. |

Unknown settings, invalid nonempty values, bool-as-integer bounds, unsafe controls,
detected credentials and unresolved template markers are errors even when disabled.
Required issuer/action/repository values are checked when enabled even if no findings
will be exported. Text is preserved exactly, not silently redacted or rewritten.
Ordinary LF/tab formatting in action text is allowed; executable markup is not.
Secret detection cannot replace operator review. Exporter implementation identity is declared
centrally as `review_policy.releases.job_openvex_export` (checked-in value
`openvex-export-1`), not inferred from installed files or model output.

If no accurate common action can be authorized for all publishable findings, leave this v1
export disabled for that run. It is not a per-finding consent or partial-export workflow.
The full resolved configuration is immutable under the run's `data/configuration/`.
Changing issuer, action or repository policy requires a **new run**; do not edit an existing
run's frozen configuration or expect a pre-feature run to gain the settings.

## Product, vulnerability and time identity

Every statement uses the same reviewed-source product, scoped to the accepted snapshot and
the **full resolved configuration**, not just the inference-review settings:

```text
urn:appsec-review:source-snapshot:<H(repository_iri)>:<target_snapshot>:<resolved_config_sha256>
```

`H` is SHA-256 over canonical JSON bytes. This is not a shipped binary hash, release,
version range or assertion about all builds of the repository. No dependency purls,
SBOM-to-release guesses, product hashes or subcomponents are emitted in v1. When acquisition
provenance is absent, the operator-declared repository identity and accepted snapshot remain
explicit; the exporter does not invent a Git commit. Acquisition without a single repository
IRI retains an explicit operator-asserted qualification. A mismatch between an acquired tree
and reviewed tree is recorded, never promoted to an assertion that the acquired revision is
the reviewed snapshot. A build-index presence is not proof of build success.

Vulnerability names and IDs are internal `urn:appsec-review:vulnerability:...` identities,
derived from the repository, snapshot and claim. A CWE is not a vulnerability ID, and a CVE
is not inferred. Statement/document IDs are content-addressed. Serialization uses
`version = 1`, a fixed source-scope qualification, canonical UTF-8 JSON with a trailing LF,
and statement order by finding-package ID.

The document and statement timestamp comes from the accepted gate handoff's `completed_at`,
normalized to UTC, not the export wall clock or an exploit-execution time. Identical accepted
pins, settings, schema and exporter release produce identical OpenVEX bytes. Changed content
gets a new document ID rather than changed bytes under an old ID. Companion run-relative
paths may differ after new upstream attempts even when OpenVEX semantic bytes do not.

## Operation and outputs

In the normal graph, enabled export and optional compile-only PoC generation are
independent siblings after the gate. The final report waits for every enabled sibling.
When both are disabled, the report depends directly on the gate. The direct CLI runs the
enabled optional jobs sequentially; Dagster may schedule siblings independently.

```mermaid
flowchart LR
    Review["Inference review"] --> Gate["Final publication gate"]
    Gate --> Export["OpenVEX export if enabled"]
    Gate --> PoC["PoC generation if enabled"]
    Export --> Report["Final report: single terminal"]
    PoC --> Report
    Gate -. "Direct dependency when neither optional job is enabled" .-> Report
```

Export does not wait for, inspect live output from, or require PoC generation. The report
continues to consume its separate accepted PoC handoff. PoC `compile_verified` means
compilation only, not exploitation; `compile_failed` does not refute an affected finding.
See [PoC operation](poc-generation.md).

Use standalone dispatch **only for a run whose original frozen configuration enabled export**
and whose required upstream jobs already have accepted handoffs:

```text
appsec-review run job_openvex_export --run-id <id> --upstream-from-run
appsec-review run job_final_report_publication --run-id <id> --upstream-from-run
```

The unit topology is
`load.verify_inputs -> export.assemble -> acceptance.publish_handoff`.
Outputs belong under
`runs/<run-id>/data/jobs/job_openvex_export/attempts/<attempt>/steps/...`.
Use the accepted job handoff's references, not a guessed attempt path or newest-looking file.

| Artifact | Meaning |
| --- | --- |
| `verified-inputs.json` | Bounded, verified input identities from the load unit. |
| `schemas/` under the load task | Eight hash-pinned schema/license/lock snapshots, including transitive final-report definitions, retained with the accepted output. |
| `openvex.json` | Nonempty upstream-compatible document with `affected` statements; absent when no statements qualify. |
| `openvex-manifest.json` | Protected companion: provenance, source qualification, per-package inclusion/exclusion, statement-to-evidence mapping, separate scores/independence/ship-block context, limitations, bindings and exact counts. |
| `openvex-result.json` | Accepted handoff's artifact: outcome, gate identity, manifest reference, document reference or null, counts and gaps. |

Every gate package must appear once in the companion as `included`,
`gate_verification_backlog` or `gate_withheld`. Counts and actual identity sets must agree:
`gate_total = included + excluded`, `included = gate_publishable = statement_count`, and
`excluded = backlog_exclusions + withheld_exclusions`. Each statement maps to one included
package. Zero is explicit, never a stand-in for an unreadable input.

| Accepted outcome | Document and runtime meaning |
| --- | --- |
| `exported` | Nonempty validated document, no gate gap limitations; `SUCCEEDED`. Not-run limitations remain recorded. |
| `exported_with_gaps` | Nonempty validated document retains gate gaps; `COMPLETED_WITH_GAPS`. |
| `no_statements` | No publishable confirmed packages; null document reference and no document file, companion retained, named non-clean gap; `COMPLETED_WITH_GAPS`. |

The empty-result gap is `openvex_no_publishable_confirmed_findings`.
An empty `statements` array is invalid OpenVEX and is not written. Invalid settings,
corrupt/missing evidence, stale input, schema/semantic failure, unsafe paths, bound
exceedance and timeout fail the whole attempt with no new accepted handoff, rather than
producing `no_statements`. Acceptance rechecks pointers and bytes to catch concurrent changes.

## Report states and recovery

The [final-report block](final-report.md#openvex-export-projection) distinguishes
export state from vulnerability status:

```mermaid
flowchart TD
    Enabled{"Enabled in frozen config?"}
    Enabled -->|No| Disabled["disabled: no link or new export gap"]
    Enabled -->|Yes| Accepted{"Accepted export exists?"}
    Accepted -->|No| Missing["not_run: explicit limitation, no link"]
    Accepted -->|Yes| Valid{"Integrity valid?"}
    Valid -->|No| Error["Fail report: no corrupt fallback"]
    Valid -->|Yes| Current{"Current gate, review, config and release?"}
    Current -->|No| Stale["stale: rerun export, no document link"]
    Current -->|Yes| Reprove["Re-prove current upstream authority and pointer stability"]
    Reprove -->|Invalid or changed| Error
    Reprove -->|Valid and unchanged| Nonempty{"Nonempty export?"}
    Nonempty -->|Yes| Available["available: verified local document and companion refs"]
    Nonempty -->|No| Empty["no_statements: companion only, not a clean verdict"]
```

Normal enabled-export failure blocks a refreshed report in either orchestrator. A standalone
report run dispatched early can describe `not_run` or `stale`; neither is an accepted export
outcome. Corruption is an integrity failure, not a missing/stale success. Existing immutable
accepted output is usable only if all current identities and bytes still match, never as the
claimed output of a failed attempt. Historical verification rehashes
immutable inputs and every runtime-declared output artifact, checks release/identities and
validates exact canonical reassembly. Before showing references, the report also re-proves
current upstream authority and checks that acceptance did not change.

The report's `handoff`, `result`, `manifest` and `document` references are nullable
`{path, sha256}` objects, not public URLs; its statement/included/excluded counts are nullable
too. `disabled`, `not_run` and `stale` expose no output references or accepted counts.
`no_statements` retains handoff/result/companion references and exact counts, but no document.
Missing, empty and stale states add publication gaps without changing the original claims,
gate counts or ship-block decisions.

For stale output, rerun export against current accepted upstream handoffs, then rerun the
report. For settings changes, create a new run instead. For integrity/bound failures, inspect
the protected failure receipts and repair the actual upstream problem; do not edit receipts,
drop packages, lower assertions or use old files to make the job appear successful.

## Privacy, telemetry and validation limits

Both document and companion can disclose vulnerabilities. The exporter classifies their
datasets as protected, sensitive, internal run-owned artifacts with metadata-only query
exposure. Private run-root permissions/ACLs remain required. Enabling local export is **not**
permission to upload, attach to GitHub, publish a release or distribute files externally.
No signing, external publication endpoint or automatic outbound transfer is added.

The companion is not the small OpenVEX document: it retains internal evidence/policy
references, but no source snippets, secrets, prompts, model output or PoC code. Preserve its
hash-bound relationship when inspecting the document; do not flatten evidence, scores or
limitations into unsupported OpenVEX properties.

[Metrics](metrics.md#openvex-metrics) distinguish fresh attempts, accepted
statements/bytes, empty results, failures, reuse and unavailable observations. Runtime timing
belongs in telemetry, not deterministic export artifacts. A completion event or a file on disk
does not prove acceptance; the runner's accepted handoff is authoritative. The ordinary runtime
metrics snapshot precedes `HANDOFF_ACCEPTED`; the report tail's later snapshot or
`appsec-review metrics --run-id <id>` refreshes accepted semantic counts. A successful export
can therefore be awaiting reconciliation in its initial summary, not an accepted zero.

Focused offline unit files cover settings/contracts, input custody, projection/validation,
handler deadlines, report consumers, topology/wiring and metrics. This documentation pass
does not establish an integration, acceptance, live Dagster or full-suite result. Those manual
checks remain unverified until separately recorded; unit success alone cannot establish them.
