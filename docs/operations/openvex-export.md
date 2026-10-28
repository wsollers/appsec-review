# OpenVEX findings export

**Automatic local export at
`74d931273a383f2f33bac90d3569a070a0ef612d`**, on landed main `83e67b23`.
The user-selected architecture remains standalone post-gate export with gate-only reporting.
Generation and verification now run by default with no setup; explicit disable is opt-out.
Strict contracts/settings, shared certified-gate
reader, exporter input verifier/projector and topology reflect gate `/2`, review `/3`.
Exact focused verification and policy-change landing remain separately tracked;
this guide does not claim real accepted whole-chain, integration, acceptance, Linux or live
Dagster validation. See the [design](../architecture/openvex-export.md) and
[verification record](../reviews/openvex-export-implementation.md).

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

The pinned OpenVEX specification requires an individual/organization author; the automatic
local policy instead truthfully names the tool, without inventing human/vendor authority.
Schema validation does not establish that author requirement or authorize supplier issuance.
See the [specification qualification](../architecture/openvex-export.md#3-verified-upstream-specification-and-validation-pin).

## Trust and data flow

The exporter contract reads accepted, hash-bound run artifacts, not the current target checkout
or advice in target-owned guidance. It re-verifies the gate against the accepted review,
including package accounting, evidence and both package manifests; resolves accepted scope;
and binds the full frozen configuration separately from the semantic review-settings hash.

```mermaid
flowchart TD
    Defaults["Automatic tool author/action defaults; optional strict overrides"] --> Config["Frozen pre-run configuration"]
    Review["Accepted review /3, ledger, packages and evidence"] --> Gate["Certified gate /2"]
    Completion["Pre-gate PoC, chains, remediation and dossier context"] --> Gate
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
    Accept --> OperatorView["Protected export status and metrics only"]
```

The gate's `capabilities` and `attachments` are authoritative context; every nested reference
must already belong to its certified bindings, not merely appear in the exporter's inventory.
PoC/chain/dossier availability is not an eligibility filter, but corrupt certified context
is an integrity failure. Preserve `gap`, `not_run` and `notice` limitations distinctly:
`compile_only_nonexecution` is a notice, not an export gap or proof of a fixed finding.

The strict resource contract pins **nine** local resources: seven schemas, the upstream
license and its lock. Transitive `final-report.schema.json` supplies PoC-item definitions
referenced by gate `/2`; it is not permission to load final-report data or discover attachments.
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
for current export status/latest-accepted metrics, without corrupting its historical immutable
evidence or discarding independently reverified historical semantic work.

## Defaults and optional pre-run overrides

The checked-in configuration **and typed settings enable export by default**. Nothing must be
entered to generate and verify protected local files after the certified gate. The default author
is truthfully the tool, not a human, supplier or external publisher. Empty `repository_iri` is
intentional automatic mode, not a missing-input error.

The following is the shipped settings table, not a setup requirement or a placeholder template.
The checked-in job/step/task topology remains required. Override values only in configuration
used to create a **new run**; local generation does not authorize external distribution.

```toml
[jobs.job_openvex_export.settings]
enabled = true
author_kind = "tool"
author = "AppSec Review"
role = "Automated local application-security review"
action_statement = "Review and remediate the confirmed findings using the accompanying evidence; validate any fix before relying on it."
repository_iri = ""
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

Set `enabled = false` before run creation to opt out. Automatic dispatch omits explicitly disabled
export, and manual dispatch is refused; unlike PoC, there is no disabled-job manual exception.
Historical frozen disabled runs remain disabled: no retroactive rebind or edit is permitted.
Enabled export still requires the publication gate and inference review enabled.

The numeric values above are checked-in defaults and hard maxima; positive lower bounds
are permitted. They are UTF-8 byte
limits where named as bytes, not character counts. Individual input size cannot exceed total
input size. JSON depth is bounded to 32, and result JSON has a fixed 1 MiB limit.
Unique references/aggregate input bytes are measured rather than silently truncated.
The job enforces its attempt deadline at unit boundaries, with monotonic checks during
bounded reads and processing. Exceeding a bound or timeout fails the attempt.

| Input | Default and optional override |
| --- | --- |
| `author_kind`, `author` | Default `tool` / `AppSec Review` identifies automation. Explicit `individual`/`organization` values assert that author, but tool names are forbidden when falsely declared as either kind. Naming alone proves neither authority nor supplier endorsement. |
| `role` | Default `Automated local application-security review`; optional, with empty meaning omitted from OpenVEX. |
| `action_statement` | Default conservative instruction to review/remediate using evidence and validate fixes. Optional exact nonblank plain text applies to **every** exported finding; no model fallback, per-finding override or post-run approval intake exists. |
| `repository_iri` | Empty resolves to `urn:appsec-review:source:<accepted_source_snapshot_sha256>` with `source_snapshot` basis. Optional absolute ASCII `https:`/`urn:` system IRI must be safe, not a local path/branch/credential/release range; when accepted acquisition supplies a repository IRI it must match. |

Unknown settings, invalid nonempty values, bool-as-integer bounds, unsafe controls,
detected credentials and unresolved template markers are errors even when disabled.
Nonblank author/action are checked when enabled even if no findings will be exported;
empty repository remains valid automatic mode. Text is preserved exactly, not silently redacted or rewritten.
Ordinary LF/tab formatting in action text is allowed; executable markup is not.
Secret detection cannot replace operator review. Exporter implementation identity is declared
centrally as `review_policy.releases.job_openvex_export` (checked-in value
`openvex-export-2`), not inferred from installed files or model output.

The default action requests review and validation; it claims neither that a fix exists nor
that remediation succeeded. Explicit advice/author overrides remain the operator's responsibility.
This is not a per-finding consent or partial-export workflow.
The full resolved configuration is immutable under the run's `data/configuration/`.
Changing author, action or repository policy requires a **new run**; do not edit an existing
run's frozen configuration or expect a pre-feature run to gain the settings.

## Product, vulnerability and time identity

Every statement uses the same reviewed-source product, scoped to the accepted snapshot and
the **full resolved configuration**, not just the inference-review settings:

```text
urn:appsec-review:source-snapshot:<H(repository_iri)>:<target_snapshot>:<resolved_config_sha256>
```

`repository_iri` here is the **resolved** identity, not an empty configuration string.
In default automatic mode it is `urn:appsec-review:source:<accepted_source_snapshot_sha256>`;
`repository_identity_basis = source_snapshot` enforces exact namespace/snapshot equality.
Accepted acquisition is authenticated and bound if present, but never supplies a guessed
external repository, publisher or release URL in automatic mode.

`H` is SHA-256 over canonical JSON bytes. This is not a shipped binary hash, release,
version range or assertion about all builds of the repository. No dependency purls,
SBOM-to-release guesses, product hashes or subcomponents are emitted in v1. An explicit
operator IRI instead records `operator_declared` or `accepted_acquisition` basis, with strict
agreement when acquisition establishes an external IRI; neither mode invents a Git commit.
A mismatch between an acquired tree
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

Enabled PoC generation, remediation planning/validation and dossier publication run **before
one final gate**. Chains are part of review before its seal. The gate then feeds independent
report and OpenVEX-export peers. Report source, schema and `CONSUMES` stay gate-only;
export neither attaches itself to the report nor adds a report prerequisite.

```mermaid
flowchart LR
    Review["Review /3: chains before seal"] --> PoC["Enabled PoC"]
    PoC --> Plan["Enabled remediation planning"]
    Plan --> Validate["Enabled remediation validation"]
    Validate --> Dossiers["Enabled dossiers"]
    Dossiers --> Gate["Single certified gate /2"]
    Review --> Gate
    Gate --> Report["Gate-only final report /2"]
    Gate --> Export["Automatic local OpenVEX unless opted out"]
```

The diagram compresses the pre-gate completion dependencies; disabled jobs are transparent
according to frozen configuration. Export reads the gate's certified context, not live optional
producer output. PoC `compile_verified` means compilation only, not exploitation;
`compile_failed` does not refute an affected finding. See [PoC operation](poc-generation.md)
and [completion publication](final-report.md). The direct CLI dispatches export before report
sequentially; Dagster exposes independent gate-dependent peers. A failed sequential export can
stop the driver before report dispatch, but is not a report-input dependency.

Normal generation/validation is automatic. Use standalone redispatch **only for a run whose
original frozen configuration enabled export** (the new-run default)
and whose required upstream jobs already have accepted handoffs:

```text
appsec-review run job_openvex_export --run-id <id> --upstream-from-run
```

There is no required report rerun after export. A standalone report uses the accepted gate
snapshot only and cannot discover or admit newer producer output. Create/re-certify the gate
through the completion workflow when those upstream outputs change.

The unit topology is
`load.verify_inputs -> export.assemble -> acceptance.publish_handoff`.
Outputs belong under
`runs/<run-id>/data/jobs/job_openvex_export/attempts/<attempt>/steps/...`.
Use the accepted job handoff's references, not a guessed attempt path or newest-looking file.

| Artifact | Meaning |
| --- | --- |
| `verified-inputs.json` | Bounded, verified input identities from the load unit. |
| `schemas/` under the load task | Nine hash-pinned schema/license/lock snapshots, including transitive PoC-item definitions; no report data input. |
| `openvex.json` | Nonempty upstream-schema-valid document with `affected` statements; absent when no statements qualify. Tool-authored local output is not authenticated supplier issuance. |
| `openvex-manifest.json` | Protected companion: provenance, source qualification, exact certified capabilities/attachments, per-package inclusion/exclusion, statement-to-evidence mapping, separate scores/independence/ship-block context, limitations, bindings and exact counts. |
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
Only `kind = gap` limitations make a nonempty export `exported_with_gaps`; policy-not-run
and compile-only notices stay visible without becoming gaps.
An empty `statements` array is invalid OpenVEX and is not written. Invalid settings,
corrupt/missing evidence, stale input, schema/semantic failure, unsafe paths, bound
exceedance and timeout fail the whole attempt with no new accepted handoff, rather than
producing `no_statements`. Acceptance rechecks pointers and bytes to catch concurrent changes.

## Export status and recovery

The protected status-reader/metrics interface distinguishes export state from vulnerability
status. Despite the retained Python names `ExportReportView`/`ExportReportState`, these are
**operator export views, not final-report fields**. A failure is an attempt outcome with no
new acceptance, not `no_statements` or a fabricated successful status.

```mermaid
flowchart TD
    Enabled{"Enabled in frozen config? Default: yes"}
    Enabled -->|No| Disabled["disabled: no link or new export gap"]
    Enabled -->|Yes| Accepted{"Accepted export exists?"}
    Accepted -->|No| Missing["not_run: explicit limitation, no link"]
    Accepted -->|Yes| Valid{"Integrity valid?"}
    Valid -->|No| Error["Export-reader integrity failure: no corrupt fallback"]
    Valid -->|Yes| Current{"Current gate, review, config and release?"}
    Current -->|No| Stale["stale: rerun export, no document link"]
    Current -->|Yes| Reprove["Re-prove current upstream authority and pointer stability"]
    Reprove -->|Invalid or changed| Error
    Reprove -->|Valid and unchanged| Nonempty{"Nonempty export?"}
    Nonempty -->|Yes| Available["available: protected document and companion refs"]
    Nonempty -->|No| Empty["no_statements: companion only, not a clean verdict"]
```

The final report does not inspect this state, link export files or gain publication gaps from
disabled/missing/empty/stale export. It consumes only certified gate `/2`.
Corruption is an export-reader integrity failure, not a missing/stale success. Existing immutable
accepted output is current only if all present authority pins and bytes still match, never as
the claimed output of a failed attempt. Historical verification rehashes
immutable inputs and every runtime-declared output artifact, checks release/identities and
validates exact canonical reassembly. The common runtime envelope is `job-handoff/2`, separate
from the certified gate `/2` and review `/3` payloads. Its sized artifacts, attempt claim/result,
task receipts and outcome accounting are verified through the shared runtime authority;
legacy `/1` or incomplete envelopes are rejected rather than adapted. Historical export
verification uses immutable accounting, not an optional producer's latest pointer. Before
exposing current output, the operator reader re-proves
current upstream authority and checks that acceptance did not change.

The operator view's `handoff`, `result`, `manifest` and `document` references are nullable
`{path, sha256}` objects, not public URLs; its statement/included/excluded counts are nullable
too. `disabled`, `not_run` and `stale` expose no output references or accepted counts.
`no_statements` retains handoff/result/companion references and exact counts, but no document.
Missing, empty and stale states remain explicit non-clean export observations without changing
claims, gate counts, ship-block decisions or report publication status.

For stale output, rerun export against current certified upstream handoffs; no report rerun is
required by export. For settings changes, create a new run instead. For integrity/bound failures, inspect
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
metrics snapshot precedes `HANDOFF_ACCEPTED`; a later job snapshot or
`appsec-review metrics --run-id <id>` refreshes accepted semantic counts. A successful export
can therefore be awaiting reconciliation in its initial summary, not an accepted zero.

Latest state/`latest_accepted` requires current authority through `load_export`; cumulative
semantic counters independently reverify historical accepted bundles through
`read_accepted_export`, deduplicated by accepted handoff digest. A newer gate/review pointer
can stale latest without invalidating historical work. Tampered/unreadable historical bytes
preserve known execution counts but make their semantic contribution unknown with a named gap.

Focused offline unit files cover settings/contracts, input custody, projection/validation,
handler deadlines, export consumers, topology/wiring and metrics. The certified `/2` reader,
verifier and projector are implemented at this base; exact combined focused results and final
source proof belong in the [verification record](../reviews/openvex-export-implementation.md).
The coordinator's isolated installed-only wheel proof at `212f21a8` verifies all nine resource
pins, the transitive report-item definition, canonical assembly and semantic validation using
synthetic gate `/2` context, not a real accepted run. That historical proof predates the
automatic-source/common-schema repin; current wheel/source proof is recorded separately,
not inferred from it. It does not establish a self-contained
application or full installed-job execution. Real accepted whole-chain, integration, acceptance,
Linux, live Dagster and full-suite validation remain unclaimed; unit/pure-boundary success
alone cannot establish them.
