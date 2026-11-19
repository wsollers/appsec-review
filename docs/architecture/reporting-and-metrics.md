---
title: "Reporting and metrics"
kind: "architecture"
subsystem: "reporting and metrics"
status: "current"
jobs: ["job_dossier_publication", "job_final_publication_gate", "job_final_report_publication", "job_inference_security_review", "job_openvex_export", "job_poc_generation", "job_remediation_planning", "job_remediation_validation"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Reporting and metrics

## As built today

This view includes T-150's protected decision-audit readers and the bounded dossier/report repairs
in T-5086–T-5088. The gate remains `/2`; report `/3` and radar `/2` distinguish unknown metrics
from measured zero. Finding decisions are unchanged; traceability is not a new finding state or
quality label.

### Certification precedes presentation

The reporting chain consumes accepted evidence, not newly discovered target files.
[Accepted-review verification](../../src/appsec_review/jobs/accepted_review.py) rechecks review
handoff, ledger/projection, package manifests, findings, scores, coverage and referenced artifacts.
The [final gate](../../src/appsec_review/jobs/job_final_publication_gate/job.py) additionally
certifies commissioned PoC, chain, remediation and dossier attachments and frozen configuration.
Missing required admission or corrupt bindings block publication; they are not success-shaped
coverage gaps.

The [classifier](../../src/appsec_review/jobs/job_final_publication_gate/classify.py) preserves
adjudication and shipment decisions. It partitions packages exactly once into publishable
confirmed findings, supported verification backlog or withheld packages whose referenced outcome
class is unavailable. `gap`, `not_run` and `notice` limitations remain distinct. A gate that allows
publication with limitations is not a clean-target or ship-approval verdict.

The [terminal report](../../src/appsec_review/jobs/job_final_report_publication/report.py) projects
only that certified gate into JSON, deterministic Markdown/HTML, and the configured executive
PDF. SARIF is assembled inside the existing report task, not a new pipeline stage. Before
acceptance, the producer revalidates gate bindings and reassembles the report and SARIF, checking
their exact bytes and the Markdown/HTML renderings. It does not discover post-gate attachments
or mutate findings.
See [input admission](job-input-contracts.md#admission-and-read-receipts) and
[interchange outcomes](job-interchange.md#the-control-layer-beneath-the-envelope) for the shared
authority and gap mechanisms.

The executive release banner follows the gate's ship-block decisions, not severity totals or
chain membership. Chain ratings come from the certified chain manifest; absent ratings remain
`unrated` with `chain_severity_unrated`. Remediation proposals remain `proposal_only`, and
`static_checked` does not imply syntax, build or runtime verification. Dossier confirmation
does not imply reachability.

The protected `findings.sarif` contains only publishable confirmed findings with explicit
severity and certified dossier source locations. Missing or invalid severity/location produces
a `producer-gap/1` omission in `sarif-export-result.json`, not a default severity or `unknown:1`
location. Missing reachability stays `unknown`; bare numbers do not become CWE identifiers.
Backlog and withheld packages are not promoted through export.

SARIF rules partition by established domain/taxonomy and technical severity, including when a
caller supplies a rule ID. Mixed-severity results cannot inherit whichever finding sorts first.
Unmapped predicates/CWEs remain explicitly `unclassified`, without an invented OWASP category.

The job selects the confirmed-finding dossier, not a PoC dossier for the same finding. Current
accepted dossier inputs provide no ordered source-to-sink path: the job records
`sarif_codeflow_omitted` rather than converting excerpt/citation order or a legacy synthesized
timeline into `codeFlows`. The lower exporter still supports explicitly supplied ordered paths;
that capability does not establish their admission into a gate-certified dossier.

Qualified remediation comes from the dossier's exact-edit projection and its gate-bound
validation and patch artifacts, not `remediation_guide` prose or an advertised diff.
`static_checked`/`build_checked` proposals require matching passed applicability, policy and
static checks, analyst-supported semantic review, and (for `build_checked`) the passed build
check. Neither status establishes runtime correctness or a resolved finding. Fixes retain
those check statuses, validation/patch references, baseline hashes and new-file absence proofs.
Their replacement regions use the producer's UTF-8 byte offsets/lengths, without invented line
numbers. The protected projected edits must match the bound original patch exactly: redacted,
normalized or truncated patches are omitted, never applied as modified text or replaced with
private original text. Unavailable, unqualified, unbound or unsupported fix projections have
explicit `sarif_fix_omitted` records in the export accounting; changed bound bytes fail integrity
validation. No source excerpts, PoC source or raw diagnostic narratives are copied into SARIF.

### Protected payloads and public summaries stay separate

[Dossier publication](../../src/appsec_review/jobs/job_dossier_publication/job.py) produces
protected developer projections for confirmed findings and separately for every accepted PoC
outcome, including failed/unavailable outcomes. It reads only cited accepted source identities
through bounded retrieval, attaches matching engineering/chain context and records omissions.
Bounded JSON and escaped LaTeX survive ordinary PDF-render failure; a successful PDF requires
real output bytes and a hash-bound rendering receipt. Pin, template or input-integrity failure is
not a successful degraded rendering.

PoC source, source-derived engineering diagnostics, model receipts and dossier content remain
protected. The public final report contains certified references and summaries, not generated
exploit source, prompts or raw evidence dumps. Hash binding is byte integrity, not a new reader
grant or an assertion of issuer authority. Image-backed rendering follows
[host/image pins](../operations/image-pin-verification.md#the-gate) and
[signing policy](../operations/signing.md#container-images).

The deterministic [OpenVEX projector](../../src/appsec_review/jobs/job_openvex_export/projection.py)
exports one `affected` statement per gate-publishable confirmed package. Backlog and withheld
packages remain exclusions in its protected companion. Zero eligible packages produce no OpenVEX
document and an explicit no-statements outcome. It derives no `fixed` or `not_affected` status
from absence, remediation or failed PoCs. Tool authorship is not vendor attestation; the existing
[specification qualification](openvex-export.md#3-verified-upstream-specification-and-validation-pin)
remains relevant.

The existing OpenVEX job can additionally publish a protected dependency companion from an
optional admitted `job_dependency_intelligence/sca_reachability` input matched to the gate's
configuration and target snapshot. Static symbol hits with call-site evidence can project
`affected`; unknown or absent paths remain `under_investigation`. This producer has no complete
executable-path coverage certificate, so it never emits dependency `not_affected`. Its separate
receipt binds the gate and dependency inputs and preserves coverage gaps; the primary finding
export and its eligibility/accounting remain unchanged.

All these consumers retain compile-only assurance. `compile_verified` PoCs were not linked or
run; `build_checked` remediation is a bounded before/after syntax check, not a runtime fix.
Supported findings do not become confirmed through a rendered dossier, export, score or patch.

### Three measurement domains answer different questions

| Domain | Source and calculation | What it cannot establish |
| --- | --- | --- |
| Execution/process metrics | Pipeline events, measured spans, model/tool usage and accepted receipts | Finding correctness, complete target coverage or runtime proof |
| Accepted publication counts | Verified gate/review/export identities and exact candidate/package partitions | That an attempted, reused or omitted item was independently successful |
| Finding/quality metrics | Accepted finding snapshots plus optional independent labels, prior runs and corpus results | Truth from model self-agreement, dismissal, absence or unavailable labels |

[Run telemetry](../../src/appsec_review/observability/telemetry.py) writes a derivable
`run-metrics/7` summary beside the authoritative pipeline event stream. It validates events,
deduplicates invocation lifecycle records, reports conflicts, and distinguishes wall time from
summed concurrent work. Inclusive resource spans are not summed into a fictitious run total.
Unknown token/cost measurements remain unavailable rather than zero. Completion metrics count
event-scoped attempted work: retries are work, not additional accepted findings.

The [completion aggregator](../../src/appsec_review/observability/completion.py) retains finite
status/capability counters and measurement gaps without interpreting them as security evidence.
OpenVEX metrics distinguish invocation attempts from the verified current accepted export;
historical immutable exports can remain valid artifacts while being stale for current status.
Operational definitions and diagnostics belong in the [metrics guide](../operations/metrics.md).

[Triage reduction](../../src/appsec_review/observability/triage_reduction.py) is limited to
admitted lane-A scanner leads. It reconciles survived, dismissed, no-claim and unresolved
outcomes against accepted package/lane/projection artifacts. Unadmitted leads are reported
unreviewed and excluded from reduction ratios; unresolved leads do not count as reduced.
Dismissed and no-claim are not independently labelled false positives. Ratios retain their
denominators; unavailable inputs produce null counts and integrity-gap reasons.

### Finding snapshots are an operator domain

The [run adapter](../../src/appsec_review/observability/findings/run_adapter.py) loads the accepted
final report and its bound projection/evidence into a separate `finding-snapshot/1`.
Unlocated findings are counted as gaps rather than assigned guessed identities. The adapter
preserves publishable/backlog/withheld membership, unknown severity, source locations and
certified remediation presence. Static/compile validation never sets runtime remediation success.

[Coverage derivation](../../src/appsec_review/observability/findings/coverage_adapter.py) joins
accepted source, packages, units and terminal cell records. An operation-only package does not
mark its whole file reviewed. Hunt scanner backing is a location-overlap measurement, not causal
proof of scanner independence; without observations it is unknown.

The [scorecard](../../src/appsec_review/observability/findings/scorecard.py) is built on request,
not injected into the run telemetry lifecycle. Independent answer keys, developer outcomes,
audit labels, prior runs and repeated-run series are optional inputs. Missing families are
unavailable with reasons and appear in the blind-spot list. Reduction needs retention context;
precision, recall/yield and stability are distinct quantities. Evaluator labels are not fed back
to review workers or used to change their accepted findings.

[Revision-independent fingerprints](../../src/appsec_review/observability/findings/identity.py)
support exact and relocated matching with an explicit strength of identity basis. A path-only
finding cannot support relocation matching. [Lifecycle classification](../../src/appsec_review/observability/findings/lifecycle.py)
does not treat disappearance as a fix: it distinguishes not covered, not redetected and
fix candidate. The [re-check module](../../src/appsec_review/observability/findings/recheck.py)
builds/validates bounded requests but has only an injected transport, not a wired live verifier.
Its `fixed` admission requires a citation to changed reviewed content; it is not evidence that
such a real re-check has occurred.

One attribution limit is explicit in the current adapter: the field `verifier_overturned` projects
the judge verdict's disagreement with claim state. It is not a measured verifier error rate.
Unknown owner/attacker-position and other unsupported actionability fields are not inferred.
The [original finding-metrics decisions](finding-metrics.md#12-implementation-decisions)
and named T ids below retain these qualifications.

[Quality-trend comparison](../../src/appsec_review/observability/quality.py) requires a comparable
corpus, role, variant, case count and scorer, while recording implementation/configuration/
prompt/model changes as independent variables. Unknown identities prevent confident attribution.
Scripted protocol competence and case-resolution precision are labelled separately from live
provider efficacy and findings precision.

### Rendering a diagnostic view is not accepting a review

The [reporting CLI](../../src/appsec_review/reporting/__main__.py) can render existing report,
ledger, package and recording material as HTML/LaTeX into an explicit output directory, including
a bounded code-graph quality coverage box rendered by
[`reporting/graph_quality.py`](../../src/appsec_review/reporting/graph_quality.py) when
`job_code_graph_index` published a valid `graph-quality-scorecard.json`
([schema](../schemas/graph-quality-scorecard.schema.json), [T-5016](../TODO.md)).
[Its reader](../../src/appsec_review/reporting/sources.py) records missing/unreadable artifacts
as presentation gaps and can select matching attempt files rather than an accepted snapshot.
Treat diagnostic renderings of model recordings as private, not as the sanitized public report.
That tolerant diagnostic view is not the final gate's fail-closed certification or the
[accepted protected audit](triage-verifier-enhancement.md#product-routes).

The gate opts into full audit/source verification but exports only sanitized availability,
partial-population limitations and certified bindings. Disabled and legacy-unrecorded audits
remain explicit. Available payloads are fully verified before projection; bounded presentation
does not permit partial verification. Dossiers retain the accepted decision basis and distinguish
support, opposition, qualification and noncounted citations. Audit inclusion does not promote
counterevidence or judge dissent into support.

The separate [telemetry renderer](../../src/appsec_review/reporting/telemetry_render.py) writes
a receipted operational report. Its [input loader](../../src/appsec_review/reporting/telemetry/inputs.py)
can recompute a missing/incompatible summary in memory without rewriting it, and names torn-log
or unavailable-input gaps. The [end-of-run finalizer](../../src/appsec_review/reporting/telemetry_finalize.py)
is best-effort: a renderer exception warns without changing the existing run completion status.
None of these presentation paths establishes new finding, coverage or runtime-proof authority.

## Decisions

- **2026-10-28 — Evidence completion:** the
  [original reconciliation record](../reviews/evidence-completion-documentation-inventory.md#rollout-decisions-and-implementation-boundary)
  preserves compile-only PoCs, confirmed-only remediation, protected dossiers and one pre-report
  certification gate. Historical fixture/sample passes remain distinct from current live validation.
- **2026-10-28 — OpenVEX qualification:** the
  [upstream specification and pin record](openvex-export.md#3-verified-upstream-specification-and-validation-pin)
  separates schema validation from issuer authority and limits this projection's assertions.
- **2026-11-11 — Offline finding metrics:** the
  [implementation decisions](finding-metrics.md#12-implementation-decisions) place finding metrics
  in an on-request operator document, retain triage-reduction semantics and prohibit treating
  disappearance as a fixed finding.
- **2026-11-13 — Evidence-derived actionability:** the
  [behavior-oriented decisions](../tasks/2026-11-13-behavior-oriented-review.md#numbered-implementation-decisions)
  derive path/remediation facts from counted evidence and exact certified attachments, not missing
  fields or generated prose.
- **2026-11-13 — Attribution and stage loss:** the
  [triage/verifier review](../reviews/2026-11-13-triage-verifier-review.md#3-strengths-and-source-backed-gaps)
  records the incomplete decision trail and misleading judge/verifier attribution boundary.
  T-150's bounded protected trace is now implemented; later labelled evaluation and execution-bound
  coverage proposals remain separate.

## Named gaps

The [TODO registry](../TODO.md) owns scope, completion criteria and status; this table only locates
the limits relevant to interpreting reports.

| T id | Interpretation boundary |
| --- | --- |
| T-061, T-067, T-074 | Real fix-verification efficacy, fix-pair corpus/holdout and live re-check wiring. |
| T-071 | Remaining model-specific integrity measurements and honest attribution of verifier/judge outcomes. |
| T-076, T-077 | Complete developer-actionability fields and stage-attributed lead records. |
| T-154, T-156 | Labelled stage-loss audit and execution-bound coverage receipts. |

The [operator decision-audit CLI](../operations/finding-metrics.md) uses the implemented accepted
reader and fixed templates; it is not a worker/MCP grant. Audit records preserve original policy
attribution, not independent truth labels or proof that every investigation was complete.
The implemented metric families recorded as done under T-062, T-064, T-065, T-066, T-068 and
T-069 are not reopened here; missing operator inputs make a measurement unavailable, not its
implementation absent.

## Jobs and pages

| Boundary | Current job or operator pages |
| --- | --- |
| Accepted claims and engineering inputs | [Inference review](../operations/job_inference_security_review.md), [PoC generation](../operations/job_poc_generation.md), [remediation planning](../operations/job_remediation_planning.md), [remediation validation](../operations/job_remediation_validation.md) |
| Protected developer publication | [Dossier publication](../operations/job_dossier_publication.md) |
| Certification and final presentation | [Final gate](../operations/job_final_publication_gate.md), [final report](../operations/job_final_report_publication.md) |
| Affected-only machine-readable export | [OpenVEX export](../operations/job_openvex_export.md) |
| Operational measurements | [Metrics](../operations/metrics.md), [finding metrics](../operations/finding-metrics.md), [manual guidance evaluation](../operations/guidance-evaluation.md) |

Exact contracts, failure branches and acceptance checks stay on the job pages.
[Review inference and guidance](review-inference-and-guidance.md) owns the model/evidence decision
boundary; this subsystem observes and projects it rather than widening it.

### Executive report, 12-axis radar and evidence-grounded dossiers

- **12-axis Security Posture Radar (`appsec-review/security-radar-tracker/2`)**: Projects
  `surface_exposure`, `verified_coverage`, `corroborated_leads` and `confirmed_high_critical`.
  Exposure, inspection and corroboration require explicit measurements; accepted packages and
  lane-B cells cannot substitute for them. The current gate supplies no per-domain measurements,
  so those fields and undefined derived metrics remain `null` with reasons, displayed as **N/A**.
  Measured zero remains numeric. Markdown, HTML and LaTeX use the same report radar; SVG/TikZ
  geometry omits unknown vertices rather than joining or filling through them.
  See [coverage and metric qualifications](../operations/final-report.md#domain-coverage-and-unknown-measurements-t-5088).
- **Executive Report (`appsec-review/final-report/4`) & Finding Dossiers (`appsec-review/dossier/1`)**:
  `job_final_report_publication` renders an executive risk narrative, exploitability funnel,
  multi-step attack-chain summaries, top remediation choke-points, OWASP/CWE posture matrix, and
  named coverage gaps. Active chains use certified `component_claim_ids` and count each publishable
  member once. Backlog and withheld packages remain separate and cannot certify a domain clean.
  `job_dossier_publication` uses one common document across Markdown/HTML/LaTeX, preserving
  counterevidence, qualifications, risk and provenance. Ordered paths, guard conclusions and
  scanner corroboration stay unrecorded when absent from accepted projections. Actual exact-edit
  patches retain their bound artifact, original byte ranges and redacted old/new text; they are
  not applicable unified diffs. The overall accepted validation outcome governs the headline,
  never a single passing check. Compile-only PoCs remain explicitly unexecuted.
- **SARIF 2.1.0 & dependency OpenVEX**: Exports use the certified evidence described above,
  not dossier-invented paths or fixes. The optional dependency companion reads
  `appsec-review/sca-reachability/1` from the admitted dependency handoff's
  `acceptance.publish_handoff` output. Supported static symbol-use observations with call sites
  become `affected`; incomplete/unknown reachability becomes `under_investigation`. It has no
  complete executable-path certificate and cannot publish dependency `not_affected`.
  [Dependency intelligence](../operations/dependency-intelligence.md#pinned-osv-and-source-reachability)
  documents exact package/version bindings and the conservative Python-only positive symbol-use
  boundary; imports and native FFI context alone are not vulnerable-symbol calls.

Historical report `/2` and radar `/1` remain unchanged and use their declared validators. Legacy
estimates are labelled as such, never retrospectively certified as measurements.

## Dataflow

```mermaid
flowchart TD
  review["job_inference_security_review: accepted findings + attack chains"] --> engineering["job_poc_generation (compile-only) / job_remediation_planning / job_remediation_validation"]
  review --> dossiers["job_dossier_publication: appsec-review/dossier/1"]
  engineering --> dossiers
  review --> gate["job_final_publication_gate"]
  engineering --> gate
  dossiers --> gate
  gate --> report["job_final_report_publication: appsec-review/final-report/4 + SARIF 2.1.0"]
  report --> radar["appsec-review/security-radar-tracker/2: 12 axes; unknown metrics remain N/A"]
  gate --> vex["job_openvex_export: affected findings; optional dependency companion"]
  dependencies["Admitted job_dependency_intelligence: static SCA symbol-use evidence"] --> vex
  report --> snapshot["finding-snapshot/1"]
  snapshot --> scorecard["finding-metrics/1"]
  independent["Independent labels / prior snapshots / corpus results"] --> scorecard
  scorecard --> trends["Quality and stability comparisons"]
  events["Pipeline events and retained receipts"] --> metrics["run-metrics/7"]
  review --> triage["Admitted lane-A triage reduction"]
  triage --> metrics
  vex --> metrics
  metrics --> telemetry["Receipted telemetry report"]
  diagnostic["Existing ledger / packages / recordings"] --> view["On-demand diagnostic HTML / LaTeX"]
  gate -. "missing required input / corrupt binding" .-> reject["Reject certification"]
  independent -. "not supplied" .-> unknown["Unavailable metric, not zero"]
  unknown --> scorecard
  telemetry -. "render failure" .-> warning["Warning; existing run status unchanged"]
```

The metric and diagnostic paths have no return edge into review decisions or worker grants.
Protected payloads remain behind their existing access boundaries; arrows do not authorize a new
consumer. No chart or export changes compile-only assurance into runtime proof.
