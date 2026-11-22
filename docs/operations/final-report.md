---
title: "Operating the final publication gate and the final report"
kind: "operations"
subsystem: "reporting and metrics"
status: "current"
jobs: ["job_final_publication_gate", "job_final_report_publication", "job_inference_security_review", "job_poc_generation"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Operating the final publication gate and the final report

**Delivered completion ordering (`c44eddc1`, integrated by `dd9c9ad`):** PoC, remediation
and dossiers precede one final gate. The current gate `/2` and report `/4` contracts certify and consume one snapshot;
the shared reader accepts review `/3`, including nested chain/package bindings.
The [completion design](../architecture/evidence-completion-and-remediation.md) requires
one gate-certified snapshot after every enabled producer, including protected
[dossiers](dossier-publication.md). Its exact inputs, visibility and unresolved integration
surfaces are cataloged in the [dossier inventory](../architecture/dossier-data-inventory.md).
New defaults do not rewrite old frozen configurations. The owner-verified
[seeded dossier PDF sample](dossier-publication.md#verified-seeded-sample) is separate from the
historical `039b24e4` all-lane check with offline model/compiler/renderer boundary doubles.
The [acceptance ledger](../reviews/evidence-completion-documentation-inventory.md#acceptance-ledger)
records that bounded pass, focused consumer compatibility and remaining manual/current-main validation; neither result
is a full-repository clean verdict or live reproduction.

`job_final_publication_gate` and `job_final_report_publication` are the terminal publication jobs of
`wave1_review`. They turn the accepted `job_inference_security_review` handoff into the pipeline's
final, human-readable report. Neither calls a model, neither reads the target, and neither
reinterprets anything: a claim state and a `ship-block-policy/1` status are projected exactly as the
review accepted them (design: [`../architecture/inference-security-review.md`](../architecture/inference-security-review.md),
"Placement and consumers").

```text
review (chains before seal) -> enabled PoC / planning / validation / dossiers
                           -> one final gate -> final report
```

The report closes the completion publication path. The default-on standalone OpenVEX exporter
automatically generates/verifies protected local files as an independent post-gate peer,
not a report dependency or completion barrier. Explicit opt-out leaves it disabled;
historical frozen disabled runs do not change.
Gate and report are shipped enabled. Disabling the gate also makes the report transparent
(there is no certified input); enabled pre-gate completion producers remain, rather than
moving after the gate or disappearing. Enabled export requires gate and review enabled.
Disabling only report publication leaves the gate's certified snapshot available to other
consumers, including separately enabled export.

### Final-report export integrity

The existing `report.assemble` task writes `findings.sarif` and `sarif-export-result.json`
alongside `final-report.json`; there is no separate SARIF job. The accepted handoff binds
both SARIF artifacts and the existing `final-report.html`. Publication reassembles the
gate-derived JSON/SARIF and checks the Markdown and HTML renderings before accepting them.

SARIF source locations come only from gate-certified dossiers, never a target scan or the
run-owned finding-package filename. Records missing a usable severity or location are omitted
with explicit export gaps while valid siblings remain. Inspect `sarif-export-result.json`
for missing records and required-data gaps even when the gate permits publication. Optional
codeflow/fix limitations are separate: `findings.sarif` retains them under
`runs[0].properties.optional_capability_limitations`, keyed by finding and capability with
the explicit omission reason. Missing ordered traces, unavailable/unqualified exact fixes
and deliberately redacted/truncated patch projections do not by themselves lower completion.
Missing validation/patch certification, ambiguous validation records, unsupported required patch formats and missing whole
finding records still do; tampered bound artifacts still fail integrity validation.
These are export-completeness semantics, not independent verification, runtime validation
or a clean-target verdict. The gate's real review/coverage gaps remain status-affecting.
Reachability is not inferred from a
confirmed adjudication; chain severity is copied from the certified manifest, with missing
ratings explicitly `unrated`. JSON and Markdown retain the accepted ship-block decisions;
the technical executive report does not make release recommendations. High severity alone
does not impose a new release policy. Proposed patches and static checks
are not labelled verified fixes.

## The gate

The central configuration must define this exact topology:

```text
load.verify_review -> gate.classify -> acceptance.publish_handoff
```

**`load.verify_review`** reads the accepted inference review handoff through the application's
accepted-handoff pointer and re-verifies, from bytes, everything it binds. Any disagreement is an
`IntegrityError` that fails the unit, so no gate handoff is accepted:

- the review handoff validates against `inference-review-handoff/3` and its run/manifest identity matches
  the accepted scope;
- every ledger shard re-hashes, keeps its row count and merges deterministically to the handoff's
  ledger head; the published `claim-ledger.jsonl` and `projection.json` are byte-identical to what the
  shards produce; the projection hash and the gap identifiers match the handoff;
- the lead and hunt package manifests verify (including every package's bytes), and each
  content hash matches its separate handoff field;
- every finding package and score package re-hashes, validates against `finding-package/2` and
  `score-package/3`, belongs to a claim in the ledger in the same state, and carries the handoff's
  manifest, ledger head and ship-block policy hashes;
- `remediation_intake` and `verification_backlog` partition the finding packages exactly (confirmed
  versus supported, same hashes, claims, lanes and ship-block statuses) and the handoff's ship-block
  counts equal a recount of the packages;
- the coverage matrix re-hashes and keeps its row count; chain membership, manifest/ledger/actor
  receipts, duplicate identities and canonical PoC-basis digests agree;
- accepted enabled optional producers have exact review/finding/plan/upstream identities, closed
  status/accounting, nonexecution assurance and every nested artifact hash. Disabled unadmitted
  producer pointers are not discovered as input.

`job_final_publication_gate/attachments.py` verifies PoC candidate/omission partitions and provenance/
compile receipts; exactly confirmed remediation intake and validation-to-plan/patch binding; exact
dossier membership/caps/files/render receipts; and chain candidate/frontier/component accounting.
Before sealing, `reverify_snapshot` rehashes all bindings and rechecks the accepted review and
admitted producer pointers, rejecting a concurrent replacement. Frozen `resolved.json` is also
bound. Integrity failure produces no accepted snapshot; ordinary absent/failed/capped enhancement
work within an accepted producer can remain a named capability gap without re-adjudicating the
base finding. Missing enabled producer envelopes are rejected by the current typed input contract
before this capability classification; they are not accepted as success-shaped absent sections.

**`gate.classify`** places every finding package in exactly one bucket and names the limitations.

| Bucket | Packages |
| --- | --- |
| `publishable` | The handoff placed the package in `remediation_intake` (`confirmed`). |
| `verification_backlog` | The handoff placed it in `verification_backlog` (`supported`, labelled unconfirmed). |
| `withheld` | The immutable finding asserts an unavailable PoC/chain reference (`poc_outcome_unavailable`, `attack_chain_unavailable`). A withheld package keeps its accepted ship-block status and remains listed. A merely absent optional enhancement does not itself withhold an otherwise valid finding. |

`package_counts` always satisfies `total = publishable + verification_backlog + withheld` with
`exact = true`; a package that is in no bucket or in two is an integrity failure. Withholding never
changes a claim state or a ship-block status.

**`acceptance.publish_handoff`** validates and publishes `final-publication-gate.json`
(`final-publication-gate/2`, handoff `/2`, schema in [`../schemas/final-report/`](../schemas/final-report/)): the
verified review identity, the input references, the accounting and ship-block summaries copied from
the handoff, one projected record per package (title, state, ship-block decision, independence,
evidence relation ids, missing predicates, gap ids, and each score package's four separate
dimensions), the buckets, the limitations, the accepted gap ids, and `bindings`, the hash of every
artifact the gate read. `capabilities` records `poc_generation`, `attack_chains`,
`remediation_planning`, `remediation_validation`, `dossiers`; each has effective `enabled`,
`disposition`, bounded reason, handoff/summary refs, item/omitted/gap counts and nonexecution
assurance. `attachments` holds closed sanitized status/reference projections, not protected payloads.

| Capability disposition | Meaning |
| --- | --- |
| `SKIPPED_POLICY` | Disabled by frozen configuration and not explicitly admitted; discovered output is ignored. |
| `SKIPPED_NA` | Accepted producer exactly accounted for an empty eligible scope without gaps. Not clean target coverage. |
| `GAP` | Enabled expected work is absent/failed/capped or has recorded gaps. |
| `SUCCEEDED` | Accepted outcomes and nested bindings verified; no runtime proof or verified fix is implied. |

Chain work is an unconditional bounded review stage, with its manifest bound inside the review
rather than a separately discovered job. Capability status is not a finding state.

### Limitations

T-150 adds sanitized decision-audit availability, incomplete-population and scope limitations.
The gate verifies the protected audit and retains certified read hashes; the report still reads
only the gate snapshot. It does not publish raw audit narratives or change finding, score,
ship-block or PoC decisions. See [the canonical gate](job_final_publication_gate.md#gaps) for
the exact limitation IDs; these limitations retain their gate `/2` representation in report `/4`.

Each limitation is a `limitation_id`, a `kind` and a statement. `gap` limitations make the gate
status `PUBLISHABLE_WITH_LIMITATIONS` and the job `COMPLETED_WITH_GAPS`; `not_run` limitations name a
disabled-by-policy capability and never change either. `compile_only_nonexecution` is a notice.

| `limitation_id` | Kind | When |
| --- | --- | --- |
| `review_degraded` | gap | The review status is `DEGRADED`. |
| `review_empty` | gap | The review status is `EMPTY`; an empty result is not a clean verdict. |
| `review_incomplete` | gap | The review's gap ratio exceeded `lanes.incomplete_gap_ratio`; no consumer may present the review as complete. |
| `lane_degraded` | gap | A lane's outcome is `DEGRADED`, `FAILED` or `CANCELED`. |
| `gaps_recorded` | gap | The claim ledger holds any gap, with counts by class. |
| `coverage_incomplete` | gap | Any lane B coverage cell is not `reviewed` (`gap`, `not_launched`). |
| `pending_distinct_verification` | gap | A finding is `ship_blocking_pending_distinct_verification`; the handoff's verifier warning is repeated. |
| `technical_severity_unrated` | gap | A package has no `application_risk_matrix/3` rating (`technical_severity_unrated`). |
| `decision_pending` | gap | A package has ship-block status `decision_pending`: its severity is unrated because scoring factors are missing. The gate verifies and projects the status verbatim and recounts it in the handoff totals. |
| `findings_without_scores` | gap | A package has no score package. |
| `withheld_packages` | gap | The `withheld` bucket is not empty. |
| `possible_duplicates` | gap | The handoff nominates possible-duplicate claim pairs, which are not merged. |
| `remediation_planning_not_run`, `remediation_validation_not_run`, `attack_chain_composition_not_run`, `poc_lane_not_run`, `dossiers_not_run` | not_run | Corresponding capability is `SKIPPED_POLICY`; not unconditional absence text. |
| `poc_generation_gap`, `attack_chains_gap`, `remediation_planning_gap`, `remediation_validation_gap`, `dossiers_gap` | gap | Corresponding capability is `GAP`, with omitted/gap counts. |
| `compile_only_nonexecution` | notice | PoC, negative controls and remediation regressions were not executed. Build checks do not resolve findings. |

The old `unavailable_inputs` field is replaced by actual capability/attachment accounting.
Missing optional work can make publication limited without hiding a valid base finding.

## The report

```text
load.accepted_gate -> report.assemble -> report.render -----> acceptance.publish_handoff
                                      \-> report.render_pdf -/
```

`load.accepted_gate` reads only the accepted gate handoff, validates the gate document against
`final-publication-gate/2`, authenticates an explicitly supplied upstream gate digest, checks package
accounting/run identity, and re-hashes every certified binding. Every input/capability/attachment
reference must belong to that binding set. A changed, escaped, missing or uncertified reference
fails the job. No optional producer's latest pointer is read during report assembly.

`report.assemble` writes `final-report.json` (`final-report/4`, handoff `/2`, schema
[`../schemas/final-report/final-report-v4.schema.json`](../schemas/final-report/final-report-v4.schema.json)):

- `findings`: the publishable (confirmed) packages, each with its ship-block decision, independence,
  evidence relation ids, gap ids and every score package's four dimensions (technical severity,
  exploitability confidence, environmental and business impact, remediation priority), reported
  separately and never combined. A dimension the provider did not produce is `null`, which is a
  gap and not a low value. Each score also carries its `severity_assessment` (`complete`, `bounded`
  or `unrated`, with the severity floor and ceiling), and each ship-block record carries
  `technical_severity_floor`, `technical_severity_ceiling` and `missing_factors`;
- findings whose ship-block status is `decision_pending` (no technical severity yet because factors
  are missing) are never hidden. A confirmed one is listed under findings and a supported one under
  the verification backlog, each with the line "decision pending: severity not yet rated; what is
  missing: ..." and, when bounded, the severity range the missing factors leave open. The summary
  counts them, and the `decision_pending` limitation records that they are neither ship-blocking nor
  cleared;
- `attack_chains`: certified `confirmed` / `qualified_supported` chain summaries and refs;
  other terminal outcomes remain in the protected manifest and capability accounting;
- `poc_outcomes`: certified compile-only statuses, function names and protected file refs;
- `remediation_planning`, `remediation_validation`, `dossiers`: certified statuses/bindings/refs,
  never patches, source or PDF bytes; `capabilities` preserves exact disposition/counts;
- `verification_backlog`: the supported packages, labelled `not_independently_confirmed`;
- `withheld`: withheld packages with their reasons;
- `limitations`, `gap_ids`, `status` (including `review_complete`, true only for a `COMPLETE`
  review that is not `review_incomplete` and has no `gap` limitation), `provenance` and `notices`.

### Domain coverage and unknown measurements (T-5088)

The report's `security-radar-tracker/2` keeps exposure, inspected scope, accepted claims,
publishable findings and chain membership distinct. Package counts and the gate's lane-B
coverage-cell summary are **not** domain exposure or inspection telemetry. The current gate
supplies no such domain telemetry: report assembly leaves exposure/inspection and derived
coverage percentages `null`, with `surface_exposure_unknown` / `inspected_units_unknown`
gap reasons. It does not retrieve another producer to fill those fields.
Each axis also records separate publishable, verification-backlog and withheld `package_counts`.
These counts do not measure corroborated scanner leads either. Without an explicit corroboration
measurement, `series.corroborated_leads` has null count/score/unit and the metric-local
`gap_reasons: ["corroborated_leads_unknown"]`. Explicit measured zero stays zero. This optional
metric qualification does not change `coverage_status`, inspected-scope percentages or coverage
confidence: those depend on their own measurements and unresolved work, not corroboration telemetry.

The bounded dimension calculator can use explicitly supplied exposure and inspection counts.
Measured zero stays `0`; a zero exposed denominator leaves the percentage `null` with
`no_domain_coverage_bound`, not a clean verdict. A positive fully inspected population with no
findings may be `verified_no_findings`. Withheld packages and unconfirmed verification backlog
always retain their own gap reasons even with 100% inspected scope; inspection is not adjudication.
Missing inspection never earns partial credit from a supported claim. Aggregate confidence is
`null` with `domain_coverage_unknown` whenever an axis lacks a defined coverage percentage.

Active chain membership uses the certified `component_claim_ids` of `confirmed` and
`qualified_supported` chains. Each publishable finding contributes once, even across several
chains or when already high/critical; neither backlog nor withheld packages inflate those counts.
Standalone severity and ship-block status are unchanged.

The labels `chain_elevated_findings_count` and `chain_elevated_count` count participating
publishable findings, not a demonstrated increase over standalone severity. The chain card's
`trust_boundary_crossed` display text combines component security-domain IDs (or
`application_trust_boundary` as a fallback); it is not a resolved trust-zone identity or proof
of a breached boundary. The composed rating still comes only from the certified manifest.

JSON and event telemetry preserve nulls and their reasons, keeping metric reasons separate from
coverage reasons. Funnel rates with an unavailable corroboration numerator/denominator are also
null with a reason; an empty measured denominator is separately `denominator_empty`.
Markdown, HTML and executive PDF
source display **N/A**, not zero; charts omit unknown vertices and never close or fill a polygon
through them. The formats use the same report radar rather than recomputing it from format-specific
dossiers. Known counts remain numeric.

Historical `final-report/2`, `final-report/3` and radar `/1` schemas are retained unchanged. Readers select the
validator from the document's declared version and reject unsupported versions; they never rewrite
accepted bytes. Legacy charts retain recorded estimates with an explicit legacy-estimate notice,
not a retrospective assertion that exposure or inspection was measured.

### Advisory reachability and admitted chain capacity (T-5139, T-5140)

The current gate does not certify an advisory reachability measurement. Report `/4` therefore
publishes `executive_posture.reachable_supply_chain_advisories_count: null` with
`reachable_supply_chain_gap_reasons: ["certified_reachability_unavailable"]`; all three text
formats show **N/A** and explain the missing measurement. Neither confirmed finding state,
package counts, title keywords nor imported modules prove advisory reachability. No additional
producer is read, and positive reachability counting is **not implemented** by this change.
Renderers preserve recorded numeric values (including zero) in historical reports rather than
recalculating them under the new semantics.

Report `/4` retains every admitted active chain and every unrated-chain qualification. Its
attachment array reuses the gate's bound of 10,000 chains; the card array permits the same
population. The named-gap capacity is 10,076: at most 64 admitted gate limitations, 12 radar-axis
rows and one severity-gap row per admitted chain. No chains or gaps are silently sliced to fit
the former report bounds, and a missing composed severity remains unrated.

`report.render` renders `final-report.md` from that JSON and certified dossier-format references
with a pure function: the same inputs and display bounds give byte-identical Markdown, with no clock, locale or
environment input (`final-report-markdown/2`). Text that came from review artifacts is shown in code spans or escaped, so it
cannot become Markdown or HTML structure.

The same unit renders executive HTML from the report plus the exact gate-bound dossier JSON.
HTML and executive LaTeX use one bounded narrative projection; source excerpts, generated code,
patch text and raw protected payloads remain in the developer dossier. Certified composed chain
severity comes from `attack_chain_cards` in every format, never the maximum member severity.
Only historical reports without cards use the legacy fallback, which leaves missing composed
severity unrated. An explicitly empty card list remains empty.

The public dossier file map stays `json`, `latex`, `pdf`, `receipt`. Markdown/HTML file listings
come only from the private rendering receipt `/2` referenced by that map and verified against
the gate's existing binding set. JSON retains the receipt as the indirect machine-readable route.
Legacy `/1` receipts explicitly lack certification for these formats; no adjacent files are
discovered or retrospectively certified. An unloaded receipt is labelled unknown. A protected
format reference exposes only its path/hash, not its raw contents; see
[private format custody](dossier-publication.md#private-format-custody).

`report.render_pdf` renders the executive PDF (next section) from `final-report.json` and the dossier
JSON the gate binds, through the pinned `tool-report-latex` image, and writes `final-report.tex`,
`final-report.pdf` when the renderer produced a valid PDF, the retained renderer logs and a
`final-report-pdf-receipt/1` receipt (schema
[`../schemas/final-report/final-report-pdf-receipt.schema.json`](../schemas/final-report/final-report-pdf-receipt.schema.json)).

`acceptance.publish_handoff` re-validates the JSON, proves `final-report.md` is exactly the rendering
of `final-report.json` and its certified format references, re-renders HTML from the same JSON and certified dossiers,
and re-proves the executive PDF files
(the LaTeX is exactly the rendering of the JSON
plus the gate-bound dossiers, the receipt hashes those bytes, and a rendered PDF is the valid file the
receipt names), and publishes the handoff. The handoff's `artifact` is `final-report.json`, the
`report.render` output's `artifact` is `final-report.md`, and the handoff's `pdf` field carries the
executive PDF's outcome from the receipt (`state` `rendered` with `file` and `sha256`, `render_failed`,
or `not_rendered` by policy, always with a `reason`, the `latex` and the `receipt` references). All are
hash-pinned by the accepted job handoff and are run-owned
(`data/jobs/job_final_report_publication/attempts/<attempt>/steps/...`). The job is
`COMPLETED_WITH_GAPS` whenever a `gap` limitation exists, SARIF records a required export gap or the PDF
unit recorded a named gap. Gate limitations reach publication through SARIF's scoped
`producer-gap/1` records, without a second string copy. PDF-unit records also keep their identity
when forwarded, avoiding a second count in runtime outcomes. Distinct limitation scopes and
ledger identities are preserved; limitation/coverage/axis counters are not a summed gap total.

### Proof-of-concept outcomes

`job_poc_generation` ([operations](poc-generation.md)) runs **before** the gate, enabled by default
in new configurations. The gate verifies summary/candidate/provenance `/2`, all seven statuses,
the exact candidate/omission partition, review/build/basis/finding identities, nested compile
records and nonexecution assurance. The public projection uses a fixed compile-only description,
function names and four protected refs (`source`, `compile`, `readme`, `provenance`), not model
narrative or function text. `execution` is `not_performed_by_policy`, `runtime_verified` false
and `result_id` null.

For a frozen disabled manual PoC, dispatch it explicitly, then certify it with
`appsec-review run job_final_publication_gate --run-id <id> --upstream-from-run --admit-manual-poc`,
then run report publication with `--upstream-from-run`. The flag is gate-only and authenticates
the exact PoC upstream digest without changing frozen settings. A report-only rerun cannot
discover or admit later producer output; stale/mixed optional-producer identities fail the gate.
PoC failure never contradicts the finding, and a compiled PoC cannot upgrade it or alter scores.

### Standalone OpenVEX is not a report input

The user selected standalone post-gate export while preserving gate-only reporting.
Since `74d931273a383f2f33bac90d3569a070a0ef612d`, report dependencies and `CONSUMES` are exactly
`job_final_publication_gate`; the current report `/4` retains no `openvex_export` block, output links or
live optional attachment discovery. This supersedes the earlier OpenVEX report-link/fan-in
proposal, not the pre-gate completion design.

Enabled PoC, planning, validation and dossiers remain before the gate. The gate certifies their
capabilities, sanitized attachments and immutable bindings once. Report publication reads that
snapshot; it neither searches producer latest pointers nor discovers OpenVEX files. Exporter
status (`disabled`, `not_run`, `available`, `no_statements`, `stale`) belongs only to its
protected operator reader/metrics, not report fields or new publication limitations.
An exporter failure is not a report-input integrity failure. A sequential direct run can stop
on a failed export before reaching report dispatch, but that ordering does not add a report
dependency; standalone report publication still requires only its valid certified gate.

The [OpenVEX operator guide](openvex-export.md) covers no-setup tool/action defaults, automatic
accepted-snapshot identity, explicit opt-out/strict overrides, standalone outputs, privacy
and status recovery.
The default-on change adds no external publication/signature or new topology. The certified-gate shared
reader, exporter input verifier and projector are assembled at this source boundary.
The [implementation record](../reviews/openvex-export-implementation.md) tracks combined
focused verification and policy-change landing; no real accepted whole-chain,
integration, acceptance, Linux or live Dagster result is claimed here.

### What the report never contains

The closed JSON finding projection holds identifiers, hashes, accepted titles and summaries, and score dimensions. It carries no
claim statement, worker narrative, rationale, prompt, retrieval query, transcript, exploit code or PoC
source (only its description, status and file references), and no secret or target source. The finding projection is a closed schema, so a new field
needs a schema change.
Executive HTML and LaTeX additionally use the gate-bound dossier narrative fields described below;
this does not add them to JSON or certify invented paths as evidence. Protected SARIF can carry only
the separately qualified exact remediation described in [export integrity](#final-report-export-integrity).

### The executive PDF

`report.render` writes `final-report.html`; `report.render_pdf` writes `final-report.pdf`, executive
reports whose readers are the project's tech lead and business owner. Their common document model is built by
`appsec_review.reporting.executive_report.executive_document` (a pure function of `final-report.json`
and the bound dossier documents). `reporting.executive_latex` renders the executive-only
`technical-report-skeleton.tex` with the common class and the existing `tool-report-latex`
image (`SOURCE_DATE_EPOCH` 0; the `.tex` is byte-identical for the same
inputs). The container rendering, receipt and dossier binding live in
`appsec_review.jobs.job_final_report_publication.pdf`.

It contains, in plain language:

- a compact scope/summary with confirmed, backlog and withheld counts and finding IDs pointing to
  details. Ordinary headings replace the cover, slogans, readiness banner and remediation roadmap.
  No owners, deadlines or release recommendations are invented;
- review coverage by security dimension: pageable tables of the report-owned domain measurements
  and metric reasons used by JSON/Markdown, described in
  [domain coverage](#domain-coverage-and-unknown-measurements-t-5088). Format-specific dossier
  metadata does not reclassify the certified radar. Unknown metrics remain N/A, not measured zero
  or clean coverage;
- one entry per confirmed finding: what the weakness is (the dossier statement and CWE), where it is
  (snapshot/file-bound source spans), accepted mechanism/impact and preconditions, technical severity,
  independence and judge qualifications, remediation invariants, proposed checks and recorded check
  outcomes. Full narratives are not repeated in the summary;
- a per-finding entry-to-function attack-path table and evidence register. The current dossier
  contract supplies predicate citations and source context, **not authenticated ordered calls,
  function symbols, guard dispositions or entry-to-sink edges**. Those entries explicitly say
  “not established in accepted evidence.” Citation order and the legacy timeline never become
  execution order. Counted citations, analyst-assessed/noncounted evidence, assumed prerequisites
  and unknown transitions remain distinct. Conditional CBMC witnesses are not promoted to external
  reachability or exploitability proof;
- CWE IDs only from the accepted mechanism mapping; absent taxonomy names are explicit. The
  current accepted contract carries no verified affected-version/advisory CVE linkage, supported
  CVSS version/vector/provenance, or date-pinned FIRST EPSS input: those panels are **N/A with
  reasons**, not zero. Separately attributed provider scores retain their scale, rating, value,
  source ID/hash and missing factors without being relabelled CVSS/EPSS. No network lookup,
  severity-to-vector inference, local EPSS calculation or synthetic fallback fills a panel;
- attack-chain membership, compile-only outcomes, remediation proposals and remediation validation, each with
  its status and its items. Chain composed severity remains separately attributed; domain transitions
  are not source-resolved boundaries, and component roles do not establish call order.
  A `none_available` section states its reason and that this is a
  limit of the review, never evidence that the target is clean;
- the verification backlog and withheld packages, listed as unconfirmed or withheld, never as findings;
- limitations grouped as gaps, stages not run and notices, the coverage summary, and which dossiers
  were available; and references with the provenance hashes (gate handoff, gate document, review
  handoff, configuration, ledger head, policy) and the dossier and renderer references.

The finding narratives come only from the dossier JSON the gate binds
(`dossiers.items[*].files.json`), read through `bound_artifacts.read_bound_json`, so every byte is proven
against the gate's hash before it is used, and `bind_dossiers` refuses a reference outside the gate's
binding set. Claimed JSON that is missing, changed, malformed, unsupported or names another
run/dossier/kind/finding fails integrity validation before rendering; it is not relabelled as
an ordinary unavailable narrative. If a standalone pure renderer receives certified references
without loaded documents, it retains the certified count and explicitly says
`executive_dossier_not_loaded`. No reference means no certified dossier, not complete coverage.
Neither HTML nor PDF contains exploit code, prompts, payloads, generated functions, exact patch
text or dossier source excerpts (`sources[*].excerpt` is protected developer content): only
approved narrative fields and source paths/line ranges appear.

The executive PDF uses breakable prose and repeated-header `longtable` rows. Oversized table cells
are partitioned into continuation rows without truncation; long finding headings continue as
readable prose. Fonts are fixed at 10 pt body / 9 pt notes and tables, not shrunk to fit.
Upstream dossier truncations retain their original field/count/hash notices. Zero, one and many
findings use the same renderer. The template receipt retains exactly the three consumed files:
`appsec-report.cls`, `appsec-palette.tex`, and `technical-report-skeleton.tex`. Templates are
read-only mounts, so source/template changes need the normal source reload, **not an image rebuild**.
The renderer-family and report/receipt schemas are unchanged; source and template hashes identify
this presentation. Historical report `/2` and `/3` values remain attributed historical values.

Verification wording preserves the distinction between accepted state, R6 independence and
provider/model distinctness. A schema-supported `confirmed` finding with explicit false independence
is described as confirmed **but not independently verified**, not silently reclassified.
An absent flag is unknown. Normal R5 adjudication still requires independence for confirmation;
the conditional renderer fixture is not proof of a normally accepted contradictory ledger.
See [the report's qualification boundary](job_final_report_publication.md#report).

Failure behaviour: `render_pdf = false` writes the LaTeX and a `not_rendered` receipt with the gap
`final_report_pdf_disabled_by_policy`. A renderer failure (non-zero exit, timeout, OOM, oversized or
invalid output) or an unavailable image writes a `render_failed` receipt, keeps `final-report.tex`,
`report.log` and `report.pdfinfo.txt`, and names the gap (`final_report_pdf_render_failed`,
`final_report_pdf_renderer_unavailable`); no PDF is invented. A changed immutable tool pin is an
`IntegrityError`, not a gap. Every gap makes the job `COMPLETED_WITH_GAPS`. `final-report.json` is
assembled before the PDF exists and records `renderers.pdf.state = "not_rendered"` with a reason that
points at the handoff; the handoff's `pdf` field is the authoritative outcome.

A standalone diagnostic PDF and single-page HTML renderer also exists (`python -m appsec_review.reporting`,
`scripts/render-report.sh`; see [`report-rendering.md`](report-rendering.md)). It reads a finished run
and is a tool: this publication job does not call its broad loader. Protected per-finding/PoC PDFs are
independently produced by the pre-gate dossier job and appear here only as certified refs. A failed
dossier render retains JSON/LaTeX/receipt and a named gap, not an empty PDF.

## Configuration

Both jobs have a central `[jobs.<id>]` table and typed, strictly validated settings. They take no
provider, model, reasoning or budget setting because they call no model.

```toml
[jobs.job_final_publication_gate.settings]
enabled = true
max_packages = 10000        # finding packages one gate accounts for (schema bound 10000)

[jobs.job_final_report_publication.settings]
enabled = true
markdown_evidence_ids = 8   # evidence relation ids listed per finding in final-report.md
markdown_gap_ids = 16       # gap ids listed per finding and in total in final-report.md
render_pdf = true           # render the executive final-report.pdf; false keeps the LaTeX and names the gap
image_tag = "appsec-review/tool-report-latex:1.0.0"   # the dossier renderer image; image_id is bound from the host pins
render_timeout_seconds = 600
max_pdf_bytes = 16777216    # bound for the LaTeX, the PDF and each retained renderer log
```

The two Markdown bounds change `final-report.md` only; `final-report.json` always carries every
identifier. The `render_pdf`, `image_*` and byte/timeout settings govern only the executive PDF and are
hashed into its receipt (`settings_sha256`). Neither job has a Dagster pool of its own: both use the
default `application` pool.

## Verification

`tests/test_final_report.py` runs the real inference review with its scripted `Infer` double, then
both jobs, offline. It checks exact bucket accounting, verbatim projection of states and ship-block
statuses, tamper detection (ledger, projection, shard, finding, score, coverage, manifests, handoffs
and the gate document), DEGRADED and `review_incomplete` limitations, deterministic Markdown, schema
validation against `jsonschema` and the closed validator, and that every file the jobs write is
claimed by a dataset declaration. `tests/unit/job_final_report_publication/test_job_units.py` exercises
`report.render_pdf` with a container double (rendered, render failure, disabled by policy, a tampered
or unbound dossier) and the publish re-proof of the LaTeX, receipt and PDF bytes;
`tests/unit/reporting/test_executive_report.py` checks the executive document's plain-language content,
its `none_available` framing, that no excerpt reaches it and that it is deterministic. The real
`tool-report-latex` rendering of `final-report.pdf` is checked only in a review run, not by unit tests.
`tests/test_completion_publication.py` covers optional capability
combinations, disabled/manual admission, exact candidate/finding/plan/dossier/chain bindings,
snapshot-only reporting, tamper rejection and public/protected separation.
The separate owner-reported `039b24e4` native check passes genuine review-emitted candidate flow,
sanitized gate-only report, ignored corrupted optional pointers and deterministic second
JSON/Markdown hashes with offline model/compiler/renderer boundary doubles. Real PDF sample
checks remain separate. These are not live-model/runtime reproduction, full-repository clean
acceptance or authorization for new Dagster/review runs; see the
[acceptance ledger](../reviews/evidence-completion-documentation-inventory.md#acceptance-ledger).

`FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED`, `FINAL_PUBLICATION_GATE_REVIEW_VERIFIED`,
`FINAL_PUBLICATION_GATE_PUBLISHED`, `FINAL_REPORT_ASSEMBLED`, `FINAL_REPORT_PDF_RENDERED` and
`FINAL_REPORT_PUBLISHED` expose
bounded counts/dispositions/admission/duration where emitted. Their
[completion metrics](metrics.md) count attempted work and retries, not accepted evidence.
