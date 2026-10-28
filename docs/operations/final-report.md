# Operating the final publication gate and the final report

**Delivered snapshot contract (`c44eddc1`, integrated by `dd9c9ad`):** PoC, remediation
and dossiers precede one final gate. Gate/report `/2` contracts certify and consume one snapshot;
the shared reader accepts review `/3`, including nested chain/package bindings.
The [completion design](../architecture/evidence-completion-and-remediation.md) requires
one gate-certified snapshot after every enabled producer, including protected
[dossiers](dossier-publication.md). Its exact inputs, visibility and unresolved integration
surfaces are cataloged in the [dossier inventory](../architecture/dossier-data-inventory.md).
New defaults do not rewrite old frozen configurations. The owner-verified
[seeded dossier PDF sample](dossier-publication.md#verified-seeded-sample) is separate from full
native all-lane semantics, which remain pending and are not implied by these source contracts.

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

The report is the one terminal job of the graph. Both jobs are shipped enabled. Setting
`jobs.job_final_publication_gate.settings.enabled = false` also makes the report transparent
(there is nothing for it to read), which leaves the inference review as the terminal job; setting
only `jobs.job_final_report_publication.settings.enabled = false` leaves the gate as the terminal job.

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
- the lead and hunt package manifests verify (including every package's bytes) and the hunt
  manifest's content hash matches the handoff;
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
work remains a named capability gap without re-adjudicating the base finding.

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
load.accepted_gate -> report.assemble -> report.render -> acceptance.publish_handoff
```

`load.accepted_gate` reads only the accepted gate handoff, validates the gate document against
`final-publication-gate/2`, authenticates an explicitly supplied upstream gate digest, checks package
accounting/run identity, and re-hashes every certified binding. Every input/capability/attachment
reference must belong to that binding set. A changed, escaped, missing or uncertified reference
fails the job. No optional producer's latest pointer is read during report assembly.

`report.assemble` writes `final-report.json` (`final-report/2`, handoff `/2`, schema
[`../schemas/final-report/final-report.schema.json`](../schemas/final-report/final-report.schema.json)):

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

`report.render` renders `final-report.md` from that JSON with a pure function: the same
`final-report.json` and display bounds give byte-identical Markdown, with no clock, locale or
environment input (`final-report-markdown/2`). Text that came from review artifacts is shown in code spans or escaped, so it
cannot become Markdown or HTML structure.

`acceptance.publish_handoff` re-validates the JSON, proves `final-report.md` is exactly the rendering
of `final-report.json`, and publishes the handoff. The handoff's `artifact` is `final-report.json`
and the `report.render` output's `artifact` is `final-report.md`; both are hash-pinned by the accepted
job handoff and are run-owned (`data/jobs/job_final_report_publication/attempts/<attempt>/steps/...`).
The job is `COMPLETED_WITH_GAPS` whenever a `gap` limitation exists.

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

### Planned OpenVEX export projection

**Design only; not implemented at baseline `b7c31ba23af840f14cc919d56b8c557ffdb2d010`.**
The [OpenVEX design](../architecture/openvex-export.md) adds an optional model-free
`job_openvex_export` after the accepted gate, as a sibling of optional PoC generation, with
both enabled tails feeding the one final report terminal. The current topology above does
not yet include it. Normal graph execution must stop on enabled-export failure rather
than publish a refreshed report. The [draft operator guide](openvex-export.md) covers
immutable issuer/action setup, source identity, outputs, privacy and flow diagrams.

The planned optional `openvex_export` block is additive to `final-report/1`; historical reports
without it remain valid. It links only accepted, reverified run-local artifacts and never
changes claim state, gate buckets, score dimensions or ship-block decisions.

| Planned report state | Projection |
| --- | --- |
| `disabled` | Frozen setting is false; no file lookup/link and no new export gap. Manual exporter dispatch is refused while disabled. |
| `not_run` | Enabled but no accepted export, for example a standalone report dispatched early; explicit missing-export limitation, no document link. |
| `available` | Current nonempty accepted export; verify handoff, result, companion, document and gate/review/full-configuration/release pins before showing counts, local references and hashes. |
| `no_statements` | Accepted empty export; explicit zero/reasons and companion link, no document link. Not a clean verdict. |
| `stale` | Valid export belongs to another gate/review/configuration/release; explain that export must rerun, without linking the stale document. |

Corrupt output must fail report verification, not masquerade as `not_run` or `stale`.
`exported`, `exported_with_gaps` and `no_statements` are accepted exporter outcomes;
`available` is a report-consumer state, and only `affected` is a vulnerability status.
PoC compilation or its absence/failure is not an exporter prerequisite or vulnerability
reassessment. A previous accepted export is usable only while every current pin and byte
still matches; a failed attempt does not create a new accepted export.

### What the report never contains

It holds identifiers, hashes, accepted titles and summaries, and score dimensions. It carries no
claim statement, worker narrative, rationale, prompt, retrieval query, transcript, exploit code or PoC
source (only its description, status and file references), and no secret or target source. The finding projection is a closed schema, so a new field
needs a schema change.

### PDF

A standalone PDF and single-page HTML renderer now exists (`python -m appsec_review.reporting`,
`scripts/render-report.sh`, the `tool-report-latex` image; see
[`report-rendering.md`](report-rendering.md)). It reads a finished run and is a tool: this publication
job does not call its broad diagnostic loader. The consolidated public report records
`renderers.pdf.state = "not_rendered"`; protected per-finding/PoC PDFs are independently produced
by the pre-gate dossier job and appear here only as certified refs. A failed dossier render retains
JSON/LaTeX/receipt and a named gap, not an empty PDF.

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
```

The two Markdown bounds change `final-report.md` only; `final-report.json` always carries every
identifier. Neither job has a Dagster pool of its own: both use the default `application` pool.

## Verification

`tests/test_final_report.py` runs the real inference review with its scripted `Infer` double, then
both jobs, offline. It checks exact bucket accounting, verbatim projection of states and ship-block
statuses, tamper detection (ledger, projection, shard, finding, score, coverage, manifests, handoffs
and the gate document), DEGRADED and `review_incomplete` limitations, deterministic Markdown, schema
validation against `jsonschema` and the closed validator, and that every file the jobs write is
claimed by a dataset declaration. `tests/test_completion_publication.py` covers optional capability
combinations, disabled/manual admission, exact candidate/finding/plan/dossier/chain bindings,
snapshot-only reporting, tamper rejection and public/protected separation.
Source-defined test coverage and owner-reported passes are not full native all-lane, live-model,
PDF or Dagster acceptance; see the [implementation record](../reviews/evidence-completion-documentation-inventory.md).

`FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED`, `FINAL_PUBLICATION_GATE_REVIEW_VERIFIED`,
`FINAL_PUBLICATION_GATE_PUBLISHED`, `FINAL_REPORT_ASSEMBLED` and `FINAL_REPORT_PUBLISHED` expose
bounded counts/dispositions/admission/duration where emitted. Their
[completion metrics](metrics.md) count attempted work and retries, not accepted evidence.
