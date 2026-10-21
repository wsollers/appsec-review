# Operating the final publication gate and the final report

`job_final_publication_gate` and `job_final_report_publication` are the last two jobs of
`wave1_review`. They turn the accepted `job_inference_security_review` handoff into the pipeline's
final, human-readable report. Neither calls a model, neither reads the target, and neither
reinterprets anything: a claim state and a `ship-block-policy/1` status are projected exactly as the
review accepted them (design: [`../architecture/inference-security-review.md`](../architecture/inference-security-review.md),
"Placement and consumers").

```text
job_inference_security_review -> job_final_publication_gate -> job_final_report_publication
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

- the review handoff validates against `inference-review-handoff/2` and its manifest identity matches
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
- the coverage matrix re-hashes and keeps its row count.

**`gate.classify`** places every finding package in exactly one bucket and names the limitations.

| Bucket | Packages |
| --- | --- |
| `publishable` | The handoff placed the package in `remediation_intake` (`confirmed`). |
| `verification_backlog` | The handoff placed it in `verification_backlog` (`supported`, labelled unconfirmed). |
| `withheld` | The package references a proof-of-trigger result or an attack chain, whose manifests do not exist, so the reference cannot be verified (`poc_outcome_unavailable`, `attack_chain_unavailable`). A withheld package keeps its accepted ship-block status and is still listed in the report. |

`package_counts` always satisfies `total = publishable + verification_backlog + withheld` with
`exact = true`; a package that is in no bucket or in two is an integrity failure. Withholding never
changes a claim state or a ship-block status. Slice 1 produces no PoC result or attack-chain package,
so `withheld` is empty today; the rule is in place for when those lanes exist.

**`acceptance.publish_handoff`** validates and publishes `final-publication-gate.json`
(`final-publication-gate/1`, schema in [`../schemas/final-report/`](../schemas/final-report/)): the
verified review identity, the input references, the accounting and ship-block summaries copied from
the handoff, one projected record per package (title, state, ship-block decision, independence,
evidence relation ids, missing predicates, gap ids, and each score package's four separate
dimensions), the buckets, the limitations, the accepted gap ids, and `bindings`, the hash of every
artifact the gate read.

### Limitations

Each limitation is a `limitation_id`, a `kind` and a statement. `gap` limitations make the gate
status `PUBLISHABLE_WITH_LIMITATIONS` and the job `COMPLETED_WITH_GAPS`; `not_run` limitations name a
pipeline stage that does not exist yet and never change either.

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
| `remediation_planning_not_run` | not_run | `job_remediation_planning` does not exist yet. |
| `remediation_validation_not_run` | not_run | `job_remediation_validation` does not exist yet. |
| `attack_chain_composition_not_run` | not_run | No attack-chain manifest exists (design slice 3). |
| `poc_lane_not_run` | not_run | No proof-of-trigger status manifest exists; the PoC lane is plan-only (decision 3). |

The two manifests the design lists as gate inputs, the attack-chain manifest and the sanitized PoC
status manifest, are recorded under `unavailable_inputs`. When the remediation jobs are built, the
gate gains their handoffs as inputs and the two `*_not_run` limitations are retired.

## The report

```text
load.accepted_gate -> report.assemble -> report.render -> acceptance.publish_handoff
```

`load.accepted_gate` reads only the accepted gate handoff, validates the gate document against
`final-publication-gate/1`, checks its package accounting, and re-hashes every artifact in the gate's
`bindings` (the review handoff, ledger, shards, finding and score packages, coverage matrix). A
changed or missing binding fails the job.

`report.assemble` writes `final-report.json` (`final-report/1`, schema
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
- `attack_chains`: `none_available` with the reason, because no chain package exists yet;
- `poc_outcomes`: `none_available` with the reason unless the run holds an accepted
  `job_poc_generation` handoff built from this gate (see below);
- `verification_backlog`: the supported packages, labelled `not_independently_confirmed`;
- `withheld`: withheld packages with their reasons;
- `limitations`, `gap_ids`, `status` (including `review_complete`, true only for a `COMPLETE`
  review that is not `review_incomplete` and has no `gap` limitation), `provenance` and `notices`.

`report.render` renders `final-report.md` from that JSON with a pure function: the same
`final-report.json` and display bounds give byte-identical Markdown, with no clock, locale or
environment input. Text that came from review artifacts is shown in code spans or escaped, so it
cannot become Markdown or HTML structure.

`acceptance.publish_handoff` re-validates the JSON, proves `final-report.md` is exactly the rendering
of `final-report.json`, and publishes the handoff. The handoff's `artifact` is `final-report.json`
and the `report.render` output's `artifact` is `final-report.md`; both are hash-pinned by the accepted
job handoff and are run-owned (`data/jobs/job_final_report_publication/attempts/<attempt>/steps/...`).
The job is `COMPLETED_WITH_GAPS` whenever a `gap` limitation exists.

### Proof-of-concept outcomes

`job_poc_generation` ([`poc-generation.md`](poc-generation.md)) is an optional job between the gate and the report,
shipped disabled and run by hand. `load.accepted_gate` looks for the run's accepted PoC handoff:

- **none**: `poc_outcomes` is exactly what it was before the job existed (`none_available`, the "no proof-of-trigger
  status manifest" reason, no items), and the report is unchanged;
- **built from this gate handoff**: the summary is validated against `poc-generation/1`, every file it names is re-hashed,
  and `poc_outcomes` becomes `available` (or `none_available` with the reason when the job had nothing to attempt). Each
  item carries `finding_package_id`, `status` (`compile_verified`, `compile_failed`, `artifact_generated`,
  `policy_denied`, `insufficient_evidence`, `not_applicable` or `unsafe_to_attempt`), `result_id` (always `null`: nothing was
  executed), the `claim_id`, a description of at most 300 characters, the two function names and the four file references
  (`source`, `compile`, `readme`, `provenance`), plus the PoC handoff reference in `poc_outcomes.poc_handoff` and
  `provenance.poc_handoff`. The Markdown lists the same fields; the function source and the full reproducer stay in
  `data/poc/<claim-id>/`;
- **built from another gate handoff** (the gate ran again after the PoC job): the block says the PoC handoff is stale and
  shows nothing from it. Run `job_poc_generation` again.

A PoC status never changes a claim state, a ship-block status or a score, and `compile_failed` does not contradict a
finding.

### What the report never contains

It holds identifiers, hashes, accepted titles and summaries, and score dimensions. It carries no
claim statement, worker narrative, rationale, prompt, retrieval query, transcript, exploit code or PoC
source (only its description, status and file references), and no secret or target source. The finding projection is a closed schema, so a new field
needs a schema change.

### PDF

A standalone PDF and single-page HTML renderer now exists (`python -m appsec_review.reporting`,
`scripts/render-report.sh`, the `tool-report-latex` image; see
[`report-rendering.md`](report-rendering.md)). It reads a finished run and is a tool: this publication
job does not call it, and it does not touch it. The recorded reason text below is unchanged. The JSON records `renderers.pdf.state = "not_rendered"` and the Markdown says so.

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
claimed by a dataset declaration. No live model, container, network or Dagster run has exercised these
jobs.
