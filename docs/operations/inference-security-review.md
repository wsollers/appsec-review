# Inference security review operations

Design authority: [`../architecture/inference-security-review.md`](../architecture/inference-security-review.md).
This page covers operator settings for `job_inference_security_review` (Dagster job
`inference_security_review`). All settings live in `appsec-review.toml` under
`[jobs.job_inference_security_review]`. Each run freezes them into
`runs/<run-id>/data/configuration/`.

## Model selection and upgrade

The checked-in models are the `dev` profile. Real reviews select the `prod` profile, which uses more
capable models, larger limits and a distinct `strong` verifier model; see
[`model-profiles.md`](model-profiles.md) (`APPSEC_REVIEW_PROFILE=prod`, or `--profile prod` on the scripts).

Models are configured as named profiles. Each role uses one profile, and a role without an entry
uses `default`:

```toml
[jobs.job_inference_security_review.settings.models.default]
provider = "claude-cli"          # claude-cli | anthropic-api
model = "claude-haiku-5-5"       # development default; upgrade for real reviews
reasoning = "high"
max_input_tokens = 32000
max_output_tokens = 8000
max_queries = 40                 # retrieval requests per cell
max_turns = 12                   # model turns per cell
timeout_seconds = 600            # per-cell deadline

[jobs.job_inference_security_review.settings.roles.independent_verifier]
model_profile = "default"
```

The checked-in default is the current Haiku model, which keeps development and fixture runs cheap.
To upgrade for a real review:

1. Change `model`, and `reasoning` if needed, in the `default` profile. To use a different model
   for some roles, add a profile such as `[...settings.models.review]` and point those roles at it
   with `model_profile = "review"`. A `default` profile is required, and a role that names a
   missing profile is rejected.
2. Revisit `max_input_tokens`, `max_output_tokens` and the job budgets
   (`[...settings.budgets]`), because larger models cost more per turn.
3. Start the run. `job_model_connectivity` confirms that the provider serves every
   configured model, including this job's profiles, before any review work. An unavailable model
   blocks the run.

**What a model change invalidates.** Provider, model and reasoning are inputs to every cell
fingerprint, so a run after a model change executes every review cell fresh and does not reuse
cells from earlier runs. Package assembly and the other upstream jobs are not affected. The run's
resolved-configuration hash also changes.

**Independence.** The blind verifier must be a different actor from the red and blue cells. It does
not need to be a different provider. For ship-blocking findings it should run on a different model
profile (decision 2); see [Configuring a distinct verifier](#configuring-a-distinct-verifier).
Every finding package records `independence.provider_distinct` and
`independence.verifier_model_distinct`, so a run that uses one model for every role is labelled as
such.

### Configuring a distinct verifier

`[...settings.verification].require_distinct_model_for_ship_blocking` (default `true`) requires the
verifier's model profile, meaning its provider and model, to differ from every red cell's on a
claim before that claim can be published as `ship_blocking`. A confirmed finding that would block
but was verified on the red cells' model is published as
`ship_blocking_pending_distinct_verification` instead. Confirmation itself does not change: a
same-model verifier can still confirm a claim.

The checked-in configuration puts every role on the `default` profile (`claude-haiku-5-5`), so a
run with it publishes every ship-blocking finding as pending. The handoff's `verification` record
then carries a `warning`, and the job writes an `INFERENCE_REVIEW_VERIFIER_NOT_DISTINCT` event.
To verify on a second model, add a profile and point the verifier role at it:

```toml
[jobs.job_inference_security_review.settings.models.verifier]
provider = "claude-cli"
model = "<a model other than the red roles' model>"
reasoning = "high"
max_input_tokens = 32000
max_output_tokens = 8000
max_queries = 40
max_turns = 12
timeout_seconds = 600

[jobs.job_inference_security_review.settings.roles.independent_verifier]
workers = 4
model_profile = "verifier"
require_distinct_from_roles = ["hypothesis_hunter", "red_team_analyst", "blue_team_refuter"]
```

The red roles (`hypothesis_hunter`, `red_team_analyst`) keep using `default` unless they have their
own entries. The verifier's model must pass `job_model_connectivity` like any other.
Changing the verifier's profile changes the verifier cells' fingerprints, so those cells run fresh;
red and blue cells are reused. Setting `require_distinct_model_for_ship_blocking = false` publishes
same-model findings as `ship_blocking` and removes the warning. Do that only on purpose: it gives
up the decision 2 safeguard.

## Capacity and local runs

`[...settings.teams].review_teams` (default 5) is the number of review teams, each 3 red, 2 blue
and 1 blind verifier, that may run at once on the host. To run a single team locally without
editing the checked-in file, supply a capacity overlay:

```toml
# local-capacity.toml
[jobs.job_inference_security_review.settings.teams]
review_teams = 1
```

Set `APPSEC_REVIEW_CONFIG_OVERLAY=local-capacity.toml`, or pass `overlay=` to `load_config`. The
overlay may set only `review_teams` and `orchestration.dagster.pools.*`; any other key is rejected.
It is recorded as its own hashed layer in the run's configuration manifest. Capacity is excluded
from cell fingerprints, so runs with different team counts reuse each other's cells and produce
identical canonical outputs.

## Tuning scoring

Scoring is deterministic and runs only on `confirmed` and `supported` claims. The default provider
is `application_risk_matrix/3`. It rates `score-factors/1` factors, each derived from adjudicated,
re-resolved evidence: `verification`, `taint_path`, `attacker_control`, `guard_absent`,
`exposure`, `privilege`, `data_sensitivity`, `impact_class` (from the pinned MITRE catalog; see
"CWE impact classes" below) and `threat` (KEV only). The design section "Evidence-derived scoring
factors" lists every factor's scale and source. A factor with no
evidence is listed in the score package's `missing_factors`, with its reason in
`missing_factor_reasons`. It is unknown, never zero and never a low value.

### Missing factors: the interval

`application_risk_matrix/3` does not guess what a missing factor would have scored. It computes an
exploitability **interval**. The floor gives every missing factor its minimum points, the ceiling
gives it its maximum, and both ends are mapped through the same `bands`. Technical severity is then
looked up for the floor and for the ceiling:

| Floor and ceiling | `severity_assessment.assessment` | `technical_severity` |
|---|---|---|
| Same band, nothing missing among the scored factors | `complete` | that band |
| Same band, some factors missing but none could change it | `bounded` | that band |
| Different bands | `unrated` | `null`, with `severity_floor`, `severity_ceiling` and `unresolved_factors` |
| `impact_class` missing | `unrated` | `null`, no bounds |

Removing evidence therefore never lowers a rating. It can only move a finding from `complete` to
`bounded` to `unrated`.

**What to do about an unrated finding.** An unrated `confirmed` or `supported` finding is published
with ship-block status `decision_pending`, never `not_ship_blocking` (see "Ship-block status"). Read
the score package's `severity_assessment.unresolved_factors` and the reason each has in
`missing_factor_reasons`, then supply the missing evidence: export graph facts for the language so
`taint_path`, `attacker_control` and `guard_absent` reach higher values, supply accepted security
tags so `exposure` is known, or add a `cwe_impact_overrides` entry when `impact_class` is missing.
Rerun the review and the finding is rated. Do not lower `bands` or the points tables to make
findings rate: that hides the missing evidence instead of supplying it. If a factor is never
obtainable for your targets, set its table so every value gives the same points. It then adds no
width to the interval, which is a deliberate, reviewable statement that the factor does not
discriminate.

**Providers that are enabled but not implemented.** `cvss_v4`, `cvss_v31_compat` and
`ssvc_decision` can be listed in `scoring.enabled_providers`, but this build has no
implementation for them. They are not skipped silently: the scoring stage records one `score_gap`
per run for each (subject `provider:<name>`), the scores document lists them under
`unavailable_providers`, and they produce no score. Nothing in the ship-block policy reads them.

The model lives under
`[jobs.job_inference_security_review.settings.scoring.providers.application_risk_matrix]`:

```toml
[...providers.application_risk_matrix]
implementation = "application_risk_matrix/3"     # or "application_risk_matrix/1" (no model tables)

[...providers.application_risk_matrix.exploitability.points]
verification = { supported = 20, confirmed = 40 }
taint_path = { code_evidence = 10, tool_observation = 15, codeql_path_observation = 20, graph_dataflow_path = 25 }
attacker_control = { internal = 0, direct_unclassified = 10, local = 15, remote = 25 }
guard_absent = { code_evidence = 15, tool_observation = 15, graph_fact = 20 }
exposure = { local = 0, internal_network = 5, public = 10 }

[...providers.application_risk_matrix.exploitability.bands]
medium = 40                                      # total >= medium -> medium; >= high -> high
high = 75

[...providers.application_risk_matrix.environmental.points]
exposure = { local = 5, internal_network = 10, public = 30 }
privilege = { sandboxed = 0, elevated = 25 }
data_sensitivity = { sensitive = 20, secret = 30 }

[...providers.application_risk_matrix.environmental.bands]
medium = 25
high = 50

[...providers.application_risk_matrix.technical_severity]   # impact class x exploitability rating
critical = { low = "medium", medium = "high", high = "critical" }
high = { low = "low", medium = "medium", high = "high" }
medium = { low = "low", medium = "low", high = "medium" }
low = { low = "low", medium = "low", high = "low" }
```

How to tune it:

- **Weight a factor differently.** Change its points. A factor table must list every value on the
  factor's scale, and points must be integers in `[0, 1000]` that never decrease from the weakest
  to the strongest value. A dimension you set replaces that dimension's default whole: an
  `exploitability` or `environmental` table needs both `points` and `bands`, and its `points` must
  list every factor you still want. An omitted `exploitability`, `environmental` or
  `technical_severity` table keeps its default.
- **Move the band edges.** Change `bands.medium` and `bands.high`. Both are inclusive thresholds
  on the summed points, and `medium` must be below `high`.
- **Change what a band means.** Edit `technical_severity`. Rows are impact classes and columns are
  exploitability ratings; a band may never fall as either axis rises.
- **Change a CWE's impact.** Impact classes are derived from the run's pinned MITRE CWE catalog
  (below). To make an exception, add it to `[...settings.scoring.cwe_impact_overrides]`. The CWE
  class is one factor among many: it sets the severity row, while exploitability comes from the
  evidence.

`exploitability` may use `verification`, `taint_path`, `attacker_control`, `guard_absent`,
`exposure` and `privilege`. `environmental` may use `exposure`, `privilege` and
`data_sensitivity`. Validation rejects any other factor. `impact_class` sets the matrix row and
never carries points. `threat` (KEV) applies its fixed one-band raise and never carries points.
`epss` is not a factor: EPSS never changes a score and is not recorded in score packages.
Validation rejects a non-monotone model at load time, so stronger evidence can never lower a
rating.

### CWE impact classes

The `impact_class` factor follows `cwe-impact-derivation/1` (decision 11; the design section "CWE
impact class" has the full rule). Precedence is override, then derivation from the run's pinned
MITRE catalog, then a missing factor with its reason. Derivation reads each weakness's catalog
Common_Consequences, maps every technical impact to a class, and takes the highest:

| Catalog technical impact | Class |
|---|---|
| Execute Unauthorized Code or Commands | `critical` |
| Modify Memory, Gain Privileges or Assume Identity, Bypass Protection Mechanism, Modify Application Data, Modify Files or Directories | `high` |
| Read Memory, Read Application Data, Read Files or Directories | `medium`; `high` if the weakness has an `Integrity`-scoped consequence whose impacts are not all rated `low` |
| Alter Execution Logic, DoS: Crash/Exit/Restart, DoS: Instability, DoS: Amplification, DoS: Resource Consumption (CPU, Memory, Other) | `medium` |
| Hide Activities, Unexpected State, Quality Degradation, Reduce Performance, Reduce Reliability, Reduce Maintainability | `low` |
| Varies by Context, Other, anything else | no contribution |

A CWE with no mapped impact, no consequences or no catalog entry, and no override, leaves
`impact_class` missing and technical severity `null`. It is never rated low.

Overrides list exceptions only. Each entry needs a class and a reason:

```toml
[jobs.job_inference_security_review.settings.scoring.cwe_impact_overrides]
"CWE-79" = { impact_class = "medium", reason = "script runs in the victim's browser, not on the reviewed target; ..." }
```

The shipped overrides are CWE-79, CWE-190 and CWE-476 (`medium`), CWE-209 and CWE-601 (`low`), and
CWE-502 (`critical`). Each records a judgement the catalog's worst-case consequence does not
express for the reviewed target. Before adding one, check the score package. An override's factor
detail records `derived_class` whenever the catalog derives a class, so an override that matches
derivation is redundant and can be removed. The old `cwe_impact_classes` key is rejected at load.

**Catalog state.** Derivation needs the run's pinned `mitre` feed with a `mitre-index/2` index
(re-run `mitre_sync` after upgrading; a `/1` index has no consequences).

- **Unpinned, mismatched or unreadable catalog, or a `/1` index.** Nothing is derived. Every
  non-overridden `impact_class` is missing with the catalog gap as its reason.
- **Stale catalog** (older than `feed_max_age_days`). Classes are still derived, as CWE names
  still are. Each factor records `catalog_status = stale` and the stale gap, and the score
  package gains an assumption naming the stale snapshot. Claim CWE validation still falls back
  and records its gap, as before.

`scores.json` records the rule and the catalog identity it used under `impact_class`.

**What a scoring change invalidates.** The model, the impact derivation rule, the overrides and
the pinned MITRE catalog snapshot enter the provider configuration hash. A change to any of them
gives new `score_id`s and invalidates score-dependent PoC eligibility and report projection. It
does not rerun claim discovery or verification. `application_risk_matrix/1` ignores the overrides
and the catalog. It rates its frozen pre-decision-11 CWE table, so a rollback reproduces earlier
ratings.

## Tuning lane B ranking

Lane B ranks review units by the sum of their known signal points (see the design section "Lane B:
open discovery"). The top `lanes.hunt_max_units` units are hunted. Every weight is set in one
table, and the checked-in values are the shipped defaults:

```toml
[jobs.job_inference_security_review.settings.ranking]
lps = 1000                           # full review-prioritization (LPS) score
sii = 1000                           # full source-history instability (SII) score
hotspot = 1000                       # full hotspot score
tag_density = 1000                   # tag density at tag_density_full_tags_per_file tags per file
tag_density_full_tags_per_file = 4
lead_hint_medium = 100               # per medium lead hint
lead_hint_low = 30                   # per low lead hint
lead_hint_info = 10                  # per info lead hint
lead_hints_max = 1000                # cap on the summed lead hints
advisory_kev = 250                   # any advisory in the unit is CISA KEV-listed
advisory_epss = 250                  # times the unit's highest EPSS percentile
```

Every weight is an integer in `[0, 1000]`, except `tag_density_full_tags_per_file`, which is
`[1, 1000]`. Unknown keys are rejected, and an omitted key keeps its default. A weight of `0`
removes that signal's points from the score. The signal still counts as known for the tie-break
and stays in each unit's rank basis. An unknown
signal (a missing producer or feed) still contributes nothing, whatever its weight.

The weights are semantic, not capacity: they are recorded in the package manifest's `settings`
and change the settings fingerprint. Changing them reorders units and moves the hunt cutoff,
which reassembles hunt packages. The rank rule stays `review-unit-rank/2` because the formula does
not change.

## Code-graph evidence

When the run has accepted `graph` shards (`job_code_graph_index`; today C/C++ only):

- **Packages.** Lead packages embed the `dataflow_path` facts correlated `bridged` or `partial`
  with a CodeQL lead, with their sink, entry point, guards and ranges; hunt packages embed the
  unit's sink and entry-point facts. `retrieval.graph_families` lists the accepted families and
  `retrieval.graph_scopes` the CodeQL scope ids they belong to.
- **Strategies.** A hunt unit with an accepted `sink_site` family launches `sink_up`; one with an
  `entry_point` family launches `entry_down`. Without them the slot falls back to `persona_sweep`
  with a `required_source_unavailable` gap.
- **Capabilities.** `query_code_graph` is granted to the red, hunter, blue and verifier roles. A
  cell receives and may cite graph rows of its package's `graph_scopes` and nothing from another
  scope. `depth` is capped by `[jobs.job_code_graph_index.settings.graph].max_call_depth` as frozen
  into the run.
- **Evidence admission.** A citation counts toward an obligation only when `predicate-admission/1`
  makes its `(entity kind, predicate)` cell `direct`. Source text cited for anything but the
  construct itself is `analyst_assessed`: recorded in the ledger, listed on the finding package as
  `analyst_assessed_evidence` and in the report, never counted. A tool observation counts only for
  the predicates `tool-rule-predicates/2` gives its producer, rule and result kind (a CodeQL point
  result is `affected_construct` only). Both versions, and `obligation-rules/2` (required predicates
  by claim family), are in the package reuse basis, so changing any of them reruns the affected cells.
- **Evidence and scoring.** A cited graph fact counts as direct evidence only for its mapped
  predicate and only when the re-resolved fact is `direct_eligible`. A dominating guard or a bounded
  range only qualifies `missing_or_ineffective_guard` unless the exported facts show it bounds the
  destination (`evidence-admissibility/3`; the relation then records the reason). Scoring then reads
  `taint_path = graph_dataflow_path`, `attacker_control` from the cited source class, and
  `guard_absent = graph_fact`.
- **Gaps.** Every non-complete graph `(scope, family)` row is a `code_graph` producer gap in the
  evidence map, the packages and the completeness ledger; a run without a `graph` index records a
  `code_graph` `missing` gap.

`tests/integration/test_code_graph_end_to_end.py` exercises this path offline with an injected
worker. No live model or live CodeQL export has run it.

## Review protocol v2 observability

The model-facing layer ([`review-protocol-v2.md`](../architecture/review-protocol-v2.md)) leaves these traces:

- **Denials.** A denied retrieval request is not a gap. It appears as a `REVIEW_CELL_AUTHORITY_DENIED` security event
  and in the cell receipt (`turns[].retrievals[]` with `status: denied` and its code); `counts.denials` and
  `counts.queries` include it. A cell that repeats an identical denial ends `invalid` with one `authority_error` gap
  `repeated_denial:<code>:<tool> <request>`.
- **Label feedback.** The cell receipt records `feedback` (labels dropped, stances recorded as unresolved, leads the
  answer did not account for), `compact_result` (what the model wrote), `result` (the expanded document the
  validators saw), `repair_errors` (why the last attempt was rejected) and `label_table.retrieved` (the `Q` labels). Old receipts are not reused: the executor version
  and validator versions changed.
- **Briefs.** Each lane writes `poc-basis.json` beside `chain-seeds.json` (now empty: the compact answer carries no
  chain seeds) and names it in the lane document under `poc_basis`.
- **View bounds.** `max_view_bytes`, `max_view_source_lines` and `max_view_type_declarations` under
  `[jobs.job_inference_security_review.settings.packages]` bound what a cell sees. A view that omitted rows names
  them in a material gap and in `omitted`; the whole stored package, including every gap, stays hash-pinned.

## The adjudication judge

After a team's red, blue and blind-verifier cells finish, an `adjudication_judge` cell may judge each claim
([`review-judge-and-poc.md`](../architecture/review-judge-and-poc.md)). The judge sees the labelled package, the claim
and two sides, A and B, in an order fixed by `sha256(manifest || claim || "judge-order")` and unrelated to role. It
answers `A`, `B`, `both`, `neither` or `unresolved` with citations; the application de-shuffles the answer to
`red_correct`, `blue_correct`, `partly`, `neither` or `unresolved` and records it. **It never sets a claim state:** R5
and R6 are unchanged, confirmation still needs the blind verifier, and the judge's relations (provenance
`adjudication_judge`) are published but not counted by R5 or scoring.

```toml
[jobs.job_inference_security_review.settings.roles.adjudication_judge]
enabled = true                      # false removes the judge cells and the verdicts
when = "all"                        # "all": every claim red affirmed; "disagreement": only where blue differs
judges_per_claim = 1                # 1..5; each judge sees the sides in its own deterministic order
workers = 4
model_profile = "default"           # a different profile gives a different judge model
require_distinct_from_roles = ["hypothesis_hunter", "red_team_analyst", "blue_team_refuter"]
max_why_chars = 600                 # a side's reason as shown to the judge
max_cited_rows_per_side = 12
max_cited_row_chars = 400
```

- **Cost.** `when = "all"` adds one judge cell (up to `max_turns` turns) per admitted claim that red affirmed, per
  `judges_per_claim`. `when = "disagreement"` runs a judge only where a blue cell contradicts, qualifies, leaves a
  predicate unresolved or gave no answer, or the two blue cells disagree. The PoC candidate gate needs a verdict, so
  claims that are not judged are never PoC candidates.
- **Model.** `judge_model_distinct` records whether the judge's model profile differs from the roles in
  `require_distinct_from_roles` on the claim. It is recorded in the verdict, the finding package
  (`independence.judge_model_distinct`) and the handoff accounting (`accounting.judge_verdicts`), and is never required.
  The checked-in configuration uses the `default` profile for every role.
- **What changes.** Adding or changing this block changes the configuration hash and the judge cells' fingerprints
  only; red, blue and verifier cells are reused.
- **Where it shows.** The ledger has one `judge_verdict` event per judge cell; a finding package carries
  `judge_verdict` (`disagrees_with_state` is set when the judge sided against a `confirmed` or `supported` finding);
  the gate and the report show it read-only; the handoff's `accounting.judge_verdicts` counts verdicts by outcome. A
  judge cell that failed is an ordinary cell gap, and a verdict whose request could have carried a red or blue
  identifier is dropped with an `authority_error` gap.
- **Role-blind request.** The judge's request never holds a role, task, persona, actor, cell or (when the judge runs on
  another model) model name of the red or blue side. `judge-request-check-<attempt>.json` beside the cell receipt
  records the check (hashes only).

### PoC candidates

The handoff's `poc_candidates` lists every claim that is `supported` or `confirmed`, whose judge said `red_correct`,
that carries a `poc_basis` with a resolved entry point and call path, and whose `application_risk_matrix/3` technical
severity is configured:

```toml
[jobs.job_inference_security_review.settings.poc_candidates]
accept_partly = false                        # true also accepts a judge verdict of "partly"
risk_ratings = ["medium", "high", "critical"]
```

An entry holds the claim and package ids, state, judge verdict, the `poc_basis` (hash and bounded copy), the finding
package reference and the evidence relation ids. A later job reads the list; this one never builds or runs a proof of
concept.

## Ship-block status

Every finding package records a `ship_block` decision under `ship-block-policy/1` (decision 1),
computed in `review/ship_block.py` when the handoff is published. The first matching row wins:

| Status | When |
|---|---|
| `ship_blocking` | The claim is `confirmed`, it qualifies, and distinct verification held. |
| `ship_blocking_pending_distinct_verification` | The claim is `confirmed` and qualifies, but its verifier ran on a red cell's model. |
| `needs_verification` | The claim is `supported` (not independently confirmed) and would otherwise qualify. |
| `decision_pending` | The claim is `confirmed` or `supported`, does not qualify, and a material input is missing: its technical severity is unrated, or the score package lists material missing factors. Not a release decision. |
| `not_ship_blocking` | Anything else: a rated claim below the blocking thresholds, or a state that cannot block. |

Precedence is the table order. The three qualifying statuses come first because they name the next
action (block, get a distinct verifier, get independent confirmation), and a KEV-listed dependency
qualifies even when its severity is unrated. `decision_pending` is returned only when the claim does
not qualify and the missing input could still change that. It is never published as "does not
block". Its reasons are `technical_severity_unrated` and one `missing_factor_<name>` per factor
that keeps the severity unrated; resolve them as described under "Tuning scoring".

A claim qualifies when `application_risk_matrix/3` rates its technical severity in
`blocking_technical_severities`, or when it is a dependency finding with a KEV-listed reference
input. A dependency finding is a claim proposed from a lane A lead of a `dependency_lead_families`
family. CVSS and SSVC outputs, and the NVD reference CVSS vectors, are recorded under
`ship_block.displayed_context` with `decides = false` and never change the status. A claim without
an `application_risk_matrix/3` rating (for example a missing `impact_class`, or missing factors that
leave the severity interval open) records the reason `technical_severity_unrated` and is
`decision_pending` unless the KEV dependency path applies. Treat that as a gap to resolve, not as a
low-risk verdict.

```toml
[jobs.job_inference_security_review.settings.ship_block]
blocking_technical_severities = ["high", "critical"]   # bands of application_risk_matrix/3
kev_dependency_blocks = true
dependency_lead_families = ["dependency_advisory", "artifact_scanner"]
```

Each package's `ship_block` record holds the status, the policy version and `policy_sha256`, every
condition evaluated, the inputs (claim state, technical severity and its score id, lead families,
KEV flag and verifier distinctness), and citations to the adjudication, the deciding score package
and the verification review. The handoff's `ship_block` object counts findings per status, overall
and per lane.

## Remediation intake and verification backlog

Decision 4 separates the findings the handoff publishes:

- `remediation_intake` lists only `confirmed` finding packages, with their ship-block status.
  It is the only finding list `job_remediation_planning` reads (the handoff's `planned_consumers`
  also give that job `score_packages` and `gap_ids`).
- `verification_backlog` lists `supported` finding packages labelled `unconfirmed`, with the
  required predicates that still lack direct support (`missing_predicates`) and their gap ids.
  No remediation job reads it. A backlog item enters remediation only after a later review
  confirms it.

The handoff's `planned_consumers` names the four downstream jobs fixed by decision 8 and the
handoff fields each one reads: `job_remediation_planning`, `job_remediation_validation`,
`job_final_publication_gate` and `job_final_report_publication`. The gate and the report are built and
read this handoff ([`final-report.md`](final-report.md)); the two remediation jobs are not.

## Outcomes

- Ordinary failures, such as provider errors, timeouts, invalid output, a failed team or an entire
  failed lane, become typed gaps. The handoff is then published with status `DEGRADED`.
  `review_incomplete = true` is set when the gap ratio exceeds `lanes.incomplete_gap_ratio`.
- Integrity failures block publication and leave the accepted pointer unchanged. These include a
  tampered manifest or shard, a broken ledger chain, a non-deterministic merge, or the application
  granting a forbidden capability.
- Re-executing a lane unit reuses every succeeded cell whose fingerprint still matches.
- A judge that fails, times out or returns an invalid answer is an ordinary cell gap with one terminal record; the
  claim is still adjudicated by R5 and published without a `judge_verdict`, and is never a PoC candidate. A missing
  verdict is not a `neither` and not agreement with either side. `accounting.judge_verdicts` in the handoff counts
  the verdicts that were recorded, and the cell counts under `lanes[].cells_by_status` include every judge cell.
