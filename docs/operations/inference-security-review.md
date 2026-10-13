# Inference security review operations

Design authority: [`../architecture/inference-security-review.md`](../architecture/inference-security-review.md).
This page covers operator settings for `job_inference_security_review` (Dagster job
`inference_security_review`). All settings live in `appsec-review.toml` under
`[jobs.job_inference_security_review]`. Each run freezes them into
`runs/<run-id>/data/configuration/`.

## Model selection and upgrade

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
3. Start the run. `job_review_intake.model_preflight` confirms that the provider serves every
   configured model, including this job's profiles, before any review work. An unavailable model
   blocks the run.

**What a model change invalidates.** Provider, model and reasoning are inputs to every cell
fingerprint, so a run after a model change executes every review cell fresh and does not reuse
cells from earlier runs. Package assembly and the other upstream jobs are not affected. The run's
resolved-configuration hash also changes.

**Independence.** The blind verifier must be a different actor from the red and blue cells. It does
not need to be a different provider or model family; that requirement is open question 2 in the
design. Every finding package records `independence.provider_distinct`, so a run that uses one
model for every role is labelled as such.

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
is `application_risk_matrix/2`. It rates `score-factors/1` factors, each derived from adjudicated,
re-resolved evidence: `verification`, `taint_path`, `attacker_control`, `guard_absent`,
`exposure`, `privilege`, `data_sensitivity`, `impact_class` (from the pinned MITRE catalog; see
"CWE impact classes" below) and `threat` (KEV only). The design section "Evidence-derived scoring
factors" lists every factor's scale and source. A factor with no
evidence is listed in the score package's `missing_factors`, with its reason in
`missing_factor_reasons`. It adds no points and is never read as a low value.

The model lives under
`[jobs.job_inference_security_review.settings.scoring.providers.application_risk_matrix]`:

```toml
[...providers.application_risk_matrix]
implementation = "application_risk_matrix/2"     # or "application_risk_matrix/1" (no model tables)

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
| Read Memory, Read Application Data, Read Files or Directories | `medium`; `high` if any of the weakness's consequences is `Integrity`-scoped |
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
- **Evidence and scoring.** A cited graph fact counts as direct evidence only for its mapped
  predicate and only when the re-resolved fact is `direct_eligible`. Scoring then reads
  `taint_path = graph_dataflow_path`, `attacker_control` from the cited source class, and
  `guard_absent = graph_fact`.
- **Gaps.** Every non-complete graph `(scope, family)` row is a `code_graph` producer gap in the
  evidence map, the packages and the completeness ledger; a run without a `graph` index records a
  `code_graph` `missing` gap.

`tests/integration/test_code_graph_end_to_end.py` exercises this path offline with an injected
worker. No live model or live CodeQL export has run it.

## Outcomes

- Ordinary failures, such as provider errors, timeouts, invalid output, a failed team or an entire
  failed lane, become typed gaps. The handoff is then published with status `DEGRADED`.
  `review_incomplete = true` is set when the gap ratio exceeds `lanes.incomplete_gap_ratio`.
- Integrity failures block publication and leave the accepted pointer unchanged. These include a
  tampered manifest or shard, a broken ledger chain, a non-deterministic merge, or the application
  granting a forbidden capability.
- Re-executing a lane unit reuses every succeeded cell whose fingerprint still matches.
