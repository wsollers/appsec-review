---
title: "Review protocol v3: two intakes, one review"
kind: "architecture"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review"]
last reconciled: "fadb6c2e9f8e23a99a59bf3c26cab82db7060493"
---
# Review protocol v3: two intakes, one review

Status: design, decided with the user on 2026-11-16 from the evidence of application runs `2026-11-15-0005`
and `2026-11-15-0006`; not implemented. Where this document and
[review protocol v2](review-protocol-v2.md) disagree, v2 describes the code as it runs today and this
document describes where it goes. Each migration step below is a TODO entry; nothing here authorises a
review run, a model call or a job-boundary change outside the
[add-a-job-contract](../../.claude/skills/add-a-job-contract/SKILL.md) checklist.

## 1. What the runs showed

Run `2026-11-15-0005` reviewed a five-file C++ smoke target (27 first-party functions) in 445 minutes and
failed at dossier publication. Its inference review job alone took 338 minutes and 49 model-hours on
`claude-haiku-5-5`:

| Measure | Run 0005 | Source |
|---|---|---|
| Lead-lane packages / hunt-lane packages | 24 / 52 | `lead-packages.json`, `hunt-packages.json` |
| Hunted units | 50 of 53 (`hunt_max_units = 50`) | package manifest `units` |
| Cell attempts | 1,146 (306 succeeded, 528 invalid, 314 over budget) | `scripts/cell-outcomes.py` |
| Hunter attempts | 618 for 106 successes, 15.9M output tokens (45 % of the run) | same |
| Adjudication-judge attempts | 45, of which 33 invalid | same |
| Model calls | 4,969; 49.5 model-hours; 31 s median | execution receipts |
| Output tokens | 35.6M of a 48M budget | `smoke-score.txt` |
| Claims | 65 after 9 duplicate merges; 4 confirmed, 28 supported, 26 insufficient, 7 out of scope | merge and adjudication artifacts |
| The same use-after-free | 8 supported claims under 8 identities, 4 lead packages | ledger |
| Telemetry fsync in one lane unit | 22,903 calls, 1,303 s off-CPU of 109 minutes | `OPERATION_PROGRESS` phases |

Three of the four confirmed findings were scanner leads (the argv `strcpy`, the `popen` command injection);
the fourth, `malloc` sized from `recv` data, came from the hunt lane and no scanner reported it. The blue
refuters mostly answered "qualifies" or "unresolved", and the states the policy assigned followed what the
red analysts proposed and what the independent verifier could resolve.

Run `2026-11-15-0006` carried the first repairs (claim identity `claim/3` folding site identities, lane B seeded
from lane A, the closed vocabularies stated in the role prompts, the `expand` KeyError fixed). At 101 minutes
its lead lane had completed 233 cells (1.3 cells a minute in run 0005, 2.3 here), 156 attempts had succeeded
against 142 in run 0005's whole 204-minute lane, the invalid share had fallen from 55 % to 32 %, and no
`tool_error:expand` gap was recorded. The model-call rate was unchanged at about 16 a minute: the gain is
that fewer calls are thrown away, not that calls are faster.

## 2. The decision

The review has two **intakes** and one **review**.

1. **Scanner observations** are candidate findings produced by tools. They are normalized by their lead
   family, assessed when their severity is unknown, admitted by policy, clustered by defect site and reviewed.
   This is lane A today and it stays.
2. **Model hunting** is a second *producer of candidate findings*, not a second review protocol. A hunter
   with the retrieval tools and the accepted facts proposes hypotheses about code the scanners did not flag,
   and each hypothesis is published as a `tool_observation` of the same shape a scanner produces: scanner,
   rule, location, message, severity unknown. From there it is a lead like any other.

The review itself is one lane: **analyse**, **verify**, **decide**. One analyst cell per package proposes
structured findings with label citations; one verifier cell per finding checks each predicate against the
accepted facts with its own retrieval and never sees the analyst's prose; a deterministic policy maps verified
predicates to a state. The blinded judge remains available as an escalation when analyst and verifier disagree
on a high-severity finding, not as a step every finding pays for.

Lane B, the blue refuter as a default role, and rounds beyond one are removed when the migration completes.
The ledger, claim identity, evidence relations, warrants, gaps, adjudication policy, scoring and reporting are
unchanged: the verifier and the policy already produce the records they consume.

## 3. Intake A: scanner observations

Unchanged in shape; two policies decided on 2026-11-15 already apply (T-5029, T-5025):

- Lane A admits critical and high by *effective* severity: the scanner's reported value, or for a lead
  reported unknown the assessed severity from lead triage. An unassessed unknown lead is recorded with
  `residual_coverage: unassessed_unknown`, a `lead_admission` skipped gap, and reaches the hunter's unit
  selection (section 4.1) rather than being reviewed blind.
- Leads of one defect site share one package: same path, within `packages.lead_cluster_lines` of a member and
  the same enclosing function where graph facts know it. The package's neighborhood is the merge of its
  members' neighborhoods, bounded by the verified correlated paths.
- `excluded-leads.json` lists every observation the manifest did not admit, with its reason and whether a
  hunt unit still covers it.

## 4. Intake B: model hunting as a producer

### 4.1 Where it runs, and how much

A producer job, `job_model_hunting` (working name), runs after review data indexing and package-scope
acceptance and before the inference review. It consumes the accepted indices through the same `RetrievalCore`
and capability grants as review cells.

The grain of one hunter **cell** is one function with its neighborhood: that is what fits a cell's token cap
and four turns, and the scale at which the menu accounting (section 4.3) is exact. The grain must never set
the **count**: a game has hundreds of thousands of functions, and even a one-hop reach from a few thousand
admitted leads is tens of thousands of units. The count comes from a budget and a ranking:

- **Budget.** `hunting.max_cells` per run, set per profile, replaces `hunt_max_units` as the outer bound.
  Selection takes ranked units until the budget is spent; every unit below the line is recorded as
  `below_hunt_cutoff` with its rank and the reason it was a candidate. A run always finishes, and the artifact
  says what was not looked at.
- **Ranking, attack surface first.** Units are ordered by (1) distance from an attack-surface entry point in
  the accepted graph (network message handlers, file and save parsers, asset and mod loaders, scripting
  bindings; the threat model's interaction catalog and the `trust:user-tainted` and `exposure:client-facing`
  tags identify them), (2) containing or lying within one call hop of an admitted lead, (3) carrying an
  unassessed unknown lead, (4) facet score. The hunter's cost then grows with the attack surface, not with
  lines of code.
- **Areas, a coarse tier above the function.** Before per-function hunting, one bounded cell per component or
  subsystem (hundreds on a game, not hundreds of thousands) reads the threat model, the tags and the
  entry-point summary and nominates *areas* such as "the packet dispatcher and its handlers" or "the save-game
  deserializer". An area is a selection input that raises its functions in the ranking, never a finding. This
  is where a model's judgment about architecture is paid for, bounded by the component count.
- **Incremental.** On a later run against the same codebase, only functions whose source hash or neighborhood
  changed since the last reviewed snapshot are candidates; unchanged functions reuse the previous run's
  verified results through cell memoization. This is the M6 cache; for a game it is a requirement, not an
  option.

The honest consequence: one run never covers a whole game. It covers the attack surface to a budget, records
what it skipped, and the next run continues from there.

### 4.2 What it publishes

One accepted shard of `tool_observation` entities, family `model_hypothesis`:

| Field | Value |
|---|---|
| `tool_id` | `model-hunter` |
| `native_rule_id` | `<security_predicate>/<CWE or none>` from the hypothesis |
| `location` | the cited sink or construct line (a label the hunter cited; unresolved labels are dropped with feedback) |
| `message` | the hypothesis statement, bounded, redacted by `secret-redaction/1` |
| `native_severity` | absent: the hunter nominates a *consequence*, never a severity |
| `payload.hypothesis` | the structured claim the hunter emitted (predicate support labels, taint path, evidence requests), kept for the verifier |
| `payload.producer` | `job_model_hunting`, cell id, guidance bundle hash, model, provider |

The shard's dataset authority is `PROVISIONAL`: nothing downstream may count a model hypothesis as scanner
coverage, and no claim state beyond `proposed` is reachable without verification against accepted facts.
`lead_families.OBSERVATION_PRODUCERS` gains the decision for the job (`tests/review/test_lead_coverage.py`
enforces that every producer has one), and `lead-family/model_hypothesis/1` sets the family's obligations:
`affected_construct`, `attacker_input_control`, `source_to_sink_reachability`, `missing_or_ineffective_guard`,
`security_impact`.

### 4.3 What happens to a hypothesis

Nothing special. Triage assesses its severity (the rule table and, where configured, the model triage pass);
the admission policy decides; clustering merges it with a scanner observation on the same site, which makes
the model's view *corroboration* of the scanner's lead instead of a second claim; and `excluded-leads.json`
lists the hypotheses that were dropped and why. A hypothesis that reaches a package is analysed and verified
like a scanner lead. Its `payload.hypothesis` is shown to the analyst as a lead's message is today, never to
the verifier.

### 4.4 Bounds

All in the central TOML, all reported per run by `scripts/cell-outcomes.py`:

- `hunting.max_cells` (the budget) and the ranking rule of section 4.1;
- area cells per component (one) and hunter cells per unit (one, a second only for a unit with both sinks and
  entry points, where sink-up and entry-down look at different things);
- turns per cell (four) and hypotheses per cell (`hunt_max_claims_per_package` today);
- **yield**: verified findings per hundred hypotheses, reported every run. A target whose yield falls under a
  configured floor (5 to start) has hunting disabled for its later runs by configuration, never silently.

## 5. The review: analyse, verify, decide

| Step | Cells | Role and guidance | Output |
|---|---|---|---|
| Analyse | 1 per package | `red_team_analyst` with the stack persona; the three red lenses become one task that names the lenses | `red-compact` findings with label citations, counter-evidence, evidence requests, PoC basis |
| Verify | 1 per finding | `independent_verifier`, starting from the neutral structured claim, own retrieval, never the analyst's prose | `verifier-compact`: per-predicate stance with citations, disposition |
| Decide | 0 | adjudication policy (`steps/adjudicate`) | claim state, relations, warrants |
| Escalate | 0 or 1 per disputed high-severity finding | `adjudication_judge`, blinded sides | verdict |

Rounds: one. A second analyst pass runs only for a package whose evidence requests the application could
fulfil (a fact the analyst asked for exists in the accepted indices and was not in the package), and at most
once. The cell caps decided under T-5028 apply: final by the fourth turn, one retry of a timed-out cell at a
reduced setting, a token cap sized for a bounded answer.

What this removes: lane B as a protocol (`hunt_review.teams`, lane allocation, `lead_budget_share`), the blue
refuter as a default role (`blue_per_team = 0`; the role stays registered for the escalation path and for
targets that opt in), `red_per_team = 1`, `max_rounds = 1`. The claim ledger, `claim/3` identity,
`evidence-relation/1`, warrants, gaps, the adjudication policy, scoring, attack chains and reporting do not
change.

Cost per package falls from about eight cells and up to three rounds to two or three cells and one round;
with clustering, the smoke target's 76 packages become roughly 25. The expected effect on run 0005's numbers
is a review lane of 50 to 80 cells instead of 1,146 attempts, and model time under five hours instead of 49.

## 6. Measurement

Every run reports, from run-owned records only:

- `scripts/cell-outcomes.py`: attempts, outcomes and reasons per role; per package attempts and successes;
  model-call wall time by outcome; and, once Intake B exists, hunter yield;
- `scripts/smoke-score.py`: structural checks, budget use, and keyed scoring when the user supplies the key;
- the package manifest and `excluded-leads.json`: what was reviewed and what was not, with reasons;
- `OPERATION_PROGRESS` phases: `telemetry.lock_wait`, `telemetry.fsync`, `storage.fsync` per lane unit.

The comparison that decides each migration step is run against run: the same target and overlay, one change
at a time, findings and cost side by side. Passing unit tests do not establish review quality.

## 7. Migration

| Step | Change | Kind | Item |
|---|---|---|---|
| M1 | The clean run with the 2026-11-15 repairs (claim identity, vocabularies, expand, dossier hashing, admission, clustering, fsync) | code, landed together | T-5024, T-5025, T-5027, T-5029 |
| M2 | Measurement run with the review reduced to analyse-then-verify: `red_per_team = 1`, `blue_per_team = 0`, judge disabled, `max_rounds = 1`; same target and overlay as M1 | configuration only | T-5028 (caps), new entry for the run |
| M3 | `job_model_hunting`: the producer of `model_hypothesis` observations, its lead family, producer decision, dataset and topology edge; the hunter guidance moves from the hunt lane to the producer | job boundary | T-5030 (redefined) |
| M4 | Remove lane B from the review job: units, lane allocation, the cross-lane seed path, `lanes.*` settings that only lane B used; hunt packages become ordinary clustered packages of `model_hypothesis` leads | code | new entry, after M3 |
| M5 | Judge as escalation: enabled only for disputed findings at or above a configured severity; blue refuter opt-in | configuration and a small routing change | new entry |
| M6 | Scale: tooling cached per target snapshot and re-run for changed files; one package queue served across hosts; cell memoization reused across runs | design, then jobs | T-5031 follow-ups |

M2 needs no code and runs right after M1. M3 is the first real build and goes through the job-contract
checklist. M4 follows M3 in the same release so that no run ever has both a hunt lane and a hunting producer.

## 8. Decisions (2026-11-16)

Decided with the user from the evidence above and the recommendations put to them.

| # | Decision | Why |
|---|---|---|
| D1 | A hunter cell is one function with its neighborhood. | Fits the cell caps; the menu accounting is exact at that scale; cross-function context is one `expand` away. |
| D2 | The number of hunter cells is a per-run budget with attack-surface-first ranking, an area tier and incremental selection (section 4.1), never the function count. | A game has hundreds of thousands of functions; cost must scale with the attack surface and with what changed. |
| D3 | Reach from admitted leads plus a separate, small facet-ranked allowance. | Hunting matters most where scanners are silent; run 0005's one novel confirmed finding came from such a unit. |
| D4 | One strategy per unit by default; a second only for a unit with both sinks and entry points. | Each strategy is a full cell. |
| D5 | The hunter nominates a consequence, never a severity; triage assesses, the scorer rates after verification. | Admission must not follow the model's confidence. |
| D6 | Hunter model: the analyst's model for the first measurement run, then one stronger-model comparison. | One change per run keeps results attributable; the hunter is where a stronger model is most likely to pay. |
| D7 | Yield floor 5 verified per 100 hypotheses, measured on the smoke targets first. | Near what the run 0005 hunt lane achieved; stops a target where hunting is noise. |
| D8 | The blue refuter is off by default and opt-in per target after M2 confirms it. | In run 0005 its answers were mostly "qualifies" or "unresolved" and did not move states; the verifier refutes with its own retrieval. |
| D9 | The judge is an escalation for disputed findings at or above high. | 33 of 45 judge attempts were invalid; agreement needs no judge, and a disputed low finding is itself the right record. |
| D10 | One bounded second analyst pass, only when a requested fact exists in the accepted indices and was not in the package. | Evidence requests were fulfilled only by later rounds in run 0005; removing rounds entirely would waste them. |
| D11 | Cell caps: final by the fourth turn, one retry at a reduced setting, a token cap sized for a bounded answer. | Cells that ran six turns and 78,000 tokens produced nothing. |
| D12 | Unknown-severity leads: triage assesses; admitted only on an assessed high or critical; otherwise a hunter menu item and an `excluded-leads.json` row, never a blind review and never a silent drop. | Unknown is most of what scanners emit on native code; reviewing all of it is the cost explosion. |
| D13 | Cluster window: the whole enclosing function when graph facts place both leads, eight lines otherwise. | A function is the natural unit of a defect; the window is the fallback for unplaced code. |
| D14 | A model hypothesis may cluster with a scanner observation on the same site and becomes corroboration. | The best evidence a scanner lead is real, at no extra cost. |
| D15 | Model-originated findings are marked as such in reports and dossiers. | A reader deciding what to fix should know the provenance; hiding it is the drift being corrected. |
| D16 | Excluded leads: a counts table in the final report, the JSON artifact for detail. | Rows belong in the artifact, the summary in the report. |
| D17 | M2 runs as the next review after the clean run, same target and overlay, configuration only. | One change against one baseline. |
| D18 | The cpp smoke target stays the baseline through M5; a larger target joins at M3. | Small enough to read every finding; the hunter is the component whose cost scales with code size. |
| D19 | Scale work (M6) is designed after M3 lands. | The cache and the shared queue must fit the job graph M3 produces. |

## 9. Open questions for the user

1. **Area tier model.** The area-nomination pass is few cells with wide context. Same model as the hunter,
   or the stronger one from the start?
2. **Attack-surface catalog.** Which entry-point classes count as attack surface for the first large target
   (network, file, scripting, asset loading, IPC)? The threat model's interaction catalog is the default list.
3. **Incremental baseline.** For the first run against a game there is no previous snapshot: run the budgeted
   attack-surface pass alone, or also a one-time wider pass over a configured allowance?

## 10. References

- [Review protocol v2](review-protocol-v2.md), [review package contract](review-package-contract.md),
  [inference security review](inference-security-review.md) (the code as it runs today).
- `src/appsec_review/review/lead_families.py` (`OBSERVATION_PRODUCERS`, families), `review/packages.py`
  (`cluster_leads`, `finding_leads`), `review/excluded_leads.py`, `jobs/job_inference_security_review/teams.py`
  (`run_lane`, `lane_allocation`), `review/compact.py` (the compact contracts).
- Host-local run evidence: `runs/2026-11-15-0005/data/verification/{cell-outcomes,smoke-score}.txt`,
  `runs/2026-11-15-0006` (in progress at the time of writing).
- TODO: T-5024, T-5025, T-5027, T-5028, T-5029, T-5030, T-5031, T-5032.
