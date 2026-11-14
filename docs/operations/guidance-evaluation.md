---
title: "Evaluating review guidance"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Evaluating review guidance

Structural prompt tests establish schema, authority and provenance compatibility, not model
accuracy. `python -m appsec_review.review.evaluation` adds an **explicitly opt-in** role experiment
using the real composed guidance, configured provider/model and compact output schemas.
It never changes production claim state or configuration.

## Cases and scope

`tests/fixtures/review_guidance/cases.json` contains 15 original, inert source fixtures: vulnerable,
fixed and incomplete-evidence variants for destination capacity, tenant authorization, delayed
worker identity, effective deployment configuration and refund atomicity. Labels resolve to
numbered, hashed excerpts. Expected outcomes, case family and decisive citation labels are
answer keys held out of model input; the fixtures are not registered runtime guidance.

The original `review.evaluation` experiment is a single final answer with **no retrieval tools**. Missing declarations,
helper implementations and deployment receipts must produce explicit uncertainty. This measures
bounded source reasoning and output discipline, not retrieval quality, whole-repository recall,
multi-round convergence, independence adjudication or production false-positive rates. Verifier
inputs retain a neutral structured condition, not another worker's argument.

## Running

No inference runs without `--live`. Offline re-scoring reads recorded raw proposals and recalculates
metrics against the same case-set hash:

```sh
.venv/bin/python -m appsec_review.review.evaluation \
  --responses runs/guidance-eval/data/evaluation/report.json
```

To deliberately spend the configured model budget on a paired procedure ablation:

```sh
.venv/bin/python -m appsec_review.review.evaluation \
  --live --profile dev --role independent_verifier --variant paired \
  --output runs/guidance-eval
```

Use a **new** output directory beneath `runs/`; existing outputs are never overwritten. `--profile prod`
uses the existing production profile without increasing any limits. Supported roles are
`hypothesis_hunter`, `red_team_analyst`, `blue_team_refuter` and `independent_verifier`.
`--variant full` and `--variant without_procedures` run one arm only. Paired arms share the case
input, role, model and one persisted job budget; the second arm may therefore be incomplete if
the first exhausts the budget. Compare only complete, matched runs.

The procedure-only ablation removes the procedures section's items and recomputes section and
bundle hashes; it never removes governing rules, role constraints, persona knowledge or task
contracts. This is evaluation code, not a production guidance switch.

The run stores resolved review configuration under `data/configuration`, hash-addressed bundles
under `data/guidance`, and raw requests, responses, case keys and the report under `data/evaluation`.
Transport failures and skipped cases remain explicit gaps. Unreported output usage is conservatively
charged at the configured output ceiling; reported metrics retain unknown usage rather than zero.

## Reading results

| Metric | Interpretation |
|---|---|
| Recall | Correct, citation-grounded vulnerable decisions divided by all vulnerable cases, including failures and skipped cases. Not applicable to blue, which cannot confirm a claim. |
| False-refutation rate | Vulnerable cases incorrectly called safe divided by all vulnerable cases. |
| Unsupported-conclusion rate | Conclusive outputs with the wrong expected decision or insufficient/unknown decisive source citations divided by conclusive outputs. |
| Abstention precision / recall | Correct incomplete-evidence abstentions with a named gap or request, relative to all abstentions / incomplete cases. Failed calls are not abstentions. |
| Duplicate rate | Repeated red condition/CWE/affected/precondition keys divided by red proposals. |
| Tokens per correct resolution | Reported input plus output tokens divided by correct resolutions; unavailable when usage is incomplete. Monetary cost is explicitly unavailable, not estimated from guessed prices. |

Red `no_claim` is not a clean finding and receives no safe-resolution credit. Blue qualifiers or
unresolved answers are not affirmations. Correct answer words without the required source
citations do not earn conclusive credit.

These are deterministic **citation-sufficiency proxies**. A cited excerpt can still be misread;
inspect raw reasoning and source lines before accepting a gain. Keep a separate, rotating private
holdout for statistically meaningful evaluations: these small public fixtures can be learned and
are suitable for regression experiments, not a general performance claim. No live performance
gain is established by the offline tests or by adding this harness.

## Multi-turn prompt competence

`review.competence.run_competence_case` exercises real composed bundles, accepted source/index
manifests, `run_cell`, retrieval authorization, paging and compact citation expansion for the
independent verifier, hypothesis hunter and lead analyst. Discovery also uses the production
`RedInvocation` and configured `red_discovery.admission_errors`, not a fixture validator. The nine
cases in `competence_cases.json` and scripts in `competence_scripts.json` cover native bounds,
tenant authorization and deployment configuration: retrieval selection, truncation, denial
recovery, remaining budgets/final turn, missing artifacts, wrong citations, hostile untrusted
text, false-positive controls and justified abstention. Expected outcomes and scripted answers
are held out of worker prompts.
`stateful_competence_cases.json` adds vulnerable, controlled and incomplete refund-retry examples,
including a cross-file transaction guard and contradictory **unselected** configurations. The
case set is inert and public, not a threat-model or deployment producer.

Focused offline unit command:

```sh
.venv/bin/python -m pytest tests/review/test_prompt_competence.py \
  tests/review/test_discovery_competence.py tests/review/test_worker_competence.py \
  tests/test_stateful_guidance.py -n 2 --shuffle-seed=808 \
  --basetemp=test/tmp/fleet-f08-competence -q
```

Scripted fixtures establish protocol behavior, not live efficacy. No-claim discovery output is
not a safety verdict and earns no safe-resolution credit. Unknown citation labels are scored
only after production expansion; a fabricated blocked-lead label earns no justified-abstention
credit. If a lead appears in both `no_claim` and `blocked`, the production `lead_accounting`
outcome decides; a `no_proposal` outcome cannot score as abstention. Hunter output with no lead
menu has no lead-level blocked decision: an empty hunt is not
an abstention result. Source citation metrics remain proxies and reuse the existing evaluator.

`review.worker_competence.run_planning_case` uses real governed build-family bundles, the shared
`plan_prompt` renderer, `feedback_request`, exact on-disk inventory reads and `bounded_feedback`
final recipe validation. A foreign path/hash can recover only through the production repair
budget; an incomplete final never enters the complete-response cache. It uses a synthetic native
build catalog, not a real build or cross-family toolchain-coverage claim.

`run_remediation_case` re-reads the accepted review through production `load_review` before
dispatch. The supplied review snapshot must match this verified document; a self-consistent
mapping is not an alternative authority. It reconstructs retrieval through `retrieval_core` from
that review's hash-bound scope and rejects a different supplied manifest. It then checks
confirmed-only membership and the candidate cap, reads the bound projection and accepted native-build
handoff, runs `SourceReader`, the shared `writer_task` / `review_prompt` and real `run_model`,
then `PlanAnswer` and `verify_patch_scope`. Experiment inputs retain the accepted review references.

The synthetic review fixture seeds scanner/model observations, not a final confirmed partition.
It uses production scope/package assembly, R5 adjudication, sealed ledger merging/projection,
finding generation, accounting and handoff construction; `load_review` derives the resulting
partition and identities. Removing or corrupting the accepted pointer, handoffs, ledger/shards,
projection, finding, scope or package manifest blocks model dispatch. No accepted-review loader
or final validator is mocked. Build/index hash mismatches also fail before dispatch; an exact patch is
checked but never applied or executed. Initial source text is already supplied in production:
line-window retrieval here tests re-reading, **not** a claim that a hidden page improved the model.
Invalid remediation retrieval/final output remains terminal, unlike recoverable discovery and
planning denials.

The specialized adapters require an explicit transport or `live=True`, use new output directories,
and persist rendered prompts, requests, responses, exact input identities and native outcome
receipts under `appsec-review/worker-competence/1`. This is a new experiment-only envelope, not a
changed worker schema or a quality score. No inference-execution/provider, job registry, TOML,
telemetry aggregation or shared test-harness changes are needed.

Future **manual acceptance only**, not run during implementation:

```sh
.venv/bin/python -m tests.acceptance.test_prompt_competence --live \
  --config appsec-review.toml --profile dev \
  --provider claude-cli --model claude-haiku-5-5 \
  --role independent_verifier --variant full \
  --cases tests/fixtures/review_guidance/competence_cases.json \
  --output runs/competence-live-YYYYMMDD-unique
```

Provider/model flags assert the selected configured identities; they are not overrides. Use the
actual configured pair if it changes. Output must be a new run directory. The entrypoint records
configuration, corpus and model identities along with quality metrics and gaps.
`tests/acceptance/test_prompt_competence.py::test_live_prompt_competence` is an alternative
opt-in pytest entrypoint requiring `APPSEC_REVIEW_LIVE_COMPETENCE=1` and
`APPSEC_REVIEW_COMPETENCE_ARGS` containing those arguments as a JSON array. Integration,
acceptance and live paths are excluded from implicit unit collection; selecting them is a
separate manual action, not authorization granted by a passing unit run.

### Manual ablations and extension boundary

After separate live authorization, the same entrypoint accepts `--role hypothesis_hunter` or
`--role red_team_analyst`, `--variant without_procedures`, and `--turn-cap N` (2 through the
selected role's configured maximum). Omitting these retains verifier/full/configured-turn
behavior. Provider/model flags must match that **role's** resolved profile. Use separate new
outputs and a frozen corpus/profile for each arm; do not compare incomplete or failed arms as
successes. `--turn-cap` changes model evidence turns, not review-team convergence rounds.
The two specialized Python adapters also expose `variant="full" | "without_procedures"` and
explicit `live=True`; callers must supply the same admitted inputs and configured bounds as in
the offline cases. None of these entrypoints has been executed live for F08.

For an independently authorized full-review role/round experiment, the existing central selectors
are `jobs.job_inference_security_review.settings.teams.red_per_team`, `blue_per_team`,
`verifier_per_team`, and `jobs.job_inference_security_review.settings.rounds.max_rounds`.
Keep their existing configuration validators and independence requirements; this document does
not authorize zeroing required roles or changing judging policy. Pre-register a bounded matrix,
freeze source/scope/build/guidance/model identities, retain every failed/partial arm, and compare
candidate yield separately from independently verified findings using held-out adjudication.
Repeated roles on one model are not independent evidence; scripted outcomes measure neither
precision nor marginal role yield. F08 does not change these settings or run this experiment.

The generated threat-model producer and its bounded inference routing consumer now exist;
deployment-inventory publication remains T-108. The original F07/F11 labels identify
proposed experiment adapters, not absent production guidance or permission to create a producer.
Any future threat-model/deployment-context or experiment-planning adapter must use its
actual admitted producer artifacts, production request constructor/renderer, application reader
and final validator. Add missing/foreign/stale inputs and closed-schema regressions before an
adapter is considered covered. Never synthesize a future producer receipt merely to fill a card;
missing context remains named uncertainty.
