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

Each case is a single final-answer experiment with **no retrieval tools**. Missing declarations,
helper implementations and deployment receipts must produce explicit uncertainty. This measures
bounded source reasoning and output discipline, not retrieval quality, whole-repository recall,
multi-round convergence, independence adjudication or production false-positive rates. Verifier
inputs retain a neutral structured condition, not another worker's argument.

## Running

No inference runs without `--live`. Offline re-scoring reads recorded raw proposals and recalculates
metrics against the same case-set hash:

```powershell
.\.venv\Scripts\python.exe -m appsec_review.review.evaluation `
  --responses runs\guidance-eval\data\evaluation\report.json
```

To deliberately spend the configured model budget on a paired procedure ablation:

```powershell
.\.venv\Scripts\python.exe -m appsec_review.review.evaluation `
  --live --profile dev --role independent_verifier --variant paired `
  --output runs\guidance-eval
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
