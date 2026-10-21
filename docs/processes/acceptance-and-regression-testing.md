# Per-job output correctness, acceptance, and anti-regression

## The requirement

Each job must produce a *correct* result for its inputs. Not a result of the right shape, not a
result identical to last week's, not a pipeline that eventually finds planted defects: given these
inputs, is this output the right answer?

That is a stronger requirement than end-to-end acceptance, and it is checkable earlier, closer to
the defect, and without a human answer key for most of what goes wrong.

## Where it belongs: the validator seam that already exists

`appsec_review.runtime.units` runs every unit like this:

```python
for validator in unit.output_validators:
    validator(unit_context, result)
atomic_json(unit_root / "result.json", result)
```

The validators run **before the result is persisted**. A contract that fails there means the wrong
output is never recorded and the unit fails — exactly the semantics wanted, and it applies to every
real run, not only to test runs. `Unit` also takes `input_validators`, so a consuming job can
reject an upstream handoff it cannot trust.

The seam is almost unused. `output_validators` appears in 3 job files out of roughly 24, and 18 of
the ~20 instances are in `job_third_party_data_sync`; the rest of the graph persists whatever its
handlers return. Correctness contracts belong here, not in a separate test harness.

## The job contract: declared input, declared output

For each job: **given the correct input, did it produce the correct number of files of the correct
output?** That is a coarse, mechanical question. It needs no oracle, and it is where every defect
found during the 2026-10-15 bring-up actually lived.

Every expected count is *derived* from something already declared. A literal `assert count == 10`
is brittle and measures nothing; `assert len(exports) == len(declared_tables)` holds on any target.

| job | input | required output | derivation source |
| --- | --- | --- | --- |
| `job_target_catalog` | N accepted source files | N entries, or an exclusion carrying a reason for each absence | the accepted file set |
| `job_project_build` | discovered build units | one dispatch receipt per unit, each SUCCEEDED / BLOCKED / NOT_APPLICABLE with a reason | `build-systems.json` |
| `job_language_build` | compile database with K translation units | K compile records; artifact kinds drawn only from the role vocabulary | the accepted compile database |
| `job_tree_sitter_ast` | M parseable catalog files | M parsed records, plus a named gap per exclusion | the catalog |
| `job_codeql_analysis` | S scopes x declared suites | S databases, S query executions, and one export file per declared table (10 for cpp) | `rules/codeql-graph-export/columns.json` |
| `job_evidence_collection` | enabled producers | one observation index **and one registered manifest shard** per producer | the producer configuration |
| `job_artifact_indexing` | X producer shards | X registered shards, every id unique | the upstream manifests |

Two supporting properties make the counts trustworthy:

- **Internal consistency.** Fields that must agree: `capped` true only when `observed >= limit`;
  `retained == len(records)`; `terminal_status == "SUCCEEDED"` implies `gaps == []`; `file_count`
  equals the number of files hashed into `tree_sha256`.
- **The gap / NA split.** A required producer that ran and failed is a **coverage gap**. A producer
  correctly not applicable to an input is **not applicable**. Different claims, different classes --
  not two strings in one flat list where 193 `partial` records hide a permanent failure of a
  mandatory analysis.

### This is not query correctness

Whether a query returns the right rows is a separate, finer assertion, made with a canned CodeQL
database and expected results. It is a required deliverable, tracked in
[`../TODO.md`](../TODO.md), and it does not belong in the job contract. The job contract asks
whether the suite ran, resolved, and produced the declared number of accounted-for outputs.

## Why this ordering: the bring-up defects, scored

| defect | class that catches it | needs an oracle? |
| --- | --- | --- |
| duplicate `relation_id` aborted indexing | 2 — uniqueness | no |
| 27 observation indices written, none registered | 2 — producer/shard conservation | no |
| graph-export pack never compiled on any target | 4 — required producer, zero output | no |
| `o`/`object` kind duplication | 3 — kind vocabulary | no |
| `capped: true` with `observed: 2`, limit 10,000 | 3 — consistency | no |
| CERT suite yielding nothing | 4 — required producer, zero output | no |

All six are caught without any answer key. That is the argument for doing this before the corpus
acceptance work: the expensive instrument catches less than the cheap one.

## The ontology, made mechanical

A required tool that ran and failed is a **coverage gap**. A tool correctly determined not to apply
to an input is **not applicable**. These are different claims and must be different classes in the
artifact, not two strings in one flat `gaps` list where 193 `partial` records hide a permanent
failure of a mandatory analysis.

Contract: every non-`SUCCEEDED` disposition carries a reason and a class in
`{NOT_APPLICABLE, COVERAGE_GAP}`; a `COVERAGE_GAP` on a required producer fails the job unless the
configuration declares it accepted, with the reason recorded.

## Phases

### Phase 1 — contract harness and the first contracts
- `src/appsec_review/acceptance/contracts.py`: reusable validators (`unique_by`, `conserves`,
  `implies`, `vocabulary`, `agrees_with_upstream`), each raising with the offending values named.
- Apply to the jobs where the bring-up found defects first: `job_artifact_indexing`,
  `job_evidence_collection`, `job_codeql_analysis`, `job_language_build`, `job_project_build`.
- Unit tests feed each validator a correct and a corrupted result; no Docker, no target.
- Effort ~2 days. Enforced on every run from the moment it lands.

### Phase 2 — the gap/NA split
Introduce the class field, migrate producers, and make a required-producer coverage gap fail by
default. Effort ~1-2 days, touches many jobs shallowly. This is the change that makes 223 gap
records legible.

### Phase 3 — exact expected output on calibration inputs
Two inputs are small enough to state the correct output in full: `native/linux-calibration` and the
benign "nothing" target. Record, per job, the exact expected normalized output — for calibration,
the full `artifacts[].kind` set (`object` 152, `executable` 38, `shared-library` 19,
`static-library` 19, `compile-database` 1) and the `excluded_bookkeeping` counts; for the benign
target, zero promoted findings. Effort ~2 days.

### Phase 4 — the comparison tool
Implemented as `deploy/dagster/bin/stepwise.py compare`, with the logic in `appsec_review.acceptance`
(operator procedure: [`deploy/dagster/README.md`](../../deploy/dagster/README.md#stepwise-acceptance-of-wave1_review)).
It normalizes each job of a run and diffs it against the accepted outputs, classifying every
difference as `job-status`, `gap-added`, `gap-removed`, `finding-added`, `finding-removed`,
`coverage` or `volatile`, and exits non-zero on anything but `volatile`. Primarily a diagnostic — "what changed between these two runs" was the question
that consumed most of the bring-up, answered by hand. Effort ~1 day.

Normalization must mask: run and attempt ids, timestamps and durations, absolute paths, **image ids
and digests** (host-specific by design), randomized scratch names (`.appsec-review-build-scratch.T70GHa`,
`targetZ0X9iP`), container names and pids, and any digest computed over the above. Without this a
diff is unreadable, and byte comparison across hosts is impossible in principle.

### Phase 5 — corpus acceptance against the answer key
The outermost layer, and the only one needing an oracle. The corpus is blind (`appsec-multi-vuln`
at a pinned tag; see Decisions). The oracle is a reviewed good run, accepted one job at a time: not
an arbitrary previous run, but one whose every job output was checked and accepted before the next
job was. `test/acceptance/expectations.toml` maps each case to the defects that must be found with a
resolving location, the producers that must have run, and the gaps that are accepted. Reported as a
found/missed/spurious matrix per case and family, so the result is a measurement rather than a
pass/fail bit; spurious findings are left to the refutation stage. Effort 2-4 days, dominated by the
job-by-job acceptance of the first good run.

The answer key is a reviewed run of `appsec-multi-vuln`, pinned at a tag recorded at acceptance
time and accepted job by job with `stepwise.py`. Each accepted output is committed as
`test/acceptance/<tag>/<job>.json`. A known-good seed of the run after each job is recorded alongside
it, which lets `stepwise.py verify-job` re-run any single job from a byte-identical starting
state. A required-producer coverage gap is reported, not fatal, and spurious findings are reported
for refuters to remove rather than failing the comparison.

## What these contracts do not reach

A job whose output is a large, open-ended result set is not covered by any of the four classes.
`job_codeql_analysis` runs 117 CERT C++ queries plus the default suites; `job_evidence_collection`
drives twenty scanners. For those, correctness is a question about each rule's semantics, and no
conservation or consistency property answers it.

The only contract available today is the weak one the pipeline already applies: a required producer
returning zero results is a coverage gap, not a clean classification. That is enough to catch a
suite that silently stopped working, and not enough to catch a suite that works but answers wrongly.

Candidate instruments, and the open question that decides the cost, are recorded in
[`../TODO.md`](../TODO.md) under "Decide how to assert correctness for large query-set jobs". Note
that `rules/sei-cert/multivuln.json` already carries `expected_findings`, `expected_exclusions` and
`known_false_negatives` against a pinned target commit, so a machine-readable oracle exists for at
least one rule set.

## Non-goals

- **No byte comparison of artifacts** — see the volatile fields above.
- **No baseline captured from a pipeline with unexplained gaps.** Runs before `a5f443e7` had graph
  export failing on every target and no observation shard reachable through the manifest; freezing
  those enshrines the defects.
- **Not a smoke test.** Smoke proves a tool starts.

## Decisions (2026-10-16)

1. **A required-producer coverage gap does not fail the run by default.** It stays a named gap in
   the run's results; Phase 2 makes it legible, not fatal.
2. **Spurious findings are reported, not failed.** Phase 5 lists them; the refutation stage votes
   them down and eliminates them from the final report. Missed expected defects are the failure.
3. **The answer key is a reviewed good run, built one job at a time.** Each job's normalized output
   is accepted individually, in graph order, once its inputs are accepted, and becomes that job's
   expectation. A job is not accepted while it carries an unexplained gap (see Non-goals).
4. **Baselines and expectations live under `test/acceptance/`,** committed and reviewed. The
   corpus is pinned to an `appsec-multi-vuln` tag (to be named; the earlier pin `2994384` is not
   in the local target history), and every expectation records that tag and its commit.

## Decisions (2026-10-18)

5. **Local and Dagster parity comes first, on a small corpus.** Every job is walked through both
   drivers from the same seed with `stepwise.py parity` before it is accepted, on the blind
   `targets/cpp-multivuln` corpus at tag `cpp-multivuln-v1`. Its answer key is
   `test/acceptance/cpp-multivuln-v1/expectations.toml`. Model-backed jobs replay the Dagster
   run's recorded responses. Further corpora are added only after the whole chain matches; see
   [`local-dagster-parity.md`](local-dagster-parity.md).


## System acceptance (SAT/SIT)

`stepwise.py system --tag <tag>` runs one complete `wave1_review` through Dagster (or takes a finished
run with `--app-run ID`) and checks it end to end. It is the check that the whole graph succeeds and
produces its final artifacts; per-job parity shows each job behaves the same through both drivers.

| Check | Fails when |
| --- | --- |
| Every job of the graph | a job has no accepted handoff, or finished other than `SUCCEEDED` / `COMPLETED_WITH_GAPS` |
| Evidence integrity | any handoff, artifact or path-and-hash reference does not resolve to its recorded bytes, or a job bound an upstream handoff the run did not accept |
| Final artifacts | the review packages (`data/review-packages/*/manifest.json` and its pages) or the document-issue ledger are missing, empty, changed, or fail `docs/schemas/document-issue-ledger.schema.json` |
| Model contract | a model-backed job sent a request the accepted run did not, or a request never got a complete response (below) |
| Baselines | the normalized output of a job differs from `test/acceptance/<tag>/<job>.json` (`stepwise.py compare`) |
| Answer key | a defect in `test/acceptance/<tag>/expectations.toml` has no finding on its file and line. Spurious findings are reported and never fail |
| Funnel | never: the per-defect funnel (below) is printed and written to the report, and does not change the verdict |

The live test is `tests/live/test_wave1_system_live.py`, skipped unless `APPSEC_REVIEW_SYSTEM_ACCEPTANCE=<tag>`
is set. It needs the Dagster stack running, the Docker daemon, the Claude CLI overlay and the real model.

Two things the checks do not do, found by running them:

- **Parity cannot see two sides that are equally broken.** The Clang static analyzer exited 1 on every
  translation unit with no diagnostics, and the walk accepted that because both drivers agreed. Only the
  answer key shows it. `parity` now also refuses a Dagster run whose model calls could not reach a model
  (`unavailable_model_calls`), after a stack recreated without the CLI overlay produced a degraded baseline.
- **A model's answer is never asserted.** It varies from run to run. For every model call the system
  run asserts the contract around it instead (`appsec_review.acceptance.model_contract`):
  1. *Inputs match.* The first-attempt requests of the run, normalized like output (event numbers, hashes
     and run ids masked), equal those recorded from the accepted run in
     `test/acceptance/<tag>/model-contract.json`. Repair requests carry the previous failure and are not
     compared.
  2. *Responses are complete.* Every request ends with a response that names its schema, validates against
     the schema file where one exists (`docs/schemas`), and obeys the rules its consumer applies: for a
     dependency-repository proposal a candidate id, a confidence of 0 to 0.95, evidence references taken
     from those the request supplied, and a rationale. A request whose every attempt failed is a violation.
     Failed attempts that a repair recovers are counted and reported.
  Record the accepted run's contract with `stepwise.py model-contract --tag <tag> --from <recordings dir>`.
  A job whose valid answers differ from the accepted ones, and every job downstream of it, is still
  compared with its baseline, but those differences are reported as attributable to the model and do not
  fail the run; every other job is compared strictly. Baselines are re-normalized with the current masks
  on both sides before comparing, so adding a mask does not require re-accepting a corpus.

## Funnel: where each seeded defect stopped

The answer key says whether the deterministic producers *observed* a seeded defect. It cannot say why a
defect that was observed never became a finding. `appsec_review.acceptance.funnel` follows every defect of
the key through the model-backed review and reports, from run artifacts only, the last stage it reached and
the specific reason it stopped. It is read-only on the run directory and deterministic.

`stepwise.py system` prints one line per defect and four aggregate lines after the answer-key lines, and
writes the same data under a new `funnel` key of `runs/metadata/stepwise/system/<run>-<tag>.json`. The same
report is available for any finished run:

```text
python -m appsec_review.acceptance.funnel --run <run dir or run id> [--expectations <toml>] [--json]
```

**Asserted versus reported.** `available` and `observed` are the deterministic stages the answer key already
asserts for deterministic producers (a miss there stays a failure, unchanged). Every later stage depends on a
model and is **reported, never asserted**: the funnel cannot change `SYSTEM OK` / `SYSTEM FAILED`, and a
failure to build it is printed and recorded, not raised. A funnel that stops at `reviewed` is a statement about
the model run, not a regression.

| Stage | Reached when |
| --- | --- |
| `available` | the file is in the run's accepted source catalog (`data/indices/source`) |
| `observed` | a tool observation lies on the defect's lines; the producers are listed |
| `selected` | an inference package (lead or hunt) whose lead menu has an entry on the lines is in a lane queue |
| `reviewed` | a red cell (`red_team_analyst`, `hypothesis_hunter`) of that package has a terminal record other than `not_launched`; the status counts and dominant gap class are recorded |
| `retrieved` | those cells' receipts record executed retrievals that returned rows (count and tools recorded; denied lookups are not rows) |
| `proposed` | a claim whose affected entity lies on the lines exists (ledger `claim_proposed`, or the published projection) |
| `challenged` | a blue cell recorded a disposition on the claim |
| `judged` | a `judge_verdict` ledger event (or judge cell result) exists for the claim |
| `verified` | the independent verifier recorded a disposition |
| `adjudicated` | the claim left the `proposed` state |
| `published` | the claim is in the final report's findings, verification backlog or withheld bucket; its ship-block status is reported |

A stage the run has no mechanism for at all is `not_applicable_in_this_run` (for example blue cells or a judge
in a run of the older protocol) and does not stop the chain. The judge is advisory: when a judge exists in the
run but did not rule on this claim, `judged` is `not_reached` and the chain continues. When several claims land
on one defect, the claim that got furthest (then the strongest state, then the smallest id) represents it, and
all claim ids and states are listed.

`stopped_because` is a machine-readable code, optionally with a `:detail` suffix, and a sentence:

| Code | Meaning |
| --- | --- |
| `file_not_in_catalog`, `no_tool_observation_at_location` | stopped at `available` / `observed` |
| `inference_review_absent` | the run has no inference review to follow |
| `no_lead_at_location` | no package lead lies on the lines, so nothing could be reviewed |
| `package_not_selected_cap` | a review package covers the lines but the inference job assembled none for it |
| `package_not_selected_lead_cap`, `package_not_selected_hunt_cap` | an inference package covers the lines but never entered that lane's queue |
| `red_not_launched` | the admitted package's red cells were never launched |
| `red_cells_<status>:<gap class>` | no red cell succeeded; the dominant terminal status and gap class (`red_cells_invalid:schema_error`, `red_cells_timed_out:budget_gap`) |
| `retrieval_all_denied:<code>`, `retrieval_empty`, `retrieval_not_attempted` | stopped at `retrieved`: every lookup denied (dominant denial code), lookups returned nothing, or none was made |
| `red_no_claim` | red cells succeeded and retrieved but proposed no claim on the lines |
| `blue_not_run`, `blue_cells_not_succeeded`, `verifier_not_run`, `verifier_cells_not_succeeded` | the stage exists in the run but not for this claim |
| `claim_not_adjudicated` | the claim is still `proposed` |
| `claim_contradicted_by_blue`, `claim_contradicted_by_verifier`, `judge_sided_with_blue`, `verifier_insufficient_evidence`, `claim_contradicted`, `claim_insufficient_evidence`, `claim_not_reachable`, `claim_not_exploitable`, `claim_duplicate`, `claim_out_of_scope`, `claim_coverage_gap` | the claim ended in that state, with the verdict that explains it taken first from the judge, then blue, then the verifier |
| `final_report_absent`, `not_in_final_report` | the claim is `supported` or `confirmed` but did not reach the report |
| `published_confirmed`, `claim_supported_not_confirmed`, `published_withheld` | published as a finding, in the unconfirmed verification backlog, or withheld |

How to read it: take the defect's `stopped_because` first; it names the stage to look at. `red_cells_*` and
`retrieval_*` point at the cells (the aggregate shows first-attempt parse rate, retrieval denials by code,
cells by terminal status, calls per cell and claims by state, all from the run's recordings, cell receipts
and ledger). `no_lead_at_location` points at lead generation, not the model. A defect that reaches
`published` with a judge verdict of `blue_correct` is published with a note, never hidden.

What the funnel cannot see: it links a claim to a defect only through the claim's resolvable affected
entities; a claim on an entity with no indexed location is counted in the aggregate but linked to no defect.
Hunt units are matched through the lead menu entries of their package, not through unit scope. `judge_verdict`
event fields follow `docs/architecture/review-judge-and-poc.md`; until a run records them, `judged` is
`not_reached` or `not_applicable_in_this_run`. The funnel is not evidence about the target: a defect that
stops early says the review did not look, never that the code is clean.

Operating notes: recreate the stack with `docker compose -f compose.yaml -f compose.claude.yaml up -d`, never
`compose.yaml` alone. A local run that consumes a hash recorded inside the container (the retrieval
manifest embeds `target_root`) needs `parity --container-paths`, which mounts the checkout at `/opt/app`
in a rootless namespace for the local side.
