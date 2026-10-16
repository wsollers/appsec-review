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
`appsec-review compare --baseline <x> --candidate <run-root>`: normalize both runs, diff into
`job-status` / `gap-added` / `finding-added` / `coverage` / `volatile`, exit non-zero on anything
but `volatile`. Primarily a diagnostic — "what changed between these two runs" was the question
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
