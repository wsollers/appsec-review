---
title: "Finding metrics: operator guide"
kind: "operations"
subsystem: "reporting and metrics"
status: "current"
jobs: []
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Finding metrics: operator guide

Design and rationale: [`../architecture/finding-metrics.md`](../architecture/finding-metrics.md).
This page is how to run what is implemented. Everything here is offline and derived: no command
launches a review, calls a model, contacts a crash service or reads a target. Performance and
provenance metrics are a different subject; see [`metrics.md`](metrics.md).

All commands run from the checkout's own Linux environment:

```sh
.venv/bin/python -m appsec_review.observability.findings <command> --help
```

Exit status is 0 on success and 2 for an unusable input, named on stderr. A figure that cannot be
computed prints as `n/a (<reason>)`; it is never printed as zero and never changes the exit status.

## 1. Publish a run's finding snapshot

```sh
.venv/bin/python -m appsec_review.observability.findings snapshot \
  --run runs/<run-id> --target-id <name> --source-revision <commit-or-changelist> \
  --history runs/metadata/finding-history \
  [--units <reviewed-units.json>] [--slice-rules <rules.json>]
```

The run is read through the verified readers the final report uses. A run whose current accepted
report cannot be verified is an error; nothing is published. The snapshot is content-addressed
under `<history>/<target-id>/snapshots/`; publishing the same snapshot again reports `duplicate`,
and a second, different snapshot of the same run and stage is refused.

- `--target-id` is your stable name for the target (`[a-z0-9][a-z0-9._-]*`). A run names its
  target by path and fingerprint, neither of which survives a new revision.
- Without `--units` the reviewed source files are derived from the run (T-073):
  - A catalogued file is **reviewed** when a review package that contained it had every red cell
    succeed. Its content hash is the accepted source catalog's. Reviewed means a review ran over
    the file, never that the file is clean.
  - Every other catalogued file is unreviewed with one reason: `cells_incomplete` (in a package
    whose red cells did not all succeed), `not_launched` (in a package no red cell was launched
    for) or `not_packaged` (in no assembled package). A run does not record the files of a review
    unit below the hunt cutoff, so those files are `not_packaged` too; the gap
    `units_below_hunt_cutoff:<n>` counts the units.
  - Files the run never catalogued are not listed.
  - When the derivation fails the snapshot has no units and the gap
    `reviewed_units_not_derived:<reason>` names why (no accepted review, an unreadable package or
    index, or an accepted index set that is no longer the one the review used). A later comparison
    can then only say `not_covered` for an absent finding.
- `--units` supplies the reviewed files yourself and turns the derivation off. Format:

  ```json
  {"schema": "appsec-review/reviewed-units/1",
   "reviewed": {"src/net/parse.c": "<sha256 of the file at this revision, or null>"},
   "unreviewed": {"src/mods/loader.c": "not_built"}}
  ```

- `--slice-rules` classifies findings by ownership, build configuration and component from path
  globs (`*` within a segment, `**` across segments, `?` one character):

  ```json
  {"schema": "appsec-review/finding-slice-rules/1",
   "ownership": {"engine": ["Engine/**"], "middleware": ["ThirdParty/**"], "default": "first_party"},
   "build_configuration": {"editor_or_test": ["**/Editor/**", "**/Tests/**"], "default": "shipping"},
   "components": [{"name": "netcode", "paths": ["Source/Net/**"]}]}
  ```

  A finding gets a value only when all its locations agree. Attacker position is never inferred.

## 2. Print the scorecard

```sh
.venv/bin/python -m appsec_review.observability.findings scorecard \
  --history runs/metadata/finding-history --target-id <name> --run-id <run-id> \
  [--prior-run-id <run-id>|none] [--key <expectations.toml>] \
  [--run-summary runs/<run-id>/data/telemetry/summary.json] \
  [--run runs/<run-id> | --leads <leads.json> --lead-labels <labels.json>] \
  [--outcomes <developer-outcomes.json> --as-of YYYY-MM-DD] \
  [--entry-points <catalogue.json>] \
  [--crash-evidence <evidence.json> --debug-id <id> --crash-revision <version>] \
  [--reviewed-kloc N] [--budget N] [--json] [--output <file>]
```

The page has four parts, always in this order: what the team gets, how far to trust it, what triage
did, where the review is blind. Every optional input enables a family; without it that family is
listed under "not measured" with its reason.

| Input | Enables |
| --- | --- |
| a prior snapshot in the store (default: the latest earlier run) | new, persisting, regressed, fix candidate, not re-detected, not covered |
| `--key` | this run's recall and control false positives with intervals; precision; severity agreement |
| `--run-summary` | refutation and silence as separate ratios, unresolved share |
| `--run` with `--key`, or `--leads` with `--lead-labels` | true-lead retention beside false-lead removal, by stage |
| `--outcomes` with `--as-of` | fix rate, rejected-as-false rate, accepted risk and expiry, time to disposition |
| `--entry-points`, or `--run` | share of entry points reviewed; the uncovered list |
| `--crash-evidence` | crash-corroborated findings; memory-safety crash buckets with no finding |

Reading rules:

- **Absent is not fixed.** `fixed` appears only after a targeted re-check
  (`observability.findings.recheck`) admitted a result that cites changed code. `fix_candidate`,
  `not_redetected` and `not_covered` are printed on their own line labelled "not progress".
- **Retention is printed with removal.** A triage that removes every lead shows true-lead
  retention 0 beside false-lead removal 1.
- **Intervals** are 95% Wilson intervals over independent units (key cases, labelled leads,
  findings). Stability figures over overlapping run pairs carry none.
- One run on a small key is a noisy estimate. Trend the repeated-run detection rate instead
  (section 5).

Lead records from the run (`--run`, T-077). `--run` names the run directory of `--run-id`; giving
it together with `--leads` or `--lead-labels` is an error. The run's lane A documents are read
through the verified readers of the `triage_reduction` section, so the dispositions are that
section's:

- One record per lane A lead. An admitted lead carries the section's disposition; a lead that was
  not admitted has none and is outside every ratio.
- The removing stage of a lead where no claim was raised is `red_no_proposal`. For a lead dismissed
  by adjudication it is `blue` when a refuter cell produced a contradiction the adjudication table
  counted on a required predicate, `verifier` when only the independent verifier did, and
  `unattributed` otherwise. `unattributed` covers `out_of_scope` (a scope rule dismissed the claim,
  no role did), a claim whose state history does not record the deciding row, a dismissal with no
  counted contradiction recorded, an unknown producing cell, and a lead whose claims were dismissed
  by different stages. Each is counted in a gap `dismissal_unattributed:<reason>:<leads>`.
- `judge` is never derived: a judge sets no claim state and the adjudication table does not count
  its relations, so a judge that sided with blue did not remove the lead.
- With `--key`, a lead is labelled by location only: `true` inside a defect's scope, `false` inside
  a control's scope (the lead then counts toward that control's false-positive rate), unlabelled
  elsewhere. Scanner rules often carry no reliable CWE, so the weakness is not compared. Lead
  locations come from the accepted observation index; when it cannot be read, or is not the index
  set the review used, there are no labels and the gap `lead_locations_unavailable:<reason>` says so.
- Gaps of the derivation are printed as `gap (derived input): …` and are in the document's
  `input_gaps`. Unreadable lane A documents give `n/a (no_lead_records)`, never an empty lead list.

Entry points from the run (`--run` without `--entry-points`, T-073). The catalogue is built from
the run's accepted `surface:entry:*` security tags:

| Tag | Kind |
| --- | --- |
| `surface:entry:http-public`, `surface:entry:http-internal`, `surface:entry:message-consumer` | `network_handler` |
| `surface:entry:rpc` | `rpc_handler` |
| `surface:entry:file-input` | `file_loader` |

- An entry point is `reviewed` when its file is reviewed (section 1), `not_built` when its file is
  under no accepted build unit, and otherwise `not_admitted` with its file's reason.
- No tag marks a parser, so the `parser` kind is never derived
  (`entry_point_kind_unmapped:parser`). The other entry terms (`cli`, `env-config`, `local-ipc`,
  `mobile-deeplink`, `cloud-public`, `ci-untrusted`) are none of the four kinds and are counted in
  `entry_tags_without_kind:<n>`.
- The tagging producers assign no `surface:entry:*` tag today. Until one does, the derived
  catalogue is `n/a` with the gap `entry_points_not_derived:no_entry_point_tags`; supply
  `--entry-points` to measure entry-point coverage in the meantime. The file is a list of
  `{"entry_id", "kind", "path", "status", "reason"}` rows.

Without `--run`, `--leads` is a list of `{"lead_id", "admitted", "disposition", "removed_stage",
"family", "scanner", "control_id"}` records and `--lead-labels` maps a lead id to a label.

Developer outcomes file (`fingerprint` is the finding's `fingerprint.exact` from the snapshot):

```json
{"schema": "appsec-review/developer-outcomes/1", "target_id": "<name>", "outcomes": [
  {"fingerprint": "<64 hex>", "disposition": "fixed|rejected_false|accepted_risk|duplicate",
   "opened_on": "2026-11-01", "decided_on": "2026-11-05", "expires_on": null}]}
```

`accepted_risk` requires `expires_on`. `--as-of` is the evaluation date; the clock is never read.

## 3. Ingest crash reports

```sh
.venv/bin/python -m appsec_review.observability.findings crash-ingest \
  --source stackwalk_json=<file-or-directory> --source sanitizer_report=<file-or-directory> \
  --source sentry_event=<file-or-directory> \
  --strip-root /home/builder/src/ --output <evidence-directory>
```

Sources are files you already exported. The command makes no network call, runs no tool and reads
no raw minidump. Adapters:

| Adapter | Input you export |
| --- | --- |
| `stackwalk_json` | the JSON a stackwalker printed for a minidump (for example rust-minidump `minidump-stackwalk --json`); this is how Crashpad, Breakpad, Windows and Unreal minidumps arrive |
| `sanitizer_report` | AddressSanitizer, UndefinedBehaviorSanitizer or ThreadSanitizer text logs |
| `sentry_event` | exported Sentry event JSON |

Not implemented: Crashpad or Breakpad integration, fetching from any crash service, walking raw
`.dmp` files, symbolication (T-075). Field handling was written from each format's public
documentation; check the first real export of each kind against the adapter before relying on it.

What is kept is only the normalized record: fault class, crashing-thread frames (function,
target-relative file, line, module, offset), module identifiers, version. User, device, host and
session identifiers, addresses, environment, command lines, breadcrumbs, tags and messages are
dropped at parse time. `--strip-root` removes the build machine's path prefix; a frame path under no
given root is stored as unknown, never as an absolute path. A file that fails to parse is counted
by its SHA-256 and error class; the batch continues.

The fault class orders buckets for review (write and execute faults, sanitizer memory errors and
heap corruption first; near-null reads and assertions last). It is an ordering, not a severity and
not an exploitability claim.

On the scorecard a crash bucket binds to the reviewed code by build identifier (`--debug-id`),
revision (`--crash-revision`) or symbol. A published finding is crash-corroborated when a bound
bucket has a frame in the finding's function, or in its file within its lines, and the fault class
is compatible with the weakness family. Corroboration is evidence for the judge and a label source;
it never confirms a claim by itself. Memory-safety buckets bound to reviewed code with no finding
at any frame are counted under "where it is blind".

## 4. Draw an audit sample of removed leads

```sh
.venv/bin/python -m appsec_review.observability.findings audit-sample \
  --leads <leads.json> --seed <text> --size N --output <sample.json>
```

`leads.json` is a list of `{"lead_id", "disposition"}`. The sample is drawn only from leads that
were dismissed or raised no claim, is reproducible for a given seed, and is never overwritten. A
person labels the sampled leads `true`, `false` or `unresolved`; the labelled sample gives the
audit miss rate with its interval (`triage.audit_miss_rate`).

## 5. Repeated corpus runs (user-owned)

Single-run recall on a small key moves many points per defect. To measure detection and stability,
review the same pinned corpus revision at least five times under one configuration, publish each
run's snapshot (section 1), then compute from Python:

```python
from appsec_review.observability.findings import history, labels, stability
loaded = history.load_history(store, "<name>")
runs = [history.read_snapshot(store, "<name>", row["sha256"]) for row in loaded["snapshots"]]
series = stability.series(runs, subset="actionable")       # adjacent and pairwise stability, recurrence
flaps = stability.flapping(runs)                           # severity or state changing between runs
detected = [{"run_id": run["run_id"],
             "detected": [case for case, hits in labels.key_case_hits(key, run["findings"]).items()
                          if hits and case in defect_ids]} for run in runs]
rates = stability.detection_rates(detected, defect_ids)    # per-defect rate with Wilson interval
```

`stability.detection_alarm(baseline, candidate)` and `integrity.canary_drift(baseline, candidate)`
flag a defect whose detection interval fell below its earlier interval. They are operator alarms,
never run verdicts. `stability.experiment_document` turns the same snapshots into an
`appsec-review/quality-experiment/1` input for the existing experiments domain
([`glasswing-experiments.md`](glasswing-experiments.md)); it maps the published stage to that
domain's `verified` stage and names a gap when one finding was cited on different lines in two runs.

The review runs themselves are live validation and run only at the user's request.

## 6. Detector scoring and trend comparison changes

- `python -m appsec_review.acceptance.scoring` and `stepwise.py system` now score the published
  findings (producer `review`) by default; `--no-review` scores scanners only. Each producer line
  adds `scope_tp`, `scope_fp`, `scope_precision`, `scope_recall` and `headline`; `review`'s headline
  match is function scope and weakness family, scanners' is the strict line-and-CWE match.
  `accuracy` is case-based. `scoring detection <producer> unique_tp=… fp=…` lines give each
  producer's unique detections and false positives. Report schema: `appsec-review/detector-scoring/2`.
- A `[[defect]]` in `expectations.toml` may carry `severity = "low|medium|high|critical"`.
- `observability.quality.compare_trends` compares observations of the same corpus, role, variant,
  case count and scorer, and reports which of implementation, configuration, prompts and model
  `changed` or are `unknown`, with `deltas` per metric. `python -m appsec_review.observability.quality
  --run <run-dir>` refuses a supplied identity that contradicts the run's frozen record.

## 7. Fix-pair corpora and the holdout ledger

`observability.findings.corpus.load_fix_pairs(path)` reads a TOML corpus of pre-fix and post-fix
revision pairs, `expand` gives the keyed expectations (`still_present` before the fix, `fixed`
after), and `write_scoring_key` writes an `expectations.toml` for one side, never inside a
`targets` path. A corpus marked `holdout = true` is used only through
`record_holdout_use(ledger, corpus, purpose="evaluation", ...)`; any other purpose is refused and
every use is recorded. No real pairs are checked in yet (T-067): choosing and pinning them is
user-owned.

## 8. Tests

Unit tests (run by anyone, smallest relevant selection):

```sh
.venv/bin/python -m pytest -q tests/test_finding_*.py tests/test_crash_*.py \
  tests/test_detector_scoring.py tests/test_operations_quality.py \
  -n 8 --shuffle-seed=<n> --basetemp=test/tmp/<name>
```

Manual suites, written and **not run** by the implementing session; they run only at the user's
request:

```sh
# Integration: a real scripted review, gate and report chain read through the verified readers.
.venv/bin/python -m pytest -q tests/integration/test_finding_metrics.py \
  --basetemp=test/tmp/finding-metrics-integration

# Acceptance: the operator workflow in child processes over a disposable store.
.venv/bin/python -m pytest -q tests/acceptance/test_finding_metrics.py \
  --basetemp=test/tmp/finding-metrics-acceptance
```
