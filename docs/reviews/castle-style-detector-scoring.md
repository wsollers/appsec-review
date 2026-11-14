---
title: "CASTLE-style detector scoring, negative controls and the CASTLE regression corpus"
kind: "review"
subsystem: "testing and operations"
status: "historical"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# CASTLE-style detector scoring, negative controls and the CASTLE regression corpus

Status: implemented 2026-11-02 in chunks A-E below (coordinator session). Changed 2026-11-11 by
[`../architecture/finding-metrics.md`](../architecture/finding-metrics.md) (T-063): report schema `/2`, the
published findings (`review`) scored by default, a function-scope and weakness-family match beside the strict
one, case-based accuracy (decision 7's per-report accuracy is no longer computed), detection marginals, and an
optional `severity` on `[[defect]]`. Where the decisions below differ, the code and that document are current. Live acceptance of case-094 and
the CASTLE-C250 scoring run are user-owned and not yet run.

Source: Dubniczky et al., "CASTLE: Benchmarking Dataset for Static Code Analyzers and LLMs towards
CWE Detection", TASE 2025, arXiv:2503.09433v2. Dataset: <https://github.com/CASTLE-Benchmark/CASTLE-Benchmark>
(MIT). The three items:

1. **Negative controls.** An answer key that lists only seeded defects cannot measure false positives.
   Keys gain fixed-twin negative controls (the "Metamorphic pairs" item of `docs/TODO.md`).
2. **Per-producer and combination scoring.** TP/FP/FN/TN, precision, recall, accuracy and the CASTLE
   score per producer, plus the CASTLE combination score over producer sets, to show which scanners
   earn their place and which are net-negative noise.
3. **CASTLE as a public C regression corpus.** A pinned, blind, buildable copy of CASTLE-C250 with an
   answer key held outside the target, so scanner wrapper or configuration breakage shows up against
   the paper's reference numbers. It is a public regression set, not a private holdout.

Everything here is **reported, never asserted**: no score changes `SYSTEM OK` / `SYSTEM FAILED`, and a
low score is a statement about detectors, never evidence that a target is clean.

## Decisions

1. **Key format.** `expectations.toml` keeps `[corpus]` and `[[defect]]` and gains `[[control]]`
   (negative controls). Fields of both tables:

   | Field | Required | Meaning |
   | --- | --- | --- |
   | `id` | yes | unique across defects and controls |
   | `path` | yes | target-relative POSIX path |
   | `line`, `end_line` | `line` yes | target lines `line..end_line` |
   | `lines` | no | explicit target-line list; overrides `line..end_line` for the hit test (CASTLE marks several lines) |
   | `cwe` | defect yes, control no | the defect's weakness; for a control, the weakness the code guards against |
   | `scope_start`, `scope_end` | no | attribution scope (decision 2); default is the target lines |
   | `scope` | no | `"file"`: the case covers the whole file (CASTLE: one file is one case) |
   | `pair` | no | id of the counterpart (a defect's fixed twin and the reverse) |
   | `upstream` | no | provenance name of the source test (CASTLE file name) |
   | `summary`, `producers` | no | as before; `producers` only on defects |

   `[corpus]` may add `scored_paths = ["..."]`: reports outside these path prefixes are ignored
   entirely (a key for one case of a multi-case target). The loader rejects duplicate ids, a `pair`
   naming a missing id, scopes in one file that overlap, and a scope that does not contain its lines.
   `answer_key.load_answer_key` is unchanged and still reads only `[[defect]]`, so
   `test/acceptance/cpp-multivuln-v1/` is untouched and keeps working. The new loader is
   `scoring.load_scoring_key(path) -> ScoringKey`.

2. **The scoring unit is a key case.** CASTLE assumes one file holds zero or one weakness; our corpora
   hold many. Each key entry is one case with an attribution scope. A report (same path, lines
   `[start, end]`) is attributed to the case whose scope, widened by the tolerance, contains its
   start line, else to the first case in line order whose widened scope overlaps it; scopes in one
   file never overlap (decision 1), so attribution is unique. A report in a scored path but in no
   scope is **unattributed**: listed per producer, excluded from the score and from P/R/A, because
   unlabelled code is not known to be clean.

3. **Match rule.** In a defect case, a report is a **hit** when its lines overlap the defect's target
   lines widened by `tolerance` (default 2; `--tolerance N`) and one of its CWEs is accepted for the
   key CWE by `data/reference/scoring/cwe-match.json` (a key CWE absent from the table accepts only
   itself). Non-hits are classified (`scoring_model.ReportOutcome`): `location_hit_cwe_miss`,
   `location_hit_cwe_unknown` (no CWE), `off_location` (in scope, off the lines), `control`,
   `unattributed`. Only `hit` is a true positive. A lenient location-only count (hit plus the two
   `location_hit_*` outcomes) is reported beside the strict one and never enters the score.

4. **Report identity and CWEs.** A report is `scoring_model.Report`: producer, path, lines, native
   rule, normalized CWEs, resolvable evidence reference. Reports of one producer with the same path,
   start line and rule collapse into one. CWEs come from the observation payload
   (`indexing.products.cwe_ids`), else from the pinned `data/reference/scoring/rule-cwe.json` by
   producer and rule, else none.

5. **Producers.** Every tool observation in the run's observation index shards
   (`data/indices/observations/**/*.sqlite`, kind `tool_observation`) is a report of the producer
   its payload names, lowercased, with a leading `tool-` removed. Real payloads name it in different
   fields, so the first present of `scanner`, `tool`, `common.scanner`, `tool_id`, `scanner_identity`,
   `producer` and `tool_identity.id` wins (`producer_reports.producer_name`); for example `codeql`,
   `cppcheck`, `semgrep`, `opengrep`, `clang-static-analyzer`, `clang-tidy` and `infer`. Observations
   with no producer or no location are counted as named gaps. With `--include-review`, rows of the
   accepted current final report (`answer_key.current_report_findings`) are reports of producer
   `review`; when that report is unavailable the review producer is a named gap, never zero reports.

6. **CASTLE score (paper eq. 1-2), per producer.** For a case with attributed reports `t`: a defect
   with a hit scores `5 - (|t| - 1) + B(cwe)`; a control with `t` empty scores 2; every other case
   scores `-|t|`. `B(c) = 5 - floor((S(c) - 1) / 5)` for a Top-25 rank `S(c) <= 25`, else 0, using the
   key CWE. The rank table is pinned in `data/reference/scoring/cwe-top25.json` with provenance. The
   default list is `castle-2025-table2`, the standings in the paper's Table 2 (which the paper
   attributes to MITRE's 2024 Top 25, though several differ from it), so CASTLE numbers are
   comparable with the paper; the actual MITRE 2024 list (`mitre-2024`) is pinned too and selectable
   with `--top-list`. Each report states the theoretical maximum (`sum over defects of 5 + B`, plus 2
   per control) and the silent-tool floor (2 per control). For CASTLE-C250 with the default list
   these are **1232** and **200**. The paper's text says 1250, which eq. 1-2 with its own Table 2 does
   not produce; we report the computed value.

7. **Plain metrics, per producer.** TP = defect cases with a hit; FN = defect cases without; TN =
   control cases with no attributed report; FP = attributed non-hit reports, counted per report as the
   paper's Table 3 does (its accuracy column is `(TP+TN)/(TP+TN+FP+FN)`, e.g. Cppcheck 2.13
   119/259 = 46%). `fp_cases` (cases with any non-hit report) is also given. Precision `TP/(TP+FP)`,
   recall `TP/(TP+FN)`, accuracy as above; an undefined ratio is `null`. A key with no controls (v1)
   still scores; TN is reported as not measurable with the gap `no_negative_controls`.

8. **Combination score.** For a producer set `P`, per case: a defect hit by any member scores
   `5 + B(cwe) - sum over k of extra_k`, where `extra_k = |t_k| - 1` for a member that hit and `|t_k|`
   for one that did not, so the true positive is credited once and every other report is a cumulative
   penalty; a defect nobody hit scores `-sum |t_k|`; a control scores 2 when every `t_k` is empty, else
   `-sum |t_k|`. With one producer this is exactly decision 6. The report gives the full set, the best
   subsets up to `--max-combination` (default 3) members among producers with at least one attributed
   report, and each producer's **marginal contribution** `score(F) - score(F \ {p})` over the full set
   `F`: positive earns its place, negative is net noise.

9. **Wiring.** `python -m appsec_review.acceptance.scoring --run <dir|run id> [--expectations TOML]
   [--tolerance N] [--include-review] [--producers a,b] [--max-combination K] [--top-list NAME]
   [--json]` prints or emits `appsec-review/detector-scoring/1`. `stepwise.py system` prints it after
   the funnel and stores it under `scoring` in its report JSON; a failure to build it is printed and
   recorded, never raised, and never changes the verdict. When the key is CASTLE-C250, the report sets
   the paper's reference numbers (`data/reference/castle/castle-c250.lock.json`) beside ours by
   producer, for comparison only.

10. **Paired case (item 1).** At the user's explicit direction the code goes into the
    `appsec-multi-vuln` corpus repository (`F:\XBOX-Repositories\appsec-multi-vuln`, remote
    `wsollers/appsec-multi-vuln`) and its answers go into the evaluator guide
    (`F:\XBOX-Repositories\appsec-multi-vuln-guide`), so the corpus carries no hint of which code is
    defective or correct. Both are worked on through the WSL links `~/projects/appsec-multi-vuln` and
    `~/projects/appsec-multi-vuln-guide`, on local branches `case-094` stacked on `polyglot-case-093`;
    nothing is pushed and nothing is written under `targets/` (the user pushes, pulls and pins).
    - *Corpus.* `projects/native/case-094` is a C++ CMake project with seven pairs for the v1
      weakness classes CWE-121, 416, 476, 190, 134, 78 and 798: one defective and one correct
      implementation of the same operation, both reachable from `main`, with neutral names, comments
      and commit message, registered in the README, `support/project-matrix.json` and the smoke
      scripts like earlier cases. The commit is tagged `appsec-multi-vuln-c094-v1` locally.
    - *Guide.* Seven `data/defect-inventory.json` records `case-094#1..7` and a new optional
      top-level `controls` array (`case-094#c1..c7`, each with `pair`, `why` and located `construct`s)
      that the guide's validator and renderer check, with the rubric rule that a report on a control
      is a false positive and a silent control a true negative.
    - *Key.* `test/acceptance/appsec-multi-vuln-c094-v1/expectations.toml` is derived from the guide
      at the pinned corpus and guide commits: paths from the target root,
      `scored_paths = ["projects/native/case-094"]`, function scopes, seven defects and seven controls
      linked by `pair`. It has no baselines or seeds until the user's live acceptance produces them.
      The cpp-multivuln checkout behind v1 is not on this host and is not recreated.

11. **Default key.** `funnel.DEFAULT_EXPECTATIONS` (and the scoring CLI default) stays
    `test/acceptance/cpp-multivuln-v1/expectations.toml`, the only key with accepted baselines. Other
    keys are passed with `--expectations`. v1 is never mutated.

12. **CASTLE corpus (item 3).**
    - *Pin.* `data/reference/castle/castle-c250.lock.json`: upstream URL, commit
      `c7391c9ec5dd944653103fbf55e7ebbf85842d82`, dataset version 1.2 (2025-03-13), SHA-256 of
      `datasets/CASTLE-C250.json`, MIT licence and attribution, and the paper's Table 3 reference rows.
      At this commit the `.c` files carry no YAML header or `{!LINE}` markers; the metadata (`cwe`,
      `vulnerable`, `lines`, `compile`) lives in the JSON, whose `code` equals each file byte for byte.
    - *Preparation.* `python -m appsec_review.acceptance.castle prepare --upstream <clone>
      --output <dir> --key <toml>` verifies the clone's commit and the JSON hash, then writes a blind
      git repository to `--output`, which must be outside this repository. The user clones it into
      `targets/` and pins it, as for every target.
    - *Blindness.* Files become `src/t<first 10 hex of sha256(salt + upstream name)>.c`, so names carry
      no CWE and no order. Comment text is blanked by a C lexer that respects strings, character
      literals and line continuations and keeps every newline, so line numbers are unchanged and the
      key's lines map identically. Every output path and file is checked with the same marker
      expression as `tests/test_blind_target_isolation.py`; a hit fails preparation and names the test.
    - *Build.* Upstream files are never edited. A generated, neutral `CMakeLists.txt` builds one
      executable per file and maps each upstream `compile` line to link libraries (OpenSSL, SQLite3,
      CURL through `find_package`; mysqlclient through pkg-config) and per-target flags. A missing
      library fails the configure step; it is not silently dropped. The current native-cpp image has
      OpenSSL and pkg-config but not the SQLite3, CURL or mysqlclient development packages (26 programs
      link them), so the whole configure fails there until the image owner adds them.
    - *Determinism.* One commit with a fixed author, committer and date, tagged `castle-c250-v1`, so the
      blind commit SHA is reproducible and recorded in the lock and the key
      (`9792c7495ab01a0f38968bce02ba5588ef4c133e`, reproduced from a fresh preparation).
    - *Key.* `test/acceptance/castle-c250-v1/expectations.toml`, generated: 150 defects (`lines` from
      the JSON) and 100 controls, all `scope = "file"`, each with `upstream`. It is committed (MIT,
      derived metadata, attributed), never placed in the target.

## Contract and chunks

The shared contract is `src/appsec_review/acceptance/scoring_model.py` (records, `ReportOutcome`,
`normalize_cwe`, reference paths). Chunks import it and never edit it.

| Chunk | Owns |
| --- | --- |
| A scoring core | `src/appsec_review/acceptance/scoring.py`, `data/reference/scoring/cwe-top25.json`, `data/reference/scoring/cwe-match.json`, `tests/test_detector_scoring.py` |
| B run reports | `src/appsec_review/acceptance/producer_reports.py`, `data/reference/scoring/rule-cwe.json`, `tests/test_producer_reports.py` |
| C CASTLE corpus | `src/appsec_review/acceptance/castle.py`, `data/reference/castle/**`, `test/acceptance/castle-c250-v1/expectations.toml`, `tests/test_castle_corpus.py`, `tests/fixtures/castle/**` |
| D paired case | `appsec-multi-vuln` `projects/native/case-094/**` plus its README, matrix and smoke rows; the guide's case-094 records and `controls`; `test/acceptance/appsec-multi-vuln-c094-v1/expectations.toml` |
| E wiring and docs (after A-D merge) | `deploy/dagster/bin/stepwise.py` system command, `docs/operations/acceptance-funnel.md`, `docs/processes/acceptance-and-regression-testing.md`, `docs/operations/test-targets.md`, `docs/TODO.md`, this design |

Interfaces between chunks:

- `scoring.load_scoring_key(path: Path) -> ScoringKey`
- `scoring.score(key: ScoringKey, reports: Iterable[Report], *, tolerance=DEFAULT_TOLERANCE,
  top_list=DEFAULT_TOP_LIST, max_combination=DEFAULT_MAX_COMBINATION, producers=None,
  gaps=(), reference=None) -> ScoringReport`, with `ScoringReport.as_dict()` (schema
  `appsec-review/detector-scoring/1`) and `render_lines(report) -> list[str]`
- `scoring.score_run(run_root, expectations, *, include_review=False, ...) -> ScoringReport`: the
  path shared by the CLI and `stepwise.py system`; it loads the key, the run's reports and the key's
  `reference_lock`
- `producer_reports.reports_from_run(run_root: Path, *, include_review: bool = False)
  -> tuple[list[Report], list[str]]` (reports, named gaps); paths relative to the target root

## Manual validation (owned by the user)

Scanner runs over CASTLE, reviews, `stepwise.py accept`/`system`, Dagster, live, integration and
acceptance runs are not run by the implementing agents. The exact commands are in
[`../operations/acceptance-funnel.md`](../operations/acceptance-funnel.md#detector-scoring).
