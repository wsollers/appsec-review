# Bounded focused tests and serial operator recovery

This implements the operator-only safeguards for **T-057**, without changing release scoping,
job packages, frozen inputs, gate policy, signing enforcement or worker authority.
Session: WSOLLERS1 WSL, 2026-11-10. Base:
`076fdc3d28b2b0250ed0670261f84ed080d47a83`, confirmed by ancestry after an explicitly approved
fast-forward of the isolated `william-sollers-xbox-sturdy-system` branch. The parent owns
local-main integration and all live operations.

## Design and implementation

1. Fail closed on focused argv before pytest starts: exact existing test files/nodes, resolved
   scope, option-aware parsing, no root/dot/directory/file-glob tokens, duplicate or missing
   selectors, scope/report overrides or ambient `PYTEST_ADDOPTS`. A shell-expanded file list
   cannot be distinguished from an explicit list; use exact argv and an inspected expected count.
2. Preflight collection under 30 seconds, at most 200 tests, inside a 300-second total command
   budget. Explicit positive finite overrides and `--expect-tests` are visible in the command
   report. Every execution worker verifies the same final collection **before xdist scheduling**.
   On refusal, rejected nodes are withheld from the scheduler and the explicit failure/proof
   is retained; they are not silently deselected into a passing run.
3. Reuse the existing acceptance supervisor's gated subreaper/Windows Job Object primitives
   without changing the acceptance lane. Reserve cleanup inside the deadline, terminate only
   the owned tree (including Linux children that call `setsid`), and preserve collection/log/
   junit/timing/supervisor diagnostics. Baselines cannot hide timeout, refusal or uncertain
   cleanup, and those outcomes cannot overwrite a baseline.
4. Keep recovery serial: `recover --app-run RUN` verifies all current/archived walk, claim and
   tagged Dagster dispatches using the existing runtime stop verifier. After separate inspection
   and explicit admission, `recover --app-run RUN --plan FILE` verifies stops again and reuses
   guarded rewind. Replay `check`/`accept` verify stops before preserved-key comparison, covering
   newly completed successful replays. No command here admits, cancels, launches or accepts a
   graph. Old keys, provenance, checks, claims, independent acceptance and reacceptance evidence
   remain intact.

Only the existing proof-checked claim bookkeeping and the two named model-preflight inventory
workarounds are allowed. The inventory exemptions are temporary normalization defects of
passes 01 and 04, not permanent comparison rules: volatile advertised inventory belongs
outside compared accepted content, with raw evidence retained. The
[recovery guide](../operations/recovery-repair.md) defines the current strict boundaries and
the intended producer/key fix. Comparisons retain `unadjusted_differences` as well as final
differences and the exact allowed changes; meaningful differences still fail.

The user-directed revision raises the original 120-second total default to 300 seconds:
a correctly focused file of runner-driven tests can take 90-130 seconds before cleanup.
The earlier timeout demonstrated working enforcement of an undersized default, not a useful
failure of the tests. Collection remains capped at 30 seconds, scope at 200 tests, and
per-test limits remain unchanged. Historical results below retain their actual 120-second
configuration and failure status; they are not relabelled as 300-second runs.

Implementation ownership is `deploy/dagster/bin/{ops_tests,ops_test_guard,stepwise,stepwise_rewind}.py`,
their focused unit tests/`tests/operator_support.py`, and the directly related operator/testing
documentation. None of these paths matches the current release manifest's common, job,
validator or script input closure. The active deployment was not accessed to remeasure it.

## Initial focused verification (120-second default)

The first exact collection attempt failed because this checkout lacked `.venv/bin/python`.
The system Python 3.10 venv attempt lacked `ensurepip`; that incomplete, session-owned venv was
replaced with Python 3.12 through `uv venv --clear --python python3.12 .venv`.
`uv pip install --offline --python .venv/bin/python -e '.[test,dagster]'` restored only cached
dependencies. Editable import provenance resolved inside this worktree's `src/appsec_review`.

Exact file/node collection was inspected before execution. Final counts: guard 51, rewind 68,
operator `-k run_tests` 14 (167 deselected), documentation 1, TODO registry 5.
Collection commands used `.venv/bin/python -m pytest --collect-only -q`, an explicit
`--basetemp=test/tmp/repair-<area>-collect...`, and the exact file/node selector; no directory
or dot selector was passed to pytest.

Final focused commands (the operator wrapper repeats and verifies collection):

```sh
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 51 --parallel --test-workers 2 --shuffle-seed 11015 -- tests/test_ops_test_guard.py
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 14 --parallel --test-workers 2 --shuffle-seed 11015 -- tests/test_operator_scripts.py -k run_tests
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 68 --parallel --test-workers 8 --shuffle-seed 11015 -- tests/test_stepwise_rewind.py
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 5 --parallel --test-workers 2 --shuffle-seed 11013 -- tests/test_todo_registry.py
```

These passed respectively in pytest-reported **9.36 s, 7.78 s, 36.51 s, 1.98 s**; no skips or
tests over 10 seconds. Total command times were **14.219 s, 12.912 s, 41.567 s, 7.010 s**.
Each invocation's expanded argv, exact node manifest, total elapsed
including collection/cleanup, bounds and result remain in `test/tmp/reports/tests-custom-*.json`
and the adjacent logs, timings and process receipts in this worktree.

Failed iterations are retained, not relabelled as successes:

| Invocation suffix after `run-tests` | Outcome | Total seconds | Report suffix after `tests-custom-20261110-` |
| --- | --- | --- | --- |
| `--expect-tests 42 --parallel --test-workers 2 --shuffle-seed 11010 -- tests/test_ops_test_guard.py` | 41 passed, 1 failed: initial execution-refusal exit-code/proof contract | 16.359 | `180345-256638-68012.json` |
| `--expect-tests 68 --parallel --test-workers 2 --shuffle-seed 11010 -- tests/test_stepwise_rewind.py` | **Exit 124**, despite 68 passing assertions: total deadline expired during process shutdown; owned cleanup confirmed | 117.049 | `180345-166280-68011.json` |
| `--expect-tests 51 --parallel --test-workers 2 --shuffle-seed 11013 -- tests/test_ops_test_guard.py` | 50 passed, 1 failed: xdist hid the collection-refusal diagnostic | 14.158 | `181258-450183-69020.json` |
| `--expect-tests 2 --parallel --test-workers 2 --shuffle-seed 11014 -- tests/test_ops_test_guard.py::test_execution_collection_drift_is_refused_before_test_body` | 1 passed, 1 failed: pytest's unconditional collection-finish hook advertised rejected nodes to xdist | 8.004 | `181416-513001-69366.json` |

The two-node regression then passed in 3.46 s (8.202 s total), with no test body executed by the
rejected inner workers. The full guard file subsequently passed. The rewind rerun used eight
bounded workers, **not** a larger deadline or per-test limit. Tiny timeout regressions prove
both import/collection and execution timeouts, exhausted-before-start budgets, no surviving
owned descendants, intact diagnostics and an unrelated inert process remaining alive.

The repository-wide documentation-link check remains a named environment gap, not a pass:

```sh
.venv/bin/python deploy/dagster/bin/ops.py run-tests --strict --expect-tests 1 --parallel --test-workers 2 --shuffle-seed 11015 -- tests/test_documentation.py
```

It failed its one test in 1.56 s because two unchanged documents link into the absent
`targets/appsec-multi-vuln` checkout (`support/project-matrix.json` and `README.md`). This is
already in `scripts/known-failures.txt`; an initial non-strict invocation reported the same
failure but returned the existing known-failure-normalized zero, so it was repeated with
`--strict` and exited 1. Reports end in `181825-048958-69941.json` and
`181905-177751-69978.json`. No target files were created to hide the gap. The same link parser
checked all **four changed documents** directly: no missing links. Python compilation and
`git diff --check` also passed.

## Integration boundary

### User-directed revision verification (300-second default)

The additive revision is based on `b9134b6861b9aff3aeab51e527dd13f13f531c71`; the parent
reports that initial change integrated as `91f828945`. The parent owns the T-057 registry
update and authorized appending the normalization-defect notes to passes 01 and 04 without
altering their historical results. No new TODO ID or runtime publication change is introduced.

```sh
.venv/bin/python -m pytest --collect-only -q --basetemp=test/tmp/repair-300-collect tests/test_ops_test_guard.py
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 54 --parallel --test-workers 2 --shuffle-seed 11016 -- tests/test_ops_test_guard.py
```

Collection found 54 tests in 0.29 s; all 54 passed in 10.18 s (15.095 s total), with no skips or
tests over 10 seconds. New assertions pin the effective 300/30/200 defaults and explicit lower/
higher total overrides; existing scope refusal, collection mismatch, two-second timeout,
owned cleanup and baseline refusal cases still pass. Report:
`test/tmp/reports/tests-custom-20261110-183702-302620-83748.json`.
The earlier 120-second receipts remain unchanged. No 90-130-second or live test was run
merely to demonstrate the new numerical default.

The registry gate was collected explicitly with
`.venv/bin/python -m pytest --collect-only -q --basetemp=test/tmp/repair-300-todo-collect tests/test_todo_registry.py`
(5 tests, 0.23 s), then verified with
`.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 5 --parallel --test-workers 2 --shuffle-seed 11016 -- tests/test_todo_registry.py`
(5 passed, 1.98 s; report `tests-custom-20261110-183901-138594-92971.json`).
All six changed documents pass the existing local-link parser; `git diff --check` passes.
The previously recorded whole-tree missing-target documentation gap is unchanged.

### Unchanged operational limits

`scripts/run-tests.ps1` remains unchanged by parent decision because it is in the measured
script closure. Its existing surface uses the safe defaults; new count/time and explicitly
authorized heavy-mode controls use the Python `ops.py` CLI. Native Windows parity of those
parameter declarations is a scoped limitation, not a new TODO allocation.

The implementation agent performed no Docker, model, target or external-network execution;
no integration, acceptance, live review, full-suite, native Windows, merge, push, deployment
or reload. Unit fixtures fake
external Dagster/Git boundaries and use real guard, state, admission, publication and comparison
behavior. Manual live commissioning remains with the parent after resolving source/operator
freezes; these unit results are not evidence of a live run or its content quality.

## Parent integration and operator verification

The parent integrated the exact tested commit `b9134b6861b9aff3aeab51e527dd13f13f531c71`
into local `main` as **`91f82894520db1337cc87f2425617bbf446dccc3`**. The mounted checkout had
no nonterminal dispatches, and none of the changed paths belongs to its measured release
inputs. Deployed release `9966930659bf5359aa3f1503192d4793de96a3dae5f00120c249d2700cc2fa3a`
therefore remained unchanged; no reload, image rebuild or re-admission was needed.

In the integration checkout, with production profile/overlay/Dagster-home variables unset:

```sh
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 51 --parallel \
  --test-workers 2 --shuffle-seed 11015 -- tests/test_ops_test_guard.py
```

The inspected collection and execution each contained exactly 51 tests: **51 passed in 9.19 s**,
**14.317 s total**, no case over ten seconds, confirmed cleanup of both owned process trees.
The declared bounds stayed at 200 tests / 30 s collection / 120 s total. Report:
`test/tmp/reports/tests-custom-20261110-182826-739491-78630.json`.

The parent also exercised the authorized existing walk's operator path:

```sh
.venv/bin/python deploy/dagster/bin/stepwise.py recover --app-run 2026-11-10-0003 \
  --plan runs/c094-catalog-repair-plan.json
```

It verified all twelve recorded dispatches stopped, returned `ALREADY APPLIED`, launched no
jobs, and left `state.json` byte-identical. Log: `runs/loop-safeguards-recover.log`; before/after
hash receipts: `runs/loop-safeguards-state-{before,after}.sha256`. This verifies the idempotent
operator path, not another review run or heavy-tier test. No changes were pushed.

The integration checkout's exact `tests/test_documentation.py` selector also passed:
`ops.py run-tests --strict --expect-tests 1 --parallel --test-workers 2 --shuffle-seed 11015 --
tests/test_documentation.py`, one test in 1.56 s. Report:
`test/tmp/reports/tests-custom-20261110-183250-584161-78955.json`.
