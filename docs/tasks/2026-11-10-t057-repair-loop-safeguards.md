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
2. Preflight collection under 30 seconds, at most 200 tests, inside a 120-second total command
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
equivalences are allowed. The [recovery guide](../operations/recovery-repair.md) defines their
producer/artifact boundaries. Comparisons now retain `unadjusted_differences` as well as final
differences and the exact allowed changes; meaningful differences still fail.

Implementation ownership is `deploy/dagster/bin/{ops_tests,ops_test_guard,stepwise,stepwise_rewind}.py`,
their focused unit tests/`tests/operator_support.py`, and the directly related operator/testing
documentation. None of these paths matches the current release manifest's common, job,
validator or script input closure. The active deployment was not accessed to remeasure it.

## Focused verification

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

`scripts/run-tests.ps1` remains unchanged by parent decision because it is in the measured
script closure. Its existing surface uses the safe defaults; new count/time and explicitly
authorized heavy-mode controls use the Python `ops.py` CLI. Native Windows parity of those
parameter declarations is a scoped limitation, not a new TODO allocation.

No Docker, model, target or external-network execution; no integration, acceptance, live review,
full-suite, native Windows, merge, push, deployment or reload was performed. Unit fixtures fake
external Dagster/Git boundaries and use real guard, state, admission, publication and comparison
behavior. Manual live commissioning remains with the parent after resolving source/operator
freezes; these unit results are not evidence of a live run or its content quality.
