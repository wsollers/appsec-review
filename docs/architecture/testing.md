# Testing architecture

Rules for repository agents live in [`../../AGENTS.md`](../../AGENTS.md) ("Verification"). This
page describes how the test tiers are built, collected and run, and the standards each tier is held
to. Where this page and `AGENTS.md` differ, `AGENTS.md` wins and this page is corrected.

## Tiers

| Tier | Location | Collected by bare `pytest` | Who runs it | Needs |
| --- | --- | --- | --- | --- |
| Unit | everything under `tests/` except the paths below | yes | anyone, on every change, smallest relevant selection | the `test` extra (`dagster` extra for `tests/orchestration/dagster`) |
| Integration | `tests/integration/` | no; only when named explicitly | the user, on explicit request | Docker, tool images, target checkouts, sometimes model access |
| Bounded acceptance | `tests/acceptance/`, driven by `scripts/run-tests.* --acceptance <profile>` | no | the user, on explicit request | see [`bounded-acceptance.md`](bounded-acceptance.md) and [the operator guide](../operations/bounded-acceptance.md) |
| Live / system | `tests/live/`, `tests/test_live_*.py`, Dagster review runs, `stepwise.py system` | no | the user, on explicit request | the Dagster stack, Docker, real models, an opt-in `APPSEC_*` variable naming the run or tag |

Per-job correctness, parity and system acceptance (SAT/SIT) are described in
[`../processes/acceptance-and-regression-testing.md`](../processes/acceptance-and-regression-testing.md).

`tests/conftest.py` enforces the collection boundary: `pytest_ignore_collect` drops
`tests/integration`, `tests/acceptance`, `tests/live` and `tests/test_live_*.py` unless one of
those paths is passed on the command line. Explicit selection collects them; it does not authorize
running them.

## The unit harness

Everything below is implemented in `tests/conftest.py` and applies to every test it collects.

- **Temporary state.** `--basetemp` and the pytest cache must stay under `test/tmp/`
  (`pyproject.toml` sets `--basetemp=test/tmp`); the harness rejects overrides outside it. Give each
  concurrent or focused session its own `--basetemp=test/tmp/<session-name>`.
- **Production-sizing guard first.** `tests/test_000_unit_environment_guard.py` is reordered to be
  the first item of every session (`pytest_collection_modifyitems`). It fails, listing each
  offending variable, when the session would resolve production sizing: a non-`dev`
  `APPSEC_REVIEW_PROFILE`, any `APPSEC_REVIEW_CONFIG_OVERLAY`, an `APPSEC_REVIEW_CONFIG` other than
  the checkout's `appsec-review.toml`, any `APPSEC_NATIVE_*` variable, any `DAGSTER_HOME`, an
  `APPSEC_ACCEPTANCE_ROOT` / `APPSEC_ACCEPTANCE_RUNS_DIR` binding, or resolved sizing values that
  differ from the checked-in dev values. Expected values are derived from the files, not hard-coded.
  It never skips and never scrubs the environment. Under xdist the controller runs the same check as
  a preflight before workers start.
- **Timing table.** Every test's start, finish, setup/call/teardown durations, worker and outcome
  are written to the SQLite table `test_timings` in `<basetemp>.timings.sqlite`, next to the base
  directory. Query it while a run is in progress, for example
  `SELECT nodeid, duration_s FROM test_timings ORDER BY duration_s DESC LIMIT 10`.
- **Slow-test list.** The terminal summary ends with `tests slower than 10s: N` and the offending
  node ids. That list is work to fix, not noise.
- **Order and parallelism.** `pytest-xdist` is in the `test` extra. `--shuffle-seed=<int>` shuffles
  the collected order deterministically (the guard stays first) and prints the seed in the header,
  so an order-dependent failure is reproducible.
- **Unit-only fakes.** An autouse fixture stops run-completion hooks from starting the LaTeX
  telemetry container in unit tests; integration and live tests keep the real renderer.
- **Missing targets.** `@pytest.mark.requires_target("<name>")` skips, naming the absent
  `targets/<name>` checkout.

## Unit-test standards

1. **Independent.** No shared mutable state, ordering assumptions or reliance on another test's
   files, fixtures or side effects. Each test passes alone, in any order and in parallel.
2. **Under 10 seconds** per test (setup, call and teardown together) unless the user has approved
   longer. Meet it by making the test narrower or faster, never by weakening assertions, skipping
   coverage, raising timeouts, or moving a heavyweight test into the unit tier.
3. **Deterministic collection.** Parametrize from sorted sequences, never sets or directory
   listings in filesystem order, so every worker collects the same ids. Ids are short, printable and
   contain no newline or carriage return; pass `ids=` when the values are long or multi-line.
4. **Real behavior, fake boundaries.** Exercise the code under test; fake only external boundaries
   (subprocess, network, model, container engine). Fixtures that build handoffs or evidence must
   produce what the current admission rules accept, not bypass them.
5. **No production environment.** Never read the production profile, overlays, `/opt/app`,
   `/var/lib/appsec-review-*`, the running Dagster instance, or `runs/`. The guard enforces the
   configuration part.
6. **Skips name what is missing.** A skip is a coverage gap, never a pass. No `xfail` to hide a
   failure.
7. **Real Docker is not a unit dependency.** A small set of unit-collected tests still start real
   containers and skip without the engine or images; they are listed as deferred work in
   `AGENTS.md`. Tests that only assert `docker` argv through fakes are ordinary unit tests.

## Standards for integration, acceptance and live tests

These tiers are slower and depend on the host, but the same principles apply:

- **Isolation.** Each test or case owns a fresh workspace under a unique `test/tmp/<name>` (or the
  acceptance supervisor's private workspace) and never reads or writes production `runs/`, Dagster
  storage or the deployment's data volumes. Cases do not depend on each other's outputs unless the
  dependency is declared, as acceptance stages are.
- **Declared time budgets.** Each case carries an explicit cap. Bounded acceptance enforces its own
  (60 s per ordinary case, declared exceptions, 600 s per profile). For `tests/integration` and
  `tests/live` the harness (`tests/time_budgets.py`, wired in `tests/conftest.py`) fails any test
  whose setup, call and teardown together exceed its budget:

  | Tier | Default | ini option | Rationale |
  |---|---|---|---|
  | integration | 300 s | `integration_time_budget_seconds` | a Docker probe plus one bounded build or tool command, whose own timeouts are 60–180 s |
  | live | 1800 s | `live_time_budget_seconds` | one CodeQL database (bounded at 900 s) plus its query run |

  The defaults live in `[tool.pytest.ini_options]` in `pyproject.toml`; lower or raise them for one
  run with `-o integration_time_budget_seconds=<seconds>`. A test or module that legitimately needs
  longer declares `pytest.mark.time_budget(<seconds>, reason="...")`; the reason is mandatory and the
  declaration is a reviewed change. Module-scoped fixtures charge their setup to the module's first
  test, which is why the whole-review live modules declare 14400 s (not yet calibrated from the
  timing table). The check runs after each phase ends: it reports overruns, while a hung test is
  stopped by its own internal timeouts. A cap is never raised to make a slow case pass. Unit tests
  have no hard budget; their 10 s limit is enforced by the end-of-run slow-test list.
- **Deterministic selection and ids,** as for unit tests.
- **Opt-in, named prerequisites.** A test that needs Docker, images, targets, models or a run id
  gates on an `APPSEC_*` variable or a probe and skips naming what is missing. A skip is reported as
  a gap.
- **Timing.** The same timing table is recorded whenever these tiers run through pytest; report
  their durations beside the result.
- **Who runs them.** Only the user, or an agent at the user's explicit request for that run. Never
  as an automatic repair, merge or completion gate.

## Working loop

1. Run the smallest selection that covers the change, with explicit file selectors and a unique
   base directory: `python -m pytest -q tests/test_x.py --basetemp=test/tmp/<name>`.
2. Before integrating, run the affected files shuffled and in parallel with a bounded worker count:
   `python -m pytest -q -n 8 --shuffle-seed=<seed> tests/test_x.py tests/test_y.py --basetemp=test/tmp/<name>`.
   Do not use `-n auto` on a shared host; it starts one worker per core.
3. If a failure appears only in the shuffled or parallel run, re-run that node id alone. If it passes
   alone, it is an order or isolation defect in the tests, and fixing it is in scope.
4. For a whole-suite gate, run `python -m pytest -q -rfEs -n 8 --basetemp=test/tmp/<name>` with no
   positional arguments, save the output under `test/tmp/`, and first prove the exclusion with
   `--collect-only -q` (no `tests/integration`, `tests/acceptance`, `tests/live` or
   `tests/test_live_*.py` ids).
5. Group failures by their exception and message, not by file, and check each group against a
   baseline commit in a separate worktree to separate pre-existing failures from regressions.
6. Record each command, elapsed time and result, and name any integration, acceptance or live
   validation that is still needed.

## Known failures

`scripts/known-failures.txt` lists node ids that fail without any change of yours, one
`<node id> | <reason>` per line; `scripts/run-tests.* --strict` ignores it. Each entry carries a
reason, an entry is removed in the same commit that fixes the failure, and the list is not a
substitute for fixing or reporting a failure.

## Operator wrapper

`scripts/run-tests.sh` and `scripts/run-tests.ps1` wrap these commands for named suites and
bounded acceptance profiles; see
[`../operations/operator-scripts.md#run-tests`](../operations/operator-scripts.md#run-tests).
`--parallel` runs `--test-workers` xdist workers (default 8, never `auto`), and named suites other
than `live` run shuffled with a printed `--shuffle-seed` (reproduce with `--shuffle-seed <n>`, opt
out with `--no-shuffle`).
