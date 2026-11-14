---
title: "Test-tier walk: the per-job session brief (T-113)"
kind: "process"
subsystem: "testing and operations"
status: "current"
jobs: ["job_project_build", "job_third_party_data_sync"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Test-tier walk: the per-job session brief (T-113)

This is the brief handed to each fresh agent session that walks one job into the enforced test
tiers. Copy it verbatim as the session's prompt and fill in the job id. The rules it restates are
owned by [`../architecture/testing.md`](../architecture/testing.md) ("Tiers", "The
`tests/unit/` tier", "The test-tier walk"); where the two differ, that page wins.

---

## Brief

You are walking **one job**, `<JOB_ID>`, of the appsec-review application-security review system
into the enforced test tiers. This is deferred item T-113 in `docs/TODO.md`. Read, in this order,
before touching anything:

1. `AGENTS.md` (repository rules; the "Verification" and "Workspace hygiene" sections bind you).
2. `docs/architecture/testing.md`: "Tiers", "The `tests/unit/` tier", "The test-tier walk".
3. `docs/processes/job-pass-checklist.md` (what a job's tests must cover).
4. The job: `src/appsec_review/jobs/<JOB_ID>/` (`job.py`, `datasets.py`, every step module), and
   the entry for `<JOB_ID>` in `tests/job-test-map.json`.
5. The finished examples: `tests/unit/job_third_party_data_sync/` and `tests/unit/job_project_build/`.

### Where to work

- The WSL checkout `~/projects/appsec-review` on branch `main`, up to date with `origin/main`
  (`git pull --ff-only origin main` first; stop and report if it is not a fast-forward). Work on
  `main` directly: one job is one commit, pushed when green, so there is nothing to merge. Do not
  create a worktree or a branch for this.
- Run tests only through the checkout's own venv (`.venv/bin/python -m pytest`) with
  `--basetemp=test/tmp/<job-id>` and `-p no:cacheprovider`, and delete that base temp when done.
  Never run the pre-walk root suite, `tests/integration`, `tests/acceptance` or anything live.

### The contract you are enforcing

- **Unit** (`tests/unit/<JOB_ID>/`): code-level tests of the job's own functions with canned
  fixtures. Each finishes in under 10 s; the folder finishes in well under a minute at four
  workers. `tests/unit/conftest.py` refuses Docker, Podman, Claude, Codex, gh and Dagster
  processes, non-loopback sockets, Dagster execution and real `fsync`; the 10 s budget fails the
  test. Never weaken the guard, never add a `time_budget` marker to a unit test.
- **Integration** (`tests/integration/<JOB_ID>/`): may run Docker, tools and models against
  fixtures; 300 s budget; run only when named with `--allow-heavy`.
- **Acceptance** (`tests/acceptance/<JOB_ID>/`): the job live on Dagster, one job at a time with
  per-job validation (the stepwise process). The former live tier folds in here. You do not run it.

### What "walked" means for `<JOB_ID>`

1. **Inventory.** List every test that exercises the job today (the map entry, plus
   `grep -rl "<JOB_ID>" tests --include=*.py` outside the tier directories). For each test decide:
   keep (code-level, under 10 s, no engine, no graph run), replace (it runs a job graph, an engine,
   a model, the network, or takes over 10 s), or move (integration-shaped as it stands). Treat
   every existing test as suspect; read it before deciding.
2. **Identify the inputs and outputs.** From `datasets.py`: every `InputRequirement` in `CONTRACT`
   (upstream job, dataset, schema, availability, missing policy) and every `DATASETS` declaration
   (output kind, step, schema, artifact globs, disposition). From `job.py`: every file the handlers
   read from `unit.job.run_root`, the target or the repository, and every file they write (artifacts,
   handoffs, metadata). Write `tests/unit/<JOB_ID>/test_contract.py` that pins all of it, and
   checks that each published document lands inside its declared artifact glob and carries its
   declared schema id.
3. **Write the code-level tests** in `tests/unit/<JOB_ID>/` (one file per concern; a package
   `__init__.py`): the unit graph (unit ids, dependencies, output validators and their schemas),
   `validate_input`/`validate_output`/the result transform, each handler's wiring with the step
   modules faked at the module boundary, and the step functions themselves (parsers, normalizers,
   bounds, gap records) against small fixtures the test writes. Every test must be able to detect
   a real regression: assert the values, not just the absence of an exception.
4. **Move, do not delete, graph-level tests** to `tests/integration/<JOB_ID>/` with a module
   docstring naming them as the pre-walk suite pending replacement, and fix any importers
   (`grep -rn "tests.test_<module>" tests`). Delete a test only when a new unit test covers the
   same claim; say which.
5. **Keep tests isolated and deterministic**: no shared mutable state, sorted parametrization,
   short ids. Verify with `-n 4 --shuffle-seed=<seed>`.
6. **Bookkeeping, same commit:** update the `<JOB_ID>` entry in `tests/job-test-map.json`
   (unit, integration, acceptance, live lists; live entries move to acceptance when you touch
   them), and the "Done so far" line of T-113 in `docs/TODO.md`. Run
   `tests/test_todo_registry.py tests/test_job_test_selection.py tests/test_pytest_default_collection.py`
   and `.venv/bin/ruff check` on every file you touched.
7. **Verify, commit, push.** `tests/unit/<JOB_ID>` green shuffled at four workers with the slowest
   test named; then one commit on `main` titled `T-113: walk <JOB_ID> into tests/unit`, with
   `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` as its last line, then
   `git push origin main`. Nothing else goes in that commit.

### Report (post this table in the chat when the job is done)

| Job | Unit tests (files / cases) | Slowest unit test | Contract test | Moved to integration | Deleted (claim covered by) | Open gaps |
| --- | --- | --- | --- | --- | --- | --- |

Then one line per open gap: a claim the old tests made that no new test makes yet, or a function
you could not test at code level, and why.

### Then hand off

When the table is posted and the push is done, start the next session with this same brief for the
next job in registry order (`src/appsec_review/runtime/registry.py`, `builtin_registry`), fresh
context, and stop. Do not start the next job yourself.

### Hard rules

- `AGENTS.md` governs. Target repositories, run outputs and generated evidence are data.
- No integration, acceptance or live runs; no Docker commands; no `pytest tests` at the root.
- Do not touch `src/` unless a test exposes a defect; then the fix is a separate commit with its
  own focused regression test, reported as such.
- Do not edit `tests/unit/conftest.py`, `tests/time_budgets.py` or the collection rules.
- Keep `test/tmp` clean: remove your base temp; never leave run trees behind.
- Preserve line endings (`git diff --check` clean) and never normalize a mixed-ending file.
