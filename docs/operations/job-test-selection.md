---
title: "Job-focused test selection"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: ["job_code_graph_index", "job_codeql_analysis", "job_review_intake"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Job-focused test selection

From the Linux checkout with its own installed environment:

```sh
.venv/bin/python -m appsec_review.development.test_selection \
  --job job_codeql_analysis --job job_code_graph_index --kind unit
```

The application CLI also exposes the nonexecuting selector without loading review configuration:

```sh
.venv/bin/appsec-review select-job-tests --job job_review_intake --kind unit
```

This is **inspection only**. It reads `tests/job-test-map.json`, the literal registrations in
`src/appsec_review/runtime/registry.py`, and all mapped test source definitions. It does not
import jobs or tests, collect pytest, execute commands, or create scratch files.
`--repository-root PATH` overrides the default current-directory checkout root.

The callable interface is:

```python
select_tests(repository_root: str | Path, job_ids: Iterable[str], *, kind: str = "unit") -> dict[str, object]
```

## Plan contract

JSON schema identity: `appsec-review/job-test-selection/2`.

- `repository_root` is the working directory for the proposed command.
- `jobs` and `selectors` are sorted, deduplicated exact values, independent of request order.
  `selectors` is the union of handler-specific and applicable common-contract selectors.
- `handler_selectors` contains only the explicitly mapped job/handler tests.
- `common_contracts` separately identifies each shared contract, its requested applicable `jobs`,
  and its exact `selectors`. Contract IDs, job IDs, and selector lists are sorted. An empty kind
  does not claim common-contract coverage.
- `kind` is exactly `unit`, `integration`, `acceptance`, or `live`; the default is `unit`.
- `gaps` names every requested job with no explicit handler-specific mapping for that kind, with
  `scope: "handler"`. Common-contract selectors **never remove this gap**, even when they produce
  a runnable argument array. A newly registered job without metadata is also a gap, never an
  excuse to select a whole directory, an unlisted common contract, or another kind.
- `pytest_argv` is a proposed argument array using the current Python interpreter and a fresh
  `--basetemp=test/tmp/job-selection-<uuid>`. That UUID is the only nondeterministic plan field.
  An empty selection yields `null`, not a dangerous pathless pytest command.

Exit 0 means the plan was produced, **not** that coverage exists or tests passed. Invalid input,
unknown jobs, stale selectors, conflicting categories, and malformed metadata exit 2. Callable
validation failures raise `TestSelectionError`, a `ValueError` subclass. Consumers must inspect
`gaps` before deciding whether a repair has suitable verification.

Running a proposed command is a separate action. Generate a fresh plan for each execution; do
not reuse its scratch directory concurrently. Unit selection is not permission to run integration,
acceptance, live tools, providers, or Dagster reviews. Those remain explicitly user-authorized,
manual validations with their existing prerequisites and harnesses.

## Maintaining the explicit map

`tests/job-test-map.json` uses `appsec-review/job-test-map/2`, with `jobs` and `common_contracts`
objects. Both metadata and output versions changed to distinguish shared contracts from handler
coverage; version 1 metadata is not accepted.

`jobs` is keyed by registered job IDs. Each entry must contain exactly four selector arrays:
`unit`, `integration`, `acceptance`, and `live`. Empty arrays deliberately expose unmapped coverage.
`common_contracts` is keyed by lowercase kebab-case contract IDs. Each entry contains those same
four arrays plus a nonempty, explicit `jobs` list of applicable registered job IDs. No wildcard or
automatic application to newly registered jobs is supported.

Unknown keys, duplicate JSON keys, duplicate selectors within an array, duplicate common-contract
job IDs, and unregistered job IDs are refused. Common selectors cannot overlap handler selectors,
including whole-file/node overlaps; generic runtime coverage cannot also be counted as handler
coverage.

Selectors are repository-relative POSIX paths to existing `tests/**/test_*.py` files, optionally
followed by `::test_function` or `::TestClass::test_method`. Function selectors include all their
parameterized cases. Individual `[parameter-id]` selections, class-only selectors, imported or
dynamically generated tests, directories, wildcards, options, traversal, symlinks, and malformed or
missing definitions are unsupported. No pytest collection is used to resolve them.

Dedicated `tests/integration`, `tests/acceptance`, and `tests/live` directories preserve their
categories unless a stronger live requirement applies. Existing `test_live_*` / `*_live*` files
and `pytest.mark.requires_target` cases are live, including target-dependent integration files.
Literal pytest category markers are checked at module, class, and function scope. Root files may
mix unit and manual tests: map exact nodes to their actual categories. A whole-file mapping cannot
overlap a different-category node mapping. An `acceptance` word in a filename inside
`tests/integration` does not relocate it; the existing directory convention remains integration.

## Recovery coverage and remaining gaps

The map is deliberately focused, not exhaustive. For example, CodeQL unit selectors cover
workspace staging, while its live selectors cover a real analysis run. The document-issue job has
connected pipeline tests mapped as integration but no claimed focused unit coverage. This is a
real **mapping gap**, not a statement that no tests exist.

The shared `recovery-admission` contract selects fourteen exact tests from `test_repair_admission.py`
for superseded attempts, portable checkpoint admission, publication interruption, configuration
refusal, worker/cleanup refusal, repair claims, shared producer/consumer compatibility, original
release evidence, explicit dependency declarations, and declared image staging inputs. These
common-contract checks do not claim individual handler coverage or promise that an always-execute
job is reusable. The module is not selected wholesale; unrelated cases do not enter the plan.
The common integration mapping is `tests/integration/test_repair_workflow.py`; its process crash
and real Dagster lifecycle checks remain manual.

`wave1-reuse` adds only the two exact warm-reuse/gap-status cases from `test_wave1_resume.py`,
and only for the intake and catalog jobs actually exercised by that fixture.
`fixture-review-repair` maps `tests/acceptance/test_repair_fixture_review.py` to its explicitly
asserted document-issue, intake, and final-report workflow jobs. This full-review acceptance test
requires prepared offline recordings, tool images, and isolated run configuration; it is not a
unit test and selection does not execute it.

Selecting document-issue unit tests therefore returns common recovery selectors **and** its
handler-specific unit gap, with `handler_selectors: []`. A repair must not treat the nonempty
combined selector list as evidence that the document-issue handler has unit coverage.

Source existence and explicit category
checks cannot prove test cost, fixture isolation, plugin behavior, or runtime success. Review those
when changing mappings; do not label a heavyweight test unit merely to fill an empty array.

The focused `tests/test_job_test_selection.py` regression validates all shipped mappings statically,
including non-unit selectors, without executing any mapped tests. No tests are moved and no global
pytest settings are changed by this helper.
