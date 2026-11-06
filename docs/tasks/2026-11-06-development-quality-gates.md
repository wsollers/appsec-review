# DEVELOPMENT PACKAGE 02 - INCREMENTAL DEVELOPMENT QUALITY GATES

User authorization, quoted verbatim: "I agree with 1,2,3,4,5 and the mcp / skill recomendations. please create a detailed instruction prompt for each  to implement them on independent working trees. They should be fully covered with unit tests. There should be intergration and acceptance tests (but do not run them due to time constraints). when complete and tested the code should be merged back to local main. These tasks can run as top level independent chats and do not need to be monitored or supervised. Ensure all of these are included in their respective development package. Run those chats/tasks/workers on the Model GPT 6 Astra High 1M context window."

Implement recommendation 2: checked-in, effective development gates that prevent new contract drift without a repository-wide cleanup. Save this entire package first as docs/tasks/2026-11-06-development-quality-gates.md in your worktree, and append implementation, test, and local-main integration evidence when finished. Work independently in autopilot; do not request supervision from the originating chat. Use GPT-6 Astra/high/long-context for any necessary bounded subagent as well. Do not push or open a PR.

## Baseline/environment

Repository wsollers/appsec-review; reviewed source 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5. Confirm ancestry and inspect newer changes. Read AGENTS.md and .claude/skills/multi-session-coordination/SKILL.md. Develop/test only in an isolated Linux or WSL Linux-filesystem worktree and its own environment. Ubuntu-22.04 is available on the initiating machine; do not run tests against a Windows-mounted primary tree. The configured local integration target is F:\XBOX-Repositories\appsec-review main. A Linux companion branch must ultimately reach that main, not merely a private mirror.

## Ownership and existing work

Own pyproject.toml quality/development dependencies and configuration, new GitHub Actions workflows, narrowly scoped quality runner/configuration modules, new dedicated gate tests, and quality documentation. Do not broadly edit application implementation to make a whole-repository baseline pass. Other packages own recovery (01), worker loops (03), prompts (04), operational/quality-result reporting (05), and MCP/skills (06).

There is an existing independent session 'Unit suite prod-sizing guard', ID d963e6fd-4153-401f-842f-1f6c18def977, branch william-sollers-xbox-unit-suite-prod-sizing-guard. At assignment time it owns dirty changes to tests/conftest.py, tests/test_000_unit_environment_guard.py, tests/test_codeql_predecessor.py, tests/test_codeql_preinstalled.py, tests/test_feed_provenance.py, tests/test_shared_layout_provenance.py, src/appsec_review/indexing/inventory.py, src/appsec_review/jobs/unity_build.py, and src/appsec_review/storage/shared.py. Do not duplicate, overwrite, or reinterpret that session's pending user decision. Avoid these files; use separate new gate tests/modules and preserve its environment checks when integrated.

## Verified baseline and design constraints

- No checked-in standard Ruff/mypy/pyright/import-linter configuration or CI workflow was found. This does not prove no external service has ever analyzed the project.
- 636 Python modules; many large legacy modules. New gates must be credible and incrementally adoptable, not thousands of unrelated formatting edits.
- Hashing/serialization/path/process code is not uniformly interchangeable. storage canonical JSON has a trailing newline, retrieval canonical JSON does not, and signing canonical JSON rejects floats and invalid keys. Signing/bootstrap must remain able to verify the application without importing the untrusted application it verifies.
- Explicit integration/live/acceptance tests already have separate paths; preserve default collection safety. User authorizes unit tests now, not heavyweight suites.

## Required implementation

1. Add pinned/reproducible development dependencies and Ruff configuration. Introduce a clear ratcheting baseline or intentionally scoped initial rules that rejects new violations without hiding new problems behind broad ignores. Fix only directly coupled narrow violations. Document scope and baseline renewal policy.
2. Add one type checker, selected for fit with the existing Python types. Initially cover high-value runtime/storage/inference/public contracts, with explicit bounded legacy exclusions and a credible growth plan. Do not use wholesale Any casts, type-ignore blankets, or silently successful fallbacks to pass.
3. Add architecture/dependency checks for real trust boundaries and stable public interfaces. Do not blanket-ban hashlib.sha256, json.dumps, subprocess.run, datetime.now, or all cross-job imports; many current public producer consumers are legitimate. Distinguish permitted dependency APIs and bootstrap isolation from unsupported private-internal imports. Test the checker with minimal valid and invalid module graphs.
4. Add CI for focused offline unit/contract checks, lint and type checking, with least-privilege permissions and no secrets required for ordinary PR code. Establish transparent changed-scope selection and documented coverage. Gate scripts must fail if selectors or required tools are missing, not report a false success.
5. Add a scoped self-analysis/SAST gate for this repository with a reviewed rule set and a bounded initial baseline. Keep deterministic findings separate from stylistic lint. Do not launch a live appsec-review review, provision scanners, or build container images as validation here. A lightweight chosen tool can be installed only after declaring its dependency and then run in the isolated environment if it is within the bounded check; otherwise write the test/gate and clearly record that tool's validation limitation.
6. Provide manual-only workflow/job definitions or documented commands for integration and acceptance suites. They must NOT run as part of default PR/main/merge validation. Do not dispatch them now, including indirectly through a broad pytest selector.
7. Update directly related developer docs. Package 01 owns the job-to-unit-test manifest/selector; do not invent a competing job registry. Quality CI may use current public selectors or adopt the package-01 selector only after it exists on main.

## Unit tests to implement and RUN

Test changed-file selection, deleted/renamed paths, full/shared-contract changes requiring a broader bounded unit set, unknown mappings, no-tests false-green protection, subprocess/tool failure and timeout classification, absent tools, config parsing, baseline ratcheting, allowed/forbidden import-boundary fixtures, bootstrap isolation, and exact JSON byte variants where touched. Verify CI/test selectors never execute integration, acceptance, live, image-building, or real-model tests implicitly. Prefer AST/structured config assertions over brittle text snapshots. Test tooling in an isolated fixture repository, not the user's primary checkout. Include focused existing config/collection checks that are not owned by the active guard task.

## Integration/acceptance tests to WRITE but NOT RUN

Write isolated-repository integration tests for the quality command end-to-end and an acceptance scenario introducing representative lint/type/boundary/self-scan defects and then removing them. Assert a clean project fails neither silently nor because unrelated optional live tools are unavailable. Keep them under explicit integration/acceptance paths. Include future manual commands and expected failure/success conditions in this package; do not execute these suites or a live CI run.

## Definition of done and integration

Run focused unit tests and chosen bounded lint/type validations covering changed scope in your own Linux worktree, using unique test/tmp basetemp. Record exact command, tested revision, elapsed time, pass/fail and honest exclusions. Do not weaken tests or hide required failures. Commit implementation, unit/integration/acceptance tests, docs and this package.
You own completion through merge into canonical LOCAL main. Merge latest main into your branch if needed and rerun directly affected units on the combined tree. Serialize final integration with all other packages using the existing repository integration procedure/lock; absent one, use an OS-backed advisory appsec-independent-main-integration.lock in the canonical main Git common directory. Inspect ownership, clean state and active-run freeze under the integration gate; no destructive reset, forced checkout, blanket ours/theirs, remote push, or periodic monitoring. Use a safe ordinary local merge and verify the ready commit is an ancestor of actual local main. Final independent-session report must include ready SHA, resulting main SHA, exact focused results, and integration/acceptance NOT RUN. If an existing owner, source freeze or unresolved semantic conflict prevents landing, preserve ready commits and name that blocker rather than claiming completion.

## Implementation evidence

- Initial assigned HEAD equals the reviewed baseline; ancestry check passed.
- Development companion: Ubuntu-22.04, `/home/wsollers/worktrees/appsec-quality-02`,
  branch `william-sollers-xbox-development-quality-gates`. A Git bundle transferred history
  from the assigned Windows worktree; no development or tests run on the mounted Windows tree.
- Read root agent guidance and canonical multi-session coordination procedure.
- Requested an exact-commit integration handoff from the existing canonical-main owner;
  this worktree session does not access the main checkout directly.

### Implemented scope

- Pinned Ruff, mypy, Bandit, pytest and the editable-build backend; checked in the complete
  hash-pinned Python 3.12 runtime/test/quality lock.
- Added the standalone `tools.quality` command, strict configuration parsing, NUL-delimited Git
  change parsing, bounded explicit unit selection, required-tool/version checks, structured
  failure/timeout classification and per-file pytest execution coverage enforcement.
- Added correctness-only Ruff rules, strict mypy on five application public-contract modules
  plus gate tooling, AST architecture checks and a separate five-rule Bandit self-scan.
- Initial reviewed baseline: 47 exact diagnostics (40 private dependency observations, two Ruff
  diagnostics, five Bandit observations). No type-check errors or bootstrap-isolation exemptions.
  New tool code cannot acquire a baseline. Counts can only shrink against the selected Git base.
- Added least-privilege, SHA-pinned ordinary PR/main CI and documented manual-only integration/
  acceptance commands. No job-to-test registry was added; package 01 retains that ownership.
- Preserved all application implementation, the guard session's owned files, and existing
  conftest environment/collection safety. Exact JSON byte variants have focused regressions.
- Updated `docs/development/quality-gates.md` and linked it from the README.

### Validation log before the implementation commit

All commands below ran in `/home/wsollers/worktrees/appsec-quality-02` with its own `.venv`
under Ubuntu-22.04 / CPython 3.12.15. The editable import resolved to this checkout's
`src/appsec_review/__init__.py`. The base revision for these working-tree iterations was
`528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`; no newer main commits were present when rechecked.
Elapsed wall times include the small WSL invocation overhead where indicated.

| Command | Elapsed | Result |
| --- | --- | --- |
| `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q tests/quality/test_config_selection.py tests/quality/test_boundaries_baseline.py tests/quality/test_runner.py tests/quality/test_workflows.py --basetemp=test/tmp/package02-unit-1` | 5.99s wall; 5.01s pytest | 88 passed |
| `.venv/bin/python -m mypy --config-file=pyproject.toml --output=json --no-error-summary --no-incremental` | 11.63s wall | Exit 0, no diagnostics |
| `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q tests/quality/test_config_selection.py tests/quality/test_boundaries_baseline.py tests/quality/test_runner.py tests/quality/test_workflows.py tests/test_config.py tests/test_pytest_default_collection.py tests/test_review_model_request.py --basetemp=test/tmp/package02-unit-2` | 20.61s wall; 19.71s pytest | 144 passed |
| `.venv/bin/python -m ruff check tools/quality tests/quality tests/integration/test_quality_command.py tests/acceptance/test_quality_gate.py` | 0.23s wall | Exit 0; manual tests inspected, not executed |
| `.venv/bin/python -m ruff check --ignore-noqa --select F401,F841 tools/quality tests/quality tests/integration/test_quality_command.py tests/acceptance/test_quality_gate.py` | under 1s | Exit 0 |
| `.venv/bin/python -m tools.quality check --base 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5 --full` | 58.21s wall | PASS: 645 source modules, 47 unchanged baseline entries; 148 units passed in 16.99s |

The last command's component times were Ruff 0.152s, mypy 13.139s, Bandit 20.662s, architecture
6.081s and the unit subprocess 17.585s. `--full` selected only the four new quality unit files
and the three explicit existing contract files shown above, with a unique
`test/tmp/quality-<uuid>` basetemp. It did not collect the whole repository suite.

Two initial baseline-generation attempts failed closed: 31.41s on Bandit's valid `./` filename
prefix, then 36.49s on a false bootstrap dependency caused by losing guarded-import provenance
at an aliased private attribute use. Both root causes were corrected and regression-covered.
The next seed run passed in 44.04s with 51 observations. Review then removed four false positives
for standard Python protocol/metadata attributes and strengthened SAST fingerprints to bind the
containing function; the unpublished seed was regenerated, yielding 47 entries in 36.17s.
The generation command was:

```bash
.venv/bin/python -m tools.quality baseline --initialize \
  --reason 'Initial reviewed legacy diagnostics at 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5; see docs/development/quality-gates.md for rule scope and dispositions.'
```

No failed check was suppressed, skipped, or accepted by increasing a timeout. The initial Ruff
baseline explicitly retains the pre-existing Python-3.11-incompatible f-string and duplicate
import; passing on Python 3.12 is not a claim of full Python 3.11 compatibility. Other legacy
modules remain outside strict mypy diagnostic scope. Contract sentinels are not complete
per-job coverage.

### Written manual scenarios - NOT RUN

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  tests/integration/test_quality_command.py --basetemp=test/tmp/quality-integration-manual
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  tests/acceptance/test_quality_gate.py --basetemp=test/tmp/quality-acceptance-manual
```

The integration tests require an isolated clean fixture repository to pass the real CLI/static/
unit sequence while PATH exposes Git but not optional live tools; missing selectors must return
structured error exit 2. The four acceptance scenarios add lint, type, private-boundary and
self-scan defects, require exit 1 with the corresponding diagnostic, remove the defect and require
exit 0. Integration, acceptance, live reviews, image builds and live CI dispatches were NOT RUN.

### Local-main integration custody

The existing Windows-main integration owner (`f9628e8e-873f-4f72-8aca-3069fb9fe4af`) confirmed
canonical main at `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5` with a clean tracked/untracked state.
It also reported an existing HOLD from the two-stage build-topology delivery owner, pending a
release or Stage B handoff. This package does not waive that hold. Final ready SHA, exact-commit
verification and integration evidence are recorded below when available.

### Exact implementation-commit verification

- Implementation commit: `46e4ea2246c646576b051d4c0301ee66cd363616`;
  tree: `cf02f7402e20a7be85443b3875ed88f0ec012bcc`.
- At that exact clean revision, reran
  `.venv/bin/python -m tools.quality check --base 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5 --full`:
  PASS in 56.31s wall; 148 tests passed in 17.08s. Components: Ruff 0.171s,
  mypy 11.432s, Bandit 19.642s, architecture 6.762s; unit subprocess 17.688s.
- All 25 changed paths had LF index and worktree bytes; `git diff --check` passed.
  The initial Ruff cache was removed from the repository root and its configured location is
  now `test/tmp/.ruff_cache`. No hash-pinned application fixtures were normalized or edited.
- Final review tightened baseline output-path containment and added a regression against an
  external parent symlink before any baseline initialization write. Structured policy tests
  also reject blanket Ruff/mypy ignore/exclude settings.

### Final code verification and ready handoff

- Final tested code commit: `65f9d8ca5d8040b11f64e42675ae682cb8e87862`;
  tree: `59e940846f3a97f8d669a4092261341765eb72fd`.
- Exact command:
  `.venv/bin/python -m tools.quality check --base 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5 --full`.
- Result: PASS, exit 0, 49.92s wall. All **149 selected unit tests passed in 15.35s**; no skips,
  xfails or deselections. Static corpus: 645 modules, 47 unchanged baseline observations and
  zero new diagnostics. Component elapsed times: Ruff 0.140s, mypy 10.764s, Bandit 17.475s,
  architecture 5.272s, unit subprocess 15.801s.
- Final change set is 25 owned paths. Both code commits use the requested Copilot App author,
  committer and co-author trailer. All application implementation files remain unchanged.
- The canonical-main owner will receive a local Git bundle with sole prerequisite
  `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`, exact ready commit/tree and this focused evidence.
  The requested lock is `appsec-independent-main-integration.lock` in canonical main's Git
  common directory, held with an OS-backed exclusive handle for the ownership/freeze/clean-state
  checks, ordinary local merge and final ancestry verification.
- Integration and acceptance test files remain **NOT RUN**, as do live reviews, container/image
  operations and a live GitHub Actions dispatch. No push or pull request is authorized.

### Canonical local-main integration - completed

- Ready commit: `f8daf3d34dd9576e2c2ee48f825e740475c1fb7a`;
  tree: `be72b38366c5372c5918edf6c8b1e0f29a96bbe1`.
- The prior hold owner explicitly released it: Stage B had never started. The designated
  integration owner then held an exclusive FileStream (`OpenOrCreate`, `ReadWrite`,
  `FileShare.None`) on
  `F:\XBOX-Repositories\appsec-review\.git\appsec-independent-main-integration.lock`.
  Under that lock it rechecked ownership, source freeze, clean tracked/untracked state and
  absence of in-progress Git operations, then performed an ordinary `merge --ff-only`.
- Resulting actual canonical Windows **main**:
  `f8daf3d34dd9576e2c2ee48f825e740475c1fb7a`, tree
  `be72b38366c5372c5918edf6c8b1e0f29a96bbe1`, clean. The lock handle was released in `finally`;
  the empty advisory lock file remains in the Git common directory.
- Independently verified through the canonical repository's shared refs from the assigned
  app worktree: `git merge-base --is-ancestor f8daf3d34dd9576e2c2ee48f825e740475c1fb7a main`
  returned 0, and `git rev-parse main` returned that exact ready SHA.
- No tests ran in the Windows checkout; the exact WSL code verification above applies.
  The canonical-main tree contains the same tested code plus documentation-only evidence.
  No push, PR, destructive reset, rebase, or automatic conflict resolution occurred.
  The integration owner separately notified the owner of the canonical WSL companion; the
  requested Windows-main landing is already complete, not merely a private-mirror commit.

### Additional documentation check and honest limitation

At ready revision `f8daf3d34dd9576e2c2ee48f825e740475c1fb7a`, ran:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  tests/test_documentation.py --basetemp=test/tmp/package02-docs
```

Result: **1 failed in 0.66s** (1.14s wall). This pre-existing repository-wide link check requires
two files from the user-owned target checkout that is deliberately absent in the isolated WSL
development tree: `targets/appsec-multi-vuln/support/project-matrix.json` and
`targets/appsec-multi-vuln/README.md`. Both links originate in the unchanged
`docs/architecture/build-environments-and-execution-capture.md:532-533`. The same named gap was
already documented in the baseline architecture material. No target was acquired, no unrelated
documentation was rewritten, and the check's assertions were not weakened.

Reusing that test's link matcher on exactly the changed README, quality guide and package
document found **no unresolved local links**. The 149-unit quality command remains passing;
the supplemental whole-documentation check is explicitly not claimed to pass in this checkout.
This final integration-evidence update changes only this package document.
