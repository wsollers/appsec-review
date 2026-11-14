---
title: "Incremental offline quality gates"
kind: "process"
subsystem: "testing and operations"
status: "current"
jobs: ["job_target_analysis_plan"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Incremental offline quality gates

Run development checks from a Linux-filesystem checkout and its own Python 3.12 environment.
These are development contracts, not review-worker guidance or proof that this application is
free of vulnerabilities. No review, target acquisition, model call, image build, scanner
provisioning, Dagster run, integration suite, or acceptance suite is part of the gate.

## Reproducible setup and commands

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/quality.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
.venv/bin/python -m tools.quality check --base main
```

The editable package must resolve inside this checkout. `pyproject.toml` pins Ruff 0.14.2,
mypy 1.18.2, Bandit 1.8.6, pytest 8.4.2 and the build backend in the `quality` extra.
`requirements/quality.lock` pins and hashes their complete Python 3.12 dependency closure,
including the runtime and test extras. Checks themselves require no network or credentials.
For a reviewed dependency update, regenerate the lock with:

```bash
uv pip compile pyproject.toml --extra quality --extra test --python-version 3.12 \
  --generate-hashes --output-file requirements/quality.lock
```

`check --full` means the **full bounded contract allowlist**, never the full repository suite.
`--static-only` and `--units-only` expose the two parts for focused work; their JSON reports
explicitly label the other part `NOT RUN`. The default base is `HEAD`, suitable for working-tree
changes. Use the actual PR base/main predecessor for branch-level baseline enforcement, as CI
does. A nonexistent base fails; it does not silently fall back to an empty change list.

## Enforced scope

| Gate | Initial coverage | Deliberate limitation |
| --- | --- | --- |
| Ruff | Every tracked or untracked Python source under `src/appsec_review` and `tools/quality`; E9 syntax, F811 redefinition, F821/F822/F823 undefined names/exports/locals, with `--ignore-noqa` | No formatting/import-sort campaign; other rules are not yet enabled. Tests and external scripts are outside this corpus. |
| mypy | Strict checking of `runtime/job.py`, `runtime/plan.py`, `storage/atomic.py`, `storage/validation.py`, `inference/request.py`, and all `tools/quality` | Imported definitions are followed with `follow_imports=silent`, not replaced wholesale by `Any`; diagnostics in other legacy modules are not enforced. No `ignore_missing_imports`, blanket ignores, or weakened application annotations. |
| Architecture | AST imports, relative imports, imported aliases' private attributes, and literal dynamic imports throughout the same source corpus | Not a general dynamic Python call graph; reflection, reassignment, plugin resolution and arbitrary runtime imports outside the bootstrap trust set are not proven safe. |
| Bandit | Entire source corpus, B102/B301/B307/B506/B602, all severities, with `--ignore-nosec` | Deterministic suspicious-construct detection, not taint analysis, exploit verification, secrets scanning or a live appsec-review run. |
| Units | The exact file lists in `[tool.appsec-quality]` | Contract sentinels, not every affected job's unit coverage. |

All static gates scan the entire declared corpus on each invocation, even on documentation-only
changes. This catches violations in newly added modules and avoids changed-line heuristics that
miss renamed or moved code. A missing source root, type-check root, selected test, executable,
Python tool distribution, or exact tool version fails. Invalid tool output, a scanner's skipped
file/error list, contradictory exit status, nonzero tool exit, or timeout also fails explicitly.
Static checks use a 120-second **per-tool** limit, not a claim that all checks are seconds-scale
units. The baseline measurement records actual timings.

The five initial type-checked application files are the complete explicit legacy-scope boundary,
not examples of a broader claim. Expand one public contract family at a time: runtime datasets
and handoffs next, then storage admission, then transport adapters. Add real annotations and
focused regressions before adding each file to `tool.mypy.files`; keep the strict flags and
review dependency diagnostics separately. The initial selected files have no mypy baseline
diagnostics. Existing `Any`-typed application payload fields remain visible limitations.

## Dependency contracts

- Public cross-job producer/consumer APIs remain allowed. Within one top-level application
  package, or one concrete `jobs/<job>` family, internal helpers remain permitted. Across those
  owners, private module/symbol imports, wildcard imports and aliased private access are
  unsupported dependencies. Standard Python protocol attributes such as `__getitem__`,
  `__dataclass_fields__` and TypedDict metadata are not private implementation APIs.
- The listed public runtime/storage/inference contracts must not depend on concrete jobs or
  orchestration adapters. Application callers use the inference public API rather than directly
  importing provider adapters.
- Runtime application modules cannot import development tools. The development gate is outside
  `src`, is not packaged into the runtime, and never imports application modules to inspect them.
- The six signing verifier/bootstrap modules are stdlib-only. Bootstrap and its core/shim may
  not import the application they verify. The standalone-compatible verifier siblings may use
  only explicit trusted sibling imports guarded by `if __package__:`. The entire trusted set is
  inspected, so a trusted sibling cannot quietly import an application helper. Unknown dynamic
  imports in this set are rejected. **Bootstrap isolation cannot be baselined.**

This deliberately does not ban `hashlib.sha256`, `json.dumps`, `subprocess.run`, `datetime.now`,
or all cross-job imports. Storage JSON's trailing LF, retrieval's no-LF wire format, and signing's
float/key restrictions remain separate public contracts, with exact-byte unit assertions.

## Initial baseline and renewal

`quality/baseline.json` records exact path, rule, message, source line and fingerprint; repeated
identical findings are counted, so copying an exempted defect adds a failing occurrence.
Fingerprints bind the diagnostic message and enclosing AST statement, ignoring line shifts.
Bandit fingerprints bind the containing function (or module at top level), so changing a
`SafeLoader` declaration without changing its `yaml.load` call invalidates that exemption.
Tool messages containing their own line references may still require review after a shift.

The reviewed initial source is `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`. Its dispositions are:

| Diagnostics | Disposition |
| --- | --- |
| Existing cross-owner private dependencies | Named legacy debt, retained individually instead of refactoring unrelated jobs. Public producer/consumer imports are not exempted because they are allowed by design. |
| Ruff F811 in `jobs/job_target_analysis_plan/job.py` | Existing duplicate `replace` import; narrow cleanup is deferred to that module's owner. |
| Ruff Python-3.11 syntax diagnostic in `reporting/html.py` | Existing 3.12-only f-string syntax despite the advertised 3.11 minimum. CI executes on 3.12; [T-160](../TODO.md) tracks this compatibility gap, not a claim of 3.11 conformance. |
| Bandit B506 in `debug_symbols/_reader_pdb.py` and `rulepacks/sei_cert/pack.py` | Reviewed custom `yaml.SafeLoader` subclasses with bounded/strict constructors; Bandit does not infer these subclasses. Bind their containing functions rather than ignoring all YAML loads. |
| Bandit B102 in `signing/bootstrap.py`, `signing/import_hook.py`, `signing/sitecustomize_shim.py` | Deliberate execution of explicitly loaded verifier/verified module bytes. Retained exact enclosing-function baselines; not a global `exec` exemption or a new audit of the signing design. |

Normal CI compares the proposed baseline to the Git base's baseline as a multiset. Entries can
only disappear or decrease in count; changing its configured filename cannot bypass that check.
New development-tooling findings and bootstrap-isolation findings are never eligible. First
adoption has no preceding baseline and is clearly reported as such; reviewers must review that
seed. Like every checked-in CI policy, deliberate changes to the checker/configuration itself
require review and repository branch protection to enforce the required status.

After fixing or deleting an old diagnostic:

```bash
.venv/bin/python -m tools.quality baseline --prune --reason "Explain the removed legacy debt"
.venv/bin/python -m tools.quality check --base main
```

Pruning cannot absorb new violations. Stale entries fail until pruned. `baseline --initialize`
is solely for the initial reviewed seed and refuses an existing file; deleting/reseeding it
does not bypass the base comparison. Do not renew by accepting the current count, adding broad
ignores, rehashing changed behavior, or suppressing diagnostics. A rule/version/scope expansion
that would require more legacy exemptions needs a separate explicit policy review; there is no
routine "accept all" switch.

## Changed-scope unit selection and CI

Git NUL-delimited `--name-status --find-renames` preserves both sides of renames/copies and deleted
paths. Untracked working-tree paths are included. Shared configuration, the declared shared
paths, explicit `--full`, and **any unknown mapping** select quality units plus the bounded
existing contract files. The report names unknown paths and explicitly declines to claim job
coverage. Documentation-only and quality-only changes still run all quality sentinel files.
No new test is automatically executed merely because its filename changed.

Selectors must be existing, exact, reviewed offline test files: not directories, globs, node
expressions, manual-suite paths, or live/image-building/real-model names. A pytest plugin requires
every selected file to actually collect tests and fails skipped, xfailed, deselected, and empty
coverage. The runner disables plugin autoload and ambient `PYTEST_ADDOPTS`, preserves repository
conftest safety checks, and allocates a unique `test/tmp/quality-<uuid>` base directory.

`.github/workflows/quality.yml` runs on ordinary pull requests and pushes to main, uses pinned
actions, `contents: read`, no persisted checkout credentials, no secrets and no privileged
`pull_request_target`. A JSON report in the job log shows changed paths, chosen files, reasons,
named coverage limitations, static timings, baseline counts and unit output.
Set **Offline development quality / quality** as a required check through repository settings
if enforcement on GitHub is desired; checking in a workflow does not configure branch protection.

The public [job test selector](../operations/job-test-selection.md) now exists. This quality
allowlist remains a separate bounded sentinel selection; the implementation does not delegate to
that selector. Any integration must preserve the same offline/fail-closed guarantees. Developers
still select additional affected unit coverage when a change needs more than these sentinels.

## Manual integration and acceptance (not default gates)

These commands are documentation, not steps in the PR/main workflow. They are written for a
future explicit user-authorized run and **were not run for this package**:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  tests/integration/test_quality_command.py --basetemp=test/tmp/quality-integration-manual
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  tests/acceptance/test_quality_gate.py --basetemp=test/tmp/quality-acceptance-manual
```

The integration scenario copies the development gate into a fresh fixture Git repository,
executes installed tools end-to-end, checks both static and unit success, and ensures manual
test sentinels are never imported. Missing selectors must return structured error exit 2.
The acceptance scenarios add a representative undefined name, type mismatch, private import,
or `eval` in an isolated fixture repository: each must produce diagnostic exit 1; removing it
must produce exit 0. No optional live tools are prerequisites. These scenarios are distinct
from the lightweight unit tests of selection, parsers, failure handling and minimal AST graphs.
