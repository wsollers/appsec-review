---
title: "Development package 06 - read-only operator MCP and development skills"
kind: "task"
subsystem: "testing and operations"
status: "historical"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Development package 06 - read-only operator MCP and development skills

## Original development package

DEVELOPMENT PACKAGE 06 - READ-ONLY OPERATOR MCP AND DEVELOPMENT SKILLS

User authorization, quoted verbatim: "I agree with 1,2,3,4,5 and the mcp / skill recomendations. please create a detailed instruction prompt for each  to implement them on independent working trees. They should be fully covered with unit tests. There should be intergration and acceptance tests (but do not run them due to time constraints). when complete and tested the code should be merged back to local main. These tasks can run as top level independent chats and do not need to be monitored or supervised. Ensure all of these are included in their respective development package. Run those chats/tasks/workers on the Model GPT 6 Astra High 1M context window."

Implement the approved MCP/development-skill recommendations, preserving worker isolation and explicit run selection. Save this entire development package in docs/tasks/2026-11-06-operator-mcp-development-skills.md before implementation; append the final implementation, test and local-main integration record. This is independent top-level autopilot work, not a supervised child. Do not report to the origin chat. Any necessary bounded subagents use GPT-6 Astra/high/long-context. No remote pushes, PRs, live reviews, model calls, real service provisioning, or global workstation customization changes.

Base/environment
wsollers/appsec-review; reviewed base 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5. Verify ancestry and inspect present source. Follow AGENTS.md and .claude/skills/multi-session-coordination/SKILL.md. Implement/test in an isolated Linux/WSL Linux-filesystem worktree with its own environment, never the Windows primary checkout. Ubuntu-22.04 is available. Canonical configured local main is F:\XBOX-Repositories\appsec-review; do not substitute a private mirror's main for required integration.

Ownership and boundaries
Own read-only operator MCP schemas/adapters/stdio handling, explicit-run launch configuration/templates, repository-development skills under .claude/skills, and corresponding tests/docs. All Python source paths below are under src/appsec_review. Package 05 owns enhanced human operational presentation/aggregation; do not build another state machine or a second comprehensive dashboard. Package 01 owns recovery and job-test execution; 03 owns model loops; 04 owns runtime guidance/card rendering; 02 owns pyproject/CI/global test configuration. Build on current public run/log/receipt/retrieval interfaces. Thin read queries may live in a reusable operator module owned by this package, but remain read-only projections rather than a competing lifecycle authority. No hard dependency on an unpublished sibling API; preserve current adapters so later integration can reuse them.

Verified facts
- Existing appsec-review-mcp is an operator stdio interface pinned to one accepted run. It is not registered in a checked-in .mcp.json, but global configuration was not audited. This checkout has no accepted run to hardcode. A static registration with a fabricated/latest run would fail or select unsafe scope.
- Review cells have no model-held tools; retrieval is application-mediated. Do not install MCPs into their transports. query_owasp_workbench is intentionally MCP-only; accepted control_evidence projections provide worker context.
- OSV/NVD/KEV/EPSS already reach review packages through review/advisories.py. Source excerpts already exist. query_artifacts intentionally does not expose arbitrary artifact bytes or protected raw streams.
- Skills are separated: repository-development skills canonically under .claude/skills, metadata.audience repository-agent; .agents/skills contains only the repository-development-skills pointer. Runtime skills are separately registered under pipeline/skills and never load development instructions.

Required implementation
1. Provide ONE bounded read-only operator MCP interface, extending the existing service or adding a narrowly separate mode if authority separation requires it. Cover explicit run/job/attempt inspection, failure details by protected/sanitized references, coverage gaps, bounded log pages, accepted artifact discovery, and recovery-plan inspection using existing functionality. Add read-only Dagster state through allowlisted GraphQL operations and explicitly configured trusted endpoints. No generic GraphQL/SQL/shell/URL execution tool and no mutation authority.
2. Distinguish application run IDs from Dagster dispatch IDs. Bind requests to exact selected run/accepted manifest where applicable; expose missing/unaccepted/unsupported state explicitly. Do not infer 'latest' across unrelated runs or treat empty results as success. Resolve artifact references through current verification/read boundaries; return bounded sanitized content only where an explicit approved type supports it.
3. Supply a repository-owned launch/config template or wrapper requiring explicit run selection and optional manifest pin. Never commit workstation absolute paths, credentials or a live run ID. Provide a valid client configuration example rather than unconditional .mcp.json startup that cannot work without a selected run. Document registration for external development agents; do not modify global agent settings or install third-party services silently.
4. Add development skills: run-triage-and-repair (failure -> reproduce -> focused units -> implementation provenance -> admitted restart), add-a-job-contract (datasets/config/registry/inputs/outputs/publication/tests checklist), add-runtime-guidance (authority/registration/bundle/schema/evaluation checklist), and codeql-release-recompile (reuse existing scripts and exact release/source checks). Reuse existing coordination/docs skills, not copies. Include explicit integration/acceptance authorization rules and current limitations. Development skills may describe future manual live operations but must never automatically execute them or widen a review worker's authority.
5. Evaluate the approved targeted worker lookup improvements against actual missing questions. For query_change_context, add grants only for relevant hunter/red roles if scope can be enforced with accepted entity/package identities; changing an allowlist alone is insufficient. If adding a new grant requires role/registry changes owned by package 04, make the smallest mechanically consistent change after inspecting current main or preserve a tested capability adapter without widening authorization. For advisory lookup, reuse accepted projections and only add a bounded typed query if an unmet workflow actually needs it. For artifact excerpts, allow only explicitly approved sanitized indexed artifact types with hash/byte/citation checks, never arbitrary raw stdout/stderr, protected command data, archives or filesystem reads. Record decisions and evidence; do not add unused tools merely to reach a count.
6. Keep protocol correctness and failure semantics explicit: bounded JSON-RPC inputs, initialize/tool catalog contracts, notifications, invalid parameters, tool-result errors versus transport errors, pagination/cursor binding, redaction and schema/version compatibility. Keep stdout protocol-clean and diagnostics elsewhere.

Unit tests to implement and RUN
Test dispatch directly without launching servers: initialization/catalog consistency, notification handling, invalid JSON/request shapes, tool errors, size bounds, explicit-run requirement, unavailable accepted manifest, exact manifest/run mismatch, application-versus-Dagster IDs, path/identity scope and artifact tampering, secret/raw-stream exclusion, pagination/filter/expiry behavior, Dagster endpoint and query allowlists with fake network boundary, and truthful missing coverage. Test configuration generation without user-specific secrets/paths and without auto-selecting a run. Test development-skill frontmatter, canonical placement, pointer-only .agents, no runtime/development cross-reference leakage, existing tooling links and instructions matching actual CLI capabilities. For any new lookup, test permitted and denied roles, unavailable producers, exact evidence references and non-authoritative context. Do not fake the authorization under test.

Integration/acceptance tests to WRITE but NOT RUN
Add explicit stdio-client integration cases, accepted run fixture retrieval, fake/isolated Dagster service interoperability, and acceptance scenarios where a developer inspects a failed run, obtains a nonexecuting recovery plan and finds the exact unit-test/replay references. Add permission-negative cases proving no mutation or arbitrary file/query access. Put suites under tests/integration and tests/acceptance and preserve default collection exclusions. Do NOT start a server or execute these suites now. Document future manual commands/prerequisites; do not claim integration acceptance from unit dispatch tests.

Completion and local integration
Run comprehensive focused offline unit tests for the changes in your own Linux environment with unique test/tmp basetemp, plus existing relevant MCP/guidance-separation tests. Record exact tested revision, commands, elapsed time and results. Update operator docs and development package; commit all code, tests, configuration examples and skills. Incorporate latest main into your branch and rerun affected units on the combined tree.
You own landing this package into canonical LOCAL main. All packages use the repository's existing serialized integration ownership/lock; absent one use an OS-backed advisory appsec-independent-main-integration.lock in the canonical main Git common directory. Do not mutate main concurrently, bypass an existing owner/source freeze/dirty checkout, reset or force-checkout, blindly choose ours/theirs, push remotely, or start a monitoring loop. Perform a safe ordinary local merge and verify ready SHA ancestry in actual main. Final independent report names ready/main SHAs and focused test results, with integration/acceptance NOT RUN. Preserve ready commits and state a genuine merge blocker locally if safe landing cannot be finished; do not ask the originating chat to supervise.

## Implementation and verification record

Initial HEAD is the reviewed base, `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`.
Development uses an isolated Ubuntu-22.04 Linux-filesystem worktree and its own environment.
The original package above was saved before implementation.

Ownership: this package owns MCP operator adapters/protocol/configuration and the four new
development procedures; it does not change recovery execution, human dashboards, runtime role
guidance, global test configuration, workstation registrations, or service deployments.
Package 04 separately owns the `AGENTS.md` deferred-signing correction; this package leaves that
file unchanged.

Integration constraint: the session host explicitly prohibits reading or writing the canonical
primary checkout. That is a genuine blocker to landing in canonical local main, not permission
to substitute the isolated repository's `main`. Ready commits will be preserved locally.

### Implemented surfaces and decisions

- Extended the existing stdio entry point with one operator catalog: run availability, job and
  attempt inventories, exact attempt status, structural log pages, historical recovery-plan
  inspection, and read-only Dagster dispatch state. Existing accepted retrieval adapters and
  worker capabilities remain separate. There is no new lifecycle state machine or dashboard.
- Operational reads use the existing run layout and telemetry schema, canonical contained paths,
  bounded regular-file reads, and exact byte/hash references. Raw messages, traceback contents,
  stdout/stderr, command data and arbitrary artifact bytes are withheld. Missing/unaccepted/
  unsupported state and stale or truncated projections are named gaps, not success claims.
- The operator accepts a missing or unaccepted selected run for triage, but never admits evidence
  without `RetrievalCore` verification. Its accepted manifest becomes sticky on first verified use
  (or must match the supplied pin). OWASP retains its separate exact accepted-manifest pin.
  The optional retrieval audit sink sends diagnostics outside the observed run; existing
  application retrieval still writes its normal audit events.
- Added a configuration generator that prints a client entry only with explicit application-run
  selection. No checked-in unconditional registration, live run default, global settings change,
  service installation or credential configuration was added.
- Dagster uses an immutable operator-configured endpoint and a fixed read operation, bounded
  network reads, exact UUID/application-tag checks and closed sanitized response shapes. It
  exposes no caller-supplied query, URL, SQL, shell or mutation.
- Added the four requested canonical development skills and executable contract checks for
  frontmatter, placement, existing command parsers, source links and authorization boundaries.
  No runtime guidance, registry role grants or `.agents` pointer copies were changed.
- Recovery inspection reads an exact existing `RESUME_PLANNED` event; it does not call the
  planner because the current CLI planning path emits telemetry and can inspect the target.
  The result is explicitly historical and nonexecuting. It points to the current resume unit
  file and CLI replay/planning entry points. Exact repair tests and replay inputs not recorded
  by that producer remain an operator-selection gap; no package-01 API was invented.

### Targeted worker lookup assessment

| Proposed improvement | Evidence and decision |
| --- | --- |
| `query_change_context` for hunter/red | `retrieval/core.py:1114` accepts path/component/signal filters rather than an accepted subject identity. `mcp/capability.py:24,180-198` requires package-bound identities and grants only existing scoped queries. A bare allowlist expansion would permit broad context and conflict with package 04's runtime role ownership. **No new grant.** Tests exercise real signed capabilities, exact accepted subjects and denied operator/history queries for all current roles. Existing scoped `query_precomputed` remains available for accepted `history_context` facts when the package grants them. |
| Advisory lookup | `review/advisories.py:37,111-129,132` already joins accepted observation-bound facts, produces bounded lead/hunt context, preserves feed gaps and declares that context cannot satisfy proof obligations. Existing enrichment regressions cover NVD/KEV/EPSS provenance. No unmet workflow was identified; **no redundant advisory tool** was added. |
| Artifact excerpts | `retrieval/core.py:490,675` already separates sanitized indexed payloads from hash-verified source excerpts. Existing `query_artifacts` discovers accepted identities but does not download bytes. There is no newly approved sanitized artifact-byte type in this package; **no raw artifact excerpt grant** was added. Existing source byte/citation checks and artifact tamper/exclusion regressions are retained. |

### Offline verification record

All commands below ran in the isolated Ubuntu Linux-filesystem worktree with its own Python 3.12
editable environment; the package import resolved inside that checkout. Initial environment
probing found no `.venv`; dependencies were then restored from the existing `.[test]` manifest.
No integration, acceptance, live review, runtime model call, service provisioning or server
startup was executed.

The development passes below used base revision
`528b3fa681d9e33113932c9fc4abf9ddbc53b6e5` plus the in-progress package changes. Immutable committed
verification and local-main status are recorded separately below once ready.

| Pass | Focused command after `.venv/bin/python -m pytest -q` | Wall time | Result |
| --- | --- | --- | --- |
| Initial operator dispatch | `tests/test_operator_protocol.py tests/test_operator_queries.py tests/test_mcp_jsonrpc_errors.py --basetemp=test/tmp/operator06-first` | 6.72 s | 62 passed, 2 failed: test scan-bound override leaked into schema checks; a paging test omitted the core's required structured `find` filter. Corrected test inputs, preserving the assertions. |
| Expanded operator/capabilities | `tests/test_operator_protocol.py tests/test_operator_queries.py tests/test_operator_configuration.py tests/test_operator_worker_boundaries.py tests/test_mcp_jsonrpc_errors.py --basetemp=test/tmp/operator06-second` | 9.20 s | 86 passed. |
| Skill contracts | `tests/test_operator_development_skills.py tests/test_skill_separation.py --basetemp=test/tmp/operator06-skills` | 8.14 s | 43 passed. |
| Comprehensive related regressions | `tests/test_operator_protocol.py tests/test_operator_queries.py tests/test_operator_configuration.py tests/test_operator_worker_boundaries.py tests/test_operator_development_skills.py tests/test_mcp_jsonrpc_errors.py tests/test_retrieval_core.py tests/test_retrieval_artifacts.py tests/test_retrieval_interfaces.py tests/test_review_package_capability.py tests/test_skill_separation.py tests/review/test_advisory_enrichment.py -k 'not live_stdio_smoke and not mcp_stdio_parity' --basetemp=test/tmp/operator06-regression` | 60.94 s | 199 passed, 1 failed, 2 manual stdio cases deselected. The existing managed-retrieval fixture rewrote frozen configuration without republishing its bound claim/handoff. Its setup now preserves the complete configuration and republishes through `write_fixture_handoff`; production admission checks and test assertions are unchanged. |
| Managed fixture and Dagster | `tests/test_retrieval_core.py::test_standalone_managed_retrieval_keeps_admission_through_manifest_loading tests/test_operator_dagster.py --basetemp=test/tmp/operator06-dagster-fixture` | 3.85 s | 206 passed, 1 failed: IPv4-mapped IPv6 loopback classification differs on Python 3.12. The endpoint parser needs an explicit mapped-address refusal; the negative assertion is retained. The managed fixture regression passed. |

Comprehensive related regressions take about a minute rather than seconds; they are bounded
offline units and were not relabeled or weakened. The two mixed legacy stdio cases are explicitly
excluded from these commands because they start processes. New manual suites and prerequisites
are documented in `docs/operations/retrieval-mcp.md`; writing or importing fixture helpers does
not establish integration/acceptance success.

The IPv4-mapped address parser was corrected explicitly (including HTTP/HTTPS dotted and
hexadecimal spellings) without weakening the negative tests. The final development pass then ran:

```sh
.venv/bin/python -m pytest -q \
  tests/test_operator_protocol.py tests/test_operator_queries.py \
  tests/test_operator_configuration.py tests/test_operator_worker_boundaries.py \
  tests/test_operator_development_skills.py tests/test_operator_dagster.py \
  tests/test_mcp_jsonrpc_errors.py tests/test_retrieval_core.py \
  tests/test_retrieval_artifacts.py tests/test_retrieval_interfaces.py \
  tests/test_review_package_capability.py tests/test_skill_separation.py \
  tests/review/test_advisory_enrichment.py \
  -k 'not live_stdio_smoke and not mcp_stdio_parity' \
  --basetemp=test/tmp/operator06-comprehensive
```

Result: **410 passed, 2 manual stdio cases deselected**, 63.46 s pytest time / 64.34 s wall time.
The new integration and acceptance files passed AST syntax parsing only, not execution.
The legacy mixed stdio smoke's assertions were also updated for the operator's intentional
no-run-write behavior and current retrieval catalog; that manual case remains **NOT RUN**.

The latest canonical local `main` reference observed before preparing the ready commit remains
`528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`. Only Git metadata was inspected through this session's
checkout; the primary checkout was not read or written, and no integration lock or merge was
attempted there. A private clone's `main` is not reported as canonical-main integration.

### Initial committed verification and preservation

- **Tested implementation SHA:** `adbd2fcdffbebbffc76005112b29db6360ed529e`.
- **Canonical local-main ref:** `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`.
  A fresh local bundle of that actual ref was fetched into `refs/remotes/canonical/main` in the
  isolated Linux repository. `git merge --ff-only refs/remotes/canonical/main` reported
  `Already up to date`; ancestry was verified before the committed test pass.
- **Committed test command:** the complete 13-file command above, changing only basetemp to
  `--basetemp=test/tmp/operator06-committed`. The worktree was clean before execution and the
  import origin was checked again. Result: **410 passed, 2 deliberately deselected manual stdio
  cases**, 62.10 s pytest time / **62.93 s wall time**.
- **Local-main integration: BLOCKED.** The session's checkout-access restriction forbids reading
  or writing the canonical primary checkout. No main merge, lock acquisition, dirty-checkout
  bypass, reset, forced checkout, conflict auto-resolution or source-freeze override was attempted.
  Main remains at the actual ref above; this is not a claim that the canonical worktree was
  inspected or that the ready commit landed.
- **Local preservation:** the ready implementation commit is on
  `william-sollers-xbox-operator-mcp-development-skills` in the isolated Linux worktree, in the
  session's `operator-ready.bundle`, and imported into the original repository's Git object
  database under `refs/remotes/operator-package06/ready`. This import changes only Git metadata:
  neither the Windows session's source files nor the primary checkout are modified. The final
  documentation-only record commit follows the tested implementation and preserves its exact
  source/test tree.
- **Manual validation:** integration, acceptance, live review and model execution remain
  **NOT RUN**. The three new manual files received syntax parsing only. No remote push, PR,
  workstation registration, global Git setting, third-party service or provisioning change occurred.

All 24 changed files passed LF index/worktree checks and `git diff --check`; the repository root
was inspected. Disposable test outputs are confined to this package's unique `test/tmp` directories.
The isolated environment and ready Git bundle are retained for later authorized local integration.

### Final combined-tree verification and local-main outcome

Canonical main advanced during preservation. Its new actual ref
`f8daf3d34dd9576e2c2ee48f825e740475c1fb7a` contains package 02's offline quality gate.
That ref was fetched through a local bundle and merged normally, without conflicts, into this
package's **Linux feature branch**, producing
`e617f90c1ffc7a322c6d06b23b72c706207e6028`. This is not a merge into canonical main.
Ancestry against the newly incorporated canonical-main ref was verified.

The same complete 13-file focused command above was rerun on this clean combined revision:

| Environment and basetemp | Result | Wall time |
| --- | --- | --- |
| Existing environment, `--basetemp=test/tmp/operator06-combined-main` | 410 passed, 2 manual stdio cases deselected; pytest time 69.75 s | 70.57 s |
| Main's pinned quality/test dependencies, `--basetemp=test/tmp/operator06-pinned-combined` | 410 passed, 2 manual stdio cases deselected; pytest 8.4.2, pytest time 39.88 s | 40.66 s |

After the dependency-manifest change from main, the isolated environment was aligned with
`uv pip install --python .venv/bin/python --require-hashes -r requirements/quality.lock`.
No global environment was changed. On exact revision
`e617f90c1ffc7a322c6d06b23b72c706207e6028`, the newly available static gate ran:

```sh
.venv/bin/python -m tools.quality check --base refs/remotes/canonical/main --static-only
```

**PASS**, 36.18 s wall time. Ruff, the configured scoped mypy gate, Bandit and architecture checks
scanned the declared 649-module corpus, reported no new diagnostics, and retained the 47 existing
shrink-only baseline findings without modification. Per-tool times were 0.154 s, 10.774 s,
18.893 s and 5.972 s respectively. The static command intentionally ran no extra unit, integration,
acceptance or live suites. Its bounded mypy scope is not a claim that every adapter is strictly typed.

**Final ready implementation/test revision:** `e617f90c1ffc7a322c6d06b23b72c706207e6028`.
The following record-only commit changes this document, not the tested source, tests or skills.
The final branch tip is retained in `operator-ready.bundle` and
`refs/remotes/operator-package06/ready` in the original repository's Git database.

**Canonical-main landing remains BLOCKED** by the primary-checkout access restriction. The last
incorporated actual main SHA is `f8daf3d34dd9576e2c2ee48f825e740475c1fb7a`; no merge into that
checkout, lock bypass, source-freeze override, origin-chat handoff or remote push was performed.
**Integration and acceptance: NOT RUN.** No server, live review or runtime model was started.

### Local-main landing outcome

The two BLOCKED entries above are retained as history. They described this package's own
worktree session, which could not modify the primary checkout. The user-directed landing was then
handed to the designated canonical-main integration owner, which merged the exact ready commit
into local `main` in `F:\XBOX-Repositories\appsec-review`.

- **Ready SHA:** `b8f77b96937ec6d1d8b98a1bdf78ce46779fbb71`
  (`refs/remotes/operator-package06/ready`, tree `e5d284144a06b9ccb0ebb105dab1c2e89174afa4`).
- **Previous main:** `0d2c6d7b8830436bda7eed3e2c66f89c6525a17d`. It added only package 02's
  evidence document, so the landing was a merge rather than a fast-forward. The merge base was
  `f8daf3d34dd9576e2c2ee48f825e740475c1fb7a`. None of this package's 24 changed paths overlap
  `f8daf3d3..0d2c6d7b`.
- **Merge commit:** `37ae743ca28c26239383d68054accb1826e60ad7`, tree
  `4edb4e1fe254e661ff3b419d2401e662790d5181`, titled
  "Merge operator-mcp-development-skills (b8f77b96)". Its parents are `0d2c6d7b` and `b8f77b96`,
  and it carries the Copilot co-author trailer. The merge had no conflicts, and its tree matched
  the `git merge-tree` prediction.
- **Checkout and lock checks:** the integration owner opened an exclusive OS file handle on
  `.git/appsec-independent-main-integration.lock` in the canonical Git common directory
  (OpenOrCreate, ReadWrite, FileShare.None). It held that handle across the checks and the merge,
  and released it in `finally`. The checks confirmed that the branch was `main` at `0d2c6d7b`, that
  `status -uall` was empty, that there were no operation markers or competing owner, and that the
  ready ref was unchanged. The merge ran with hooks, auto-gc and maintenance disabled. After the
  merge, `git status -uall` was clean, both `b8f77b96` and `0d2c6d7b` are ancestors of `main`,
  and the ignored `targets/` clones were preserved.
- **Validation:** the integration owner ran no tests on the merged tree. The recorded evidence
  is the 410-test focused run and the static gate on `e617f90c` above. Focused Linux checks on the
  landed SHA are still pending in this package's worktrees.
- **WSL:** canonical WSL `main` (`~/projects/appsec-review`) is a separate checkout with its own
  custodian. When this record was written it remained at
  `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`. Updating it awaits that custodian's authorized step.
- No push or pull request was made.

### Post-landing verification

- **Tested revision:** `1a627f23d904c0c86233c92b1ad6e2ef7d0e07a6`, the landed `main` that includes
  the landing record above, checked out in this package's isolated Linux environment. The complete
  13-file focused pytest command recorded above was rerun unchanged except for
  `--basetemp=test/tmp/operator06-post-landing`. Result: **410 passed**, with the 2 manual stdio
  cases deliberately deselected. Pytest reported 56.92 s and the wall time was 57.78 s.
- **Static gate coverage:** `git diff` from the previously tested `e617f90c` to `1a627f23` is empty
  for `src`, `tests`, `.claude`, `tools`, `pyproject.toml` and `requirements`. The earlier passing
  static-quality result therefore covers identical source and configuration.
- **Platforms:**
  - This package's Windows session checkout and isolated WSL worktree are both at `1a627f23`.
  - Canonical WSL `main`, owned by its custodian, was fast-forwarded with the user's approval to
    the exact merge `37ae743ca28c26239383d68054accb1826e60ad7`. The custodian reported that
    `b8f77b96` is an ancestor and that tracked status was clean. It also reported that
    `data/feeds`, ignored targets, `.git/rebase-apply` and non-main refs were preserved.
  - The user then directed that Windows and canonical WSL `main` be brought to the same commit.
    The canonical-main integration owner reports the exact resulting SHA outside this record.
- This supersedes the historical integration blocker. No canonical source freeze remains.
  **Integration, acceptance, live review and runtime model execution: NOT RUN.** No push or pull
  request was made.
