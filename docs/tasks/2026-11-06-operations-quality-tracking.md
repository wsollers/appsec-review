# DEVELOPMENT PACKAGE 05 - OPERATIONAL VISIBILITY, QUALITY TRENDS AND RETENTION

User authorization, quoted verbatim: "I agree with 1,2,3,4,5 and the mcp / skill recomendations. please create a detailed instruction prompt for each  to implement them on independent working trees. They should be fully covered with unit tests. There should be intergration and acceptance tests (but do not run them due to time constraints). when complete and tested the code should be merged back to local main. These tasks can run as top level independent chats and do not need to be monitored or supervised. Ensure all of these are included in their respective development package. Run those chats/tasks/workers on the Model GPT 6 Astra High 1M context window."

Implement recommendation 5 as a coherent operational package, not a replacement pipeline. Save this entire specification before coding as docs/tasks/2026-11-06-operations-quality-tracking.md and append verification and local integration results. This is detached independent autopilot work; do not seek supervision or send status to the originating chat. Use GPT-6 Astra/high/long-context for any genuinely necessary bounded subagent. Do not push, open a PR, query customer services, run live reviews/models, or deploy infrastructure.

Environment/baseline
Repository wsollers/appsec-review at reviewed base 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5; confirm ancestry and account for newer main. Follow AGENTS.md and .claude/skills/multi-session-coordination/SKILL.md. Develop/test in your own Linux/WSL Linux-filesystem worktree and environment, not the Windows primary checkout. Ubuntu-22.04 is available. Canonical local integration main is F:\XBOX-Repositories\appsec-review; a mirror's main does not satisfy completion.

Ownership and interfaces
Own observability/, operational/reporting telemetry modules, enhanced presentation in deploy/dagster/bin/run_report.py and related status/watch utilities, longitudinal quality reports, and durable-run retention code plus their tests/docs. Source prefixes otherwise mean src/appsec_review. Package 01 owns runtime job/graph/repair and primary cli.py; 03 owns transport/retry/budget charging; 04 owns guidance and per-case multi-turn competence evaluation; 06 owns thin read-only operator MCP adapters. Do not create competing job-state authority or rewrite those siblings' internals. Preserve existing report schema/API compatibility while introducing versioned extensions. All features must function against current accepted receipts and event APIs without requiring an unpublished sibling change. Use standalone operator/reporting entrypoints rather than racing package 01 over CLI recovery code; avoid pyproject changes owned by 02.

Known baseline
Progress heartbeats, resource spans, attempt/run IDs, gap accounting, model-call events, execution receipts with exit/timeout/OOM/stdout/stderr hashes, run_report.py and review_run.py status/watch already exist. Build workspace retention already protects active/held work. acceptance/scoring.py and review/evaluation.py already compute quality metrics. This checkout has no actual review-run directories, only metadata; do not fabricate live metrics. The gaps are joined usability, consistent classification, unknown usage, cost provenance, trend persistence and general artifact lifecycle.

Required implementation
1. Build one bounded operator status presentation joining application run, orchestration dispatch, job/step/attempt, last progress, retries, declared gaps, failure records, reusable evidence and resource/cleanup ownership. Keep operational success separate from analysis completeness. Base liveness on recent progress and authoritative process/orchestrator evidence, not age alone; unknown must not mean dead. Show why work is blocked and what safe action is possible. Preserve existing status/watch commands.
2. Standardize reporting of existing execution and model events/receipts. Include exit/timeout/OOM/cancel categories and hash-bound diagnostic references without dumping stderr, source, prompts or secrets into central logs. Repair verified TimeoutExpired reporting, event correlation and reused/unknown usage interpretation in the owned reporting layer. Package 03 will improve transport mechanics; support old and new valid records explicitly.
3. Add bounded offset/cursor-based event following and incremental aggregation where appropriate, avoiding repeated full-log reads in long sessions. Measure/represent lock wait, fsync and aggregation overhead through existing spans. Separate authoritative lifecycle durability from progress sampling; do not silently drop critical records. Add bounded, configurable stuck/cleanup-unconfirmed alert records or local notifications with deduplication, without installing an external monitoring service.
4. Add cost provenance: provider-reported charges where actually available, opt-in versioned API-price estimates, and subscription/unknown usage without invented dollars. Expose per-run and per-job totals; per-finding allocation must be clearly labelled and avoid double-counting shared calls, retries or cached/replayed results. Preserve unknown usage instead of zero. Do not provision billing APIs or assume token counts equal subscription charges.
5. Publish revision-bound quality trend artifacts from existing acceptance/evaluation results. Record corpus identity, implementation SHA, prompt/model/config identities, case counts, precision/recall, justified abstention, unsupported conclusions, retrieval failure and usage. Incomparable configurations/corpora, empty denominators, missing results and duplicates need explicit statuses. Supply deterministic recorded-fixture regression thresholds and a manual opt-in live-evaluation path, not automatic live calls.
6. Implement reference-aware durable-run/artifact retention planning with a dry-run default and explicit operator apply. Respect active runs, leases, repair holds, retained audit roots, accepted receipts, cross-run references and existing build workspace retention. Fail closed on malformed/unknown roots or uncertain ownership; never delete retained dependencies based solely on age. Test deletion only in tiny synthetic fixtures. Do NOT delete, compact or migrate any existing production runs/data during this task. Use the smallest implementation that can prove safe scope; unsupported legacy states must be named holds, not silently treated as garbage.
7. Optional OTLP export should be a derived bounded read of existing events, disabled by default, with redaction and backpressure/failure visibility. It must never become evidence authority or block a review because a collector is absent. Implement a testable adapter without provisioning a collector or exporting real run data. Reuse existing dependency mechanisms; coordinate manifest changes through latest main rather than overlapping package 02.

Unit tests to implement and RUN
Use synthetic run folders, deterministic clocks, fake Dagster responses and in-memory/fake exporters. Cover active-versus-stale long operations, missing heartbeats, incomplete and conflicting lifecycles, torn log tails, cursor restart/truncation, reused gaps, multiple dispatches and attempts, bounded scans, unsupported schemas, timeout/OOM/cancel distinctions, diagnostic redaction, actual/estimated/subscription/unknown cost, missing token usage, replay/cache accounting, shared-cost allocation, trend comparability and thresholds, and exporter failure/backpressure. Retention cases must cover active/held roots, cycles/dedup/shared objects, cross-run references, concurrent claims, path/symlink refusal, interrupted deletion, idempotent plans and preserved accepted evidence. Exercise existing aggregation/status functions rather than mocking them out.

Integration and acceptance tests to WRITE, NOT RUN
Write separate suites combining real event writers and receipt readers with an isolated Dagster service/collector when explicitly requested later; interrupted jobs and restart; quality trends over a pinned fixture corpus; and retention applied to a disposable multi-run fixture with reuse/holds. Keep them under tests/integration and tests/acceptance and excluded from default unit collection. No service startups, Docker builds, live reviews, real telemetry export or integration/acceptance execution now. Document exact manual commands and prerequisites.

Completion and safe local-main merge
Update related operational docs and this package. Run targeted offline unit tests in your isolated Linux environment with unique test/tmp basetemp. Record exact tested revision, commands, elapsed times, outcomes and honest limitations; passing units are not live acceptance. Commit code/tests/docs, incorporate latest local main into your own branch, and rerun affected units on the merged candidate.
Land the tested branch into canonical LOCAL main using the repository's existing serialized integration ownership/lock. If no integration lock exists, all six packages use an OS-backed advisory appsec-independent-main-integration.lock in canonical main's Git common directory. Hold it only during final safe main inspection/update; refuse dirty main, active source freezes, existing ownership conflict or unexplained semantic conflicts. Never reset/force-checkout, blanket-select ours/theirs, push remotely, or start a monitoring loop. Verify ready SHA ancestry in final main. Finish with implementation/ready/main SHAs and unit results, clearly labelling integration/acceptance NOT RUN. If landing is blocked, preserve ready commits and name the blocker in your own session.

## Subsequent user clarification

"I'm confused WSL \~/projects/appsec-review is what we have been considering the master repo. Any work in the window repo must sync to there"

WSL `~/projects/appsec-review` is consequently the authoritative integration target;
the earlier Windows integration target above is superseded. Initial read-only verification
confirmed both repositories at `528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`.

## Implementation and verification record

The specification was committed before coding as
`605daf95` (full SHA available in Git). Initial implementation was committed as `843aba70`;
receipt/checkpoint/retention revisions and manual suites were committed as `c8ad7e1b`.
All are on `william-sollers-xbox-operations-and-quality-tracking`.

Verification uses the isolated Linux-filesystem worktree
`/home/wsollers/copilot-worktrees/operations-quality-b603f2c2`, with its own editable install
and Python 3.12.15 `.venv`. Its imported `appsec_review.__file__` was confirmed inside that
worktree. The Windows worktree's `.git` file contains a Windows absolute path and cannot be
read directly by Linux Git; local Git bundles transfer exact commits instead. No network push
was performed. The initial system interpreter was Python 3.10.12 and lacked pytest, so the
test extra was installed into this separate Python 3.12 environment with:

```sh
uv venv --python python3.12 .venv
uv pip install --python .venv/bin/python -e '.[test]'
```

Focused unit commands, executed from the isolated worktree:

```sh
.venv/bin/python -m pytest -q \
  tests/test_operations_reporting.py tests/test_operations_quality.py tests/test_operations_retention.py \
  tests/test_pipeline_log.py tests/test_operation_telemetry_gaps.py \
  --basetemp=test/tmp/operations-b603f2c2-first
```

At `843aba70`: **75 passed, 1 failed in 31.55s**. The new timeout regression omitted two
required `ReviewModelRequest` token-limit fields; the fixture was corrected, without weakening
the exception or redaction assertions.

The same selectors at `c8ad7e1b`, using
`--basetemp=test/tmp/operations-b603f2c2-second`: **85 passed in 31.45s**.
Both runs emitted an existing Python warning from the explicit fork regression in
`test_operation_telemetry_gaps.py`; it was not suppressed. These are offline unit results, not
live acceptance. The selected pre-existing sampler tests make this check roughly 32 seconds.

The integration and acceptance suites were syntax-parsed only, not imported or executed.
Their exact manual commands and service prerequisites are in
`docs/operations/quality-and-retention.md`.

Supported retention application is deliberately restricted to explicitly sealed, private
offline artifact stores. Ordinary production/legacy roots remain named holds: existing live
writers do not share the new offline-store deletion lock. No production data has been
deleted, compacted, sealed or migrated. No integration or acceptance execution, live review,
service startup, deployment or real telemetry export has been performed.

Implementation candidate before the final custody audit:
`7d8c3901b2660c5f0f0979ecce13d25c0115b7c8`.

The expanded focused command was:

```sh
.venv/bin/python -m pytest -q \
  tests/test_operations_reporting.py tests/test_operations_quality.py tests/test_operations_retention.py \
  tests/test_pipeline_log.py tests/test_operation_telemetry_gaps.py \
  tests/test_pytest_default_collection.py tests/reporting/test_telemetry_inputs.py \
  --basetemp=test/tmp/operations-b603f2c2-candidate
```

At that exact implementation commit: **106 passed in 30.94s**. Then `git merge --no-edit main`
in the isolated WSL worktree confirmed the candidate already contained authoritative WSL main
`528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`. The same command, with
`--basetemp=test/tmp/operations-b603f2c2-main-candidate`, was rerun on the unchanged merged
candidate: **106 passed in 31.88s**. The same existing fork warning remained visible.

All three standalone entrypoints (`operator`, `quality`, `retention`) passed offline `--help`
checks. Both manual suites were syntax-parsed again without execution. The recorded synthetic
fixture is byte-pinned to SHA-256
`d7f98edbf8deb0458657ef4fb1f7fee264ee1ff7ee23afa76841955ba3331a33`.
Its committed bytes are retained under the repository's `-text` fixture rule; portable source
and documentation were checked/normalized to LF without changing those fixture bytes.

No new mounts or deployment were performed. The changed application Python modules require a
future user-requested application-image rebuild/reload through the existing signed lifecycle;
they are not hot-loaded merely because this source branch is integrated.

The final custody audit additionally rejects hardlinked or writable catalog, journal and lock
control files, not only artifact aliases; its focused regression is included in the final run.

### Final tested implementation and local integration result

Initial ready-code SHA: `de3178df75eaea298db22fdd78bcd2266e71031a`.
The expanded seven-file command above, with
`--basetemp=test/tmp/operations-b603f2c2-ready`, passed **107 tests in 31.23s** after
incorporating current WSL main (already up to date). The existing fork warning remains the
only warning. Subsequent handoff changes are documentation-only.

At the first guarded integration attempt, canonical WSL `main` was
`528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`.
Integration was **attempted and refused**, not performed. The OS-backed advisory
`/home/wsollers/projects/appsec-review/.git/appsec-independent-main-integration.lock`
was held during the final inspection and released on refusal. WSL main contains these nine
pre-existing untracked provenance files:

```text
data/feeds/nvd/provenance/sha256-043a85b6911198e6/27749a75513307c695d4bfac76bd00964058a236416492321269cc7b201c0362.json
data/feeds/nvd/provenance/sha256-1469bd3d33eb4026/7eca6c16e6e826c04ed9032e1d332c74eb5d71be9af14ee5a099362caf714fc4.json
data/feeds/nvd/provenance/sha256-82b0d4a335e49053/a722a111f0f5416a884f49af7f066a940113b05c3489b9d5aaa419b9f9056672.json
data/feeds/nvd/provenance/sha256-a4372f6ee319d62c/4ab663164a8322e5a9c8c94acfa1eb425a338a41de000b3f53929446c058f8f7.json
data/feeds/nvd/provenance/sha256-c9b29a6b2c3d3dd9/c5b5c84591dc83c927ce30aad2c814bbee593f1df526f4fed7efbd352c844923.json
data/feeds/nvd/provenance/sha256-ddc9f6d711fe276d/23b33002ad1633fcfca3a3f90fc4082ef79e305996eecd007d69a87d6628a693.json
data/feeds/nvd/provenance/sha256-dfa1d05817d8d858/b5abd3ac85a3600c288246ab89452191ed158b76d9d855615286df4d3b246456.json
data/feeds/nvd/provenance/sha256-dff574e49f810a38/48bdb2882c2e120c2fb767e05ba5c7977b893afd3db6b63d293848b4240853d6.json
data/feeds/nvd/provenance/sha256-e38cf684c7b1a798/aeb9c8c99f014ff413e786c1a75258b0bde11a19a424e8f72f96b264b226de91.json
```

Those files were not read, deleted, moved, ignored, staged or committed by this package.
The guard stopped at the dirty-tree check, so later source-freeze/runtime ownership checks
were not claimed complete. Existing WSL run directories are not assumed inactive based on age.
No customer/local service was queried to bypass the guard.

Ready work is preserved on `william-sollers-xbox-operations-and-quality-tracking` in both
the app-facing Windows repository and the authoritative WSL repository's Git database, with
the separate Linux worktree retained. The final branch-tip SHA (including this documentation)
is recorded in the session handoff. The Windows primary checkout was not touched.

The integration owner must resolve the unrelated dirty provenance state explicitly, then
incorporate any newer WSL main, rerun the affected offline units and retry the same serialized
ownership/source-freeze checks before landing. No force checkout, reset, stash, automatic
conflict resolution, push, PR, deployment or production cleanup was used.

**Integration and acceptance suites: WRITTEN, NOT RUN. Live evaluation and real OTLP export:
NOT RUN. Production retention application: NOT RUN.**

### Incorporating independently advanced main

During final synchronization, another package advanced WSL main to
`37ae743ca28c26239383d68054accb1826e60ad7`. A fresh locked inspection confirmed the **same
nine untracked provenance files**, so the dirty-main blocker was not resolved. This package
did not infer permission from another session's merge and did not bypass the guard.

That newer main was incorporated into this package's isolated branch as merge
`d4d8b8cfea57e9a0c1d52c437f8d5395579bf566`, then transferred back to the app-facing branch
by local bundle. The merge had no content conflicts. Its committer identity was supplied
per command from this session's existing Git author identity; no shared/global Git config
was changed.

Latest main added the quality dependency extra/lock and public cross-package boundary checks.
The existing reporting timestamp/status helpers were exposed as public reporting interfaces
rather than importing private symbols or duplicating their behavior. At
`25703d3367f7c4199ccafa2d9437825f465cfe8d`, the same seven-file unit command with
`--basetemp=test/tmp/operations-b603f2c2-current-main` passed **107 tests in 40.60s**, using
the latest-main pinned pytest 8.4.2. The static gate ran concurrently:

```sh
uv pip install --python .venv/bin/python -e '.[test,quality]'
uv pip install --python .venv/bin/python --require-hashes -r requirements/quality.lock
.venv/bin/python -m tools.quality check \
  --base 37ae743ca28c26239383d68054accb1826e60ad7 --static-only
```

Static result: **PASS**, 655 modules scanned, no new diagnostics, 47 existing baseline
findings retained under the unchanged shrink-only policy. Timings: Ruff 0.175s, mypy 11.717s,
Bandit 19.409s, architecture 5.736s. This gate's own unit selection was **NOT RUN**;
the affected 107-test suite was executed separately. Static checks are not live vulnerability
assessment, and their declared type-checking boundary remains the one documented by Package 02.

Final retention revision: `4e5e344b8bc03b46ea3cc5205d028c62be45ab29`. Its only code delta
from the statically checked candidate rejects malformed sealed-store owner identities.
The focused final command was:

```sh
.venv/bin/python -m pytest -q tests/test_operations_retention.py \
  --basetemp=test/tmp/operations-b603f2c2-final-retention
.venv/bin/python -m ruff check --ignore-noqa src/appsec_review/observability/retention.py
```

Result: **16 passed in 1.56s**, and the focused Ruff check passed. These 16 tests overlap the
combined suite; they are not presented as 16 additional independent cases.
The ready branch includes WSL main `37ae743ca28c26239383d68054accb1826e60ad7`; landing remains
blocked by the unrelated dirty provenance state. No production data or Windows-primary
checkout changes were made.

The final current-record compatibility check also covered the existing `JOB_REUSED` shape,
which records a handoff hash without completion metadata. Revision
`df49731c418ff7e4394efa91ad82d1292154e435` preserves that hash as an unverified reference and
reports unknown reused completeness explicitly instead of treating an outer success as
coverage evidence. On that exact **final implementation SHA**:

```sh
.venv/bin/python -m pytest -q \
  tests/test_operations_reporting.py tests/reporting/test_telemetry_inputs.py \
  --basetemp=test/tmp/operations-b603f2c2-final-reporting
.venv/bin/python -m ruff check --ignore-noqa src/appsec_review/observability/operator.py
```

Result: **36 passed in 4.58s**, and the focused Ruff check passed. These tests overlap earlier
runs and are not summed into an inflated coverage count. The final handoff adds documentation
only; source/test/deploy byte identity is checked against this implementation. Disposable
test state and tool caches created by this package were removed from its isolated worktree.
Its Linux environment, ready branch and local transfer bundle are retained for integration
after the independent dirty-main blocker is resolved.
