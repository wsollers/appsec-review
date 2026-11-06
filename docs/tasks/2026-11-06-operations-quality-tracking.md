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

Serialized WSL-main integration is pending the final ownership, dirty-tree and source-freeze
inspection. Existing WSL run directories were observed; their age is not evidence of inactivity.
The final custody audit additionally rejects hardlinked or writable catalog, journal and lock
control files, not only artifact aliases; its focused regression is included in the final run.
