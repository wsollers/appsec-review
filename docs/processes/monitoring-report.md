---
title: "Review monitoring and job-output reports"
kind: "process"
subsystem: "reporting and metrics"
status: "current"
jobs: []
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# Review monitoring and job-output reports

Use this Markdown format for a five-minute monitoring chat and its separate job-output
verification chat. This document defines reporting and a reusable kickoff prompt, not a new
runtime protocol or standing permission to launch, repair, or bypass checks. Root
[`AGENTS.md`](../../AGENTS.md) governs. The kickoff's user authorization, not telemetry or a model's
output, commissions operations.

## Evidence and scope

Read the [monitor procedure](../operations/run-monitor.md), [metrics reference](../operations/metrics.md),
and [recovery runbook](../operations/recovery-repair.md). Use current job contracts and the deployed,
run-owned graph: jobs may have changed since an earlier run or audit.

| Report content | Evidence source |
| --- | --- |
| Observed identity and event coverage | `appsec-review/run-monitor/1`: `observed_at`, `run_id`, `dagster_run_id`, `profile`, `configuration_sha256`, `source_sha256`, `graph_sha256`, `coverage`, `gaps` |
| Current job progress | `state.jobs`, `state.epoch_attempts`, `state.current`, `state.current_steps`; preserve their completeness flags |
| Historical attempts and reuse | `state.attempts`; distinguish observed reuse from planned retention |
| Model usage and timing | `models.totals`, `models.by_model`, `models.hotspots`, `models.cost`, their availability/sample counts |
| Changes since last poll | `delta`, only when `available` is true |
| Native execution | Exact Dagster run's status, parent/root, execution-plan snapshot, selected steps, and step timestamps |
| Resource, retrieval, and tool work | Existing `run-metrics/7` summary and bounded operation/tool receipts, with their observation time and scope |
| Correctness and meaningful output | Verification chat's exact-attempt report, accepted handoff/outcomes, referenced artifacts, and independent source/tool evidence |

The monitor is not a receipt validator or a quality audit. Do not regenerate the full metrics
summary or rescan every artifact every five minutes. Read an existing summary only when relevant;
if absent or stale, say so. Inclusive resource/phase times are not additive across overlapping
spans. A raw scanner observation, claim, verified finding, and published finding are different
quantities.

Use `unknown (reason)` for missing measurements and `>=N` for lower bounds. Use `N/A (reason)`
only for something genuinely not applicable. Zero requires measured evidence. Completed job
counts include failed terminal jobs; never label that total "successful." A selected/retained
plan is not proof of execution or consumption. No ETA from job counts alone.

Preserve complete identities in the session's run record; the report may abbreviate digests
once that record is linked. Always display the complete application and Dagster IDs.
Report timestamps with a timezone, including UTC. Do not expose raw prompts/responses,
credentials, tool arguments, target source excerpts, or unbounded exception text in status reports.

## Five-minute report template

Use the same headings at every poll. Keep tables to active/newly terminal work and top-three
hotspots; report omitted-row counts. A quiet poll can say "unchanged" but must retain the current
identity, authoritative execution status, and material caveats.

```markdown
### Review monitor - <YYYY-MM-DD HH:MM:SS UTC> (<local time and zone>)
**Execution:** <native state> | **Quality:** <pending/pass/fail/blocked, verifier report ref>
**Change:** <one sentence describing actual new progress, failure, or no change>

**Identity:** app `<APPLICATION_ID>`; Dagster `<DISPATCH_UUID>`; parent `<UUID or none>`.
Profile/model/reasoning: `<values>`; configuration `<sha>`; implementation `<sha>`;
tooling image `<identity>`; target `<commit/snapshot>`. Epoch `<id>`.
Monitor `<chat ID>`; output verifier `<chat ID>`; fix chain `<FIX chat IDs/branches or none>`; identity record `<reference>`.

#### Progress
Selected jobs <N or unknown>; terminal <N>; running <N>; remaining <N>.
Terminal partition: <succeeded / completed-with-gaps / failed / cancelled / other observed states>.
Current attempts <N>; historical attempts <N>; job retries <N>.
Retained plan <N>; observed accepted-job reuse <N or unknown>; task reuse <N or unknown>.

| Job / attempt / step | Native and application states | Elapsed / last progress age | Result or blocker |
| --- | --- | --- | --- |
| <identity> | <states, separately> | <durations and clock origins> | <bounded reason/evidence ref> |

#### Models and work
Scope: <application all epochs or explicitly measured dispatch interval>.
Calls <N>: succeeded <N>, failed <N>, active <N>; model retries <N>; invalid outputs <N>.
Tokens: input <N>, output <N>, cache <N>, reasoning <N or unknown>.
Call latency p50/p95/max <values>, measured/missing samples <N/N>;
queue delay p95 <value>, measured/missing <N/N>, scope <e.g. accounting admission>.
Cost <measured amount/currency or unknown>; credits <measured or unknown>.
Top time/token/retry hotspots: <up to three job/role names with measured values>.
Resource/retrieval/tool work: <available measured counters with scope/age, or unavailable reason>.
Delta since <time>: <reliable changes, or unavailable reason>.

#### Output quality
Verifier backlog <N jobs>; checked <N>: pass <N>, fail <N>, blocked <N>, not applicable <N>.
Finding funnel: <scanner observations / admitted leads / proposals / unique claims by state /
publishable findings / published findings, each with its own denominator or unknown>.
New meaningful outputs: <actual artifacts/counts and verifier evidence, or none established>.
Gaps: <canonical cause counts; expected / unexpected / unclassified, with decision refs>.

#### Limits and next action
Telemetry: <caught-up/backlog, sequence, last-event time, omitted rows, timestamp/graph/ownership gaps>.
Receipt verification: <what was checked by whom, what was not checked>.
Next: <continue, diagnose exact fault, await decision, hand off, or finish>.
```

Do not subtract cumulative lower-bound snapshots to manufacture a delta. Do not call historical
model totals retry expenditure. Keep task, model, job, and native-dispatch failures separate.
Polling delays are reported using actual observation times, not a claimed punctual schedule.

## Job-completion verification

The kickoff/coordinator chat creates both the initial monitoring chat and one separate verification
chat as direct sibling children after concrete run identity exists (never nesting the verifier inside
the monitor).
That chat follows newly terminal jobs in the exact dispatch and audits accepted publications,
not files still being written. Failed/rejected attempts may supply diagnostic evidence, not
accepted output. Discover completions at least every five minutes; process each new
`(application, dispatch, job, attempt, handoff hash)` once and retain a durable cursor/report index.
Never redispatch jobs merely to inspect their output.

For each job, reconcile:

1. **Inputs:** declared contract versus admitted/supplied handoffs, configuration/source/target
   identities, and actual read receipts. Keep availability, supply, read, and citation separate.
2. **Files and accounting:** committed publication marker and referenced hashes, schemas, actual
   files, row counts, partitions, duplicates, missing outputs, and meaningful consumer links.
   A successful rendering task is not proof of a PDF: inspect its receipt and actual PDF.
3. **Meaning and physical payload invariants:** compare outputs with evidence independent of the
   producer (target source, raw tool results, or independent counts). Checking `handoff.json`
   hashes, receipt JSONs, aggregate counts, or `COMPLETED_WITH_GAPS` status never establishes
   usefulness. For compiled and indexed stages, directly inspect binary section headers (`readelf -S`
   `.debug_*` / `-g` flags in `compile_commands.json`), real build targets versus configure-probe
   artifacts (`CMakeScratch`/`CompilerId`), first-party file and function-body coverage inside
   SQLite `entities`, `locations`, and relationship tables (symbols, AST, IR, CFG, call graph,
   CSA seeded neighborhoods, scanner shards), and tool stderr plus kernel/cgroup OOM logs (`dmesg`)
   whenever any tool or sub-branch shard has `0` rows (even when container `oom_killed` is `false`).
   Record whether the check was exhaustive or sampled and what was not examined.
4. **Look behind gate rejections and `BLOCKED` masks:** when a build or tool job rejects outputs
   on a policy, capture, or schema gate (or leaves downstream jobs `BLOCKED`), still inspect the
   raw built `.o`/ELF binaries, `compile_commands.json` flags, scratch outputs, and stderr/OOM
   logs already on disk in that same verification pass so co-existing build, flag, or tool defects
   are caught in the same repair cycle rather than hidden until the next epoch.
5. **Gaps and findings:** group canonical outcome gaps by cause, not repeated log strings.
   Match expected causes to explicit user decisions; historical failures are not an expected
   list. Explain legitimate empty/not-applicable outputs. Unexplained zeros, missing compile
   evidence when compilation is applicable, and an all-insufficient-evidence result need a
   causal diagnosis, not a pass.

Some jobs correctly produce no findings. Expect useful findings from the review as a whole,
but never force each job to report a vulnerability. Do not read `PLANTED.md`, answer keys,
evaluator guides, or private fix pairs to steer the review. Known planted defects are an
expectation to investigate, not permission to invent a finding or relabel a gap as confirmed.

```markdown
### Job output verification - <job> / <attempt>
**Result:** <PASS / FAIL / BLOCKED / NOT_APPLICABLE> | **Meaningful:** <yes / no / unverified>
App `<ID>`; dispatch `<UUID>`; handoff `<path>@<sha>`; checked `<UTC time>`.
Source/config/target identities: <exact refs>. Prior audit: <ref, source revision, applicability>.

| Check | Expected / independent evidence | Observed | Assessment |
| --- | --- | --- | --- |
| Inputs and actual consumption | <contract, admitted pins, read receipts> | <observed footprint> | <result> |
| Published files and schemas | <required outputs> | <verified refs/counts, missing files> | <result> |
| Content and relationships | <independent counts/source/tool evidence> | <meaningful content, joins, locations> | <result> |
| Coverage and gaps | <scope and approved expected-gap decisions> | <canonical cause/count partitions> | <result> |
| Consumer usefulness | <what downstream work needs> | <usable/blocked/not applicable> | <result> |

**Findings/output funnel:** <relevant measured quantities and denominators; not invented zeros>.
**Empty-output explanation:** <proved reason or unresolved blocker>.
**Unexpected gaps/defects:** <IDs, causal evidence, affected inputs/outputs and consumers>.
**Expected gaps:** <cause, cost to coverage, user-decision reference; or none confirmed>.
**Not verified:** <sampling bounds, unavailable raw evidence, unresolved source references>.
**Action:** <no repair / notify monitor with exact repair boundary / user decision>.
```

Store these reports in session artifacts or an explicitly assigned host-local audit directory,
not in the target or another job's publication. The verifier is read-only apart from its own
reports/cursor. It never changes acceptance, restarts Dagster, or edits runtime data.
It sends new causal defects to the monitor immediately. For each distinct failing or defective
job within its user-authorized scope, the monitor stripes the repair onto a dedicated sibling
`FIX - <XXXX>` chat working in an isolated Linux worktree branched directly off `main` rather than editing the live
run's checkout inline; unresolved expected-gap, target-scope, or policy choices go to the user.
It must not quietly mark an unexpected gap as expected.

The background verifier does not gate Dagster scheduling. If the user instead wants no downstream
job to run before independent acceptance, use the existing job-by-job walk, not this full-run
monitoring prompt. This distinction must be stated at launch.

## Fault, handoff, and final report

Append the following to a fault/recovery report:

```markdown
#### Recovery
Fault <app/dispatch/job/attempt/step>; failure time <UTC>; detected <UTC>.
Cause <source/artifact-supported diagnosis>; evidence <references>; uncertainty <named gaps>.
Fix <FIX chat ID(s), isolated worktree branch(es) off main, merged main revision, changed files>;
validation <focused unit tests in worktree and post-merge on main, or not run>.
Boundary <whole failed job(s) and genuinely affected descendants>;
retained successful jobs <N and evidence>; no cell/pool salvage.
Admission <plan/config/source refs>; native parent <UUID>; selected steps <N/list ref>.
Timing: detection -> fix ready <duration>; run terminal -> merge complete <duration>;
restart command -> native STARTED <duration>; command -> claim <duration>;
claim -> first handler <duration>; claim -> application terminal <duration>;
claim -> native finalization <duration>.
Output <accepted disposition/counts/artifact refs, or not yet published>.
Successor monitor <chat ID>; verifier <chat ID>; prior monitor schedule <cleared/not cleared>.
```

The monitor's repair orchestration authority comes from the executed kickoff below; the read-only
monitor skill alone does not grant it. Preserve actual admission/signing checks and original
evidence. Follow current `AGENTS.md`: do not invent source locks or run automatic regression
suites. Do not broaden fixes into audit-wide cleanup or a new recovery framework. Changes to
budgets, bypasses, scope, or costly extra runs need user direction.

Stripe each job's repair onto a fresh `FIX - <XXXX>` chat and isolated Linux worktree off `main` so the active
run and its five-minute monitoring keep progressing without touching the bind-mounted main checkout:

- **Keep the active run progressing untouched:** `/home/wsollers/projects/appsec-review` is
  bind-mounted read-only into Dagster under signed-source verification. Never edit
  `/home/wsollers/projects/appsec-review`, reload Dagster, or cancel unaffected running branches
  while the dispatch is still active. Let unaffected jobs run to completion and let the verifier
  continue auditing newly completed publications.
- **Launch one `FIX - <XXXX>` sibling chat per affected job:** When the monitor confirms a runtime
  fault or receives a source-supported causal defect from the verifier for a job not already owned
  by an active fix chat, send the bounded fault/defect package to the parent kickoff/coordinator
  chat so the parent calls
  `create_session(session_kind="chat", name="FIX - <XXXX>", kickoff={"mode": "autopilot", "prompt": "..."})`
  (`<XXXX>` = short job slug or defect ID, at most 40 characters total; pass
  `detached=true` only when no parent coordinator chat exists). This keeps every `FIX - <XXXX>`
  chat as a flat sibling alongside `Verify ...` and `Monitor ... (epoch N)` and isolates each job's
  diagnosis, edits, and unit tests in its own clean context window.
- **Spawn each `FIX` worktree independently off `main`:** The coordinator assigns each issue a
  distinct sequence label (`seq = 01, 02, ...`) and branches **every** `FIX` worktree directly off
  `/home/wsollers/projects/appsec-review`'s frozen `main` commit (`BASE_SHA`), never chaining
  `FIX-02` onto an unmerged `FIX-01` branch:
  `git -C /home/wsollers/projects/appsec-review worktree add /home/wsollers/projects/appsec-review-fix-<run-id>-<seq>-<slug> -b fix/<run-id>-<seq>-<slug> <BASE_SHA>`
  - Each `FIX - <XXXX>` chat runs Python/pytest inside its own worktree with
    `PYTHONPATH="$PWD/src"` using `/home/wsollers/projects/appsec-review/.venv/bin/python`
    (verifying `appsec_review.__file__` resolves inside its worktree; never reinstall into the
    shared `.venv` or edit `/home/wsollers/projects/appsec-review`), fixes the root cause and
    immediate blockers, adds focused unit regression tests (`<10s` per test,
    `--basetemp=test/tmp/<slug>`, shuffled/parallel check), verifies `git diff --check`, commits
    cleanly on `fix/<run-id>-<seq>-<slug>`, reports the exact commit SHA, touched files, whole-job
    boundary, and unit results to the coordinator and monitor, and ends without a schedule.
- **Merge back when the run is over, reload, and restart affected whole jobs:** Wait until the
  active Dagster dispatch reaches a confirmed terminal state (reconciled with `verify-repair-stop`
  and with the verifier's completion backlog for that dispatch drained) **and** all dispatched
  `FIX - <XXXX>` chats for the epoch have reported ready commits. Then, at this explicit terminal
  run/epoch boundary when no Dagster run is `STARTED`, the serialized integration owner
  (coordinator or retiring monitor, never two sessions concurrently) merges the ready
  `fix/<run-id>-<seq>-<slug>` branches into `/home/wsollers/projects/appsec-review` (`main`) one at
  a time (`fix-01` through `fix-NN`, resolving any cross-branch conflict explicitly), runs the
  combined affected focused `<10s` unit tests and `git diff --check` on `main`, removes the merged
  temporary worktrees (`git worktree remove ...`) and `fix/<run-id>-*` branches, reloads signed
  sources (`lifecycle.py reload` / `scripts/stack-restart.sh --code-location-only`), and restarts
  the entire failed/defective job(s) with mandatory parent linkage
  (`scripts/review-start.sh --run-id <APP_RUN_ID> --parent-run-id <DAGSTER_RUN_UUID> --restart-from-job <JOB_ID>`),
  retaining compatible successful jobs and invalidating affected downstream outputs. Inspect the
  actual parent-linked selection (`ops.py` rejects `--restart-from-job` without `--parent-run-id`);
  an application `--run-id` alone is not a targeted restart. If admission cannot provide that
  boundary, report the blocker instead of silently launching a fresh full graph. For several
  independent failed jobs, pass `--parent-run-id <DAGSTER_RUN_UUID>` with repeated
  `--restart-from-job <JOB_ID>` flags, not their successful common ancestor.

After a restarted job's dispatch is admitted and has real start/claim progress:

- Spawn a **new sibling monitoring chat** - never nested under the retiring monitor - with complete
  exact app/dispatch/parent IDs, effective config/source/target identities, selection/retention
  proof, repair/timing records, expected-gap decisions, outstanding defects, and the verification
  chat's ID/cursor. Because `create_session` nests non-detached children under whichever session
  calls it, a child monitor must not call `create_session` with default nesting: instead, send the
  complete successor kickoff and recovery record to the parent kickoff/coordinator chat so that
  parent calls `create_session(session_kind="chat", ...)` to create `Monitor ... (epoch N)` as a
  flat sibling alongside prior epoch monitors and the verifier (or, if no parent coordinator chat
  exists, pass `detached=true` so the successor is created as a top-level sibling).
- Reuse the existing verification chat and retarget it explicitly; do not start duplicate auditors
  on every rotation. Preserve old attempt reports; a retry never retrospectively clears them.
- Confirm the successor's identity and five-minute session automation (via the parent coordinator
  or successor handshake) before the old monitor clears its own automation and ends. Transfer the
  single derived-monitor checkpoint without deleting/resetting it. Do not let old/new monitor
  processes poll it concurrently.
- Ending means clear the old schedule and finish the conversation turn. Do not delete the chat,
  kill unrelated processes, archive the verifier, or claim the restarted fault is fixed merely
  because the successor is `STARTED`. The successor checks passage of the original fault.
- If successor creation/scheduling fails, the old monitor retains responsibility and reports the
  failure; never abandon a live retry or create many speculative replacement chats.

On terminal execution, require exact dispatch-bound graph/selection and terminal evidence,
independently reconciled with native Dagster. Keep missing run-owned graph/event evidence as a
named gap, never manufacture it. Native snapshot/terminal records can be retained separately for
operator reconciliation. Ask the verifier to drain its known completion backlog and deliver its
final meaningfulness report. Overall execution and quality are separate final outcomes.
Clear monitoring only after terminal reconciliation; the verifier clears its own schedule when
its backlog is exhausted or explicitly reported blocked. Surface unresolved output failures,
expected/unexpected coverage costs, actual report/PDF/OpenVEX artifacts, and measured timings.

## Copyable fresh-run kickoff

Paste this into a new repository chat. Pasting/executing this prompt requests the operations;
writing this document does not launch them. The initial action is a new full review with a
parallel output audit, not the stricter serialized walk.

```text
Start an entirely NEW C++ smoke review, restart/reload Dagster first, and establish the two
monitoring chats described in docs/processes/monitoring-report.md. This authorizes this initial fresh run
and focused fault-diagnosis/repair/whole-job-restart cycles within it, not additional fresh
whole-graph reruns. Do not reuse a historical run ID.

Read current AGENTS.md, docs/processes/monitoring-report.md, docs/operations/run-monitor.md,
docs/operations/recovery-repair.md, and the relevant development skills. Current AGENTS.md wins
over older process examples. Do not automatically run regression suites, introduce agent source
freezes, disable checks, modify the target, or use answer keys.

Use the Linux checkout /home/wsollers/projects/appsec-review via ssh -o BatchMode=yes wsl-ubuntu,
with its own .venv. From Windows, send literal bash in a PowerShell here-string ending '# End';
do not use wsl -e bash -c or develop in the Windows checkout.
Target: appsec-review-smoke-cpp; profile: copilot-dev-astra-6.2; overlay: none;
recording: off; compiler family: clang. Verify current target HEAD and deployment selection;
record the actual commit, snapshot, configuration, source release, image and model identities.
Do not change the target to match an old pin or assume the old 43-job graph remains current.

Inspect live Dagster state first. If another review is active, report the exact conflict before
restarting its services; do not terminate unrelated work. Preserve data volumes and old run
evidence. Jobs have changed: re-sign/reload the actual mounted sources and verify the served code
location and job topology match them before launch. Use the supported stack operation:
  scripts/stack-restart.sh --code-location-only --target appsec-review-smoke-cpp \
    --profile copilot-dev-astra-6.2 --overlay none --recording off --no-probe
If the stack is stopped, use the supported stack-start/lifecycle route with the same explicit
selection. Do not rebuild tooling images for an application-code change. Report an actual
missing-tool/image or launch-guard blocker rather than bypassing it.

Launch exactly once, using the supported fresh-run command:
  scripts/review-start.sh --target appsec-review-smoke-cpp \
    --profile copilot-dev-astra-6.2 --overlay none --recording off \
    --compiler-target clang --id-wait 180
Do not pass --run-id, parent/restart flags, --force or --stop-on-first-error for this initial run.
Reconcile any existing terminal submission intent through its recorded operator route first.
Verify the returned application ID, native dispatch UUID, no-parent identity, actual selected
graph and first admitted claim/progress. Record CLI entry and native STARTED separately.
An ambiguous launch response is a reconciliation task, not permission to submit twice.

From this kickoff/coordinator chat, create ONE separate job-completion verification chat and ONE
dedicated epoch-1 monitoring chat as direct sibling children (do not have the monitor spawn the
verifier underneath itself). Pass each chat the other's exact session ID, this coordinator's
session ID, this full assignment, the exact run identity, and docs/processes/monitoring-report.md.
Use create_session with session_kind="chat" and kickoff={"mode": "autopilot", "prompt": "..."} for each
chat, not a new worktree, workflow fleet, or fictional chat name. Each uses get_session_automation first and
a five-minute save_session_automation schedule in that same chat; never use an app-wide schedule,
a shell loop or a permanent daemon. Schedules contain complete standalone instructions and exact
IDs so they survive context loss. Report honestly if session scheduling is unavailable.

The monitor polls once now and once per wake:
  .venv/bin/python -m appsec_review.observability.monitor --runs-root runs \
    --run-id EXACT_APP_ID --dagster-run-id EXACT_DISPATCH_UUID --save
Also read that exact native run via deploy/dagster/bin/ops.py:
  sys.path.insert(0, "deploy/dagster/bin")
  import ops
  r = ops.get_run(ops.default_url(), EXACT_DISPATCH_UUID)
Bound printed metadata to active/failed/recent step statuses and times. Use the Markdown report
format in docs/processes/monitoring-report.md. Preserve unknowns, lower bounds, graph/epoch scope,
retained-versus-recomputed work, telemetry lag, receipt limitations and observed timestamps.

The verifier follows every completed job, checking actual admitted inputs, published files,
hashes/schemas/counts, semantic correctness and downstream usefulness against independent
evidence and the applicable prior audit. Report whether outputs are CORRECT AND MEANINGFUL,
not merely nonempty: never rely on handoff/receipt JSONs or aggregate counts alone. For build
and index stages, directly verify ELF debug sections (readelf -S .debug_* and -g flags), real
targets versus CMakeScratch/CompilerId probes, first-party file/function-body joins inside
SQLite entities/locations/edges (symbols, AST, IR, CFG, CSA seeded neighborhoods, scanner
shards), and stderr plus kernel/cgroup OOM logs (dmesg) whenever any tool or sub-branch shard
has 0 rows (even if container oom_killed is false). When a gate rejects outputs or blocks
downstream jobs, still inspect the raw binaries, compile_commands.json flags, and tool logs
already on disk in the same pass so co-existing defects are not masked until the next epoch.
Explain legitimate empty outputs; diagnose unexplained zeros and gaps.
Keep scanner observations, proposals, claim states and confirmed/published findings distinct.
Some gaps may be expected, but no exact expected-gap list has yet been confirmed for this new
run: record cause-level user decisions and coverage costs, not blanket exemptions.
We expect useful findings from the smoke review; never manufacture them or inspect PLANTED.md,
private answers or evaluator/fix-pair lists to steer detection.

Prior audit references:
  /home/wsollers/appsec-review-audits/2026-11-24-0001/06d3f854-82e2-4f33-b0fb-ba036eca3a3a/
Use manifest.json, expectations and per-job reports; these describe the original source/attempts.
Only 22 of its 43 whole-job audits were completed (11 FAIL, 11 BLOCKED); 21 were incomplete.
The separate 48-job static I/O audit is not current-run verification. Match each expectation to
the current contract and actual graph; changed/new jobs require fresh examination.
Store new verification reports separately, keyed by run/dispatch/job/attempt/handoff hash.

When the monitor detects a confirmed runtime fault or receives a source-supported pipeline defect
from the verifier for a job, DO NOT edit /home/wsollers/projects/appsec-review or interrupt the
active Dagster dispatch while other jobs can still make progress. Instead, stripe each affected
job onto its own fresh sibling chat named "FIX - <XXXX>" (<XXXX> = short job slug or defect ID,
<=40 chars) and keep monitoring/verifying the active run:
  1. Ask this parent kickoff/coordinator chat to spawn "FIX - <XXXX>" via
     create_session(session_kind="chat", name="FIX - <XXXX>", kickoff={"mode": "autopilot", "prompt": "..."})
     so it sits as a flat sibling alongside Verify and Monitor chats (pass detached=true only when
     no parent coordinator chat exists). Raise unresolved scope/expected-gap/policy decisions to
     the user rather than silently accepting bad output; no unrelated tests, broad redesigns, or
     new budget/bypass decisions.
  2. Spawn each Linux FIX worktree independently off main in WSL (seq = 01, 02, ...):
     - Every issue creates /home/wsollers/projects/appsec-review-fix-<run-id>-<seq>-<slug> on
       branch fix/<run-id>-<seq>-<slug> directly off /home/wsollers/projects/appsec-review's
       frozen main HEAD (BASE_SHA). Never chain FIX-02 onto an unmerged FIX-01 branch.
  3. Inside its worktree, each FIX - <XXXX> chat runs focused unit tests with
     PYTHONPATH="$PWD/src" /home/wsollers/projects/appsec-review/.venv/bin/pytest
     --basetemp=test/tmp/<slug> (verifying appsec_review.__file__ resolves inside that worktree;
     never reinstall into the shared .venv or modify /home/wsollers/projects/appsec-review), adds
     focused unit regressions (<10s each, shuffled/parallel), checks git diff --check, commits on
     fix/<run-id>-<seq>-<slug>, reports the exact commit SHA, touched files, whole-job restart
     boundary and unit results to the coordinator and monitor, and finishes without a schedule.
  4. When the active Dagster run is OVER (confirmed terminal, verify-repair-stop passed, and the
     verifier's completion backlog for that dispatch is drained) AND all FIX - <XXXX> chats for the
     epoch have committed, merge the ready fix/<run-id>-<seq>-<slug> branches into
     /home/wsollers/projects/appsec-review (main) one at a time (fix-01 .. fix-NN), run combined
     affected focused <10s unit tests and git diff --check on main, remove the merged temporary
     worktrees (git worktree remove ...) and fix/<run-id>-* branches, reload through supported
     signed-source deployment (lifecycle.py reload / stack-restart.sh --code-location-only ... --no-probe),
     and restart only the affected whole-job boundaries with mandatory --parent-run-id <DAGSTER_UUID>
     (scripts/review-start.sh --run-id <APP_ID> --parent-run-id <DAGSTER_UUID> --restart-from-job <JOB_ID>,
     repeating --restart-from-job <JOB_ID> for independent failed jobs; preserve successful upstream
     jobs; no cell/pool salvage, fake pointers or whole-graph fallback).

Once the corrected job has genuinely restarted, rotate to a NEW sibling monitoring chat with the
exact successor identity, repair and timing evidence - never nested under the retiring monitor.
Because create_session nests non-detached children under its caller, a child monitor must NOT call
create_session with default nesting: instead, send the complete successor kickoff and recovery
evidence to the parent kickoff/coordinator chat so the parent calls create_session(session_kind="chat", ...)
to spawn Monitor <run-id> (epoch N) as a flat sibling alongside Monitor <run-id> (epoch 1) and the
verifier (or pass detached=true only when no parent coordinator chat exists). Reuse/retarget the
existing verification chat. Confirm the new monitor and its five-minute schedule are active before
clearing the old monitor's schedule and ending that old conversation's work. Retain all
handoff/report history. Never let two monitors write the same checkpoint at once or end before
the successor accepts responsibility.

At completion (once the run is terminal; never read answer keys during the run), run
`.venv/bin/python -m appsec_review.reporting efficacy --run EXACT_APP_ID --config appsec-review.toml`
on the WSL host to refresh keyed smoke effectiveness and target-grouped Run-over-Run reports, and
give native execution status AND the verifier's output-quality status, unresolved
gaps, meaningful findings and actual report/Candidate A-B-C/detailed-finding-report/PDF/OpenVEX/efficacy dispositions/counts/references. A successful
step is not proof a file was produced; zero findings with unexplained gaps is not a clean result.
Retain command-to-start, claim-to-first-handler, application-terminal and native-finalization
timings separately. Finish the verifier's completion backlog and clear the corresponding
schedules when done; preserve all original and restarted attempt evidence.
```
