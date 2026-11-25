---
title: "Review monitoring and job-output reports"
kind: "operations"
subsystem: "reporting and metrics"
status: "current"
jobs: []
---
# Review monitoring and job-output reports

Use this Markdown format for a five-minute monitoring chat and its separate job-output
verification chat. This document defines reporting and a reusable kickoff prompt, not a new
runtime protocol or standing permission to launch, repair, or bypass checks. Root
[`AGENTS.md`](../AGENTS.md) governs. The kickoff's user authorization, not telemetry or a model's
output, commissions operations.

## Evidence and scope

Read the [monitor procedure](operations/run-monitor.md), [metrics reference](operations/metrics.md),
and [recovery runbook](operations/recovery-repair.md). Use current job contracts and the deployed,
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
Monitor `<chat ID>`; output verifier `<chat ID>`; identity record `<reference>`.

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
3. **Meaning:** compare outputs with evidence independent of the producer (target source, raw
   tool results, or independent counts). Trace joins, locations, relationships, and claimed
   coverage. Existence, nonzero counts, and schema validity alone do not establish usefulness.
   Record whether the check was exhaustive or sampled and what was not examined.
4. **Gaps and findings:** group canonical outcome gaps by cause, not repeated log strings.
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
It sends new causal defects to the monitor immediately. The monitor diagnoses/repairs observed
pipeline defects within its user-authorized scope; unresolved expected-gap, target-scope, or
policy choices go to the user. It must not quietly mark an unexpected gap as expected.

The background verifier does not gate Dagster scheduling. If the user instead wants no downstream
job to run before independent acceptance, use the existing job-by-job walk, not this full-run
monitoring prompt. This distinction must be stated at launch.

## Fault, handoff, and final report

Append the following to a fault/recovery report:

```markdown
#### Recovery
Fault <app/dispatch/job/attempt/step>; failure time <UTC>; detected <UTC>.
Cause <source/artifact-supported diagnosis>; evidence <references>; uncertainty <named gaps>.
Fix <revision/files>; validation <actually performed, or not run>.
Boundary <whole failed job(s) and genuinely affected descendants>;
retained successful jobs <N and evidence>; no cell/pool salvage.
Admission <plan/config/source refs>; native parent <UUID>; selected steps <N/list ref>.
Timing: detection -> fix ready <duration>; restart command -> native STARTED <duration>;
command -> claim <duration>; claim -> first handler <duration>;
claim -> application terminal <duration>; claim -> native finalization <duration>.
Output <accepted disposition/counts/artifact refs, or not yet published>.
Successor monitor <chat ID>; verifier <chat ID>; prior monitor schedule <cleared/not cleared>.
```

The monitor's extra repair authority comes from the executed kickoff below; the read-only
monitor skill alone does not grant it. Preserve actual admission/signing checks and original
evidence. Follow current `AGENTS.md`: do not invent source locks or run automatic regression
suites. Reproduce/analyze the observed fault, fix the cause and necessary immediate blockers,
and use supported signed-source reload. Do not broaden this into audit-wide cleanup or a new
recovery framework. Changes to budgets, bypasses, scope, or costly extra runs need user direction.

Restart the entire failed job, retaining compatible successful jobs and invalidating affected
downstream outputs. Inspect the actual parent-linked selection; an application `--run-id` alone
is not a targeted restart. If admission cannot provide that boundary, report the blocker instead
of silently launching a fresh full graph. For several independent failed jobs, use repeated
`--restart-from-job` selections, not their successful common ancestor.

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
monitoring chats described in docs/monitoring_report.md. This authorizes this initial fresh run
and focused fault-diagnosis/repair/whole-job-restart cycles within it, not additional fresh
whole-graph reruns. Do not reuse a historical run ID.

Read current AGENTS.md, docs/monitoring_report.md, docs/operations/run-monitor.md,
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
session ID, this full assignment, the exact run identity, and docs/monitoring_report.md.
Use create_session with session_kind="chat" and a complete kickoff (mode="autopilot") for each
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
format in docs/monitoring_report.md. Preserve unknowns, lower bounds, graph/epoch scope,
retained-versus-recomputed work, telemetry lag, receipt limitations and observed timestamps.

The verifier follows every completed job, checking actual admitted inputs, published files,
hashes/schemas/counts, semantic correctness and downstream usefulness against independent
evidence and the applicable prior audit. Report whether outputs are CORRECT AND MEANINGFUL,
not merely nonempty. Explain legitimate empty outputs; diagnose unexplained zeros and gaps.
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

On a confirmed runtime fault, the monitor identifies the actual root cause from bounded evidence,
fixes it and immediate prerequisites, reloads through supported signed-source deployment, and
restarts the whole failed job through inspected parent-linked recovery. Preserve successful
upstream jobs; no cell/pool salvage, fake pointers or whole-graph fallback.
Also act on source-supported pipeline defects from the verifier within that same scope; raise
unresolved scope/expected-gap/policy decisions rather than silently accepting bad output.
Keep technical worker-stop, signing and admission requirements intact without inventing extra
workflow freezes. No unrelated tests, broad redesigns or new budget/bypass decisions.

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

At completion, give native execution status AND the verifier's output-quality status, unresolved
gaps, meaningful findings and actual report/PDF/OpenVEX dispositions/counts/references. A successful
step is not proof a file was produced; zero findings with unexplained gaps is not a clean result.
Retain command-to-start, claim-to-first-handler, application-terminal and native-finalization
timings separately. Finish the verifier's completion backlog and clear the corresponding
schedules when done; preserve all original and restarted attempt evidence.
```
