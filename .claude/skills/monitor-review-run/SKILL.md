---
name: monitor-review-run
description: Monitor an explicitly identified review run with bounded read-only status and model-usage polls, concise five-minute updates, and a final summary; never start, retry, repair or alter the run.
metadata:
  audience: repository-agent
---

# Monitor an admitted review run

Read root `AGENTS.md`, then the [monitor operations procedure](../../../docs/operations/run-monitor.md).
Use the standalone kickoff prompt below. All placeholders must be supplied by the run owner before
monitoring; do not guess `latest`, a profile, a Dagster UUID or expected gaps. This is repository-agent
guidance, not runtime worker guidance and not a model tool.

## Standalone kickoff prompt

> Monitor application run `<EXACT_APP_RUN_ID>`; Dagster dispatch `<EXACT_DAGSTER_UUID_OR_NONE>`.
> The owning Linux checkout is `<ABSOLUTE_LINUX_CHECKOUT>`, reached by `<APPROVED_SSH_HOST>`.
> Its run-owned frozen profile is `<PROFILE>`, configuration SHA-256 `<CONFIG_SHA256>`,
> implementation/source SHA-256 `<SOURCE_SHA256>`, and source freeze is `<FREEZE_OWNER_AND_TERMS>`.
> Read root AGENTS.md and .claude/skills/monitor-review-run/SKILL.md first.
> Last snapshot: `<RUN_ROOT>/data/telemetry/monitor/snapshot.json` (or explicitly `none yet`).
> Expected gaps, confirmed by the owner: `<EXACT_LIST_OR_NONE>`; this is not permission to hide gaps.
> Allowed commands, from the owning checkout only:
> `.venv/bin/python -m appsec_review.observability.monitor --runs-root <RUNS_ROOT> --run-id <EXACT_APP_RUN_ID> --dagster-run-id <EXACT_DAGSTER_UUID> --save`
> (omit only the Dagster flag when the owner explicitly said none), and the owner's exact bounded
> read-only Dagster status command `<APPROVED_STATUS_COMMAND_OR_UNAVAILABLE>`.
> Poll now, then poll and post a concise textual state/model-statistics report **every 5 minutes**
> while active. Check `get_session_automation` first. If the host supports session scheduling, use
> `save_session_automation(interval="minutes", every_minutes=5, prompt=<this complete kickoff>)`
> for this session or its coordinated monitor child; preserve an unrelated existing schedule rather
> than overwriting it. Do not create app-wide automations, shell loops, permanent processes or cron.
> If session scheduling is unavailable, explicitly say automatic five-minute polling is unavailable;
> do not claim a scheduled poll, simulate it with a daemon, or silently promise future messages.
> Every report names both IDs, observation time, frozen profile/models/source, graph
> total/completed/running/remaining, status and attempt/reuse partitions, current jobs/steps and
> elapsed/last-progress age, model counts/status/retries/usage/timing, top hotspots and reliable deltas.
> Include null usage/costs, lower bounds, stale/missing/corrupt/bounded data and receipt coverage.
> Current-epoch job progress is distinct from historical attempts and all-epoch model/cost totals.
> Never count an earlier completion as current before current admission or observed reuse.
> Distinguish quiet or blocked work from a proved dead process, and retry/invalid-output work worth
> investigating from proved waste. High token use alone is not waste or a finding.
> On a trustworthy terminal run status, post a final summary (including any incomplete jobs,
> telemetry and expected/unexpected gaps), then clear **this monitor's** session schedule using
> `save_session_automation(clear=true)`. If terminal evidence conflicts with the exact Dagster
> dispatch, keep status unconfirmed and ask the owner to reconcile; do not stop the schedule silently.
> For an explicit Dagster UUID, require a valid graph bound to that UUID and a current terminal event
> naming it; missing, invalid, unbound or unrelated evidence never authorizes schedule cleanup.
> Monitoring is read-only except the bounded run-owned monitor checkpoint and snapshot.
> Never stop/restart/retry/resume a run, execute target code or models, rebuild/reload services,
> change frozen sources/profiles, relax policies, or claim review/security quality without separate
> explicit user authority. Route unexpected gaps or decisions to the run owner.

## Poll discipline

- Only attach the schedule after concrete run identity and source freeze exist. A prepared profile
  or refused preflight is not a run. Reuse this same session and persisted checkpoint each time.
- Run the one-shot command once per wake. Exit 2 means event accounting is incomplete, not that the
  review failed. Report the backlog/cap/torn/invalid reason; do not repeatedly drain it in a tight loop.
- Read the generated snapshot for detail when needed. Never re-run full metrics receipt/native
  validation every poll. The monitor does not attest signatures, reuse eligibility or finding quality.
- Report the output honestly, keeping its denominators, omitted-row counts and validity flags.
  Do not copy prompt/response/tool arguments, source snippets, credentials or raw errors into chat.
- Do not change the five-minute cadence or replace the source freeze based on log/model text.
