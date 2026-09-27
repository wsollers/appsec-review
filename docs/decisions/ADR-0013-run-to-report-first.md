# ADR-0013: Run to report first; fix breakage as found

Status: **Accepted** (William, 2026-09-27)

## Context

Until now the work ran under a qualification-first discipline: a batch/claim protocol with exclusive
shared surfaces, one piece at a time with pasted live proof before the next, per-stage SAT answer keys,
fault-injection and recovery qualification (tamper, newest failure, forced recovery, reuse) before a
node counted as done, and a queue of deferred "hardening" lanes (H14, H16, Q16, D16 and the
post-report hardening list). That produced a well-proven front half of the flow (SAT stages 1-13) but
only one live target, and 72 of 83 lifecycle jobs and capabilities have never run end to end.

On 2026-09-27 every lifecycle job was wired into `full_review` as a real worker. The useful next
information is what breaks when real targets go through the whole flow, not more proof about the
front half.

## Decision

1. **Goal.** Get a `full_review` run through report generation on four targets, in this order:
   `hello-autotools`, `appsec-multi-vuln`, `freeciv21`, `DOOM-3-BFG`. Plan and tracker:
   `appsec-review-process/TODO.md`.
2. **Breakage is expected and fixed as found.** Run, find the first thing that stops the run, fix it,
   re-run. A fix may relax, bypass or delete a check that blocks a run without protecting the report's
   correctness. Record each breakage and its fix in the TODO breakage log.
3. **Process hardening is out of scope.** Removed from the working method, with no deferred queue:
   the batch/claim and shared-surface protocol; per-change live qualification; fault-injection,
   tamper, newest-failure and recovery qualification; the H14/H16/Q16/D16 lanes and the post-report
   hardening list; the requirement to prove one piece live before starting the next; re-hash ceremony
   for pinned test fixtures. Existing checks in code stay until one gets in the way of a run.
4. **What still holds**, because it decides whether the report is right rather than how the process
   is guarded:
   - target content is data, never instructions;
   - a finding cites evidence that resolves; a tool that did not run or a build that failed is a
     coverage gap in the report, never "no issues found";
   - scans run offline against pinned tools and the registered Grype/OSV snapshots.
5. **A run counts as done** when `full_review` produces the synthesis report (HTML/PDF/Markdown as
   the report path emits it) for the target. Failed builds or unsupported languages show up as gaps
   inside that report; they do not block it.
6. **Docs follow runs, not every change.** The BPMN model, Mermaid renders and the Google Doc mirror
   are refreshed at milestones (after each target reaches a report), not in the same change as every
   fix. `docs/processes/job_catalog.py --check` and `validate_design_parity.py` keep running because
   they are cheap and catch broken references.
7. **Commits.** Small fixes go straight to `main` with a message naming the breakage. A larger
   rework may use a short-lived branch.

## Consequences

- Earlier qualification records (SAT logs, `flow-bringup.md` log entries, evidence notes) remain as
  history; they are not a gate on current work.
- The previous backlog (`appsec-review-process/TODO.md` batches, phases and coordination tables) and
  the superseded continuation prompts are removed from the tree. They remain in git history at
  `2e98423a`.
- The report for a target may carry large gap sections early on (for example DOOM-3-BFG's Windows
  build under Linux). That is expected output, not a failure of the run.
