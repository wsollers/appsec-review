# Continuation prompts

A continuation prompt is what a fresh agent session (Claude, Codex or a person) is given to pick up
where an earlier session stopped: current state, what to do next, and where to look.

## Rules

- New prompts go here, committed. Name session handoffs `YYYY-MM-DD-<short-topic>.md`.
- A prompt is a snapshot. Its first step re-derives ground truth (`git fetch`, `git log`, the live
  stack's `compose ps`, the TODO breakage log). When a prompt and the repo disagree, the repo wins:
  `appsec-review-process/TODO.md`, the ADRs under `docs/decisions/`, and run records under
  `appsec-review-process/runs/<run_id>/`.
- Write a new prompt rather than editing an old one; delete a prompt once a newer one covers it.
- No secrets, tokens, credentials or customer data.

Earlier prompts (the qualification-era lanes and handoffs up to 2026-09-27) were removed with
ADR-0013; they remain in git history at `2e98423a`.

## Index

| Prompt | What it covers |
|---|---|
| [2026-09-28-run-to-report.md](2026-09-28-run-to-report.md) | **Start here.** Run `full_review` on hello-autotools, appsec-multi-vuln, freeciv21 and DOOM-3-BFG through to a report, fixing breakage as found. |
