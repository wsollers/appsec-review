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
| [2026-10-01-live-run-debugging.md](2026-10-01-live-run-debugging.md) | **Start here.** Live `full_review` debugging loop: run on zarathustra/hal5000, paste output, fix, push to `main`, re-launch; four targets through to a report, currently `appsec-multi-vuln`. |
| [2026-10-01-blint-cve-bin-tool-host-qualification.md](2026-10-01-blint-cve-bin-tool-host-qualification.md) | Build `tool-blint`/`tool-cve-bin-tool`, publish the NVD-derived cve-bin-tool database, and qualify `02-binary-hardening` 1.1 and `02-binary-component-cve-match` inside B13 on a host. |
