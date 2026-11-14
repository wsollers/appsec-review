---
title: "Lead severity triage"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Lead severity triage

`job_inference_security_review` runs `triage.lead_severity` after accepting the review scope and
before assembling lead packages. It handles only leads whose scanner-reported severity is
`unknown`; a scanner rating that exists is never rewritten.

The stage chooses an assessed priority in this order:

1. `lead-severity-rules/1`, the typed rules in
   `jobs.job_inference_security_review.settings.triage.rules`;
2. `cwe-impact-derivation/1` over the run-pinned MITRE CWE catalog;
3. one bounded `lead_triager` model turn per batch, using the configured `triage` model profile.

The checked-in development configuration keeps that profile on Haiku. The model has no tools and
receives only the scanner rule, bounded message and path, pinned reference context, a bounded
source excerpt, and the finding's bounded `tool_facts`. Secret-family excerpts pass through
`secret-redaction/1` first. Invalid output may get one repair turn when retry policy and execution
admission permit it; active first-error mode does not promise a retry. Provider failure, timeout, an
oversized request, insufficient context, or uncited numeric reasoning leaves the lead `unknown`
with a named `triage_failed:*`, `triage_skipped:*`, or `triage_unresolved:*` gap; it never becomes
`low` by default.

## Numeric reasoning must cite a tool fact

The model step applies `numeric-reasoning-guardrail/1` (`review.numeric_reasoning`). Models often
reach a right answer through unsound reasoning about value ranges, bounds, integer overflow or
wrap, and loop trip counts or termination, so such facts must come from a deterministic tool.

- Each finding of the request carries `tool_facts`. A fact id is a kind letter plus a 1-based
  ordinal, unique within the finding. Today the only fact is `O1`, the scanner observation itself:
  scanner, rule id, bounded message, path and line. The facts are part of the finding input, so
  they feed the cache fingerprint.
- A result item may set `tool_fact` to one supplied fact id. An id the finding did not supply is a
  validation error that goes to the repair turn, like an unknown lead id.
- When the reason uses numeric reasoning (`range_bound`, `arithmetic_wrap` or `loop_iteration`)
  and cites no supplied fact, the lead stays `unknown` with
  `triage_unresolved:uncited_numeric_reasoning`. Fresh and cached items pass the same check.
- An accepted numeric assessment records the cited fact in `assessed.tool_fact`. Every lead row
  whose reason used numeric reasoning carries a `numeric_reasoning` block with the rule, the
  detected categories and the cited fact; an unresolved row also keeps the model's severity and
  reason for audit. The document-level `numeric_reasoning` block records the rule id, the gap code
  and the cited and uncited counts.

The deterministic steps (`lead-severity-rules/1` and the CWE-catalog derivation) are not subject to
this check.

## What the result changes

The assessed value controls lead ordering and admission only. It does not feed scoring, claim state,
or ship-block policy. Each lead-menu record keeps both sides:

- `original`: the scanner's native and normalized values;
- `assessed`: value, source, basis, reason, version, and triage identity, or `null`;
- `effective`: the reported value when known, otherwise the assessment, otherwise `unknown`;
- `gap`: why an unknown lead remained unresolved.

The run-owned `lead-triage.json` artifact records every deterministic decision, bounded model batch,
request hash, attempt, result, unresolved gap, pinned guidance identity, model profile, and catalog
identity. Each final finding carries the severity records of the finding-lead packages that proposed
its claim, and the inference-review handoff carries the triage artifact hash and summary counts.

## Configuration and recovery

The `[jobs.job_inference_security_review.settings.triage]` table in `appsec-review.toml` controls the
switch, batch size, model profile, lead cap, excerpt and reason bounds, and deterministic rules.
Changing any semantic setting invalidates the affected triage fingerprints. Set `enabled = false`
to restore unassessed `unknown` ordering while retaining an explicit disabled artifact.

When `unresolved` is nonzero, inspect the lead rows and batch gaps in `lead-triage.json`:

- `triage_unresolved:insufficient_context`: improve accepted source mapping or leave the uncertainty;
- `triage_unresolved:uncited_numeric_reasoning`: the model reasoned about ranges, bounds, wrap or
  loops without citing a supplied tool fact; read the row's `numeric_reasoning` block, and leave the
  lead unknown until a tool supplies the fact;
- `triage_failed:timeout` or `triage_failed:provider_error`: restore the configured Haiku provider and rerun;
- `triage_failed:invalid_output`: inspect the two bounded attempts and the recorded validation errors;
- `triage_failed:request_too_large`: reduce excerpt or batch bounds;
- `triage_skipped:max_leads`: raise the cap deliberately or accept the named coverage gap.

Cache entries are content-addressed by the lead input, rule table, model binding, prompt, and pinned
reference context. A changed input is never silently reused.
