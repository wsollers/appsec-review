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
receives only the scanner rule, bounded message and path, pinned reference context, and a bounded
source excerpt. Secret-family excerpts pass through `secret-redaction/1` first. Invalid output gets
one repair turn. Provider failure, timeout, an oversized request, or insufficient context leaves the
lead `unknown` with a named `triage_failed:*`, `triage_skipped:*`, or `triage_unresolved:*` gap; it
never becomes `low` by default.

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
- `triage_failed:timeout` or `triage_failed:provider_error`: restore the configured Haiku provider and rerun;
- `triage_failed:invalid_output`: inspect the two bounded attempts and the recorded validation errors;
- `triage_failed:request_too_large`: reduce excerpt or batch bounds;
- `triage_skipped:max_leads`: raise the cap deliberately or accept the named coverage gap.

Cache entries are content-addressed by the lead input, rule table, model binding, prompt, and pinned
reference context. A changed input is never silently reused.

