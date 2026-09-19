# Opengrep rules — authored here, not vendored

Decided 2026-09-19: this project stays on Semgrep as the production SAST engine
(`images/audit-static`, unchanged) and authors its own Opengrep rules here, over
time, to reach parity with the 7 Semgrep `p/*` packs `Invoke-VendorAuditPrePass.ps1`'s
`sast-multi-semgrep-*` steps currently use — rather than vendoring
`github.com/semgrep/semgrep-rules` into `images/audit-static-opengrep`, whose content
is under the Semgrep Rules License v1.0, not a standard OSS license (see
`../Dockerfile`'s header for the full reasoning). Writing our own rules sidesteps that
question entirely: nothing here is derived from Semgrep's rule content, so there is
nothing to clear a license for.

## Layout

One directory per target category, matching the 7 existing Semgrep steps' rulesets
(`owasp-top-ten`, `csharp`, `golang`, `python`, `php`, `java`, `security-audit`). Put
`.yml` rule files directly under the matching `rules/<category>/` directory. Opengrep's
own rule YAML format is Semgrep-rule-syntax-compatible (same underlying pattern
language, per Opengrep's own docs) — write against Opengrep directly against real code,
not by trying to reverse-engineer what a specific semgrep-rules file might have looked
like.

## Tracking progress

`parity-status.json` in this directory is the source of truth for "how far along are
we" — update its `status`/`opengrep_rule_files`/`notes` fields whenever rules are added
for a category, rather than letting progress live only in commit history or memory.
`php` and `java` are flagged there as the two categories worth prioritizing first (see
their `notes`) since they're this pipeline's primary/secondary SAST passes for PHP and
carry Spring-specific coverage respectively — not a hard requirement to do them first,
just the most consequential gap to close first.

## Wiring into the real pipeline

Do NOT point any `Invoke-VendorAuditPrePass.ps1`/`.sh` step at
`audit-static-opengrep:local` for a category while it's still `not_started` or
`in_progress` with only a handful of rules — an empty or thin ruleset still exits 0 and
writes a small valid JSON/SARIF file, which is exactly the "looks clean, actually never
scanned anything real" failure shape this project has hit before with Semgrep itself
(a bad `--config` still produces a small valid JSON with an empty `paths.scanned`).
Wire a category in only once its own entry here is marked `parity_reached` and that
judgment has been sanity-checked against a real target, one category at a time — not
as a single all-at-once cutover once every category happens to be done.
