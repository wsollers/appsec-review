# ADR-0036: State comes from enums; prose is commentary

Status: **Accepted** (2026-10-06, William: "check anywhere we were matching with a regex whether it was
actually trying to query a status from a fixed finite universe, and if so consider it for enum redesign").
Extends [ADR-0013](ADR-0013-run-to-report-first.md) item 7 and
[ADR-0034](ADR-0034-inference-classifies-python-routes.md).

## Context

Run `20261006T150309Z-fdd8d6` blocked at `claim-ledger-final`: `claim_ledger._reject_promotions` scanned
an 08 `refutation_rationale` with `PROHIBITED_TEXT` and read "whether the buffer is fixed-size" as an
"is fixed" promotion. PR #75 added `(?!-)` to two of the six copies of that guard. The guard protected
nothing: a claim's state changes only through closed enum fields (stage dispositions, obligation
status, ledger status and `TRANSITIONS`) and closed schemas whose limits are consts
(`finding_created: false`, `compliance_claimed: false`, `final: false`, ...). Scanning prose only
added failures that depend on how a model phrased a sentence, which is not repeatable.

## Decision

1. **Python determines state; models classify; model text is data, never authority.** Every status,
   verdict, disposition, severity, applicability, compliance, remediation, runtime or verification
   value is an explicit field from a finite universe: a JSON Schema `enum`/`const` or a Python
   constant set, emitted by the model or tool and validated by Python.
2. **Prose is commentary.** Hypotheses, rationales, summaries, notes, limitations, gap statements and
   dissent are stored and rendered as labelled text. No job parses them for meaning, and no wording
   can fail, block, drop or withhold a record.
3. **Structured promotions still fail.** `PROHIBITED_KEYS` key checks (`claim_ledger`,
   `threat_model_core`, `component_characterization`, `owasp_join_report`, `report_input_assembly`,
   `validate_job_output.PROMOTION_FIELDS`), closed schemas, claim-class allow-lists and status
   transitions are the guarantee. A guard that cannot be expressed structurally becomes a
   non-blocking limitation, never a text scan.
4. **Syntax parsing stays.** Regexes that parse identifiers, paths, line ranges, versions, hashes, tool
   formats, or redact secrets are not status inference and are unchanged.
5. A new status-like value gets an enum field in the schema, the contract, the prompt fragment and
   the Python validator together.

## Changes (2026-10-06)

Removed the prose guards: `claim_ledger.PROHIBITED_TEXT` (and the hunter-text stripping it forced),
`synthesis_report.PROHIBITED_TEXT`, `threat_model_core.PROHIBITED_TEXT`, `threat_workbench`
`prohibited_text`/`clean`/`keep` (records were dropped or withheld for their words),
`owasp_join_report.PROHIBITED_TEXT`, the `owasp_validator_result` summary and assertion scans,
`component_characterization._promotes_prohibited_conclusion`, `owasp_intercom.PROHIBITED`,
`owasp_dynamic_requests.PROMOTION`, and the dead diagnostic rules
`persona_invocation.CLAIM_TEXT_RULES`/`_asserts_prohibited` and
`validate_job_output.PROMOTION_TEXT`/`_asserted`. Each has a test that the old false positive passes
and that the structured promotion is still rejected.

Left as they are, with the reason:

- `owasp_validator_result` `deployed_terms` reads the obligation text and the citation's
  `covered_scope` to decide whether non-equivalent test evidence covers a deployed scope. It only
  ever disqualifies evidence (`cannot_verify`), never fails a cell. The enum redesign (a scope kind on
  the reduced validator citation) is open in `TODO.md`.
- `owasp_join_report` bare-checklist-status check: a route whose hypothesis only restates "control
  failed" becomes a gap instead of a route. Non-blocking quality check.
- `owasp_dynamic_requests.INJECTION` and `threat_workbench_intercom` injection patterns: scope and
  instruction hygiene, not status inference; the intercom one only flags.
- `pipeline/summarize_evidence.parse_hadolint` counts levels from hadolint text output and
  `orchestrator/retrieval-report.py` classifies LSP failure reasons and feedback wording: diagnostics
  only. Switching hadolint to `-f json` needs an image script change.

## Consequences

- Code fingerprints change for L01, `claim-ledger-final`, 01 (`component_characterization.py`), 03
  core and workbench, 04 join, and 10; those jobs re-run. `persona_invocation.py` and
  `validate_job_output.py` are shared runtime and do not re-run anything.
- A model can now write "severity: high" in a rationale and it is published as that model's words.
  The report labels unverified text as such; the severity in the report comes only from 12's enum.
