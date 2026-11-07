# TASK - STANDARDIZE, VALIDATE AND RECORD THE JOB CONTROL LAYER

User direction, quoted: "input and output layers should be standard json schemas and validated.
The files they reference can have different formats but the job control language must be
standardized tracked verified and recorded." Resolve before the next live test cycle.

Source of the findings: `docs/plans/job-catalog-and-interchange-audit-2026-11-07.md` section 3
(interchange JSON), items 1, 3, 4, 7, 8, 9, 11, 12 and migration steps 1-5.

## Decision

Three layers, each with its own rule:

1. **Envelope** (`claim`, `status`, `outcomes`, `handoff`, `latest`, dataset contract): already
   one shape and byte-verified. Unchanged.
2. **Job control layer** (task receipts, attempt status, unit outputs, `terminal_status`,
   dispositions, gaps, the accepted-handoff read path): standardized, closed, JSON-Schema
   described, validated at publication, recorded in the claim. This task.
3. **Payload artifacts** (SARIF, LLVM IR, SQLite shards, corpora, per-job summaries): format-native.
   Only their references are standardized (`{path, sha256, size_bytes}` plus the dataset
   declaration's schema and bounds). Not changed here; the audit's section 4 recommendation (keep
   SQLite shards as the neutral form, one typed JSON Lines contract for the three bulk-row handoffs,
   no CSV) stands as follow-up.

## Implemented (worktree `feature/tooling-only-image`, on top of the mount change)

### Accepted-upstream reader (audit item 8)

- `src/appsec_review/runtime/consume.py`: `upstream_scope`, `accepted_upstream`,
  `has_accepted_upstream`, `accepted_latest`, `consumable_handoffs`, `current_pins`.
- The runner opens an `upstream_scope` around claim-time input identity, attempt input preparation
  and every unit execution. Inside it a producer resolves by the digest the claim pinned and a
  producer the claim did not pin is refused (`UpstreamNotPinnedError`) even when `latest.json`
  exists; a producer with no accepted handoff at all is "required/absent". Outside a scope the
  hash-verified pointer is used and the result says `pinned=False`.
- `claim.consumable_handoffs` is new: the projected `upstream_handoffs` (unchanged, still what the
  handoff records and resume compares) plus the accepted handoffs of the job's `CONSUMES` and its
  full-topology ancestors as they stood at claim time. The claim therefore records exactly what the
  attempt may read, and a producer accepted later in the run can never leak in.
- All 23 job modules that read `latest.json` now go through `accepted_upstream` (or
  `accepted_latest` for a job's own prior attempt); `indexing/store.accepted_handoff` and the
  OpenVEX bounded reader honour the pins. `job_build_environment_analysis` keeps its contract-bound
  reference check (it already compares an explicit digest) and `job_openvex_export/reporting.py`
  keeps its pointer reads (post-review staleness reporting, by design).

### Closed terminal-status vocabulary (audit item 3)

- `interchange.ProducerStatus` (19 values) is the single vocabulary; `runtime/handoff.py` derives
  `_KNOWN_STATUSES` from it.
- `interchange.validate_unit_output` runs in `build_outcomes` for every succeeded unit at
  publication. An unknown `terminal_status`, an unknown disposition status, a malformed
  `dispositions`/`gaps` array or an invalid `coverage_disposition` **rejects the attempt**
  (`rejected-handoff.json`) instead of publishing with an `unknown_producer_status` gap.
  Diagnostic reconstruction of older attempts keeps the previous mapping.

### Control-record schemas (audit items 1, 2, 9, 11, 12)

- `docs/schemas/job-control.schema.json`: `task-receipt/1` (closed), `attempt-status/1`,
  `unit-output/1` (the `UNIT_OUTPUT_KEYS` projection), `producerStatus`, `producerGap`,
  `disposition`. `tests/test_job_control_schema.py` validates runner-written receipts and results
  against it and pins the enums to the code.
- Task and attempt `status.json` now carry `schema`. `result.json` is written as
  `unit-execution/2` only (`UnitExecutor.execute` no longer writes `/1`; readers still accept it).
- `interchange.UNIT_OUTPUT_KEYS` replaces the inline projection list in `runner.py`.

### Gap records (audit item 4)

- `interchange.producer_gap(...)` builds a `producer-gap/1` record with the same identity the
  runtime derives for free text, so migrating a job keeps stable gap ids.
- `Job.strict_gaps`: when set, a free-text or ad-hoc gap rejects publication. Converted now (no gap
  sites): `job_image_pin_verification`, `job_model_connectivity`, `job_build_iteration`,
  `job_third_party_data_sync`. `tests/test_gap_contract.py` holds the explicit legacy list (42
  jobs); it may only shrink, and a new job must be strict.

### CONSUMES parity (audit item 5)

- `job_security_tagging` declares the manifest publishers it follows; the OWASP upstream
  allowlist no longer names the unregistered `job_target_documents`.
- `tests/test_consumes_parity.py`: every `CONSUMES` entry is a registered job scheduled before the
  consumer. (A topology edge is not required to be a `CONSUMES` entry: many edges are ordering
  only.)

### Docs

- `docs/architecture/job-interchange.md`: "The control layer beneath the envelope".
- `AGENTS.md`: control-layer rules.

## Verification

- Focused: `tests/test_upstream_consumption.py` (7), `tests/test_job_control_schema.py` (14),
  `tests/test_gap_contract.py` (5), `tests/test_consumes_parity.py` (97), plus
  `tests/test_handoff_interchange.py`, `tests/test_interchange_schema.py`, `tests/test_job_runtime.py`,
  `tests/test_repair_admission.py`, `tests/test_wave1_resume.py`: all green except the known
  environment-specific `test_catalog_path_index_accepts_structured_inventory_gaps`.
- Differential: the full unit suite (`tests/`, excluding integration/acceptance/live) run on
  unmodified `main` and on this branch in the same Python 3.13 environment; the failure sets are
  compared below. Environment-specific baseline failures (missing host tools, Python 3.13) are not
  attributed to this change.

## Not done here (follow-up, in priority order)

1. Convert the 42 legacy jobs' gap sites to `producer_gap` and flip `strict_gaps`; the audit
   found 24 dict-literal sites and many string sites. Do it per job, bumping `schema_identity`.
2. Wire the 67 unused `docs/schemas/*.schema.json` files into their jobs' `output_validators`
   (audit item 11); confirm each still matches its writer first.
3. Retire duplicate schema versions one reader at a time (`review-package/3` vs `/6`,
   `final-publication-gate/1` vs `/2`, `guidance-bundle/1..4`).
4. Typed JSON Lines contract for the three bulk-row handoffs; move Grype and post-build onto typed
   inputs (audit section 4).
5. Record the control-record schema ids and hashes in the claim's dataset contract so each run is
   self-describing about the control language it ran under.
