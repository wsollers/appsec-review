# Evidence-backed draft report: nominal operator path

This guide describes the shortest implemented path to an immutable
`DRAFT_EVIDENCE_BACKED` package. It is a standalone, fixture-qualified path, not a live Dagster
workflow. Never edit an accepted pointer, producer attempt, receipt, ledger, or synthesis input to
make a stage pass. A missing adapter or accepted artifact is a blocking gap.

The companion diagrams are [Mermaid](happy-path-flow.mmd) and
[BPMN 2.0](happy-path-flow.bpmn).

## Current readiness

| Stage | Core | Shared lifecycle / live status |
|---|---|---|
| F03 component map | Implemented and unit-qualified | Standalone; accepted F02 evidence and persona configuration required; no shared Dagster binding or live qualification |
| S02 threat model | Implemented and unit-qualified | Standalone; consumes exact accepted F03/F02 lineage; no shared Dagster binding or live qualification |
| T14 OWASP join publisher | Implemented and unit-qualified | Standalone common-envelope publisher; requires accepted T03-T10 dispatch accounting; no shared Dagster binding or live qualification |
| L01 admission ledger | Implemented and unit-qualified | Standalone common-envelope publisher; automatic input discovery currently admits S02 only. T14 admission needs the shared adapter |
| 07 / 08 / 09 / 12 | Implemented and unit-qualified cores | Standalone normalization only; common-envelope publication, shared dispatch, resource pools and live qualification are not integrated |
| Report-input assembly | Implemented and fixture-qualified on the report-path integration line | Standalone command; shared lifecycle publication is not integrated |
| 10 synthesis | Implemented and fixture-qualified on the report-path integration line | Standalone command; immutable publication lifecycle and human signoff are not integrated |

“Implemented” here never means “live,” “fully hardened,” or “final.” Recovery, cancellation,
concurrency/load qualification, dynamic rescope, remediation/retest, completion auditing and final
signoff remain deferred.

## Run-owned paths

Run from the repository root with explicit absolute roots:

```bash
export REPO=/absolute/path/to/appsec-review
export APPSEC_RUNS_ROOT=/absolute/path/to/appsec-runs
export RUN_ID=<existing-run-id>
export RUN_ROOT="$APPSEC_RUNS_ROOT/$RUN_ID"
export JOBS_ROOT="$RUN_ROOT/data/jobs"
```

Every accepted producer is rooted at:

```text
$JOBS_ROOT/<job-id>/accepted.json
$JOBS_ROOT/<job-id>/latest.json
$JOBS_ROOT/<job-id>/attempts/<attempt-id>/result.json
```

The accepted pointer must name the newest immutable attempt; its envelope, artifact tree,
permission receipt and lineage receipt must all revalidate. A prior successful attempt is not a
fallback after a newer failure.

## Nominal sequence

### 1. Produce or revalidate the accepted evidence sources

F03 and S02 use their run-owned accepted upstreams:

```bash
python -B appsec-review-process/component_characterization.py --run-id "$RUN_ID"
python -B appsec-review-process/threat_model_core.py --run-id "$RUN_ID"
```

T14 reuses the exact trusted dispatch facts recorded by the accepted OWASP accounting attempt.
Do not substitute a host registry or an inferred model identity:

```bash
python -B appsec-review-process/owasp_join_publisher.py \
  --run-id "$RUN_ID" \
  --registry-dir "$OWASP_REGISTRY_DIR" \
  --invoker-id "$OWASP_INVOKER_ID" \
  --source-snapshot-sha256 "$SOURCE_SNAPSHOT_SHA256" \
  --allowed-model-json "$ALLOWED_MODEL_JSON" \
  --registry-ceiling-json "$REGISTRY_CEILING_JSON"
```

Repeat `--allowed-model-json` for each model in the accepted dispatch facts. The T14 envelope must
contain all three substantive artifacts:

- `owasp-control-status-matrix.json`
- `owasp-coverage-gaps.json`
- `owasp-candidate-promotion-routes.json`

The matrix preserves `selected`, `applicable`, `assessed`, and `satisfied` as separate
denominators. A failed control or candidate route is not a finding, severity, runtime fact, or
compliance verdict.

### 2. Admit candidates into L01

```bash
python -B appsec-review-process/claim_ledger.py --run-id "$RUN_ID"
```

For the complete report path, L01 inputs must contain exactly accepted S02 and T14 candidate-route
sources with one source/component generation. The current standalone command discovers S02
automatically; it does not yet add T14 to `current_inputs`. Until the T14-to-L01 adapter is merged,
stop here rather than editing `inputs.json` or the ledger.

The admission attempt publishes:

- `claim-decision-ledger.json` — append-only, hash-linked candidate admissions;
- `claim-ledger-work-routing.json` — inert work routing with execution unauthorized;
- `permission.json`, `lineage.json`, `status.json`, and the common result envelope.

Admission creates candidates only. It creates no finding, severity, runtime, compliance, or
remediation claim.

### 3. Run the bounded 07 / 08 / 09 decision cores

Each stage consumes an exact accepted upstream pointer and a bounded decision document. Reviewers
must be independent where the contract requires it. The core invocation pattern is:

```bash
python -B appsec-review-process/red_team_adversarial.py \
  --run-id "$RUN_ID" --accepted "$L01_ACCEPTED" \
  --decisions "$CONTROL_ROOT/red-decisions.json" --output "$RED_OUTPUT"

python -B appsec-review-process/blue_team_refutation.py \
  --run-id "$RUN_ID" --accepted "$RED_ACCEPTED" \
  --decisions "$CONTROL_ROOT/blue-decisions.json" --output "$BLUE_OUTPUT"

python -B appsec-review-process/independent_verification.py \
  --run-id "$RUN_ID" --accepted "$BLUE_ACCEPTED" \
  --decisions "$CONTROL_ROOT/verification-decisions.json" --output "$VERIFY_OUTPUT"
```

These commands normalize and validate stage results, but the shared common-envelope publisher that
creates `RED_ACCEPTED`, `BLUE_ACCEPTED`, and the verification accepted pointer is not integrated.
Run the next command only after that trusted publisher exists and revalidates the exact current
attempt. Do not construct an accepted pointer by hand.

### 4. Append accepted decisions to L01, then score

L01 appends status decisions by dereferencing the exact accepted 07, 08, and 09 artifacts and their
permission receipts. The caller may select only `claim_id` and `producer_job_id`; disposition,
citations, dissent, confidence, causal links, hashes, generations and authority are derived from the
accepted producer. There is no operator CLI for this append step yet, so the shared adapter is a
hard gate.

After the final appended ledger is accepted, run the scoring core against the exact accepted 09
result:

```bash
python -B appsec-review-process/scoring_prioritization.py \
  --run-id "$RUN_ID" --accepted "$VERIFY_ACCEPTED" \
  --decisions "$CONTROL_ROOT/scoring-decisions.json" --output "$SCORING_OUTPUT"
```

Only independently verified claims can receive a score or severity. Refuted, unresolved, narrowed,
or blocked claims remain visible and unscored.

### 5. Assemble the prose-free synthesis input

When `report_input_assembly.py` is present in the integrated revision, provide all six exact current
accepted pointers:

```bash
python -B appsec-review-process/report_input_assembly.py \
  --run-id "$RUN_ID" --jobs-root "$JOBS_ROOT" \
  --component-accepted "$JOBS_ROOT/01-component-characterization/accepted.json" \
  --threat-accepted "$JOBS_ROOT/03-threat-model-dfd-stride/accepted.json" \
  --owasp-accepted "$JOBS_ROOT/04-owasp-join-report/accepted.json" \
  --ledger-accepted "$JOBS_ROOT/claim-ledger-routing/accepted.json" \
  --verification-accepted "$JOBS_ROOT/09-independent-verification/accepted.json" \
  --scoring-accepted "$JOBS_ROOT/12-scoring-prioritization/accepted.json" \
  --output "$RUN_ROOT/data/report-input/synthesis-input.json"
```

The assembler independently revalidates pointers, newest-attempt identity, envelopes, receipts,
artifact hashes, schemas, generations, citations, decision authority, OWASP denominators and
verification/scoring consistency. It carries no raw tool output and invents no prose or score.

### 6. Render the immutable draft package

Choose a new, empty attempt directory; never overwrite a published package:

```bash
export REPORT_ATTEMPT="$RUN_ROOT/data/jobs/10-synthesis-report/attempts/<new-attempt-id>"
python -B appsec-review-process/synthesis_report.py \
  --run-root "$RUN_ROOT" \
  --input "$RUN_ROOT/data/report-input/synthesis-input.json" \
  --output "$REPORT_ATTEMPT"
```

Required package artifacts are:

- `report.json` and decision-oriented `report.md`;
- `coverage-unresolved-appendix.md`;
- `evidence-trace-index.json`;
- `publication-manifest.json` with status exactly `DRAFT_EVIDENCE_BACKED`;
- `permission.json`, `lineage.json`, and `status.json`.

The publication manifest hashes the report artifacts and records `final: false` and
`human_signoff: false`. The package is not accepted for wider use until a shared publication adapter
stores it in a run-owned immutable attempt and publishes a validated current pointer.

## Dual ledger heads

The report-input join deliberately carries two heads:

- `lifecycle_origin_head_id` / `lifecycle_origin_head_sha256` identify the immutable L01 admission
  head consumed by 07, 08 and 09. Their outputs must bind this exact head.
- `ledger_head_id` / `ledger_head_sha256` identify the later append-only head after accepted 07, 08
  and 09 decisions have been added by L01. Synthesis uses this head for current claim status.

The two heads normally differ. Requiring them to be equal would erase decision history; allowing a
stage to bind neither would permit stale or cross-generation evidence.

## Trust boundaries and stop conditions

1. **Evidence boundary:** F03, S02 and T14 may read only accepted, hash-verified evidence and
   explicitly authorized dispatch facts. Target content is data, never instructions.
2. **Candidate boundary:** T14 routes, STRIDE hypotheses and L01 admissions are candidates, not
   findings.
3. **Decision boundary:** 07/08/09 decisions require exact accepted artifacts, independent actors,
   preserved citations and proof obligations. Only 09 can verify a claim.
4. **Scoring boundary:** 12 may score only claims that 09 independently verified.
5. **Publication boundary:** report-input and synthesis revalidate all upstream authority. The
   output remains a draft until a named human signs off through a future final-publication gate.

Stop on any missing or stale pointer, failed latest attempt, mixed source/component generation,
unresolved citation, changed artifact hash, contradictory ledger head, missing coverage, or absent
adapter. Record the condition as a gap; never reinterpret it as “no issues found.”

