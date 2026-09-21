# Critical Findings SARIF Job

## Current scope

`critical_findings_sarif` is an implemented Dagster format-transform job. It validates a staged,
structured finding document and publishes SARIF 2.1.0 as a run-owned immutable attempt. It does
not aggregate lane outputs, create findings, upgrade severity, or perform independent
verification. The synthesis/verification process must prepare the input first.

The job uses the registered `10-critical-findings-sarif` composition:

- persona: `report-artifact-publisher`
- role: `sarif-exporter`
- domain: `verified-findings`
- tooling profile: `local-sarif-transform`
- output contract: `critical-findings-sarif`

It is a standalone registered job rather than a completed `full_review` lifecycle node. The
upstream `09-independent-verification` and aggregate `10-synthesis-report` workers remain planned.
Conversion success is never proof that a finding was verified.

## Input and launch

Stage one bounded UTF-8 file at:

```text
appsec-review-process/runs/<run_id>/inputs/critical-findings.md
```

Only stage findings that are independently verified or explicitly retained as unresolved by the
synthesis decision. Then submit from the host:

```powershell
python -B appsec-review-process/launch_job.py `
  --run-id <linux_run_id> `
  --job critical_findings_sarif `
  --wait
```

The input is limited to 4 MiB. It must contain at least one finding, unique IDs, supported
severity, and a `path:line` or `path:start-end` location. Malformed blocks fail the entire attempt;
they are never silently skipped.

## Run-owned output

```text
runs/<run_id>/data/jobs/10-critical-findings-sarif/whole/
  accepted.json
  latest.json
  attempts/<attempt_id>/
    inputs.json
    pre.json
    command.json
    manifest.json
    post.json
    result.json
    status.json
    outputs/critical-findings.sarif
    logs/stdout.log
    logs/stderr.log
    logs/events.jsonl
```

The input record captures the source hash, finding count, registry composition, timeout, output
contract, worker kind, the hashes of the worker and of every shared runtime module it depends on,
Python/PyYAML versions, executable, runtime image label and the pinned child-execution contract.
Post-validation checks input freshness, worker freshness, the SARIF envelope and result count, then
records source/output hashes before publishing `accepted.json`. A failed newer attempt blocks an
older success.

## Common runtime adoption

Since Workstream B Batch 9 this worker no longer owns its own lifecycle. It uses the same boundary
as `02-ossf-scorecard`:

- `publish_job_output.py` owns the per-job lock, reusable admission, interrupted-attempt recovery,
  collision-safe attempt allocation and terminal exception routing. Preflight blockers become
  `BLOCKED`, post-allocation failures `FAILED`, and `KeyboardInterrupt` `CANCELED`, with the
  original exception re-raised so Dagster behavior is unchanged.
- `result.json` is the immutable v1.0 worker-result envelope (`worker_result.py`). `accepted.json`
  is the common accepted pointer; pre-migration pointers stay integrity-readable but are never
  reused as current.
- `validate_job_output.py` is read-only. The `critical-findings-sarif` contract now declares
  `outputs/critical-findings.sarif` as its single result artifact, validated against
  `schemas/critical-findings-sarif.schema.json`. Finding-count agreement with the immutable
  validated input and the manifest hash checks remain local to the worker.
- The contract deliberately declares no `claim_class`. The three trusted claim-class policies limit
  their outputs to evidence and reject finding/severity promotion; this contract republishes an
  upstream verification decision as SARIF, so that policy does not apply to it. It still cannot
  verify, create or upgrade a finding — the strict fixed-input boundary is what prevents that.
- The bounded conversion child runs under `appsec-review/deterministic-child/1.0`: one absolute
  executable with a fixed argv prefix, no shell, an explicit environment, an in-attempt log root, a
  timeout and one-MiB retained limits per diagnostic stream, with complete child-tree cleanup on
  every exit path. Timeout, child loss and log-write failure all fail closed; retained-log
  truncation alone is bounded diagnostics and does not invalidate a successful conversion.

The conversion itself is unchanged. The Markdown format, strict validation, SARIF mapping and the
standalone `critical_findings_sarif` Dagster job are identical; the job is still not bound to
synthesis.

## Markdown finding format

Each finding is a YAML-frontmatter block followed by Markdown sections:

```markdown
---
id: CRIT-EXAMPLE-001
title: Example critical finding title
severity: Critical
status: Open
component: example-component
location: path/to/file.ext:123
category: appsec-review
cwe: CWE-000
asvs: null
data_classes: []
regulatory: []
cve: []
confidence: Confirmed
discovered_by: independent-verification
---
### Description
Short finding description.

### Evidence
- Origin lane: `09-independent-verification`
- Evidence: a run-owned accepted attempt and cited source location

### Impact
Impact of the verified issue.

### Remediation
Pointer to remediation output or required follow-up.
```

Required fields are `id`, `title`, `severity`, `status`, `location`, and `confidence`. Supported
severity values are `Critical`, `High`, `Medium`, `Low`, and `Info`. Use `null` or an empty list for
unknown optional mappings instead of inventing them.

## Inclusion rules for the producer

The upstream synthesis/verification producer should include a finding only when:

- severity and disposition are explicit;
- independent verification supports the claim, or synthesis explicitly preserves it as unresolved;
- at least one source location is available;
- it is not refuted, false-positive, skipped, not applicable, or merely a checklist gap; and
- duplicates have been resolved using stable finding identity and root cause.

Scanner-only observations and discovery candidates do not become final findings merely by being
formatted as Markdown.

## Failure and applicability

The job fails closed for missing input, invalid UTF-8/YAML, missing required fields, duplicate IDs,
invalid locations, unsupported severity, timeout, nonzero worker exit, source races, implementation
changes, invalid SARIF, or hash mismatch. It does not fall back to an earlier accepted attempt.

When no findings qualify, do not fabricate a successful empty input. Record an explicit
not-applicable/no-qualifying-findings decision in the future synthesis job. Empty-SARIF publication
will be added only with that upstream skip contract.

## Qualification

Focused tests cover strict parsing, a golden conversion document, registry composition, the
common-envelope success/reuse/force/tamper path, contract-declared result validation, preflight
`BLOCKED`, work `FAILED`, cancellation `CANCELED`, deterministic-child fault mapping, retained-log
truncation, pending-publication recovery, interrupted-attempt recovery, no fallback after a newer
failure, and the Windows/Linux line-ending and child-environment paths. Generic allocation,
publication and child-runner behavior is qualified once in `tests/test_worker_adoption.py` and
`tests/test_deterministic_child.py`.

`appsec-review-process/qualify_sarif_adoption.py` is the bounded live sequence for this worker:
success, immutable reuse, pending-publication recovery, interrupted-attempt recovery, a newer
failure that blocks the older success, and a fresh recovery attempt. It must be run because the
migration changes this worker's executable identity, and its report belongs under the owning
ignored qualification run.

The 2026-09-19 qualification below predates the common-runtime adoption and certifies only the
pre-migration implementation.

The 2026-09-19 qualification passed in run `20260919T170944Z-6cf0e5` using service image
`sha256:4e6f79b3ef9df020ceaa1a86a2d1d469fb6c2224f38f4e0fdcec6cd80dd15513`. Dagster run
`bc4ce182-9d3f-462a-a807-d0bced86ff44` published accepted attempt
`1807a9c72e764a53bb16c80f0636546f`; run
`e1629e82-add3-4f74-9d57-5a82f6a86a08` reused that attempt. The accepted manifest records one
synthetic result, source SHA-256
`a095a99c11f02257a09ae4e423eadd2060b7f2d49d14f231cff5089438a3cb8f`, and SARIF SHA-256
`e465971345ef63945346799c399bc42992f23c0170edbb6e3ef15ca6d6679dde`. Four focused tests passed
on Windows and four in the Linux code-server; the seven Dagster transition tests also passed after
updating their stale unavailable-worker fixture. Run evidence is ignored local data.
