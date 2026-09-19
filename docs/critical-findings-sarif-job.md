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
    status.json
    outputs/critical-findings.sarif
    logs/stdout.log
    logs/stderr.log
    logs/events.jsonl
```

The input record captures the source hash, finding count, registry composition, timeout, worker
hash, Python/PyYAML versions, executable and runtime image label. The bounded worker is launched as
an argument array with a restricted environment. Post-validation checks input freshness, worker
freshness, the SARIF envelope and result count, then records source/output hashes before publishing
`accepted.json`. A failed newer attempt blocks an older success.

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

Focused tests cover strict parsing, semantic compatibility with the deleted legacy converter,
registry composition, immutable reuse, force, tamper rejection, newer-attempt failure, and source
races. A live qualification stages the same fixture into a Linux-owned run, submits the registered
Dagster job, validates accepted output and immutable reuse, and records service output under the
qualification run.

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
