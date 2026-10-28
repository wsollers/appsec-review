# Dossier publication operations

Status: commissioned design, **not runnable at the inspected contract commit**
`5f5548da3d039f73c7d6858d2b28a4593a264efe` (2026-10-28).
`job_dossier_publication` and its schema ids are reserved in
[`completion_contracts.py`](../../src/appsec_review/jobs/completion_contracts.py); the handler,
typed settings, registered topology and rendering receipts have not shipped at this baseline.
This page records the operational change boundary, not invented commands or defaults.
The [source-verified data inventory](../architecture/dossier-data-inventory.md) lists actual
producer/index/query/provenance surfaces and unavailable capabilities.

## Membership and placement

The [approved completion contract](../architecture/evidence-completion-and-remediation.md#11-parallel-implementation-decisions)
requires one protected developer dossier for **each confirmed finding**, irrespective of whether
its investigation originated in a document or source code, and a separate dossier for **each
accepted PoC candidate outcome**. Failed, declined, unavailable and unsupported PoC outcomes
still need an accounted dossier with their limitations. Supported claims are not promoted to
confirmed findings by PoC generation or dossier rendering.

The intended graph is review (including chain ledger/manifest before sealing), optional compile-only
PoC, optional confirmed-only planning/validation, then dossier publication, **one final gate**,
and the terminal public report. Dossiers never consume the final gate: that would create a cycle.
The gate certifies their manifest, and the report exposes only certified references and statuses.
Current [PoC](poc-generation.md) and [report](final-report.md) instructions describe the older
post-gate PoC behavior until integration replaces it.

## Required retained evidence

| Record | Operational meaning |
| --- | --- |
| Accepted input references | Review/job/ledger/manifest and exact claim/finding package/hash bindings; accepted optional producer handoffs, frozen settings and tool/guidance identities. No later `latest.json` discovery after certification. |
| Dossier JSON | Deterministic bounded developer projection, preserving evidence/adjudication/score/independence/shipment provenance, applicable attachments, coverage and unavailable dimensions. |
| LaTeX source | Deterministic escaped rendering input; retain it even when rendering cannot complete. |
| PDF | Publish only real rendered bytes with a hash-bound success receipt. Missing image, timeout, failure or cap is a named render gap, never a placeholder called a PDF. |
| Rendering/cleanup receipt | Accepted input/output/template/image identities, actual outcome and limitations; temporary scratch custody and cleanup, without secrets or raw prompts. Exact fields await implementation. |
| Producer manifest/handoff | Exact accounting of eligible dossiers and every terminal rendering outcome, immutable attempt-owned paths/hashes, and explicit gaps. |

The existing standalone renderer and commissioned `tool-report-latex` image are described in
[report rendering](report-rendering.md). Reuse its hardened no-network/non-root/read-only execution,
template/palette and deterministic date behavior rather than running arbitrary generated TeX or
untrusted model commands on the host. A real seeded PDF sample and render smoke are required
acceptance evidence; this documentation-only phase has produced neither.

## Process telemetry (commissioned)

Use existing correlated `context.events` and
[run metrics](metrics.md#completion-rollout-tracking-pending-integration), not a new backend.
Required observations include stage/candidate progress, eligible/terminal dossier counts,
source-retention and PDF-render outcomes, duration, caps, timeout/render/adapter failures and
coverage/integrity/cleanup gaps. Correlate by run/attempt and safe artifact identity, with
low-cardinality lane/stage/status/error-class rollups; model usage is reported only where emitted.
Exact events and aggregate fields remain pending source reconciliation at this baseline.

Telemetry must distinguish retained JSON/LaTeX from an actually rendered PDF and must not
convert a disabled/missing lane into a measured zero. Emit allowlisted counts, statuses and hashes
only, never raw source, patches, PoC text, prompts or credentials into either attempt or central
logs. Accepted manifests, not process counters, govern dossier membership and gate certification.
See the [completion telemetry contract](../architecture/telemetry.md#evidence-completion-tracking-commissioned).

## Visibility and assurance

Dossier JSON, source excerpts, inert PoC source, LaTeX and PDF are **protected developer material**,
not public report content. Resolve only bounded accepted source/artifacts; preserve file/shard/
manifest hashes and omission counts. Exclude credentials, literal secret matches, raw prompts and
arbitrary model transcripts even from developer dossiers. Existing broad diagnostic report
rendering is not permission to copy its entire interchange into a dossier.

Public JSON/Markdown/HTML/PDF may carry sanitized descriptions, finding identity, status, assurance
and artifact references, not source or payload text. A protected reference does not make its bytes
public. Every format must preserve:

- PoC `compile_verified` means syntax/object/sanitizer-object and symbol checks, **never execution**.
  Test and negative control remain unexecuted.
- Remediation proposals are not applied to the user target; validation operates only within its
  approved scratch/static/build boundary.
- `execution = "not_performed_by_policy"`, `runtime_verified = false`, `result_id = null`.
  `build_checked` / `static_checked` does not mean `fixed`, `resolved` or runtime regression verified.
- Original finding state, score dimensions and shipment decision remain unchanged.

## Recovery and acceptance boundaries

The [rollout decision](../architecture/evidence-completion-and-remediation.md#11-parallel-implementation-decisions)
selects automatic remediation planning and bounded nonexecuting validation for new reviews after
implementation acceptance, with automatic compile-only PoC and dossiers also intended. These are
planned central defaults, not the inspected baseline configuration. Existing runs retain their
frozen settings: new checkout defaults must not silently enable a previously disabled producer
when resuming or publishing an old run. Automatic processing does not authorize runtime execution
or imply reproduction or a fixed finding.

Ordinary per-item failures must be terminal accounted outcomes so a dossier can state what was
not produced. A missing expected capability or incomplete/capped scope is a named gap.
Disabled-by-policy, empty eligible scope and integrity failure are distinct.
Tampered bytes, inconsistent bindings, cross-review attachments or malformed accepted manifests
must fail integrity validation, not become success-shaped empty sections.

Retries must write a new immutable attempt and leave earlier accepted artifact bytes intact.
Resume must invalidate consumers when any consumed review, PoC, plan, validation, settings,
schema, tool or rendering identity changes. The final gate must verify all referenced bytes and
certify one snapshot before reporting.

Before calling this operational, reconcile actual central settings, CLI/manual invocation,
direct/Dagster dependency parity, dataset declarations, versioned schemas, candidate counts,
enabled/disabled combinations, render-failure retention, tamper rejection, deterministic output,
public-data leakage checks and the live PDF sample. Track results and remaining gaps in the
[implementation record](../reviews/evidence-completion-documentation-inventory.md).
