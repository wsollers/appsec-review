# Dossier publication operations

Status: producer delivered in `065f736c`, centrally wired in `b702eb7`, assurance compatibility
fixed in `7641fa5` (2026-10-28). The semantic job, protected loader, renderer, typed settings and
receipts are implemented. **End-to-end acceptance remains pending**: chain publication now emits
review handoff `/3`, but the delivered shared reader still expects `/2`; final PoC/gate/report
attachment contracts and a real seeded PDF sample are not yet reconciled here.
The [source-verified data inventory](../architecture/dossier-data-inventory.md) lists actual
producer/index/query/provenance surfaces and unavailable capabilities.

## Membership and placement

The [approved completion contract](../architecture/evidence-completion-and-remediation.md#11-parallel-implementation-decisions)
requires one protected developer dossier for **each confirmed finding**, irrespective of whether
its investigation originated in a document or source code, and a separate dossier for **each
accepted PoC candidate outcome**. Failed, declined, unavailable and unsupported PoC outcomes
still need an accounted dossier with their limitations. Supported claims are not promoted to
confirmed findings by PoC generation or dossier rendering.

The registered graph is review (including chain ledger/manifest before sealing), optional compile-only
PoC, optional confirmed-only planning/validation, then dossier publication, **one final gate**,
and the terminal public report. Dossiers never consume the final gate: that would create a cycle.
The gate certifies their manifest, and the report exposes only certified references and statuses.
The [PoC](poc-generation.md) and [report](final-report.md) pages identify the remaining contract
transition; an ordered graph alone does not make incompatible accepted handoffs usable.

The implemented units in
[`job_dossier_publication/job.py`](../../src/appsec_review/jobs/job_dossier_publication/job.py) are:

```text
load.verify_inputs -> dossiers.create -> acceptance.publish_handoff
```

`load_inputs` uses the shared accepted-review verifier, exact claim/package/hash binding and source
manifest. It verifies optional producer summary/item/gap accounting, confirmed-only remediation,
planning-to-validation identity, all nested artifact references and the chain manifest.
`verify_snapshot` rehashes inputs and rejects accepted pointers that changed during publication.
The final publication checks that rendered plus omitted rows exactly partition confirmed findings
and accepted PoC outcomes. Source and producer integrity failures are not ordinary render gaps.

## Central settings

These are current defaults in [`appsec-review.toml`](../../appsec-review.toml), under
`jobs.job_dossier_publication.settings`; the closed parser is
[`DossierPublicationSettings`](../../src/appsec_review/jobs/job_dossier_publication/settings.py).
Settings and renderer/image identities are recorded in artifacts; the frozen run, not the current
checkout, determines an older run's configuration.

| Setting | Default / meaning |
| --- | --- |
| `enabled`, `render_pdf` | Both `true` for new configurations. Disabling PDF retains JSON/LaTeX with `latex_only` and a policy gap. |
| `max_packages`, `max_dossiers` | 10000 verified packages / 20000 dossier candidates. Overflow remains in `omitted` with exact finding binding and `max_dossiers` reason. |
| `max_artifact_bytes` | 16777216 bytes per bounded input or rendered artifact. |
| `max_source_excerpts`, `max_evidence_rows` | 4 excerpts / 24 citation rows. Cited accepted identities only; source retrieval uses two context lines. |
| `max_text_chars`, `max_code_lines`, `max_code_chars` | 1800 text characters / 40 lines and 4000 characters per code block; truncation records preserve omitted counts/hashes. |
| `image_tag` | `appsec-review/tool-report-latex:1.0.0` |
| `image_id` | `sha256:1dd77c969bba00168bc3128e5ee8290328dd06c09ecd4d845618c3c6336530e4` |
| `render_timeout_seconds` | 600 seconds. A configured pin mismatch is an integrity failure, not successful degraded rendering. |

## Required retained evidence

| Record | Operational meaning |
| --- | --- |
| Accepted input references | Review/job/ledger/manifest and exact claim/finding package/hash bindings; accepted optional producer handoffs, frozen settings and tool/guidance identities. No later `latest.json` discovery after certification. |
| Dossier JSON | Deterministic bounded developer projection, preserving evidence/adjudication/score/independence/shipment provenance, applicable attachments, coverage and unavailable dimensions. |
| LaTeX source | Deterministic escaped rendering input; retain it even when rendering cannot complete. |
| PDF | Publish only real rendered bytes with a hash-bound success receipt. Missing image, timeout, failure or cap is a named render gap, never a placeholder called a PDF. |
| Rendering receipt | `appsec-review/dossier-rendering-receipt/1`: dossier/run/status/visibility, file refs, renderer, `source_date_epoch`, template file/tree hashes, tool/image/policy identities, settings hash, optional retained execution receipt and gaps. |
| Producer manifest/handoff | Exact accounting of eligible dossiers and every terminal rendering outcome, immutable attempt-owned paths/hashes, and explicit gaps. |

Outputs are new immutable directories under the attempt's
`steps/dossiers/tasks/create/items/<kind-and-finding-hash>/`: `dossier.json`, `dossier.tex`,
`dossier.pdf` only when rendered, and `receipt.json`. Available container execution/stream and
`report.log`, `report.pdfinfo.txt`, `report.txt` diagnostics are retained as protected artifacts.
The renderer removes its newly created `input` and `scratch` staging directories in `finally`;
the rendering receipt is not a fabricated separate successful-cleanup assertion.

[`reporting/dossier_render.py`](../../src/appsec_review/reporting/dossier_render.py) reuses the
existing catalog/runtime executor and template/palette, not a second container runner.
The hardened image uses no network, read-only inputs/template, no shell escape and
`SOURCE_DATE_EPOCH=0`. JSON and LaTeX are written before the render attempt. `rendered` requires
successful bounded execution and retained PDF bytes; ordinary failure gives `render_failed` with
no PDF ref, while policy-disabled rendering gives `latex_only`. Both keep JSON/LaTeX/receipt.
Integrity failures stop publication. The image pin is source-verified here; owner-reported smoke
and the real seeded sample must still be reconciled with retained evidence before acceptance.

## Process telemetry

Use existing correlated `context.events` and
[run metrics](metrics.md#completion-rollout-tracking-pending-integration), not a new backend.
Required observations include stage/candidate progress, eligible/terminal dossier counts,
source-retention and PDF-render outcomes, duration, caps, timeout/render/adapter failures and
coverage/integrity/cleanup gaps. Correlate by run/attempt and safe artifact identity, with
low-cardinality lane/stage/status/error-class rollups; model usage is reported only where emitted.
The producer emits `DOSSIER_INPUTS_VERIFIED`, `DOSSIER_BATCH_PLANNED`,
`DOSSIER_RENDER_STARTED`, `DOSSIER_RENDER_FAILED`, `DOSSIER_RENDER_COMPLETED`,
`DOSSIER_PUBLICATION_ASSEMBLED` and `DOSSIER_PUBLICATION_PUBLISHED`.
The fixed `completion.lanes.dossiers` metrics bucket is grouped by event; batch and item totals
must not be added as unique dossiers.

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
is wired as automatic planning, bounded validation, compile-only PoC and dossier defaults for new
configurations; rollout acceptance still depends on the remaining contracts and sample. Existing runs retain their
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

Before calling the new end-to-end graph operational, reconcile final review/PoC/gate/report
contracts, explicit manual admission, enabled/disabled combinations, tamper rejection, deterministic
and public-data leakage checks and the live PDF sample. Producer factories and declarations alone
are not that acceptance result. Track checks and remaining gaps in the
[implementation record](../reviews/evidence-completion-documentation-inventory.md).
