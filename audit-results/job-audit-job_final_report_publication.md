# Job 45/47 — job_final_report_publication

## Scope and result

- Audited **`main`, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, in `/home/wsollers/projects/appsec-review`, using authorized SSH/UNC access. Initial and final Git status were clean; the editable import resolved to this checkout's `src/appsec_review/__init__.py`. The default Windows checkout was not inspected or tested.
- Read the full updated shared brief, authorized AGENTS and coordination skill. This was one read-only functional audit; no subagents, repository edits, installs, real external renderers/tools/providers, services, integration, acceptance or live review runs.
- **Ten source-backed findings: one high, eight medium, one low**, with bounded reproductions below. A further independence-wording issue is explicitly conditional, not counted as an established reachable production defect. Documentation drift is reported separately.
- **26 focused units passed in 4.89 s**, wrapper total **13.831476 s**; zero failures, errors, skips or tests over 10 seconds. Eleven small probes took **0.311563 s + 0.002098 s**, excluding imports, and did not invoke external processes. Passing units do not certify live finding quality or PDF correctness.
- Gate, dossier and OpenVEX auditors were not awaited or duplicated. The newly completed gate/dossier reports were subsequently read at their finding/seam sections and reconciled below; their findings are not added to this report's ten. Findings here concern this report's projections/exports and their immediate shared rendering/measurement consumers.

## Registration, admission and intended contract

`src/appsec_review/runtime/registry.py:113,184` registers the builder. The central recipe at `appsec-review.toml:3845-3872` enables it, with one worker per step. `datasets.py:40-56` declares review-graph dispatch, accepted-evidence target access, scheduling after the final gate, handoff propagation, and `always_execute=False`. Its five units are terminal in the graph: no registered job declares this report as a predecessor. The graph and disabled selection are derived by `orchestration/topology.py:46-80` and `runtime/selection.py:11-29`; `enabled` is a central selection switch, not a local handler early-return.

Only two input requirements are declared:

| Producer / input | Declaration | Actual use |
|---|---|---|
| `job_final_publication_gate/handoff` | `appsec-review/job-handoff/2`, required/reject, producer evidence | `load_accepted_gate` → `indexing.store.accepted_handoff` → `runtime.consume.accepted_upstream`; in a real attempt, the contract and admitted digest select the accepted handoff. |
| `job_final_publication_gate/publication_gate_decisions` | `appsec-review/final-publication-gate/2`, optional/gap declaration | The handler actually requires the gate document referenced by the required handoff; there is no missing-document empty-report branch. It reads all gate-certified binding bytes and projects the gate. |

The report does **not** independently read current PoC, remediation or dossier producer pointers. Their exact summaries/references arrive through the gate snapshot. The chain manifest and dossier JSON receive additional bound reads; remediation is projected from certified gate rows, not rediscovered or executed.

`job_final_publication_gate/verify.py:43-74` checks gate envelope/document schema, expected handoff digest, run identity, total package count and aggregate bucket IDs; `verify_gate_snapshot:24-40` rehashes every binding and requires every input/capability/attachment reference to belong to that set. `sarif.chain_manifest_items:15-29` additionally checks the manifest schema/run, its bound reference, and chain status/components/artifact agreement. This audit relies on the gate's semantic certification; it does not re-audit its producer.

Current versus historical identity is intentional: inside an attempt, the admitted gate digest wins even if a later gate is accepted (`runtime/consume.py:147-203`). Later optional producer heads do not rewrite this report. The operator finding-metrics reader, conversely, requires the **current** report, gate, review, projection and accepted index to agree (`acceptance/system.py:140-207`); it refuses a stale report instead of silently selecting history.

### Every declared step/task

| Step / task | Actual processing and output | Integrity/error behavior and coverage |
|---|---|---|
| `load.accepted_gate` | `job.py:101-113`: accepted gate document/snapshot verification; returns gate handoff/document refs, status, counts and binding count. | Missing/changed/wrongly pinned input fails closed. Runtime admission is shared; unit fixtures fake the accepted-handoff boundary. |
| `report.assemble` | `job.py:115-160`: verifies resolved configuration profile, builds report from gate and bound chain manifest; schema-checks/writes `final-report.json`; builds and validates `findings.sarif` and `sarif-export-result.json`; emits `FINAL_REPORT_ASSEMBLED`. | No model or target scan. Findings/backlog/withheld remain distinct. SARIF omission gaps produce `COMPLETED_WITH_GAPS`. F01–F03/F05–F09 affect derived content or bounds. |
| `report.render` | `job.py:162-181`: Markdown with configured ID limits, executive HTML, repeated pure-render equality; writes `final-report.md` and `final-report.html`. | No external renderer. Publication repeats these comparisons. HTML is called without certified dossiers, unlike PDF: F04. |
| `report.render_pdf` | `job.py:183-201`, `pdf.py:54-201`: binds dossier JSON, renders LaTeX, optionally calls pinned `tool-report-latex`, retains valid PDF/logs/execution copy and receipt, emits `FINAL_REPORT_PDF_RENDERED`. | Disabled policy retains LaTeX and names a gap; tool failure keeps source/logs and no invented PDF. Changed template/pin/configuration is fatal. External boundary was faked in selected units; actual LaTeX/PDF execution was not run. |
| `acceptance.publish_handoff` | `job.py:203-290`: rehashes gate snapshot; schema-checks report and rebuilds it; recomputes SARIF/receipt, Markdown and HTML; rerenders LaTeX with bound dossiers; checks receipt report/TeX/PDF hashes and basic PDF structure; emits `FINAL_REPORT_PUBLISHED`; returns `/2` report handoff. | Equality faithfully reproduces the same projection defects; it does not detect their semantic incorrectness. Item count is publishable + backlog, excluding withheld. Gate gap statements, PDF gaps and SARIF gaps determine terminal status. |

The topology/dependencies in `job.py:46-48,292-306` match central task order. There are no model roles, task prompts, provider settings or runtime-guidance selections in this job. Generated “Undeclared (T-147)” task metadata does not mean PDF execution is absent.

## Publication, schemas, limits and consumers

### Package/report semantics

`report.py:76-149` carries gate status, accounting, ship-block counts, coverage summary, package buckets, limitations, capabilities and certified references. `review_complete` is true only for `COMPLETE`, no `review_incomplete`, and no gate limitation of kind `gap`. `not_run` and `notice` alone do not change that decision. Report-only PDF/SARIF problems are separate from the accepted review's completeness.

Attack-chain presentation retains only `confirmed` / `qualified_supported`; all four statuses plus proposed/admitted/rejected/deduplicated/capped counts remain explanatory accounting. PoCs retain compile-only status and fixed nonexecution assurance. Supported findings never become confirmed by a build, export or rendering. Roadmap tiers are deterministic critical → high → chain → dependency/config quick win → residual, ties by severity/package ID. `static_checked` is not promoted to build verification in this report. Rejected/inconclusive validation can fall back to a `proposal_only` roadmap label, while its actual rejected/inconclusive row remains in the validation section; no state mutation occurs.

Markdown renders every package and score dimension and bounds only evidence/gap identifier lists. Human display bounds do not truncate JSON identifiers. Executive tables/bullets use fixed presentation limits (64 rows, 240-character values, 1,200-character prose; `executive_report.py:49-50`, `digest.py:61-85,112-120`). Row omissions are counted/hashed; some table-cell/bullet character cuts discard the individual truncation object, so no blanket “every cut is individually receipted” claim is made.

### Files and dataset custody

All job files are under:

```text
data/jobs/job_final_report_publication/attempts/<attempt>/
  steps/load/tasks/accepted_gate/{result,status}.json
  steps/report/tasks/assemble/
    final-report.json
    findings.sarif
    sarif-export-result.json
  steps/report/tasks/render/
    final-report.md
    final-report.html
  steps/report/tasks/render_pdf/
    final-report.tex
    final-report.pdf                         # only on rendered success
    receipt.json
    container-execution.json                 # when execution receipt exists
    container-stdout.bin, container-stderr.bin
    report.log, report.pdfinfo.txt, report.txt # when present and within bound
  steps/acceptance/tasks/publish_handoff/{result,status}.json
  claim.json, handoff.json, ...               # shared runtime control files
```

- `final_report_publications`: artifact-only, acceptance step, `final-report/2`; globs cover load, report JSON, render/PDF trees and acceptance.
- `final_report_sarif`: protected, report step, SARIF 2.1.0; exact `assemble/findings.sarif`.
- `final_report_sarif_accounting`: artifact-only, report step, `sarif-export-result/1`; exact accounting JSON.
- All are unindexed; declared MCP inventory/coverage routes expose sanitized metadata, not payload authority. The selected file-custody test found no unclaimed job files.
- Final JSON uses the closed final-report/common schemas; PDF uses `final-report-pdf-receipt/1`; SARIF accounting has its own closed root schema. The SARIF **document** gets hand-written critical structural/reference checks, not a full external OASIS schema validation in this job.
- The handoff advertises `final-report-handoff/2` and references JSON/Markdown/HTML/SARIF/accounting/LaTeX/PDF receipt; actual PDF outcome is its `pdf` field. JSON's earlier `renderers.pdf.state="not_rendered"` deliberately points readers to that outcome; it is not a discovered defect.

Runtime unit `status.json` contains hash-bound `input_consumption` (`input-reads/1`); see `runtime/runner.py:683-715`. Handoff-envelope reads are observed, but `bound_artifacts.read_bound_json` does not itself record every nested dataset read. This is the documented bounded-instrumentation limitation (`docs/architecture/job-input-contracts.md:111-132`), already noted by earlier auditors, not a new absence of admission.

`strict_gaps=False` is existing legacy debt (`tests/test_gap_contract.py:12-24`): gate/PDF strings and typed SARIF gaps coexist. Shared runtime outcome normalization remains separate from human Markdown gap counts. No new terminal status vocabulary is added.

### Configuration and failure bounds

`settings.py:17-70` is closed/typed: Boolean `enabled`/`render_pdf`; Markdown limits 0–256; timeout 1–600 seconds; byte bound 1–67,108,864; nonempty tag and immutable SHA-256 image ID. Recipe defaults are 8/16 IDs, PDF enabled, 600 seconds and 16 MiB. Host pins supply the image ID. `pdf_identity`/`settings_sha256` exclude Markdown-only settings.

PDF execution pins catalog version, manifest/runtime-policy hashes and configured image identity; mounts template/input read-only, scratch writable, working directory `/scratch`, `SOURCE_DATE_EPOCH=0`, and a file-size limit (`pdf.py:141-156`). Its receipt records report/TeX/PDF/template/tool/settings/execution identity, dossier read counts, gaps and nonexecution policy. Fresh output is required for principal output names; input/scratch staging is removed in `finally`.

TeX exceeding the configured bound is fatal. Nonzero exit, timeout, OOM, file-size signal, missing/symlink/oversized/structurally invalid PDF yields a named rendering failure. OSError/RuntimeError becomes renderer-unavailable; ValueError becomes integrity failure. `valid_pdf` checks size/header/trailer, not full PDF semantic correctness. Log files over the bound are not copied; real retention behavior beyond fake fixtures remains unverified.

No semantic cache/model loop exists. Runtime config/input/component/release identities govern reuse. `implementation_identity=None` delegates to runtime release identity, rather than the unused local `IMPLEMENTATION` constant. Generic checkpoint/signing/shared-store behavior was not executed end-to-end.

### Metrics and operator consumers

Three local events expose attempted assembly, PDF and publication. Assembly includes bucket/capability/gap counts, radar/coverage/chain/roadmap metrics, duration and `runtime_verified=False`. PDF includes status, dossier read counts, gap count, enabled flag and duration. Publication includes unchanged publication/review flags and counts, release readiness and PDF status.

`observability/completion.py` intentionally aggregates event-scoped attempted work, including retries, not accepted finding truth; F10 identifies fields that never reach its summarized view. SARIF's counts are persisted in its own accounting artifact. `observability/findings/run_adapter.py:114-186,232-277` consumes accepted report buckets plus resolved source evidence; absent locations are named omissions, missing observations remain unknown, static remediation is not runtime success, and severity comes from the ship-block projection. No pipeline producer consumes this report as new adjudication.

## Findings

### FR-F01 — High — A withheld, unconfirmed package can certify 100% domain coverage with no findings

- **Evidence:** `reporting/dimensions.py:376-400` counts withheld packages as claims but increments unconfirmed backlog only for `verification_backlog`; `:408-410,428-437` substitutes package count for exposure and treats everything outside backlog as adjudicated; `:449-463` chooses `verified_no_findings` without considering the withheld/gate gap. `job_final_report_publication/report.py:142` supplies neither independent exposure nor inspection telemetry.
- **Trigger:** a supported memory-safety package is withheld because its chain outcome is unavailable; the review status itself remains `COMPLETE`.
- **Expected / actual:** withheld/unconfirmed work must remain an explicit verification gap. **R3** used the actual classifier and schema-valid report: gate limitation `withheld_packages`, `review_complete=false`, yet the memory axis became `verified_no_findings`, `verified_coverage.score=100`, `is_gap=false`, `gap_reasons=[]`.
- **Impact/confidence:** high-confidence overstatement in executive tables, radar and derived coverage confidence; no source exposure/inspection evidence was bound. This does not change the original gate's overall incomplete/limited status, but falsely certifies a domain within it.
- **Smallest correction:** retain unavailable domain coverage until exact exposure/inspection evidence is admitted; at minimum treat all supported/withheld-unverified packages as gaps rather than adjudicated work. Do not infer target-wide coverage from final package density.
- **Overlap:** completed T-176; open T-156, T-5045 and T-5078 cover wider execution-bound coverage, lead/chart bindings and misleading output. This is a concrete report-side arithmetic defect over an ordinary coherent classifier result, not a duplicate of upstream hunt coverage or FPG-F02's inconsistent certificate.

### FR-F02 — Medium — HTML and executive PDF discard the certified composed chain severity

- **Evidence:** `report.py:145` correctly builds cards with certified manifest items; `reporting/executive_report.py:561` instead calls `build_attack_chain_cards(report)` without those items or the already built cards. `executive_posture.py:107,131` therefore finds no manifest rating and emits `unrated`.
- **Trigger:** an admitted chain manifest supplies a rating.
- **Expected / actual:** project the same certified rating in every format. **R1** produced schema-valid JSON with `composed_severity="critical"` and Markdown `composed severity critical`; the executive document box said **`composed severity unrated`** and gained an extra gap count.
- **Impact/confidence:** high confidence; the most prominent leadership formats contradict accepted machine-readable/Markdown content. Their repeat-render checks reproduce the error exactly.
- **Correction:** use the canonical `report["attack_chain_cards"]` when present, retaining a compatibility fallback only for genuinely older reports.
- **Overlap:** T-176 and recent `094669218` certified-projection change; no exact prior report match found.

### FR-F03 — Medium — Radar ignores every gate-shaped chain membership

- **Evidence:** `reporting/dimensions.py:334-347` reads `item["claim_ids"]`; the closed gate/report chain schema requires **`component_claim_ids`** (`docs/schemas/final-report/common.schema.json:68-78`). `executive_posture.py:37-43` uses the correct field, while radar `:388-396` uses the empty set.
- **Trigger:** a publishable low/medium finding participates in a certified active chain.
- **Expected / actual:** consistent chain-elevated counts. **R2** yielded executive posture count **1**, radar chain-elevated count **0**, and radar high/critical-or-chain count **0** for that domain.
- **Impact/confidence:** high confidence. JSON/Markdown radar and event counters undercount chain participation. PDF may separately count a dossier's `chains` and therefore disagree further. Standalone severity is not supposed to be overwritten; the bug is the explicitly chain-inclusive series/count.
- **Correction:** consume the schema's `component_claim_ids`, with a focused real-shape parity test across formats.
- **Overlap:** T-176; separate from F02's lost manifest rating.

### FR-F04 — Medium — HTML reports certified dossiers as nonexistent and omits available narratives

- **Evidence:** `job.py:168-169,231` calls `render_executive_html(report)` without dossiers; PDF binds them at `:190,238`. `executive_report.py:640-671` counts only the supplied dossier sequence and `:264-275` calls its absence a report gap.
- **Trigger:** at least one gate-certified confirmed-finding dossier is available.
- **Expected / actual:** either render approved certified summaries consistently, or explicitly distinguish “not loaded in this format” from “not certified.” **R5** ran all five handlers with PDF disabled and a real bound fixture dossier: HTML said **“0 of 0 gate-certified dossier documents”** and “dossier was not available”; the retained executive TeX included the available statement. Gate certification count was **1**.
- **Impact/confidence:** high confidence in the executed handler path. HTML loses location/narrative/engineering context and can classify radar domains differently because executive PDF recomputes radar using dossier metadata while JSON/HTML do not.
- **Correction:** use one intentionally scoped canonical projection across formats, or accurately label/report withheld-by-format content without inventing zero certified dossiers. Preserve source-excerpt protection.
- **Overlap:** T-176. **Distinct from dossier DP-04:** this finding concerns `final-report.html` not loading the already-bound dossier JSON; DP-04 concerns the upstream `dossier.md`/`dossier.html` sidecars missing from certified file maps. The final report correctly cannot list unbound sidecars. This is not a claim that all protected dossier content must be exposed in public HTML.

### FR-F05 — Medium — The wired SARIF exporter silently drops every trace and validated fix

- **Evidence:** `job_final_report_publication/sarif.py:32-54` reduces each bound dossier to CWE/predicate and its first location. It never supplies `dossier`, `taint_path_timeline` or remediation data. `reporting/sarif.py:133-146,292-361` can build code flows/fixes only from precisely those omitted fields.
- **Trigger:** a certified dossier contains an available source-to-sink timeline and qualified static/build remediation.
- **Expected / actual:** admitted exportable details should reach the enriched exporter, or be explicitly reported unavailable/omitted. **R7** bound inert rich dossier JSON through the real binder: job SARIF emitted **0 code flows, 0 fixes, 0 gaps**. Passing the same dossier to the existing lower-level exporter emitted **1 code flow and 1 fix**.
- **Impact/confidence:** high-confidence wiring omission. This does not prove actual upstream dossier trace/patch quality, and is not permission to publish unvalidated or source-excerpt content.
- **Correction:** construct a closed, evidence-derived export projection including approved trace/fix fields and their assurance; retain explicit omission accounting for unusable details. **Do not blindly forward today's synthesized dossier timeline:** DP-01 shows it can be invented from unordered/counterevidence locations, and DP-02 shows the actual exact-edit patch does not reach the advertised diff field.
- **Overlap:** T-176 explicitly claims enriched SARIF complete. **DP-01/DP-02 are prerequisite producer-content defects, not newly counted here.** R7 deliberately supplies inert rich fields to isolate this separate unconditional stripping even if upstream content were corrected; it is not proof the current producer emits sound traces/diffs.

### FR-F06 — Medium — Unclassified SARIF findings are invented as authentication/OWASP A07 findings

- **Evidence:** `reporting/sarif.py:92-103` falls back to `DIMENSIONS[0]` when classification returns `None`; `:106-125` derives OWASP from that fabricated domain.
- **Trigger:** a valid publishable finding with `security_predicate="other"` and an unmapped CWE/title, but explicit usable severity/location.
- **Expected / actual:** remain unclassified/unknown, not guessed. **R8** exported `other (CWE-9999)` as **`authentication_session`, `AuthN & Session`, `A07:2025`**, with no gap.
- **Impact/confidence:** high confidence. The result/rule IDs and taxonomy assert a category unsupported by input; Markdown/JSON radar correctly leaves comparable inputs unclassified.
- **Correction:** allow an explicit unclassified SARIF rule/domain and omit unestablished OWASP taxa, or name an export gap.
- **Overlap:** T-176; no exact prior audit/TODO defect found.

### FR-F07 — Medium — Mixed-severity findings share the first finding's SARIF security severity

- **Evidence:** `reporting/sarif.py:432-434` creates rule IDs from domain/CWE, `:460` sorts by finding ID, `:488-493` keeps only the first rule, and `:524-528` sets rule-level `security-severity` from that one finding. Results for that rule all reference the same rule index.
- **Trigger:** two publishable findings of the same CWE/domain have different technical severity.
- **Expected / actual:** standard SARIF rule-level security severity must not be determined by an unrelated finding's opaque ID. **R11** exported low and critical CWE-120 findings: **one shared rule with `security-severity="2.5"`**, both rule indexes 0, while custom per-result severities remained low/critical.
- **Impact/confidence:** high confidence in conflicting export data; consumers using standard rule properties can understate the critical finding (or overstate a low finding when sort order reverses). No external upload was performed.
- **Correction:** use a rule identity that can represent each severity, or a documented deterministic severity policy that preserves per-result meaning rather than first-wins.
- **Overlap:** T-176; not a defect in gate scoring itself.

### FR-F08 — Medium — Reachable supply-chain count is permanently zero because its input is forbidden

- **Evidence:** `reporting/executive_posture.py:45-57` requires `pkg["reachability"]`. Gate finding projection never includes it (`jobs/accepted_review.py:80-112`); `common.schema.json:522-548` is closed, and its properties contain no reachability field. `report.py:142-144` feeds these closed packages directly into posture.
- **Expected / actual:** unestablished reachability should be unavailable, not a measured zero. **R10** confirmed the schema forbids the required property and the report reports zero for a supply-chain finding. Thus every currently valid report takes this zero path, irrespective of separately available dependency analysis.
- **Impact/confidence:** high confidence in the dead measurement path and misleading numeric presentation. This audit does not assert that any real dependency was reachable.
- **Correction:** expose unknown/unbound with a reason until a gate-certified reachability projection is explicitly declared and joined; do not infer reachability from confirmation or widen reads to live optional producers.
- **Overlap:** T-166's outstanding dependency-use/reporting work and T-176. The missing capability is known scope; the new concrete manifestation is an unconditional leadership-facing zero.

### FR-F09 — Medium — Legal chain volume can make final report assembly fail its own schema

- **Evidence:** `executive_posture.py:285-294` appends one named gap per unrated chain without a bound. `final-report.schema.json:488-490` caps named gaps at **256**, while cards/active chains permit **1,000** (`:191,476`), gate attachments permit **10,000** (`common.schema.json:134`), and `config/inference_review.py:792` accepts up to **10,000** chains.
- **Trigger:** a larger explicitly configured review has enough active chains with missing composed severity, or more than 1,000 active chains overall. Default `max_attack_chains=50` does not reach this threshold.
- **Expected / actual:** all admitted outcomes should remain representable, or an upstream explicit cap/omission contract should prevent admission. **R9** built 245 distinct chain cards and **263 named gaps**; the real final-report validator rejected `$.named_coverage_gaps: array length out of bounds`.
- **Impact/confidence:** high confidence in the bounds mismatch; report assembly fails after a gate-shaped document can represent the input. The probe exercises projection/schema shape, not a real 245-chain accepted ledger.
- **Correction:** reconcile admitted maximums and publication schema bounds, or produce a deterministic bounded gap aggregation with complete accounting. Do not silently truncate chains.
- **Overlap:** T-176; no exact existing entry found.

### FR-F10 — Low — Completion summary drops new report metrics and disabled-PDF outcomes

- **Evidence:** `job.py:146-153` emits radar/coverage/chain/roadmap counters and nested radar/rate maps. `observability/completion.py:17-46,91-104` has no corresponding counters/maps, and `not_rendered` is absent from `OUTCOMES`; `:176-178` ignores that PDF status.
- **Expected / actual:** summary consumers should preserve supported report metrics/outcomes or explicitly declare them event-only. **R6** fed actual handler events into `completion_metrics`: radar was present in assembly details but absent from the aggregate, and the disabled PDF event's `outcomes` was **`{}`**.
- **Impact/confidence:** high confidence; raw event data and PDF receipt remain intact. This is loss in derived observability, not evidence destruction or altered publication.
- **Correction:** add bounded typed aggregate fields/status support or document the deliberate event-only contract. Keep retry/process counters distinct from accepted finding counts.
- **Overlap:** T-176 telemetry deliverable; no exact prior match found.

## Conditional observation, documentation and known overlaps

### FR-U01 — Conditional medium — Executive wording ignores an explicit lack of independence

`executive_report.py:180-189` says “Yes: an independent verifier confirmed this finding” whenever `state=="confirmed"`; `independence.independent=False` merely suppresses the parenthetical. R4 supplied a schema-supported false independence flag: Markdown correctly said “independent verifier no,” HTML said yes. The gate/shared projection preserves that flag, but this audit did **not** prove a normally generated, accepted ledger can produce this combination; therefore this is a verified renderer behavior with an unproven production trigger, not included in the ten findings. Treat it as an **extension of DP-01's presentation/independence overclaim**, not another cumulative finding. Respect the existing distinction between same-provider/model verification and true independence; do not change finding state to repair wording. Prior inference-auditor independence concerns are a separate upstream issue.

### Newly available upstream findings confirmed at this report's seams — not new counts

- **FPG-F01, missing unit-context snapshot bindings:** `load.accepted_gate` and publication call the same shared snapshot verifier, which hashes only its provided binding closure. This report adds no recursive unit-context revalidation. The gate auditor's reproduced missing closure therefore applies here; not rerun or counted again. “Every certified binding is hashed” does not mean every necessary historical dependency was certified.
- **FPG-F02, contradictory bucket/count certificate:** `build_report` filters packages by row bucket but copies gate counts; `publish` rebuilds that same projection. The already reported faulty-certificate case can consequently preserve mismatched displayed counts and handoff `item_count` here. This is a direct static extension of FPG-F02, not a separate report bug or a claim that the ordinary classifier currently generates those contradictions.
- **DP-04, missing dossier Markdown/HTML bindings:** `render.py:274-277` lists only the gate's certified file map, so those sidecars remain absent from the final-report listing. The report must not discover or add unbound sidecars as a workaround. The fix belongs to the producer/receipt/gate file-map chain with its downstream projection updated together.
- **DP-01, invented dossier fallback content:** no claim in this audit that hashing a dossier establishes the truth of its narrative/path. FR-U01 is an extension; F05's recommended SARIF repair must await valid evidence-derived trace/fix inputs rather than turning DP-01 content into machine-readable path authority.
- The dossier auditor independently confirmed **RV-F05**; that remains one prior cumulative finding. DP-03's dossier-Markdown content omissions are likewise not final-report-Markdown omissions and are not recounted.

### Documentation drift

- `docs/operations/job_final_report_publication.md:170` explicitly says the handler does not invoke a PDF renderer, contradicting its own generated five-task table and `job.py:183-201`. Its process/dataflow/publication prose still describes only JSON/Markdown.
- `docs/operations/final-report.md:297-310` still documents nine axes/two series, while code produces twelve/four.
- `docs/architecture/reporting-and-metrics.md` has a late T-176 section claiming a different four-series vocabulary, populated SARIF flows/fixes and an OWASP posture matrix; the earlier as-built discussion is more accurate. The dedicated OWASP final-report projection is already open **T-5012**, not a new missing-job finding.
- T-160 already tracks actual minimum-Python renderer syntax compatibility; tests here used Python 3.12, not the declared minimum.
- T-147 already tracks missing generated task/model/tool bindings.
- Reviewed relevant previous reports by seam search, with the remediation-validation report read fully. Its **RV-F05** (dossier static-check headline after rejected validation) is not counted again here. PoC/remediation planning/validation certified-assurance findings remain their owners' results.
- T-5078 references host-local prior output audits unavailable here; exact overlap with those individual items is **unread**, not assumed absent. No TODO entries were changed.

## Focused validation record

All Linux scripts ran from `/home/wsollers/projects/appsec-review` via:

```powershell
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
    "printf %s $encoded | base64 -d | bash"
```

Preflight/final checks:

```bash
git rev-parse HEAD
git status --short
git branch --show-current
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Result: exact required SHA, clean status, main, correct editable source. Later scripts asserted the exact HEAD and empty porcelain before collection/execution. No shared environment variable was modified by the audit; normal pytest fixtures operated only inside their own processes/private test trees.

### Explicit collection

```bash
.venv/bin/python -m pytest --collect-only -q -o addopts= \
  -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-fr45-collect-20261118-01 \
  tests/unit/job_final_report_publication/test_contract_and_settings.py \
  tests/unit/job_final_report_publication/test_job_units.py \
  tests/unit/job_final_report_publication/test_report_and_render.py \
  tests/unit/reporting/test_executive_report.py \
  tests/unit/reporting/test_t176_radar_and_dossiers.py::test_twelve_domains_and_four_series_validate_against_schema \
  tests/unit/reporting/test_t176_radar_and_dossiers.py::test_radar_coverage_gaps_never_conflated_with_clean_domains \
  tests/unit/reporting/test_t176_radar_and_dossiers.py::test_domain_and_owasp_mapping_covers_all_twelve_axes \
  tests/unit/reporting/test_t176_radar_and_dossiers.py::test_executive_report_posture_chains_roadmap_and_multi_format_rendering
```

**26 collected in 1.64 s**, zero executed; exit 0. One `PytestConfigWarning: Unknown config option: cache_dir` because cacheprovider was disabled. Collection used its private base temp.

### Shuffled execution

```bash
scripts/run-tests.sh --parallel --test-workers 2 \
  --max-tests 26 --expect-tests 26 --shuffle-seed 4518 --strict -- \
  tests/unit/job_final_report_publication/test_contract_and_settings.py \
  tests/unit/job_final_report_publication/test_job_units.py \
  tests/unit/job_final_report_publication/test_report_and_render.py \
  tests/unit/reporting/test_executive_report.py \
  tests/unit/reporting/test_t176_radar_and_dossiers.py::test_twelve_domains_and_four_series_validate_against_schema \
  tests/unit/reporting/test_t176_radar_and_dossiers.py::test_radar_coverage_gaps_never_conflated_with_clean_domains \
  tests/unit/reporting/test_t176_radar_and_dossiers.py::test_domain_and_owasp_mapping_covers_all_twelve_axes \
  tests/unit/reporting/test_t176_radar_and_dossiers.py::test_executive_report_posture_chains_roadmap_and_multi_format_rendering
```

**26 passed, 4.89 s pytest, 13.831476 s wrapper total, exit 0**. No failures/errors/skips/known failures/slow tests. Wrapper collection also enforced exactly 26; collection and execution process cleanup were confirmed with zero remaining processes. Environment guard preflight ran before xdist workers.

Coverage by file: mapped contract/settings **2**, mapped handler units **6**, mapped report/render units **3**, executive-report units **11**, selected radar/executive T-176 cases **4**.

```text
test/tmp/tests-custom-20261118-135241-018773-3596150
test/tmp/logs/tests-custom-20261118-135241-018773-3596150.log
test/tmp/tests-custom-20261118-135241-018773-3596150.collection.json
test/tmp/tests-custom-20261118-135241-018773-3596150.junit.xml
test/tmp/tests-custom-20261118-135241-018773-3596150.timings.sqlite
test/tmp/reports/tests-custom-20261118-135241-018773-3596150.json
```

The wrapper used this checkout's `.venv/bin/python`, `-p ops_test_guard`, explicit root/config, `-o addopts=`, its private basetemp/JUnit, `-n 2`, and seed 4518. Existing normal wrapper collection/execution reuse of that unique directory was sequential.

### Bounded reproductions

Executed as two `.venv/bin/python -B - <<'PY' ... PY` scripts, not additional pytest cases:

| Probe | Real functions and smallest input difference | Observation |
|---|---|---|
| R1 | `build_report(..., chain_manifest_items=[{..., composed_severity:"critical"}])`, then `executive_document`; schema-valid report | JSON/Markdown critical; executive chain box unrated. |
| R2 | Same report, low-severity confirmed member of a `component_claim_ids` chain | Posture elevated 1; radar elevated 0/high-critical 0. |
| R3 | `verified_document` fixture; supported memory package references unavailable chain; real classify + build + schema validation | Withheld supported package credited as 100% verified/no findings. |
| R4 | Schema-supported `independence=False` on confirmed projection, pure HTML/Markdown | HTML yes, Markdown no; normal upstream reachability unproven. |
| R5 | Inspected `_setup_run(dossier=True, render_pdf=False)`, actual five handlers; fake accepted-handoff boundary; PDF factory fails if called | HTML falsely 0 of 0 certified/unavailable; TeX includes bound narrative; no external renderer called. |
| R6 | Actual R5 event rows → `completion_metrics` | New radar map absent; PDF `not_rendered` outcome absent. |
| R7 | Real `bind_dossiers`/`gate_sarif` against inert hash-bound dossier JSON with two-step timeline and build-checked diff; compare lower-level exporter supplied the same dossier | Wired export 0/0/no gaps versus helper 1 flow/1 fix. Does not certify upstream dossier construction. |
| R8 | `export_sarif_bundle` with `other`, CWE-9999, medium severity, valid path/line | Invented Auth/A07 taxonomy, no gap. |
| R9 | 245 distinct active unrated chain IDs → `build_report` + real schema validator | 263 named gaps, publication schema failure. Shape probe, not full accepted ledger. |
| R10 | Read closed finding schema and actual posture over a supply-chain title | Reachability property forbidden; count 0. |
| R11 | `export_sarif_bundle` with same CWE-120/domain, IDs `a-low` and `b-critical`, explicit low/critical severity | Shared rule severity 2.5 despite critical result. |

R1–R9 total **0.311563 s** after imports, including setup/cleanup; R10–R11 total **0.002098 s**. R5/R7 owned a unique `test/tmp/job-audit-fr45-repro-<uuid>` directory, removed in `finally`; removal confirmed. No shared fixture/source file was edited. The other probes were in memory.

Two read-only inspection mistakes were harmless and are not test failures: a remote search attempted unavailable `rg` (exit 127; subsequent searches used UNC tools), and a schema read first used a nonexistent top-level path before locating `docs/schemas/final-report/sarif-export-result.schema.json`. Neither caused an install or fallback to the Windows checkout.

## Read inventory and remaining gaps

**Read fully:** all eight job `.py` files; gate `verify.py`; shared `bound_artifacts.py` and `engineering_contracts.py`; reporting `dimensions.py`, `executive_posture.py`, `executive_report.py`, `sarif.py`, `sarif_export.py`; runtime selection; completion metrics; final-report/gate/PDF/SARIF-accounting schemas; job operation page; architecture reporting-and-metrics; T-176 task plan; all three mapped job-unit files; executive-report and T-176 test files; legacy `tests/test_final_report.py` and `tests/final_report_support.py` (read only); shared brief/AGENTS/coordination skill; remediation-validation prior report.

**Read in selected ranges/searches:** common final-report schema (chain/finding/coverage/count contracts), root pytest harness/environment guard and fixture helpers, central recipe/test map, registry/topology, runtime consume/input receipts/runner, accepted-review finding projection, accepted-final-report/current identity reader, finding metrics adapter, bounded digest helpers, HTML and LaTeX formatting entry points, template identity, container execution receipt retention, chain manifest producer severity fields, wrapper implementation and named TODO/prior-report seams; newly available dossier report lines 78–134 and gate report lines 130–166, plus their seam searches. These are not claims of whole-subsystem coverage or independent reruns of those auditors' probes.

**Material unread or unverified:** complete gate/dossier/OpenVEX producer internals (separate auditors), complete review ledger/scoring semantics, all shared signing/custody/permission/checkpoint implementations, complete renderer/template internals, actual OASIS full-schema validation, PDF visual layout/content/determinism from a real LaTeX process, full current accepted-run source/evidence closure, all operator CLI/report loaders and downstream metrics suites, unselected SARIF helper edge tests, actual supported-minimum Python, and HAL host-local output audit entries.

**Explicitly not run:** mapped acceptance `tests/test_final_report.py::test_report_json_is_schema_valid_and_contains_the_required_sections`, other legacy chain tests, integration/live/Dagster reviews, any real provider/compiler/container/PDF renderer, target code, current production run or service. The legacy acceptance helper's `report_job()` uses the real default executor with PDF enabled; its old “no container” module prose was not trusted as authorization to run it.

Final authorized source remained exactly pinned and clean. Test logs/receipts remain under ignored private `test/tmp`; synthetic probe scratch was removed. Only this session report was created outside the repository. Audit stops after this job.
