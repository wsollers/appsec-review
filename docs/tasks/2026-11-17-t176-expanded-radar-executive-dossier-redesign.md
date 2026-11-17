---
title: "Task plan T-176: Expand radar dimensions to 12 axes and redesign executive reports and dossiers"
kind: "task"
subsystem: "reporting and metrics"
status: "current"
jobs: ["job_dossier_publication", "job_final_publication_gate", "job_final_report_publication", "job_openvex_export"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Task plan T-176: Expand radar dimensions to 12 axes and redesign executive reports and dossiers

This plan implements **T-176** (`docs/TODO.md`): expanding the security dimension radar tracker
from 9 axes / 2 series to **12 comprehensive security axes / 4 funnel series**, redesigning the
**Executive Security Report** (`executive_report.py`, `html.py`) and **Developer Finding Dossiers**
(`dossiers.py`, `dossier_render.py`) for maximum leadership clarity and engineering actionability,
enriching **SARIF 2.1.0** with `codeFlows` and `fixes`, and binding **OpenVEX** statements to exact
CVE identifiers (`job_openvex_export`).

## Problem and motivation

- `reporting/dimensions.py` tracked 9 axes (`M, N, I, W, F, P, A, R, X`) and only 2 series
  (`discovered`, `verified`), leaving **Secrets/Credentials**, **Supply-Chain/Dependencies**, and
  **Build/CI/Binary Hardening** invisible on the radar and hiding stage-by-stage triage funnel
  conversion (`discovered -> admitted -> corroborated -> verified_actionable`).
- `reporting/executive_report.py` lacked an immediate **Ship / Conditional-Ship / Block** release
  posture banner, multi-step attack-chain visual summaries, OWASP ASVS compliance heatmaps,
  first-party vs vendored SCA reachability breakdowns, and 30/60/90-day root-cause remediation
  waves.
- `reporting/dossiers.py` and `dossier_render.py` omitted structured **Attacker-to-Sink Trace
  Tables** (`Entry -> Propagation Hops -> Failed/Absent Guard -> Sink`), CPG/CFG provenance badges,
  compile-checked PoC trigger specs (clearly marked `not_performed_by_policy`), unified remediation
  diffs, and regression-test checklists.
- SARIF exports dropped `codeFlows` and `fixes`, and `job_openvex_export` emitted package-level
  entries without exact CVE IDs or reachability justifications (`code_not_in_execute_path`).

## Technical design and dataflow changes

1. **12-Axis, 4-Series Security Radar Tracker (`src/appsec_review/reporting/dimensions.py`):**
   - Expand radar axes to 12 deterministic dimensions covering 100% of CWE, OWASP, SCA, and CI/build
     findings:
     - `M` — Memory & Native Safety (buffer/heap/UAF/integer/pointer)
     - `N` — Injection & Interpreter Execution (SQLi, command, LDAP, template, eval)
     - `I` — Input Validation & Deserialization (XXE, unsafe deserialize, prototype/schema)
     - `W` — Web & Client Surface (XSS, CSRF, CORS, open redirect, SSRF)
     - `F` — Filesystem & Path Handling (path traversal, symlink/archive slip, file upload)
     - `P` — Authentication, Authorization & Session (authn bypass, IDOR/BOLA, JWT/privilege)
     - `A` — Cryptography & Trust Anchors (weak ciphers/hashes, RNG, TLS/cert, key handling)
     - `S` — Secrets & Credential Hygiene (hardcoded keys, tokens, private certs, env leaks)
     - `R` — Concurrency, Timing & Resource Bounds (races/TOCTOU, deadlocks, DoS/exhaustion)
     - `X` — Business Logic, State & API Spec Drift (workflow bypass, state confusion, OpenAPI drift)
     - `D` — Supply-Chain & Reachable Dependencies (reachable CVEs, vendored libs, FFI exposure)
     - `K` — Build, CI/CD & Binary Hardening (workflow injection, missing PIE/NX/RELRO/Canary/CFI)
   - Track **4 stage-conversion series** per axis: `discovered` (raw observations), `admitted`
     (first-party non-stylistic leads), `corroborated` (multi-tool or red-affirmed), and
     `verified_actionable` (verifier/judge confirmed/actionable), plus normalized risk-posture
     scores (`0..100`) and crisp multi-polygon SVG rendering (accessible palette, legend, data
     table fallback).
2. **Redesigned Executive Security Report (`executive_report.py`, `html.py`):**
   - **Section 1 — Release Readiness & Executive Verdict:** Ship-blocker gate status, top 3
     business-risk takeaways, severity/confidence scorecard, and 12-axis SVG radar + funnel table.
   - **Section 2 — Critical Attack Chains & Crown-Jewel Exposure:** Mermaid/structured multi-hop
     attack paths across trust boundaries (`job_threat_model_generation` + `attack_chain_analyst`).
   - **Section 3 — Prioritized Remediation Roadmap:** Wave 1 (Immediate Ship-Blockers), Wave 2
     (High-Leverage Shared Root-Cause Fixes), Wave 3 (Defense-in-Depth & Hardening).
   - **Section 4 — Supply-Chain Reachability & OWASP Control Posture:** Reachable (`used`) vs
     non-reachable (`not_used`) CVEs, binary hardening matrix, and OWASP ASVS control scorecard.
   - **Section 5 — Coverage Honesty & Named Analytical Gaps:** Explicit accounting of first-party
     coverage, skipped/degraded tools (`producer-gap/1`), and PoC non-execution policy notice.
3. **Redesigned Developer Finding Dossiers (`dossiers.py`, `dossier_render.py`) + SARIF & OpenVEX:**
   - Every finding dossier renders: (a) Header card (`finding_id`, severity, CWE, CVSS/exploitability,
     radar axis, owner component/symbol, attacker position); (b) **Step-by-step Source-to-Sink
     Trace Table** with exact `file:line` excerpts and provenance tier; (c) **Why Existing Guards
     Fail** (dominating guard analysis); (d) **Static PoC Trigger Specification** (marked
     `Execution: not_performed_by_policy`); (e) **Validated Remediation Diff & Verification
     Checklist**.
   - Enrich SARIF 2.1.0 with `codeFlows[].threadFlows[]`, `relatedLocations`, CWE `taxa`, and
     proposed `fixes` where validated; enrich `job_openvex_export` with exact `vulnerability.name`
     (`CVE-...` / `GHSA-...`) and `not_affected` justification `vulnerable_code_not_in_execute_path`
     when `T-170` proves `not_used`.

## Schema and telemetry specification

```text
New / updated versioned schemas:
- appsec-review/security-dimensions/2      (12 axes, 4 funnel series, per-axis posture score & CWE map)
- appsec-review/executive-report/2         (release_verdict, radar_summary, attack_chains, remediation_waves, coverage_gaps)
- appsec-review/finding-dossier/2          (trace_steps[], failed_guards[], static_poc_spec, validated_remediation)

Telemetry & metrics recorded per attempt:
- reporting.radar_counts_by_axis_and_series, reporting.funnel_conversion_rates,
  reporting.dossiers_rendered, reporting.sarif_codeflows_emitted, openvex.cve_statements_by_status
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Update [`../architecture/reporting-and-metrics.md`](../architecture/reporting-and-metrics.md),
   [`../architecture/dossier-data-inventory.md`](../architecture/dossier-data-inventory.md),
   [`../operations/final-report.md`](../operations/final-report.md),
   [`../operations/dossier-publication.md`](../operations/dossier-publication.md),
   [`../operations/openvex-export.md`](../operations/openvex-export.md), `docs/docs-ledger.json`,
   and run `scripts/generate-docs.py`.
2. **Full indexing & lineage preservation:** Bind lead admission and stage conversion cleanly
   through `job_final_publication_gate` (`T-5045`) so every number on the 12-axis radar traces to
   accepted run artifacts.
3. **Fast, isolated unit tests (`<10s`):** Add unit tests under `tests/unit/reporting/`,
   `tests/unit/job_final_report_publication/`, `tests/unit/job_dossier_publication/`, and
   `tests/unit/job_openvex_export/` verifying all 12 radar axes, 4-series monotonicity
   (`discovered >= admitted >= corroborated >= verified_actionable`), SVG validity, executive/dossier
   Markdown + HTML rendering, SARIF 2.1.0 `codeFlows`, and CVE-bound OpenVEX—`<10s` per test, no
   LaTeX container execution.
4. **Common querying & indexing skills doc alignment:** Cross-reference provenance tiers displayed
   in dossiers with [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md).
5. **Frontier prompting, roles & skills alignment:** Ensure structured fields produced by review,
   PoC, and remediation roles map 1-to-1 into dossier sections without post-hoc free-text guessing.
6. **Metrics & telemetry:** Publish complete 12-axis stage-conversion metrics and actionable yield
   summaries in `job_final_report_publication` telemetry.
7. **Proper schema versioning:** Validate `/2` dimension, executive-report, and dossier schemas at
   publication while supporting `/1` historical artifacts.
