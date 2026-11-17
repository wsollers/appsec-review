---
title: "Task plan T-174: Unify compile-only PoC harnesses and add multi-language remediation validation"
kind: "task"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_poc_generation", "job_remediation_planning", "job_remediation_validation"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Task plan T-174: Unify compile-only PoC harnesses and add multi-language remediation validation

This plan implements **T-174** (`docs/TODO.md`): unifying Proof-of-Concept (PoC) eligibility,
adding static/AST/compile-syntax validation across **all nine smoke target languages** while
**strictly prohibiting PoC execution**, ranking `job_remediation_planning` by exploitability and
shared root-cause leverage, and upgrading `job_remediation_validation` beyond Python-only
`ast.parse`.

## Safety invariant — Zero PoC execution

> **Mandatory policy (`T-175`):** No generated PoC script, binary, harness, or test case may ever
> be executed by `job_poc_generation` or any unit/integration step until sandboxing is separately
> designed and approved by the user. `generated_code_execution` remains hard-pinned to
> `"not_performed_by_policy"`, enforced by code guards and dedicated unit assertions.

## Problem and motivation

- `job_poc_generation` had inconsistent finding-admission predicates across `confirmed` vs
  `corroborated` statuses and lacked AST/syntax verifiers for Ruby, C#, and PHP (3 of the 9 smoke
  target languages).
- `job_remediation_planning` sorted remediation items lexicographically by finding ID instead of
  prioritizing ship-blocking `critical`/`high` reachable vulnerabilities and shared root-cause
  architectural fixes (such as adding a single centralized parameterization helper or middleware
  guard that closes N findings at once).
- `job_remediation_validation` validated proposed diffs with Python `ast.parse` only, leaving C/C++,
  Java, JS/TS, Ruby, Go, C#, Rust, and PHP remediation diffs without structural AST syntax and
  post-patch barrier checks.

## Technical design and dataflow changes

1. **Unified static/compile-only PoC generation (`job_poc_generation`):**
   - Admit `confirmed` and high-confidence `corroborated` findings of `critical` or `high` severity
     plus `medium` findings participating in verified attack chains.
   - Provide structured **non-executing** PoC artifacts (`request_payload_spec`, `harness_source`,
     `trigger_preconditions`, `expected_vulnerable_oracle`, `expected_fixed_oracle`) validated via
     in-process **Tree-sitter syntax/AST parse checks** (zero parse-ERROR nodes, required entry
     harness symbol present, no placeholder `TODO`/`pass` stubs) across all 9 languages:
     `cpp`, `java`, `javascript`, `python`, `ruby`, `go`, `csharp`, `rust`, and `php`.
2. **Risk-and-leverage remediation planning (`job_remediation_planning`):**
   - Order remediation waves by `(ship_blocker_tier, severity_rank, chain_participation, shared_root_cause_leverage, finding_id)`
     and group findings sharing a common sink utility, middleware, or vulnerable dependency upgrade
     into consolidated engineering work items with concrete before/after diff guidance.
3. **Multi-language AST & barrier remediation validation (`job_remediation_validation`):**
   - Apply proposed unified hunks in memory against the accepted source snapshot, parse the
     post-patch file with Tree-sitter across all 9 target languages to verify zero syntax errors
     and preserved function signatures, and verify via the CFG/guard extractor (`T-168`) that the
     remediation introduces a dominating guard, safe API replacement, or parameterized call.

## Schema and telemetry specification

```text
New / updated versioned schemas:
- appsec-review/poc-artifact/2             (adds target_language, ast_syntax_valid, generated_code_execution="not_performed_by_policy")
- appsec-review/remediation-plan/2         (adds priority_wave, shared_root_cause_group, leverage_count)
- appsec-review/remediation-validation/2   (adds ast_parse_clean, signature_preserved, dominating_guard_verified)

Telemetry & metrics recorded per attempt:
- poc.eligible_findings, poc.ast_syntax_valid_by_language, poc.execution_policy_blocks (always 0 executions)
- remediation.waves_planned, remediation.shared_root_cause_clusters,
  remediation_validation.ast_verified_by_language, remediation_validation.guard_verified_count
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Update [`../architecture/review-judge-and-poc.md`](../architecture/review-judge-and-poc.md),
   [`../architecture/evidence-completion-and-remediation.md`](../architecture/evidence-completion-and-remediation.md),
   [`../operations/poc-generation.md`](../operations/poc-generation.md),
   [`../operations/remediation.md`](../operations/remediation.md), `docs/docs-ledger.json`, and run
   `scripts/generate-docs.py`.
2. **Full indexing for downstream inference:** Feed validated PoC specs and verified remediation
   diffs directly into `job_dossier_publication` and `job_final_report_publication` (`T-176`).
3. **Fast, isolated unit tests (`<10s`):** Add code-level unit tests under
   `tests/unit/job_poc_generation/`, `tests/unit/job_remediation_planning/`, and
   `tests/unit/job_remediation_validation/` covering all 9 smoke languages, stub/placeholder
   rejection, strict non-execution enforcement, risk/leverage wave ordering, and in-memory patch +
   Tree-sitter validation—`<10s` per test, zero Docker/model calls.
4. **Common querying & indexing skills doc alignment:** Ensure `poc_writer`, `remediation_planner`,
   and `remediation_validator` use `evidence-and-graph-querying` (`read_excerpt`, `query_syntax`,
   `query_debug_symbols`) documented in
   [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md).
5. **Frontier prompting, roles & skills alignment:** Refine `poc_writer` and `remediation_*`
   prompts to demand self-contained, idiomatic, non-destructive harnesses and minimal surgical
   patches preserving public API contracts.
6. **Metrics & telemetry:** Record per-language AST validation pass rates, stub rejections, and
   remediation root-cause consolidation ratios.
7. **Proper schema versioning:** Validate `/2` PoC and remediation schemas at publication while
   retaining `/1` readers for replay.
