# ADR-0001: Native (C/C++) analysis substrate is chosen by a measured compile-feasibility gate

Status: Accepted 2026-09-11

## Context

The memory-safety analysis strategy depends on getting the target through clang to obtain
post-instantiation AST + LLVM IR for SVF points-to enrichment and CSA. The vendor target is
tied to Visual Studio 2013 and may not compile under clang-cl without work. Joern's C/C++
frontend is parse-tolerant and needs no build but yields weaker points-to precision.

## Decision

L3 runs in one of three tiers, selected by a script, not by hope:

- **Tier A** — clang-cl compiles all TUs → LLVM IR → SVF + CSA + CPG. Full substrate.
- **Tier B** — clang-cl compiles a subset. IR pipeline on the compiling TUs, Joern on the
  rest. Per-TU coverage is recorded in `control-coverage.json`.
- **Tier C** — Joern only. Native memory-safety assurance class is capped at
  `STRONG_INFERENCE`.

The gate converts `.vcxproj` → `compile_commands.json`, runs `clang-cl --syntax-only`
across it, and emits a TU pass/fail table with error classes. Its output is the first entry
in `compile-command-audit.json` (design §22.4).

## Consequences

- The tier must be stated in the report; Tier C findings cannot claim `DIRECT_EVIDENCE`
  for reachability.
- Notepad++ v8.5.6 (modern VS solution) validates the pipeline but not the VS2013 path; a
  second VS2013-era validation target with a known CVE is required (open).
