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
- The gate's failure classes must map to converter fixes, not just be counted. On the
  first target, every failure class turned out to be a converter defect, not a property
  of the code (see below). Expect the same on the vendor tree before concluding Tier B/C.

## Outcome on the validation target (2026-09-11)

Notepad++ v8.5.6, 320 TUs: **Tier A**. Progression 0 → 191 → 249 → 320 across one
session; each step was a Windows-on-Linux gap in the converter or driver invocation, none
was a limitation of clang on the code. The eight gaps and their fixes are recorded in
`images/audit-native/README.md` (§ "Windows-on-Linux gotchas"). Per-project bitcode was
linked and SVF Andersen completed on the `notepadPlus` module (341k unique points-to sets),
which contains `Utf8_16.cpp`, the site of CVE-2023-40031/40036/40164/40166.

Three analysis-only deviations from the shipped build are now standard and must be listed
in `compile-command-audit.json` for every run: `_NO_CRT_STDIO_INLINE`, `/EHsc` where the
project relied on MSBuild's default, and the case-insensitive VFS overlay. None changes
program semantics in a way that affects points-to or memory-safety analysis; the
divergence is recorded regardless (design §23.4).

Open: the same converter on the VS2013 `CTP_Nov2013` vendor tree, where `__resumable` /
`__await` will fail as `MS_EXTENSION`. Decision pending between an analysis-only shim
(`-D__await=co_await`, modern `<pplawait.h>`) and a Tier B bucket for those TUs.
