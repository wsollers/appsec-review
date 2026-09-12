# ADR-0006: CodeQL as a pre-engagement evidence-gathering lane

Status: Accepted 2026-09-12

## Context

ADR-0001 rejected CodeQL as the native memory-safety substrate (no sound alias/points-to
analysis). That leaves its actual strengths unused: mature security-extended query suites
across C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Swift, with
versioned query packs and SARIF output, and a build-mode-none extractor that needs no
working toolchain. For the pre-gather phase — "what does this codebase look like before
the specialist lanes start" — that breadth is the point.

Two constraints shape how it can be used:

1. **License.** The CodeQL CLI is licensed for open-source and academic use; use on
   proprietary code in a commercial engagement requires GitHub Advanced Security. A
   finding produced under the wrong basis is unusable and a liability.
2. **Fidelity.** `--build-mode none` for C/C++ skips build-driven preprocessing; the
   clang-cl tracer is documented as preliminary. C/C++ CodeQL results are therefore
   breadth evidence, not the basis for memory-safety claims.

## Decision

- Add `images/audit-codeql` (CodeQL bundle, pinned; query packs bundled; offline).
- The run script refuses without `CODEQL_LICENSE_BASIS ∈ {oss, academic, ghas}`; the
  value is recorded in `run-manifest.json` and must appear in the engagement's
  `run-manifest.json` and negative-space notes.
- Default extraction: interpreted/buildless where available; `--build-mode none` for
  C/C++, Java, C#. Traced clang-cl replay is an explicit opt-in experiment.
- CodeQL C/C++ findings enter L3 only as candidates alongside CSA/SVF, never as the
  substrate; their assurance class is capped at `STRONG_INFERENCE`.
- PHP is out of CodeQL's scope; `audit-static` remains the PHP lane.

## Consequences

- Pre-gather gains one uniform SARIF per language with versioned query provenance.
- The license basis becomes an explicit engagement input (intake / L0).
- Two images now contain "C++ analysis"; the report must state which produced a given
  finding and under what extraction mode.
