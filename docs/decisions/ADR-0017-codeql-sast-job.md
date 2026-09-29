# ADR-0017: CodeQL runs in its own job, always, with build-mode none

Status: **Proposed** (implemented on branch `ws-sast`; decisions 1 and 2 are William's, 2026-09-28;
3 to 6 are the implementer's and need review)

## Context

ADR-0006 added `images/audit-codeql` (CodeQL bundle v2.27.0, query packs bundled, offline) as a
pre-engagement lane with a license gate in `run-codeql.sh`. Nothing in the Dagster graph ran it.
The source SAST lane had Semgrep with 4 repository rules (plus 16 vendored opengrep C rules, same
branch) and per-language tools; freeciv21 and doom3-bfg had zero built native units, so the native
SAST lane skipped and C/C++ had pattern rules only.

## Decision

1. **Always run; no license gate in the pipeline** (William). The job does not read
   `CODEQL_LICENSE_BASIS`; the image default (`ghas`) stays as documentation.
2. **CodeQL is wired into the lanes** (William): C/C++ plus the interpreted and JVM/.NET languages.
3. **A separate job, `02-codeql-sast`**, not a tool inside `02-source-sast`. CodeQL is slow (minutes
   per language against seconds for Semgrep) and memory-hungry, so it needs its own limits, its
   own reuse fingerprint and the option to be skipped or re-run without re-running Semgrep. Its
   contract `codeql-sast` feeds `02-evidence-assembly` as a required edge. The claim ledger's
   `lead_candidates` (branch `review-batch`) needs one producer row for it (see TODO.md).
4. **`--build-mode none` for every language, including C/C++.** Tracing the accepted native build
   (`codeql database create --command` replaying the locked build) would need the CodeQL bundle
   inside each per-target build image, would execute the target's build again (hostile-build
   territory, ADR-0012), and gives nothing when build resolution produced no unit (freeciv21,
   doom3-bfg). CodeQL 2.27 supports build-mode none for cpp, csharp, java, javascript/typescript,
   python and ruby. The fidelity loss (no compiler-driven macros, includes, templates;
   unresolved Java/C# dependencies) is recorded as a coverage gap on every run. Go has no
   build-mode none (autobuild needs the toolchain and module downloads) and is a gap; gosec covers
   Go in `02-source-sast`. A traced C/C++ mode can be added later as a second tool id without
   changing the contract.
5. **One B13 container per language** running the repository-owned
   `images/audit-codeql/scripts/codeql-sast-lane.sh` (create, analyze with the bundled
   `<lang>-security-extended` suite to SARIF, drop the database). A language that times out, is
   OOM-killed or exits non-zero is a coverage gap (ADR-0013); a canceled or gate-refused container
   blocks. Timeout, memory, CPU, threads and `--ram` are job tunables.
6. **SARIF result messages are not promoted.** Leads carry rule id, the rule's short description
   from the pinned query pack, CWE tags, path, start/end line and a fresh source hash, like
   `02-source-sast` and `02-native-sast`. CodeQL messages quote target identifiers and code; they
   stay in the immutable attempt (`tools/codeql-<lang>/scratch/codeql.sarif`).

## Consequences

- `audit-codeql` needs a B16 record (image rebuild, which also picks up the lane script, then
  registry registration). Until then every language is an `UNAVAILABLE` gap and the job still
  publishes OK_WITH_GAPS.
- C# fails in the current image (no .NET SDK; build-mode none needs `dotnet` for reference
  resolution) and is a per-language gap until the image carries an SDK.
- ADR-0006's "license basis is an explicit engagement input" no longer holds for this job.
