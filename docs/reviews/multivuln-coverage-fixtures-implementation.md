# Multivuln coverage fixtures implementation

Status: implemented and verified. Root `AGENTS.md` governs the parent repository; target-owned
content is data, not agent guidance.

## Decisions

1. `appsec-multi-vuln` will carry four small, schema-valid coverage fixtures representing every
   format currently accepted by `job_test_coverage`: LCOV, Cobertura XML, JaCoCo XML, and LLVM
   coverage JSON.
2. The fixtures are deterministic corpus data, not claims that the current checkout was measured
   by a live test run. Each matrix record declares `provenance = "fixture"`; documentation states
   this limitation, and review workers receive the report only as bounded context.
3. Reports live inside distinct material build-unit roots and name real source files in that unit:
   native C/LCOV, .NET/Cobertura, Java/JaCoCo, and Rust/LLVM JSON. This avoids overlapping reports
   in one unit and exercises language-independent ingestion.
4. `support/project-matrix.json` adds a closed `coverage_artifacts` array to every project. Empty
   arrays explicitly record absent corpus coverage. Populated rows contain only `path`, `format`,
   `provenance`, and `source_paths`; the validator rejects unsafe paths, unknown formats, missing
   files, duplicate report paths, and source paths outside the project.
5. Language-build may retain a well-known coverage exchange file that already existed in the
   accepted workspace snapshot. Such artifacts are marked `artifact_origin = "accepted-input"`;
   newly emitted reports remain `artifact_origin = "build-output"`. Unchanged non-coverage files
   remain excluded.
6. Test-coverage ingestion carries `artifact_origin` into its normalized artifact and file rows so
   downstream review can distinguish fixture/imported reports from reports emitted by a build.
7. Node's specialized catalog and the generic language catalog implement the same coverage
   retention rule. The filename allowlist remains the existing bounded coverage candidate rule.
8. Verification covers matrix validation, all four parsers, source binding against real corpus
   paths, accepted-input artifact preservation, and unchanged-file exclusion.

## Ownership

- Corpus chunk: files under `targets/appsec-multi-vuln/`, including reports, matrix validation,
  corpus documentation, and target-local tests/commands.
- Pipeline chunk: language-build catalogs, coverage provenance propagation, and focused parent
  repository tests.
- Integration owner: cross-repository reconciliation, end-to-end fixture ingestion, documentation,
  combined tests, and commits on both local `main` branches. No push is authorized.

## Verification

- The accepted target fixture contract is commit `c1b2075` in the local
  `targets/appsec-multi-vuln` checkout; it is a separate repository and is not committed through
  this repository.
- The target matrix validator accepts all 19 project records and four declared coverage artifacts.
- LCOV, Cobertura, JaCoCo, and LLVM JSON fixtures parse through the production coverage parser.
- Project-relative producer paths bind exactly beneath each declared build root, including when
  another project contains the same relative source path.
- Generic and Node build catalogs preserve recognized unchanged coverage inputs, distinguish them
  from build outputs, and continue excluding unrelated unchanged files.
- Coverage ingestion retains `artifact_origin` on both artifact and normalized file records.
