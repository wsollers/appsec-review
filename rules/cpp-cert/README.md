# Native C/C++ CERT rule bundle

This directory is a rule asset bundle for the single generic C/C++ analysis workflow. It does not
define jobs, project detectors, containers, orchestration, or runtime configuration.

## Included rules and mappings

- `codeql/cert/` is the unchanged MIT-licensed CERT C++ CodeQL query pack from
  `github/codeql-coding-standards` release `v2.62.0`. It contains 117 queries covering 82 CERT C++
  identifiers. The pack metadata requires `codeql/cpp-all` 5.0.0 and
  `codeql/common-cpp-coding-standards`; those dependencies and an appropriately licensed CodeQL CLI
  must be supplied by the analysis environment.
- `semgrep/cpp-cert-gap-rules.yml` contains seven original MIT rules for high-confidence local
  shapes involving ownership, lifetime, mismatched deallocation, and locks. The rules use the open
  Semgrep YAML format and are intended to run under either Semgrep CE or OpenGrep.
- `mappings/codechecker/` contains unchanged Apache-2.0-with-LLVM-exception mapping files from
  CodeChecker. They connect CERT identifiers to Cppcheck, clang-tidy, and Clang Static Analyzer
  labels. A mapping is not an executable rule and does not establish that a checker is installed,
  enabled, or complete.
- `coverage.json` is the machine-readable high-value crosswalk. It deliberately names incomplete
  local and analyzer coverage rather than interpreting absence of a match as a clean target.

The CodeQL pack is broad. The original Semgrep rules are intentionally narrow: a syntax-only rule
was added only where the positive shape could be tested without creating an obvious clean-fixture
false positive. Deep ownership, lifetime, exception, bounds, and interprocedural concurrency cases
remain assigned to CodeQL or another semantic analyzer.

## License and provenance decisions

Exact revisions, upstream paths, licenses, and hashes are in `bundle-lock.json`.

The Semgrep Registry and `semgrep-rules` repository were evaluated but not imported because the
Semgrep Rules License v1.0 does not provide the redistribution terms required here. No registry
rule was copied or adapted. MISRA and AUTOSAR prose and example suites are also excluded because
redistribution and derivative rights were not established. Existing identifier labels inside the
Apache-licensed CodeChecker mappings are retained as identifiers only.

CMU SEI is used as the authority for CERT identifiers and canonical links. No CERT standard prose
or examples are copied into the original rules. CERT is a trademark of Carnegie Mellon University.

## Offline verification

From the repository root:

```text
python rules/cpp-cert/verify_bundle.py
python -m pytest tests/test_cpp_cert_rules.py -q
```

The focused test runs the positive and clean fixtures with the already-pinned Semgrep image when
Docker and that image are available. It never pulls an image. OpenGrep parity is an explicit skip
until a pinned OpenGrep executable is provided locally.

## Operator-only update workflow

Updates are a deliberate acquisition operation, separate from review execution:

1. Fetch a named upstream release or commit into a temporary operator checkout.
2. Review the upstream license and release diff before copying anything.
3. Replace only `cpp/cert/src` from CodeQL and the five named CodeChecker mapping files; do not
   import executables, prompts, CI configuration, or unrelated rules.
4. Record the exact commit, release, upstream path, license, file count, and deterministic hashes in
   `bundle-lock.json`. The tree hash is SHA-256 over sorted records of
   `relative-path`, a NUL byte, the file SHA-256, and a newline.
5. Update `coverage.json` only from the files actually present. Keep unsupported cases as named
   gaps.
6. Run the offline verifier, focused tests, and both positive and clean fixture scans. An OpenGrep
   result may be claimed only after the same locked rules and fixtures pass under a pinned OpenGrep
   version.

No update step is invoked by the generic C/C++ analysis workflow, and review runs do not access the
network to refresh rules.
