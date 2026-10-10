# SEI CERT rule pack

`rules/sei-cert/` is a portable Semgrep CE / OpenGrep rule pack mapped to the SEI CERT C, C++,
Oracle Java, and (draft) Android standards. It records a status for **every** inventoried CERT rule,
not only the ones it implements, so absent coverage is always a named gap. Procedures for changing
and testing the pack are in [`../operations/sei-cert-rule-pack.md`](../operations/sei-cert-rule-pack.md);
the generated coverage view is [`../../rules/sei-cert/COVERAGE.md`](../../rules/sei-cert/COVERAGE.md).

## Layers

```text
official SEI repository (cmu-sei/secure-coding-standards, pinned commit)
  -> sources/cert-source-index.json   generated metadata: id, title, URL, CWE, exception ids, page hash
  -> mappings/<standard>.json         authoritative status and analysis for every CERT rule
  -> rules/<standard>/<cert>.yml      engine rules, each tied to one CERT rule
  -> fixtures/<standard>/<cert>.*     annotated positive, variant, negative, near-miss, exception cases
  -> validate (static) / evaluate (both engines, fixtures and multivuln) -> run-owned evidence
  -> job_evidence_collection          tool-semgrep and tool-opengrep execute the lock-verified rules
```

`pack.json` names every file, pins both engines, and defines the portable-syntax and value
vocabularies. `pack.lock.json` hashes every pack file; any file it does not name, or any changed
file, fails validation and blocks execution in the evidence job.

## Directory and naming conventions

```text
rules/sei-cert/
  pack.json, pack.lock.json, LICENSE.md, COVERAGE.md (generated), multivuln.json
  sources/cert-source-index.json
  mappings/{c,cpp,java,android}.json
  rules/{c,cpp,java}/<cert-id-lowercase>.yml
  fixtures/{c,cpp,java}/<cert-id-lowercase>.<ext>
```

- Engine rule IDs are `appsec-review.sei-cert.<source-language>.<cert-id>.<variant>`, for example
  `appsec-review.sei-cert.cpp.mem51-cpp.array-new-scalar-delete`. The language segment is the
  language of the analyzed code, so a CERT C rule that the CERT C++ standard lists as applying to
  C++ has a `cpp.<c-rule>` variant (for example `cpp.err34-c.unchecked-conversion-function`). The
  validator rejects a C++ variant of a C rule that the C++ standard says does not apply (such as
  CON31-C, whose C++ counterpart is CON50-CPP).
- All engine rules for one CERT rule live in `rules/<standard>/<cert>.yml`; fixtures for them live
  in `fixtures/<standard>/`. A rule whose findings also evidence a second CERT rule names it in
  `metadata.cert_also` (MSC50-CPP findings also evidence MSC30-C in C++ code).
- Required rule metadata: `pack`, `cert`, `cert_standard`, `source_language`, `cert_url`, `cwe`,
  `confidence`, `precision`, `coverage` (the parent mapping status), `technology`,
  `min_engine_versions`, `implementation_notes`, `license`. `cwe` may contain only identifiers the
  official page records; an analyst's additional judgment goes in `supplemental_cwe`, which may not
  repeat official identifiers. The rule message names the CERT identifier.

## Mapping model and statuses

Each mapping entry carries the official identifier, title, URL, retrieval date, source revision,
page path and hash, official CWE and exception identifiers, an original summary and compliant /
noncompliant concepts, `analysis_class`, `status`, `confidence`, exception handling, false-positive
and false-negative risks, the implementation (rule IDs per engine, engine versions, rule files,
fixtures, covered subset) or `null`, and an alternative-analyzer recommendation. The JSON contract
is [`../schemas/sei-cert-mapping.schema.json`](../schemas/sei-cert-mapping.schema.json).

| Status | Meaning |
| --- | --- |
| `SUPPORTED` | Every syntactic form of the rule's noncompliant condition is detected within the pack-wide limits (no preprocessing; no function-pointer, reflection, or cross-function resolution). Requires positive, variant, negative, and near-miss fixtures for every rule, fixtures for every honored exception, no `known-false-negative` fixture, and no exception outside the implemented subset. |
| `PARTIAL` | A named subset of the condition is detected; `implementation.coverage_note` and the false-negative risks name what is not. |
| `REQUIRES_DATAFLOW` | Needs value, taint, lifetime, or path reasoning beyond the pack. |
| `REQUIRES_COMPILER_OR_IR` | Needs resolved types, layout, linkage, preprocessing, or bytecode; delegated to compiler-backed analyzers (clang-tidy, Clang Static Analyzer, Cppcheck with a compile database, SpotBugs). |
| `REQUIRES_CODEQL` | A vendored CERT C++ CodeQL query (`rules/cpp-cert/codeql`) or a standard CodeQL Java query targets it. |
| `REQUIRES_MANUAL_REVIEW` | Needs human judgment of trust, sensitivity, or design, or the official page is incomplete. |
| `UNSUPPORTED_SEMANTIC` | No pattern engine or listed analyzer can decide it reliably. |
| `UNSUPPORTED_LANGUAGE` | The rule targets an artifact the engines cannot analyze (Android manifest XML). |
| `DUPLICATE_EXISTING_RULE` | Covered by another repository rule named in `duplicate_of`. Currently unused. |

Unimplemented entries are assigned deterministically from their analysis class: Android manifest
rules are `UNSUPPORTED_LANGUAGE` and incomplete Android pages `REQUIRES_MANUAL_REVIEW`; C++ rules
with a vendored CodeQL query are `REQUIRES_CODEQL`; design rules are `REQUIRES_MANUAL_REVIEW`;
build/whole-program and C/C++ type-semantic rules are `REQUIRES_COMPILER_OR_IR`; Java
type-semantic rules go to CodeQL, then SpotBugs/PMD, else `UNSUPPORTED_SEMANTIC`; data-flow rules
are `REQUIRES_DATAFLOW`; concurrency rules are `REQUIRES_DATAFLOW` when an analyzer is listed and
`REQUIRES_MANUAL_REVIEW` otherwise; and syntactic rules not yet implemented are delegated to a
listed compiler-backed analyzer or manual review and flagged `pattern_candidate`. Implemented
entries were reviewed against the official page, fixtures, and both engines. Summaries and analysis
classes of unimplemented entries were drafted from the official pages and should be re-read
against the page before an entry is promoted.

Exception handling is one of `excluded-by-rule` (tested by an `exception:` fixture),
`reported-for-review` (the rule cannot recognize the exception syntactically; tested by an
`unmodeled-exception:` fixture that expects the finding), `outside-implemented-subset`, or
`not-implemented`.

Source facts that the index preserves instead of hiding: the draft Android standard reuses `DRD25`
for two rules (keyed `DRD25@CRP` and `DRD25@MSC`); SER12-J names its exception `SER12-EX0`; and the
CERT C++ standard lists 80 CERT C rules as also applying to C++ and 23 as not applying.

## Portable syntax requirements

Rules use only the keys and operators listed under `portable_syntax` in `pack.json`; `fix`,
`fix-regex`, `join`, `extract`, `options`, `paths`, and version gates are rejected, and taint rules
are limited to intraprocedural `mode: taint`. YAML anchors, aliases, and merge keys are rejected.
The following engine behaviors were observed with Semgrep 1.178.0 and OpenGrep 1.30.2 and shape
the rules:

- Both engines ignore keys that override a YAML `<<` merge, so merged metadata silently differs
  from what a YAML library reads.
- A parenthesized declaration pattern such as `std::string $L(...);` inside `pattern-inside`
  matches in Semgrep but not OpenGrep; the initializer form `std::string $L = $INIT;` matches every
  initializer spelling in both.
- Neither engine parses `engine(std::time(nullptr))` as a declaration; that spelling is a recorded
  false negative.
- C++ class, struct, and template-specialization patterns do not parse; a C ellipsis parameter is
  indistinguishable from a pattern ellipsis. Such shapes use bounded `pattern-regex` /
  `pattern-not-regex` scoped by an AST pattern.
- `pattern-inside: namespace std { ... }` also encloses later sibling namespaces, so namespace
  scope is established with a bounded balanced-brace expression.
- Java catch-type literals in patterns are ignored and a type metavariable binds only the first
  member of a multi-catch union; types are checked through `metavariable-regex`.
- An unbound metavariable in a negative clause matches anything, including the positive call; negative
  clauses name functions literally.
- Semgrep CE withholds `extra.lines` (`"requires login"`) while OpenGrep returns source text;
  normalization never uses it.
- When given directories, Semgrep's default ignore list drops `test/` and `tests/` paths; the harness
  and the evidence adapter always pass explicit files.
- One invalid rule makes the whole run exit with status 2; parse failures in target files are
  warnings and become coverage gaps.

## Evaluation and evidence

The evaluation runs every rule over every fixture with both engines, scores each rule (true and
false positives, false negatives, known false negatives and positives, expected exclusions),
compares normalized findings across engines (rule, path, line range, interpolated message), checks
that engine-emitted CERT metadata matches the validated rule, and, when the pinned
`targets/appsec-multi-vuln` checkout is present, checks expected findings, expected exclusions, and
known false negatives there. Every finding records the source file hash and whether its line
resolves. Raw stdout/stderr and the result are written with SHA-256 identities to a manifest that
`verify-evaluation` re-checks. Evaluation output is run-owned and is never committed.

## Integration with static-analysis evidence

`job_evidence_collection` runs the pack through its existing adapter boundary:

- `tool-semgrep` loads the Semgrep baseline and the SEI CERT rules; `tool-opengrep` (its own pinned
  image) loads only the SEI CERT rules and is scoped to C, C++, and Java files.
- Before either runs, the job verifies the rule files against `pack.lock.json` and mounts them
  read-only at `/rules-sei-cert`; a mismatch makes the tool `BLOCKED` with an explicit gap.
- Engine errors and skipped targets become coverage gaps (the terminal status is `PARTIAL`), and
  each record keeps the canonical rule ID, its `rule_mapping` (CERT identifier, URL, coverage
  status, CWE), and the cataloged source file hash. The tool identity records the pack's
  `rule_files_sha256` and `tree_sha256`.
- Every applicable run carries the limitation that only the implemented subset is evidenced and
  that an absence of findings is not CERT conformance.

`rules/cpp-cert/` remains the CodeQL and CodeChecker crosswalk; it references pack rule IDs and no
longer contains Semgrep rules.

## Interpreting results

Rule-pack implementation coverage, test-fixture coverage, analyzer execution success, and findings
on multivuln are four different facts, and none of them, alone or together, establishes CERT
conformance of a target. A `SUPPORTED` rule with no findings means the pack saw no syntactic
violation in the unpreprocessed files it parsed; conformance additionally requires the delegated
analyses, the excluded preprocessing and cross-function cases, exception documentation in the
source, and human review of the rules no tool decides.
