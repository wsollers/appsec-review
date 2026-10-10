# Review prioritization

Status: implemented in `src/appsec_review/jobs/job_review_prioritization/`. Operator guidance is in
[`../operations/review-prioritization.md`](../operations/review-prioritization.md).

## Purpose and boundary

`job_review_prioritization` extracts structural metrics and security-relevant heuristics from the
reviewed snapshot and combines them with accepted history hotspots into the **LLM Prioritization
Score**. The score orders LLM review attention: a high score means "review first".

- A metric, heuristic signal, or score is never a vulnerability finding and never raises the
  severity of one.
- A low score is not evidence that code is safe. Parser errors, truncated or unparsed files,
  unsupported languages and constructs, unresolved imports, and unavailable producers are named
  gaps, never clean results.
- Target bytes, comments, identifiers, and tool output are data, never instructions. The job runs
  in-process over accepted, hash-verified artifacts and target bytes; it executes nothing.

## Placement and inputs

```text
... -> codeql_analysis -> owasp_control_assessment -> review_prioritization -> security_tagging
```

In Dagster's `wave1_review` the job follows the last retrieval-manifest publishers (CodeQL and OWASP)
and precedes security tagging, which remains the single terminal job. It is also a standalone
Dagster job. It is not in the direct CLI graph, which does not run Tree-sitter.

| Input | Required | Use |
|---|---|---|
| Accepted intake and target catalog | yes | snapshot fingerprint, inventory paths, hashes, languages, components |
| Accepted `job_tree_sitter_ast` handoff | yes | per-file concrete syntax trees (node types, fields, spans, ordinal paths) and per-file parse gaps |
| Target bytes | yes | identifier, comment, and literal text; every read re-verifies the catalog SHA-256 |
| Accepted `job_source_history_analysis` | no | per-file history attention score (hotspot feature) |
| Accepted `job_evidence_collection` Semgrep shard | no | matches of the `review-signals.yml` pack |
| Accepted `job_codeql_analysis` observations | no | path-problem code flows (verified semantic paths) |

Every optional input that is absent, disabled in configuration, or failed is a named gap and makes
the corresponding feature *missing* (see [missing values](#missing-values)), never zero.

## Signal identity and basis

Every signal records its producer (`tree-sitter`, `semgrep`, or `codeql`), rule id, rule-set
version (`appsec-review/review-heuristics/1`, the locked Semgrep pack SHA-256, or the CodeQL query
identity), the source file SHA-256, the exact location (Tree-sitter byte and point spans; Semgrep and
CodeQL line spans), the owning function when there is one, and one basis:

| Basis | Meaning | Producers |
|---|---|---|
| `observed_syntax` | an exact construct is present: annotation, attribute, export, route literal, insecure literal setting, suppression directive, Semgrep structural match | Tree-sitter, Semgrep |
| `heuristic_inference` | a name-based reading: a callee name and receiver path match a known API, or a function's counts cross a threshold | Tree-sitter |
| `verified_semantic_path` | CodeQL's dataflow model connects a source to a sink | CodeQL |

Taint flow is never inferred from co-location, call names, or import reachability. Only CodeQL
path-problem flows produce `verified_semantic_path`, and even those are CodeQL observations, not
confirmed defects.

## Structural complexity

### Functional units

Every named function and every lambda, closure, and function literal is its own unit. A nested
unit's decisions are excluded from its enclosing unit, so nothing is counted twice; the nested unit
records `parent_function`. Units without bodies (prototypes, abstract and interface methods, auto
properties) are not units. Anonymous units take the name of the variable, field, property, or key
they are bound to, or `<callback:CALLEE>` when passed as a call argument (for example
`Register.<callback:mux.HandleFunc>`).

| Language (grammar) | Units |
|---|---|
| C (`c`) | `function_definition` |
| C++ (`cpp`) | `function_definition`, `lambda_expression` |
| Java | `method_declaration`, `constructor_declaration`, `compact_constructor_declaration`, `lambda_expression` |
| C# (`csharp`) | methods, constructors, destructors, operators, conversion operators, accessors with bodies, `local_function_statement`, `lambda_expression`, `anonymous_method_expression` |
| Go | `function_declaration`, `method_declaration`, `func_literal` |
| JavaScript, TypeScript, TSX | function declarations and expressions, generator functions, `arrow_function`, `method_definition` |
| Rust | `function_item`, `closure_expression` |
| PHP | `function_definition`, `method_declaration`, `anonymous_function`, `arrow_function` |

Qualified names join enclosing namespaces, classes, structs, `impl` types, Go method receivers, and
enclosing functions. Python is parsed by Tree-sitter but is outside this batch's scored languages;
its files are reported as `language_not_scored:Python`.

### Cyclomatic complexity (`appsec-review/cyclomatic-complexity/1`)

McCabe's decision count: `1 + decisions` inside the unit.

| Decision | Counted as | Grammar nodes |
|---|---|---|
| conditional branch | +1 per `if` and per `else if` | `if_statement`, `if_expression` (Rust), PHP `else_if_clause` |
| loop | +1 | `for`, range/each/`foreach`/`for…of`, `while`, `do`, Rust `loop` |
| statement `switch` case | +1 per non-default case clause | C/C++ `case_statement` with a value, Java `switch_label` with `case`, C# each `case` in a `switch_section`, JS `switch_case`, Go `expression_case`/`type_case`/`communication_case`, PHP `case_statement` |
| exhaustive multiway expression | arms − 1 | Rust `match`, C# `switch` expression, PHP `match` |
| guard | +1 | Rust match-arm guard, C# `when` (case guard and catch filter) |
| catch | +1 per clause | C++, Java, C#, JS/TS, PHP |
| conditional expression | +1 | `?:` ternaries |
| short-circuit operator | +1 per operator | `&&`, `\|\|`, PHP `and`/`or` |
| null coalescing | +1 per operator | `??`, `??=`, `&&=`, `\|\|=` |
| refutable binding with diverging else | +1 | Rust `let … else` |
| error propagation | see below | Rust `?`, Go `if err != nil { return … }` |

Cross-language decisions:

- **Go error checks and Rust `?`.** Both are explicit error-propagation branches. A Go check is an
  `if` (always one decision); Rust's `?` is an implicit early-return branch with no `if`. Counting
  only the Go form would make equivalent Go and Rust code differ by the number of error sites.
  `count_error_propagation` (default `true`) counts both; `false` removes both (subtracting Go
  `if err != nil` checks whose consequence returns, and not adding `?`). Every unit always
  publishes `cyclomatic_with_error_propagation`, `cyclomatic_without_error_propagation`, and the
  per-form counts, so either convention can be compared. Exceptions (Java, C#, C++, JS, PHP) are
  implicit and are not counted; only `catch` clauses are.
- A multi-value case (`case 1, 2:`) is one clause. `default` is never a decision.
- Exhaustive multiway expressions count `arms − 1` because one arm is the fall-through path,
  matching a `switch` statement that has a `default`.
- `?.` (optional chaining / null-conditional access) is not counted; `??` is.
- `try`, `finally`, `return`, `break`, `continue`, `throw`, and `goto` add no cyclomatic decision.

### Size and density

- **SLOC**: distinct physical lines touched by non-comment leaf tokens. A nested unit's lines also
  count toward its enclosing unit's SLOC.
- **Complexity density**: unit cyclomatic complexity / unit SLOC; for a file, the sum of its units'
  cyclomatic complexity / file SLOC.
- **Average function complexity**, **functions above threshold**, and **share above threshold** are
  published per file and per language for each configured threshold (`cyclomatic_thresholds`,
  default 10 and 15; "above" means strictly greater). The score uses the share above
  `scored_threshold`.

### Cognitive complexity (`appsec-review/cognitive-complexity-approx/1`)

An approximation of the rules in SonarSource's *Cognitive Complexity* white paper. It is not
SonarSource's implementation and is named and versioned as an approximation. It is published
separately from cyclomatic complexity and never substituted for it.

| Rule | Increment |
|---|---|
| structural: `if`, ternary, `switch`/`match`/`select` (once per construct), loops, `catch`, Rust `let … else` | +1 + current nesting |
| hybrid: `else if`, `else` | +1 (no nesting penalty) |
| boolean operator sequences | +1 per run of like operators in token order (`a && b && c` = 1, `a && b \|\| c` = 2) |
| jumps: `goto`, labeled `break`/`continue` | +1 |
| direct recursion | +1 once per unit |
| nesting | structural constructs increase nesting for their bodies; conditions stay at the current level; `try` does not nest |

Deviations from the white paper (also published in the accepted document):

- nested lambdas and closures are scored as their own units starting at nesting 0 instead of
  adding to the enclosing method with a nesting increment;
- recursion is detected only for direct calls whose callee name equals the unit name; indirect
  cycles and overload resolution are not analyzed;
- boolean sequences are flattened through parentheses; negation does not split a sequence;
- preprocessor conditionals and macro bodies are not scored (see below).

`??`, `?.`, and Rust `?` add no cognitive increment.

### Unsupported constructs and parse coverage

| Condition | Result |
|---|---|
| C/C++/C# preprocessor conditionals inside a unit | `unsupported_construct:preprocessor_conditional_not_analyzed:<n>`; the branches are not counted |
| Rust macro invocation whose token tree contains control-flow tokens | `unsupported_construct:macro_control_flow_not_analyzed:<n>` |
| Tree-sitter `ERROR`/`MISSING` nodes | file `parse_errors:<n>` gap; each unit containing one has `parse_error: true` |
| Tree-sitter node or byte bound reached | `ast_truncated` gap; the file is not scored (a partial tree would understate complexity) |
| no accepted Tree-sitter rows (failed scope, unavailable grammar) | `ast_unavailable` gap |
| generated file | `generated_file_not_scored` gap |
| `max_files`, `max_file_bytes`, `max_functions` reached | `file_bound_reached`, `file_byte_bound_reached`, `function_bound_reached` |

## Dependency topology (`appsec-review/import-graph/1`)

Imports are read from the syntax tree and resolved only against the accepted inventory and locally
declared packages or namespaces:

| Language | Import form | Resolution (confidence) |
|---|---|---|
| C/C++ | `#include "x"` | relative to the including file (1.0); else a unique inventory suffix match (0.8); `<x>` is external |
| Java | `import a.b.C`, `a.b.*`, `import static` | the file declaring type `C` in package `a.b` (1.0); wildcard: every file in the package; missing type in a local package is unresolved |
| C# | `using N` | every file declaring namespace `N` (0.9); otherwise external |
| Go | `import "mod/pkg"` | the nearest `go.mod` module path maps to the package directory's non-test files (1.0); otherwise external |
| JS/TS | `import`, `export … from`, `require("…")`, `import("…")` | relative specifiers with extension and `index` probing (1.0); bare specifiers are external; `@/`, `~/`, `#` aliases are unresolved (tsconfig `paths` are not evaluated) |
| Rust | `mod x;`, `use crate::…`/`self::…`/`super::…` | module files `x.rs`/`x/mod.rs` under the crate `src` (1.0); other roots are external crates |
| PHP | `require`/`include` (`_once`), `use A\B\C` | `__DIR__`/`dirname(__FILE__)` concatenations (1.0); plain relative literals are guessed relative to the file (0.8); `use` resolves to the file declaring the class in that namespace (1.0) |

Non-literal `require`, `import()`, and `include` are `dynamic` records. Local-looking specifiers
that do not resolve are `unresolved` records. Both are named gaps per file, and the file's coupling
is flagged `coupling_lower_bound`.

Coupling uses Robert Martin's package metrics over module nodes: a Go package directory, a C#
namespace, otherwise a file. Only resolved edges at or above `min_edge_confidence` (default 0.8)
count. For a module, **Ce** (efferent) is the number of other modules it depends on, **Ca**
(afferent) is the number of other modules that depend on it, and **instability** is
`Ce / (Ca + Ce)`, which is `null` (undefined, not zero) when `Ca + Ce = 0`. Files inherit their
module's values. The same metrics are published between catalog components. External dependencies
are counted separately and are not part of Ce. Implicit same-package references (Java, Go, C#) are
not import edges and are not counted.

## Heuristic signals (`appsec-review/review-heuristics/1`)

Call rules match a callee's simple name plus its receiver path. A receiver-qualified call matches
only if a configured qualifier names a segment of the receiver (`exec.Command`, `Runtime.getRuntime().exec`).
An unqualified call matches only when the rule allows bare calls, optionally only if the file
imports a module (for example, bare `exec(...)` only in a file that imports `child_process`). Only
call, annotation, assignment, and declaration nodes are inspected, so comments and string literals
never match. The fixture verifies these decoys: a string containing `Runtime.getRuntime().exec(cmd)`,
a comment mentioning `eval(`, a regular-expression `.exec(...)`, a local Go method named `Command`,
and C++ `std::cout <<` stream insertion.

| Category | Surfaces and examples | Basis |
|---|---|---|
| `public_api` | routes and controllers (`@GetMapping`, `[HttpGet]`, `app.post("/x", …)`, `mux.HandleFunc("/x", …)`, actix attributes), schemas and serializers (`z.object`, `@JsonProperty`, `[DataContract]`, `#[derive(Serialize)]`, Go `json:` struct tags), exports (ESM/CommonJS, Go exported names outside `main`, Rust `pub`, public Java/C#/PHP methods, C/C++ header declarations) | observed |
| `ingress` | route handler units, request-binding annotations and extractors (`@RequestBody`, `[FromBody]`, `web::Json<…>`), request accessors (`req.body`, `r.Body`, `Request.Query`, PHP superglobals), C `recv`/`fgets`/`scanf`/`getenv` | observed / heuristic |
| `validator`, `parser`, `middleware` | `validate*`/`sanitize*`, `htmlspecialchars`, `@Valid`; `JSON.parse`, `json.Unmarshal`, `serde_json::from_str`, `readValue`; `app.use`, `app.UseAuthorization`, Go `func(http.Handler) http.Handler` | heuristic / observed |
| `sink` | `command_exec`, `sql`, `deserialization`, `code_eval`, `file_path`, `outbound_request`, `memory` (C/C++ unbounded copies), `html_output`, `redirect` | heuristic |
| `sensitive_wrapper` | a project function that calls into an external library surface: `xml`, `image`, `crypto`, `regex` (records whether the pattern is a literal), `ffi` (Rust `extern` blocks and calls into them, Java `native`, `[DllImport]`, cgo, `dlopen`), `deserialization` | heuristic / observed |
| `privilege_shift` | `impersonation` (`setuid`, `ImpersonateLoggedOnUser`, `WindowsIdentity.RunImpersonated`), `access_control_bypass` (`@PermitAll`, `[AllowAnonymous]`, `permitAll()`, `csrf().disable()`), `insecure_verification` (`InsecureSkipVerify: true`, `rejectUnauthorized: false`, certificate callbacks returning `true`, `CURLOPT_SSL_VERIFYPEER` off, `SSL_VERIFY_NONE`, `danger_accept_invalid_certs(true)`), `privileged_action`, `cross_origin` | observed / heuristic |
| `state_mutation` | one signal per unit whose transaction, database-write, and filesystem-write operations reach `state_mutation_min_operations` and span at least two kinds (or begin two transactions); counts are published per unit | heuristic |
| `custom_parsing` | one signal per unit whose slicing/indexing, bitwise operations (excluding C++ stream `<<`/`>>`), and manual (de)serialization calls (`from_be_bytes`, `binary.BigEndian`, `ntohl`, `ByteBuffer.getInt`, …) reach `custom_parsing_min_operations` and `custom_parsing_min_density` per SLOC | heuristic |

### Suppression directives

Suppressions are counted per file and per unit (a directive inside a unit, or a leading
annotation/comment on the line before it). Density is suppressions per SLOC. The category is the
directive's own kind, escalated to `security` when the suppressed rule names a security check
(`secur`, `cwe`, `gosec`, `G104`, `CA2100`/`CA3xxx`/`CA5xxx`, `SCS…`, `taint`, `injection`, `xss`, …).

| Language | compiler | lint | type | security |
|---|---|---|---|---|
| C/C++ | `#pragma warning(disable…)`, `#pragma GCC/clang diagnostic ignored` | `NOLINT`, `NOLINTNEXTLINE`, `NOLINTBEGIN`, `cppcheck-suppress` | | `coverity[…]`, `flawfinder: ignore`, security-named `NOLINT(…)` |
| Java | `@SuppressWarnings` with javac keys only | other `@SuppressWarnings`, `@SuppressFBWarnings`, `NOSONAR`, `//noinspection`, `CHECKSTYLE:OFF` | | security-named values |
| C# | `#pragma warning disable CS…` | `#pragma` analyzer codes, `[SuppressMessage]`, `ReSharper disable` | `#nullable disable` | `[SuppressMessage("Security", …)]`, `CA2100`/`CA5xxx`/`SCS…` |
| Go | `//go:nocheckptr`, `//go:linkname` | `//nolint`, `//lint:ignore` | | `#nosec`, `//nolint:gosec` |
| JS/TS | | `eslint-disable[-line|-next-line]`, `tslint:disable`, `istanbul ignore` | `@ts-ignore`, `@ts-expect-error`, `@ts-nocheck`, `as any` | security-plugin rule names |
| Rust | `#[allow(…)]` rustc lints, `unsafe` blocks | `#[allow(clippy::…)]` | | `#[allow(unsafe_code)]` |
| PHP | `@` error-control operator | `phpcs:ignore`, `@codingStandardsIgnore…` | `@psalm-suppress`, `@phpstan-ignore…` | `@psalm-suppress Tainted…` |
| all | | | | `nosemgrep`, `lgtm[…]`, `codeql[…]`, `deepcode ignore` |

### Semgrep pattern pack

`rules/semgrep/review-signals.yml` (hash-locked in `rules/semgrep/rules.lock.json`) runs in the
existing evidence-collection Semgrep execution. Its rule ids are
`appsec-review.review-signal.<category>.<name>`. It covers what is awkward to express as a node
match: trust-all `checkServerTrusted`, `HostnameVerifier` returning `true`, Spring
`anyRequest().permitAll()` and disabled CSRF, Go/Node/PHP disabled TLS verification, SQL built by
string concatenation (Java, Go, PHP), PHP request data passed to `unserialize`, C# shell processes
with concatenated arguments, unhardened `DocumentBuilderFactory`, and libxml2 `XML_PARSE_NOENT`.
Matches are recorded with producer `semgrep` and basis `observed_syntax`, attributed to the
innermost unit by line. An unplanned, failed, or absent Semgrep run is the
`semgrep_review_signals_unavailable` gap.

### CodeQL source-to-sink paths

For each accepted CodeQL path-problem observation, each SARIF code flow is a candidate path from its
first to its last step. The job keeps the shortest flow per (rule, source location, sink location)
and attributes source and sink to their innermost units. The CodeQL SARIF normalizer
(`appsec-review/codeql-sarif-normalizer/2`) records each step's `code_flow` index so alternative
flows are not concatenated; observations normalized without it are reported as
`semantic_path_flow_boundaries_unavailable`. A language whose CodeQL scopes did not succeed, a
language CodeQL does not cover (PHP), and an absent CodeQL handoff make `semantic_path` missing for
those files.

## LLM Prioritization Score (`appsec-review/llm-prioritization-score/1`)

Files and functions are scored separately with the same weights.

| Feature | File value | Function value | Why it is included | Default weight |
|---|---|---|---|---|
| `cyclomatic` | max unit CC | unit CC | more paths to reason about and test | 2 |
| `cognitive` | max unit cognitive | unit cognitive | harder to read, so defects hide | 2 |
| `complexity_density` | sum CC / SLOC | CC / SLOC | branching concentrated in little code | 1 |
| `share_above_threshold` | share of units with CC > `scored_threshold` | n/a | how much of a file is hard code | 1 |
| `afferent_coupling` | module Ca | inherited | many dependents widen the blast radius of a defect | 1 |
| `efferent_coupling` | module Ce | inherited | many dependencies widen the trusted surface | 1 |
| `instability` | Ce/(Ca+Ce) | inherited | published for analysis | 0 |
| `suppression_density` | suppressions / SLOC | unit suppressions / SLOC | silenced checks mark known friction | 1 |
| `ingress` | count | count | untrusted input enters here | 2 |
| `sink` | count | count | dangerous operations happen here | 2 |
| `privilege_shift` | count | count | authority changes or checks are relaxed | 3 |
| `sensitive_wrapper` | count | count | thin code over risky library surfaces | 1 |
| `state_mutation` | count | count | multi-step mutations invite consistency and TOCTOU bugs | 1 |
| `custom_parsing` | count | count | hand-written decoders are a classic memory and logic risk | 1 |
| `public_api` | count | count | contract surface reachable by other code or clients | 1 |
| `parser`, `middleware` | count | count | input interpretation and request pipeline | 1 |
| `validator` | count | count | published; validation presence is not risk | 0 |
| `semantic_path` | CodeQL paths with an end in the file | paths with an end in the unit | a modeled source reaches a sink | 3 |
| `history_hotspot` | accepted history attention score | inherited | recent and repeated change correlates with defects | 2 |

Signal counts include both Tree-sitter and Semgrep matches; counts are complete even when stored
signal records are truncated by `max_signals_per_file`.

**Normalization.** Each feature becomes a zero-anchored mid-rank percentile
`(count below + 0.5 × count equal) / population` within its population, except that a value of 0
maps to 0 so that the absence of a signal never earns rank. The population is every scored item of
the same scope (`normalization_population = "run"`) or of the same scope and language (`"language"`,
useful when comparing languages with different idioms).

<a id="missing-values"></a>**Missing values.** A feature is missing (`null`) when its producer did not
cover the item: no CodeQL coverage for the language, no accepted history or a partial history
binding for an absent file, no functions in a file (complexity), or undefined instability. Missing
features are excluded and the remaining weights are renormalized:
`score = Σ wᵢ·pᵢ / Σ wᵢ` over available features. `feature_coverage` (the available share of
configured weight) and `missing_features` are published with every item. Zero is never imputed for
a missing value, because that would rank uncovered languages (for example PHP without CodeQL)
systematically lower. With exact history binding, a file without in-window changes has
`history_hotspot = 0`, an observed value.

**Tie-breaking.** Higher score, then more boundary signals (`ingress + sink + privilege_shift +
semantic_path`), then higher feature coverage, then path, start line, and name.

**Selection.** The top `ceil(file_top_fraction × files)` files and `ceil(function_top_fraction ×
functions)` functions are indexed, or exactly `*_top_count` items when it is positive, capped by
`max_indexed_items`. The complete ranking of every item is kept in the run artifact.

## Outputs and index schema

Attempt artifacts (all hash-identified in the handoff):

- `syntax-facts.json`: per-file metrics, units, signals, suppressions, imports, and declarations;
  per-language summaries.
- `dependency-graph.json`: every import outcome, edges, module and component Ca/Ce/instability.
- `semantic-evidence.json`: Semgrep matches and shortest CodeQL paths with owning units.
- `priority.json`: every ranked file and function with its full feature vector, percentiles,
  missing features, coverage, evidence ids, and rank.
- `review-prioritization.json`: the accepted document (identities, sources, settings, summaries,
  top items, gaps, and the index manifest).

Retrieval index `priority`, shard `review-prioritization`:

| Entity kind | Native id | Payload | Location |
|---|---|---|---|
| `priority_item` | `file:<path>` or `function:<path>#<qualified>@<line>:<column>` | scope, rank, score, `features`, `percentiles`, `missing_features`, `feature_coverage`, `boundary_total`, `evidence` (bounded by `max_evidence_links_per_item`), `evidence_truncated`, unit metrics, weights, population, score identity | functions: exact Tree-sitter bytes and points; files: whole file |
| `review_signal` | signal, suppression, or path id | the signal record: producer, rule id and version, basis, category, surface, owning function, detail | Tree-sitter exact span; Semgrep line span; CodeQL sink line span |

Relations: `priority_item -DERIVED_FROM-> review_signal`, `file item -CONTAINS-> function item`, and
`file item -DEPENDS_ON-> file item` for resolved imports between indexed files (non-exact with an
ambiguity note below confidence 1.0). Coverage areas: `complexity`, `dependency-graph`,
`semgrep-review-signals`, `codeql-semantic-paths`, `history-hotspots`, and `prioritization`.

## Gap taxonomy

| Gap | Meaning |
|---|---|
| `<path>: parse_errors:<n>` | the file has Tree-sitter error or missing nodes; affected units are flagged |
| `<path>: ast_truncated (…)`, `ast_unavailable (…)` | no complete syntax tree; the file is not scored |
| `<path>: unsupported_construct:<kind>:<n>` | control flow inside preprocessor conditionals or macros is not counted |
| `<path>: unresolved_or_dynamic_imports: …` | coupling is a lower bound |
| `<path>: signals_truncated:<n>`, `function_bound_reached`, `file_bound_reached`, `import_record_bound_reached` | configured bounds reached |
| `language_not_scored:<language> (<n> files)` | inventory language outside this batch |
| `semgrep_review_signals_unavailable: …`, `semgrep_review_signals_disabled` | no Semgrep pattern evidence |
| `semantic_paths_unavailable: …`, `semantic_paths_partial: …`, `semantic_paths_disabled`, `semantic_paths_truncated: …` | CodeQL path evidence missing or incomplete |
| `history_hotspots_unavailable: …`, `history_hotspots_disabled`, `history: <gap>` | history feature missing or partial |

Changed accepted target bytes, Tree-sitter rows that disagree with the catalog hash, and corrupt or
escaping artifacts fail the job instead of producing a gap.

## Approximations and limits

- Cognitive complexity is an approximation (see deviations above).
- Call, wrapper, sink, ingress, parser, validator, and middleware rules are name-based heuristics
  without symbol resolution; aliased imports and wrappers of wrappers are not followed.
- Import resolution does not evaluate build systems, include search paths, tsconfig `paths`,
  Composer autoload maps, Cargo workspaces beyond `src`, or Java/C# implicit same-package use.
- Public API "changes" are not diffed: contract declarations are combined with the history hotspot
  feature rather than compared between revisions.
- Function-level history is not available; functions inherit their file's hotspot score.
- Source-to-sink paths exist only where CodeQL ran a path-problem query that succeeded; PHP has no
  CodeQL extractor.
