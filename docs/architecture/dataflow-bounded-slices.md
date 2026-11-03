# Dataflow-bounded package slices

Status: implemented for the review-package context of lane A finding leads (`package-slice/2`,
`package-neighborhood/3`). The CodeQL export scope (`seed_depth`, see
[`seeded-codeql-neighborhoods.md`](seeded-codeql-neighborhoods.md)) and the retrieval tools are
unchanged.

## Why

A lead package used to show the model the whole function around the lead plus its callers and
callees to `max_call_depth` levels. Call depth is a poor proxy for relevance: most of what it adds
has no data relationship with the finding. LLMxCPG (Lekssays et al., USENIX Security 2025,
arXiv:2507.16585) reduced LLM context by 68–91% without losing detection signal by building the
context from:

1. the source-to-sink taint path;
2. "interacter" identifiers that share lines with the path;
3. a backward slice over the path and its interacters.

This repository applies the same idea to the review package, using the CodeQL `dataflow_path` facts
already in the accepted `graph` index as the path. It adds no new producer and changes no query.

## Which bound applies

| Lead | Bound | What the package carries |
|---|---|---|
| has at least one correlated `dataflow_path` (`DERIVED_FROM` state `bridged` or `partial`) | `dataflow_path` | the path's flows, entries, sinks, guards and ranges; only the `call_site` facts between functions on the path; a source slice |
| has no correlated path | `call_depth` | today's call-depth neighborhood, unchanged, plus a `dataflow_slice` gap `dataflow_path_unavailable` |

The bound is recorded in the stored neighborhood (`bound.kind`, `bound.paths`, `bound.call_depth`),
so each package states why its context has the extent it has. The fallback is never silent: a lead
without a path is a named gap, not a lead with an empty slice.

## The slice (`package-slice/2`)

Code: `src/appsec_review/review/slicing/`.

- `contract.py` defines the record, the strategy protocol and the gap names.
- `anchors.py` turns path facts into anchors and function spans.
- `spans.py` resolves the named function or method that encloses a line, in every catalog language.
- `compose.py` runs the strategies and applies the budget.
- `registry.py` maps configured names to strategy classes.
- `sources.py` is the facade over accepted data that the strategies read.

### Anchors and function spans

Every located line of a path step becomes an **anchor**, with the reason `source`, `sink` or
`path_step`. So does every located guard, range and sanitizer, with the reason `guard`, `range` or
`sanitizer`.

The enclosing function of each anchor comes from `spans.resolve`. It tries four layers, most precise
first. The first layer that answers wins and becomes the span's `span_basis`:

1. **`tree_sitter`:** the accepted tree-sitter `ast_node` rows of the file, at the anchor's file hash.
   The innermost row of a callable node type that contains the anchor gives the extent. If the parse
   is clean and its rows cover the line but no callable contains it, the anchor is outside every
   function, and that answer is final. If the parse has errors near the anchor, or its rows stop
   before the line (the parser's node bound), resolution moves to the next layer and records a
   `slice_function_fallback` gap.
2. **`graph_symbol`:** the function-name lines of accepted graph symbols at the same file hash
   (`GraphContext.function_headers`). The anchor's step symbol is tried first, then the nearest
   preceding header. The extent comes from the language's text rule.
3. **`text`:** the language's header patterns (`spans.LANGUAGES`, keyed by file suffix), searched
   upward from the anchor. The innermost header whose extent contains the anchor wins.
4. **Otherwise:** a `slice_function_unresolved` gap that names the language and the layers tried. No
   window is invented.

Only named functions and methods are spans. Lambdas, closures and blocks belong to the named
function around them. Function-valued bindings (`const f = () => {...}` in JavaScript and TypeScript,
`f := func() {...}` in Go) count as named.

The text rules decide where an extent ends:

| Rule | Languages | Extent |
|---|---|---|
| `indent` | Python | the block below the header |
| `brace` | C, C++, Objective-C, Java, Kotlin, Scala, C#, JavaScript, TypeScript, Go, Rust, Swift, Dart, PHP, shell, PowerShell | from the first body `{` at parenthesis depth 0 to its matching `}`, ignoring braces inside that language's strings, character literals and comments |
| `keyword` | Ruby | from `def` to its matching `end` |

An expression body (`= expr`, `=> expr`) ends with its statement. A header with no body is a
declaration, not a function.

Overlapping extents are merged, and a merged span keeps the basis of its least precise part. An
extent cut at the line bound is marked `truncated`. `tests/fixtures/function_spans/` holds one source
file per language and a recorded tree-sitter golden. `tests/review/test_slicing_spans.py` checks every
layer against them.

Missing input produces these gaps:

- `slice_source_unavailable`: the file's text could not be read.
- `path_step_unlocated`: a step's location is missing, invalid or ambiguous. An ambiguous location
  still anchors.
- `truncated_steps`, `omitted_paths`, `ambiguous_step_location`: inherited from the path fact,
  prefixed with the path identity.

### Strategies (pluggable)

A strategy implements `SliceStrategy`: a `name`, a `precision`, and
`expand(request) -> SliceContribution`. It returns lines only inside the request's function spans,
each tagged with its reasons.

The configured strategies are listed in `appsec-review.toml` under
`[jobs.job_inference_security_review.settings.packages].slice_strategies`. Each name must be in
`registry.STRATEGIES`. Adding a strategy means writing one class, registering one name and adding it
to the TOML list; the composer and record do not change.

| Name | Precision | Input | Adds |
|---|---|---|---|
| `llvm_ir_def_use` | compiler | LLVM IR def-use flow rows (`producer_neighborhood`, producer `llvm-ir`) | backward definitions of values used on path lines; uses of values defined there (interacters) |
| `svf_points_to` | compiler | SVF `points_to_set` / `memory_object` records at anchor lines | allocation and accessor lines of the objects anchors point to (`alias`) |
| `tree_sitter_references` | syntax | tree-sitter `ast_node` rows (`syntax-projection/1`) | same-function references of names on path lines (interacters); earlier assignments to them (backward definitions) |
| `lexical_identifiers` | lexical | verified source text only | identifier matches (interacters), assignment or declaration lines (backward definitions) and the function header; always available |

The precision order is `path` > `compiler` > `syntax` > `lexical`. Every configured strategy runs and
their lines are combined. A line keeps the reasons of every strategy that produced it, and the
highest-precision strategy becomes its `basis`. Higher-precision information is therefore used
wherever it exists, and the lexical strategy fills in only where nothing better covers a function.

A strategy whose input is absent reports `not_applicable`. One with input for only some files reports
`partial`. One that raises is isolated as `failed`. Each of these states carries a named gap. When no
strategy applies, the slice still holds the anchors, plus a gap saying no expansion was possible.

Known limits:

- **`llvm_ir_def_use`:** at `-O0` a stack slot has no source line, so the strategy treats the slot's
  earlier lines as possible stores. It misses stores later in a loop.
- **`svf_points_to`:** reads only objects that have a `memory_object` record. Indirect-call targets are
  checked for completeness but add no lines.
- **`tree_sitter_references`:** matches names within one function, with no control flow and no name
  resolution.
- **`lexical_identifiers`:** has no scoping, shadowing, aliasing or macro awareness. A function whose
  only expansion is lexical is named with `slice_lexical_only`.

### Budget

The line caps are `max_slice_lines` (default 120, 1–2000) and `max_slice_lines_per_function`
(default 40, at most `max_slice_lines`). The per-function cap is applied first, then the total cap.

Lines are dropped in this order:

1. lowest precision first;
2. then farthest from an anchor in the same function;
3. then highest line number.

Anchors are dropped last, and only if the anchors alone exceed the budget. Every dropped line is
counted in `omitted.lines` and named in a `slice_truncated` gap.

### Record

`SliceResult.record()` is validated by `$defs.inference_package_slice` in
`docs/schemas/review-packages.schema.json`. It holds:

- `rule`;
- the sorted path identities;
- the functions (path, file hash, function, first and last line, `truncated`, `span_basis`), each
  with its lines (line number, sorted reasons, basis, precision label);
- the per-strategy outcomes (name, precision, state, lines contributed, gaps);
- `omitted.lines`;
- the sorted, unique gaps.

It stores no source text. The view reads the text when a cell starts and checks it against the
recorded file hash.

## Package, view and manifest

**Assembly** (`review/packages.py`, `assemble-review-packages/12`) reads the slice inputs through
`SliceSources`. `GraphContext.neighborhood` takes the lead's observation identity and picks the bound:

- **`dataflow_path`:** `flows` are the lead's correlated paths, sorted by identity, at most
  `max_paths_per_sink`. `entries` are the paths' source entry points. `sinks`, `guards` and `ranges`
  are limited to the paths' sinks. `callers` and `callees` are only the `call_site` facts whose caller
  and callee both lie on the path: a call made from the lead's function is a callee, and every other
  on-path call is a caller. A call without a symbol is matched by name and gets an `ambiguous` gap.
  `chain` follows the path's functions. The `function` record is unchanged.
- **`call_depth`:** today's breadth-first walk to `max_call_depth`.

The stored neighborhood (`package-neighborhood/3`) gains two fields:

- `bound: {kind, paths, call_depth}`;
- `slice`: a `package-slice/2` record, or `null` under `call_depth`.

Slice gaps become package gaps with producer `dataflow_slice`. Their state is:

| Gap | State |
|---|---|
| `slice_strategy_failed` | `failed` |
| `slice_truncated` | `truncated` |
| not-applicable, unavailable and unresolved gaps | `unavailable` |
| all others | `partial` |

Under `max_package_bytes`, the slice's lowest-precision lines are trimmed before neighborhood rows,
and the trimmed lines are counted in `omitted.lines`.

**View** (`review/package_view.py`, `package-view/4`): under the `dataflow_path` bound, the `S` source
section shows one `slice` row per slice function. Each row contains only the slice's lines, with
`...| n line(s) elided` markers between runs and per-line `reasons`. The lead's line is always shown,
and secret redaction applies as before.

A slice function whose file hash differs from the accepted source falls back to the whole-extent
rendering, with a gap. A slice function in another file is shown only when its function identity
reads back at the recorded hash; otherwise it is a gap. The view's neighborhood summary states the
bound, the number of paths, lines and omitted lines, and each strategy's state.

**Manifest:** `counts.neighborhood_bounds` counts finding-lead packages by bound. Cell receipts carry
no package or view metadata and are unchanged.

**Schemas:** every view is validated against `docs/schemas/review-package-view.schema.json` when it
is built. The manifest is validated against `docs/schemas/review-package-manifest.schema.json` before
it is hashed, and again by `verify_package_manifest`. Both are loaded by `review/schemas.py`. A
violation is an `IntegrityError` that blocks publication; it is never turned into a gap.

### Tests with real producer output

`tests/review/test_slicing_end_to_end.py` runs the whole slice over C files with real producer
output from `tests/fixtures/slicing_end_to_end/`:

- clang-18 LLVM IR, normalized by the real `llvm-ir` producer;
- SVF output from the real alias-analysis job;
- tree-sitter rows from the real syntax normalizer.

All four strategies apply, and the test pins the slice's exact lines, which leave out an unrelated
variable. `record.py` re-records the fixture; it needs Docker and is run by hand.
`tests/review/test_slicing_sources.py` tests the `AcceptedSliceSources` facade against real index
shards, covering shard selection, filtering, caps, caching and every unavailable reason.

### Gap vocabulary

All slice gaps use the producer `dataflow_slice`:

- `dataflow_path_unavailable`
- `slice_strategy_not_applicable`
- `slice_strategy_partial`
- `slice_strategy_failed`
- `slice_lexical_only`
- `slice_truncated`
- `slice_source_unavailable`
- `path_step_unlocated`
- `slice_function_unresolved`
- `slice_function_fallback`
- `slice_out_of_span`
- the inherited path gaps

None of them is evidence that code is safe.

## Not done

- No new CodeQL query and no change to the export's `seed_depth`. The proposed alias-slice layout
  modes in [`graph-alias-slice-layout-modes.md`](graph-alias-slice-layout-modes.md) would be a further,
  higher-precision strategy behind the same registry.
- The 68–91% reduction is the paper's result. This repository has not yet measured its own
  reduction on a live review run (`docs/TODO.md`).
