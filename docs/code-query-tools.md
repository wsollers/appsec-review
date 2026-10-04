# Structural code-query tools for model jobs (brief U)

Model jobs used to page raw CPG JSON with `input_grep`/`input_jq`. They now query a deterministic,
hash-verified **code index** instead. Decision record: [ADR-0032](decisions/ADR-0032-structural-query-tools.md).

## Pipeline

1. `02-treesitter-ast` (pinned container, `treesitter_ast_job.py`) produces the `appsec-review/treesitter-ast/1`
   document: per-file symbols, call sites, imports. It is a deterministic worker; the tree-sitter script is mounted
   content-addressed from `data/tooling/` (AGENTS.md rule).
2. `02-code-index` (`code_index_job.py`, deterministic Python) builds `code-index.sqlite`
   (schema `appsec-review/code-index/1`) from the CPG records file, the tree-sitter AST and the export tables.
   It depends on `02-code-property-graph`, `02-treesitter-ast` and binary triage, and since P09 (`55a173e`) takes
   optional edges from `02-ir-facts` and `02-debug-symbol-index` (a skip binds nothing and is no gap); their records
   fill the `ir_functions` and `debug_symbols` tables (FTS names included). The Joern exporter
   (`pipeline/joern_export_records.sc`) exports only `isExternal(false)` methods and type declarations, plus
   `INHERITS` type rows and method-reference rows (P07, P10); these fill `type_edges` and `address_taken`.
   Location-less METHOD/TYPE_DECL rows from older exports are an `external-stub` observation and deduplicated
   macro-expansion nodes a `duplicate` observation, neither a gap (P07, P08); a location-less CALL stays a gap.
   `cpg-exporter:no-inheritance-edges` is emitted only when no edge was exported for a language with inheritance,
   `cpg-exporter:no-method-reference-nodes` only when there are no method references. The capabilities it could
   build (`cpg`, `treesitter`, `exports`, `type_edges`, `method_references`, `ir_facts`, `debug_symbols`) are recorded
   in `code-index.json`; the exporter change is not yet compiled by a host run.
3. A model job is granted `code_*` tools only when **all** hold: its tooling profile lists `query tool: <name>`;
   the tunable family (`code_query_*_enabled`) is on; the job pins an accepted
   `02-code-index/attempts/<a>/code-index.json`; and that index's capabilities can answer the tool.
4. `input_mcp.py` opens the index read-only after re-verifying its hash. `--allowedTools` and the prompt's
   **Tool Guides** section are built from the same granted list (`tool_guides.render`), so a tool is never granted
   without its guide or described without being granted.

## Tools

`code_symbol`, `code_callers`, `code_callees`, `code_locate`, `code_type_info`, `code_file_outline`, `code_search`,
`code_calls_to`, `code_path`, `code_address_taken`, `code_overrides`, `code_exports`; and the language-server family
`code_definition`, `code_references`, `code_hover`, `code_call_hierarchy` (below).

Every result carries `complete`, `reasons`, `gaps`, `truncated`, `source` (cpg / treesitter / exports) and a locator
(`path:line`). Unresolved calls, an unknown class hierarchy or a truncated answer make `complete=false`; the guides
tell the model never to conclude "no callers" or "unreachable" from an incomplete answer. Results are untrusted data.
`code_path` reuses `reachability.CallGraph`, so it cannot disagree with the reachability stages.

## Who gets the tools

- `hypothesis-hunt-static` and `claim-review-static` profiles (hunters and claim reviewers; attack-chain cells use
  claim-review-static, so they already have the tools).
- `threat-workbench-static-evidence`: eight query actions. Effective only if the index was accepted before stage 03.
- `component-evidence-router` (01), `threat-model-static-evidence` (03) and `owasp-control-validator` (04 validator
  cells): the twelve tools of `hypothesis-hunt-static`. `02-code-index` is a required graph dependency of 01, 03 and
  04-asvs-masvs; 01 and the validator dispatch pin the accepted `code-index.json` (`claude_cli_invoker.code_index_pin`).
  No accepted index: the job runs on the evidence lookups and records a coverage gap. The 03 core is deterministic;
  its workbench cells get their tools through `threat-workbench-static-evidence` and the supporting-evidence menu.
- A profile that lists any `query tool:` line is served the lookup tools at any input size; below the inline limit
  its inputs stay inlined as well. A profile that lists none gets tools only above the inline limit.
- `max_tool_calls_per_cell` caps lookup calls per invocation (all repair rounds). Past it every call returns a fixed
  `budget_exhausted` error and the invoker writes a `coverage gap: tool-call budget exhausted ...` limitation.
- Persona task prompts (both hunters, claim review) carry a short "Structural queries" paragraph; the details live in
  the tool guides so they cannot drift from the granted set.

## Tunables and metrics

`code_query_*` tunables (all enabled by default) set per-family switches and result limits. `input_mcp.py --usage-file`
records each call; `orchestrator/retrieval-report.py` prints a code-tool block (calls, incomplete answers, truncations
per tool) beside the "files read" line.

After a run (no model, Docker or network; reads only the run tree):

```
python3 orchestrator/retrieval-report.py <run> --summary [--json] [--compare <other run>]
python3 orchestrator/retrieval-report.py <run> --feedback [--json]
python3 orchestrator/retrieval-report.py <run> --check     # exit 1 when there is a finding
python3 orchestrator/retrieval-report.py <run> --diagnose [--job <job>] [--json]
python3 orchestrator/run-status.py <run> --tooling          # the same findings after the job lines; exit stays 0
```

`--summary`: the share of tool-served invocations that made a lookup call (overall and per job); per family
(`input`, `evidence`, `code_structural`, `code_lsp`) the share of granted invocations that used it, calls and
empty/error/truncation rates; granted-but-unused tools per job; invocations that hit `max_tool_calls_per_cell`;
citation backing per job. The grant comes from `llm-transcripts/<job>/<attempt>/tool-grant.json` (written by the
invoker beside `tool-usage.json`; older runs: the `lookup tools granted:` limitation). `--compare` prints this run
minus the other. `--check` thresholds (constants at the top of the script): a granted family never called; empty
rate > 50% for a tool with >= 10 calls; error rate > 10% for a tool with >= 5 calls; any cap exhaustion; citation
backing < 80%; lsp granted and every lsp call answered server failed / not ready; > 30% of feedback blocks with
`coverage_confidence: low`; a run with no tool-served invocation is reported as a gap, not a pass.
Citation backing counts a cited path as tool-backed (read or surfaced by a call) or pinned-backed (one of the
invocation's `readable_inputs`, found through the persona request beside its output), compared in one repo-relative
form. `--diagnose` explains the numbers: tool errors grouped by cause with example arguments, `evidence_read` path
shapes, the 02-lsp-xref servers and gaps with `data/lsp/` start failures and recorded GAP answers, and per job up to
10 cited paths no tool fetched, classified normalization-mismatch, pinned-inline, present-in-target-but-not-read or
not-in-target.

A tool-granted model job may add an optional envelope-level `tooling_feedback` block
(`schemas/common/tooling-feedback.schema.json`: useful and unhelpful tools, up to five `wanted` items, coverage
confidence, what it would change). The invoker strips it before the result is validated or derived, writes it to
`llm-transcripts/<job>/<attempt>/tooling-feedback.json` (always copied, like `tool-usage.json`) and drops an invalid
or oversized block with a `tooling feedback dropped:` limitation. It never feeds evidence, findings, routing or a
fingerprint. The request (`pipeline/prompt-fragments/tooling-feedback.md`) is appended to the dispatched prompt
after the persona cache key is computed, so existing cache keys are unchanged. `--feedback` groups the blocks per
job beside the measured numbers for the same job and tool; model text is printed as data, truncated.

`code_query_force_indexed_mode` (flag, default on): a job whose profile grants tools gets the lookup tools even when
its inputs fit inline (the inputs stay inlined too). Turn it off to compare runs (for example freeciv21 with and
without the query tools): a small job then stays inline with no tools and its grant is dropped, so the prompt's tool
guides, the server's tool list and `--allowedTools` still agree. Jobs whose inputs exceed the inline limit keep their
grant either way.

## Dependency reachability

`06-cve-reachability` binds the accepted `02-treesitter-ast` output of the same source generation as its tree-sitter
hint input. A manually supplied `<run>/inputs/dependency-reachability/treesitter-ast.json` still wins. Tree-sitter stays
a hint engine (call sites matched by name, never `reachable` on its own). There is no job-graph edge from 02-treesitter-ast
to 06: if the job has not been accepted when 06 binds, 06 records the usual `engine-input-absent` gap.

## Language servers (recorded-sidecar replay, built 2026-10-04)

The deferred "sealed code-intel sidecar" is built on the replay rule it named: every answer is recorded in the run and
hash-bound, and a replay reads the recording, never the live server.

1. Which servers are needed: an accepted `02-language-census` (`language-census.json`, its `languages_needing_server`)
   when the run has one, read as an optional input; otherwise the languages of the accepted code index's `files`.
2. `lsp_service.py` is the broker. A server is ready once its build input exists: C/C++ the accepted `02-native-build`
   unit's adapted `compile_commands.json` (one build variant per unit), Java `pom.xml`/Gradle, Go `go.mod`, Rust
   `Cargo.toml`, TS/JS `tsconfig.json`/`jsconfig.json`/`package.json`, Python and PHP nothing; otherwise the gap is
   `lsp-not-ready: no compile_commands` (or the missing marker). The first query for (run, server, variant) creates
   `runs/<run>/data/lsp/locks/<server>-<variant>.lock` with `mkdir`, writes `owner.json` (pid, container id, start time,
   loopback port, token) and spawns a daemon that starts the server in its buildenv image through
   `container_execution.build_docker_argv` (network none, checkout and build inputs read-only, one run-owned scratch dir;
   `--interactive` added for stdio). Concurrent first queries wait for `ready`, so one container starts. A lock whose
   owner pid or container is gone is renamed aside (one winner) with a record in `data/lsp/recoveries/`. The daemon
   stops after `idle_seconds` without a query or on `lsp_service.py teardown --run-id` (run end). A start or initialize
   failure is recorded in `data/lsp/failures/`; it is retried once, then every query is an `lsp-server-failed` gap.
3. No project code runs: rust-analyzer build scripts, proc macros and check-on-save off; gopls with
   `GOFLAGS=-mod=readonly GOPROXY=off GOTOOLCHAIN=local`; jdtls with Maven/Gradle import and autobuild off (recorded as
   the `lsp-limit` `jdtls-build-import-disabled`: dependency types are unresolved); clangd with `--compile-commands-dir`,
   no background index, no `--query-driver`, no clang-tidy; typescript-language-server without automatic type
   acquisition. C# is withheld: csharp-ls loads projects through MSBuild, which runs project targets.
4. Every live answer is written once to `data/lsp/recordings/<key>.json` (method, params, response, server name and
   version, image id and digest, build variant and build-input hash, source snapshot, time), sealed by `record_sha256`.
   The key hashes the query and the server identity, so the same query on the same inputs replays the same answer; a
   recording that fails its hash is an `lsp-recording-invalid` gap.
5. `02-lsp-xref` (`lsp_xref_job.py`; depends on `02-code-index` and optionally `02-native-build`; an optional edge
   makes it upstream of `07-hypothesis-discovery`, so the menu can pin it for hunters and claim reviewers) asks
   definition, references and incoming/outgoing calls for every indexed function, bounded by `max_queries` (over it:
   `lsp-budget-exceeded`), and writes `lsp-xref.sqlite` (`lsp_functions`, `lsp_definitions`, `lsp_references`,
   `lsp_calls`, `lsp_servers`, `lsp_files`) beside a hash-bound `lsp-xref.json`. Validation rebuilds the database from
   the recordings alone. Gaps: not ready, no server, failed, unresolved includes (clangd `pp_file_not_found`), names
   not located, budget.
6. Model access: `code_definition`, `code_references`, `code_hover`, `code_call_hierarchy` answer from the precomputed
   rows first, then from the broker (recorded, then live). They are granted through `code_query_grant` when the profile
   lists them, `code_query_lsp_enabled` is on and the job's inputs pin an accepted `02-lsp-xref/.../lsp-xref.json`
   (`supporting_evidence_menu` pins it for hunters and claim reviewers). `code_query_lsp_calls_max` bounds the calls per
   cell. Profiles: `hypothesis-hunt-static`, `claim-review-static`, `owasp-participation-static`. Guide:
   `tool-guides/code_lsp.md`.

Not done here: no graph edge from `02-language-census` yet (that job lands on its own branch; add it as an optional
dependency of `02-lsp-xref` when both are merged; until then the census is read if it was accepted first),
`04-owasp-participation` does not pin `lsp-xref.json` yet (its owner adds it to the cell inputs), the run
end does not call `lsp_service.py teardown` yet (the idle timeout stops servers meanwhile), and the buildenv images'
servers are unqualified with these presets on a real target.

## Deferred

- **Query-time CodeQL.** Same determinism and cost concerns; the existing CodeQL SARIF and reachability tables stay the
  source. Revisit after the index has been used on freeciv21 and doom3-bfg.
- **Lead-context (brief V):** attach SARIF code flows and index context to leads; starts after this merges.
