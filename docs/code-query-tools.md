# Structural code-query tools for model jobs (brief U)

Model jobs used to page raw CPG JSON with `input_grep`/`input_jq`. They now query a deterministic,
hash-verified **code index** instead. Decision record: [ADR-0032](decisions/ADR-0032-structural-query-tools.md).

## Pipeline

1. `02-treesitter-ast` (pinned container, `treesitter_ast_job.py`) produces the `appsec-review/treesitter-ast/1`
   document: per-file symbols, call sites, imports. It is a deterministic worker; the tree-sitter script is mounted
   content-addressed from `data/tooling/` (AGENTS.md rule).
2. `02-code-index` (`code_index_job.py`, deterministic Python) builds `code-index.sqlite`
   (schema `appsec-review/code-index/1`) from the CPG records file, the tree-sitter AST and the export tables.
   It depends on `02-code-property-graph`, `02-treesitter-ast` and binary triage. The capabilities it could build
   (`cpg`, `treesitter`, `exports`) are recorded in `code-index.json`.
3. A model job is granted `code_*` tools only when **all** hold: its tooling profile lists `query tool: <name>`;
   the tunable family (`code_query_*_enabled`) is on; the job pins an accepted
   `02-code-index/attempts/<a>/code-index.json`; and that index's capabilities can answer the tool.
4. `input_mcp.py` opens the index read-only after re-verifying its hash. `--allowedTools` and the prompt's
   **Tool Guides** section are built from the same granted list (`tool_guides.render`), so a tool is never granted
   without its guide or described without being granted.

## Tools

`code_symbol`, `code_callers`, `code_callees`, `code_locate`, `code_type_info`, `code_file_outline`, `code_search`,
`code_calls_to`, `code_path`, `code_address_taken`, `code_overrides`, `code_exports`.

Every result carries `complete`, `reasons`, `gaps`, `truncated`, `source` (cpg / treesitter / exports) and a locator
(`path:line`). Unresolved calls, an unknown class hierarchy or a truncated answer make `complete=false`; the guides
tell the model never to conclude "no callers" or "unreachable" from an incomplete answer. Results are untrusted data.
`code_path` reuses `reachability.CallGraph`, so it cannot disagree with the reachability stages.

## Who gets the tools

- `hypothesis-hunt-static` and `claim-review-static` profiles (hunters and claim reviewers; attack-chain cells use
  claim-review-static, so they already have the tools).
- `threat-workbench-static-evidence`: eight query actions. Effective only if the index was accepted before stage 03.
- Persona task prompts (both hunters, claim review) carry a short "Structural queries" paragraph; the details live in
  the tool guides so they cannot drift from the granted set.
- The same profiles also list the MITRE lookup tools (`mitre_technique`, `mitre_capec`, `mitre_cwe`, ADR-0034), which
  use the same grant path (including indexed mode for an inline-sized job) but need no index pin; see
  [mitre-feed.md](mitre-feed.md#lookup-tools-adr-0034-item-5).

## Tunables and metrics

`code_query_*` tunables (all enabled by default) set per-family switches and result limits. `input_mcp.py --usage-file`
records each call; `orchestrator/retrieval-report.py` prints a code-tool block (calls, incomplete answers, truncations
per tool) beside the "files read" line.

`code_query_force_indexed_mode` (flag, default on): a job granted code or MITRE lookup tools runs in indexed mode
(inventory plus lookup tools) even when its inputs would fit inline. Turn it off to compare runs (for example freeciv21
with and without the query tools): a small job then stays inline with no tools and its grants are dropped, so the
prompt's tool guides, the server's tool list and `--allowedTools` still agree. Jobs whose inputs exceed the inline
limit keep their grants either way.

## Dependency reachability

`06-cve-reachability` binds the accepted `02-treesitter-ast` output of the same source generation as its tree-sitter
hint input. A manually supplied `<run>/inputs/dependency-reachability/treesitter-ast.json` still wins. Tree-sitter stays
a hint engine (call sites matched by name, never `reachable` on its own). There is no job-graph edge from 02-treesitter-ast
to 06: if the job has not been accepted when 06 binds, 06 records the usual `engine-input-absent` gap.

## Deferred

- **Sealed code-intel sidecar.** Keeping build containers alive with their language servers (jdtls, gopls, clangd) and
  querying them at model time. Deferred: the sidecar's answers depend on server state and build scripts, so replay would
  not be deterministic; the build-script risk (a project's build running during analysis) needs a sandbox design first.
  Replay rule if built: every answer is recorded in the run and hash-bound; a replayed job reads the recording, never the
  live server. Evidence that would justify building it: reviewed runs where `complete=false` on `code_callers`/`code_type_info`
  is the main reason a lead is left unresolved for Java/Go/C#.
- **Query-time CodeQL.** Same determinism and cost concerns; the existing CodeQL SARIF and reachability tables stay the
  source. Revisit after the index has been used on freeciv21 and doom3-bfg.
- **Lead-context (brief V):** attach SARIF code flows and index context to leads; starts after this merges.
