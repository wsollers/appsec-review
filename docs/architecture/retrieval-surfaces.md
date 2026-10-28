# Retrieval surfaces: tools, MCP, review cells, and skills

Four things in this repository are easy to confuse because older documents use "MCP" for all of
them. They are different, and this page is the one place that says which is which.

| Term | What it is | Who uses it |
|---|---|---|
| **Retrieval tool** | A typed, bounded read of accepted index shards, for example `search`, `find`, `read_excerpt`, `trace`, `resolve_evidence`, `query_observations`, `query_build_security`, `query_code_graph`. The names and parameter schemas are in `docs/schemas/retrieval-mcp-tools.json` and `src/appsec_review/mcp/schema.py`. | Every consumer below. |
| **Retrieval core** | `appsec_review.retrieval`: the code that opens the accepted shards read-only and answers a tool call. | Jobs, review cells, and the MCP adapter. |
| **MCP adapter** | `appsec_review.mcp` and the `appsec-review-mcp` command: a read-only JSON-RPC (MCP) stdio server over the retrieval core, pinned to one accepted run. | External clients and the OWASP workbench. **Not** review cells. |
| **Runtime skill** | A bounded guidance file under `pipeline/skills/<name>/SKILL.md`, registered for one job and hash-pinned with its guidance. | Configured model workers, including the review roles' selected evidence-checking procedures and the `binary-evidence` skill (attached to review cells only when the run has a binary shard). It grants no tools. |

## How each consumer reaches the data

```text
accepted index shards (read-only, hash-verified)
        |
  retrieval core  (appsec_review.retrieval)
     |-- jobs call it directly (indexing, prioritization, package assembly, scoring, ...)
     |-- review cells: the application runs each model "retrieve" request in-process
     '-- MCP adapter: stdio server for external clients
```

- **Review cells (red, blue, verifier, hunter) never use MCP and have no tools.** The Claude CLI
  transport passes `--tools "" --allowedTools ""`. The model answers each turn with either
  `{"action": "retrieve", "requests": [{"tool": …, "parameters": {…}}]}` or `{"action": "final", …}`.
  The application authorizes each request against the cell's capability (`review/capability.py`),
  runs it on the retrieval core, and returns the bounded rows in the next turn. Query, token, turn and
  byte budgets are enforced by the application. The model never opens a socket, a file or a process.
- **The tool catalog is part of the prompt.** Each cell is told which tools it is granted, their exact
  parameter schemas, and a worked request (`turn_protocol.tool_catalog`). It is not discovered through
  an MCP `tools/list` call.
- **Authority is shared, transport is not.** The review cell loop and the MCP adapter apply the same
  rules: only granted tools, no `path`, glob, regular expression, query-language or URL parameters,
  entity-scope checks, and page, depth and byte caps. A review cell's capability is a frozen record
  bound by hash to the run, manifest, package, role and round. The scoped MCP session uses the role
  tool lists in `mcp/capability.py::_ROLE_TOOLS`.
- **`query_owasp_workbench` is MCP-only.** It reads a separate store, so it is not grantable to a
  review cell. This does not exclude OWASP context from review: accepted publications project to
  PRECOMPUTED `control_evidence`, then provisional lead/hunt packages and labelled red/blue/verifier
  requests with authority links and original evidence refs. Those interpretations are indirect for
  every final predicate. Review cells retrieve underlying evidence through their granted in-process
  tools, not by opening the workbench through MCP.
- **Runtime skills carry no target facts or tool grants.** Selected review procedures explain
  evidence checks and syntax-only limitations without naming new tools or setting policy. The role,
  persona and governing-rules guidance a review cell receives is assembled from `pipeline/guidance`
  and `pipeline/prompt-fragments`, and is hash-pinned in the run. See
  [`review-protocol-v2.md`](review-protocol-v2.md).

## Reading older documents

In design documents written before this page, "MCP endpoint", "MCP tool" and "models query through
MCP" usually mean **a typed retrieval tool that a worker can ask for**. Read them as "retrieval tool".
Where a document says a model "infers away from the precomputed neighborhood through MCP", the model
asks for those rows with the retrieval tools; for a review cell the request runs in-process, not over
the MCP transport.

## What is precomputed, and what a model has to ask for

Producers publish shards ahead of the review: the multilingual CodeQL code graph (call sites with `CALLS`
edges, `sink_site`, `range_fact`, `guard_fact`, `dataflow_path`, `flow_summary`, `entry_point`) from the
seeded CodeQL neighborhood to the configured call depth, plus observations, build provenance, tags and
history. The code graph is seeded around finding locations, not whole-program. The Joern CPG producer
is disabled by default. When `[binary_decompilation]` configures binaries, `job_binary_evidence_indexing`
publishes bounded `binary` shards (`binary_function`, `binary_call_site`, `binary_import`,
`binary_string`) from the frozen Ghidra publications; they are read with the same `search`, `find`,
`trace` and `read_excerpt` tools ([`binary-decompilation.md`](binary-decompilation.md)). A package carries the identities and, under review protocol v2, the labelled
neighborhood facts for its lead; everything else is a retrieval-tool call.

The default-on debug-symbol producer adds a separate `debug_symbols` shard for
the run-selected Clang/DWARF or MSVC/native-PDB lane. `query_debug_symbols`
provides bounded symbols, address/source ranges, type layouts, inline frames,
compilation units, coverage and existing graph links. Both review-cell and MCP
capabilities constrain these reads. This is a retrieval tool, not a runtime
skill or an interactive debugger; see [the design](debug-symbol-indexing.md) and
[operations](../operations/debug-symbol-indexing.md).

Export packs and language catalogs now exist for C/C++, Java/Kotlin, JavaScript/TypeScript,
Python, Ruby, Go, C#, Rust and deferred Swift. Actual availability depends on accepted databases,
configured pins and per-family coverage; only C/C++ has native cross-check producers. Swift
remains disabled. `list_codeql_databases` and `query_codeql_neighborhood` use the package's exact
graph-scope grants in both MCP and the in-process loop.

Independently, `query_syntax` reads precomputed Tree-sitter definitions, written calls, imports
and identifier occurrences from the `analysis` index. It uses exact source-file grants, not
graph-scope grants, so failed builds/databases do not block source navigation. Its AST results
remain syntax-only and cannot substitute for semantic paths or resolved call targets.

## Where to go next

- Tool definitions: `docs/schemas/retrieval-mcp-tools.json`.
- Operating the MCP gateway for an external client: [`../operations/retrieval-mcp.md`](../operations/retrieval-mcp.md).
- Index shards and the retrieval core: [`python-and-retrieval.md`](python-and-retrieval.md).
- What a review cell is shown and may ask: [`review-protocol-v2.md`](review-protocol-v2.md) and
  [`inference-security-review.md`](inference-security-review.md) (R2).
- Runtime skills and prompt composition: `AGENTS.md` ("AI guidance locations").
