# Retrieval surfaces: tools, MCP, review cells, and skills

Four things in this repository are easy to confuse because older documents use "MCP" for all of
them. They are different, and this page is the one place that says which is which.

| Term | What it is | Who uses it |
|---|---|---|
| **Retrieval tool** | A typed, bounded read of accepted index shards, for example `search`, `find`, `read_excerpt`, `trace`, `resolve_evidence`, `query_observations`, `query_build_security`, `query_code_graph`. The names and parameter schemas are in `docs/schemas/retrieval-mcp-tools.json` and `src/appsec_review/mcp/schema.py`. | Every consumer below. |
| **Retrieval core** | `appsec_review.retrieval`: the code that opens the accepted shards read-only and answers a tool call. | Jobs, review cells, and the MCP adapter. |
| **MCP adapter** | `appsec_review.mcp` and the `appsec-review-mcp` command: a read-only JSON-RPC (MCP) stdio server over the retrieval core, pinned to one accepted run. | External clients and the OWASP workbench. **Not** review cells. |
| **Runtime skill** | A bounded guidance file under `pipeline/skills/<name>/SKILL.md` sent to a model worker for one job. | The build-repair, dependency-resolution, post-build assessment and target-analysis workers. **Not** review cells. |

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
  review cell.
- **Runtime skills carry no target facts and no retrieval instructions for review.** The role,
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

Producers publish shards ahead of the review: for C and C++, the code graph (call sites with `CALLS`
edges, `sink_site`, `range_fact`, `guard_fact`, `dataflow_path`, `flow_summary`, `entry_point`) from the
seeded CodeQL neighborhood to the configured call depth, plus observations, build provenance, tags and
history. The code graph is seeded around finding locations, not whole-program. The Joern CPG producer
is disabled by default. A package carries the identities and, under review protocol v2, the labelled
neighborhood facts for its lead; everything else is a retrieval-tool call.

## Where to go next

- Tool definitions: `docs/schemas/retrieval-mcp-tools.json`.
- Operating the MCP gateway for an external client: [`../operations/retrieval-mcp.md`](../operations/retrieval-mcp.md).
- Index shards and the retrieval core: [`python-and-retrieval.md`](python-and-retrieval.md).
- What a review cell is shown and may ask: [`review-protocol-v2.md`](review-protocol-v2.md) and
  [`inference-security-review.md`](inference-security-review.md) (R2).
- Runtime skills and prompt composition: `AGENTS.md` ("AI guidance locations").
