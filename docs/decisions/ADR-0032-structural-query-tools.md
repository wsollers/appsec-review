# ADR-0032: Structural query tools over a deterministic code index

Status: **Proposed** (2026-09-29, brief U; awaiting William). Details: [`docs/code-query-tools.md`](../code-query-tools.md).

## Context

Indexed-mode model jobs could only grep and `jq` raw evidence files. Call graphs, types and sink call sites in a CPG
are too large to page, and tree-sitter output had no producing job. Quality of hunts and claim reviews depends on
cheap, accurate structural questions.

## Decision

1. Add jobs `02-treesitter-ast` (pinned container) and `02-code-index` (deterministic Python) producing a SQLite
   index from the CPG, tree-sitter AST and export tables. It is hash-verified and opened read-only by the MCP server.
2. Expose twelve `code_*` read-only tools. Every answer states `complete`, gaps, truncation, source and a locator;
   incompleteness is data, not an error, and models are told never to infer absence from it.
3. Grants are least-privilege and derived, not configured twice: profile line, tunable family, accepted index
   with a matching capability. The tool guides shown to the model come from the same list as `--allowedTools`.
4. The tree-sitter job mounts a content-addressed copy of `treesitter_ast.py` from `data/tooling/` (AGENTS.md).
   **Needs William's explicit approval.**
5. `06-cve-reachability` consumes the accepted tree-sitter output as a hint engine when no manual file is supplied.
6. Defer the live code-intel sidecar and query-time CodeQL (see the Deferred section of the design doc).

## Consequences

Model-facing answers are reproducible from hashed inputs. The index adds two jobs and a build step per run.
`complete=false` will be common on native code with indirect calls; that is accurate, and reviewers see it as gaps.
