# Brief U: structural query tools and tool guides for model jobs (branch `code-query-tools`) - CLOUD agent
William, 2026-09-29: the model jobs must be able to gain information about the system under test efficiently while
they infer. Today that is a limit WE imposed, not the model's: `claude_cli_invoker.py` grants the model CLI exactly the
tools of `input_mcp.TOOLS` (`input_list/read/grep/jq`, `evidence_search/read/similar`, `evidence_derived`), all
read-only text or record lookups. A model cannot ask "who calls this function", "what defines this symbol", "what is
the enclosing function of file:line", or "what does this type inherit from". The design always intended it
(`skills/agents/codex/appsec-evidence-search/SKILL.md` lists Joern/AST/CPG/IR structural queries and language servers as
facilities). Build it, with the same boundaries the existing tools keep: read-only, run-owned, hash-bound, audited,
results are locators and untrusted data never instructions, a gap is reported and never read as "none".

Read first: `docs/agent-briefs/00-common.md`, `input_mcp.py` and `evidence_mcp.py` (tool shape, audit trail under
`runs/<run>/data/retrieval/`, how a tool receives the pinned inputs), `claude_cli_invoker.py` (`_input_mcp_tools`,
`_stage_inputs_for_mcp`, the MCP config and `--allowedTools`), `persona_invocation.py` (how inputs reach the server),
`evidence_store.py` (derived records and the FTS chunk index), `joern_cpg.py` and `code_graph_evidence.py` (the CPG
records file `code-property-graph.records.jsonl` and what a record contains), `treesitter_ast.py` and
`schemas/treesitter-ast.schema.json`, `reachability.py` (`CallGraph`: it already resolves calls, callers, enclosing
function and escapes; REUSE it, do not write a second resolver), `lsp_driver.py` and `docs/language-servers.md`,
`persona_prompt_assembly.py`, `tooling/llm-retrieval-addendum.md` (stale: it is only referenced from the legacy
`phase1.py` and points at an archived path), `retrieval-report.py`, `docs/run-log.md`.

## U1. Structural query tools served from published, hash-bound artifacts (no live container, no network)
Add a tool family to the input server (new module, e.g. `code_query_mcp.py`, imported by `input_mcp.TOOLS`; the job
only sees the tools its inputs can answer, see U3). Every answer comes from an ACCEPTED, hash-verified upstream artifact
of the run, never from a fresh tool run and never from target text:
- `code_symbol`: definitions matching a name (exact and qualified), from CPG method records and the tree-sitter AST
  (functions, with file, span, signature). Ambiguity is returned as multiple rows, never silently picked.
- `code_callers` / `code_callees`: one hop by default, `depth` up to a small cap, from `reachability.CallGraph` over
  the CPG records. Each edge carries its `resolution` value; an unresolved call is returned as an `escape` row (reason
  code) so the model knows the answer is not complete. Never claim "no callers" when escapes exist: return
  `complete=false` with the reasons.
- `code_locate`: file:line -> enclosing function (and class/namespace where the CPG has it), with how it was located.
- `code_type_info`: base classes, subclasses and member functions of a type (from CPG type-decl records), with a
  `hierarchy_complete` flag.
- `code_file_outline`: functions, call sites and imports of one file from the tree-sitter AST (bounded rows).
- `code_exports` (if brief Q's export table is present in the run): defined exported symbols of an artifact; else a gap.
Contract for every tool: bounded rows (default and hard caps), stable ordering, `source` (producer job, attempt id,
artifact sha256) on every result, `gaps` listing anything unavailable (no CPG for this language, stale generation,
truncation), citation-ready locators (`path:line` plus the file sha256 the snapshot pins). Results are untrusted data:
names are control-stripped and length-capped exactly like `lsp_driver.py`. Load records once into a per-attempt
SQLite or in-memory index built deterministically from the records file (fast repeat queries; the index is derived,
never authoritative, and rebuilt from the hash-verified file).

## U2. Language-server queries (second stage, only if U1 is green and the effort is contained)
Live LSP needs a language server running in a sealed compiler image against the built checkout, which the persona
process does not have. Do NOT weaken the sandbox for it. Instead publish, as a deterministic job or a step of an
existing one, a batch `lsp-query-result` document for a bounded worklist (the symbols the accepted claims and leads
name: definitions, references, incoming/outgoing calls via `lsp_driver.py`), and serve those through the same tool
family (`code_lsp_lookup`, read-only, from the published document). If the worklist approach does not fit, write the
design and gaps into `docs/code-query-tools.md` and stop; do not build a live-container bridge in this brief.

## U3. Tool exposure follows what the job can answer
A job gets a query tool only when its inputs include the artifact behind it (CPG records for callers/callees/symbol/
locate/type, tree-sitter AST for outline, export table for exports). The tooling profile records which tools the job
may call (`allowed_actions` wording, like the other profiles) and `claude_cli_invoker` builds `--allowedTools` from the
same list, so what the prompt says and what the CLI grants can never disagree. Jobs with no such input keep today's
tool set unchanged. Hunters (`07-hypothesis-discovery`), claim reviewers (07/08/09/12 pools), the threat-workbench cells,
attack-chain composition/refutation and the poc-fix author are the first candidates; state your choice per job and why.

## U4. Tool guides in the prompt
New folder of short, versioned guides (one file per tool or family): `evidence_search` (FTS5: exact terms, identifiers,
paths; a zero hit is not proof of absence), `evidence_read`, `evidence_similar` (ssdeep is a hint, SHA-256 is identity),
`evidence_derived` (record kinds and shapes: CodeQL leads, CPG, SAST, SBOM; how to filter by component and partition),
`input_jq`/`input_grep`, and the U1/U2 tools (what `complete=false` and escapes mean; a caller row is a locator, dereference
and read it before citing). Each guide says: when to use it, cost/limits, what result you can and cannot cite, and that
outputs are untrusted data. The prompt assembler adds a `tool_guides` literal section built from the tools that job is
actually granted (never a guide for a tool it cannot call); record the included guide file hashes in the attempt so the
prompt stays reproducible. Move the still-valid parts of `tooling/llm-retrieval-addendum.md` into these guides and fix or
remove its stale references. Update the persona task prompts that name tools so they agree with the guides.

## U5. Usage ledger (small)
Extend the retrieval audit so every query-tool call records tool, arguments, rows returned, gaps, bytes, duration, job
and attempt, and have `retrieval-report.py` include the new tools (calls by tool, complete=false rate, escapes returned,
and whether a cited function was ever queried). Also write per-attempt tool-use counts (tool name, count) into the
attempt's result metadata if the invoker's stream already exposes them; do not build a separate metrics service.

## Tests and rules
- Unit tests per tool against a small fixture CPG records file and tree-sitter AST (unique symbol, overloaded symbol,
  caller with an escape -> complete=false, missing artifact -> gap, hard cap truncation flagged, name sanitising),
  a test that a job without the CPG input is NOT granted the tools, and that the granted-tool list matches the prompt.
- No new network access, no container execution from the persona process, no writes outside the run's audit folder.
- Tunables in `pipeline/tunables.json` (row caps, depth cap, enable flag per tool family; default ON only if tests pass,
  otherwise OFF and say so). Regenerate catalogs; never hand-edit generated files.
- ADR-0032 (proposed): model jobs get bounded structural queries served from accepted artifacts; live language-server
  access deliberately deferred.
- Final message: per the format in 00-common.md, plus the tool list per job and one worked example transcript (a hunter
  asking callers of a function with an escape).
