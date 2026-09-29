# Brief U: searchable AST and CPG, structural query tools and tool guides for model jobs (branch `code-query-tools`) - CLOUD agent
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

## U0. Make the data exist and be searchable (William, 2026-09-29: a properly indexed, searchable AST and CPG gets most of the value; native code matters most)
Audit result behind this brief (verify each line before building): the FTS derived-records index (`evidence_index_enrichment.PROFILES`)
covers only 16 producers; no job in `job-graph.json` produces the tree-sitter AST (`treesitter_ast.py` output is supplied by
hand to `dep_reachability_lifecycle` only); the CPG records file is searchable only as text chunks; source SAST, CodeQL,
secrets, SCA/SBOM, IaC and license results are readable on the supporting-evidence menu but not in the FTS derived index;
`06-reachability-codeql`/`-ir` tables are not on the menu.
1. **New job `02-treesitter-ast`** (deterministic, `pinned_container` like `02-code-property-graph`; run `treesitter_ast.py`
   from the vendored `/opt/treesitter` in the same compiler images the language jobs already use; register in `job-graph.json`,
   contract, schema (`treesitter-ast.schema.json` exists), lineage and receipts exactly like sibling jobs; per-language
   applicability skip when no grammar; gaps for oversized/unreadable files as the script already records). Ship the
   records-file pattern for large outputs (as CPG does) so the result stays small. It runs beside the CPG job, needs no build.
   Make `dep_reachability_lifecycle` consume the accepted job output when present instead of only the manual supply
   (manual supply keeps working).
2. **A deterministic, hash-bound code index, published by a job, not rebuilt per attempt.** New job `02-code-index`
   (or extend `02-evidence-index`; decide and justify) that reads the accepted CPG records file, the tree-sitter AST and,
   when present, IR facts and the debug-symbol index, and publishes one SQLite database (schema below) plus its sha256 in
   the job result. Every query tool reads THIS artifact (verify the hash, open read-only). Tables (adapt to the real record
   shapes; do not invent fields the CPG lacks): `methods` (id, name, full_name, signature, file, start/end line, is_external,
   language), `calls` (caller_id, callee_full_name/callee_id, file, line, resolution, argument_count and argument text
   where the CPG has it), `types` (name, kind, file, line), `type_edges` (derived_type, base_type: inheritance),
   `members` (type, member, kind), `identifiers`/`fields` access rows where available, `literals` (string constants
   with file:line), `imports`, `files` (path, sha256, language), plus FTS5 tables over method names, call targets,
   identifiers and string literals for fuzzy lookup. Indexes on every join column. Native C/C++ is the priority: memory
   operations (calls to memcpy/strcpy/sprintf/alloc/free families and their argument expressions), function pointers
   and address-taken functions, vtables/overrides, and preprocessor-expanded locations must be representable.
3. **Broaden the FTS derived index and menu:** add `02-source-sast`, `02-codeql-<lang>` (all), `02-secrets-inventory` (the
   redacted artifact only), `02-sca-vulnerability-match`, `02-sbom-inventory`, `02-iac-config-scan`, `02-license-scan`
   and `02-treesitter-ast` summaries to `evidence_index_enrichment.PROFILES` with the correct authority label
   (`derived_evidence` for tool output, never `untrusted_documented_intent` mislabeled); add `06-reachability-codeql`,
   `06-reachability-ir` and the code index to `supporting_evidence_menu.py`. Respect the existing caps and redaction; keep
   SARIF message text withheld from model-facing search text (decision D-02 item 6): rule id, category, location and
   severity are indexed, tool prose is not.
4. Report in your final message which producers are now searchable, the index sizes and build time on the fixture,
   and anything that could not be indexed (with the gap it produces).

## U1. Structural query tools served from published, hash-bound artifacts (no live container, no network)
Add a tool family to the input server (new module, e.g. `code_query_mcp.py`, imported by `input_mcp.TOOLS`; the job
only sees the tools its inputs can answer, see U3). Every answer comes from the U0 code index (built from ACCEPTED, hash-verified upstream artifacts
of the run), never from a fresh tool run and never from target text:
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
- `code_search`: FTS over method names, call targets, identifiers and string literals (fuzzy discovery when the exact name is unknown).
- `code_calls_to`: call sites of a named function or family (for example the unsafe-copy family) with file, line, caller and
  the argument text/count the CPG records, filterable by component, partition or path prefix (native memory-safety triage).
- `code_path`: bounded call paths from a function (or program entry) to a target function via `reachability.CallGraph`,
  returning up to N paths and every escape encountered (`complete=false` when any escape can hide a path).
- `code_address_taken` / `code_overrides`: functions whose address is taken or stored in tables, and the overrides of a
  virtual method, with `hierarchy_complete` and the reason codes brief S defines (use them if brief S is merged; otherwise
  return the existing escape reasons).
- `code_exports` (if brief Q's export table is present in the run): defined exported symbols of an artifact; else a gap.
Contract for every tool: bounded rows (default and hard caps), stable ordering, `source` (producer job, attempt id,
artifact sha256) on every result, `gaps` listing anything unavailable (no CPG for this language, stale generation,
truncation), citation-ready locators (`path:line` plus the file sha256 the snapshot pins). Results are untrusted data:
names are control-stripped and length-capped exactly like `lsp_driver.py`. Load records once into a per-attempt
SQLite or in-memory index built deterministically from the records file (fast repeat queries; the index is derived,
never authoritative, and rebuilt from the hash-verified file).

## U2. DEFERRED: live language-server and CodeQL queries at model time
William, 2026-09-29: defer both; the indexed AST and CPG (U0/U1) should cover most needs. Do NOT build a live bridge.
Write `docs/code-query-tools.md` section "Deferred" with: the sealed code-intel sidecar design (read-only checkout mount,
no network, unprivileged, resource-capped, pinned image, closed query set through `lsp_driver.py`, audited, torn down by
the owning Dagster job), why build scripts make jdtls/gopls a target-controlled-code risk, the replay rule (record each
query and answer), and what evidence would justify building it (the usage ledger in U5 showing hunters asking for
things the code index cannot answer). Same for query-time CodeQL (a bounded set of parameterised, pre-compiled query
packs, results published as locators). Design only.

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
