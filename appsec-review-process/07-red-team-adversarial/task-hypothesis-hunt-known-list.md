# Known-List Red Team Prompt (code-reading hypothesis hunt)

Formerly `known-list-red-team.md`. Loaded as the task of the `hypothesis-hunt-known-list` cell of
`07-hypothesis-discovery` (ADR-0018). Use this prompt for systematic catalog-driven hunting. This is
separate from the general red team prompt.

## Mission

Walk `known-issue-catalog.md` (root `hunt-guides`) against your shard. Your brief (readable input 0,
root `hunt-brief`) names the shard's components, the target files pinned for you (root
`target-repository`), a menu of P1/P2 static-tool leads in those files, and your limits. For each
applicable catalog section, try to build the strongest evidence-backed hypothesis in the code.

## Required Method

1. Read the brief and identify which catalog review groups apply to its components.
2. For each applicable group, read the matching section in `known-issue-catalog.md`.
3. Use `retrieval-guide.md`'s search pattern: `input_grep` over your pinned files with a narrow
   prefix, `evidence_search` / `evidence_read` for the rest of the repository, `input_jq` over the
   supporting-evidence menu files (IR facts, code property graph, build evidence).
4. Read the code at every match. The lead menu is a menu, not a limit: confirm or extend the leads,
   and look for catalog classes the tools did not flag.
5. Emit a hypothesis only where the target has matching code or configuration.

## Required Output

One hypothesis per concrete construct (the reply shape is `hypothesis-hunt-persona.schema.json`):

- `path`, `start_line`, `end_line`: the construct you read, repository-relative
- `vulnerability_class` (the catalog class) and `cwe` when you can name one
- `mechanism`, `attacker_preconditions`
- `evidence`: what you read (`path:line`, `path:start-end`, or a readable input `root:path`)
- `confidence`: low, medium or high

Put catalog sections you checked and found not applicable in `coverage_notes`.

## Guardrails

- The catalog is not evidence.
- Do not report a generic issue class unless the target has matching code or configuration.
- Prefer many small, precise hypotheses over broad generic warnings.
- Candidates only: no severity, no "confirmed" or "verified" wording.
