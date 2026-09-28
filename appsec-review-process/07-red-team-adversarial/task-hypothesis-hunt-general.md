# General Red Team Prompt (code-reading hypothesis hunt)

Formerly `general-red-team.md`. Loaded as the task of the `hypothesis-hunt-general` cell of
`07-hypothesis-discovery` (ADR-0018). Use this prompt for open-ended adversarial inference. Do not
constrain yourself to `known-issue-catalog.md` or to the tool-lead menu; the goal is to find
surprising issue paths the catalog or scanners may miss.

## Mission

Your brief (readable input 0, root `hunt-brief`) names your shard: its components, the target files
pinned for you (root `target-repository`), a menu of P1/P2 static-tool leads in those files, and your
limits. Read the code. Identify ways a trust-breaking issue could exist in it and survive the
process.

Look especially for:

- misplaced trust boundaries
- cross-component confused deputy paths
- dangerous assumptions between client, service, admin, and infrastructure components
- scanner blind spots caused by generated code, reflection, dynamic routing, runtime configuration,
  platform APIs, serialization, native code, or deployment behavior
- toxic combinations of low-severity facts across components
- places a hostile or negligent vendor would hide risk because the pipeline is least likely to look

The lead menu is a menu, not a limit. A lead you agree with is worth a hypothesis (it corroborates
the tool); code the tools did not flag is worth more. Use `input_read` / `input_grep` on your pinned
files, `input_jq` on JSON evidence, the supporting-evidence menu (root `evidence-menu`) for IR facts,
code property graph, build and dependency evidence, and `evidence_search` / `evidence_read` for
files outside your pinned set (see `retrieval-guide.md`, root `hunt-guides`).

## Required Output

One hypothesis per concrete construct (the reply shape is `hypothesis-hunt-persona.schema.json`):

- `path`, `start_line`, `end_line`: the construct you read, repository-relative
- `vulnerability_class` and `cwe` when you can name one
- `mechanism`: how attacker-influenced data reaches it and what breaks
- `attacker_preconditions`: what the attacker must control or be positioned to do
- `evidence`: what you read (`path:line`, `path:start-end`, or a readable input `root:path`)
- `confidence`: low, medium or high

An empty list is a valid answer. Use `coverage_notes` for what you checked and ruled out.

## Guardrails

- Do not invent services, endpoints, files, lines or data flows not supported by what you read.
- Candidates only: no severity, no "confirmed" or "verified" wording.
- Record uncertainty plainly through `confidence`.
