# Brief J: one folder for personas and roles, structurally identical (branch `personas-folder`) - CLOUD agent

Today personas and roles are JSON in `appsec-review-process/registry/personas` (75) and `registry/roles` (44), prompt
text lives in fragments and per-lane `subprompts.md`, and 48 records are generated (`provenance.reviewed: false`).
Goal: a person opening one folder sees every persona and every role in the same shape.

## Layout (new, under `appsec-review-process/personas/`)
```
personas/
  persona.schema.json        role.schema.json
  personas/<persona-id>/persona.json   prompt.md
  roles/<role-id>/role.json            prompt.md
```
- Every persona folder has EXACTLY those two files; every role folder exactly those two. No extras, no optional files.
- `persona.json` has the same key set and key order for every persona (id, title, role, scopes: jobs/stages, evidence
  streams, model class, budget class, output contract ref, `persona_variants` if any, provenance incl. `reviewed`).
  `role.json` likewise. Use the fields the registry records already carry; do not invent new semantics. Fields that do
  not apply are present with an explicit empty value, never omitted.
- `prompt.md` holds the prompt text that is today in fragments/subprompts for that persona or role; content moved
  byte-for-byte where possible (persona prompt text is part of job fingerprints; report which fingerprints move).
- A test `tests/test_persona_folder_uniform.py` enforces: exact file set per folder, exact key set/order, schema
  validity, unique ids, every role referenced by a persona exists, every persona referenced by a job template exists,
  and no orphan files.

## Work
1. Write the two schemas from the union of existing record fields (report any field that is inconsistent across the
   75/44 records and how you normalised it).
2. `git mv` records into the new layout in one pure-move commit, then a second commit that changes the loaders
   (`catalog_personas.py`, registry loader, `persona_prompt_assembly.py`, anything reading `registry/personas|roles`)
   and every path reference. Registry `job-templates`, `output-contracts`, `domains`, `tooling-profiles` are NOT moved
   here (brief K does that later).
3. Add the per-stage roles now missing (open item in TODO "Personas and reviewer pools"): `red-team-adversary`,
   `blue-team-refuter`, `independent-verifier`, `scorer`, `hypothesis-hunter`, replacing the generic `claim-reviewer`
   at stages 07/08/09/12 and the hunter pool. Keep ADR-0021 defaults: a failed reviewer shard fails the stage (no
   partial publication). Generated persona records stay `reviewed: false`; do not flip any.
4. `catalog_personas.py check` must pass; regenerate `docs/personas-and-registry/persona-assignment.md`.
5. Docs: `docs/personas-and-registry/README` section describing the layout and how to add a persona or role (copy a
   folder, edit two files, run the check). Short ADR only if a decision needs recording (next free ADR number).

## You own
`appsec-review-process/personas/**`, `catalog_personas.py`, persona loaders/assembly, persona registry tests,
`docs/personas-and-registry/**`. Do NOT touch `job-graph.json` structure, other registry dirs, `claim_ledger.py`,
`execution_state.py` (brief I), `synthesis_report_presentation.py` (brief M).
## Acceptance
Uniformity test passes; `catalog_personas.py check` passes; all persona/registry-related test modules pass; a dry
run of persona assembly for one job before/after produces the same assembled prompt (test it for 3 jobs, including
07, and the hunter pool).
