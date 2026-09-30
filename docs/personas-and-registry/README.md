# Personas and roles

- [persona-catalog.md](persona-catalog.md): the human-readable catalog of reviewer personas; generated
  persona records are derived from it.
- [persona-assignment.md](persona-assignment.md): which persona and role every model-calling job runs as.
- [ADR-0021](../decisions/ADR-0021-sharded-claim-review-personas.md): persona variants and the sharded
  07/08/09/12 claim review pool. [ADR-0024](../decisions/ADR-0024-per-stage-review-roles.md): role variants
  and the per-stage review roles.

## The personas folder

Every persona and every role is one folder under `appsec-review-process/personas/`, and every folder of a
kind has the same shape:

```
appsec-review-process/personas/
  persona.schema.json        role.schema.json
  personas/<persona-id>/persona.json   prompt.md
  roles/<role-id>/role.json            prompt.md
```

- `persona.json` / `role.json` is the machine record a job template composes. Every key the schema lists
  is present, in the schema's property order. A field that does not apply holds an explicit empty value
  and is never omitted: `best_used_in_lanes: []` when a persona names no lanes, `provenance: {}` for a
  hand-authored persona (catalog-generated personas carry `generated_by`, `source`, `reviewed`, `note`).
- `prompt.md` is the exact section the prompt assembler puts in a job's prompt for that record
  (`## Persona (<id>)` or `## Role (<id>)` and the record as sorted JSON). It is written by
  `catalog_personas.py generate`, never by hand, so opening a folder shows what the model reads.
- Loading leaves an empty optional field out (`persona_registry.loaded`), so a record reads exactly as it
  did before the fields were made explicit; assembled prompts and pinned record hashes did not move.
- Persona records name no role. Personas and roles are bound together by job templates in
  `appsec-review-process/pipeline/job-templates/` (`composition`, `persona_variants`, `role_variants`, and the claim review
  pool's `stage_personas` / `stage_roles`). Job templates, domains, tooling profiles and output contracts
  stay in `registry/`.
- `appsec-review-process/persona_registry.py` is the one place that knows these paths; loaders go
  through it.

`tests/test_persona_folder_uniform.py` enforces the layout: exactly those files in every folder and
nothing else in the tree, the key set and order, schema validity, ids equal to folder names and unique,
the provenance shape, `prompt.md` current, and every persona and role a job template names exists.

## Adding a persona or a role

1. Copy an existing folder of the same kind and rename it to the new id, e.g.
   `cp -r appsec-review-process/personas/personas/owasp-validator appsec-review-process/personas/personas/<new-id>`
   (a hand-authored persona) or `.../personas/roles/claim-reviewer .../personas/roles/<new-id>`.
2. Edit `persona.json` (or `role.json`): set the id field to the folder name and rewrite every value.
   Keep every key and the key order; use `[]` or `{}` for a field that does not apply. A hand-authored
   persona has `"provenance": {}`.
3. Regenerate the prompt and run the checks (from the repository root):

   ```
   python3 -B appsec-review-process/catalog_personas.py generate
   python3 -B appsec-review-process/catalog_personas.py check
   cd appsec-review-process && PHASE1_TEST_DATA=$(mktemp -d) python3 -m unittest tests.test_persona_folder_uniform
   ```

A persona is used by a job only once a job template composes it or lists it in `persona_variants`; a role
once a template composes it or lists it in `role_variants`. See
[AUTHORING-TEMPLATE.md](../../appsec-review-process/pipeline/AUTHORING-TEMPLATE.md) for what makes a
good persona or role.

A catalog persona (a `### <id>` section of [persona-catalog.md](persona-catalog.md)) is not copied by
hand: edit the catalog and run `generate`. To take ownership of a generated record, hand-edit it and set
`"provenance": {}`; the generator then leaves it alone.

## Per-stage review roles

The 07/08/09/12 claim review pool runs each stage under its own registry role (ADR-0024), chosen by
`claim-review-pool-cell.stage_roles`:

| Stage | Role | Allowed claim class |
|---|---|---|
| 07 red team | `red-team-adversary` | `candidate_only` |
| 08 blue team | `blue-team-refuter` | `refutation` |
| 09 verification | `independent-verifier` | `verification_observation` |
| 12 scoring | `scorer` | `verification_observation` |

The template's composed role stays the generic `claim-reviewer`. The code-reading hypothesis hunters
already run as their own role, `vulnerability-hypothesis-hunter`.
