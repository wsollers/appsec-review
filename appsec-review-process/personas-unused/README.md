# Parked personas and roles

Records here are **not loadable by any job**. `persona_registry` resolves personas and roles only under
`appsec-review-process/personas/{personas,roles}/`, and `catalog_personas.py` reads only
`docs/personas-and-registry/persona-catalog.md`, so nothing in this folder is rendered, generated, checked or
fingerprinted. The folder sits beside `personas/` rather than inside it because
`tests/test_persona_folder_uniform.py` fixes that tree to exactly two schemas and two record folders.

A record was parked when no job template (`composition`, `persona_variants`, `role_variants`, `stage_personas`,
`stage_roles`), worker, config file or test named it. The full method and the list of records deliberately *not*
parked are in `docs/prompt-persona-role-alignment-plan-2026-10-01.md`, section 3.

## Restoring one

1. `git mv appsec-review-process/personas-unused/<personas|roles>/<id> appsec-review-process/personas/<personas|roles>/<id>`
2. Persona generated from the catalog (`provenance.generated_by: catalog_personas.py`): move its `### <id>` section from
   `docs/personas-and-registry/persona-catalog-unused.md` back into `persona-catalog.md` under its group. Otherwise,
   clear `provenance` so the record is hand-authored.
3. Name it in a job template, then run `python3 appsec-review-process/catalog_personas.py check` and
   `python3 -m unittest tests.test_persona_folder_uniform` from `appsec-review-process/`.

## Parked on 2026-10-01

| kind | id | reason |
|---|---|---|
| persona | `acceptance-test-intelligence-reviewer` | no template, code, config or test names it; catalog-generated |
| persona | `architecture-doc-summarizer` | no template, code, config or test names it; catalog-generated |
| persona | `completeness-auditor` | no template, code, config or test names it; catalog-generated |
| persona | `dev-lead` | no template, code, config or test names it; catalog-generated |
| persona | `executive-risk-briefing` | no template, code, config or test names it; catalog-generated |
| persona | `integration-test-intelligence-reviewer` | no template, code, config or test names it; catalog-generated |
| persona | `load-test-and-abuse-capacity-reviewer` | no template, code, config or test names it; catalog-generated |
| persona | `network-topology-doc-consumer` | no template, code, config or test names it; catalog-generated |
| persona | `nginx-rest-api-specialist` | no template, code, config or test names it; catalog-generated |
| persona | `pii-flow-mapper` | no template, code, config or test names it; catalog-generated |
| persona | `postman-bruno-collection-consumer` | no template, code, config or test names it; catalog-generated |
| persona | `product-requirements-security-mapper` | no template, code, config or test names it; catalog-generated |
| persona | `qa-lead` | no template, code, config or test names it; catalog-generated |
| persona | `qa-lead-output` | no template, code, config or test names it; catalog-generated |
| persona | `security-program-owner` | no template, code, config or test names it; catalog-generated |
| persona | `smoke-test-validator` | no template, code, config or test names it; catalog-generated |
| persona | `synthesis-integrator` | no template, code, config or test names it; catalog-generated |
| persona | `terraform-iam-reviewer` | no template, code, config or test names it; catalog-generated |
| persona | `unit-test-intelligence-reviewer` | no template, code, config or test names it; catalog-generated |
| role | `final-publication-custodian` | no template, code, config or test names it |
