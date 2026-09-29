# Brief L2: derive-list fixes

Branch `derive-fixes`, from latest `main`. Read `00-common.md`, `L-formats-finish.md`, decision log D-17 (c),
`contract_derive` and its tests.

## Scope
Three hand-written derive lists omit fields the model then has to echo, costing repair rounds. Fix each, so the
derive list matches the schema's derivable fields (ADR-0013: Python derives mechanical fields):
1. `poc_fix_derive`: `explanation_status` and `poc.reason`.
2. `claim_review_derive`: `citations`.
3. `hypothesis_hunt_derive`: `drop_reason`.

## Rules
- Prefer generating the list from `contract_derive` over adding more hand-typed names; add a test that fails when a
  schema field marked derived is missing from a derive list.
- Each change moves only its own job's fingerprint. Report before/after fingerprints per job; no other job may move.
- Do not touch the batch `$ref` conversion of inline formats (deferred, D-17 b). The inline-format baseline may only go down.
- Tests as in 00-common.md; regenerate catalogs, never hand-edit them.
