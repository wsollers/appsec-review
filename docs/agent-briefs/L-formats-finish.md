# Brief L: shared formats and stricter validator, redo cleanly (branch `formats-2`) - CLOUD agent
START AFTER brief J is merged (persona schemas overlap).

`ws-formats` (b22ae718) is one interrupted, untested WIP commit, 136 commits behind `main`. Do NOT rebase or merge it.
Read it (`git show origin/ws-formats --stat`, then its `formats.py`, `schema_format_lint`, `contract_derive`, validator
and pointer-schema changes) as a design sketch and rebuild on current `main`:
1. Shared formats module: sha256, ISO timestamps, ids, paths, run ids, enums used by many schemas, defined once and
   referenced by `$ref` instead of copy-pasted patterns (the sketch touched ~40 schemas).
2. Validator keyword coverage: the dependency-free validator must implement (or explicitly reject as unsupported, never
   silently ignore) every JSON Schema keyword the repo's schemas use. Write a lint that lists keywords used vs supported.
3. `schema_format_lint`: fails on schemas with an unreferenced duplicate of a shared format.
4. `contract_derive`: derive mechanical contract fields from schemas where ADR-0013 says Python derives them.
Work in slices, one commit per slice, tests first; each slice leaves the full suite at baseline. If a slice would
change any published artifact byte-for-byte or any fingerprint, stop and report before doing it.
## You own
`formats.py`, `schema_format_lint.py`, `contract_derive.py`, the validator, the schemas you convert, their tests.
## Do not touch
Persona files, `job-graph.json` structure, `execution_state.py`.
