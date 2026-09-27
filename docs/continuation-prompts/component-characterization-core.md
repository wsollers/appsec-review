# F03-core — nominal component characterization

Work in an isolated worktree based on component-core commit `ef415950` (or current `main` plus that
single core commit). Read `AGENTS.md`, the Independent work protocol, F02/F03 backlog and the
component-purpose-map architecture before editing.

Own only `component_characterization.py`, its dedicated schema/registry/task records, fixtures and
focused tests. Do not edit source SAST, build replay, the job graph, parity manifest or generated
views, Dagster workflow/definitions, launcher, common runtime, TODO/docs or generated catalogs.
Report shared-surface needs to the master for serialized integration.

Complete the nominal core so it consumes the exact hash-bound F02 `intel-manifest.json` lineage and
emits deterministic component purpose, ownership, paths, relationships, evidence citations,
confidence, unknowns and tag cloud. Rescope events must be explicit and bounded. Test overlapping
and unassigned paths, stale/missing citations, manifest/hash mismatch and deterministic IDs using
fixtures. Preserve the honest state: F03 remains `BLOCKED(F02)` until the master integrates a real
accepted F02 envelope. Do not spend this lane on recovery qualification.

Commit but do not merge. Report files, tests, limitations, branch/commit and the exact shared
integration request.
