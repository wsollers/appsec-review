# F02-core — nominal evidence assembly

Work from current `main` in an isolated worktree. Read `AGENTS.md`, the Independent work protocol,
the F01/F02 backlog, the canonical evidence/state architecture and the common worker-result envelope
before editing.

Own only a new `appsec-review-process/evidence_assembly.py`, its dedicated schema, output contract,
registry composition records, fixtures and focused tests. Do not edit the job graph, parity manifest
or generated views, Dagster workflow/definitions, launcher, common runtime, TODO/docs, generated
catalogs, build replay, source SAST or component characterization. Report shared-surface needs to the
master for serialized integration.

Implement a deterministic, fail-closed core that validates terminal producer instances, accepted
pointer/envelope hashes, producer IDs, source/build lineage, generation/freshness, permissions,
coverage and authorized terminal skips before publishing a hash-bound `intel-manifest.json`.
Required producers that are absent or nonterminal must prevent a complete publication; fixture-only
gaps/skips must remain explicit and must not be described as coverage. Cover corrupt, stale,
mixed-generation, duplicate and early-publication cases in focused tests. This is nominal core
construction, not fault/recovery hardening; do not mark F02 executable or qualified.

Commit but do not merge. Report files, tests, manifest semantics, limitations, branch/commit and the
exact shared integration request.
