# E03-core — nominal native SAST producer

Work from current `main` in an isolated worktree. Read `AGENTS.md`, the Independent work protocol,
E03, the native-build and source-SAST contracts, and pinned tool/image guidance before editing.

Own only a new native-SAST worker, its dedicated schemas/contracts/registry records, analyzer rules
or adapters, fixtures and focused tests. Do not edit build replay/source SAST, IR files, shared job
graph/parity/Dagster/launcher/runtime, TODO/docs or generated catalogs. Report shared integration
needs to the master.

Implement the nominal path from an exact accepted `02-native-build` envelope and clang compile
database to pinned clang-tidy, cppcheck and Clang Static Analyzer evidence leads. Bind source,
native-build attempt, build variant, compile database, tool image/version/config and raw evidence
hashes. Normalize leads without finding/severity promotion; unsupported translation units, tool
errors and partial coverage are explicit gaps. Cover deterministic fixture output plus malformed,
stale and mismatched lineage in focused tests. Do not spend this lane on reuse/recovery/cancel/live
qualification.

Commit but do not merge. Report files, tools actually available, tests, limitations, branch/commit
and exact shared-surface integration request.
