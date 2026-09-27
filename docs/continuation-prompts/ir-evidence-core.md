# E04/E05-core — nominal IR capture, link and facts

Work from current `main` in an isolated worktree. Read `AGENTS.md`, the Independent work protocol,
E04/E05, the accepted native-build contract and canonical evidence rules before editing.

Own only new IR capture/link/facts workers, their dedicated schemas/contracts/registry records,
fixtures and focused tests. Do not edit native/source SAST, build replay, shared job graph/parity,
Dagster/launcher/runtime, TODO/docs or generated catalogs. Report shared integration needs to the
master.

Implement the nominal lineage: accepted native-build + compile database -> per-unit LLVM bitcode
capture -> deterministic linked module -> debug-location and pointer/memory fact records. Bind exact
source snapshot, compiler/toolchain, build variant, native-build attempt, compile entries and every
module/fact hash. Zero/partial capture and uncovered units are explicit gaps; malformed or stale
bitcode/link inputs fail closed. Facts are evidence, never vulnerability verdicts. Cover the fixture
happy path, deterministic output, stale variant and malformed bitcode/facts in focused tests. Do not
spend this lane on reuse/recovery/cancel/live qualification.

Commit but do not merge. Report files, tests, limitations, branch/commit and exact shared-surface
integration request.
