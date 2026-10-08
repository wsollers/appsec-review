# Architecture TODOs

## Add `grype_db_sync` to `job_third_party_data_sync`

The archived pre-refactor tree was inspected for a reusable Grype database. It contains a Grype
executable archive and image/build records, but no database snapshot with a verifiable database
schema version, listing metadata, content hashes, source provenance, or freshness identity. Those
bytes are therefore not a usable database snapshot and were not copied.

Future work should add an independent `grype_db_sync` step to `job_third_party_data_sync`, alongside
the NVD, OSV, and MITRE branches. It must use Grype's supported database update mechanism, record the
Grype tool/image identity and upstream database schema/build identity, enforce download and
extraction bounds, hash every published file, validate the database with the pinned Grype version,
publish immutably with a last-known-good pointer, and expose a bounded lookup/consumer interface.
The step must fail truthfully when provenance, validation, or freshness cannot be established.

## Supply an entitled, pinned CodeQL closure

The C++ job now publishes a producer-local CodeQL shard and precise blocked disposition. Enabling
database creation and queries still requires an applicable user/environment entitlement plus a
hash-pinned offline CLI, extractor, query-pack, and license-notice closure. Preserve the current
selective invalidation boundary: query-pack changes must not rebuild Clang AST or LLVM IR.

## Supply a pinned Joern/c2cpg closure

The C++ job now publishes a producer-local Joern shard and precise blocked disposition. Enable it
only after reviewing and locking one platform archive and its complete JDK/dependency closure, then
add bounded CPG export fixtures and security probes. Do not put the full CPG into MCP responses.
