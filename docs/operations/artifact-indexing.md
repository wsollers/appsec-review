# Produced-artifact indexing

`job_artifact_indexing` is the repository-independent boundary between accepted language builds and
artifact consumers. It reads only the accepted, hash-verified `job_language_build` handoff, its
workspace manifests, and its declared produced artifacts. It never discovers authority by scanning
the target tree.

The job publishes immutable `artifacts` SQLite/FTS shards in three independently fingerprinted
groups:

- catalog shards per build unit and canonical artifact family;
- archive-member shards per package artifact and extractor identity; and
- relationship shards per artifact.

The accepted composite manifest retains the previously accepted physical indexes and replaces the
prior `artifacts` shard set atomically. Catalog fingerprints contain no scanner, retrieval transport,
or MCP identity. A scanner change therefore invalidates only its observation shards, and an MCP
change invalidates no physical shard.

## Recovery and integrity

Restart the same application run normally. A completed shard whose deterministic path, SQLite
integrity, metadata, and hash still verify is reused. A stale or corrupt shard is an integrity
failure and stops publication; it is never silently overwritten. Changing one artifact changes its
family catalog shard and its artifact-specific member or relationship shards without invalidating
unrelated build units or artifact families.

An unavailable, failed, empty, truncated, or ambiguously mapped producer remains an explicit
coverage gap. Raw artifact bytes, protected command arguments, and stdout/stderr never enter the
SQLite/FTS payloads. The accepted summary and composite manifest are run-owned artifacts bound to
the accepted job handoff.
