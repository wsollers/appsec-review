# Tree-sitter AST production

`job_tree_sitter_ast` is an independent syntax producer. It consumes the accepted review-intake
target snapshot and target-catalog ownership/topology handoffs; it does not consume CodeQL,
compiler AST/IR, SAST, or inference output.

The planner assigns only accepted inventory files to the most-specific accepted component and
build/source root, then partitions them by language and locked grammar. Each partition has a stable
scope identity and fingerprint over the target snapshot, exact source hashes, accepted exclusions,
grammar revision and generated parser hash, container image ID, normalizer version, and bounds.
Changing one partition therefore invalidates only that partition.

Large language partitions are deterministically chunked by configured file-count and source-byte
ceilings. The parser additionally enforces per-file bytes and nodes plus a total node ceiling for
the invocation, keeping container memory, output, and retry work bounded without silently dropping
the remainder.

The only production parser is `tool-tree-sitter`. Its image is assembled from a digest-pinned
Python base, hash-locked wheels, and pre-generated Linux grammar libraries. Image assembly verifies
every cached byte. Review execution is non-root, read-only, network-disabled, capability-free, and
bounded by the central container policy; it cannot download or compile grammars.

Each successful scope emits:

- an immutable normalized AST JSONL shard;
- an immutable generic `analysis` SQLite retrieval shard;
- canonical AST-node identities and exact source locations;
- grammar-native node type and named/error/missing/extra flags;
- exact parent/child ordering and field relations;
- parse diagnostics, exclusions, counts, truncation, and container execution identity.

The nodes are concrete syntax, not semantic symbols. Consumers use the existing retrieval search,
find, trace, source-resolution, and coverage APIs. There are no Tree-sitter-specific MCP tools.
Unsupported languages, unavailable grammars, parser failures, malformed syntax, and bounds are
explicit coverage gaps. A failed scope does not discard successful sibling shards. Framework
integrity failures—changed accepted bytes, escaped paths, image/hash mismatch, corrupt outputs, or
invalid manifests—stop publication.
