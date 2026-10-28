# Tree-sitter AST production

`job_tree_sitter_ast` is an independent syntax producer. It consumes the accepted review-intake
target snapshot and target-catalog ownership/topology handoffs, plus accepted language-build
outputs when that producer is enabled. It does not consume CodeQL, compiler AST/IR, SAST, or
inference output. Source-only graphs retain their original prerequisites.

The planner assigns only accepted inventory files to the most-specific accepted component and
build/source root, then partitions them by language and locked grammar. Each partition has a stable
scope identity and fingerprint over the target snapshot, exact source hashes, accepted exclusions,
declared grammar-lock metadata, container execution image ID, normalizer version, and bounds.
Changing one partition therefore invalidates only that partition.

Workspace-only generated source uses a bounded lane of accepted artifact identities, not a
workspace scan. Receipt/manifest validation binds selected customer bytes to their producer;
detached read-only copies back explicit generated logical paths. Scope and source-backing
provenance flow through AST/source entities and prioritization into source resolution. Retrieval
checks the accepted backing's run, target, canonical artifact, hash, size and custody, never
falling back to a similarly named target file. Supplied-platform roles are excluded before payload
access. Generated origin alone neither excludes source nor proves delivery; unresolved shipping
relationships remain gaps.

Large language partitions are deterministically chunked by configured file-count and source-byte
ceilings. The parser additionally enforces per-file bytes and nodes plus a total node ceiling for
the invocation, keeping container memory, output, and retry work bounded without silently dropping
the remainder.

The only production parser is `tool-tree-sitter`. Its image is assembled from a digest-pinned
Python base, hash-locked wheels, and pre-generated Linux grammar libraries. Image assembly verifies
every cached byte. Review execution is non-root, read-only, network-disabled, capability-free, and
bounded by the central container policy; it cannot download or compile grammars.
Those acquisition checks are platform maintenance, not customer-review payload fingerprinting.

The supported grammar contract is closed and identical across planner, parser routing, acquisition,
and the asset lock: C, C++, C#, Go, Java, JavaScript, Kotlin, PHP, PowerShell, Python, Ruby, Rust, Shell,
TSX, and TypeScript (plus the C/C++ catalog alias). Shell routes to the upstream Bash grammar.
Each library is pinned by upstream revision, SHA-256, size, and license. Catalog languages outside
that set, currently including Swift, continue through publication as explicit unavailable
coverage rather than a fallback parse.

Each successful scope emits:

- an immutable normalized AST JSONL shard;
- an immutable generic `analysis` SQLite retrieval shard;
- canonical AST-node identities and exact source locations;
- grammar-native node type and named/error/missing/extra flags;
- exact parent/child ordering and field relations;
- parse diagnostics, exclusions, counts, truncation, and container execution identity.

The nodes are concrete syntax, not semantic symbols. Consumers use the existing retrieval search,
find, trace, source-resolution, and coverage APIs, plus `query_syntax` through the retrieval core,
external MCP or the application-authorized in-process review loop.
`job_review_prioritization` rebuilds per-file trees from the accepted JSONL shards to derive
function complexity, imports, and heuristic signals; see
[`review-prioritization.md`](review-prioritization.md).
Unsupported languages, unavailable grammars, parser failures, malformed syntax, and bounds are
explicit coverage gaps. A failed scope does not discard successful sibling shards. Framework
integrity failures—changed accepted bytes, escaped paths, image/hash mismatch, corrupt outputs, or
invalid manifests—stop publication.

## Bounded syntax navigation

The host normalizer rereads only accepted files through hash-verified source custody and adds
`appsec-review/syntax-projection/1` to selected canonical AST nodes. It does not parse again or
require a build. Written names, exact name spans, syntactic enclosing-definition identities and
qualifier chains complement the existing node span, source hash, scope, language and grammar.
A partial SQLite expression index on source identity, category and written name bounds lookup;
the original AST JSONL, node types and parent relations remain available.

The initial explicit mappings cover C/C++, C#, Go, Java, JavaScript/TypeScript/TSX, Kotlin,
Python, Ruby, Rust and PHP. They are syntax subsets, not exhaustive language symbol tables.
PowerShell and Shell retain raw AST coverage with an unavailable projection mapping; Swift
still has no locked grammar and is not enabled. Names longer than 512 bytes are omitted.
Anonymous forms, local module resolution and semantic references remain gaps, not inferred facts.

`query_syntax(mode, subject, name?, limit?, cursor?)` accepts `definitions`, `calls`, `imports`
and `references`. The last mode means identifier occurrences, including defining occurrences,
not binding resolution. `name` matches the exact written spelling, without converting `.` or
`::`. A source-file identity bounds one immutable file; an AST subject further bounds the byte
span. Imports include syntactic declarations and known call forms, but never resolved module
edges. All names, imports and call targets are explicitly unresolved.

The existing exact source-file identities in a signed package/cell capability grant returned
nodes independently of CodeQL graph scopes. Only nodes actually returned become addressable
for subsequent source resolution; a filename, AST-kind prefix or sibling file is not a grant.
No SQL, path, glob, Tree-sitter query program or runtime source-tree scan is accepted.
Responses use the common manifest-bound cursors, page/time/byte limits and explicit coverage gaps.
Parse errors make per-file coverage partial. Scope-language metadata, including failed scopes,
drives the syntax language matrix; component-prefixed scope names are never parsed as languages.

Syntax nodes retain their existing evidence-admission rules: direct evidence for an affected
construct, never direct dataflow, input control or guard sufficiency. A successful syntax fallback
does not repair missing CodeQL coverage. Projection version changes invalidate scope reuse.
