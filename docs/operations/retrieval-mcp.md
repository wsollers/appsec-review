# Operating the local retrieval MCP gateway

The gateway serves one already accepted review run. It does not build indexes and cannot change a
run.

Start it over stdio:

```text
appsec-review-mcp --runs-dir runs --run-id 2026-10-08-0001
```

For a stricter deployment pin, copy the `manifest_sha256` from
`runs/<run-id>/data/indices/accepted.json` and add:

```text
--manifest-sha256 <64-lowercase-hex-digest>
```

Startup fails when the run id is invalid, the accepted pointer or handoff is missing, the handoff
is not accepted, the pin differs, an artifact path escapes the run, or a manifest/index hash or
embedded identity differs. Those failures require repairing or rerunning the producer; operators
must not edit generated run material.

The server implements JSON-RPC MCP initialization, tool listing, calls, and ping. Tool definitions
are in `docs/schemas/retrieval-mcp-tools.json`. Application code should instantiate
`RetrievalCore` instead of calling the MCP process.

The live smoke in `tests/test_retrieval_core.py` starts a fixture server and invokes the core tool
set, while `tests/test_retrieval_artifacts.py` exercises artifact queries through both the core and
stdio transport.
Top-level tool-call spans and nested retrieval spans appear in `data/logs/pipeline.jsonl` under the
run. One transport call produces one `MCP_TOOL_COMPLETED` metric event even when it invokes several
internal retrieval operations.

`query_build_security` reads only accepted immutable `build_security` shards. It supports exact
project, build-root/action, configuration, compile-unit, linked-artifact, producer, and shard
scopes. Results include only redacted normalized command facts; protected exact argv artifacts are
never returned through MCP.

`query_artifacts` reads only accepted `artifacts`, `observations`, and `evidence` shards. Exact
filters cover canonical artifact identity or SHA-256, kind, format, language/runtime, platform,
architecture, build unit, project/component, producing build-action identity, package/PURL,
scanner/tool identity, coverage status, and shard. Responses retain the accepted run and manifest
identity plus every physical shard's schema, hash, fingerprint, and shard id. Serialization strips
protected command data, raw scanner artifacts, stdout/stderr, credentials, and source/model text.
The tool cannot read or download artifact bytes, extract archives, accept a filesystem path,
execute a target, or run caller-supplied SQL, regular expressions, globs, or shell commands.
Missing scanner or shard coverage is reported as a gap.

`query_owasp_workbench` is pinned to the MCP session's run and reads only that run's accepted OWASP
shard manifest. It scopes by standard/version/profile, control, component, project, evidence mode,
validator, batch, disposition, or shard and returns explicit pagination, truncation, ambiguity, and
coverage gaps. A run without an accepted workbench manifest returns an availability gap, not an
empty-coverage claim.

`query_design_artifacts` reads only the accepted `analysis/design_artifacts` shard. Exact filters
cover taxonomy category and subtype, cataloged state, and probe status. `path_prefix` is a
normalized literal folder prefix, never a glob. Name-only binary documents and probe bounds are
returned as coverage gaps. A run without design discovery returns an availability gap. See
[`../architecture/design-artifact-discovery.md`](../architecture/design-artifact-discovery.md).

`search_design_content` is bm25 full-text search over the accepted `analysis/design_content`
chunks only. It can be filtered by category, literal path prefix, chunk kind, and converted state.
Cataloged hits resolve through `read_excerpt`. Converted-document hits carry their hash-pinned
text-artifact identity, character range, and bounded `converted_excerpt`.
`query_interface_operations` filters declared HTTP, async, gRPC, and GraphQL operations by exact
protocol, method, literal route prefix, effective security state, scheme, streaming, operation id,
and artifact path prefix. See
[`../architecture/design-content-index.md`](../architecture/design-content-index.md).

`query_ci_configuration` reads only accepted `ci_*` observation shards and the canonical
`ci_findings` evidence shard. Exact filters cover provider, pipeline, workflow, stage, job, step,
tool, rule, category, canonical finding, and shard. Unavailable linter branches are returned as
coverage gaps; the tool never scans the target tree or reads an evaluator guide.
