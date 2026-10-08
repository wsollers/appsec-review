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

The live smoke in `tests/test_retrieval_core.py` starts a fixture server and invokes all six tools.
Top-level tool-call spans and nested retrieval spans appear in `data/logs/pipeline.jsonl` under the
run. One transport call produces one `MCP_TOOL_COMPLETED` metric event even when it invokes several
internal retrieval operations.
