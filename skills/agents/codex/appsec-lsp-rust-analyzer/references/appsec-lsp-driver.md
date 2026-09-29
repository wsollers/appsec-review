# lsp_driver.py output (`appsec-review/lsp-query-result/1`)

Source: `appsec-review-process/lsp_driver.py`; tests: `appsec-review-process/tests/test_lsp_driver.py`.

```
{"schema": "appsec-review/lsp-query-result/1",
 "server": {"name", "argv", "info": {"name", "version"}, "exit_code", "stderr_bytes", "notifications"},
 "root", "limits", "status": "OK" | "OK_WITH_GAPS" | "FAILED",
 "capabilities": {"definition": bool, ...},
 "results": [{"query_index", "query", "status": "OK" | "GAP", "results": [...],
              "dropped_outside_root", "truncated"}],
 "gaps": [{"kind", "detail", "query_index"?}]}
```

Result rows: `definition`/`references` give `{path, start_line, start_character, end_line,
end_character}`; `documentSymbol`/`workspaceSymbol` add `name`, `kind` (LSP SymbolKind) and
`container`; call hierarchy rows add `name`, `kind` and `call_lines`.

Gap kinds: `server-missing`, `server-start-failed`, `initialize-failed`, `protocol` (crash,
malformed or oversized message), `timeout`, `unsupported` (capability not advertised),
`server-error` (JSON-RPC error; only the numeric code is kept), `path-outside-root`,
`file-too-large`, `invalid-query`, `truncated`, `root-missing`.

What is never in the output: server stderr, log messages, error message text, hover text or file
contents. Locations outside `--root` (system headers, SDKs, dependency caches) are counted in
`dropped_outside_root`, not listed.
