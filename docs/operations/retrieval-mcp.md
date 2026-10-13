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

The stdio gateway and plain `RetrievalMcpAdapter` are operator interfaces. Review workers must
receive only `ScopedRetrievalMcpAdapter` with a package and role capability issued from a verified
run-owned review package. It checks package identity and permitted entities on every call and
denies broad search and cross-package retrieval. A `query_code_graph` row outside the package's
exact entities is returned only when its accepted `payload.scope.scope_id` is one of the package's
`retrieval.graph_scopes`; the identities such a row references become addressable for the rest of
the session. Any other row fails the call. The package contract and current bounds are in
[review-package-contract.md](../architecture/review-package-contract.md).

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
shard manifest. It scopes by shard `family` (`standards`, `component-classification`,
`applicability`, `validation-work`, `control-result`, `finding-package`), standard/version/profile,
control, component, project, evidence mode, validator, batch, disposition, or shard and returns
explicit pagination, truncation, ambiguity, and coverage gaps. A run without an accepted workbench manifest returns an availability gap, not an
empty-coverage claim.

`query_codeql` reads only accepted `observations` shards whose shard id starts with `codeql-`.
Exact filters cover CodeQL language, original source language, scope, build unit, rule, level,
path, and shard. Missing CodeQL shards and non-complete shard coverage are returned as gaps; see
[`codeql-analysis.md`](codeql-analysis.md).

`query_change_context` reads only the accepted `history/change-context` shard and returns
change-context priority records in rank order, filtered by scope (`file`, `function`, `component`),
exact path, component, or a non-zero signal. Every incomplete source (review records, deployments,
schedule, test association, organization data, function attribution, fix-on-fix) is returned as a
coverage gap. Records order review work and are never findings; see
[`change-context-analysis.md`](change-context-analysis.md).

`query_ci_configuration` reads only accepted `ci_*` observation shards and the canonical
`ci_findings` evidence shard. Exact filters cover provider, pipeline, workflow, stage, job, step,
tool, rule, category, canonical finding, and shard. Unavailable linter branches are returned as
coverage gaps; the tool never scans the target tree or reads an evaluator guide.

The `priority` index holds `job_review_prioritization` output: `priority_item` entities for the
indexed top files and functions (full feature vector, percentiles, missing features, coverage, rank,
and score) and `review_signal` entities for their linked evidence. Query it with the generic
`search`, `find`, `trace`, and `coverage` tools and `"indexes": ["priority"]`. A ranked item orders
review attention and is never a finding; examples are in
[`review-prioritization.md`](review-prioritization.md).

`query_hotspots` returns those priority items in rank order with exact scope/path and minimum-score
filters. Each result includes the stored feature vector, evidence identities, and resolving source
location. It reports absent or partial priority coverage as a gap.

`query_precomputed` reads only accepted `precomputed` shards for an allowlisted query set. The
sets cover builds, artifacts, advisories, scanner correlation, CI, history, controls, reference
intelligence, documents and review packages; the complete list and product contracts are in
[`indexing-and-query-reuse.md`](../architecture/indexing-and-query-reuse.md).
`job_review_data_indexing` publishes the stage-1 sets (`build_provenance`, `artifact_inventory`,
`dependency_advisories`, `scanner_correlation`, `ci_trust`, `history_context`, `control_evidence`,
`reference_intelligence`, `symbol_links`, `document_context`); the stage-3 sets (`hotspot_context`,
`review_package`) return an unavailable gap until they are built. The former graph sets
(`call_graph`, `control_flow`, `dataflow`, `sarif_correlation`, `ast_ir_cpg_mapping`,
`guards_ranges`, `entrypoint_paths`) are retired and rejected as invalid; use `query_code_graph`.
It never executes analyzers or target code during retrieval.

`query_code_graph` reads only accepted `graph` shards published by `job_code_graph_index`
([`code-graph-index.md`](code-graph-index.md)). It takes a closed `mode` (`callers`, `callees`,
`sinks`, `entry_points`, `paths`, `guards`, `ranges`, `summary`, `sarif_path`), an exact
`subject` identity whose kind the mode accepts, and optional `depth` (`callers`/`callees` only),
`sink_class`, `source_class`, `limit` and `cursor`. It accepts no path, name, language or free
text. `depth` is capped by `jobs.job_code_graph_index.settings.graph.max_call_depth` as bound to
the run (`data/configuration/resolved.json`; a changed resolved configuration fails startup) and by
the core's depth limit. Every response carries the scope's coverage rows; a bound reached is
`truncated` with a named gap, and a scope or family without an accepted shard returns `[]` with an
unavailable gap, never a claim of absence. `sarif_path` returns the `dataflow_path` facts
correlated with a CodeQL observation and their `bridged`/`partial` state; a `broken` correlation
returns a gap and no path. The tool never runs CodeQL or any analyzer.

`query_observations` filters accepted observation shards by exact scanner, rule, normalized
reported severity (`critical`, `high`, `medium`, `low`, `info`, `unknown`), observation class,
suppression and duplicate state, source-file or artifact identity, and exact path with an optional
line range. Each result carries the native severity, normalized value, normalization basis and
rule (`appsec-review/reported-severity/1`) and its lead state. Results order by reported severity
and are tool observations, never confirmed findings. Non-complete scanner coverage is returned as
gaps; suppression and duplicate filters need the accepted `scanner_correlation` shard.

The `links` index holds `job_review_data_indexing` cross-domain link shards in five families
(`representation`, `finding_source`, `package_advisory`, `symbol_syntax`, `history_code`). Query it
with `find` and `trace` and `"indexes": ["links"]`; non-exact joins remain separate ambiguous
relations carrying their method and confidence.

`query_dataset_inventory` is the bounded catalog of the accepted dataset inventory: one record per
dataset (disposition, query route, exception reason, producer attempt and coverage), the
publication audit, and coverage cells for languages, build units, producer/consumer edges, the
input-source matrix, query sets, the `code_graph` lane, follow-up query sets and offline FTS
validation. Operation
details are in [`review-data-indexing.md`](review-data-indexing.md).

`coverage` pages accepted shards and reports each shard's sanitized producer, entity and
relation counts by kind, and coverage rows.
