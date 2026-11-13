---
title: "Operating the read-only operator MCP gateway"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: ["job_code_graph_index", "job_review_data_indexing", "job_review_prioritization"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Operating the read-only operator MCP gateway

The gateway selects exactly one **application run**, even when that run has not reached index
acceptance. Accepted-evidence queries still require verified acceptance; operator inspection never
turns missing state into accepted evidence. It does not build indexes, execute recovery, or change a
run. It is for external clients; the review cells (red, blue, verifier, hunter) do not use it and have
no tools, because the application runs their retrieval requests in-process (see
[`../architecture/retrieval-surfaces.md`](../architecture/retrieval-surfaces.md)).

Start it over stdio:

```text
appsec-review-mcp --runs-dir runs --run-id <application-run-id>
```

For a stricter deployment pin, copy the `manifest_sha256` from
`runs/<run-id>/data/indices/accepted.json` and add:

```text
--manifest-sha256 <64-lowercase-hex-digest>
```

An application ID has the form `YYYY-MM-DD-NNNN`; a Dagster dispatch is a separate UUID.
There is no `latest` selection. Startup rejects invalid selection or endpoint configuration.
`inspect_run` distinguishes missing runs, unaccepted index state, unsupported pointer versions and
verified acceptance. Evidence calls fail when the accepted pointer/handoff is absent, the handoff
is not accepted, the pin differs, a path escapes the run, or a manifest/index hash or embedded
identity differs. The first verified manifest binds the session when no explicit pin was supplied;
later calls cannot silently switch to another accepted manifest. Those failures require repairing
or rerunning the producer; operators must not edit generated run material.

The server implements JSON-RPC MCP initialization, tool listing, calls, and ping. Tool definitions
for accepted retrieval remain in `docs/schemas/retrieval-mcp-tools.json`; the operator additions
are in `src/appsec_review/mcp/operator_schema.py`. The served catalog is their union, not a second
service. Application review code should instantiate `RetrievalCore` instead of calling the MCP
process. The operator supplies a diagnostic-only audit sink: reading an observed run does not
append pipeline events or change receipts. Existing in-process retrieval retains its run-local
audit behavior.

## Explicit client registration

No unconditional `.mcp.json` is installed. Generate a configuration only after selecting the run:

```sh
python -m appsec_review.mcp.configuration --run-id <application-run-id> \
  --runs-dir runs --manifest-sha256 <64-lowercase-hex-digest>
```

This prints JSON and writes no configuration. The optional manifest argument can be omitted.
The `mcpServers` client configuration shape is:

```json
{
  "mcpServers": {
    "appsec-review": {
      "command": "appsec-review-mcp",
      "args": ["--runs-dir", "runs", "--run-id", "<application-run-id>"]
    }
  }
}
```

Replace the placeholder using the generator before registering; it is deliberately not a live
run ID. Register the generated entry in the external development agent's project-scoped MCP
configuration or UI, according to that client's documented format. Ensure that client resolves
the executable in the checkout's environment and its `runs` path from the intended working
directory; supply an explicit locally chosen runs directory when the client's working directory
is different. Do not commit workstation paths or credentials. The generator never reads global
agent settings, selects a run, installs a service, or installs tools into review-worker transports.

An optional `--dagster-endpoint <trusted-graphql-endpoint>` enables `inspect_dagster`. Configure
only an endpoint administered by the operator; it is disabled by default. The tool takes an exact
`dispatch_id`, never a URL or GraphQL text. Its fixed read query verifies that the returned
dispatch's application tag matches the selected application run. HTTPS is required except for
explicit loopback HTTP. Credentials in URLs, redirects, ambient proxies, query strings and URL
fragments are refused. Authentication-header and arbitrary query/mutation support are intentionally
absent. Network access occurs only when that tool is called, not at registration or initialization.

## Triage and recovery

| Tool | Scope and result |
| --- | --- |
| `inspect_run` | Exact selected application run and accepted-index availability; no lifecycle inference. |
| `list_jobs` | Bounded pages of job identities in this run. Existence is not acceptance. |
| `list_attempts` | One exact job's attempts; never automatically chooses its latest attempt. |
| `inspect_attempt` | Exact job/attempt status, failure class, status-byte identity and protected failure references. |
| `read_logs` | Bounded structural events with exact job/attempt/level/event-type filters and byte/hash references. |
| `inspect_recovery_plan` | An exact recorded `RESUME_PLANNED` event selected by the log reference's `offset` and `sha256`. |
| `inspect_dagster` | Exact UUID at the startup-configured endpoint, with independently verified application binding. |

Accepted artifact discovery and coverage use the existing `query_artifacts`, `coverage` and
`query_dataset_inventory` tools. No tool reads arbitrary files, executes SQL/shell/GraphQL supplied
by a caller, returns archive bytes, or exposes protected stdout/stderr, command data, failure
message text, or tracebacks. Log pages intentionally expose only sequence, event type, level,
job/attempt identities and resolving byte references. Status/plan references are observations of
operational records, **not** accepted artifacts or proof of current restart safety.

For a failed run, inspect the exact attempt, page `read_logs` with
`"event_type": "RESUME_PLANNED"`, then pass the chosen reference's `offset` and `sha256` to
`inspect_recovery_plan`. The latter projects the existing resume planner's recorded decisions;
it does not instantiate another planner, rescan the target, compute fresh admission or dispatch a
job. Original decision reasons are protected. Missing or truncated decisions remain named gaps.
A historical plan may be stale. No plan is manufactured when no planner event exists.

The plan provides actual CLI entry points and `tests/test_wave1_resume.py` as a baseline regression
reference. The exact repair-specific unit selectors, build failure context, candidate, prepared
image and replay references still require operator selection; the service cannot invent them.
`plan-resume` itself emits telemetry and requires an explicit target/system, so it is deliberately
not executed by this read-only service. Recipe replay, promotion, job execution and restarts remain
separately authorized manual operations.

Development procedures are canonical in
[`run-triage-and-repair`](../../.claude/skills/run-triage-and-repair/SKILL.md),
[`add-a-job-contract`](../../.claude/skills/add-a-job-contract/SKILL.md),
[`add-runtime-guidance`](../../.claude/skills/add-runtime-guidance/SKILL.md), and
[`codeql-release-recompile`](../../.claude/skills/codeql-release-recompile/SKILL.md).
They reuse existing coordination/docs procedures. They are never runtime-worker guidance.

## Protocol and bounds

The server negotiates MCP `2025-06-18`, implements a complete single-page catalog and preserves
JSON-RPC IDs. Notifications receive no response and never dispatch tools. Unsupported methods,
invalid request shapes and invalid parameters are JSON-RPC errors. Known tool execution failures
are MCP `isError: true` results with stable codes; unexpected server failures are internal errors.
Neither protocol errors nor stderr diagnostics echo exception messages, user paths or raw data.
Stdio stdout contains JSON-RPC only.

Each input frame is at most 128 KiB and 32 JSON nesting levels; duplicate keys, non-finite numbers,
invalid UTF-8 and batches are rejected. Oversized frames produce a bounded error and terminate
the stream instead of draining an unbounded input. Responses are at most 1 MiB. Logs scan at most
1 MiB per page and enforce the producer's 64 KiB event bound. Directory inventories examine at
most 4,096 entries; larger inventories fail explicitly rather than claim complete coverage.
Individual operational JSON documents are limited to 1 MiB.

Page sizes are 1-100. Operator cursors are authenticated with a session-private key, expire after
five minutes, and bind the application run, manifest, tool and exact supplied filters/page size.
They cannot move between clients. A log or directory changed since a page was read invalidates its
cursor: restart pagination explicitly. No follow loop runs. A torn final log record is withheld
with a gap; malformed complete records, sequence gaps, schema mismatches and foreign-run records
fail. A bounded scan with no matching rows is not proof that matching events do not exist.

## Manual interoperability validation

Offline units dispatch directly; they do **not** establish stdio/service interoperability.
The following suites are written for explicit future user authorization and were **NOT RUN** for
this package:

```sh
.venv/bin/python -m pytest tests/integration/test_operator_stdio.py \
  tests/integration/test_operator_dagster.py \
  --basetemp=test/tmp/operator-mcp-manual-integration
.venv/bin/python -m pytest tests/acceptance/test_operator_triage.py \
  --basetemp=test/tmp/operator-mcp-manual-acceptance
```

Prerequisites: an isolated Linux checkout/environment with test dependencies, permission to start
fixture stdio processes and the isolated fake Dagster HTTP service, and no active review using that
checkout. These fixtures need no live run, model, credentials, container or provisioned service.
Existing mixed legacy stdio smoke cases in `test_retrieval_core.py` and `test_retrieval_artifacts.py`
also remain manual. Default integration/acceptance/live collection exclusions are unchanged.

The stdio gateway and plain `RetrievalMcpAdapter` are operator interfaces. Review workers must
receive only `ScopedRetrievalMcpAdapter` with a package and role capability issued from a verified
run-owned review package. It checks package identity and permitted entities on every call and
denies broad search and cross-package retrieval. A `query_code_graph` row outside the package's
exact entities is returned only when its accepted `payload.scope.scope_id` is one of the package's
`retrieval.graph_scopes`; the identities such a row references become addressable for the rest of
the session. Any other row fails the call. The package contract and current bounds are in
[review-package-contract.md](../architecture/review-package-contract.md).

`query_syntax` is the build-independent syntax fallback over accepted Tree-sitter `analysis`
shards. Its closed modes are `definitions`, `calls`, `imports` and `references` (identifier
occurrences, not semantic references). It requires an exact source-file or AST identity, accepts
an optional exact written name, and shares bounded pagination and manifest pinning. An AST
subject further limits the byte span. A signed package's exact source-file identities authorize
only returned nodes of those files; no CodeQL graph scope is required. The node identity can
then be passed to `find` or `read_excerpt`. Names, imports and call targets stay unresolved, and
every answer names syntax-only limitations rather than claiming semantic flow evidence.

The legacy live smoke in `tests/test_retrieval_core.py` starts a fixture server and invokes the
core tool set, while `tests/test_retrieval_artifacts.py` includes a stdio case. Do not run those cases
as offline units. Plain in-process `RetrievalMcpAdapter` calls retain top-level and nested
`data/logs/pipeline.jsonl` spans; the read-only operator transport instead sends audit diagnostics
outside the observed run.

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
empty-coverage claim. Complete pinned catalogs are not full assessment coverage: only four narrow
Python static procedures are implemented; qualification/unsupported/unresolved rows remain
explicit. The MCP-only query is not a review-cell tool. Review cells instead receive the accepted
PRECOMPUTED `control_evidence` projection in provisional lead/hunt packages, then retrieve original
evidence through scoped in-process tools. Every PRECOMPUTED interpretation is indirect for every
final predicate; tags, control labels and source identity alone cannot prove a vulnerability.

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
`reference_intelligence`, `symbol_links`, `document_context`); the unpublished sets
(`hotspot_context`, `review_package`, `redacted_secret_exposure`, `contract_enforcement`,
`deployment_exposure`, `test_intent`; `QUERY_SETS` in `retrieval/precomputed.py`) return an
unavailable gap until they are built. The former graph sets
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
Seeded Clang-Tidy and Static Analyzer observations add four optional filters: `seed` (`path:line`, a
ledger location the diagnostic was labelled against), `function` (the IR function holding it),
`fix_it` (boolean; a fix-it is reported, never applied) and `min_trace_length` (analyzer path steps).
An observation without those fields never matches them; malformed values fail with
`invalid observation filter: <name>`.

`query_codeql_neighborhood` also accepts `include` values `flow` (LLVM IR blocks, edges, dominators and
def-use and, where Clang's CFG dump matched, the source-level `source_cfg`, with the seed's block and its
dominators), `diagnostics` (analyzer results with traces), `symbols` (clangd symbols in their own `clangd`
identity space, never a raw USR, cross-referenced to the CodeQL symbol) and `cpg` (Joern functions with
name-matched calls, branches and reaching-definition counts; absent with a `producer_not_run` gap while the
deprecated Joern job is not enabled). A function the producers did not cover is an `outside_precomputed_neighborhood` gap.
Grants follow the scope check of the graph path. Contract: `docs/architecture/seeded-neighborhoods.md`
section 9.


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
