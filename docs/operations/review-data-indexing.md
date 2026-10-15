# Operating review-data indexing

`job_review_data_indexing` precedes `job_review_package_assembly` in both the direct review graph
(`appsec-review start`) and the Dagster `wave1_review` graph. It follows `job_code_graph_index` in
both, and `job_security_tagging` in Dagster. It accounts for every
dataset the run produced, restores shards a manifest rewrite dropped, publishes cross-domain links
and the stage-1 precomputed query sets, and publishes the dataset inventory as an indexed dataset.
The design is in [`indexing-and-query-reuse.md`](../architecture/indexing-and-query-reuse.md).

The job reads only the accepted retrieval manifest, accepted handoffs, the run-owned resolved
configuration and hash-verified run-owned artifacts. It never parses raw scanner output, LLVM IR
or a CPG, never runs target code, and never adds a search service. MCP reads only the accepted
immutable shards it publishes.

`job_target_catalog.retrieval_indexes.build_target_documents` runs earlier in both graphs. It
consumes the catalog's hash-pinned file inventory and publishes the `documents` shard into the
accepted catalog manifest. This indexing job carries that shard forward and audits its dataset
declaration. Use `search`, `find`, and `read_excerpt` with `index=documents` to inspect declared
OpenAPI operations and target-owned test/document intent. Missing files and unsupported formats
appear as coverage gaps; neither a design statement nor a test is observed enforcement.
`precompute.document_context` groups exact method/route and trust-boundary identifiers from the
accepted document shard. Query it with `query_precomputed(query_set="document_context")`; its facts
are review context, and unmatched declarations or requests are named gaps, not findings. See the
[document analysis design](../architecture/document-evidence-analysis.md).

## Steps

| Step.task | Output | Notes |
|---|---|---|
| `load.accepted_inputs` | `accepted-inputs.json` | Verifies the accepted manifest and target snapshot, reads every registered job's accepted handoff, restores shards a producer published but a later manifest rewrite dropped, reports shard conflicts, reads resolved job topology, pins global reference feeds and records the OWASP workbench status. |
| `links.cross_domain` | `links/links-*` shards | Five link families: `representation`, `finding_source`, `package_advisory`, `symbol_syntax`, `history_code`. Exact links need equal identity, hash or byte span; name/line/hash-only joins are separate ambiguous relations carrying their method and confidence. |
| `precompute.<query_set>` | `precomputed/qs-<query_set>` shards | One immutable shard per stage-1 set: `build_provenance`, `artifact_inventory`, `dependency_advisories`, `scanner_correlation`, `ci_trust`, `history_context`, `control_evidence`, `reference_intelligence`, `symbol_links`, `document_context`. |
| `fts.image_validation` | `data/indexing/fts/<attempt>/` | Offline cross-check of this job's shard text with the pinned `tool-sqlite-fts` image (see below). |
| `audit.inventory` | `inventory.json` | Publication completeness audit. A violation fails the job and blocks index acceptance; the report stays on disk. |
| `matrix.coverage` | `coverage-matrices.json` | Language, build-unit, producer/consumer and input-source matrices plus the follow-up query-set list. The `code_graph` lane is computed from accepted `graph` shards (see below). |
| `publish.inventory_index` | `inventory/dataset-inventory` shard and manifest | Accepted manifest = upstream shards + restored shards + link, product and inventory shards. |

All bounds are in `[jobs.job_review_data_indexing.settings]` in `appsec-review.toml`.

## Publication audit

Each registered job declares its outputs in `src/appsec_review/jobs/<job>/datasets.py`
(`DatasetDeclaration`, attached to `Job.datasets`). The audit enumerates the registry and the
run-owned resolved configuration, scans the run-owned `data/` tree (bounded by `max_run_files`),
re-hashes every handoff artifact, and summarises every accepted shard
(row counts are recomputed, not trusted). It emits one row per dataset with its disposition
(`indexed`, `artifact_only`, `protected`, `unavailable`), query route, exception reason, producer
attempt, shard or artifact references and coverage state.
Files the job runtime writes for every job are claimed as runtime receipts: attempt claims, status,
results, handoffs and logs, per-task receipts, and the `inputs/retrieval-manifest.json` that
`JobRunner` pins into an attempt inheriting more than one upstream index lineage.
The inventory also records this job's own reports and shard. Its own shard row names the
`inventory/dataset-inventory` identity; the shard's SHA-256 resolves through the verified accepted
manifest because a shard cannot contain its own content hash.

Violation codes: `undeclared_job`, `unknown_step`, `undeclared_shard`, `ambiguous_shard_claim`,
`shard_without_registered_producer`, `shard_counts_disagree`, `dangling_artifact`,
`artifact_hash_mismatch`, `unaccounted_handoff_artifact`, `unaccounted_file`,
`run_tree_truncated`, `run_tree_unreadable`, `snapshot_mismatch`, `missing_required_output`,
`shard_conflict`, `indexed_without_route`, `exception_without_reason`,
`registry_configuration_mismatch`, `duplicate_dataset_id`. Warnings (`unreferenced_index_files`,
`upstream_not_run`) do not block
acceptance. A restored shard is recorded as a repair.

When the audit fails, read `data/jobs/job_review_data_indexing/attempts/<attempt>/steps/audit/tasks/inventory/inventory.json`,
fix the producer declaration or the producer, and resume the graph. Do not widen a declaration to
silence an unknown output.

## Code-graph coverage

Code-graph facts are not precomputed query sets. The former `call_graph`, `control_flow`,
`dataflow`, `sarif_correlation`, `ast_ir_cpg_mapping`, `guards_ranges` and `entrypoint_paths`
sets are retired: `query_precomputed` rejects them as invalid, and graph facts are read through
`query_code_graph` over the `graph` index
([code-graph precomputation](../architecture/code-graph-precomputation.md)).

This job only accounts for the graph. The `code_graph` lane of the language and build-unit
matrices reads the accepted `graph` shards of `job_code_graph_index` (one per scope and fact
family; the shard's producer names `family`, `language` and `scope_id` or `build_unit_id`) and
their coverage rows. A family is `complete` only when every coverage row is complete; the lane is
`complete` only when all seven families are. With no accepted `graph` shard (including while
`job_code_graph_index` is not registered or did not run) the lane is `unavailable` and its basis
says so; that is a coverage gap, never evidence that the code is clean. A language without a
CodeQL graph export pack (every language but C/C++ today) has `graph` shards whose rows are all
`unavailable`, so its lane is `unavailable` with the basis "every fact family unavailable".
`cpg_graph` stays `unavailable`: Joern is deprecated and disabled by default, and a retained Joern
CPG is not graph coverage.

The inventory audit accounts for `job_code_graph_index` like any producer: its `code_graph_facts`
shards (including coverage-only `unavailable` ones) and its `artifact_only` stage, checkpoint and
summary files, and `job_codeql_analysis`'s `codeql_graph_export` directory. Because
`job_codeql_analysis` rewrites the accepted manifest to its own shards, `load.accepted_inputs`
restores every dropped shard from its producer's accepted handoff (`restored_shards`).
`tests/integration/test_code_graph_end_to_end.py` runs this job after the real CodeQL and graph
jobs and checks the Python `code_graph` lane.

The `graph_follow_up` cells list the query sets this job does not produce (`hotspot_context`,
`review_package`, `redacted_secret_exposure`, `contract_enforcement`, `deployment_exposure`,
`test_intent`) with status `pending_follow_up`; `hotspot_context` and `review_package` also carry
the per-language `code_graph` states they would compose.

## SAST lead menus

`scanner_correlation` holds one `lead` fact per accepted source-SAST observation (category
`source_sast` and every CodeQL result) with native severity, normalized *reported* severity
(`appsec-review/reported-severity/1`), the normalization basis, inline-suppression state matched
from accepted prioritization syntax facts, duplicate relationship (same exact line and CWE, or same
scanner rule), flow identities and resolving location. `menu` facts list every High/Critical lead,
including suppressed and duplicate ones, per component in partitions of `menu_partition_size`; an
unknown native severity has its own menu and is never read as low. An `audit` fact records
counts; the job fails if any High/Critical or unknown-severity lead is missing from its menu, and a
lead menu that would exceed `max_facts_per_product` fails instead of truncating. Scanner severity
orders attention only.

## Build facts

`build_provenance` combines artifact-anchored source→build→artifact→observation chains with one
`build_action` fact per accepted language-build action. Command facts follow the
`review-package` command schema: every argv token keeps its ordinal and a kind; only
allowlisted values survive (security flags, optimization/debug/standard flags, safe defines,
library names); host paths become `target:`/`relative:` logical identities or `<external-path>`;
response files, linker arguments and unknown positional values are redacted. Environment facts
report security classes (`toolchain_selection`, `compiler_flags`, `loader_injection`,
`search_path`, `reproducibility`, `build_mode`, `network_proxy`, `package_registry`,
`sensitive_variable`) with presence and allowlisted values only. Exact argv/envp are read at job
time from the hash-verified protected capture (`events.jsonl`) and are never indexed; the fact
carries its hash.

## Offline FTS image validation

`fts_image_validation` is `disabled`, `optional` (default) or `required`. The worker exports the
FTS documents of this job's link and product shards as bounded JSONL, then runs the pinned
`tool-sqlite-fts:1.0.0` image (`probe`, `build`, `verify`) through `ContainerExecutor` (no network,
read-only root and target mount, dropped capabilities). It verifies the executed image ID against
the catalog pin, compares record count, input hash and deterministic probe terms with the
in-process shards, and keeps the image database only as a validation receipt. An unavailable image
records a named gap in `optional` mode and fails the job in `required` mode. Accepted shard text is
exported verbatim because retrieval already exposes it; documents whose text matches secret
patterns are counted as a gap against the producing shard.

## MCP routes

- `query_dataset_inventory` — bounded catalog of dataset rows, the audit record and coverage
  cells (`language`, `build_unit`, `producer_consumer`, `input_source`, `query_set`,
  `graph_follow_up`, `fts_validation`).
- `query_observations` — accepted observation shards filtered by scanner, rule, normalized
  reported severity, observation class, suppression/duplicate state, source or artifact identity
  and exact path/line range; returns native severity and the normalization rule. Suppression and
  duplicate filters need the accepted `scanner_correlation` shard; without it the response is empty
  with a named gap.
- `query_precomputed` for every stage-1 set; `find`/`trace` with `indexes=["links"]` for links.

## Reuse

Link and product shards are keyed by rule version, the exact upstream shard identities they read,
pinned feed and OWASP identities, extra run-owned inputs and the settings they depend on. A
verified checkpoint under `data/indexing/checkpoints/` reuses an unchanged shard; changing one
rule rebuilds only that shard.
