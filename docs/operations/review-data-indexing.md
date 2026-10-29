# Operating review-data indexing

`job_review_data_indexing` precedes `job_review_package_assembly` in both the direct review graph
(`appsec-review start`) and the Dagster `wave1_review` graph. It follows `job_code_graph_index`,
`job_security_tagging` and the default-enabled OWASP assessment when those jobs are enabled on either
surface. It accounts for every
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
OpenAPI/Swagger HTTP operations, AsyncAPI, gRPC and GraphQL declarations, bounded full-text
document chunks, and target-owned test/document intent. Chunks and operations retain inclusive
source-line and byte spans. Non-HTTP declarations remain searchable records; they are not promoted
to HTTP route-context candidates. Missing files and unsupported formats
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

### OWASP projection and custody

The shared enabled direct/Dagster order is tagging/tag cloud → OWASP → this job → package assembly →
hunt/red-blue/independent verification. The OWASP job is enabled by default; if explicitly
disabled, its absence produces
an unavailable `control_evidence` gap, not full coverage. Qualification-only publications remain
explicitly non-production-eligible.

`precompute.control_evidence` authenticates the accepted OWASP manifest/shards, re-resolves original
typed citations against its pinned accepted upstream snapshot, and uses the publication's
`assessment_bounds.max_source_lines` rather than silently reverting to a default cap. Deep
obligations, independent counterevidence, dissent and custody remain lossless in the immutable
workbench authority; index summaries carry hash-pinned authority links instead of depth-truncated
copies. Later lead/hunt assembly expands and verifies that authority with operation-local reuse,
not a persistent verification bypass. Duplicate-row ambiguity still fails expansion.

Only eligible, source-anchored adverse assessment hypotheses become provisional `owasp_control`
leads. `not_satisfied` does not mean exploitable; `satisfied` does not mean component safety.
Unsupported/`not_assessed`/failed/`cannot_verify` outcomes remain unresolved coverage, not failures.
Every PRECOMPUTED interpretation is indirect for **every** final predicate. Downstream
red/blue/verifier roles retrieve underlying evidence and establish their own predicates.
See [OWASP operations](owasp-control-assessment.md) for mode, receipts and denominator accounting.

## Publication audit

The following deep-audit description applies to `strict` customer-evidence assurance. Explicit
`first_party_managed` runs instead authenticate producer admission records and account for
accepted publications without enumerating scratch or revalidating admitted shard rows. Reports
identify the audit scope and the omitted scratch assurance. Supplied platform payloads are excluded
in both modes. See [performance and assurance](performance-assurance.md) for custody, release IDs,
package validation and rollback.

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

File ownership and publication requirements have separate scopes. File ownership includes every
registered job present in the run-bound configuration, including downstream and disabled jobs.
Only enabled producers in the indexing stage participate in required-output checks, accepted
handoff reconciliation and coverage rows. A resume can therefore retain downstream receipts,
document ledgers and inference artifacts without either treating them as stray files or accepting
them as current evidence. Unknown jobs and files outside a declared pattern still fail the audit.

Every new attempt's `claim.json` pins a hash-checked `dataset_contract` containing its output
declarations and step topology. Files under that attempt are matched against the pinned contract,
not a later implementation's declarations. Successful handoffs also hash-pin `claim.json` as an
artifact, so later alteration invalidates accepted-artifact verification and resume reuse.
Older attempts without this field use the current
registered declarations and are explicitly labeled `current_declarations_legacy_attempt`; their
claims are not rewritten. A missing claim is a provenance warning; a malformed, mismatched or
hash-invalid claim is an audit violation.

The report's `file_ownership` groups files by job, step, output kind and producing attempt.
Each group records the count, bytes, deterministic path/size listing hash, bounded example paths,
claim path/hash, contract basis and originating Dagster run ID. The unique producer key is the
application run ID plus job ID plus attempt ID; the existing Dagster UUID identifies the graph
invocation. No additional UUID is needed. Ownership is accounting metadata, never an accepted
handoff or proof of successful coverage. Aggregate artifact rows do not attribute all historical
files to the latest accepted attempt.

Dagster node names identify lifecycle/task locations, not separate invocations. Shared publication
allows the node name to differ between begin and task execution within the same identified Dagster
run, while still requiring matching application run, job, attempt and all other orchestration fields.
The immutable claim and shared receipt retain the original begin-node correlation; task receipts
retain the actual executing node. Direct execution and uncorrelated contexts retain exact matching.

Files outside attempt directories are explicitly `shared_or_run_scoped` with no inferred attempt
or Dagster ID. Their content identity is separate from attempt provenance. For the migrated
outputs below, immutable attempt receipts provide that provenance; legacy layouts cannot prove
which invocation first created a file. Declared ownership does not manufacture that history,
and the listing hash is not a content-integrity hash.

### Shared immutable objects and attempt receipts

The supported producers/consumers include lead-triage model results, review-data indexing's derived
link/product/inventory shards and checkpoints, document-issue ledgers, review cells and their
judge/verifier checks, shared v3 packages, pinned guidance, and producer SQLite/OWASP indexes.
New bytes live once
per run at `data/shared/objects/<sha256>`; the SHA-256 covers the **exact file bytes**. JSON
producers use sorted compact UTF-8 JSON with one trailing newline. SQLite objects retain their
exact database bytes. Private objects are never shared between application runs. Public reference
snapshots use the independently retained publication records described below.

Each producing or consuming attempt writes
`data/jobs/<job>/attempts/<attempt>/shared/<namespace>/<fingerprint>.json`.
The `appsec-review/shared-receipt/1` receipt records the application run/job/attempt, original
orchestration correlation (including the actual Dagster invocation when present), hash-pinned
claim, computation identity, object and dependency hashes, and `computed` versus `reused`.
Fresh computation is still `computed` when the physical bytes already exist. Objects themselves
do not claim a first producer: separate computations may independently produce identical bytes.
A reuse receipt references the original computed receipt, never a later invocation's identity.
Job-level reuse without executing another attempt continues to use orchestration receipts; it
does not relabel the original claim or invent an additional computation.

`data/shared/requests/<namespace>/<fingerprint>/<producer-receipt-sha256>.json` is an immutable
lookup entry, not accepted evidence. A fingerprint identifies inputs/configuration/rules and,
for triage, model/guidance/prompt identity; it does **not** prove deterministic model output.
Different results for the same fingerprint remain separate objects and producing receipts.
Selection is lexical by producer-receipt hash among complete entries visible at lookup time.
An attempt then pins its selection permanently; later writers cannot rebind it. Competing
different publications to the same attempt slot fail instead of clobbering evidence.

Publication uses a private fsynced file followed by an atomic no-replace hardlink. Matching bytes
are reused; conflicts, missing referenced bytes, symlinks and noncanonical/escaping paths fail.
Caught failures remove only their private temporary file. A retry can complete a receipt's
missing lookup entry without deleting earlier evidence. A process killed before cleanup can
leave a `.publish-*` or private build file: it is not a lookup result or accepted artifact and
the audit fails closed on it; this change does not purge interrupted evidence automatically.
The filesystem and run root remain application-owned, not an adversarial concurrent mutation
boundary.

The original three jobs declare their receipt paths in their pinned dataset contracts. New
`attempt-datasets/2` contracts also pin the runtime's enumerated publication namespaces; `/1`
contracts keep their original declarations. The runtime declares objects, lookup entries and
immutable named-layout bindings. The inventory verifies shared-file hashes,
receipt/claim identities, pinned declarations and producer references, in addition to ordinary
ownership accounting. Handoff publication pins the full receipt/object/dependency closure.
Resume and accepted-handoff readers reverify it; shared index manifests also bind the shard
to its original producing receipt. A valid receipt from a failed attempt may provide a
computation-cache result, but never satisfies required accepted output by itself.

Verified old triage entries and derived checkpoints can be read in place with a new consumer
receipt marked `unknown-original-producer`. Existing document ledgers remain readable through
their original handoffs. Old claims, manifests, paths and bytes are never rewritten.

Required existing paths remain usable: guidance is still at `data/guidance/<bundle-hash>/`,
producer indexes at `data/indices/` or `data/indexes/owasp/`, packages at `data/review-packages/`,
and cells at `data/jobs/job_inference_security_review/cells/`. New files in these layouts are
hardlinks to exact-byte objects, not duplicated payloads or replaceable symlinks. A named-layout
fingerprint selects **path plus byte hash**, while the separate `computation` metadata records
the input/model/tool/guidance fingerprint. `data/shared/named/<namespace>/<path-hash>.json`
immutably binds the path to its bytes; an incomplete new publication cannot be silently treated
as a legacy cache hit. Existing duplicate legacy files are not rewritten to deduplicate them.
Fresh package assembly, guidance composition and index building remain `computed` even when
the output bytes match. Verification-only consumers write reuse references.

The classification of the examined layouts is:

| Layout | Writer and consumer | Classification and guarantees |
|---|---|---|
| Inference v6 packages; lane/team ledgers and PoC seeds | `review/packages.py`; inference job's unit directories | **(a) Attempt-local**, unchanged; do not confuse these with shared v3 packages. |
| Review-team semaphore locks and cell-number reservations | `review/teams.py`; `review/cells.py` | Mutable coordination, not immutable evidence. Exclusive empty reservation directories prevent concurrent cell attempts from overwriting one another. |
| Review cells and judge/verifier sidecars | `review/cells.py`, inference `teams.py`; reuse, `stages.verify_receipts`, reporting cell readers | **(b) Closed for new publications**: original producing claim/invocation, immutable numbered results/checks and per-attempt reuse receipts. Legacy origin remains explicitly unknown. |
| Shared v3 packages | `review_packages.publish_review_packages`; `verify_review_packages`, document-issue analysis | **(b)**: immutable exact bytes, input validation, computed-versus-reused receipts. |
| Guidance bundles | `guidance.compose.pin_bundle`; target-plan, project-build, post-build, dependency and PoC guidance helpers | **(b)**: no-overwrite publication before inference, model-sensitive identities where model metadata is stored, attempt receipts. |
| Non-derived SQLite and OWASP indexes | `retrieval.index.IndexBuilder`, `owasp_workbench.indexes`; manifest publication/verification and `WorkbenchIndex` | **(b)**: private build adopted by hard link into the object store (see [index shard durability](#index-shard-durability)); no-replace publication retained; physical dedupe is not a cache hit; consumers pin the selected original receipt. |
| Public reference snapshots | Feed `publish_snapshot`, NVD `_publish`; `verify_current`, NVD incremental/verification paths, cve-bin-tool NVD resolver, indexing feed pins/products, review references and scanner feed readers | **(b)** for new claimed publications: independent immutable producer records and per-attempt consumption receipts. Legacy/imported origin remains explicitly unknown. |

#### Index shard durability

Every `IndexBuilder` shard is written in a private temporary file beside its final path, with
`journal_mode=OFF`, `synchronous=OFF`, one transaction and no `VACUUM`. That file is not evidence
while it is being written, so the builder establishes durability and integrity once, at
publication: one `fsync`, one SHA-256 over the finished bytes, then `adopt_private_file`
hard-links (not copies) the file into `data/shared/objects/<sha256>`, falling back to a copy only
across filesystems. The named path under `data/indices/` is then linked atomically and without
replacement. Custody registration is unchanged: the `index-shard` named binding, the attempt
receipt and the request lookup entry. `build()` returns only after the shard is durable, hashed,
linked and registered; publication is never deferred to a background task. Identical inputs
produce byte-identical shards, so matching existing bytes are reused and a mismatching named path
is a conflict. The validation digest cache recognizes hard-link aliases of one object, so a
published shard is hashed about once rather than once per path.

Job execution binds the current attempt explicitly at its validator/handler/finalizer boundary.
The participating parallel producer pools propagate this context; no filesystem-wide write
interception is used. Accepted-handoff consumption and derived-index reads produce small
`shared-input` references, including downstream jobs that did not execute the original producer.
Offline helpers and report readers without a claimed attempt do not invent one or write receipts.
Registration and provenance do not make an output accepted; required publication, source
snapshot and schema validation still apply. Mutable workspaces, status, logs, downloads, locks,
operational metadata and latest pointers remain outside the immutable-output protocol.

Public NVD, OSV, MITRE, KEV, EPSS and cve-bin-tool snapshots stay in their configured global feed
roots under repository `data/`, with no snapshot payload copied into runs. Each new claimed
computation publishes `provenance/<snapshot-id>/<record-sha256>.json`: an immutable application
assertion binding the exact manifest, original run/job/attempt/invocation, claim/configuration
hashes and a separate input/configuration/publisher computation fingerprint. Different
computations retain separate records even when they deduplicate to the same snapshot.

These records are retained independently of producing runs, together with their snapshots and
NVD parent manifests/blobs. They remain verifiable after the entire producing run is removed.
The original private claim is not exported or reconstructed: its hash is a correlation value,
not a dependency on a retained run. Records contain no target contents, prompts, credentials or
complete private configuration. Their authority is the application-owned feed filesystem, not a
third-party signature or evidence that an output was accepted.

Consumers write run-local `feed-snapshot` receipts and small content-addressed proofs, pinning
the selected global record and snapshot. Feed roots are allowlisted by the consumer claim's
SHA-pinned resolved configuration. Handoff/resume validation rechecks that configuration,
manifest, payloads, record and NVD parent/blob chain, never the current pointer. Initial
selection is lexical among complete records; an attempt cannot rebind its selection when later
writers arrive. Downstream receipt consumption creates its own reference to the global record,
not a dependency on an earlier consumer's claim.

New manifests mark publication provenance as required. Missing/corrupt records, path escapes,
symlinks, partial publications and mismatched content fail closed rather than becoming legacy
cache hits. The existing feed writer lock still rejects competing snapshot publishers; immutable
record publication is no-replace and concurrent-safe. Interrupted publication can retain a complete
snapshot before its record/current pointer is published; retry preserves those bytes.
NVD uses a complete private directory before exposing the final path, and no-replace blob links.
New claimed incremental NVD computations require their selected parent snapshot to verify;
they do not silently rebuild over a damaged pinned input.

Legacy snapshots and Grype's imported-snapshot reader retain explicit `unknown-original-producer`
consumption receipts; there is no application Grype producer to attribute. Offline helpers
without a claimed attempt do not invent one. Old claims/manifests are not rewritten, legacy
duplicate payloads are not reorganized, and no pruning or retention cleanup is introduced.
All examined new shared immutable publication surfaces are covered; mutable operational
workspaces/status/locks and historical unknown provenance remain outside that claim.

The inventory also records this job's own reports and shard. Its own shard row names the
`inventory/dataset-inventory` identity; the shard's SHA-256 resolves through the verified accepted
manifest because a shard cannot contain its own content hash.

Violation codes: `undeclared_job`, `unknown_step`, `undeclared_shard`, `ambiguous_shard_claim`,
`shard_without_registered_producer`, `shard_counts_disagree`, `dangling_artifact`,
`artifact_hash_mismatch`, `unaccounted_handoff_artifact`, `unaccounted_file`,
`run_tree_truncated`, `run_tree_unreadable`, `snapshot_mismatch`, `missing_required_output`,
`shard_conflict`, `indexed_without_route`, `exception_without_reason`,
`registry_configuration_mismatch`, `duplicate_dataset_id`, `invalid_attempt_claim`.
Warnings (`unreferenced_index_files`, `upstream_not_run`, `attempt_provenance_unavailable`) do not block
acceptance. A restored shard is recorded as a repair.

When the audit fails, read `data/jobs/job_review_data_indexing/attempts/<attempt>/steps/audit/tasks/inventory/inventory.json`,
fix the producer declaration or the producer, and resume the graph. Do not widen a declaration to
silence an unknown output.
`run_tree.unaccounted_count` is the total; the violation list contains at most 50 sampled
unaccounted paths. Preserve failed attempts and accepted pointers rather than deleting files to
make the audit pass. Before deploying an accounting change, reproduce the failure and replay the
audit read-only over retained inputs; a successful offline replay does not launch or accept a run.

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
verified shared checkpoint object and producing receipt reuse an unchanged shard; changing one
rule rebuilds only that shard. Legacy checkpoints under `data/indexing/checkpoints/` are
verified read-only and retain explicitly unknown original producers.
The low-level `publish_derived` builder still permits callers without a job context to build
legacy fixture/offline shards; it cannot assign attempt provenance. All production indexing-job
call sites supply the shared-artifact context. This compatibility path also uses immutable
no-replace publication and never removes a conflicting shard.
