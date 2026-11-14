---
title: "Generated data-flow diagram and threat model"
kind: "architecture"
subsystem: "review inference and guidance"
status: "historical"
jobs: ["job_artifact_indexing", "job_change_context_analysis", "job_ci_configuration_analysis", "job_code_graph_index", "job_codeql_analysis", "job_cpp_compiled_analysis", "job_dependency_intelligence", "job_document_issue_analysis", "job_evidence_collection", "job_final_report_publication", "job_inference_security_review", "job_language_build", "job_owasp_control_assessment", "job_review_data_indexing", "job_review_package_assembly", "job_review_prioritization", "job_security_tagging", "job_source_history_analysis", "job_target_catalog", "job_threat_model_generation", "job_tree_sitter_ast"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Generated data-flow diagram and threat model

> Current subsystem view: [Review inference and guidance](review-inference-and-guidance.md). This record preserves its original decisions and validation limits; unfinished proposals are not treated as delivered.

This is the historical design record. The current declared contract is generated in
[the job page](../operations/job_threat_model_generation.md).

Status: **design approved for the first slice (section 15); see section 17 for what is implemented
on branch `dfd-threat-model` and what is not. Nothing is merged into `main`.** Registry items:
T-107 (this job) and T-108 (the deployment inventory job it depends on for deployment facts);
the ids are reserved by the registry owner, which adds the entries on approval. The implementation plan is
[`../tasks/2026-11-12-dfd-threat-model-plan.md`](../tasks/2026-11-12-dfd-threat-model-plan.md).
This design is the re-cut of the "F07 threat model" row of T-059 as one job with typed inputs and
gap records. It is a different thing from T-070, which slices *findings* by a game threat model
(section 12).

The user's question: given the data the pipeline already has, can it manufacture a data-flow
diagram (DFD) and a threat model for a target that supplies neither? `job_target_catalog` reports
"no accepted target document" for the kinds `dfd` and `threat_model` on Freeciv, and no job
produces either today.

## 1. Answer

Yes, with a stated ceiling. The pipeline can generate a DFD whose every element is backed by a
source line or a run artifact, and a threat model that is a list of evidence-backed *questions*
per trust-boundary crossing. It cannot generate the owner's intent: which assets matter, who is
trusted, what was accepted as risk. Those stay `unknown` records.

What the evidence supports today, by DFD element:

| Element | Evidence on `main` today | Kind | Not available |
| --- | --- | --- | --- |
| Processes | Declared executable and library build points (`job_target_catalog` `build_units`); built executables and libraries (`job_artifact_indexing` `artifact_catalog`, `job_language_build` `build_actions`); link composition (`artifact_relationships` `LINKS_INTO`, `job_cpp_compiled_analysis` `cpp_build_graph`) | deterministic | Runtime role (daemon, command-line tool, test helper) |
| Entry points | Code graph `entry_point` facts with `source_class` remote, local_user, argv, environment, file, ipc, database (`job_code_graph_index`); tree-sitter call sites by written callee name (`job_tree_sitter_ast`, no build needed); prioritization `ingress` signals (`job_review_prioritization`) | deterministic | Graph facts exist only where CodeQL built a database and, by default, only near seeded finding locations. `accept`, `listen`, `bind`, `connect` and script loading are in no catalog. No job emits `surface:entry:*` tags (T-086) |
| Declared interfaces | OpenAPI, AsyncAPI, protobuf and GraphQL operations with method, route and security state (`target_documents`, authority `declared`) | deterministic | Only when the target ships such a specification |
| Data stores | Graph sink facts (`sql_query`, `path_access`), database source facts, dependency names (`job_dependency_intelligence` `dependency_context`) | deterministic | No functional category for a dependency (database, TLS, compression, scripting); no persistent-file inventory |
| External entities | Only what an entry point or an outbound call implies | derived | Who the peer is |
| Deployment and exposure | **Nothing published.** `appsec_review.deployment` parses compose, Kubernetes, nginx, redis and postgresql descriptors into services, listeners and relationships, but no job calls it | deterministic library | Dockerfile, Helm, Kustomize, Terraform, CloudFormation, systemd, network policy, volumes, secrets are named as unsupported by that library |
| Trust boundaries | None. Review packages carry `trust_boundary_id: null` "until an accepted producer provides it" | | Everything; this job derives them from evidenced crossings only |
| Component roles | 13 deterministic roles in the OWASP `component-classification` shards | deterministic | No role for a native service, a game server or a command-line tool |
| Mitigation evidence | Graph `guard_fact` and sanitizer counts, OWASP `control-result` rows, CI and configuration tool observations | mixed (control results are model-assisted) | Authentication and authorization call sites are not detected for C or C++ |

How good the result can be:

- **(a) Freeciv** (C client and server, network protocol, saved games, Lua-scripted rulesets, no
  IaC, no package manifest). A usable level-1 DFD: the server, client and tool executables as
  processes; a remote network peer, a local operator, a file supplier and the launch environment
  as external entities; flows at the granularity of the functions that call socket, file and
  environment interfaces; network, file-content and local trust boundaries. The file names in the
  tree (`server/sernet.c`, `server/auth.c`, `server/fcdb.c`, `server/meta.c`, `server/savegame/`,
  `server/scripting/`, `common/networking/packets.def`) show the target has each of these
  surfaces, but the pipeline has no parser for the packet definition file, so per-packet flows and
  packet handlers are an `unknown`, not an element. Three things limit it. First, process
  inventory is noisy until T-091 is fixed (29 autotools directories are separate build units).
  Second, without a whole-program CodeQL export the typed entry points cover only seeded
  neighbourhoods, so most flows rest on name-matched syntax (basis `observed_syntax`), and where
  the target wraps the system calls the flows attach to the wrapper, not to the handlers.
  Third, there is no deployment evidence at all, so every exposure statement is an `unknown`.
  The threat model is a complete STRIDE question list per boundary crossing with the mitigation
  evidence that was found; a model worker can add names and target-specific threats, each
  citation-checked.
- **(b) A web service with IaC.** Better on declared interfaces: OpenAPI operations give routes
  with security state, CodeQL threat-model source kinds are exported for Java, Go and Python, and
  route handlers are detected for web languages. Worse on deployment until T-108 lands: compose
  and Kubernetes services, published ports and `depends_on`/proxy relationships are exactly the
  facts a web DFD needs, and they are parsed by a library no job publishes. With T-108 the
  result is a level-0 and level-1 DFD with real network boundaries (published listener against
  internal service) and data stores identified by product for redis and postgres. Terraform, Helm
  and Dockerfile content stays a named gap; Trivy, Checkov and Hadolint findings attach to
  elements as observations by path, never as topology.

In both cases the result is a starting point a person reviews, marked as generated, and never the
target owner's document.

## 2. Rules the design holds to

1. **Every input is optional.** A missing, disabled, partial or unreadable input is a named
   `producer-gap/1` record and an entry in the input ledger (section 7). The job cannot observe
   whether a person verified an upstream job; it records each input's accepted coverage and gap
   count and passes a partial upstream on as a gap of its own.
2. **Every element cites evidence.** A process, data store, external entity, flow, trust
   boundary, asset, actor, entry point or threat carries at least one evidence reference that
   resolves to source lines or a run-owned artifact. Anything inferred without one is an `unknown`
   record and is never rendered as an element (section 6).
3. **Generated is not supplied.** Outputs are never written to the `documents` index, never
   change the catalog's `target-documents:dfd` and `target-documents:threat_model` coverage, and
   carry an `origin` block and the authority `routing_context` (section 8).
4. **Tests assert the contract**, not whether the threat model is right: schema, citations
   resolve, gaps named, deterministic assembly. There is no answer key.
5. **Freeciv is a test case, not the design basis.** Nothing in the reference data or the schemas
   names a target or a game.
6. Target text is data. Element names taken from the target are sanitized before they are
   rendered or shown to a model worker (section 9), and target-owned exclusions ("out of scope",
   "trusted") are recorded as untrusted context, never applied.

## 3. Where the job sits

One new review-graph job, `job_threat_model_generation`. It reads accepted evidence only
(`TargetAccess.ACCEPTED_EVIDENCE`): no checkout, no scan of the target tree. Source lines are
read only to resolve a citation, through the accepted source view
(`jobs.bound_artifacts.source_context_core`), the same path the inference review uses.

```text
job_target_catalog ─┬─ job_tree_sitter_ast ─────────────┐
                    ├─ job_artifact_indexing ───────────┤
                    ├─ job_cpp_compiled_analysis ───────┤
                    ├─ job_review_prioritization ───────┤
                    ├─ job_code_graph_index ────────────┤
                    ├─ job_dependency_intelligence ─────┼─► job_threat_model_generation ─► job_review_data_indexing ─► ...
                    ├─ job_security_tagging ────────────┤
                    ├─ job_ci_configuration_analysis ───┤
                    ├─ job_evidence_collection ─────────┤
                    ├─ job_owasp_control_assessment ────┤
                    └─ job_deployment_inventory (T-108, when registered) ┘
```

`schedule_after` names the last producers in each chain (`job_owasp_control_assessment`,
`job_dependency_intelligence`, `job_security_tagging`); the rest follow from the inputs.
`job_review_data_indexing` gains `job_threat_model_generation` in its `schedule_after`, so the
dataset audit and inventory see the new datasets. That changes the indexing job's contract
identity, which the integration chunk must state in its handoff. No cycle: the new job consumes
nothing downstream of the indexing job.

### 3.1 Typed inputs

`Job.contract` declares each producer envelope and only the output kinds read. All reads go
through `runtime.consume.accepted_upstream`, `indexing.store.open_shard` and
`runtime.inputs.observe_output`, so read receipts are retained and an undeclared read fails.

| Producer | Output kinds read | Availability | Authority |
| --- | --- | --- | --- |
| `job_target_catalog` | `handoff`, `components`, `build_units`, `target_documents`, `source_files`, `declaration_symbols` | envelope required, outputs optional (open question 1) | producer_evidence |
| `job_tree_sitter_ast` | `tree_sitter_ast`, `tree_sitter_coverage` | optional | producer_evidence |
| `job_artifact_indexing` | `artifact_catalog`, `artifact_relationships` | optional | producer_evidence |
| `job_language_build` | `build_actions` | optional | producer_evidence |
| `job_cpp_compiled_analysis` | `cpp_build_graph` | optional | producer_evidence |
| `job_code_graph_index` | `code_graph_facts` | optional | producer_evidence |
| `job_review_prioritization` | `priority_items` | optional | routing_context |
| `job_dependency_intelligence` | `dependency_context` | optional | producer_evidence |
| `job_security_tagging` | `tag_assignments` | optional | routing_context |
| `job_owasp_control_assessment` | `owasp_workbench` | optional | producer_evidence |
| `job_ci_configuration_analysis` | `ci_findings` | optional | producer_evidence |
| `job_evidence_collection` | `static_tool_observations` | optional | producer_evidence |
| `job_deployment_inventory` (T-108) | `deployment_inventory` | optional, `when_producer_enabled` once registered | producer_evidence |

Every optional input uses `MissingPolicy.GAP` and `CoveragePolicy.ALLOW_PARTIAL`. The catalog
envelope is the one required input because an accepted-evidence job takes its target snapshot from
its upstream handoffs, and the catalog is already in `WAVE1_REQUIRED`: a run without it does not
exist. `job_source_history_analysis`, `job_change_context_analysis`, `job_codeql_analysis`
observations and the build receipts are deliberately not inputs (section 13).

### 3.2 The deployment inventory is a separate job (T-108)

`appsec_review.deployment.extract_inventory` is a pure function over caller-supplied bytes. It is
the only source of listeners, services and service relationships, and for a web service those are
most of the DFD. This design does not call it from inside the threat-model job: the inventory is
evidence other consumers need too (the OWASP workbench's `deployment_operations` role, the F06
exposure work), so it gets its own small deterministic producer, `job_deployment_inventory`, that
reads descriptor bytes from the accepted `source_files` shards and publishes
`appsec-review/deployment-inventory/1`. Until that job is registered, the deployment lane of this
job reports one gap, "deployment inventory producer is not registered", and every exposure
statement is an `unknown`.

## 4. Steps

Deterministic assembly does all the structural work. A model worker is an optional last
refinement and is off by default.

| Step.task | Kind | What it does |
| --- | --- | --- |
| `load.accepted_inputs` | deterministic | Opens each declared input, records the input ledger, emits one gap per absent, disabled or partial input |
| `facts.structure` | deterministic | Processes and components from build units, artifacts and link relations |
| `facts.interactions` | deterministic | Entry points, outbound calls, stores, code loading and process spawning from graph facts, tree-sitter call sites and prioritization signals |
| `facts.declarations` | deterministic | Declared operations, deployment services and listeners, dependencies, component roles, tags, tool observations |
| `assembly.dfd` | deterministic | Joins facts into elements, flows and boundaries; everything unjoined becomes an `unknown` |
| `threats.enumerate` | deterministic | Applies the threat template catalog per boundary crossing and attaches mitigation evidence |
| `elaboration.model_review` | model, optional | One bounded single-shot worker per partition proposes names, assets and extra threats, each citing supplied evidence labels |
| `validation.resolve_citations` | deterministic | Re-resolves every evidence reference; an element whose citations fail is demoted to an `unknown` |
| `publication.render` | deterministic | Regenerates the Mermaid and Markdown views from the validated JSON |
| `publication.publish_handoff` | deterministic | Writes the result, artifacts and joined gaps |

Step names avoid `inference`, `deterministic`, `inspection` and `provenance`, which the Dagster
adapter routes to the `cpp_analysis` pool by name; the job gets an explicit entry in the adapter's
job pool tables.

### 4.1 Bounded retrieval, no tree scan

Each lane asks bounded questions of accepted index shards through one `EvidenceView` interface
(a thin wrapper over `RetrievalCore` built from the attempt's pinned input manifest with a shard
filter restricted to the declared inputs):

- graph facts: `find(kind="entry_point" | "sink_site" | "call_site", indexes=["graph"])`, paged
  to `max_query_rows`;
- tree-sitter: full-text search of `call_expression` nodes by written callee name, one query per
  name in the interaction catalog (section 5.1), each paged to `max_query_rows`;
- everything else: entity listings of one kind from one index.

A query that reaches its bound produces a `truncated` gap naming the query; the result is never
presented as complete. Nothing walks the target directory.

### 4.2 The model worker

Single-shot over supplied context, no tools, like the post-build and dependency workers. Its input
is the assembled DFD, the candidate threats and a table of evidence labels (`E1`, `E2`, ...) with
bounded excerpts. It may return, in a closed schema with unknown keys rejected:

- `labels`: a readable name and one-line purpose for an element, citing labels;
- `assets`: data worth protecting that an element holds or carries, citing labels;
- `threats`: target-specific threats beyond the templates, each tied to existing element ids and
  citing labels;
- `flows`: a flow between two existing elements that the cited evidence shows;
- `evidence_requests`: typed questions the supplied context could not answer.

The application, not the worker, decides what is kept. A proposal whose labels are not in the
supplied table, or whose citations fail resolution, is not an element: it is recorded as an
`unknown` of kind `uncited_model_inference`. The worker never changes or removes a deterministic
element. `evidence_requests` are recorded as `unknown` records of kind
`evidence_request_unserved`; serving them with a second application-mediated round is deferred
(plan, follow-ups). This is F07's "typed missing-evidence requests rather than worker
self-expansion".

Partitioning is by process: each call receives one process, its flows, boundaries and candidate
threats, bounded by `max_input_tokens`. Elements left over when `max_calls` is reached are a
`truncated` gap. Requests are built deterministically so recorded replay finds them.

## 5. Reference data

Three small versioned JSON files under `data/reference/threat-model/`, each with a `schema` id,
loaded once, validated against a closed shape and recorded by SHA-256 in every output. None names
a target.

### 5.1 Interaction catalog (`appsec-review/interaction-catalog/1`)

Maps evidence to a closed interaction vocabulary:

| Interaction | Examples of what maps to it |
| --- | --- |
| `network_listen` | callee names `listen`, `accept`, `bind`; a `public_api` route signal; deployment listener |
| `network_receive` | graph `entry_point` with `source_class` remote; callee names `recv`, `recvfrom`, `recvmsg`; declared operation |
| `network_connect` | callee names `connect`, `getaddrinfo`, HTTP client calls; deployment relationship |
| `file_read` / `file_write` | graph `file` sources, `path_access` sinks; prioritization `state.fs_write` |
| `datastore_query` | graph `sql_query` sinks and `database` sources; prioritization `state.db_write` |
| `code_load` | graph `code_injection` sinks on dynamic loading; prioritization `wrapper.ffi`; script-engine load calls |
| `process_spawn` | graph `command_execution` sinks |
| `environment_read` / `argument_read` | graph `environment`, `argv` sources |
| `local_ipc` | graph `ipc` sources |
| `privilege_change` | prioritization `privilege_shift` |

It also holds a dependency-name table (package or library name to `database`, `tls`,
`compression`, `scripting`, `http_client`, `serialization`), because `dependency_context` has no
functional category. Each fact records which rule matched and its **basis**:

- `verified_semantic`: a code-graph fact (resolved by CodeQL, cross-checked where available);
- `declared`: a specification, descriptor or build file says so;
- `observed_syntax`: a name-matched, unresolved call site;
- `derived`: computed from other elements (a boundary, an external entity).

The basis is shown on every element and in the rendered view, so a reader can tell a resolved
remote source from a function that merely calls something named `recv`.

### 5.2 Threat template catalog (`appsec-review/threat-templates/1`)

STRIDE per interaction: a template applies to a flow of one interaction kind crossing a boundary
of one kind toward an element of one kind. Each template has `template_id`, `stride` (one of
spoofing, tampering, repudiation, information_disclosure, denial_of_service,
elevation_of_privilege), a title, the question to answer, the obligations that would answer it,
and the mitigation evidence kinds to look for. Example: a `network_receive` flow crossing a
`network` boundary into a process yields tampering ("is every length and index in the received
data checked before use"), denial of service, spoofing ("how is the peer identified") and
elevation of privilege templates.

A template instance is a **candidate threat**: a question the evidence raises, not a finding. Its
state is one of `candidate` (template applied), `elaborated` (a model proposal that passed
validation). There is no `confirmed` state; confirming a weakness is the review's job.

### 5.3 Crosswalk (`appsec-review/threat-crosswalk/1`)

No OWASP-to-STRIDE mapping exists in the repository, so this file is new. It maps, per template:
ASVS 5.0.0 chapters, MASVS 2.1.0 groups, OWASP Top 10 2025 and API Top 10 2023 entries, CWE
families used by the graph's sink classes, and the T-070 attacker-position vocabulary
(`client_to_server`, `server_to_client`, `peer_to_peer`, `hostile_content`, `local`). A unit test
requires every chapter and entry of the pinned catalogs to be either mapped or listed as
explicitly unmapped, so the crosswalk cannot silently fall behind a catalog update.

How the OWASP assessment maps in:

- `component-classification` roles become attributes of the process that contains the component
  and select which template groups apply (for example `authentication_identity`, `storage`).
- `applicability` rows with outcome `applicable` or `conditional` attach to candidate threats
  through the crosswalk as `related_controls`.
- `control-result` rows attach as mitigation evidence with their own status
  (`satisfied`, `not_satisfied`, `cannot_verify`, `not_assessed`); they are model-assisted
  upstream and are labelled so.

The OWASP data is context for the threat list. It never creates a DFD element.

## 6. Output schemas

Four documents, each canonical JSON (sorted keys, sorted arrays, no timestamps in content) under
`data/jobs/job_threat_model_generation/attempts/<attempt>/`:

| Schema id | File | Content |
| --- | --- | --- |
| `appsec-review/generated-dfd/1` | `dfd.json` | Elements, flows, boundaries, unknowns |
| `appsec-review/generated-threat-model/1` | `threat-model.json` | Assets, actors, entry points, threats, obligations, unknowns |
| `appsec-review/generated-model-evidence/1` | `evidence.json` | The evidence references both documents cite |
| `appsec-review/threat-model-generation/1` | `result.json` | Input ledger, counts, gap list, reference-data hashes, artifact references |

JSON Schemas live in `docs/schemas/threat-model/` and are closed (`additionalProperties: false`).

### 6.1 Common blocks

Every document starts with:

```json
{
  "schema": "appsec-review/generated-dfd/1",
  "origin": {
    "kind": "generated",
    "target_supplied": false,
    "producer": "job_threat_model_generation",
    "run_id": "...", "attempt_id": "...", "target_snapshot": "...",
    "authority": "routing_context",
    "reference_data": {"interaction_catalog_sha256": "...", "threat_templates_sha256": "...",
                       "crosswalk_sha256": "..."},
    "model": null
  }
}
```

`origin.model` is `null`, or `{provider, model, guidance_bundle_sha256}` when elaboration ran.

An evidence reference:

```json
{"ref": "E12", "kind": "index_entity",
 "entity_id": "...", "entity_kind": "entry_point",
 "publication": {"job": "job_code_graph_index", "output_kind": "code_graph_facts", "index": "graph",
                 "shard_id": "...", "sha256": "..."},
 "locator": "server/example.c:120-131#b4100-4420@<file_sha256>",
 "content_sha256": "...", "basis": "verified_semantic", "rule": "graph.entry_point.remote"}
```

`kind` is `index_entity` (a record in an accepted shard, with its source location when it has
one) or `run_artifact` (`{path, sha256, size_bytes}` bound in an upstream handoff). The locator
format is the review's (`path:start-end#bstart-end@file_sha256`).

### 6.2 DFD

- `elements[]`: `{id, kind, name, name_basis, basis, evidence[], attributes, component_ids[]}`
  with `kind` one of `process`, `data_store`, `external_entity`. `evidence` has at least one
  entry; the schema enforces it. `name_basis` is `artifact_name`, `declared_name`, `derived` or
  `model_label`.
- `flows[]`: `{id, source, target, interaction, data, basis, evidence[], crosses[],
  attributes}`. `source` and `target` are element ids; `crosses` lists boundary ids. `data` is a
  short description only when evidence names it (a declared operation, a store product),
  otherwise `null`. There is one flow per process, peer and interaction, not one per call site:
  `attributes` carries `direction` (`inbound` or `outbound`), `site_count`, and `ownership`, the
  weakest rule that tied its sites to the process (`source_path`, `build_unit` or `source_root`),
  so a reader can see when a flow rests on unit-wide attribution. The call sites themselves are
  the `entry_points[]` of the threat model.
- `boundaries[]`: `{id, kind, inside[], evidence[], basis}` with `kind` one of `network`,
  `file_content`, `local_user`, `launch_environment`, `process`, `deployment_exposure`,
  `privilege`, `loaded_code`. A boundary exists only where an evidenced flow crosses it: it is
  derived from its crossings and cites them.
- `unknowns[]`: section 6.4.

Ids are stable across runs of the same target revision and, where the native identity is stable,
across revisions: `proc:` + the first 16 hex characters of the SHA-256 of the element's canonical
native identity (build unit id and artifact path for a process, the interaction and enclosing
symbol for an entry point), never of content hashes or ordinals.

How elements are established:

- A **process** is a built executable, or a declared executable build point when nothing was
  built. Libraries fold into the processes they link into (`LINKS_INTO`); a library with no
  established link is listed as a component of an `unknown` of kind `runtime_role_unknown`.
  Deployment services become processes with `basis: declared`, joined to a built artifact only
  when the descriptor names it.
- An **external entity** is derived from an entry point or outbound call: a remote network peer,
  a local operator, a file supplier, the launch environment, an unidentified remote service. Its
  evidence is the crossing.
- A **data store** is a deployment service with a store product, or a `datastore_query` or
  `file_write` interaction; which store, when not named by evidence, is an `unknown`.

### 6.3 Threat model

- `assets[]`: `{id, name, held_by[], basis, evidence[]}`. Deterministic assets are limited to what
  evidence names: credentials and key material where a secrets observation or a `data:*` tag
  exists, the store behind a data-store element. Sensitivity is never assigned; it is an
  `unknown` of kind `asset_sensitivity_unknown`.
- `actors[]`: one per external entity, with the attacker-position candidates the crosswalk gives
  for its crossings.
- `entry_points[]`: `{id, process, interaction, source_class, enclosing_symbol, basis,
  evidence[]}`.
- `threats[]`: `{id, state, stride, template_id, title, question, element_ids[], flow_ids[],
  boundary_ids[], evidence[], obligations[], mitigation, related_controls[], crosswalk}`.
  `mitigation` is `{state, evidence[]}` with `state` one of `evidence_found`,
  `not_found_in_evidence`, `not_examined`. There is no "absent": the job never claims a control
  does not exist.
- `obligations[]`: what a reviewer would need to establish to answer a threat's question, in the
  form the review protocol's proof obligations use.
- `supplied_documents[]`: ids of any target-supplied `dfd` or `threat_model` records, listed for
  a reader, not merged, with `authority: "intent"` and a note that the target's own text is
  untrusted context.
- `unknowns[]`.

### 6.4 Unknowns

`{id, kind, subject_ids[], statement, would_resolve[]}`, with `kind` closed:
`runtime_role_unknown`, `peer_unidentified`, `flow_endpoint_unresolved`, `protocol_unknown`,
`datastore_unidentified`, `boundary_not_established`, `deployment_not_described`,
`authentication_not_located`, `asset_sensitivity_unknown`, `uncited_model_inference`,
`evidence_request_unserved`, `no_element_established`, `citation_unresolved`. `would_resolve` names the input or evidence that would turn the
unknown into an element (for example `job_deployment_inventory/deployment_inventory`), which is
what makes the unknown list a work list.

An unknown is a statement about the model. A gap (section 7) is a statement about an input. A
missing deployment inventory is one gap and, typically, one `deployment_not_described` unknown per
process.

### 6.5 Rendered form

`publication.render` writes `dfd.mmd` (Mermaid `flowchart`) and `threat-model.md` from the
validated JSON. They are generated views: never hand-edited, each starting with a generated
banner, the target snapshot and the SHA-256 of the JSON it was rendered from. An output validator
re-renders and compares bytes.

- Boundaries are `subgraph` blocks; processes, stores and external entities use distinct shapes;
  each flow label carries its id, interaction and basis.
- Node ids are the element ids. Labels are sanitized target text (section 9).
- A diagram is bounded by `max_render_nodes`; a larger model renders one overview (processes,
  stores, external entities) plus one diagram per process, and the bound is a `truncated` gap
  when reached.
- `threat-model.md` has the tables a person reads: elements with basis, threats by boundary,
  unknowns with what would resolve them, and the input ledger.

Mermaid is the first form because the documentation already uses it and it needs no tool at
publication time. Graphviz output for the LaTeX report is open question 5.

## 7. Gap model

The job sets `strict_gaps=True`. Every gap is built with `interchange.producer_gap`; every
`terminal_status` is a member of `interchange.ProducerStatus`.

| Situation | `GapCode` | `scope_id` | Retryable |
| --- | --- | --- | --- |
| Declared producer has no accepted handoff in the claim | `input_unavailable` | `<producer>` | no |
| Producer is disabled in configuration | `input_unavailable` | `<producer>` | no |
| Producer not registered (deployment inventory before T-108) | `input_unavailable` | `job_deployment_inventory` | no |
| Upstream accepted with gaps or partial coverage | `producer_reported_gap` | `<producer>/<output_kind>` | no |
| Output kind declared but no shard or artifact published | `output_missing` | `<producer>/<output_kind>` | no |
| Lane read its input and established nothing | `empty_result` | `<lane>` | no |
| A bounded query, the element count or the render reached its limit | `truncated` | the query or bound name | no |
| A citation did not resolve | `location_unresolved` | the element id | no |
| Reference data or an input record failed validation | `parser_error` | file or record | no |
| Model call failed, timed out or returned invalid output after retries | `producer_failed` | the partition | yes |
| Model call budget exhausted before every partition was sent | `truncated` | `elaboration.model_review` | no |

No input gap is retryable. The runtime never reuses an accepted attempt that has a retryable gap,
and running this job again over the same pinned inputs repeats the gap. The gap closes when its
producer publishes a new accepted handoff; that changes a pinned upstream digest, which reruns
this job without the flag.

Model elaboration that is disabled in configuration is not a gap: the unit returns the
disposition `CONFIGURED_DISABLED` and `origin.model` is `null`.

Units that only join other units' gaps carry them as payload and return `"gaps": []`, as
`job_ci_configuration_analysis` does, so each gap is counted once. The job is `SUCCEEDED` only
with no gaps; otherwise `COMPLETED_WITH_GAPS`. It fails only on an integrity error (a pinned
handoff or shard whose bytes changed) or on invalid reference data.

`result.json` carries the **input ledger**: one row per declared input with
`{producer, output_kind, state, handoff_sha256, coverage_disposition, upstream_gap_count,
records_read}` and `state` one of `read`, `absent`, `disabled`, `not_registered`, `partial`,
`empty`. This is the "available, supplied, read, cited" distinction made visible: the ledger says
what was supplied and read, and `evidence.json` says what was cited.

### 7.1 When most inputs are missing

With only the catalog accepted (no build, no tree-sitter, no graph): declared executable build
points become processes with basis `declared`; there are no flows, no boundaries and no threats;
each process has `runtime_role_unknown` and `boundary_not_established` unknowns; every other input
is a gap. The job publishes that honest, nearly empty model as `COMPLETED_WITH_GAPS`. With not
even build units, it publishes zero elements, the gaps and one `unknown` naming what a first
element needs. It never fills the diagram from the model worker: elaboration does not run when
there are no deterministic elements to elaborate.

## 8. Provenance and what consumers may do

Datasets (`Job.datasets`), all with authority `routing_context` except the receipts:

| Output kind | Schema | Disposition | Sensitivity |
| --- | --- | --- | --- |
| `generated_dfd` | `appsec-review/generated-dfd/1` | artifact_only | internal |
| `generated_threat_model` | `appsec-review/generated-threat-model/1` | artifact_only | internal |
| `generated_model_evidence` | `appsec-review/generated-model-evidence/1` | artifact_only | internal |
| `generated_model_views` | `text/markdown` | artifact_only | internal |
| `threat_model_documents` | `appsec-review/threat-model-generation/1` | artifact_only | internal |
| `threat_model_receipts` | `appsec-review/threat-model-receipt/1` | protected, authority `provisional` | sensitive |

A new dataset family `threat_model` is added to `runtime.datasets.FAMILIES`. The first slice is
artifact-only; an indexed publication (a retrieval index of its own, never `documents`) is added
with its first index consumer (plan, follow-ups).

Why `routing_context`: under the review's admissibility rule (R3) any entity kind not listed as
direct evidence is indirect for every predicate. Generated elements are never listed. They "may
guide search, never satisfy an obligation".

| Consumer | May | May not |
| --- | --- | --- |
| `job_target_catalog`, `document_context` product | Nothing changes | Count a generated model as a supplied `dfd` or `threat_model`; the catalog gap stays |
| `job_document_issue_analysis` | Later: compare a supplied document against the generated model and raise reconciliation candidates, with the generated side as routing context | Use the generated model as document evidence or as the owner's statement of intent |
| `job_review_prioritization` | Not a consumer (it runs upstream) | |
| `job_review_package_assembly` | Later, by a package schema change: attach `architecture_context` (process, boundary and entry-point ids) to a unit as routing context | Put a generated boundary into `scope.trust_boundary_id`, which stays reserved for an accepted, owner-authoritative boundary (open question 2) |
| `job_inference_security_review` | Use element and threat ids to decide where to look | Cite a generated element to satisfy a predicate; a claim cites the underlying source evidence |
| `job_final_report_publication` | Later: an appendix titled as generated, behind a gate capability like the other attachments | Present it as the target's architecture or as findings |
| Finding metrics, T-070, T-076 | Offer attacker-position *candidates* per entry point to a reviewer or to operator slice rules | Fill a finding's `attacker_position`; that field "is never inferred" and stays null until the review records it |
| T-073, T-086 coverage adapter | Read `entry_points[]` as one candidate entry-point catalogue, if T-086 decides so | Treat it as complete; its ledger says what it could not see |

The first slice changes no consumer. The consumer today is the person reading the views and the
dataset inventory. Each "later" row is its own follow-up with its own decision.

## 9. Untrusted text

Names and descriptions come from the target (artifact names, routes, symbols, service names). They
are data:

- rendering replaces every character outside `[A-Za-z0-9 _./:#-]` and truncates to 80
  characters; node ids never contain target text;
- the model worker receives them inside the labelled evidence table under the governing rules,
  never as instructions;
- a target's own `dfd` or `threat_model` text is not shown to the worker at all in the first
  slice, so a target cannot steer the generated model through its documents;
- nothing from the target selects guidance, tools or configuration.

## 10. Configuration and guidance

Central TOML only; nothing about models, budgets or pools goes in a prompt.

```toml
[jobs.job_threat_model_generation]
name = "threat_model_generation"
workers = 2

[jobs.job_threat_model_generation.settings]
enabled = false            # open question 3
max_processes = 200
max_entry_points = 4000
max_flows = 8000
max_threats = 4000
max_query_rows = 2000
max_evidence_refs_per_element = 8
max_render_nodes = 120

[jobs.job_threat_model_generation.settings.reservation]
cpu = 2
memory_mb = 1024
io_slots = 1
admission_timeout_seconds = 600

[jobs.job_threat_model_generation.settings.model]
enabled = false
provider = "claude-cli"
model = "claude-haiku-5-5"
reasoning = "medium"
max_input_tokens = 48000
max_output_tokens = 8000
timeout_seconds = 300
retries = 1
max_calls = 8
```

plus one `[jobs.job_threat_model_generation.steps.<step>]` table per step of section 4. Settings
are parsed by a typed `ThreatModelSettings` with unknown keys rejected and every bound range
checked; the job is added to `PROFILE_MODEL_JOBS` so a profile can override the model keys.

Runtime guidance, following the add-runtime-guidance checklist:

- role `threat_modeler` in `pipeline/guidance/registry.json` (responsibility: propose names,
  assets and threats for supplied elements, citing supplied evidence labels; prohibited: new
  elements without citations, severity, compliance statements, statements about runtime state);
- persona: the existing `generalist` persona; no new persona;
- task `pipeline/guidance/tasks/threat-model-generation/elaborate_process.md` with the bounded
  question and an exact JSON example that validates against the output schema;
- runtime skill `pipeline/skills/threat-model-elaboration/SKILL.md`, audience `runtime-worker`,
  registered under `runtime_skills` for this job only and loaded through `load_runtime_skill`;
- a `SPECIALIZED_WORKERS` entry so the prompt is composed, hash-pinned under
  `runs/<run-id>/data/guidance/<bundle-sha256>/` and rendered by the existing path.

The worker has no tools and no retrieval. No worker authority is widened: shared behaviour stays
in `governing-rules.md`, and the role text repeats none of it.

## 11. Determinism, reuse, repair

- Deterministic steps are pure functions of the accepted inputs, the settings and the three
  reference files. Output is canonical JSON; arrays are sorted by id; content carries no
  timestamps, host names or attempt-specific paths except in `origin` and `result.json`.
- Reuse follows the runtime: the attempt is reused when the upstream handoff digests, resolved
  configuration, dataset contract and release identities match. The reference data files are part
  of the job's release pattern in `release-dependencies.json` and their hashes are in the result,
  so a changed template or catalog invalidates reuse through the operator-declared release, as
  for other jobs.
- The model step stores one receipt per partition at a run-level path
  (`data/threat-model/receipts/<key>.json`), keyed by the SHA-256 of the partition's canonical
  request, the pattern the OWASP workbench uses for its receipts. A later attempt with an
  unchanged partition reuses the receipt after checking its identity, so a repair that changes
  one upstream input re-asks only the affected partitions. Recorded replay is keyed by the masked
  request, which is deterministic per unit.
- Repair: a rejected or partial upstream that is later repaired changes that producer's handoff
  digest, so the resume plan re-runs this job and nothing upstream of it. Any change to this
  job's contract or datasets changes its attempt identity. Adding the job to a configuration does
  not rewrite frozen runs.
- Validation happens before publication: schema, unique ids, flow endpoints exist, every element
  has a resolving citation, views re-render to the same bytes. A violation rejects the attempt;
  it does not publish a partial model with a warning.

## 12. Relation to F07, F06, T-070 and the entry-point items

- **F07** (T-059): this job is F07's producer. It covers assets, actors, boundaries, flows,
  threats, obligations and unknowns, consumes classification, applicability, deployment and build
  facts, uses typed missing-evidence requests, and treats target-owned exclusions as untrusted
  context. F07's "document-candidate routing into independent review" (generated threats becoming
  hunts) is deferred to a follow-up.
- **F06** (T-059): T-108 is the static half only (publish the existing inventory). Imported
  service observations, freshness and drift, and live collectors stay in F06.
- **T-070** slices findings by attacker position for a game team. This job does not slice
  findings and does not fill finding fields. It offers attacker-position candidates per entry
  point, which T-076 may show to the reviewer who records the field.
- **T-086** must decide whether entry points come from `surface:entry:*` tags or code-graph
  facts. This job reads code-graph facts and syntax directly and does not make that decision for
  the coverage adapter.
- **T-091** (conditional automake `SUBDIRS`) and **T-098** (vendored third-party code) limit the
  process inventory on Freeciv until they are fixed; the job does not work around them.

## 13. Cost and capacity

Host: 24 cores, about 15 GiB.

- Deterministic steps read SQLite shards read-only and hold facts in memory. The bounds in
  section 10 cap the working set (at most 4,000 entry points, 8,000 flows and 4,000 threats);
  the reservation is 2 CPUs and 1 GiB. These are design bounds, not measurements: the Freeciv
  run by the walk session measures them.
- The job runs after the heavy producers (CodeQL, the compiled analyses), not beside them, and
  takes one I/O slot.
- Model use is off by default. When on: at most `max_calls` = 8 calls of at most 48,000 input
  and 8,000 output tokens, two at a time, so at most 384,000 input and 64,000 output tokens per
  attempt before receipt reuse.
- The interaction queries are the main cost on a large target: one bounded full-text query per
  catalog callee name against the tree-sitter shards. The catalog is a few dozen names.

## 14. Alternatives considered

| Alternative | Why not |
| --- | --- |
| A model worker reads the code and writes the DFD | Unevidenced by construction, not repeatable, scans the target during inference, and target text would steer it. Rule 2 could only be checked after the fact |
| Two jobs (DFD, then threat model) | The DFD has no second consumer yet, and each job costs the full registration surface. The schemas and dataset kinds are separate, so a later split is mechanical |
| Call `extract_inventory` inside this job | The inventory is evidence other consumers need; publishing it once as its own dataset keeps the build graph and deployment graph distinct (F06) |
| Write the generated model into the `documents` index as kind `dfd` and `threat_model` | Document records have no origin field; every consumer would take it for the target's own document. Rejected outright |
| `CHECKOUT` access with a scan for listeners and descriptors | Violates "query bounded indices"; duplicates the catalog and tree-sitter jobs; the walk has not verified a second reader of the tree |
| Reuse `surface:entry:*` tags as the entry-point source | No job emits them (T-086) |
| Fill `scope.trust_boundary_id` in review packages | The slot is reserved for an accepted boundary; a generated one would look authoritative |
| Use source history and change context as inputs | They rank where change concentrates; they do not establish an element. They can order the threat list later without a contract change to the schemas |
| Read CodeQL SARIF observations | Findings, not structure; the graph facts already carry sources and sinks |
| Attack trees or PASTA instead of STRIDE per interaction | They need the owner's goals and business context, which is exactly what is unknown. STRIDE per interaction is mechanical over an evidenced DFD |
| A structurizr or Threat Dragon file as the primary output | A tool format as the source of truth cannot carry citations, gaps and unknowns. An export can be rendered later from the JSON |

## 15. Smallest end-to-end slice

Deterministic only, no model, no consumer change:

1. the contract module and schemas;
2. the structure lane (catalog build units, artifacts, link relations) and the interaction lane
   (code-graph entry and sink facts, tree-sitter call sites);
3. DFD assembly, deterministic threat enumeration from the template catalog, citation
   validation;
4. Mermaid and Markdown views;
5. the job with the input ledger, strict gaps and artifact-only datasets.

That is enough to run on Freeciv after the walk reaches the code-graph job and to judge whether
the output is worth the model step, the deployment job and the consumers.

## 16. Open questions for the user

1. **Required catalog envelope.** The accepted constraint is "every input is optional". An
   accepted-evidence job needs one upstream handoff to bind its target snapshot. Recommendation:
   the `job_target_catalog` envelope is required and all its outputs are optional.
2. **Review packages.** May a generated boundary ever be shown to review workers, as a separate
   `architecture_context` routing field? Recommendation: yes, later, as its own change, and never
   in `trust_boundary_id`.
3. **Default enablement.** Recommendation: merge with `enabled = false` and the model off, and
   enable the deterministic job after the walk's first Freeciv run of it has been read.
4. **Deployment job in scope.** Is T-108 (publishing the existing deployment inventory)
   approved as part of this work? Without it the web-service answer in section 1 stays "no
   deployment facts".
5. **Report form.** Should the final report carry the generated model as an appendix, and if so
   is Mermaid in the HTML report enough or is Graphviz for the LaTeX report wanted?
6. **Model profile.** Which model should the optional elaboration use in the production profile?
   The base configuration follows the other in-job workers.
7. **Generated threats as hunts.** F07 names routing candidates into independent review. Is that
   wanted after the first slice, or should the generated model stay a reading aid?
8. **Gate from T-059.** T-059 gates every fleet row on T-057's first scored run. Does this
   request lift that gate for F07 and the static half of F06?

## 17. Implementation status (first slice)

On branch `dfd-threat-model`, not merged. Unit tests only; integration, acceptance and live
validation have not been run.

Implemented: the contract and closed schemas; the three reference data files; the structure and
interaction lanes; assembly; template threats; citation validation; the Mermaid and Markdown
views; the evidence view over admitted index shards; the job itself, disabled by default.

Not implemented, each a named limit of what a run publishes today:

- **Model elaboration** (section 4.2) and its guidance. `origin.model` is always `null`.
- **Declarations lane** (declared operations, dependencies, OWASP roles and results, tags, tool
  observations) and the crosswalk's `related_controls`. The crosswalk data exists and is carried
  on each threat.
- **Deployment inventory** (T-108). Every run records the not-registered gap, so every run
  completes with gaps.
- **Mitigation evidence.** Every threat's mitigation state is `not_examined`.
- **Assets.** The list is empty; each data store has an `asset_sensitivity_unknown`.
- **Threats on data stores.** `datastore_query` and `file_write` flows get a data-store element
  and a `datastore_unidentified` unknown but no boundary and no candidate threat, because a
  boundary rule needs a derived external entity.
- **Consumers.** None reads the outputs.

Two properties of real index data shape the result. Payloads are stored after secret redaction,
so a name or path containing a secret-like word arrives as `<redacted>`; such a process is
identified by its record, not its name, and the lane reports a gap. And tree-sitter call sites
are matched by exact written name against a C and C++ callee list, so a target that wraps the
system calls shows its wrappers, not its handlers.
