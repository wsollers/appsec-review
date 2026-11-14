---
title: "PLAN - GENERATE A DFD AND THREAT MODEL FROM ACCEPTED RUN EVIDENCE"
kind: "task"
subsystem: "review inference and guidance"
status: "historical"
jobs: ["job_review_data_indexing", "job_threat_model_generation"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# PLAN - GENERATE A DFD AND THREAT MODEL FROM ACCEPTED RUN EVIDENCE

This plan works T-107 (generate a data-flow diagram and threat model from accepted run evidence)
and T-108 (publish the static deployment inventory as a job); the registry owner has reserved both
ids and adds the entries of section 8 to `docs/TODO.md` on approval. The design is
[`../architecture/dfd-and-threat-model-generation.md`](../architecture/dfd-and-threat-model-generation.md).

**Status: plan only. No chunk starts, and no sub-agent is dispatched, until the user approves the
design and answers its open questions.** Nothing merges into `main` while the Freeciv walk is under
way. The procedure is `.claude/skills/parallel-implementation/SKILL.md`; the checklists are
`.claude/skills/add-a-job-contract/SKILL.md` and `.claude/skills/add-runtime-guidance/SKILL.md`.

User direction, quoted: "Start an agent to design and document the architecture for a job that will
manufacture a DFD and threat model as best it can. it can use all the info avail like the owasp
categorizations, and IaC, the code querying if needed or available. IE given the data we have can
we generate the artifacts. This would be a good test repo because it is authentically client
server. On it has settled on a good design. It should plan and dispatch the work with the usual
parametrs fully covered in quick valuable unit tests, has acceptatnce and integration tests but
don't run them."

## 1. Decisions the design settles

A developer does not have to invent any of these; each is fixed in the design section named.

| # | Decision | Design |
| --- | --- | --- |
| D1 | One job, `job_threat_model_generation`, `TargetAccess.ACCEPTED_EVIDENCE`, `strict_gaps=True` | 3 |
| D2 | Inputs and output kinds read; every input optional except the catalog envelope | 3.1 |
| D3 | Deployment facts come from a separate job, `job_deployment_inventory` | 3.2 |
| D4 | Step and task ids; no step named `inference`, `deterministic`, `inspection` or `provenance` | 4 |
| D5 | Lanes read through one `EvidenceView`; every query bounded; a reached bound is a `truncated` gap | 4.1 |
| D6 | Model worker is single-shot, no tools, off by default; proposals without resolving citations become unknowns | 4.2 |
| D7 | Three reference data files with their schema ids; basis vocabulary | 5 |
| D8 | Schema ids, record shapes, closed vocabularies, id derivation | 6 |
| D9 | Gap table, input ledger, terminal statuses | 7 |
| D10 | Dataset kinds, family `threat_model`, authority `routing_context`; no `documents` index | 8 |
| D11 | Label sanitization rule | 9 |
| D12 | Configuration keys and bounds; guidance placement | 10 |
| D13 | Canonical JSON, receipt keying, validation before publication | 11 |

Decisions that are the user's (design section 16) and block the chunk named:

| Question | Blocks |
| --- | --- |
| 1 required catalog envelope | C0 (contract) |
| 3 default enablement | C9 (wiring) |
| 4 deployment job in scope | C10 |
| 6 model profile | C8, C9 |
| 2, 5, 7 consumers | follow-ups only |
| 8 T-059 gate | everything |

## 2. Shared contract (C0, committed first)

One commit every other chunk imports and never edits. Concerns go back to the coordinator.

- `src/appsec_review/threat_model/__init__.py`
- `src/appsec_review/threat_model/contract.py`: schema id constants; closed enums (`ElementKind`,
  `Interaction`, `Basis`, `BoundaryKind`, `Stride`, `ThreatState`, `MitigationState`,
  `UnknownKind`, `InputState`); frozen records (`EvidenceRef`, `Fact`, `Element`, `Flow`,
  `Boundary`, `Asset`, `Actor`, `EntryPoint`, `Threat`, `Unknown`, `InputLedgerRow`, `Origin`);
  `element_id(kind, native_identity)`; `canonical(document) -> bytes`; `LaneResult(facts, gaps,
  ledger_rows)`.
- `src/appsec_review/threat_model/view.py`: the `EvidenceView` protocol the lanes read through
  (`entities(producer, output_kind, kind, *, limit)`, `search_calls(name, *, limit)`,
  `owasp_records(family)`, `artifact(producer, output_kind)`), plus `FakeEvidenceView` for tests
  (an in-memory implementation over literal records, shipped in `tests/threat_model_support.py`).
- `docs/schemas/threat-model/{generated-dfd,generated-threat-model,generated-model-evidence,threat-model-generation,elaboration-output}.schema.json`
- `tests/test_threat_model_contract.py`

Unit tests (C0), each under 10 seconds, no shared state:

| Test | Asserts |
| --- | --- |
| `test_element_ids_are_stable_and_independent_of_content_hashes` | Same native identity gives the same id; a changed file hash does not change it; different kinds never collide |
| `test_canonical_bytes_do_not_depend_on_insertion_order` | Two differently ordered equal documents serialize to identical bytes |
| `test_an_element_without_evidence_is_rejected` | Record construction and the JSON Schema both refuse `evidence: []` |
| `test_closed_vocabularies_reject_unknown_values` | Parametrized over the sorted enum names |
| `test_schemas_are_closed_and_match_the_records` | Every schema has `additionalProperties: false`; a canonical example of each record validates; an extra key fails |
| `test_origin_always_says_generated_and_not_target_supplied` | `Origin` cannot be built with `target_supplied=True` or another authority |

## 3. Chunks

Each code chunk owns its files and its tests. Command form for every chunk (WSL, the chunk's own
worktree and virtual environment, bounded workers):

```text
.venv/bin/python -m pytest <the chunk's test files> -n 4 --shuffle-seed=12345 --basetemp=test/tmp/<chunk>
```

Known pre-existing failures to hand each agent: the T-047 baseline and T-083 (judge and
budget-clock tests); neither is in these files.

### Wave 1 (parallel, after C0)

**C1 reference data and loaders**
- Files: `data/reference/threat-model/interaction-catalog.json`, `threat-templates.json`,
  `threat-crosswalk.json`; `src/appsec_review/threat_model/reference.py`;
  `tests/test_threat_model_reference.py`.
- Interface out: `load_reference(repository_root) -> Reference(interactions, templates,
  crosswalk, sha256s)`; `Reference.interaction_for(...)`, `.templates_for(interaction,
  boundary_kind, element_kind)`, `.dependency_category(name)`.
- Tests: `test_reference_files_validate_and_hash_deterministically`;
  `test_unknown_key_or_unknown_vocabulary_value_is_rejected`;
  `test_every_interaction_has_at_least_one_template_or_is_listed_as_untemplated`;
  `test_every_pinned_owasp_chapter_is_mapped_or_explicitly_unmapped` (reads
  `data/reference/owasp/catalogs/`, sorted ids);
  `test_reference_data_names_no_target` (no target name from `targets/` or the test corpora
  appears in the three files).

**C2 structure lane**
- Files: `src/appsec_review/threat_model/lanes/__init__.py`, `lanes/structure.py`;
  `tests/test_threat_model_lane_structure.py`.
- Reads: `build_units`, `components`, `artifact_catalog`, `artifact_relationships`,
  `build_actions`, `cpp_build_graph`.
- Interface out: `structure(view, reference, limits) -> LaneResult`.
- Tests: `test_built_executable_becomes_a_process_citing_the_artifact`;
  `test_declared_executable_is_a_process_with_declared_basis_when_nothing_was_built`;
  `test_library_folds_into_the_processes_it_links_into`;
  `test_library_with_no_link_evidence_is_an_unknown_not_a_process`;
  `test_absent_build_inputs_are_named_gaps_and_declared_units_still_yield_processes`;
  `test_process_limit_reached_is_a_truncated_gap`.

**C3 interaction lane**
- Files: `lanes/interactions.py`; `tests/test_threat_model_lane_interactions.py`.
- Reads: `code_graph_facts` (entry_point, sink_site, call_site), `tree_sitter_ast`,
  `priority_items` (review_signal).
- Interface out: `interactions(view, reference, limits) -> LaneResult`.
- Tests: `test_graph_entry_point_yields_a_verified_semantic_fact_with_its_source_class`;
  `test_call_site_by_name_yields_an_observed_syntax_fact_only`;
  `test_graph_fact_wins_over_a_syntax_fact_at_the_same_location`;
  `test_without_graph_facts_the_lane_reports_the_gap_and_uses_syntax`;
  `test_query_bound_reached_is_a_truncated_gap_naming_the_query`;
  `test_a_callee_name_outside_the_catalog_yields_nothing`.

**C4 declarations lane**
- Files: `lanes/declarations.py`; `tests/test_threat_model_lane_declarations.py`.
- Reads: `target_documents` (operation records; supplied dfd and threat_model ids),
  `deployment_inventory`, `dependency_context`, `owasp_workbench`, `tag_assignments`,
  `ci_findings`, `static_tool_observations`.
- Interface out: `declarations(view, reference, limits) -> LaneResult`.
- Tests: `test_declared_operation_yields_a_receive_fact_with_its_security_state`;
  `test_supplied_dfd_records_are_listed_by_id_and_never_become_facts`;
  `test_deployment_listener_and_relationship_yield_declared_facts`;
  `test_unregistered_deployment_producer_is_one_named_gap`;
  `test_dependency_name_maps_to_a_category_only_through_the_catalog`;
  `test_owasp_roles_attach_to_components_and_create_no_element`;
  `test_configuration_tool_findings_attach_by_path_as_observations`.

**C5 rendering**
- Files: `src/appsec_review/threat_model/render.py`; `tests/test_threat_model_render.py`.
- Interface out: `render_mermaid(dfd, limits) -> dict[name, text]`; `render_markdown(dfd,
  threat_model, result) -> text`; `sanitize_label(text) -> text`.
- Tests: `test_views_are_byte_stable_for_equal_documents`;
  `test_every_view_starts_with_the_generated_banner_and_source_hash`;
  `test_labels_are_sanitized_and_node_ids_carry_no_target_text` (labels containing Mermaid
  syntax, newlines, quotes and an instruction sentence);
  `test_boundaries_render_as_subgraphs_containing_their_members`;
  `test_a_model_over_the_node_bound_splits_per_process_and_reports_truncation`;
  `test_unknowns_and_the_input_ledger_appear_in_the_markdown_view`.

**C6 guidance content** (documentation and data only)
- Files: `pipeline/guidance/registry.json` (role `threat_modeler`, task, runtime skill entries),
  `pipeline/guidance/tasks/threat-model-generation/elaborate_process.md`,
  `pipeline/skills/threat-model-elaboration/SKILL.md`.
- Format contract shared with C8: the task's JSON example must validate against
  `docs/schemas/threat-model/elaboration-output.schema.json` from C0; the skill front matter is
  exactly `name`, `description`, `metadata.audience: runtime-worker`; the registry entry lists
  only `job_threat_model_generation`.
- Checks: `tests/test_skill_separation.py`, `tests/test_guidance_procedures.py`,
  `tests/test_worker_prompt_contracts.py` (the role set changes; C6 owns that test's expected
  set).

### Wave 2 (parallel, after wave 1 merges)

**C7 assembly, threats, validation**
- Files: `src/appsec_review/threat_model/assemble.py`, `threats.py`, `validate.py`;
  `tests/test_threat_model_assembly.py`, `tests/test_threat_model_threats.py`,
  `tests/test_threat_model_validation.py`.
- Interface out: `assemble(lane_results, reference, limits) -> (dfd, unknowns, gaps)`;
  `enumerate_threats(dfd, lane_results, reference, limits) -> (threat_model, gaps)`;
  `resolve_citations(documents, evidence, resolver) -> (documents, evidence, gaps)`;
  `validate_documents(documents) -> None` (raises on violation).
- Tests:
  - assembly: `test_external_entity_and_boundary_are_derived_from_an_evidenced_crossing`;
    `test_no_boundary_exists_without_a_crossing_flow`;
    `test_flow_with_an_unresolved_endpoint_is_an_unknown`;
    `test_assembly_is_independent_of_lane_and_fact_order` (shuffled inputs, identical bytes);
    `test_only_catalog_facts_yield_processes_with_role_and_boundary_unknowns`;
    `test_no_facts_yield_an_empty_model_with_one_unknown`.
  - threats: `test_each_crossing_gets_exactly_the_templates_the_catalog_selects`;
    `test_candidate_threat_cites_the_flow_evidence`;
    `test_mitigation_state_is_never_absent` (found, not found in evidence, not examined);
    `test_owasp_results_attach_through_the_crosswalk_and_are_labelled_model_assisted`;
    `test_attacker_position_is_offered_as_candidates_only`;
    `test_threat_limit_reached_is_a_truncated_gap`.
  - validation: `test_unresolved_citation_demotes_the_element_to_an_unknown_with_a_gap`;
    `test_dangling_flow_endpoint_is_rejected`; `test_duplicate_ids_are_rejected`;
    `test_documents_validate_against_the_published_schemas`.

**C8 model elaboration**
- Files: `src/appsec_review/threat_model/elaboration.py`,
  `src/appsec_review/guidance/workers.py` (one `SPECIALIZED_WORKERS` entry and the task lookup);
  `tests/test_threat_model_elaboration.py`.
- Interface out: `partitions(dfd, threat_model, evidence, limits) -> list[Partition]`;
  `build_request(partition, settings, prompt) -> ModelRequest`;
  `accept(proposal, partition) -> (additions, unknowns)`;
  `run(infer, execution, partitions, receipts) -> (additions, unknowns, gaps, receipts)`.
- The model is faked at the `Infer` boundary only (a plain function returning `ModelResult`).
- Tests: `test_request_bytes_are_deterministic_for_a_partition`;
  `test_proposal_with_an_unknown_key_is_rejected_as_invalid_output`;
  `test_proposal_citing_a_label_outside_the_table_becomes_an_unknown`;
  `test_proposal_cannot_change_or_remove_a_deterministic_element`;
  `test_evidence_requests_are_recorded_as_unserved_unknowns`;
  `test_unchanged_partition_reuses_its_receipt_without_a_model_call`;
  `test_call_budget_exhaustion_is_a_truncated_gap_and_failure_a_retryable_gap`;
  `test_no_deterministic_elements_means_no_model_call`;
  `test_target_text_reaches_the_worker_only_inside_the_evidence_table` (asserts on the rendered
  prompt, with an instruction sentence planted in an element name).

### Wave 3 (single owner, after wave 2 merges)

**C9 job wiring** owns every shared hotspot:
- New: `src/appsec_review/jobs/job_threat_model_generation/{__init__,datasets,job}.py`,
  `src/appsec_review/threat_model/index_view.py` (the real `EvidenceView` over `RetrievalCore`,
  `open_shard` and `observe_output`), `tests/test_threat_model_generation_job.py`,
  `docs/operations/threat-model-generation.md`.
- Modified: `src/appsec_review/runtime/registry.py`, `runtime/datasets.py` (`FAMILIES`),
  `appsec-review.toml`, `src/appsec_review/config/loader.py` (`ThreatModelSettings`,
  `PROFILE_MODEL_JOBS`), `orchestration/dagster/adapter.py` (job pool tables),
  `indexing/input_matrix.py`, `jobs/job_review_data_indexing` contract (`schedule_after`),
  `release-dependencies.json` (job pattern including `data/reference/threat-model/**`),
  `tests/job-test-map.json`, `tests/acceptance_inventory.json`, the job-count assertions
  (`tests/test_input_contract_admission.py`, `tests/test_inventory_publication.py`), and the
  documentation tables the parity tests read (`docs/architecture/dossier-data-inventory.md`,
  `job-consumer-read-paths.md`, `job-input-contracts.md`, `indexing-and-query-reuse.md`,
  `docs/architecture/README.md`).
- Tests, driven through the real `JobRunner` with fixture upstream handoffs written by
  `tests/handoff_fixture.write_fixture_handoff`:
  `test_job_is_registered_configured_and_in_the_graph_after_owasp_and_before_indexing`;
  `test_disabled_job_is_not_dispatched`;
  `test_unknown_setting_or_out_of_range_bound_is_refused`;
  `test_run_with_only_the_catalog_completes_with_gaps_and_publishes_an_honest_model`;
  `test_every_gap_is_a_producer_gap_record_and_each_is_counted_once`;
  `test_input_ledger_lists_every_declared_input_with_its_state`;
  `test_undeclared_upstream_read_fails_the_unit`;
  `test_changed_upstream_bytes_are_refused`;
  `test_outputs_match_the_dataset_declarations_and_nothing_lands_in_the_documents_index`;
  `test_catalog_document_coverage_for_dfd_and_threat_model_is_unchanged`;
  `test_generated_entity_kinds_are_indirect_under_review_admissibility`;
  `test_second_run_with_unchanged_inputs_is_reused_and_a_changed_input_reruns`;
  `test_model_disabled_returns_configured_disabled_without_a_gap`;
  `test_fixture_client_server_target_yields_a_resolving_dfd` (the C fixture of section 4: every
  citation resolves, at least one network boundary, views re-render to the same bytes).
- Also selected from existing files: `tests/test_job_selection.py`, `tests/test_gap_contract.py`,
  `tests/test_consumes_parity.py`, `tests/test_completion_wiring.py`,
  `tests/test_downstream_input_contracts.py`, `tests/test_review_data_indexing.py` (the
  input-matrix cases), `tests/test_documentation.py`.

**C10 deployment inventory job** (T-108; only if approved; after C9 because it shares the
hotspots)
- New: `src/appsec_review/jobs/job_deployment_inventory/{__init__,datasets,job}.py`,
  `tests/test_deployment_inventory_job.py`; the same registration surfaces as C9; removal of the
  "not registered" gap branch in `lanes/declarations.py` in favour of `when_producer_enabled`.
- Deterministic, `ACCEPTED_EVIDENCE`, `strict_gaps=True`; reads descriptor bytes from accepted
  `source_files` shards selected by the library's format rules, calls
  `appsec_review.deployment.extract_inventory`, publishes `deployment_inventory`
  (`appsec-review/deployment-inventory/1`) and maps the library's `Gap` and `Coverage` records
  onto `producer-gap/1`.
- Tests: `test_compose_and_kubernetes_descriptors_publish_services_listeners_and_relationships`;
  `test_unsupported_formats_are_named_gaps` (Dockerfile, Terraform, Helm);
  `test_target_without_descriptors_completes_with_an_empty_result_gap`;
  `test_descriptor_bytes_come_from_the_accepted_source_shard_and_are_hash_checked`;
  `test_inventory_evidence_carries_path_hash_and_line_span`.

## 4. Fixtures

Under `tests/fixtures/threat_model/`, inert and small, written for this work (never copied from a
target under `targets/`):

- `client_server_c/`: two small C programs (a server that listens, receives and writes a file; a
  client that connects and reads a file) with a build file. Used through fixture handoffs and
  literal index records, not by building.
- `web_iac/`: a route handler source file, an OpenAPI file, a compose file and a Kubernetes
  manifest.

Both are fixtures of structure only. They carry no seeded defects and no answer key, because the
tests assert the contract (design rule 4).

## 5. Integration and acceptance tests: written, NOT run

Written by C9 (and C10 for the deployment cases), excluded from default collection, executed only
at the user's explicit request.

| File | Case | Declared budget | What it exercises |
| --- | --- | --- | --- |
| `tests/integration/test_threat_model_generation.py` | `test_catalog_through_threat_model_on_the_client_server_fixture` | default 300 s | `GraphRunner` over intake, catalog, tree-sitter and the new job with real producers on the C fixture; every citation resolves against the real source shard |
| same | `test_web_fixture_with_deployment_inventory_yields_network_boundaries` | default 300 s | Adds `job_deployment_inventory`; published against internal listeners become distinct boundaries |
| same | `test_repaired_upstream_reruns_only_the_threat_model_job` | default 300 s | Resume plan after one upstream handoff changes |
| `tests/acceptance/test_threat_model_generation.py` | `test_published_model_preserves_admitted_input_and_read_identities` | `time_budget(120, reason="bounded fixture publication")` | Claim, input reads and citations agree; the dataset audit reports no unclaimed file |
| same | `test_generated_model_never_satisfies_supplied_document_coverage` | `time_budget(120, reason="bounded fixture publication")` | Catalog coverage and the `document_context` product are unchanged by the new job |
| same | `test_recorded_elaboration_replays_without_a_model_call` | `time_budget(120, reason="recorded model replay")` | Replay directory with a recorded response; no live model |

No new live test. A live run is the manual validation below.

## 6. Manual validation owed (not part of any chunk's completion)

1. The walk session runs `job_threat_model_generation` on Freeciv after the walk has accepted the
   producers it reads (at least catalog and tree-sitter; code graph for typed entry points), with
   the model step off, and records: element counts by basis, the input ledger, the gap list,
   elapsed time and peak memory against the design bounds, and a reading of the rendered DFD by a
   person.
2. A second run with the model step on, if the user chooses a profile (open question 6): calls,
   tokens, how many proposals were kept against how many were demoted to unknowns.
3. A run on a web target with compose or Kubernetes descriptors once C10 exists.
4. The integration and acceptance cases of section 5, at the user's request.

Unit results do not establish any of these.

## 7. Order, ownership and handoff

- Coordinator: this session (branch `dfd-threat-model`). Integration owner for `main`: the walk
  session, after the walk allows merges. Each chunk gets its own WSL worktree and branch
  (`tm-c1-reference`, ...) based on the exact C0 commit, checked with
  `git merge-base --is-ancestor`.
- Wave 1 is six agents (C1 to C6); wave 2 is two (C7, C8); wave 3 is one at a time (C9, then
  C10). Chunks merge one at a time into `dfd-threat-model`; a file outside a chunk's list is
  reviewed or rejected.
- Each agent commits, does not push, and hands over: branch, full SHA, owned-file diff, public
  interface if changed, decisions, the exact commands with elapsed times and results, gaps and
  deviations.
- The branch is offered to the integration owner as one ready commit range with the focused
  results; integration, acceptance and live validation are reported as NOT RUN.

Follow-ups, each needing its own decision and not planned here: an indexed publication with its
first index consumer; `architecture_context` in review packages; a report appendix behind a gate
capability; a second, application-mediated round serving `evidence_requests`; generated threats as
review hunts; Graphviz output; reading `entry_points[]` in the coverage adapter (T-086).

## 8. Proposed `docs/TODO.md` entries

For the registry owner to add (index rows and entries) under the reserved ids.

```
### T-107 — Generate a data-flow diagram and threat model from accepted run evidence
- **State:** open
- **Area:** review
- **Blocked by:** T-057
- **Why:** a target that supplies no DFD or threat model gets "no accepted target document" from
  the catalog and nothing else. No job produces either, review packages carry a null trust
  boundary, and T-059's F07 row has had no design.
- **Scope:** `job_threat_model_generation`: deterministic assembly of processes, stores, external
  entities, flows and trust boundaries from accepted build, artifact, code-graph, syntax,
  dependency, OWASP and deployment evidence; STRIDE-per-interaction candidate threats from a
  versioned template catalog; an optional bounded model worker whose uncited proposals become
  unknowns; every input optional and every absence a `producer-gap/1` record; outputs marked
  generated, authority `routing_context`, never written to the `documents` index; Mermaid and
  Markdown views regenerated from the JSON. No consumer changes in the first slice.
- **Done when:** the unit tests of the plan pass, the integration and acceptance cases exist, and
  a run on Freeciv by the walk session publishes a model whose citations all resolve, with its
  input ledger and gap list recorded in a task doc.
- **Refs:** `docs/architecture/dfd-and-threat-model-generation.md`,
  `docs/tasks/2026-11-12-dfd-threat-model-plan.md`, T-059 (F07), T-070, T-076, T-086, T-091.

### T-108 — Publish the static deployment inventory as a job
- **State:** open
- **Area:** evidence
- **Blocked by:** T-057 · **Blocks:** T-107 (deployment facts only)
- **Why:** `appsec_review.deployment` parses compose, Kubernetes, nginx, redis and postgresql
  descriptors into services, listeners and relationships, but no job calls it, so no dataset
  carries a listener, a published port or a service relationship.
- **Scope:** `job_deployment_inventory`: read descriptor bytes from the accepted `source_files`
  shards, call `extract_inventory`, publish `appsec-review/deployment-inventory/1` with its
  evidence, map the library's gaps and unsupported formats onto `producer-gap/1`. The static half
  of T-059's F06 row only; imported observations, drift and live collectors stay there.
- **Done when:** the unit tests of the plan pass and a run on a target with a compose or
  Kubernetes descriptor publishes services and listeners that `job_threat_model_generation` reads.
- **Refs:** `docs/deployment-inventory.md`, `docs/architecture/dfd-and-threat-model-generation.md`
  section 3.2, T-059 (F06), T-107.
```

Relation to existing items: T-107 is the producer T-059's F07 row describes, re-cut as a job
pass; when it is added, the F07 row gains a pointer to it. T-070 is unchanged: it slices findings
and records attacker position on findings, which this job never does. T-107 offers
attacker-position candidates per entry point that T-076 may surface to the reviewer.

`Blocked by: T-057` follows T-059's rule that every fleet row waits for the first scored run. If
the user lifts that gate for this work (design open question 8), the line is dropped.

## 9. Checks for this change (documentation only)

- `tests/test_documentation.py` (local links resolve).
- `tests/test_todo_registry.py` is not affected: this change does not touch `docs/TODO.md`.
- `git diff --check`, `git ls-files --eol` for the two new files.
