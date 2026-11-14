---
title: "Attack-surface discovery and threat-driven hunting review"
kind: "review"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_code_graph_index", "job_inference_security_review", "job_review_data_indexing", "job_review_package_assembly", "job_review_prioritization", "job_security_tagging", "job_target_catalog", "job_threat_model_generation"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Attack-surface discovery and threat-driven hunting review

## Charter and evidence boundary

Reviewed on **2026-11-13**, against commit
**5926171238607e27a948bc7d40ce190a853b3d0c** on local `main`. The required base was verified
as an ancestor; HEAD equalled that base during the source trace. This is a subsystem value and
architecture review, **not a target vulnerability audit, implementation approval, or live-run
acceptance**. No target, model, container, integration suite or acceptance suite was executed.
Tests named below were inspected as contracts, not reported as passing.

The shared checkout had extensive unrelated documentation edits, including historical design
pages and the TODO registry. Source line references below describe the reviewed base, not
those documents' evolving assertions. The documentation frontmatter retains the documentation
program's reconciliation marker; it is not the reviewed code revision. Only this review and the
[proposed enhancement design](../architecture/threat-driven-hunting-enhancement.md) belong to
this assignment. TODO registration and documentation-ledger integration belong to the parent.

Integration note: T-146 subsequently landed on main, verified at
`2612ee80f305970707520ad92774d1e1c1336c1c`; its
[implementation record](../tasks/2026-11-13-behavior-oriented-review.md#implementation-and-verification-record)
now owns the delivered operations, neutral entry tags, generated-map consumer and
operation-only/whole-file coverage distinction. Tables below deliberately preserve the older
inspection baseline. T-151/T-155/T-156 schedule only the additional question, allocation and
receipt work, not those delivered fixes; no fresh post-landing efficacy measurement is claimed.

The durable review question is: **which attacker-relevant operations did the run actually
investigate, with what original evidence, and which ones did its budget or missing evidence
leave unresolved?** A file count, generated threat count, successful worker, or completed
checklist is not an answer.

### Repeatable review brief

For a future reconciliation, pin the revision and typed contracts, then:

1. Follow source/component/build identities through publication, indexing, package selection,
   rendered input, retrieval receipts, citations, adjudication and coverage reporting.
2. For every transition name the producer, output kind, schema, authority, acceptance pins,
   retrieval route, bounds and named omissions. Distinguish available, supplied, read and cited.
3. Trace an incoming network operation, hostile-content parser, client/server authorization
   operation, missing compiled evidence and an unselected fallback unit. Inspect actual
   consumers rather than inferring use from topology or a dataset declaration.
4. Ask how actor control, ownership, sensitive resources, trust crossings and product
   configuration are established. Preserve unknowns and conflicting evidence.
5. Inspect the selection and execution denominators, including seed bias, language differences,
   package partitioning, view clipping, unavailable strategies and unserved evidence requests.
6. Compare source against existing tasks before proposing work. In particular, read
   [T-146's approved design](../tasks/2026-11-13-behavior-oriented-review.md) first.
7. Propose bounded extensions with independent efficacy measurements. Keep answer keys away
   from workers and separate offline contract checks from authorized empirical validation.
8. Hand scheduling proposals to the single TODO owner. Do not silently enable optional jobs,
   commission missing evidence, invent an intelligence taxonomy or redesign cross-package chains.

## Summary

The foundation is unusually strong on identity, custody, explicit gaps, deterministic packaging
and bounded worker authority. It is weaker on the connection between **discovered opportunity,
budget allocation, answered investigation question and measured coverage**.

Three additional improvements are justified beyond T-146:

- Attach a typed surface/coverage-obligation projection to T-146's operation identities, retaining
  evidence level, attacker/deployment uncertainty and all candidate/omitted scope.
- Make within-hunt selection and package admission budget-aware and fair to less-instrumented
  components and fallback operations, without weakening lane A admission or increasing budgets.
- Bind per-question dispositions and evidence-request outcomes to existing execution/retrieval
  receipts; make T-073's coverage adapter consume those rather than treating package membership
  as investigation.

These are proposals, **not approved behavior**. Existing T-107/T-108 own threat-model/deployment
producer work; T-129 owns canonical bucket mapping; T-070/T-076 own finding dimensions;
T-073/T-086 own source/entry coverage; T-146 owns operation planning, observed tags and the optional
generated-model consumer. No competing operation map or generated-model consumer is proposed.

## Current end-to-end flow

The following links are evidence for the implementation, with symbol and line ranges to make
the trace reproducible.

| Stage | As built at the reviewed revision | Consequence for hunting |
| --- | --- | --- |
| Catalog and identity | [Catalog datasets](../../src/appsec_review/jobs/job_target_catalog/datasets.py#L19-L37) publish `source_files`, `declaration_symbols`, `components`, `target_documents` and `build_units`. [AcceptedScope](../../src/appsec_review/review/scope.py#L137-L239) verifies the accepted manifest and separates source, component and catalog-build selectors; `_longest` chooses path-root membership. | A source hash and catalogued build unit establish scope, not successful compilation, shipping configuration, business ownership or deployment. Ambiguous real-world ownership must not be inferred from path membership. |
| Syntax and prioritization | [Prioritization rules](../../src/appsec_review/jobs/job_review_prioritization/rules.py#L16-L24) distinguish syntax, heuristic inference and semantic-path bases. [Scoring.rank](../../src/appsec_review/jobs/job_review_prioritization/scoring.py#L53-L82) normalizes available features and records missing weight. [Publication](../../src/appsec_review/jobs/job_review_prioritization/job.py#L690-L795) indexes selected items and their evidence. | Useful review-first ordering, but not a whole-surface census. The inference rank receives selected priority records, not an exhaustive list of all operations. Python is explicitly unscored by the [language map](../../src/appsec_review/jobs/job_review_prioritization/languages.py#L168). |
| Graph evidence | [Graph declarations](../../src/appsec_review/jobs/job_code_graph_index/datasets.py#L19-L28) expose `code_graph_facts`, including per-scope family coverage and database seed cards. [Graph publication](../../src/appsec_review/jobs/job_code_graph_index/job.py#L299-L341) emits unavailable coverage-only shards and marks seeded scope coverage partial. [Graph contract](../../src/appsec_review/graph/contract.py#L200-L281) retains source classes, coverage and direct-evidence constraints. | Entry/sink/guard/path facts are valuable evidence only within their modeled scope. A family existing in a shard is not proof every operation is modeled. The configured graph export is seeded, [TOML line 1900](../../appsec-review.toml#L1899-L1900); absence outside that neighborhood is not a negative. |
| Tags | [Collectors](../../src/appsec_review/jobs/job_security_tagging/producers.py#L213-L355) emit declared language/path/package facts, reported observation mappings and gap tags. [Standing gaps](../../src/appsec_review/jobs/job_security_tagging/job.py#L35-L48) explicitly say invoked capability detection is not implemented. | The vocabulary is richer than current production. Tag basis is a strength; raw tag counts still are not independent operation opportunities. T-146 owns the observed graph-backed extension. |
| Generated DFD/threats | [Job](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L1-L18), [declared inputs](../../src/appsec_review/threat_model/index_view.py#L79-L90), [datasets](../../src/appsec_review/jobs/job_threat_model_generation/datasets.py#L26-L54) and [configuration](../../appsec-review.toml#L1071-L1089) establish a registered, disabled-by-default deterministic producer with artifact-only routing outputs. | Implemented first slice, not merely a future design; nevertheless no base-code consumer uses its products. Scheduling before indexing is not consumption. T-146 is explicitly adding the optional admitted consumer. |
| DFD inference ceiling | [Interaction lane](../../src/appsec_review/threat_model/lanes/interactions.py#L124-L249) combines graph entry/sink facts, exact written-callee syntax and selected review signals; it records per-input reads and clipping. [Assembly ownership](../../src/appsec_review/threat_model/assemble.py#L180-L219) uses build unit, source path and longest source root. [Assembly](../../src/appsec_review/threat_model/assemble.py#L280-L400) retains unowned interactions as unknowns and derives boundaries/actors. | A generated network/file/process boundary is a hypothesis from original facts. Build-unit-wide ownership can attach a site to several artifacts; it is labeled, not exact runtime attribution. |
| Threat questions | [enumerate_threats](../../src/appsec_review/threat_model/threats.py#L1-L48) makes one template question per crossing. Every mitigation is `not_examined`; attacker positions are candidates. [build_documents](../../src/appsec_review/threat_model/documents.py#L79-L115) publishes empty assets and sensitivity unknowns. | STRIDE supplies questions, not established attacker capabilities, assets, missing controls or vulnerabilities. The first slice has no declaration or mitigation evidence lane. |
| Deployment | [extract_inventory](../../src/appsec_review/deployment/inventory.py#L34-L142) is a bounded pure library with source hashes, explicit selections, conflicts and unsupported-input coverage. The threat job's [deployment gap](../../src/appsec_review/jobs/job_threat_model_generation/job.py#L64-L70) states the producer is unregistered. | Static configuration extraction exists; accepted deployment publication does not. Even future static publication proves declarations, not the deployed effective environment. T-108 is the existing owner. |
| Indexing | [Products](../../src/appsec_review/indexing/products.py#L1-L39) and [datasets](../../src/appsec_review/jobs/job_review_data_indexing/datasets.py#L15-L49) provide cross-domain links, bounded precomputed products and inventory audit. [Input matrix](../../src/appsec_review/indexing/input_matrix.py#L101-L142) explicitly calls generated threats artifact-only and review decisions extend/artifact-only. | Inventory visibility is not semantic retrieval or worker use. Generated JSON can be intentionally artifact-only but needs a named bounded consumer to create review value. |
| Two package producers | [Catalog package job](../../src/appsec_review/jobs/job_review_package_assembly/job.py#L64-L100) calls `publish_review_packages`; [document_hunt](../../src/appsec_review/review_packages.py#L96-L133) grants declared document context. Separately, [inference assembly](../../src/appsec_review/jobs/job_inference_security_review/job.py#L343-L410) invokes `review.packages.assemble_packages`. | Do not assume the similarly named producers share their hunts. Document hunts go to document analysis; they are not automatically the inference hunt queue. |
| Inference units and ranking | [build_units](../../src/appsec_review/review/units.py#L207-L295) partitions sorted paths by component/build unit; boundary is null. [rank_units/select_hunts](../../src/appsec_review/review/units.py#L350-L365) sum available points, break ties by known-signal count/key and take top N. [Manifest](../../src/appsec_review/review/packages.py#L1669-L1725) retains unit rank/cutoff but not source IDs on every unit. | Current fallback is path-batch planning, not behavioral review. T-146 replaces the primary unit and ranking semantics and preserves all sources below cutoff. |
| Package and view bounds | [Hunt audit](../../src/appsec_review/review/packages.py#L1625-L1641) accounts each hunted unit's menu leads exactly once. [source_rows](../../src/appsec_review/review/package_view.py#L201-L206) supplies initial source text only for single-lead packages; [build_view](../../src/appsec_review/review/package_view.py#L417-L530) labels context, bounds the view and reports omissions. | Lead-menu membership is not exhaustive attack-surface coverage. At base a hunt may have graph/context labels but no initial source excerpt; successful retrieval must not be presumed from source IDs in the package. |
| Routing | [hunt_panel](../../src/appsec_review/guidance/routing.py#L181-L278) chooses sink-up, entry-down and control-gap from accepted data availability; missing prerequisites fall back to persona sweep. [route](../../src/appsec_review/jobs/job_inference_security_review/teams.py#L703-L800) records bases, strategy cutoffs and unscheduled matched specialists. | Good explicit fallback. A graph family with partial coverage unlocks a strategy; availability alone says nothing about which entry/sink question was actually addressed. |
| Budget and rounds | [FairShareScheduler](../../src/appsec_review/review/teams.py#L99-L161) fairly allocates between lanes, then orders by rank/package ID within a lane. [Rounds](../../src/appsec_review/jobs/job_inference_security_review/teams.py#L940-L991) stop at convergence/budget/round bounds and retain request cutoff/out-of-package gaps. | Lane fairness already exists; within-hunt surface/component fairness does not. Confirmed variant seeds are package-local; cross-package/cross-lane seeds remain an explicit gap. That is a separate workstream. |
| Receipts and metrics | [Cell retrieval](../../src/appsec_review/review/cells.py#L531-L604) logs bounded results, withheld counts and hashes; [receipts](../../src/appsec_review/review/cells.py#L868-L910) retain seen identities, output and reuse. [Coverage rows](../../src/appsec_review/jobs/job_inference_security_review/teams.py#L852-L858) turn successful hunter execution into “reviewed”. [Coverage adapter](../../src/appsec_review/observability/findings/coverage_adapter.py#L105-L237) propagates successful red-package membership to files and file status to entry points. | Actual execution is auditable, but the reviewed denominator is a package-execution proxy. It does not show that each contained source span or entry point was investigated. |

### Configured limits, not observed performance

At this revision [central configuration](../../appsec-review.toml#L2854-L2943) allows three
rounds, three red/two blue/one verifier per team, 50 selected hunt units, 200 files per path unit,
25 menu leads per hunt partition, 64 context entries, 64 KiB stored packages and a 48 KiB
model-facing view with a 160-source-line limit. The job has a shared 200-team-package ceiling
and a 0.5 lead budget share, plus turn/token/query/time ceilings.

These numbers make the distinction important: **50 selected units need not mean 50 packages,
200 supplied files need not mean 200 source reads, and a successful cell need not mean every
question was answered**. No throughput, detection or coverage percentage was measured here.

## Intelligence production and consumption

**Provisional conceptual labels only.** `docs/intelligence-buckets.json` was absent at review
time. The labels below are examples from
[the documentation program's Stage 3](../tasks/2026-11-13-docs-program-prompt.md#stage-3-intelligence-buckets-and-the-two-matrices),
not a competing taxonomy. T-129 decides exactly one canonical bucket per tool/dataset. A graph
dataset containing both call and flow families is not assigned two canonical buckets by this
table. “Operator” is not a model role.

| Conceptual label | Exact product / producer | Publication and retrieval route | Decision use and evidence ceiling | Current consumption limitation |
| --- | --- | --- | --- | --- |
| source_snapshot | `source_files`, `components`, `build_units`; `job_target_catalog` | `appsec-review/retrieval-index/2`; source/components/build shards; `find`, `search`, `read_excerpt` | Scope, original citations and component/build membership; not deployed exposure | Catalog build membership is later used as a coverage proxy for “built”, without a compile-success receipt |
| syntax | `tree_sitter_ast`, `tree_sitter_coverage`; `job_tree_sitter_ast` | `appsec-review/tree-sitter-normalizer/1` and `appsec-review/tree-sitter-ast/1`; analysis shards | Prioritization, generated interaction detection, fallback anchors; exact written syntax, not resolved call semantics | Unknown language, parse error and truncation reduce discovery; rich AST does not itself become a reviewed subject |
| symbols_and_calls / dataflow, canonical choice pending | `code_graph_facts`; `job_code_graph_index` | `appsec-review/graph-fact/1`; graph shards; `query_code_graph`, `list_codeql_databases`, `query_codeql_neighborhood` | Entry/sink/guard/path questions, scoped retrieval grants and semantic claim evidence subject to admissibility | Seeded scope and model coverage are not an exhaustive entry-point census |
| build_and_deployment | `build_actions`, `artifact_catalog`, `artifact_relationships`, `cpp_build_graph`; build/artifact/compiled jobs | `appsec-review/retrieval-index/2`; build/artifacts shards plus precomputed `build_provenance`; protected workspaces/raw commands excluded | Establish producing configuration and exact/ambiguous source-to-artifact links; sanitized build context reaches packages | Catalogued, compiled, extracted and shipped are different states; deployment declarations have no accepted producer yet |
| documents | `target_documents`; catalog; `precomputed_products` with `document_context`; indexing | documents/precomputed shards; `find`, `read_excerpt`, `query_precomputed`; catalog `document_hunt` packages | Declared routes, intended boundaries and tests can nominate a hunt, never prove enforcement | Separate document analysis route; declaration/implementation/deployment joins must not be assumed |
| history | `history_signals`, `change_context`; history/change-context jobs | `appsec-review/retrieval-index/2`; history index, precomputed `history_context`; `find/search/trace`, `query_change_context` | Instability/churn and process context order work; routing authority only | File-level history can dominate opportunities; missing history is unknown, not low risk |
| review_claims, provisional routing placement | `priority_items`, `prioritization_documents`; `job_review_prioritization` | `appsec-review/retrieval-index/2` priority shard and artifact-only `appsec-review/review-prioritization/1`; `query_hotspots` | File/function opportunity scores and linked ingress/sink/semantic signals order hunts, never prove defects | The index contains selected items and capped evidence; full intermediate metrics/signals in artifacts are not an exhaustive worker-visible surface inventory |
| review_claims, provisional routing placement | `tag_assignments`; `job_security_tagging` | `appsec-review/tag-assignment/1`; tags shards, `find/search/trace` | Persona/stack/ranking context; declared/reported/derived basis remains visible | Base lacks invoked capability collection; T-146 owns that fix; a tag is not vulnerability proof |
| review_claims, provisional routing placement | `generated_dfd`, `generated_threat_model`, `generated_model_evidence`, `generated_model_views`, `threat_model_documents`; threat job | generated DFD/model/evidence schemas version 1; artifact-only; inventory metadata, no general model-content query | Operator-visible diagrams and candidate threat questions; routing_context only | Base has no consumer; **T-146 will provide optional package context**, so do not schedule another consumer |
| metrics / build_and_deployment, canonical choice pending | `test_coverage`, `profile_data`; corresponding jobs | `appsec-review/retrieval-index/2`; analysis index; `query_precomputed` sets `test_coverage` / `profile_data`; package engineering context | Test/source binding and observed hotness can contextualize a question; neither establishes security review coverage | Context may be supplied or clipped without being read; profile popularity must not replace low-frequency hostile-input review |
| review_claims | Inference `review_packages`, `review_cells`, `claim_ledger`, `scores_and_findings` | package v6, protected cell receipts, ledger and finding artifacts; accepted consumers, not a generic raw-transcript query | Hunter proposals, counterevidence, independent adjudication; worker output is provisional until verified | Receipts exist but lack a per-surface obligation disposition joined to exact delivered spans |
| metrics | `coverage_matrices`, `dataset_inventory`; indexing; offline finding coverage/scorecard | matrices artifact plus inventory shard / `query_dataset_inventory`; `coverage_from_run` and scorecard accepted readers | Explain missing producer/language/build-unit coverage and hunt yield | Upstream inventory cannot know later worker investigation; package-success proxy must be labeled until receipt-derived coverage lands |

The tool-to-product edge uses catalog IDs, not invented tools: `tool-tree-sitter` produces syntax;
`audit-codeql` / `audit-codeql-native` supply CodeQL tooling; `tool-clangd-indexer` and `tool-svf`
supply native secondary evidence; `tool-git` supplies history; `tool-semgrep` supplies observations;
`tool-sqlite-fts` validates the retrieval text product
([catalog](../../containers/catalog.toml#L315-L325),
[syntax/history IDs](../../containers/catalog.toml#L515-L568),
[native/scanner IDs](../../containers/catalog.toml#L760-L841)).
The in-process ranker, tag mapper and deterministic threat assembler are not additional container
tool IDs. A configured tool is not a receipt proving that invocation ran.

### Availability is not use

[accepted_upstream](../../src/appsec_review/runtime/consume.py#L149-L192) enforces typed
permission and admitted pins; scheduling ancestry grants neither. The threat model's
[IndexEvidenceView](../../src/appsec_review/threat_model/index_view.py#L153-L240) verifies
producer/output ownership and shard bytes; its input ledger records counts, not worker reads.
An accepted source/index can be:

1. **Available** in a producer publication.
2. **Supplied** to a consumer claim/package and granted to a cell.
3. **Read** by application code, or **delivered** as bounded content to a worker; those are
   different observations and neither proves human-like attention.
4. **Cited** in a worker answer and independently resolved.
5. **Used in an addressed investigation question**, with a scoped disposition.
6. **Counted by adjudication** for a finding predicate.

The first four have substantial machinery today, but they are not interchangeable. The missing
join is principally (5), not another general retrieval service. Raw transcripts should remain
protected; sanitized question/evidence/omission receipts are the useful downstream product.

## Concrete gaps and value implications

| Observation | Evidence and impact | Owner / treatment |
| --- | --- | --- |
| Current path batches, raw tag density and omitted source IDs weaken opportunity planning | `units.build_units`, `_signal_rows`, `packages.assemble_packages`, cited above. Different sites can collapse into a file signal; tags/gaps can add density; below-cutoff sources cannot be distinguished by the adapter. | **Already T-146/T-086.** Review the landed interface rather than implementing a second fix. |
| Generated threat intelligence is intentionally artifact-only, and mitigation/asset context is absent | Threat job header, datasets, `enumerate_threats`, `build_documents`. Syntax/graph information can become useful questions, but no base hunt consumes the diagram. | **Already T-107 plus T-146 consumer.** T-108 owns static deployment publication. No new DFD index or second operation map. |
| Entry coverage depends on tags the base producer does not emit | `coverage_adapter.ENTRY_KIND_BY_TAG` lines 65–74 and `entry_points` lines 186–237; parser is explicitly unmapped. Graph entries already exist elsewhere. | Refine **T-086** to use accepted graph/T-146 operation anchors, not fabricate public-route tags from remote inputs. Preserve syntax-only candidates separately. |
| “Reviewed file” is broader than observed investigation | Adapter lines 105–183 and `test_a_file_is_reviewed_only_when_a_completed_package_contained_it` at [test line 66](../../tests/test_finding_coverage_adapter.py#L66-L83). A successful package marks all its source IDs; another entry in the same file inherits that result. | Extend **T-073** with question/receipt coverage; additional receipt design in HUNT-C. Relabel legacy metrics rather than retroactively inventing reads. |
| “Not built” is inferred from catalog membership | [Adapter loader](../../src/appsec_review/observability/findings/coverage_adapter.py#L263-L280) uses `scope.build_unit_for(path)`, not accepted compile/extraction receipts. A source may be reviewed without a build; a catalogued unit may have failed compilation. | **T-073/T-086**, consuming typed availability distinctions from HUNT-A. Do not treat source-only review as impossible. |
| Within-hunt selection can favor the best-instrumented component | Unit rank is global top N; unknown signals add no points and lose known-signal ties. `FairShareScheduler` only balances lanes. | **HUNT-B:** deterministic within-hunt allocation with an explicit bounded fallback reserve. This is a design risk from the algorithm, not a measured target miss. |
| Selected-unit count hides package and follow-up cost | Hunt menus split; queue order is unit rank then package ID; rounds and evidence requests spend shared limits. | **HUNT-B/HUNT-C:** allocate and account bounded question work before dispatch, distinguishing cutoff, view omission, budget failure and unanswered requests. |
| Actor, ownership, asset and deployment conclusions are underdetermined | Generated actors are candidate positions; models have empty assets and per-process deployment/role unknowns. Finding slice rules never infer attacker position ([slices](../../src/appsec_review/observability/findings/slices.py#L242-L258)). | **T-070/T-076/T-108** retain field ownership; HUNT-A carries fact-level uncertainty into questions, not stronger finding labels. |
| Hunt independence is a spatial proxy | [run_adapter](../../src/appsec_review/observability/findings/run_adapter.py#L74-L135) treats lane A as scanner-backed and lane B by source overlap ±2 lines; [hunt_lane_value](../../src/appsec_review/observability/findings/coverage.py#L156-L178) excludes unknown backing. | Reuse **T-068** evaluation, with independently labeled root causes. “No nearby scanner observation” is not empirical proof of unique detection or correctness. Triage/verifier design owns final finding quality. |
| Language/seed support creates unequal discovery opportunities | Python prioritization is unscored; graph facts depend on extraction/models/seed scope; AST fallback does not resolve dataflow. | T-146 supplies fallback; **T-126** owns future graph-producer design. Here measure the deficit and reserve bounded investigation, not promise equivalent semantic coverage. |

## As-built versus in-flight versus additional proposal

| Concern | Base implementation | Expected T-146 interface | Additional proposal |
| --- | --- | --- | --- |
| Unit identity | component/build/sorted-path range | operation/function anchors, bounded fallback, full source accounting | HUNT-A: coverage obligations referencing those same anchors, never another operation inventory |
| Tagging/rank | declared/reported tags, raw density | observed graph-backed capabilities and deduplicated opportunity score | HUNT-B: fair allocation across the existing ranked candidates under finite budgets |
| Generated map | deterministic optional producer, no consumer | optional typed admitted map context in units/packages, source references revalidated | HUNT-A: retain its candidate boundary IDs and uncertainty in questions; no new map consumer |
| Source visibility | bounded lead-centric views; package grants | relevant complete subjects/operation context | HUNT-C: hash-bound delivered-span and answered-question receipts; clipping still reduces coverage |
| Coverage | red-cell success → package sources → entry-file status | source IDs retained even below cutoff | T-073/HUNT-C: operation/question investigation and omission partitions, independent build/extraction axes |
| Finding actionability | incomplete dimensions; path-presence inference | counted path evidence and exact remediation attachment projection | T-070/T-076: supported attacker/ownership/configuration dimensions; no new finding state |

## Representative bounded traces

These are **counterfactual contract walkthroughs**, not executed experiments or discoveries in
a target. They state what the inspected code would permit and what remains unknown.

### Network service

An accepted OpenAPI route enters `target_documents` with declared security state. Syntax may
show a registration; a graph entry may classify remote input; build/artifact facts may bind the
handler to a service. None establishes internet deployment. Base document hunts use
`document_context`, while inference units are path batches. T-146 should join optional generated
map context to its operation. The proposed question is: “Can this established caller input reach
this resource mutation without the required ownership check?” Its policy and caller privilege
remain unknown until evidence supports them. Source for the handler and the guard, not a DFD
edge, supports the eventual claim. A denied or unserved configuration request leaves that
question unresolved.

### Native hostile-file parser

An accepted `fread`/loader syntax site can supply a file-content hypothesis without a successful
compiled graph. It does not show that the file is attacker-supplied, that a wrapper resolves to
libc, or that a parser size calculation is unsafe. Compiled entry/sink/path/range facts, when
accepted, narrow the question to size, lifetime or ownership. Base DFD ownership requires a
process/build link; unowned sites become unknowns rather than disappearing as “safe”.
T-146 keeps a source fallback operation. HUNT-A retains supplier control and build uncertainty;
HUNT-B gives bounded fallback opportunity; HUNT-C records whether the relevant size/lifetime
question was actually answered and what source was delivered.

### Client/server authorization operation

Graph remote input is compatible with client→server, server→client and peer interactions.
A name such as `server`, a generated actor crosswalk or an RPC declaration does not select one.
Use original receiver/mutation source, protocol registration and accepted build variant to ask
which side controls the state and where authority changes. Entitlement or object-owner policy
can be absent from code; record a specific missing-policy request. Engine/middleware ownership
may route a resulting finding differently under T-070/T-076, but source root is not business
ownership. Cross-package chain execution is not needed to record this local obligation.

### Missing compiled evidence

Without a usable CodeQL export, graph coverage-only shards remain unavailable. Hunt routing
records unavailable sink-up/entry-down and falls back to persona sweep; syntax/prioritization
can still nominate source questions. A missing DFD or deployment producer must not block source
fallback, nor make guards/reachability false. Report separate discovery, build, extraction,
selection and investigation gaps. The eventual denominator is “known, source-anchored surfaces
within this discovery scope”, not “all exposed code”.

### Below-cutoff and clipped units

A unit ranked 51 with a cutoff of 50 receives a named cutoff gap but no hunt package. Base
manifests cannot join its missing source IDs; T-146 owns preserving them. A selected unit's
partition can still be unlaunched, and its context/source can be clipped. HUNT-C must distinguish
those reasons at the operation/question, not copy the most favorable status of another package
covering the same file. A successful response with no disposition for that obligation earns
execution credit only.

## Contract evidence and task reconciliation

Existing focused tests establish intended invariants in source:
[unit rank/cutoff](../../tests/review/test_units.py#L33-L85),
[hunt menu/byte accounting](../../tests/review/test_packages.py#L162-L235),
[graph scope/fallback](../../tests/review/test_packages_graph_context.py#L257-L364),
[routing determinism](../../tests/test_guidance_routing.py#L116-L174),
[threat input/citation/publication boundaries](../../tests/test_threat_model_generation_job.py#L427-L588),
[citation demotion](../../tests/test_threat_model_validation.py#L38-L115), and
[coverage proxy semantics](../../tests/test_finding_coverage_adapter.py#L66-L107).
None of these, merely existing, proves useful live coverage or detection efficacy.

| Existing task | Reconciliation needed; no acceptance closure asserted |
| --- | --- |
| T-070 / T-076 | Slice vocabularies and operator annotation exist; attacker position is deliberately not inferred. T-146 overlaps actionability projection but not evidence-backed actor/owner/configuration capture or the keyed game cases. Retain those tasks and clarify the residual interface. |
| T-073 | Its progress correctly names the implemented adapter and unperformed real-run validation. Refine “reviewed” acceptance to receipt-backed scoped investigation; keep legacy execution coverage separate. |
| T-086 | Source-ID retention is assigned to T-146. Resolve graph/operation entry identity and parser-candidate coverage once, with T-073; do not make behavior tags the sole denominator. |
| T-107 | Registry prose says no job exists and the branch is not merged. The reviewed source contains the registered first slice, tests and disabled configuration. Update implementation status, retain missing lanes and real-run acceptance; **do not mark complete**. |
| T-108 | Library-only status matches source. Keep publication and typed static declaration consumption here; do not imply actual runtime exposure. |
| T-129 | Canonical bucket file is absent. Reuse its exact tool/output-kind mapping work; provisional labels above are not authoritative assignments. |
| T-146 | Approved/in flight, not in this base. Preserve its ownership of complete subjects, observed tags, operation units, map consumer, deduplicated opportunities and quality projections. Reconcile this review after it lands. |
| T-068 / T-126 | Keep implemented offline metric formulas as such, with efficacy/denominator limitations explicit. Reuse T-126 for graph coverage expansion; do not add another graph or chain redesign here. |

Scheduling and acceptance details are in the
[proposed design](../architecture/threat-driven-hunting-enhancement.md#implementation-sequence-and-existing-task-ownership).
The TODO registry remains the only scheduling authority. HUNT-A/B/C map to
T-151/T-155/T-156, with direct registry links in the design's implementation sequence.
Shared semantic evidence-request resolution belongs to T-153, not a second hunting lifecycle.

## Validation record

This change requires documentation checks only. The owned-file check was run with
`python3 -B`, calling `scripts.docs_support.frontmatter`, `validate_frontmatter`, `link_errors`
and `identifier_errors` against `docs/generated/inventory.json` and `docs/docs-sync.json`.
The same inline check validates LF/trailing whitespace and that cited source-line ranges exist.
A separate extension validates the handoff JSON's closed shape, references and dependency keys.
The scope is only the two owned documents and proposal JSON, not the shared documentation tree.

The initial document check passed in 0.048 s. Expanded proposal validation found four incorrect
heading fragments in 0.098 s; they were corrected. The added source-line check found four
end-line references beyond EOF in 0.106 s; those were corrected too. The final rerun and elapsed
time are recorded in the handoff. `git diff --check --` with the two owned paths was also run;
because the files are new/untracked, the explicit Python whitespace check is the meaningful
content check. Runtime paths/configuration remained unchanged at the reviewed revision.

No runtime tests, integration/acceptance tests or empirical reviews were run.
Documentation-ledger/index regeneration is deliberately left to its owner in the shared dirty
checkout. Source-backed conclusions above are not performance or vulnerability-quality results.
