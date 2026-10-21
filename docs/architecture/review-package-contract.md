# Review package and finding-lead contract

Status: implementation contract. Inference review packages are schema version 6
(`appsec-review/review-package/6`, assembly rule `assemble-review-packages/7`); the catalog-derived
document packages below stay at version 3. Accepted-manifest scope assembly, lane A
finding-lead packages for every lead family, lane B review-unit ranking and hunt packages,
membership audits and the package manifest are implemented in `src/appsec_review/review/`
(`scope.py`, `lead_families.py`, `units.py`, `packages.py`, with pinned-feed reference context
from `advisories.py` and `references.py`). The inference job consumes these packages
(`job_inference_security_review`). Version 3 added lead `advisory_context`, `advisory_summary`,
`weaknesses` and `admission_reasons`, and the `advisory_kev`/`advisory_epss` rank signals.
Version 4 adds accepted code-graph context (see [Code-graph context](#code-graph-context-version-4)).
Version 6 adds the package neighborhood and the model-facing view (see
[Neighborhood and view](#neighborhood-and-view-version-6)).
Version 5 adds lead-level memory and caller context for C/C++ leads (see
[Memory and caller context](#memory-and-caller-context-version-5)).

This contract specializes [inference security review](inference-security-review.md). Its
machine-checkable shape is [review-packages.schema.json](../schemas/review-packages.schema.json).
The earlier broad `review-input-package.schema.json` draft was removed when this implemented schema
became authoritative. Both package kinds here are pre-adjudication inputs: scanner severity is
*reported* severity for ordering, never an adjudicated finding severity.

The same versioned schema also accepts the separate catalog-derived package producer
`job_review_package_assembly`. Its `document_hunt` variant contains one accepted
`document_context` route or boundary fact and bounded source-record grants, with no scanner lead.
That producer also emits its earlier `finding_lead` and `hunt` shapes. The two producers have
distinct content-addressed manifests (`review-package-manifest/2` for catalog packages and `/1`
for inference packages), independent membership checks, and separate consumers. The document
packages are consumed by `job_document_issue_analysis`, which publishes private candidates only;
the inference job does not yet consume those document hunts. A declared route, test assertion, or
exact route registration is not proof of control enforcement.

## Source of each field

| Contract field | Accepted source and current query |
|---|---|
| `run_id`, `manifest_sha256`, `target_snapshot` | `resolve_accepted_manifest` and `load_verified_manifest` in `retrieval/core.py` and `retrieval/index.py`; verify each shard and the source snapshot before assembly. |
| `scope`, `source_ids`, `artifact_ids` | Catalog component, source, build-unit and artifact entities; `find`, `query_artifacts`. No synthetic trust boundary: use `null` until an accepted producer provides it. |
| `lead_menu` | `review/lead_families.py`: one versioned rule per lead family (see gate 3). Source-SAST and CodeQL reuse `normalize_reported_severity` and the accepted `scanner_correlation` lead facts of `indexing/sast.py` for suppression, duplicate and flow identities. Each lead keeps its accepted identity, scanner, rule, bounded `message`, `rule_cwe`, native severity, reported severity, `severity_rule` and `severity_basis`. |
| `lead_menu[].advisory_context` (lane A only) | `review/advisories.py` over the accepted `dependency_advisories` facts that cite the lead's observation: up to three advisories, each with the OSV summary, fixed versions and aliases; CVE ids; NVD records (status, dates, bounded description, CWEs, up to six CVSS metrics with family, version, vector, base score and severity); KEV entries (listed, date added, due date, ransomware use, name); EPSS entries (score, percentile, score date); per-join status; the snapshot id and staleness of each feed; and the fact's gaps. `null` when no accepted fact cites the lead. Reference context only (R3: indirect for every predicate). |
| `lead_menu[].advisory_summary` | The compact form on every lead (the only advisory form on hunt menus): CVE ids, KEV flag (`null` when unknown), highest EPSS percentile and max CVSS base score; `null` without an advisory fact. |
| `lead_menu[].weaknesses` | One block per CWE in `rule_cwe` (origin `rule`) and in the joined NVD records (origin `nvd`), at most eight: CWE id, name and abstraction from the run-pinned MITRE catalog (`source: mitre_catalog`), else from accepted `reference_intelligence` facts, else `unresolved`. |
| `lead_menu[].admission_reasons` (lane A only) | `reported_severity` when the reported severity is admitted, `kev_listed` when the advisory is KEV-listed and `lead_admission_kev` is on. |
| `lane`, `lead_family`, `rank` | `finding_lead` packages are lane `lead` with a non-null family and `rank: null`. `hunt` packages are lane `hunt` with `lead_family: null` and carry the unit's `review-unit-rank/2` rank and basis. |
| `persona`, `stack_profile` | Always `null` at assembly. Routing fills them later; assembly never guesses them. |
| `evidence`, `context` | Accepted observation, priority, CodeQL, source, build and precomputed shard identities; `find`, `trace`, `resolve_evidence`, `query_codeql`, `query_hotspots`, `query_precomputed`. A cited relation is a nomination until it resolves to a source line or hash-verified run artifact. |
| `proof_obligations` | Deterministic rule table keyed by lead class and observed prerequisites: affected construct, input control, reachability, guard/configuration state, and impact. Missing predicates stay open; model prose cannot close them. |
| `coverage_gaps` | Accepted index coverage, dataset inventory, query-set and language/build-unit cells; `coverage`, `query_dataset_inventory`. A failed, absent or skipped producer is a named gap. |
| `retrieval` | Intersection of accepted package identities, available index names, query sets and configured caps, plus `graph_families` (v4): the code-graph families accepted for the package scope, and `graph_scopes` (v4): the CodeQL scope ids of those facts, which bound every capability's scope-checked graph grant. These are grants proposed by assembly, not an MCP authorization token. |

Each `context` entry is typed `{id, kind, role}`. `kind` is the retrieval entity kind of `id`.
`role` is one of `source`, `artifact`, `component`, `build_unit`, `duplicate_of`, `flow`,
`priority`, `history`, `hotspot`, `tag`, or (v4) `entry_point`, `sink`, `path`, `guard` and
`range`. Bare identity lists are not accepted. Since the engineering-signal and profile-data
wiring, `review/units.py` also emits `test_coverage`, `profile_hotspot`, `dependency` and
`openssf_scorecard` context roles from the accepted `job_test_coverage`, `job_profile_data` and
`job_dependency_intelligence` producers registered in `review/scope.py`. They are named once in
`review/units.py::SIGNAL_CONTEXT_ROLES`, and `review-packages.schema.json` enumerates them for
`inference_context.role`; `tests/review/test_packages.py` keeps the two in step.

### Code-graph context (version 4)

`review/packages.py::GraphContext` reads the accepted `graph` shards
([code-graph precomputation](code-graph-precomputation.md) section 7.5, rule
`package-graph-context/1`). A graph shard applies to a package scope when it names the scope's
build unit (shard producer `build_unit_id` or a fact's `scope.build_unit_id`) or holds a fact
located in one of the scope's paths. A family is listed in `retrieval.graph_families` when an
applying shard covers it in any state but `unavailable`.

- Lane A: a lead package embeds every `dataflow_path` correlated with its observation by a
  `DERIVED_FROM` relation whose state is `bridged` or `partial` (role `path`), that path's
  `sink_site` (`sink`) and `entry_point` (`entry_point`), and the sink's `guard_fact` (`guard`)
  and `range_fact` (`range`) facts. A `broken` correlation is never embedded.
- Lane B: a hunt package embeds the unit's `sink_site` and `entry_point` identities, taken
  round-robin by (role, class) in identity order within whatever `max_context_entries` leaves after
  the unit's other context; the rest are counted in `omitted_context` with a `code_graph`
  `truncated` gap.
- `coverage_gaps` carry the scope's `code_graph` lane: `partial` for families covered only
  partially and `unavailable` for families with no accepted coverage. Without any accepted `graph`
  index every package carries a `code_graph` `missing` gap, and the accepted scope's `code_graph`
  producer (`review/scope.py`) adds the run-level one.
- `retrieval.graph_families` also decides lane B strategies: `sink_site` provides
  `source_sink_facts` (`sink_up`) and `entry_point` provides `entry_point_catalog` (`entry_down`)
  for that package only (`guidance/routing.py::unit_sources`). Symbol links unlock no strategy.

- `retrieval.graph_scopes` lists the CodeQL `scope_id`s of the applying shards that are not
  `unavailable`. A review cell's `CellCapability` and the scoped MCP adapter accept a `graph` row
  outside the package's exact `entity_ids` only when the row's accepted `payload.scope.scope_id` is
  listed; the row and the graph identities its payload references then become addressable and
  citable by that cell. Rows of every other scope are withheld. There is no kind-wide grant.

Graph context is a search aid. An embedded identity is evidence only when a cell cites it and
`resolve_relation` re-resolves it under `evidence-admissibility/3`.

### Memory and caller context (version 5)

Lane A only. Every finding lead gets this context, whatever scanner reported it. The rules are
`package-memory-context/1` (`review/memory_context.py`) and `package-graph-context/2`; the design is
in [`svf-alias-producer.md`](svf-alias-producer.md) section 7.

- **Memory context (C/C++ leads).** The lead's path and line are joined to the accepted
  `job_svf_alias_analysis` shards in the `analysis` index:
  - role `points_to`: the `points_to_set` records of the pointer sites on that line;
  - role `indirect_call`: its `indirect_call_targets` records;
  - role `memory_object`: the `memory_object` records those sites reference, each carrying its
    allocation site, allocator and bounded accessor fan-in.

  Every gap uses producer `svf_points_to`:
  - `missing` when no SVF shard is accepted (the job is opt-in);
  - `ambiguous` for a lead without a line;
  - `unavailable` when the line holds no record or the file is in no analyzed module;
  - `partial` when a record comes from an open-world module or is incomplete;
  - `truncated` beyond `max_memory_context_entries`, which keeps objects first, then sites, then
    indirect calls.

  Leads in other languages get neither entries nor gaps.
- **Caller context.** The lead's enclosing function comes from three places: the SVF records on its
  line, the `sink_site.enclosing_function` of graph facts on that line, and the caller of `call_site`
  facts on that line. Role `caller` lists the accepted `call_site` facts reaching that function,
  breadth-first to `caller_depth` levels and at most `max_callers` entries, in (depth, identity)
  order. A call matches by callee symbol when both sides have one, otherwise by unqualified name;
  `secondary_only` facts from SVF and clangd have no callee symbol. Gaps use producer
  `code_graph_callers`:
  - `ambiguous` when any match was by name;
  - `truncated` beyond `max_callers`;
  - `unavailable` when no accepted fact names the enclosing function.

The three bounds are tunables of the review job, set in `appsec-review.toml` under
`[jobs.job_inference_security_review.settings.packages]` and validated at load. They are required
keys with no code default on the job path:

| Setting | Meaning | Bounds |
|---|---|---|
| `max_memory_context_entries` | SVF entries per lead package | 1–1000 |
| `max_callers` | caller call-site entries per lead package (fan-out) | 1–1000 |
| `caller_depth` | caller levels walked from the enclosing function | 1–4 |

The entries still count toward `max_context_entries` and `max_package_bytes`, under the same
role-balanced truncation as every other role. Like graph context, this is a search aid: an
embedded identity is evidence only when a cell cites it and it re-resolves.

The proposed `buffer_bound` role in
[`graph-alias-slice-layout-modes.md`](graph-alias-slice-layout-modes.md) (chunk G7) planned to
claim version 5. It now needs version 6.

`input_fingerprint` hashes canonical JSON of the accepted manifest hash, package scope, all
sorted referenced shard hashes (including every applying graph shard), lead IDs, rule versions
(assembly, obligations, rank, every lead-family rule, the advisory-context rule and the
graph-context rule), the CWE reference record (source, MITRE snapshot and gap) and resolved cap
settings. `package_id` is `<kind>-<sha256>` over the
canonical package body without `package_id`. Arrays of IDs,
evidence and gaps sort by stable identity; no timestamps or completion order enter identity.
Reassembly from the same accepted inputs must produce byte-identical packages. The schema
closes object keys and bounds structural types; a semantic validator must additionally verify
hashes, sorted uniqueness, cited identities, page/byte caps and membership invariants.

### Neighborhood and view (version 6)

Review protocol v2 ([`review-protocol-v2.md`](review-protocol-v2.md)) changes what a cell is shown, not
what the stored package pins. Two things are new.

**The stored `neighborhood` (`package-neighborhood/1`, `review/neighborhood.py`, `GraphContext.neighborhood`).**
Every package has a required `neighborhood` object. For a lane A lead it is selected by *location and
function scope*, not by a correlated dataflow path:

- `function`: the lead's function symbol, name, path, start line, file hash and `basis`
  (`enclosing_fact_on_line` when a sink or call fact on the lead's line names it, otherwise
  `nearest_preceding_definition`, which also adds an `ambiguous` gap);
- `sinks`, `ranges`, `guards`, `flows`, `entries`: every `sink_site` on the lead's line or in its function, the
  `range_fact`, `guard_fact` and `dataflow_path` facts of those sinks, and the `entry_point` facts of the function or
  of those flows;
- `callers`, `callees`: `call_site` facts to `max_call_depth` levels, matched like caller context;
- `chain`: the shortest call-site chain upward from the lead's function to the nearest function that holds an
  `entry_point` fact (`reached`, ordered `hops`, the `entries` reached). When no entry point lies within
  `max_call_depth` levels the package carries an `unavailable` `code_graph_neighborhood` gap: reachability is
  unknown, never excluded;
- `corroboration`: other observations on the same line (strongest first, at most 16);
- `build`: compiler, ordered flags and hardening flags from the accepted `build_provenance` command facts that
  compile the file (`package-build-summary/1`), or a `build_provenance` gap;
- `omitted`: per-section counts of rows removed by the bounds.

Each row is an identity, a line and a one-line summary (`fact-summary/1`, `review/fact_summary.py`). A guard summary
states the guard state, polarity, condition text, operator and operand texts, and nothing about whether the guard
bounds the destination of a write. Every row is also a `context` entry (new roles `function`, `callee`,
`corroboration`, `build`), so a cell may cite it. The bounds are the code-graph settings
(`max_call_depth`, `max_neighbors_per_function`, `max_paths_per_sink`, `max_guards_per_sink`, frozen into the run) plus
`max_package_bytes`; a row removed for bytes is counted in `omitted` and named by a `truncated`
`code_graph_neighborhood` gap. Neighborhood rows are not capped by `max_context_entries`. A hunt package carries the
summaries of its embedded sink and entry-point facts. The neighborhood enters the package fingerprint with
`package-neighborhood/1`, `fact-summary/1`, `package-build-summary/1` and the graph caps.

**The model-facing view (`package-view/2`, `review/package_view.py`).** A cell is shown a view built at cell time
from the stored package, never stored as an identity and never part of a reuse basis (the basis stays the hash of the
stored package). Labels are assigned in a fixed order so one package always yields the same labels: `L` lead, `S`
source, `K` sink, `R` range, `G` guard, `F` call site (chain hops first, then callers, then callees), `P` flow, `E`
entry point, `M` memory context, `C` corroborating finding, `B` build, `T` tag, `X` material gap, `O` other context;
`Q` labels are added for every row a retrieval turn returns, and `A` labels for a claim's affected entities in blue and
verifier cells. The view:

- embeds the function's source text and, as a stated rule, the declaration (field names, types, array sizes) of every
  type the function's signature and body name that the accepted index or the lead's file declares; source is read
  through the accepted index (`RetrievalCore.read_source_lines`) and verified against the indexed file hash, and a
  type that cannot be located is a material gap;
- shows inline only the coverage gaps that bear on the package (its partition or unit, or naming its paths,
  function, build unit, a lead or a sink: `package-gap-view/1`). Every other gap stays in the stored package and is
  written once to a hash-referenced `gaps.jsonl` listed under `files` with its count and SHA-256, reachable with
  `expand`; inline plus file always equals the stored gap count;
- has a byte budget (`max_view_bytes`) and drops the least valuable rows first, counted in `omitted` and named by a
  material gap;
- omits `retrieval.entity_ids` and every raw identity that is not a labelled row;
- redacts the literal on the line(s) of every `secret` lead (`secret-redaction/1`; see gate 2). `package-view/2`
  differs from `/1` only by this redaction.

The three view bounds live next to the package bounds:

| Setting | Meaning | Bounds |
|---|---|---|
| `max_view_bytes` | byte budget of one view | 4096–1048576 |
| `max_view_source_lines` | longest function excerpt in lines | 10–2000 |
| `max_view_type_declarations` | type declarations embedded in a view | 0–32 |

## Assembly and admission gates

1. Resolve one accepted pointer and verify the run-owned handoff, manifest, target snapshot,
   physical shards and embedded identities. A changed hash, escaped path, conflicting shard,
   failed dataset publication audit or contradictory schema blocks package publication.
   `scope.accept_manifest` uses `resolve_accepted_manifest` and `load_verified_manifest`,
   re-checks each shard's row counts and snapshot against its embedded metadata, and raises
   `IntegrityError` on any mismatch. `AcceptedScope.verify` re-hashes every shard before
   assembly returns.
2. Build the evidence map: available and missing coverage per producer, components, build
   units, languages and reference-intelligence freshness. An absent producer shard is a
   `missing` gap and a stale feed a `stale` gap, with ids from `make_id("gap", 1, ...)`. Then
   normalize every accepted lead of every family with its versioned rule
   `appsec-review/lead-family/<family>/<n>` (`/2` for `artifact_scanner`, `dependency_advisory`
   and `source_sast`, `/1` otherwise):

   | Family | Accepted records | Reported severity |
   |---|---|---|
   | `source_sast` | `tool_observation` classified `source_sast`, plus the producers the decision table below maps to it (shellcheck and psalm, whose records carry the generic `static_analysis` category, and Infer) | `normalize_reported_severity`; suppression, duplicate and flows from accepted `scanner_correlation` lead facts (unknown for the tools correlation does not index) |
   | `codeql` | CodeQL observations | the same rule; `security_severity` bands first |
   | `artifact_scanner` | `job_artifact_security_analysis` observations | scanner CVSS band, else the pinned NVD CVSS band (basis `nvd-cvss-band`), else native label |
   | `dependency_advisory` | dependency-class observations (OSV, Grype) | the advisory's own CVSS band, else the pinned NVD CVSS band (v4.0, v3.1, v3.0, then v2; basis `nvd-cvss-band`), else its severity label |
   | `ci_rule` | `job_ci_configuration_analysis` observations | native label |
   | `post_build_hardening` | deterministic `build_security` checks with status `FAIL` | native label if published, else `unknown` |
   | `owasp_control` | `control_evidence` facts with status `not_satisfied` | native label if published, else `unknown` |
   | `secret` | secret-scanner observations (`tool-gitleaks`; any observation of class `secret`) | `unknown` (basis `no-native-severity`): the scanner reports none, and an unmapped label stays `unknown`, never low. Rule CWE `CWE-798`. |
   | `config_scanner` | Dockerfile and IaC misconfiguration observations (hadolint, checkov, trivy) | `normalize_reported_severity` (checkov reports none: `unknown`) |

   A family whose accepted producer shard is absent is a `missing` gap, never an empty list.
   `secret` needs the `secret_scanner` producer (the `tool-gitleaks` observation shard) and `config_scanner` the
   `config_scanner` producer; neither counts as source-SAST coverage.

   **Producer decisions (`OBSERVATION_PRODUCERS`).** Every producer of `tool_observation` rows has one explicit
   decision in `review/lead_families.py`: a lead family, or a reason it is deliberately not a lead (SBOM inventory,
   scanner diagnostics, binary hardening of catalog binaries, GitHub Actions findings the CI job already reviews,
   model-proposed post-build observations, derived graph rows). An observation whose scanner is neither mapped nor
   listed is counted per shard and scanner in an `unmapped_observations` `partial` gap, never dropped silently;
   deliberate non-leads are counted in the manifest's `non_lead_observations` (`class:<class>` or
   `scanner:<id>`). `tests/review/test_lead_coverage.py` fails when an evidence-collection tool or a job that
   derives `tool_observation` entities has no decision. The audit is in
   [`../reviews/lead-coverage-audit.md`](../reviews/lead-coverage-audit.md).

   **Secret values never reach a model (`secret-redaction/1`, `review/secret_redaction.py`).** Secret scanners run
   with `--redact` and the intake keeps no match, secret or entropy field: a `secret` lead carries only scanner,
   rule id, location, `location_exact` and the stable observation id, and its scanner message is passed through
   `redact_message`. The one remaining path is the source text of the model-facing view: for a `secret` lead the
   flagged line(s) are shown with every quoted literal, unquoted value after `=` or `:`, and long mixed token
   replaced by `<redacted:n chars>`, indentation, names and call structure kept (a multi-line span is replaced line
   by line), so the model can reason about where the credential is used but never sees it. Residual: the typed
   retrieval tools (`read_excerpt`, locators) read the file themselves and are not redacted by this rule.
   Without an accepted `scanner_correlation` shard, duplicate state is recomputed with
   `build_scanner_correlation`, suppression is `unknown`, and a `partial` gap is recorded. When
   the shard is present, its lead facts must cover exactly the accepted source-SAST
   observations and agree with the severity rule, and its audit counts per severity must match;
   a contradiction is an integrity failure. The assembler enumerates accepted shards
   exhaustively and never pages through a bounded MCP route such as `query_observations`.
3. **Lane A.** Admit every lead whose reported severity is in `admit_severities` (default
   `critical`, `high`, `unknown`) from every family, plus every lead whose advisory is KEV-listed
   when `admit_kev` (`lanes.lead_admission_kev`, default `true`) is set, and create exactly one
   `finding_lead` package per admitted lead, including suppressed, duplicate, unresolved-location and
   unknown-severity records. Preserve the original identity and native severity.
   Duplicate and suppression state is context, not a reason to remove the package.
4. **Lane B.** Partition review units by accepted component, then accepted trust boundary if
   known (none is accepted yet, so it is `null`), build unit and stable range of sorted source
   paths (`unit_max_files`). Rank units by `review-unit-rank/2`: the sum of the available signals
   in integer points 0–1000 (LPS, SII, hotspot, tag density, medium/low/info lead hints,
   `advisory_kev` = 250 when any advisory lead in the unit is KEV-listed, and `advisory_epss` =
   250 times the highest EPSS percentile), then the count of known signals, then unit key. A
   missing signal is `unknown` with reason `producer_unavailable`, `no_record` or
   `feed_unavailable`, never zero; a unit without advisory leads scores a true zero for both
   advisory signals. The top `hunt_max_units` units receive hunt
   packages; every other unit is a `skipped` gap with reason `below_hunt_cutoff`. A hunt menu
   lists every lead of its unit by reported severity then identity, and embeds no source or raw
   scanner output. Menus split into numbered partitions by `hunt_menu_partition_size` and then
   by `max_package_bytes`; `next_partition` names the following partition key. Context beyond
   `max_context_entries`, or beyond the byte bound of a single-lead package, is omitted with a
   `truncated` gap and `omitted_context`. Leads are never truncated: a package that cannot fit
   one lead without context blocks the membership gate with an integrity failure.
5. Form the expected set `E` of all admitted leads (by severity or KEV listing), including
   suppressed and duplicate IDs, and `F` from finding-lead packages. Require `E ⊆ F` per family and
   severity, exactly one package
   per ID, and no invented ID. Each hunted unit's partitions list every lead of the unit exactly
   once; the leads of a unit below the cutoff are accounted for by its `below_hunt_cutoff` gap.
   Any violation raises `IntegrityError`.
6. Publish a run-owned manifest (`appsec-review/review-package-manifest/1`) listing every
   package id, kind, lane, family, partition, SHA-256 and size; the accepted input shard hashes;
   the evidence-map hash; the CWE reference record; ranked units with their basis and hunt state;
   every gap; per-family and per-severity counts, including KEV-admitted leads; and both audits. `publish_packages` writes and verifies the bytes, and
   the review job consumes the manifest only after `verify_package_manifest` succeeds. Producer
   failure publishes explicit gaps; membership or integrity failure blocks the handoff.

## Bounded retrieval and producer dependencies

| Slice | Current accepted producer/index | Query or precompute | Missing dependency and required gap |
|---|---|---|---|
| All languages, source | target catalog `source`; Tree-sitter `analysis` where grammar/scope succeeds | `search`, `find`, `read_excerpt`, `trace`, `query_precomputed(symbol_links)` | Parse failure or unsupported grammar is per language/scope; no symbol/call graph inference from syntax alone. |
| C/C++ build units | language build, compiled analysis, clangd symbols; `build`, `compiled`, `analysis`; CodeQL graph exports normalized by `job_code_graph_index` into `graph` | `query_build_security`, `query_artifacts`, `symbol_links`, `query_code_graph` | Graph families are per CodeQL scope and family, with `complete`/`partial`/`unavailable` rows. LLVM direct-call and Clang AST are cross-check inputs only. Joern is deprecated and absent from runs by default. |
| Go, Java/Kotlin, C#, JavaScript/TypeScript, Python, Rust build units | accepted build/artifact shards; CodeQL `observations` only for successfully executed scopes | `query_artifacts`, `query_codeql`, `build_provenance`, `scanner_correlation` | Build/CodeQL absence is per unit and language. No graph export pack exists yet, so every graph family is `unavailable` for these scopes; CodeQL path steps do not become general call/dataflow graph edges. |
| PHP, shell and other catalog languages | source/Tree-sitter and applicable SAST observations | `query_observations`, `scanner_correlation`, `search` | CodeQL, compiled and symbol lanes unavailable unless a matching accepted shard exists. |
| Cross-cutting build, CI, history, control and intelligence | accepted artifact, CI, history, priority, OWASP and pinned reference shards | `query_artifacts`, `query_ci_configuration`, `query_change_context`, `query_hotspots`; `query_precomputed` products `artifact_inventory`, `dependency_advisories`, `ci_trust`, `history_context`, `control_evidence`, `reference_intelligence` | Missing input/feed, stale feed or partial source yields a named query-set gap, not complete coverage. |

`indexing/matrix.py` computes language and build-unit cells from accepted shards;
`input_matrix.py` reconciles producer declarations against them. Stage-1 products are
`build_provenance`, `artifact_inventory`, `dependency_advisories`, `scanner_correlation`,
`ci_trust`, `history_context`, `control_evidence`, `reference_intelligence` and `symbol_links`.
The five link families are `representation`, `finding_source`, `package_advisory`,
`symbol_syntax` and `history_code`. The seven former graph query sets (`call_graph`,
`control_flow`, `dataflow`, `sarif_correlation`, `ast_ir_cpg_mapping`, `guards_ranges`,
`entrypoint_paths`) are retired: code-graph facts live in the `graph` index and are read through
`query_code_graph` ([code-graph precomputation](code-graph-precomputation.md)). `hotspot_context`
and `review_package` remain planned stage-3 products. `job_cpg_analysis` is deprecated and runs no
Joern unless explicitly enabled. The optional SQLite FTS image validates a derived
text stream; accepted in-process shards remain retrieval authority.

## Role-specific views and capability enforcement

The application creates a signed or MAC-protected, short-lived capability binding **run ID,
manifest hash, package ID and hash, role, round, tool allowlist, index and query-set allowlists,
entity scope, page/byte/depth caps and expiry**. MCP verifies the binding on every call before
dispatch, then intersects request filters and result identities with the package grant. A cursor
is bound to the same capability and query hash. `mcp/capability.py::ScopedRetrievalMcpAdapter`
implements this gate over the unrestricted `RetrievalMcpAdapter`, and review cells use the
equivalent in-process `review/capability.py::CellCapability`. Both apply the package's
`graph_scopes` grant to `query_code_graph` rows. Never hand workers the unrestricted adapter.

| View | Package content | Tool reach |
|---|---|---|
| Red discovery (`hypothesis_hunter`, `red_team_analyst`) | Hunt slice and lead menu, accepted context and gaps; no adjudicated labels | Bounded `search`, `find`, `read_excerpt`, `trace`, `coverage`, `query_observations`, `query_precomputed` and relevant domain queries inside the package scope. |
| Blue refutation | One normalized claim, original cited evidence, open obligations, relevant finding-lead package and scope; may seek counterevidence | Same bounded read routes for that claim's package, including contradicting evidence. No other claim transcript. |
| Blind verifier | One normalized claim and original evidence IDs plus the minimum scope; no red/blue narratives, scores, dispositions or actor/cache IDs | Independent fresh retrieval context and the same read-only scope. Seal its result before joining red and blue records. |

No role receives arbitrary filesystem paths, shell, SQL, regex, target guidance, evaluator roots,
raw argv/environment, network access or writes. Current MCP routes on `main` are core search,
find, excerpt, trace, resolve, coverage, artifact/build/CI/CodeQL/change/OWASP queries, and
`query_hotspots`, `query_precomputed`, `query_observations`, `query_dataset_inventory` and
`query_code_graph` (`mcp/schema.py`). `query_code_graph` is the only graph route: closed modes and
exact subject identities over accepted, hash-verified `graph` shards, with caps from the run-bound
`jobs.job_code_graph_index.settings.graph`.

## Validation and Dagster handoff

Fixtures should include two languages and two build units; accepted High/Critical, unknown,
suppressed and duplicate SAST observations; a partial CodeQL scope; an unavailable Tree-sitter
scope; an ambiguous source mapping; a stale feed; a CPG binary without graph export; and
same-line contradictory evidence. Focused tests must prove schema rejection of extra fields,
stable package hashes under shuffled input, exact High/Critical and unknown membership across
partitions, unchanged lead IDs through suppression/deduplication, gap propagation, source-line
resolution, manifest/hash tampering rejection, package-scoped MCP denial, blind-view isolation,
cursor rebinding denial and reuse invalidation when one upstream shard changes. An empty query
with partial coverage must remain a gap.

Dagster exposes the job's units as visible dependencies. The implemented topology
(`[jobs.job_inference_security_review.steps]` in `appsec-review.toml`) is `scope.accept_manifest →
scope.assemble_scope → packages.assemble_lead_packages / packages.assemble_hunt_packages →
lead_review.teams / hunt_review.teams` (each team unit runs red, normalization, triage, blue and
verifier cells) `→ merge.claims → adjudicate.apply_policy → scoring.score_claims →
completeness.audit → publication.publish_claim_ledger / publication.publish_handoff`.
Assembly and publication use immutable application attempts and a serialized accepted handoff;
Dagster schedules and records node outcomes. Every expected worker cell has one terminal record.
Ordinary producer/worker failures become scoped gaps; integrity and membership failures stop
publication. Resume fingerprints depend on accepted manifest, package bytes, guidance and
configuration so an upstream change invalidates only affected packages and worker cells.

## Ordered implementation

1. Done: schema version 4 (code-graph context roles, `retrieval.graph_families` and
   `retrieval.graph_scopes` on top of version 3's pinned-feed advisory context, weaknesses, KEV
   admission and advisory rank signals), deterministic assembly over accepted shards for both
   lanes, membership audits and manifest publication in `src/appsec_review/review/`. The fixture
   tests live in `tests/review/`, and the fixture builder is
   `tests/fixtures/inference_review/builder.py`.
2. Done: `job_inference_security_review` consumes the verified package manifest; the Dagster
   acceptance and `tests/integration/test_code_graph_end_to_end.py` run lead and hunt packages end
   to end.
3. Done: capability-scoped dispatch (in-process `CellCapability`, `ScopedRetrievalMcpAdapter`) and
   red, blue and blind projections, with denied cross-package and cross-scope queries tested.
4. Partly done: C/C++ graph facts come from CodeQL exports (`graph` index). Per-language export
   packs, and per-language/build-unit dependency selection, remain open.
5. Partly done: inference fan-out and adjudication exist (slice 1); downstream accepted finding
   publication remains open.
