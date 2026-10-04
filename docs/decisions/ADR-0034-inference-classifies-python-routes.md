# ADR-0034: Inference classifies, Python routes (OWASP ASVS universe first)

Status: **Accepted** (2026-10-04, William: "model jobs emit classification and metadata only; deterministic
Python decides every job's universe"). Wave 0 (this record, frozen contracts, rule table, configs, guard
tests) is merged; the jobs land in wave 1, the chain switch and deletions in wave 2 (P3).

## Principle

1. A model job emits **classification or metadata only**: a label, a role, a citation, a rationale. It never
   chooses what other jobs look at, which controls apply, which lanes run or how much work follows.
2. **Deterministic Python decides every job's universe** from accepted evidence and versioned rule data, and
   publishes it as an extract: the included items, the excluded items, and the reason for each.
3. **Every model-dispatching job computes its planned calls and enforces a budget before the first call.**
   Over budget is `BLOCKED` with the plan recorded, never a partial run and never a silent cut.

## Context: run 20261003T235640Z-f42fbf

The OWASP chain on hello-autotools let the model shape the work at every step:

- `01-component-characterization` (a model job) returned **9 function-level components** for a small C CLI,
  each with model-invented `downstream_lanes`; `standards_lifecycle` routed worklist targets from those lanes.
- `owasp_component_routing` matched components to families by **keywords** (`_tokens`, `_family_match`,
  `_local_only`, `NON_WEB_NA_DOMAINS`, `LOCAL_KINDS`, `NETWORK_TRAITS`) and emitted **`all_controls`** rules,
  so every matching component got every L1+L2 control (253 rows each).
- `config/owasp-batching/default-v1.json` cut each component's chapter into **12-row batches**; with the
  pinned ASVS 5.0.0 snapshot that is 29 batches per component, so up to 9 x 29 = 261 validator cells
  (formula over the v1 limits; the number of cells actually started is in that run's T05 batch plan).
- `run_dispatch` ran them with **`max_parallel` 1**.

Cost scaled with how many components the model named, not with what the code does, and nothing checked the
plan before the calls started.

## Decision: the OWASP ASVS universe

Three graph nodes with per-chapter cells replace component routing. Contracts are frozen as JSON Schemas.

| Node | Kind | Dependencies | Output (schema) |
|---|---|---|---|
| `04-owasp-candidate-search` | Python | `02-code-index` (req), `02-code-property-graph` (req), `02-treesitter-ast` (req; skip `not-applicable-language-absent`), `02-source-sast` (optional) | `owasp-candidate-search.schema.json` |
| `04-owasp-participation` | model, read-only `code_*` tools | candidate-search (req), `02-code-index` (req) | reply `owasp-participation-cell.schema.json`; result `owasp-participation.schema.json` |
| `04-owasp-universe` | Python | candidate-search (req), participation (req; skip `no-candidates`) | `owasp-universe.schema.json`, `asvs-participants-V<n>` (`owasp-participants-bundle.schema.json`) |

**Candidate search.** For each ASVS 5.0.0 chapter V1..V17 it evaluates `data/owasp-asvs/category-rules-v1.json`
(`owasp-category-rules.schema.json`) over the accepted index. Rule kinds and the only source each reads:
`calls_to` (`calls.callee_name`, `ts_calls.callee`), `symbol_regex` (`methods`, `ts_functions`),
`identifier_regex` (`identifiers`), `literal_regex` (`literals`), `import_regex` (`imports`), `sast_rule_ids`
(accepted `02-source-sast` hits), `entry_point` (`methods` named in
`dep_reachability_engines.ENTRY_POINT_SOURCES`, or joined by `exports.method_id`). A hit becomes a candidate at
its enclosing function (`methods` span, else `ts_functions`; outside any function a `<module>` candidate at the
hit line). V2 widens from input-source rules one hop along resolved calls (`propagation`). Hits under test,
docs, example, vendored, generated or build-system globs are published as `excluded` with that reason. Every
chapter is listed with its search basis (rule id, kind, hit count), zero included. A source language the table
does not cover, or that tree-sitter did not parse (`no-grammar`, `grammar-unavailable`, `max-files`,
`file-too-large`), makes coverage incomplete.

**Participation.** One cell per chapter with candidates, split by `max_candidates_per_cell`. Persona
`owasp-validator`, new role `asvs-participation-classifier`, new tooling profile `owasp-participation-static`
(the `code_*` query lines of `hypothesis-hunt-static.json`), grant through `code_query_grant`
(`claude_cli_invoker.py`); pool mechanics as `hypothesis_discovery.py`. The reply carries only
`records[{candidate_id|null, symbol, file, start_line, end_line, role, citations[{file,line}], rationale}]`,
role `implements | enforces | consumes | not_participating`. Python checks every citation resolves in the
snapshot and every candidate has exactly one record; a missing, duplicate or unresolved record is an
`unclassified` gap. Planned calls = sum of `ceil(candidates / max_candidates_per_cell)`, checked against
`max_participation_calls` before the first call.

**Universe.** One target `asvs-V<n>` per chapter with decision and reason:

- `participating` (`participating_code_cited`): at least one validated implements/enforces/consumes record.
  Symbols roll up to files; a symbol or file may take part in several chapters. The chapter's evidence bundle
  `asvs-participants-V<n>` holds hash-bound source excerpts of its participants (canonical evidence).
- `not_applicable`: zero candidates with complete coverage, or every candidate `not_participating` with
  resolved citations. Nothing else is N/A.
- `gap`: incomplete coverage, unclassified candidates, or participation unavailable.

Budget: planned validator calls = sum over participating chapters of
`ceil(L1+L2 control rows / max_control_target_rows)`; `max_control_target_rows` is read from the batch config
the universe config names (`default-v2.json`, 40), `max_validator_calls` is 20
(`config/owasp-universe/default-v1.json`). Every chapter has at most 35 L1+L2 rows, so a full universe plans 17
calls. Over budget the universe is written `BLOCKED` (with `budget_exceeded`), is never accepted, and no
validator call is made. MASVS for a target with no mobile platform is a `not_applicable` family with its reason.

**Chain adaptation.** T03/T04/T05/T06/T10 and the join stay.

- `owasp_component_routing.py` loses its keyword logic (`NON_WEB_NA_DOMAINS`, `LOCAL_KINDS`, `NETWORK_TRAITS`,
  `_tokens`, `_local_only`, `_family_match`, the rule loop). The job id stays as a pure projection of the
  accepted universe into `owasp-applicability-request.json`: one component per participating chapter.
- `owasp_applicability` gets a universe binding and an optional component field
  `control_scope {domain_ids: [Vn]}`, so a chapter target gets only that chapter's controls (253 rows in all).
- The lane-in admits `asvs-universe` (`derived_intelligence`, `locator_only`) and `asvs-participants-V<n>`
  (`source_excerpt_bundle`, `canonical_evidence`).
- Batching uses `config/owasp-batching/default-v2.json` (`max_control_target_rows` 40, `max_components` 1,
  qualification fixture `tests/fixtures/owasp-batching-default-v2.json`); v1 stays for existing tests. The
  projection routes every obligation of a chapter through one batch route, so T05's batch count equals the
  universe's plan.
- `04-owasp-validator-cell` takes a tunable `max_parallel` capped by `pool_persona_llm_slots`, passed at the
  `dagster_workflow.py` OWASP dispatch call; `run_dispatch` no longer defaults to 1 and re-checks that the
  handoff count equals the planned count and is within budget, refusing without an accepted universe.
- The `standards_lifecycle` OWASP worklist reads the projected universe request; the inline `_route_owasp` is
  removed. Graph edges `04-owasp-universe -> 04-owasp-validation-worklist` and `-> 04-asvs-masvs`.
- The component map stays admitted, as report context only.

### Open questions, decided

1. **Unit.** Candidates are functions/symbols; files are a roll-up; one item may sit in several chapters.
2. **Not applicable.** Only for zero candidates under complete coverage, or all candidates
   `not_participating` with resolved citations. A failure to search or classify is a gap (AGENTS.md rule 2).
3. **Budget.** Planned = sum `ceil(rows / 40)` per participating chapter; limit 20 validator calls and
   34 participation calls (40 candidates per cell). Over budget is `BLOCKED` before any call; raising a limit
   is a new config version, never a runtime override.
4. **MASVS.** Applies only to a mobile target; otherwise a `not_applicable` family with its reason.
5. **Component routing and map.** The job id survives as a projection; the keyword routing is deleted; the
   component map is report context and no longer routes OWASP work.

### Code index gaps found while writing the rule table (wave-1 tasks)

- `literals` holds only string literals in call-argument text (`how = call-argument-text`); initializers and
  tables are not indexed. `literal_regex` hits are a lower bound. Task: add tree-sitter string-literal rows or
  keep literal rules as corroboration only.
- `identifiers` comes from the CPG only; for a tree-sitter-only language `identifier_regex` has no rows.
  Candidate search must report such a rule as `rule_without_index_support`, not as zero hits.
- `exports` is the binary dynamic export table (with an accepted `02-binary-triage`), not source exports;
  `entry_point: exported_symbol` covers shipped native libraries only.
- Source-SAST hits are not in the index; candidate search reads the accepted `02-source-sast` result.
- `files` lists only what the CPG or tree-sitter saw. Unparsed languages (Kotlin, Swift, Objective-C, Scala:
  no grammar in `treesitter_ast.SUFFIXES`) are known only from the tree-sitter gaps, which candidate search
  must read.
- Framework handlers exist in `ENTRY_POINT_SOURCES` for Java, Go and C# only; JS, Python, PHP and Ruby
  handlers are reached through import rules.
- Rust `unsafe` blocks are not indexed.

## Consequences

- Fingerprints of every `04-owasp-*` job change (new nodes, new request shape, v2 batch config); the OWASP
  chain reruns once. Earlier OWASP results are not comparable row for row (per chapter, not per component).
- Cost follows the code: a small CLI plans a handful of validator calls (the guard test caps the
  hello-autotools-like fixture at 12); a 40-component target with code in three chapters plans 3.
- A large native target can exceed the participation budget (many candidate functions per chapter). That is
  a visible `BLOCKED` with the plan, resolved by a reviewed config version, never a silent cut.
- The old routing, the inline `_route_owasp` and the use of `downstream_lanes` for OWASP are removed.
- Guard tests: `appsec-review-process/tests/test_adr34_owasp_participation.py`.

## Follow-ups

1. Audit the other places a model output routes work (other uses of `downstream_lanes`, STIG/SRG targets,
   threat-model and hunter shard selection, claim-review sharding) and move each universe to Python with an
   extract and a budget.
2. MASVS only for mobile targets: a deterministic mobile-platform detector (manifests, Gradle/Xcode projects)
   and MASVS category rules, with Kotlin/Swift indexing.
3. The Android case in the multi-vuln target: its Kotlin/Java sources need indexing before the MASVS universe
   can be anything but a gap.
