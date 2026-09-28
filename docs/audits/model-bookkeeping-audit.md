# Model bookkeeping audit: fields personas write that Python should own

Date: 2026-09-28. Repo `main` at `0a5a5b5d`. Read-only audit; nothing but this file was written.
Scope: every job that sends a model call (`ClaudeCliInvoker`) and the output contract it fills.
Evidence used: the job templates, output contracts, schemas, task prompts, the post-processing and
validation code for each contract, the breakage log in `appsec-review-process/TODO.md`, persona
outputs from the four current runs, and 78 invoker `repair-log.json` files that were left in
`/tmp/claude-cli-invoker-*` (transcripts are off, so these are the only record of why the invoker
rejected a reply).

Goal: the model supplies judgments and names. Python derives ids, orders lists, computes hashes,
resolves references and stamps times. The final validator stays strict. A reference that does not
resolve becomes a gap, not a failed job.

---

## 0. Structural finding: repairs run after the gate that fails

`ClaudeCliInvoker.invoke` (`claude_cli_invoker.py` ~1140-1170) does three things in this order:

1. It shows the model the **final** schema, byte for byte (`_render_json_schema`), orchestrator-owned
   fields included.
2. It runs `fill_result` and `_fill_pinned_values`. Only build-plan, the evidence binding and the
   intake review pool pass a `fill_result`.
3. It validates the reply against that same final schema (`_validate_envelope`). A failure here
   costs a repair round (`invocation.repair_attempts`, default 1). A second failure kills the
   invocation.

The job-side repairs run later, after `pi.run_invocation` returns: the component-map repairs
`_normalize_component_ids`, `_drop_unresolved_relationships`, `_repair_against_target`,
`_record_untagged_gaps` and `_backfill_citations`; discovery's `source_revision` overwrite and
`_backfill_citation_content_hashes`; `build_classify.finalize`; and the claim-review and OWASP
checks. So they cannot save a reply that failed the schema. Two consequences:

- The model has to put a pattern-valid value in every field Python later overwrites. The component
  map has 14 `sha256:` lineage patterns and D01-D04 have `source_revision`. The model either
  invents a value or fails a round.
- The model never learns which fields are someone else's job. It spends output tokens on them and
  writes gaps complaining about them (see 1.4).

The fix is shared (section 4): a persona-facing schema, plus a per-contract **derive** step that runs
before `_validate_envelope`. The strict final validation stays where it is.

---

## 1. Summary: top 10 changes (ranked by breakage avoided x ease)

| # | Change | Why now | Ease |
|---|---|---|---|
| 1 | **Claim review pool (07/08/09/12):** the model returns `{claim_id, judgment fields, citation_ids, obligation statuses}`. Python builds the reviewer/verifier actor, resolves citation ids to the upstream citation objects, and fills `candidate_id`, `subject_id`, `evidence_sha256`, `claim_class` and the JSON `assertion` string. | **Live blocker, not yet logged:** multi-vuln `20260928T034921Z-be3585` deterministic-pool-merge/07 **FAILED 16:20 today**: "pool decision violates its closed schema ($.decision.reviewer: missing required property 'artifact_path')". All 60/60 decisions carry 6 of 10 actor fields. All 60 also give `citations` as bare id strings, so the next check would fail too. Integrity hole: when the model does type the citation objects, they are checked only by `citation_id` and then published verbatim as `review_citations` / `refutation_citations`, so a miscopied `artifact_sha256` would be published unverified. | Small: one `fill_result` in `ClaimReviewerInvoker` plus a persona schema |
| 2 | **Invoker derive step + persona-facing schema** (generalize `fill_result` into a registry keyed by contract; validate the persona schema, derive, then validate the final schema). Also use fixed envelope keys (`result`, `summary_markdown`) instead of filename slugs. | Enables every other row. 48 of the 97 rejected rounds in the repair logs were envelope-shape errors: 25 `project_discovery_summary_placeholder`, 8 "envelope['candidates'] must be a JSON object", 13 key-set mismatches, 2 md/json swaps. | Medium; shared runtime, so no job refingerprint |
| 3 | **OWASP validator result (04-owasp-validator-cell -> T07):** Python stamps identity, handoff echo, producer, terminal/budget actuals, consts, fragment/obligation skeleton and order, derived statuses, citation dereference and `result_id`. | Guaranteed failure on the first live cell. `result_id` must equal `"assessment-" + digest(document minus result_id)[:20]` (`owasp_validator_result.py:558`), which a model cannot compute. `producer.producer_id` must equal the pool `instance_id` (`owasp_dispatch.py:629`), and the model is never told it. Neither has hit yet only because every dispatch so far was `EMPTY`. | Medium: the handoff already holds every value |
| 4 | **Component map lineage/provenance out of the model schema** (`evidence_manifest_lineage`, `target`, `source_revision`, `source_snapshot_sha256`, `schema`, `characterization_basis`, citation `content_hash`). | 4/4 recent maps publish a **false gap** about these fields ("gap-manifest-lineage-hashes": "zero-value placeholders are used and rely on orchestrator overwrite"). That forces OK_WITH_GAPS and puts the false gap in the report. `content_hash` is 14% of map bytes. | Small |
| 5 | **Component map `downstream_lanes`: closed vocabulary** (model picks lane ids from a list; Python maps aliases; unknown becomes a gap). | Silent routing loss. 11 accepted maps use 60 distinct free-text lanes (`source-review`, `sca`, `03-attack-surface-mapping`...). The consumers match exact ids: `full_review_input_assembly.py:300` needs `05-native-memory`/`02-native-build` (never emitted, so no component-derived native units), and `standards_lifecycle.py:72` needs `04-asvs-masvs`/`15-deployment-hardening` (and falls back to *all* components). | Small (enum + alias map) |
| 6 | **Evidence-producer binding: drop the model call.** `_fill_binding` + `_fill_pinned_values` overwrite every field, so the reply is discarded. | 28 hash-echo repair rounds (24 "does not echo the pinned input hashes", 4 invented 63-hex hashes). A breakage-log row notes 12/13 instances failed before the fill. There are ~26 haiku calls per run for nothing. | Small (deterministic cell). **Design flag**, see 3.7 |
| 7 | **Component map ids and references by name:** Python slugs `scope_id`, `group_id`, `trigger_id`, `unknown_id` and `gap_id` as well as `component_id`. It resolves every `*_component_ids`, `parallel_review_group`, `rescope_trigger_id` and `affected_scope_ids` by name or slug, derives `parallel_review_groups[].component_ids` from the components, and sorts and dedupes. A miss becomes a `classification_gaps` entry. | 5 of the 01 breakage-log rows are this class (derived id, dangling edge, ordering, missing tag). The existing repairs cover only components, relationships and tags. Every other reference still fails the job. | Medium (extends existing repairs) |
| 8 | **Build classify: `fill_result` like build-plan, and pre-seeded units.** Python stamps `source_revision`, `target`, `index` and `build_set` before validation, and gives the model the index units (`unit_id`, `root`) to classify. An index unit the model omits becomes `unclassified` plus a coverage gap. | The prompt says "write null", but `source_revision` is `type: string` (7 null rejections in build-plan before its fill). "index unit X is not classified" is a hard failure today. | Small |
| 9 | **Build plan: Python fills `plans[0].unit_id/root/class` from `plan-unit.json`; the model echoes `unit_id` only as a check value.** | 9/38 wrong-unit plans and one run-killing wrong unit (be3585). **Meaning flag:** stamping the id alone would hide a plan written for the wrong project. Keep the echo, and treat a mismatch as retry, then gap. | Small |
| 10 | **D01-D04 discovery: provenance out of the schema, references resolve to gaps, derived coverage.** `source_revision`, `target` and `content_hash` go into the derive step. `relationships[].target_partition_id`, `safe_command_plan[].project_id` and `dependencies[].target_service_id` resolve by id or name, and a miss becomes a coverage gap. D01 `coverage.unassigned_paths` is computed from the inventory minus the include/exclude patterns. | Today these fail in `validate_job_output` (`_partition_errors`, `_project_discovery_errors`, `_operations_topology_errors`). `unassigned_paths` is model-written and only format-checked, so it can be silently wrong. `content_hash` is 21% of project-inventory bytes (20.3K of 97.5K). | Small-medium |

---

## 2. Past-breakage tally

### 2.1 Breakage log (`appsec-review-process/TODO.md`, 94 dated rows)

Rows caused by the model writing bookkeeping:

| Run | Job | Bookkeeping class | Row summary | Fixed by |
|---|---|---|---|---|
| hello 9de8ccea | 01 component map | derived id | relationship id `report-runner--writes-to--logger` not the derived id | always derived (6450f3f8) |
| hello 73fe984c | 01 | dangling reference | edge endpoint `tmp-hello-autotools-log` not a component | `_drop_unresolved_relationships` -> gap |
| freeciv21 a63ffa38 | 01 | ordering; exact path; coverage | tag ids unordered; representative location not a target file; `flake.nix` in no scope | `_repair_against_target` |
| hello helloautotoo | 01 | derived id | `fixed-buffer-store` vs name "Fixed Buffer Store Macro" | `_normalize_component_ids` |
| hello helloautotoo | 01 | cross-reference coverage | component missing from tag cloud (item d; a-c were validator bugs) | `_record_untagged_gaps` |
| multi-vuln 17b564af | 03 (from 01 output) | cross-reference binding | "F03 must cite exactly one F02 assembly artifact; found 0" | threat model binds a default |
| hello helloautotoo | 02-evidence-assembly | hashes | 12/13 cells miscopied 4 hashes + job id | `_fill_pinned_values` |
| hello helloautotoo | 02-evidence-assembly | whole output is bookkeeping | non-JSON twice | `_fill_binding` supplies all |
| hello helloautotoo | persona-tool-pool-dispatch | echo | reviewer failed to echo canonical candidates | `fill_result` supplies all |
| doom3 0c0b82 | 02-build-plan | roll-up | tier C unit not named in `coverage_gaps` | `_fill_known` |
| multi-vuln be3585 | 02-build-plan | unit identity | 9/38 units planned the wrong unit | inline plan-unit.json |
| multi-vuln be3585 | 02-build-plan | unit identity | wrong-unit plan failed the job, 18 paid plans discarded | per-unit retry -> gap |

The same class appears in code comments rather than the log: D01 `source_revision` "unknown"
(hal5000 2026-09-24) and D01 `content_hash` (same day) in `discovery_gate.py:617-634`; build-plan
null `source_revision` (freeciv21) and image base `:local` tag (multi-vuln) in `build_plan._fill_known`.

**Not yet logged:** multi-vuln be3585 07 red-team pool merge FAILED 2026-09-28 16:20 (reviewer
actor fields; see #1).

**Total:** 12 log rows + 4 code-comment incidents + 1 live = **17 incidents**. Seven of them
(everything in the 01 rows) needed a new repair function. Excluded: orchestrator-side
timestamp-format bugs (three rows: claim-review pointer `accepted_at`, evidence assembly `now`,
input-assembly `generated_at`). They are the same bookkeeping class but Python-written, and
`tmp/schema-format-audit.md` section 5 (`formats.py`) covers them.

### 2.2 Invoker repair logs (`/tmp/claude-cli-invoker-*/repair-log.json`, 78 invocations, 97 rejected rounds)

19 of the 78 invocations show two rejected rounds, which means they failed after the repair budget.

| Cause | Rounds | Class |
|---|---|---|
| Envelope shape/keys (`project_discovery_summary_placeholder` 25, `candidates` not an object 8, key-set mismatch 13, md/json swapped 2) | 48 | envelope bookkeeping |
| Producer-binding hash echo (24 mismatch + 4 invented 63-hex values) | 28 | hashes |
| JSON syntax / empty reply | 11 | not bookkeeping |
| `build_plan.source_revision` null | 7 | provenance |
| Citation not resolvable to a pinned input | 3 | exact path (hybrid) |

In the four current runs, 27 accepted persona results carry "schema repair retry: 1 rejected
response" (build-plan 11, intake pool 6, evidence-assembly 5, D01 2, D02 1, build-classify 1, 07 claim pool 1): that
many paid second calls. **At least 83 of the 97 rejected rounds (86%) are bookkeeping**, not
judgment.

---

## 3. Per-contract tables

Owner key: **PY** = python-derived (remove from the persona schema and prompt). **MODEL** = model
judgment (keep). **HYB** = hybrid: the model gives a name or choice and Python resolves or checks it.
"Repaired?" says whether Python fixes the field today, and where. "Fails?" says whether a wrong
value fails the job today.

### 3.1 component-map: `01-component-characterization` (developer-engineer, sonnet-5), `component-purpose-map.schema.json`

Post-processing: `component_characterization.py` `_dispatch_persona` (stamps identity, lineage and
content_hash), `_normalize_component_ids`, `_drop_unresolved_relationships`,
`_repair_against_target`, `_record_untagged_gaps`, `validate_payload`. All of these run **after**
the invoker's schema gate.

| JSON path | Rule | Repaired? | Fails? | Owner | Change |
|---|---|---|---|---|---|
| `schema`, `characterization_basis` | const | no | yes (invoker gate) | PY | drop from persona schema; stamp in derive |
| `target`, `source_revision`, `source_snapshot_sha256` | = run inputs | overwritten post-gate | pattern at gate | PY | derive (move the `_dispatch_persona` lines into the pre-gate derive) |
| `evidence_manifest_lineage.*` (14 hashes, ids, 2 consts) | = accepted F02 manifest | overwritten post-gate | pattern at gate | PY | remove from the persona schema and from the prompt ("Copy the manifest-lineage object..."); this ends the false `gap-manifest-lineage-hashes` in 4/4 maps. Saves ~1.35 KB output per map |
| `**.evidence_citations[].content_hash` | = pinned sha | `_backfill_citations` post-gate | stale -> fail | PY | drop from the persona citation shape; derive. ~5.9 KB of 42.6 KB (14%) |
| `**.evidence_citations[].path` | pinned input under its root | no | yes | HYB | the model cites a path; derive drops unresolvable citations and records a gap (never fabricates); an object left with zero citations becomes a gap subject |
| `functional_components[].component_id` | slug(name) | yes (`_normalize_component_ids`) | on collision | PY | drop from the persona schema; derive from `name`; a collision gets a `-2` suffix and a gap |
| `code_scope_classification[].scope_id`, `parallel_review_groups[].group_id`, `rescope_triggers[].trigger_id`, `unknowns[].unknown_id`, `classification_gaps[].gap_id` | unique slug | no | yes (uniqueness) | PY/HYB | the model gives a short `name`; Python slugs it and dedupes |
| `component_relationships[].relationship_id` | `from--type--to` | yes (6450f3f8) | no | PY | drop from the persona schema |
| `component_relationships[].from/to_component_id` | resolves | dropped -> gap | no | HYB | the model names the endpoint (component name or id); resolve by slug |
| `functional_components[].parallel_review_group` | resolves to a group | no | **yes** | HYB | resolve by group name; a miss creates a gap and puts the component in an `unassigned` group |
| `parallel_review_groups[].component_ids` | resolves; mirrors the component-side field | sorted only | **yes** (unresolved) | PY | **derive** from each component's `parallel_review_group` (redundant data); the model keeps the group `rationale` and `downstream_lanes` |
| `tag_cloud[].tag` order, uniqueness | sorted, unique | ids sorted, tags **not** | **yes** (tag order) | PY | sort and merge duplicate tags in derive |
| `tag_cloud[].component_ids` | sorted, resolve | sorted | yes (unresolved) | HYB | resolve names; drop misses into a gap |
| `tag_cloud[].weight` | integer | - | - | MODEL | **keep (meaning flag):** observed weights are 10-80 and never equal `len(component_ids)`, so this is salience, not a count |
| `analysis_exclusions[]` (`scope_id`, `rescope_trigger_id`) | resolve | no | **yes** | HYB | derive one row per scope with `disposition=exclude`; the model gives the `reason` on the scope and names its trigger; a missing trigger becomes a gap |
| `rescope_triggers[].affected_scope_ids/affected_component_ids`, `unknowns[].affected_component_ids` | resolve | components only | yes (scopes) | HYB | resolve by name; miss -> gap |
| `functional_components[].representative_locations` | target file, `:line` suffix | foreign ones dropped | if none inside | HYB | keep; also normalise `./` and backslashes |
| `functional_components[].downstream_lanes`, `parallel_review_groups[].downstream_lanes` | *should* be job ids the consumers match | no | **no: silent routing loss** | HYB | enum of lane ids in the persona schema (from `job-graph.json`), plus an alias map (`sca` -> `02-sca-vulnerability-match`...); unknown -> gap. **Meaning flag:** the lane choice is judgment; only the vocabulary moves |
| negative-evidence `category` token | exact category token | prefix accepted | yes | HYB | normalise to the enum in derive |
| unassigned files | every file in one scope | -> `scope:<path>` gaps | no | PY | already derived; keep |

Token note: the persona schema drops about 25 of 115 leaves. Output falls by roughly the lineage
block, every `content_hash` and every id field (~25% of bytes in the sampled map).

### 3.2 repository-partition-map: D01 `02-repository-partition-discovery` (sonnet-5), `repository-partition-map.schema.json`

Post-processing: `discovery_gate._dispatch_partition_persona` (overwrites `source_revision` and
`content_hash`, both post-gate); `validate_job_output._partition_errors`.

| JSON path | Rule | Repaired? | Fails? | Owner | Change |
|---|---|---|---|---|---|
| `schema`, `target`, `source_revision` | const / run | `source_revision` post-gate | `type string` at gate | PY | persona schema drops them; derive stamps |
| citations `content_hash` | pinned | post-gate | stale -> fail | PY | as in 3.1 |
| `partitions[].partition_id` | unique slug | no | yes | PY/HYB | slug from `name`; dedupe |
| `partitions[].relationships[].target_partition_id` | resolves | no | **yes** | HYB | the model names the target partition; resolve; miss -> `coverage.budget_limitations`/gap line and the edge is dropped |
| `primary_persona_id`, `supporting_persona_ids` | registry ids, unique | no | yes | MODEL (enum) | already an enum; derive dedupes and removes the primary from the supporting list |
| `coverage.unassigned_paths` | files matched by no include pattern | no | format only | PY | **derive** from the pinned inventory and the patterns. It is silently wrong today |
| `coverage.inventory_scope`, `uninspected_scope`, `category_checks` | judgment | - | - | MODEL | keep |

### 3.3 project-discovery: D02 `02-dev-project-discovery`, D03 `02-devops-project-discovery` (sonnet-5), `project-discovery.schema.json`

Post-processing: `discovery_gate._dispatch_project_persona` (`source_revision`, `target`,
`content_hash`, all post-gate); `_project_discovery_errors`.

| JSON path | Rule | Repaired? | Fails? | Owner | Change |
|---|---|---|---|---|---|
| `schema`, `target`, `source_revision` | run facts | post-gate | at gate | PY | derive |
| citations `content_hash` | pinned | post-gate | stale | PY | derive. 20.3 KB of 97.5 KB output (21%) |
| `projects[].project_id` | unique slug | no | yes | PY/HYB | slug from `root` (+ language); dedupe |
| `safe_command_plan[].project_id` | resolves | no | **yes** | HYB | the model names the project root; resolve; miss -> `coverage_gaps` line and the command dropped |
| `projects[].manifests`, `lockfiles` | exact repository files | no | yes (format) | HYB | derive checks that they exist; a non-existent path moves to a gap |
| envelope | - | - | 25 rejected rounds | PY | fixed envelope keys (section 4) |

### 3.4 operations-topology: D04 `02-sre-operations-topology` (sonnet-5), `operations-topology.schema.json`

Same shape as 3.3: `schema`, `target`, `source_revision` and `content_hash` become PY.
`services[].service_id` becomes PY (slug of `name`). `dependencies[].target_service_id` becomes HYB
(resolve by name; miss -> `coverage_gaps`, edge dropped; today `_operations_topology_errors` fails).
`ports[]` sort/unique becomes PY. Everything else (kind, exposure, basis, notes) stays MODEL.

### 3.5 build-classification: `02-build-classify` (sonnet-5), `build-classification.schema.json`

Post-processing: `build_classify.finalize` (post-gate: `source_revision`, `target`, `index`,
`build_set`, `content_hash`); `check`. There is no `fill_result`.

| JSON path | Rule | Repaired? | Fails? | Owner | Change |
|---|---|---|---|---|---|
| `schema`, `target`, `source_revision`, `index{attempt_id,sha256}`, `build_set` | run facts / derived | finalize, post-gate | `source_revision` string at gate | PY | move `finalize` into a `fill_result`; remove from the persona schema (the schema already allows null for `index` and `build_set`, which weakens the *final* schema. With two schemas the final one can require non-null) |
| citations `content_hash` | pinned | finalize | stale | PY | derive. 10.7 KB of 42.3 KB (25%) |
| `units[]` coverage (every index unit once) | exact | no | **yes** | HYB | pre-seed the model's input with the index units; derive adds any omitted unit as `class: unclassified` with a `coverage_gaps` line |
| `units[].unit_id` for a part (`<index_unit_id>::<part>`), `index_unit_id` | derived format | no | yes | HYB | the model gives `index_unit_id` + `part` name; Python composes `unit_id` and slugs the part |
| `units[].signal_ids` | exist in the index | no | yes | HYB | drop unknown ids (count them in a gap); never fail |
| `coverage_gaps` naming unclassified units | roll-up | no | yes | PY | derive the line for each unclassified unit (like `_fill_known` for tier C) |
| `units[].class`, `languages`, `rationale`, `confidence`, `index_review` | judgment | - | - | MODEL | keep |

### 3.6 build-plan: `02-build-plan` per unit (haiku), `build-plan.schema.json`

Post-processing: `_fill_known` (pre-gate: `source_revision`, `target`, image-base tag, tier-C
gaps); `finalize` (post-gate: `index`, `classification`, `toolchain`, `dispositions`,
`content_hash`); `check`; `merge`.

| JSON path | Rule | Repaired? | Fails? | Owner | Change |
|---|---|---|---|---|---|
| `schema`, `target`, `source_revision`, `index`, `classification`, `toolchain`, `dispositions` | run facts / derived | yes (split pre/post) | no | PY | remove from the persona schema entirely; one derive |
| `plans` length = 1 | exactly one plan | no | yes | PY | persona schema: `plan` object, not an array; derive wraps it |
| `plans[].unit_id` | = plan-unit | no | yes (whole job before the retry) | HYB (**meaning flag**) | the model *echoes* `unit_id` as a check; derive compares; a mismatch triggers retry, then a gap. Do not blind-stamp: it would publish a plan written for another unit |
| `plans[].root`, `plans[].class` | = classification | no | yes | PY | stamp from plan-unit |
| `image.base` | catalog id | tag stripped | yes | HYB | keep the strip; unknown base -> nearest catalog base + gap |
| `image.apt_packages[]` unique, <= 60 | set | no | yes | PY | dedupe and truncate with a gap |
| `commands[]` order configure -> build | ordering | no | yes | PY | stable-sort by phase in derive |
| `commands[].cwd` | relative to the unit root | re-anchored downstream | - | HYB | keep |
| `coverage_gaps` for tier C | roll-up | yes (`_fill_known`) | no | PY | keep |
| `signal_ids` | exist in the index | no | yes | HYB | drop unknown + gap |
| content_hash | pinned | finalize | stale | PY | derive |

### 3.7 evidence-producer-binding: `02-evidence-producer-binding` pool cells in `02-evidence-assembly` (haiku), `evidence-producer-binding.schema.json`

| JSON path | Rule | Repaired? | Fails? | Owner | Change |
|---|---|---|---|---|---|
| `schema` | const | `_fill_binding` | no | PY | - |
| `producer_job_id` | = accepted pointer `job` | `_fill_pinned_values` | no | PY | - |
| `accepted_pointer_sha256`, `envelope_sha256`, `permission_sha256`, `lineage_sha256` | = pinned input hashes | `_fill_pinned_values` | no | PY | - |

Every field is Python-owned and already overwritten, so the model's reply has no effect on the
published binding. Recommendation: replace the cell with a deterministic binding function (the
same code path as `_fill_pinned_values`) and drop the ~26 haiku calls per run. The breakage history
here is 28 rejected rounds, 12/13 cell failures before the fill and a cache-key crash in all 26
cells. **Design flag:** if the persona cell exists to prove that an "evidence custodian" persona saw
the inputs, that property is already gone (its output is discarded). William should decide whether
to drop the call or give the cell a real judgment to make.

### 3.8 claim-review-pool-candidates (stage pools): `claim-review-pool-cell` for 07/08/09/12 (claim-reviewer, sonnet-5), `claim-review-pool-candidates.schema.json` + `claim-review-decision.schema.json` inside `assertion`

Post-processing: `claim_reviewer_pool._pool_claims`, then `deterministic_pool_merge`, then
`claim_review_lifecycle.decisions_from_pool`, then `claim_lifecycle_core.red_team/blue_team/verify/score`.
There is no `fill_result`. The runtime block (`_runtime_instructions`) tells the model the exact
identity values and relies on it copying them.

| JSON path | Rule | Repaired? | Fails? | Owner | Change |
|---|---|---|---|---|---|
| `candidates[].candidate_id` | `decision-<claim_id>` | no | uniqueness | PY | derive |
| `candidates[].subject_id` | = upstream `claim_id` | no | yes | PY | derive from `decision.claim_id` |
| `candidates[].claim_class` | = stage class | no | yes | PY | stamp `POOL_CLASSES[stage]` |
| `candidates[].evidence_sha256` | = upstream input sha | no | pattern | PY | stamp `package.inputs[0].sha256` |
| `candidates[].assertion` | JSON-encoded string of the decision | no | parse | PY | the model returns the decision as an **object**; derive serialises it canonically (no escaping by the model) |
| one candidate per upstream claim | coverage | no | **yes** (Blocked) | HYB | derive: a missing claim gets `UNRESOLVED`/`BLOCKED` with the rationale "no reviewer decision"; an extra claim is dropped and gapped |
| `decision.reviewer` / `decision.verifier` (10 fields: `job_id`, `attempt_id`, `role_id`, `artifact_path`, `artifact_sha256`, `permission_receipt_path`, `permission_receipt_sha256`, `reason`, `source_generation`, `component_generation`) | = runtime identity + the claim's generations | no | **yes, live failure 60/60 today** | PY | remove from the persona schema; build from `_runtime_instructions` identity and the upstream claim. 22.8 K of 70.2 K output chars (32%) in the failed pool |
| `decision.claim_id` | = subject | no | yes | HYB | the model keys each decision by `claim_id`; derive checks it against the upstream set |
| `decision.citations[]` (7-field `claim-lifecycle-citation` objects) | subset of the upstream citations **by id** | no | yes (schema). Also **unverified contents published** | HYB | the model gives `citation_ids`; derive copies the upstream objects; an unknown id becomes a dissent/limitation, not a fabricated object. **Meaning flag:** a VERIFIED decision needs *new* independent evidence, which an id list cannot carry. The prompt currently forbids VERIFIED; if that is ever allowed, add a `new_citations` path that resolves through `input_id` |
| `decision.proof_obligations[]` (`obligation_id`, `statement`, `status`, `citations`) | ids and statements = upstream set | no | yes (incomplete) | HYB | the model gives `{obligation_id: {status, citation_ids}}`; derive copies the `statement`; a missing obligation -> `UNRESOLVED` |
| `dissent_ids` | unique | merged | dup -> fail | PY | dedupe in derive |
| `attacker_case`, `disposition`, `rationale`, `method`, `factors`, obligation `status` | judgment | - | - | MODEL | keep (28% of output today) |

### 3.9 claim-review-pool-candidates (intake review pool): `intake-review-pool-cell` + `-independent-cell` (sonnet-5)

`GraphReviewInvoker.fill` replaces the model's whole result with `_expected_candidates(intake)`.
Every field (`candidate_id`, `subject_id`, `assertion`, `evidence_sha256`, `claim_class`) is PY and
already derived. As with 3.7, the model call contributes nothing: a "quorum" of two identical
Python-built documents. **Design flag:** either give the reviewers a judgment to make (for example
per-candidate `rationale`/`limitations` that the merge keeps) or make the pool deterministic.

### 3.10 owasp-control-assessment-candidate: `04-owasp-validator-cell` via `owasp_dispatch` (owasp-validator), `owasp-control-assessment-result.schema.json`; checked by T07 `owasp_validator_result._validate_candidate`

No live cell has run: both dispatches so far were `EMPTY`. There is no `fill_result`. T07 requires
the accepted result to equal the candidate byte-for-byte (`owasp_dispatch.validation_outcome`), so
**all derivation must happen before the candidate file is written**, which means in the invoker
derive step.

| JSON path | Rule (T07) | Repaired? | Fails? | Owner | Change |
|---|---|---|---|---|---|
| `schema` | const | no | yes | PY | stamp |
| `result_id` | `assessment-` + digest(doc minus `result_id`)[:20] | no | **always** (not computable by a model) | PY | derive last |
| `run_id`, `selection_id` | = request / handoff | no | yes | PY | stamp |
| `handoff_identity.*` (9 fields, 3 sha256) | = T06 pointer/member | no | yes | PY | stamp from `_validation_request` facts |
| `applicability_identity`, `worklist_identity`, `batch_identity`, `hashes` | = handoff | no | yes | PY | copy from the handoff |
| `intercom` (path + 4 consts) | = handoff | no | yes | PY | stamp |
| `producer.producer_id` | = pool `instance_id` | no | **always** (the model is never told it) | PY | stamp |
| `producer.produced_at`, `terminal.started_at/ended_at`, `budget.elapsed_seconds/output_lines/timed_out` | runtime actuals, tz-aware | no | yes | PY | stamp from the invocation record (`formats.py` canonical Z) |
| `terminal.state`, `terminal.failure` | allowed by T06; consistent with the timeout | no | yes | PY | derive from `execution_status`; the model can still report inability through obligation outcomes |
| `budget.name/max_output_lines/timeout_seconds`, `tool_profile_id`, `validator.primary_role` | = handoff | no | yes | PY | stamp |
| `boundary_acknowledgements.*` (9 consts), `dynamic_test_candidates[].state/authorization/execution/target_contacted/target_mutated`, `candidate_verification_routes[].promotion_state/finding_created/severity_assigned/execution_authorized`, obligation `mandatory` | consts | no | yes | PY | stamp; remove from the persona schema |
| `fragment_results[]` order and identity (`fragment_id`, `assignment_id`, `target_id`, `control_id`, `component_id`, `final_control_status_authority`) | = handoff order | no | yes | PY | derive the skeleton from `assigned_fragments`; the model answers per `fragment_id` |
| `proof_obligation_results[]` order and `obligation_id` | = handoff | no | yes | PY | skeleton; the model answers per `obligation_id` |
| `fragment_results[].assessment_status`, `final_control_status` | `_expected_fragment_status(outcomes)`; null if fragment-only | no | yes | PY | derive: this is a deterministic roll-up T07 already enforces, so moving it changes no meaning |
| citation `citation_id` (globally unique) | unique | no | yes | PY | derive `c-<fragment>-<obligation>-<n>` |
| citation `artifact_path`, `artifact_sha256`, `accepted_pointer.*`, `freshness.*`, `source_kind` | = the accepted handoff input named by `input_id` | no | yes | HYB | the model gives `input_id` + `locator` + `observed_fact` + `covered_scope` + `evidence_mode` + limitations; derive dereferences; an unknown `input_id` drops the citation into `evidence_gaps` |
| `derived_outputs[].artifact.sha256`, `source_lineage[].artifact_sha256`, `tool_usage[].derived_output_ids` | lineage | no | yes | PY | the cell has `tool_call_limit: 0`, so derive emits empty `tool_usage`/`derived_outputs` |
| `dynamic_test_candidates[].candidate_id`, `candidate_verification_routes[].route_id`, `contradictions[].contradiction_id`, `dissent[].dissent_id` | unique | no | yes | PY/HYB | the model uses local labels; derive assigns ids and rewrites `dynamic_candidate_ids` / `verification_route_ids` / `citation_ids` references; a miss -> `unresolved_conditions` |
| obligation `outcome`, `rationale`, contradictions content, dynamic test content, route hypothesis, dissent, gaps, `reported_claims` | judgment | - | - | MODEL | keep |

Token note: the schema rendered to the model has 160 leaves. About 95 are PY under this table, so
both the persona prompt and the output shrink by roughly half or more.

### 3.11 Shared: response envelope and `evidence-citation`

- **Envelope keys** are slugs of filenames (`_envelope_fields`). Colliding stems get `_markdown`.
  A result whose top-level key equals the envelope key (`candidates`) confuses the model: 48
  rejected rounds. Owner PY: fixed keys `result` + `summary_markdown`, with salvage kept.
- **`evidence-citation.content_hash`** is overwritten in five contracts, at three different points,
  by two copies of the same function (`component_characterization._backfill_citations`,
  `discovery_gate._backfill_citation_content_hashes`). Owner PY: one derive primitive, and the
  persona citation shape is `{source_type, path, line_range, note}`.

### Not model contracts (checked, no action)

`03-threat-model-dfd-stride`, `03-threat-model-reconciliation`, `07/08/09/11/12` results,
`10-synthesis-report`, `claim-ledger-routing`, the OWASP applicability/worklists and the STIG
worklist all run as `deterministic-python`: their bookkeeping is already Python-owned. The only
model-written inputs they receive are the ones in 3.1 and 3.8.

---

## 4. Proposed shared mechanism: one derive step per contract

1. **Two schemas per contract.** In the final schema, annotate orchestrator-owned properties with
   `"x-owner": "orchestrator"`, and hybrid ones with `"x-owner": "resolve"` plus the persona-side
   name field. `schema_validate` generates `persona:<schema>` by removing `orchestrator`
   properties (and relaxing `required`) and by replacing `resolve` id fields with their name field.
   The invoker renders and validates the **persona** schema. The final schema stays strict and can
   drop today's "null in the model's response" weakening (`index`, `build_set`, `toolchain`,
   `dispositions`).
2. **A registry of normalizers**, `derive.py`: `DERIVERS[contract_id] = fn(value, ctx) -> value`,
   with `ctx` holding pinned readable inputs (path -> sha), request/run facts, the invocation record
   (instance id, times, budget actuals), upstream documents and a canonical clock (`formats.py`,
   per `tmp/schema-format-audit.md` 5b). `ClaudeCliInvoker` calls it where `fill_result` sits today
   (before `_validate_envelope` against the final schema). Existing `fill_result` hooks,
   `_fill_pinned_values` and the job-side post-gate repairs move into it, so there is one place per
   contract.
3. **Primitives** (each small, pure and unit-tested):
   - `stamp(paths <- ctx)`
   - `slug_ids(section, name, id)` with collision suffix and gap
   - `resolve_refs(section, field, index, by="name|slug|id", on_miss=gap|drop|default)`
   - `sort_unique(path, key)`
   - `rollup(field, fn)` (build_set, dispositions, tier-C gaps, fragment status)
   - `hash_citations(pinned)` and `drop_unpinned_citations`
   - `echo_check(field, expected)` (build-plan `unit_id`: compare, never trust)
   - `digest_id(prefix, exclude)` (OWASP `result_id`, applied last)
   - `serialize(field)` (claim-review `assertion`)
4. **Gaps, not failures.** Every `on_miss=gap` writes to the contract's own gap array
   (`classification_gaps`, `coverage_gaps`, `evidence_gaps`/`unresolved_conditions`, claim
   `UNRESOLVED`) through one `gap(contract, subject, reason)` helper, with the deterministic id
   `gap-<kind>-<slug(subject)>`.
5. **Visibility.** Derive returns a `derivations` summary (ids re-derived, refs resolved/dropped,
   citations dropped). Record it in `status.json` and the size log, so a model that keeps missing
   references shows up without failing the run.
6. **Persona cache.** Include the persona-schema hash in `persona_cache_key`, so the change
   re-dispatches once and then caches.
7. **Envelope.** Use fixed keys `result`/`summary_markdown` for single-artifact contracts; keep
   salvage.

---

## 5. Rollout order (rule: merge job code only when no run is past that job)

Where the four current runs stand (accepted pointers checked):

| Run | 01 / 02-build-* / 02-evidence-assembly | 04-owasp-validator-dispatch | 07 pool |
|---|---|---|---|
| hello `20260927T192621Z-helloautotoo` | accepted | - | - |
| multi-vuln `20260928T034921Z-be3585` | accepted | accepted EMPTY | **FAILED (reviewer actor)** |
| freeciv21 `20260928T005228Z-5b0fac` | accepted | - | - |
| doom3 `20260928T013300Z-0c0b82` | accepted | accepted EMPTY | - |

Order:

1. **Shared runtime first:** derive registry, persona-schema generation, envelope keys and the
   `formats.py` clock. These live in `claude_cli_invoker.py`, `schema_validate.py` and the new
   `derive.py`; `execution_state.SHARED_RUNTIME` is excluded from job fingerprints, so this does
   not re-run accepted jobs. Ship it inert, with no contract opted in.
2. **Claim review pool (3.8), now.** No run is past 07 (multi-vuln is failing *at* it), so this is
   allowed immediately and unblocks multi-vuln. Opt in `claim-review-pool-candidates` (stage
   variant) and edit `claim-review-pool-task.md` and `_runtime_instructions` (stop asking for the
   actor, the ids and the JSON string).
3. **OWASP validator (3.10)**, before any run produces a non-empty handoff set. The change sits in
   the invoker deriver plus the persona schema; T07 (`owasp_validator_result`) is unchanged. If
   `owasp_dispatch` code must change, multi-vuln and doom3 are past it, but their accounting is
   `EMPTY`, so a relaunch re-derives it in seconds. Acceptable, or wait until they pass 07.
4. **Upstream contracts (3.1-3.7, 3.9)**, in one merge window after the current four runs publish
   reports (or when starting fresh runs). All four runs are past 01/02, and each of these changes
   re-runs the whole downstream graph, so batch them:
   component map (lineage, `downstream_lanes`, id/ref derive) -> evidence binding (drop the model)
   -> build-classify `fill_result` + pre-seeded units -> build-plan persona schema + echo check ->
   D01-D04 provenance/refs/`unassigned_paths` -> intake pool decision.
5. **Tighten the final schemas last** (remove the nullable orchestrator fields) once every writer
   derives them. That is a schema change, so it goes in the same fresh-run window.

Suggested breakage-log rows to add: be3585 07 pool failure (reviewer actor, 60/60), and
`downstream_lanes` vocabulary mismatch (silent; native units from the component map are never
produced).
