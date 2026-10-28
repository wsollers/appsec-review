# Review protocol v2: the model-facing layer

Status: implemented (see section 13 for the decisions taken where this document left a choice open). Observed behavior comes from the first live
runs of `job_inference_security_review` on `cpp-multivuln-v1` (Dagster application runs
`2026-10-21-0005` and `2026-10-21-0007`).

This document changes **only what a review cell is shown, what it may ask, and what it must answer**.
It does not change the claim ledger, the closed predicate vocabulary (R4), the adjudication table
(R5), independence (R6), evidence admissibility, scoring, the publication gate or the report. Those
stay as specified in [inference security review](inference-security-review.md) and
[red discovery output](red-discovery-output.md). The compact answers below are **expanded by the
application** into the existing `red-discovery-result/1`, `blue-result` and `verifier-result`
documents before any validator runs, so downstream behavior is unchanged.

## 1. Why: what the first live runs showed

| Observation | Count | Cause |
|---|---|---|
| Model turns discarded as "no schema-bearing JSON" (run 6) | 210 of 439 | The model often omitted the constant top-level `schema` field. Fixed by tolerant parsing; now 7%. |
| Retrieval requests rejected as `malformed_request` (run 6) | 65 of 65 | The prompt named the tools but gave no parameter names or request shape. The models invented about 60 shapes. Fixed by shipping the tool catalog. |
| Lookups refused because they carried `path` (run 8) | about 1,000 | The model has a file and line from the lead; the tools want typed ids. `path` is never grantable. |
| `query_code_graph` refused for a mode/subject-kind mismatch (run 8) | about 520 | Each `mode` accepts only certain subject kinds (`guards` only a sink site, `callers` only a symbol), and `depth` applies to only two modes. |
| Lead-lane red cells ending `invalid` (run 8) | 195 of 195 | Each refused lookup was recorded as an `authority_error` gap (725 in the lead lane) and the cell ended `invalid` after its retries. |
| Context embedded in a lead package | none | Graph context is embedded only for a `dataflow_path` correlated with the lead's observation. A Semgrep lead with no correlated path carried no sink, range or guard facts, though they exist in the graph at that location. |
| Package size | 119 KB median | 93% of it is 362 inline `coverage_gaps` entries, most irrelevant to the lead. |

The models mostly asked for the right things. The interface made the right question hard to ask and
a wrong one fatal.

## 2. Principles

1. **The package carries what a reviewer needs; retrieval is for the rest.** Precomputed
   neighborhood facts are embedded, labelled, and bounded. A reviewer should often finish in one
   turn.
2. **One way to name evidence: a label.** Every row a cell sees has a short label unique within the
   cell. Cells cite labels. The application resolves labels to logical identities and checks them.
3. **A model answer is a stance plus citations, never a state.** The application records relations;
   R5 sets states. Prose is commentary.
4. **A refused lookup is feedback, not a failure.** A gap is recorded when a cell ends without a
   usable result, not for each denied request.
5. **No output is not an opinion.** A missing or invalid answer is a gap. It is never read as
   agreement or as refutation.
6. **The compact form is a layer.** Everything the model does not need to say (schema, package id,
   role, round, claim ids) is filled in by the application.

## 3. Definitions

| Term | Meaning |
|---|---|
| **Lead** | A scanner observation (or a hunt unit) admitted for review. A lead is not a finding. |
| **Claim** | A bounded security hypothesis tied to affected entities and a closed `security_predicate`. Proposed by red. |
| **Judge** | A fifth role, `adjudication_judge`, that sees the package and the red and blue positions as sides A and B in a shuffled order and records which side is correct. It answers with the shared compact shape (stance, citations by label) plus a verdict, sets no state, and does not replace the blind verifier. See [the judge and PoC design](review-judge-and-poc.md). |
| **Affirmation** | A stance of `supports` on a claim, with citations that the application can resolve. |
| **Counter-claim** | A blue statement that contradicts or qualifies a claim, with its own citations. |
| **Refutation** | An accepted contradiction: the application records a `contradicts` relation that survives evidence resolution, and R5 moves the claim to `contradicted`, `not_reachable` or `not_exploitable_in_observed_configuration`. |
| **Confirmation** | The state `confirmed` (R5 row 5): every required predicate has direct support and R6 independence holds. A verifier's `confirmed` is a proposal only. |
| **Label** | A short, cell-local handle for a package item or a retrieved row (`L1`, `S2`, `G2`, `T7`). |
| **Ref** | The logical identity behind a label (`asr:guard_fact:…`). Cells never need to type one. |

## 4. Package v2

### 4.1 Shape

The package keeps its hash-pinned identity and reuse basis. Its model-facing view is organized into
labelled sections. Ids are shortened here.

```json
{
  "schema": "appsec-review/review-package/2",
  "package_id": "finding_lead-0a9a904e…",
  "lead": {
    "label": "L1", "ref": "asr:tool_observation:41f4124d…",
    "scanner": "tool-semgrep", "rule": "cpp-banned-function-review", "severity": "info",
    "where": {"path": "src/packet.cpp", "line": 16, "function": "relay::parse_header"}
  },
  "source": [
    {"label": "S1", "path": "src/packet.cpp", "lines": "7-18", "sha256": "f3baebd1…",
     "text": ["7| int parse_header(const uint8_t *data, size_t size, Header &out) {",
              "8|   if (size < 4) { return -1; }",
              "12|  out.length = (uint16_t)(data[2] | data[3] << 8);",
              "13|  if (size < 4u + out.length) { return -1; }",
              "16|  std::memcpy(out.name, data + 4, out.length);"]},
    {"label": "S2", "path": "include/relay/relay.hpp", "lines": "9-13",
     "text": ["9| struct Header {", "10|  uint16_t kind;", "11|  uint16_t length;", "12|  char name[16];"]}
  ],
  "neighborhood": {
    "rule": "package-neighborhood/1", "call_depth": 3,
    "sinks":   [{"label": "K1", "ref": "asr:sink_site:effd6c6d…", "summary": "memcpy [memory_write], L16"}],
    "ranges":  [{"label": "R1", "ref": "asr:range_fact:9cedee4f…", "summary": "length operand is uint16_t, 0..65535"}],
    "guards":  [{"label": "G1", "ref": "asr:guard_fact:89ec1679…", "summary": "dominating: size < 4 (L8)"},
                {"label": "G2", "ref": "asr:guard_fact:ba307124…", "summary": "dominating: size < 4u + out.length (L13)"}],
    "callers": [{"label": "F1", "ref": "asr:call_site:318f79cd…", "summary": "relay -> relay::parse_header (L7)"}],
    "callees": [{"label": "F2", "ref": "asr:call_site:f80d1fa2…", "summary": "relay::parse_header -> memcpy (L16)"}],
    "flows": [], "flows_gap": "no CodeQL dataflow path reaches this sink"
  },
  "build": {"label": "B1", "compiler": "clang++ 18.1.3",
            "flags": ["-O2", "-g", "-DNDEBUG", "-std=c++17", "-Wall", "-Wextra"],
            "hardening": {"fortify_source": 3}, "ref": "asr:build_action:a0a3c663…"},
  "corroboration": [{"label": "C1", "ref": "asr:precomputed_fact:563e975c…", "relation": "nominates"}],
  "tags": [{"label": "T1", "ref": "asr:tag_assignment:e0290c0d…", "tag": "…"}],
  "material_gaps": [{"label": "X1", "text": "no graph fact gives the destination capacity of out.name; see S2"}],
  "files": {"gaps.jsonl": {"count": 361, "sha256": "…"},
            "corroborating_findings.jsonl": {"count": 3, "sha256": "…"}},
  "proof_obligations": ["affected_construct", "attacker_input_control", "source_to_sink_reachability",
                        "missing_or_ineffective_guard", "security_impact"]
}
```

### 4.2 Labels

Labels are assigned by the application, in a fixed order, so the same package yields the same labels.
The letter says the kind: `L` lead, `S` source excerpt, `K` sink, `R` range fact, `G` guard, `F`
call site, `P` dataflow path, `E` entry point, `C` corroborating finding, `B` build, `T` tag, `X`
material gap. A row returned by a tool during the cell is labelled `Q1`, `Q2` … in arrival order.
Labels exist only in the model-facing view. They are not stored as identities; the ledger stores the
resolved refs.

### 4.3 What is embedded (`package-neighborhood/1`)

Embedding is keyed by **location and function scope**, not only by a correlated dataflow path:

- the lead's function span, and the declarations of the types used at its sink sites;
- every `sink_site`, `range_fact` and `guard_fact` located in that function;
- callers and callees of that function to the configured call depth;
- every `dataflow_path`, `flow_summary` and `entry_point` that touches those sinks (the existing
  correlated-path embedding stays, and extends to a path found by sink rather than by observation);
- the build action's compiler, flags and hardening summary (from the build command facts);
- the tag assignments and corroborating observations at the same location;
- **what is needed to reason about reaching the sink from an input**: the `entry_point` facts of the function and of
  the flows that touch its sinks, and a precomputed upward **call chain** from the lead's function to the nearest
  function holding an entry point (existing `call_site` edges, at most `max_call_depth` levels), whose hops are
  labelled `F1..` in order. When no entry point is reachable within the bound the package carries a material gap, and
  a cell sees it as an `X` label: reachability is unknown, never excluded;
- **the declarations of the types used at the sink**, as a stated rule: the field names, types and array sizes of
  every user type that the lead function's signature and body name, read from the accepted index (or the lead's file)
  and hash-verified. A type the application cannot locate is a material gap.

Red and blue receive the same package and the same tools. A guard row repeats what a `guard_fact` states (state,
polarity, condition text, operator and operand texts) and never summarises whether it bounds a destination.

Bounds come from the existing graph settings (`max_call_depth`, `max_neighbors_per_function`,
`max_paths_per_sink`, `max_guards_per_sink`) and a per-package byte budget. Anything omitted is
counted with an `omitted` field and a `truncated` gap, and remains reachable with `expand`.

### 4.4 What moves out of the package

The package lists inline only the gaps that bear on the lead: gaps whose scope is the lead's
function, build unit, file or sink, plus any that remove a proof obligation. The remaining gaps are
written once to a hash-referenced `gaps.jsonl` and counted in `files`. A cell can ask for them with
`expand`. Corroborating findings at the same location are extracted the same way, with the strongest
few inline.

## 5. Retrieval

### 5.1 In-process, not MCP

Review cells have **no MCP and no tools of their own**. The model emits `retrieve` requests; the
application authorizes each against the cell capability and runs it in-process on `RetrievalCore`;
the next turn carries the bounded rows. The tool names and parameter schemas are the ones published
in `docs/schemas/retrieval-mcp-tools.json`, and the authority checks are the ones the MCP adapter
enforces, but the transport is the application loop. The MCP stdio adapter (`appsec_review.mcp`) is a
separate, read-only surface for external clients and the OWASP workbench. Registered runtime skills under
`pipeline/skills/` now also supply bounded, role-selected review procedures; they do not grant tools
or widen retrieval capabilities. See [role-selected procedures](guidance-procedures.md).

### 5.2 The tool catalog in the prompt

Every cell receives `turn_protocol.tool_catalog`: each granted tool, its description, and its exact
parameter schema, plus `retrieve_shape`, a worked request. The application also accepts the
spellings models commonly use (`arguments` or `args` for `parameters`, parameters beside `tool`, and
free-text note keys such as `purpose`). The normalized request still passes every authority check.

### 5.3 `expand`

A single tool answers "tell me more about this": `{"tool": "expand", "parameters": {"label": "G2"}}`
(or a `ref`, or a `files` entry with an offset). It returns the labelled rows that bear on that item
within the cell's grant: for a sink, its range facts and guards; for a guard, the condition and the
guarded sink; for a function, its callers and callees to the configured depth; for a flow, its ordered
steps. It replaces the model's need to choose among `query_code_graph` modes and subject kinds. The
typed tools remain and `expand` uses them internally.

### 5.4 Locator by path and line

`find`, `query_observations` and `query_codeql` accept `{"path": "src/log.cpp", "line": 16}` as a
**locator**. The application resolves it, against the package scope, to identities and runs the
query on those. A locator outside the package scope is `entity_out_of_scope`. `path` still never
reaches a filesystem, a query language or a regular expression.

### 5.5 Denial policy

A denied request returns its code, a one-line reason **and the corrected shape** to the model in the
next turn, and costs one query from the budget. It is not recorded as a gap. A gap is recorded when a
cell ends without a usable result: unparseable after repair, budget exhausted without a final answer,
timeout, or an invalid final result. Repeated identical denials within a cell end it as
`invalid` with one `authority_error` gap that names the request and the code.

## 6. Model output v2

### 6.1 Envelope

Every turn is exactly one object with an `action`. `schema` is optional and ignored if present.

- `{"action": "retrieve", "requests": [{"tool": …, "parameters": {…}}]}`
- `{"action": "final", "result": {…}}` where `result` is the role's compact answer below.

The application fills `schema`, `package`, `role`, `round_id`, `claim_id` and the lead accounting
defaults, then validates the expanded document with the existing validators.

### 6.2 Red

```json
{"action": "final", "result": {
  "claims": [{
    "id": "c1", "leads": ["L1"], "cwe": "CWE-787",
    "security_predicate": "memory_corruption",
    "statement": "memcpy in parse_header copies out.length bytes, up to 65535, into the 16-byte out.name.",
    "support": {
      "affected_construct": ["K1", "S1"],
      "attacker_input_control": ["S1"],
      "missing_or_ineffective_guard": ["R1", "S2"]
    },
    "counter": {"missing_or_ineffective_guard": ["G2"]},
    "missing": ["X1"]
  }],
  "no_claim": [], "blocked": []
}}
```

- `support` maps a predicate to the labels that support it; `counter` maps a predicate to labels that
  weigh against it. Red counterevidence is recorded as `qualifies`, as today.
- Every lead in the package appears in some claim's `leads`, in `no_claim`, or in `blocked` with a
  reason. An omitted lead is a gap.
- A hunt-lane answer uses the same shape; its `leads` name the leads of the unit menu.
- `security_predicate` is the closed security consequence of the claim (`security-predicates/1`); the obligation
  predicates appear only as keys of `support`, `counter` and the blue and verifier answers. (The first draft of
  this section named the field `predicate`; see section 13.)
- A claim may carry an optional `poc_basis`, section 6.6.

### 6.3 Blue

```json
{"action": "final", "result": {
  "claim": "c1",
  "stance": "qualifies",
  "predicate": "missing_or_ineffective_guard",
  "cites": ["G2", "S1"],
  "why": "The guard rejects short source input but does not bound writes to the 16-byte destination."
}}
```

`stance` is one of `contradicts`, `qualifies`, `unresolved`. Blue cannot author support, including in
per-predicate answers; unsupported authority fails compact validation. The application turns each
citation into a relation to the named predicate. Whether a `contradicts` stands is decided by the
evidence rules (section 7), not by the stance word.

### 6.4 Verifier

```json
{"action": "final", "result": {
  "claim": "c1",
  "disposition": "supported",
  "per_predicate": {
    "affected_construct": {"stance": "supports", "cites": ["K1"]},
    "attacker_input_control": {"stance": "supports", "cites": ["S1"]},
    "missing_or_ineffective_guard": {"stance": "unresolved", "cites": ["G2", "S2"],
                                     "missing": ["the guard does not mention out.name capacity"]}
  }
}}
```

`disposition` is a proposal from the existing closed set. The verifier works blind, from the package
and its own retrieval, as R6 requires; its output never references red or blue.

### 6.5 Label resolution (shared, role-neutral)

Parsing, label resolution, the `unresolved` rule and the stance-to-relation step are one role-neutral layer
(`review/compact.py`: `resolve_position`, `relations_of`, `citations_of`); the red, blue and verifier answers only
arrange its positions into their result document. Which role may see which other role's output is decided where each
request is built, never in that layer.

- A label resolves through the package and the cell's own retrieval receipts. A label from another
  cell, or one that does not exist, is dropped with feedback, and the claim loses that support.
- A stance without a resolvable citation is recorded as `unresolved`.
- A raw ref is accepted wherever a label is, if the cell received it.

### 6.6 The proof-of-concept brief (`poc_basis`)

Red's job is to develop the information from which a proof of concept can be generated; a separate later job builds the
proof of concept. A red claim may therefore carry one optional, bounded object. It is **not code and not a proof of
concept**; it is the brief that job will read.

```json
"poc_basis": {
  "entry": ["E1"], "path": ["F1", "F2"],
  "trigger": [{"field": "header.length", "where": "bytes 2..3", "constraint": "greater than 16",
               "why": "G2 compares the size with the length field, not with the 16-byte capacity"}],
  "input_format": "4-byte header, then name bytes",
  "preconditions": ["attacker_controls_file_content"],
  "expected_observation": "a stack-buffer-overflow write in memcpy under a sanitizer",
  "unknowns": ["X1"]
}
```

- Every free-text field is at most 240 characters; `entry` has at most 8 labels, `path` 16, `trigger` 8 rows,
  `preconditions` 8 and `unknowns` 8.
- `entry` labels must resolve to `entry_point` identities and `path` labels to `call_site` identities, in order;
  `unknowns` are `X` labels, kept as the gap text. A label that does not resolve is dropped with feedback.
- A `poc_basis` without a resolvable entry point adds a named gap to the expanded result: how input reaches the lead is
  unknown.
- Expansion fills the closed fields that exist: `attacker_entry.entity_id` from the first entry point, and every
  `preconditions` text that is a member of the closed `preconditions/1` vocabulary is added to the claim's
  preconditions. The bounded object itself is stored as `proposal.poc_basis` and copied by the application to a
  run-owned `poc-basis.json` beside the claim ledger. No relation, claim state, score or adjudication reads it.
- Blue and the verifier have no `poc_basis`: their schemas are closed, so an answer that carries one is rejected.

### 6.7 Judge

A fifth role, `adjudication_judge`, answers with the same shared compact layer (`review/compact.py`:
`resolve_position`, `citations_of`) but a different result: `verdict` (`A`, `B`, `both`, `neither`, `unresolved`), a
`per_predicate` map of verdicts with `cites`, and a `reason`
(`appsec-review/judge-result-compact/1`). Its request is built from the labelled package view and two sides shown as A
and B in a deterministic shuffled order, with the rows either side cited re-presented under judge-scoped `J` labels.
The application de-shuffles the verdict and records a `judge_verdict` ledger event; the judge sets no state and R5/R6
do not read it. The whole design is in [the judge and PoC design](review-judge-and-poc.md), sections 3 and 4, and its
implementation decisions in section 7 there.

## 7. From stance to state

The model never sets a state. For each cited label the application records an evidence relation to a
predicate (`supports`, `contradicts`, `qualifies`), re-resolves it under `evidence-admissibility/3`,
and R5 evaluates the claim.

| What a cell says | What the application records | Effect |
|---|---|---|
| Red `support[p]: [labels]` | `supports` relation per label, per predicate | Counts as direct support only if the `(kind, predicate)` cell is direct and the label resolves completely. An `analyst_assessed` cell is recorded and shown but never counts. |
| Red `counter[p]: [labels]` | `qualifies` | Never contradicts. Contradiction belongs to blue and the verifier. |
| Blue `contradicts p` with cites | `contradicts` relation per label; for a `guard_fact` or `range_fact` on `missing_or_ineffective_guard`, `qualifies` with a reason unless the facts show the destination is bounded (below) | A direct contradiction defeats the predicate (R5 rows 3 and 4). |
| Blue `qualifies` | `qualifies` | Retains a material limitation; cannot confirm. |
| Verifier `disposition` | recorded as `proposed_disposition` | A proposal; R5 decides. |
| Any `unresolved` or empty cite list | no relation | The predicate stays open (R5 row 6 or 7). |

What a cell's citation can and cannot do (`predicate-admission/2`, R3 in
[`inference-security-review.md`](inference-security-review.md)). A real label is authentic, but
authenticity is not relevance and relevance is not support. The application classifies the
`(entity kind, predicate)` pair and the model's wording never changes it:

- A source span, AST node, IR entity or symbol is `direct` only for `affected_construct`. Cited for
  `attacker_input_control`, `source_to_sink_reachability`, `missing_or_ineffective_guard` or
  `configuration_enables` it is `analyst_assessed`: shown to a reviewer, never counted.
- A package or archive member establishes that a component is present at a version. For attacker
  control, reachability, guard and impact it is `indirect`.
- A build action or compile unit is `direct` for `configuration_enables`; built binaries are
  `analyst_assessed` at best.
- No kind is `direct` for `security_impact`; impact is derived from the adjudicated claim, so it is
  not a required predicate (R4).
- A tool observation counts only for the predicates its producer and rule name, and a CodeQL result
  that is not a path never counts for `source_to_sink_reachability`.

So a cell that cites only source text yields `supported` at best, never `confirmed`: the application
needs a direct fact (a graph path, a mapped path observation) for each remaining required predicate.

Worked outcome for the `packet.cpp:16` claim: `affected_construct` has direct support from the sink
fact. `attacker_input_control` cites source text, which is analyst-assessed and does not count. `missing_or_ineffective_guard` is contested: the
dominating guard G2 compares the input size with the length field, not with the capacity of
`out.name`. Had a dominating guard always contradicted this predicate, that would have wrongly
refuted a real overflow.

**Decision (resolves former open question 1).** The graph export now records the compared operands
and the destination object size (option (a)), and the application decides, not a model: a dominating
guard or a bounded range **qualifies** `missing_or_ineffective_guard` unless
`graph/bounds.py` shows from the exported facts that it bounds the destination. It does when the
guard is dominating, `constrains_sink_operand` is `true`, `destination.object_bytes` is known, and the
comparison, normalized to `n REL K` for the sink's size operand `n` (flipped for operand order,
negated on `false_branch`), is an upper bound by a compile-time integer `K` within the destination
(`K <= object_bytes`, or `K <= object_bytes + 1` for `<`). A range fact bounds when its upper bound is
known and within the destination size taken from the sink's guard facts. Only then, and only for blue,
verifier or judge, is the citation recorded as `contradicts`; red's counterevidence is always
`qualifies`, and every other citation is `qualifies` with the reason
`guard_not_shown_to_bound_destination:<why>` (`evidence-admissibility/3`, R3). Worked outcome for
`packet.cpp`: G2 (line 13, `size < 4u + out.length`, sink operand `unknown`, other operand not a
constant, 16-byte destination) and G1 (line 8, `size < 4`, sink operand `false`) are not shown to
bound `out.name`, so a blue contradiction citing either is recorded as `qualifies` and the claim is not
refuted. A guard such as `if (n > 16) return;` before the same `memcpy` would bound it and contradict.

## 8. Failures and gaps

| Situation | Result |
|---|---|
| Unparseable turn | Repair once with the parse error; then `schema_error` gap and the cell ends `invalid`. |
| Denied request | Feedback to the model; no gap (section 5.5). |
| Label that does not resolve | Dropped with feedback; the claim loses that support. |
| Final answer fails the expanded validators | One repair turn; then `schema_error` gap. |
| Budget or timeout | `budget_gap` or `worker_gap`; the cell ends `timed_out` or `invalid`. |
| No answer for a lead | `unaccounted` lead in the lane summary, and a gap. |

A lane where every cell is a gap is reported as such in the report's limitations. It is never read as
a clean target.

## 9. Format enforcement and measurement

- **Constrain the output.** The Claude CLI offers `--json-schema <schema>`. The compact schemas in
  section 6 are small enough to try. The trial measures first-attempt parse success over the recorded
  requests of run 8 before the flag is adopted. If the CLI enforces the schema, the tolerant rules
  below become a fallback.
- **Ask for less.** The model emits no constant the application knows.
- **Tolerant parsing.** A bare or fenced object, a missing `schema`, `arguments`/`args`, parameters
  beside `tool`, and free-text note keys are normalized and counted.
- **Measure.** Each run reports first-attempt parse success, denial counts by code, cells by terminal
  status, and calls per cell. The model contract fails a run whose first-attempt parse success falls
  below a configured threshold.

## 10. Reporting and scoring

Reports, scores and the answer-key comparison read ledger enums and relations only. For each seeded
defect the comparison reports whether any claim at its location reached `confirmed`, `supported`, or a
refuted state, or none was raised. That comparison is reported, not asserted, because it depends on the
model.

## 11. Compatibility and re-invocation

- Package v2 and the compact outputs change cell fingerprints, so existing cells are not reused. The
  ledger and published artifacts keep their schemas.
- The model-facing request carries `protocol: review-protocol/2`. The expanded documents are the
  existing v1 documents.
- All inputs are the accepted outputs of the completed run. The inference review, the publication
  gate and the report can be invoked again on that run with the new protocol, without repeating any
  upstream job.

## 12. Open questions (unchanged by the implementation)

1. ~~Guard facts and the meaning of a dominating guard~~ decided in section 7 (`evidence-admissibility/3`).
2. Whether `--json-schema` is enforced and accepts the compact schemas (section 9).
3. Which hunt-lane units a role may expand beyond its package scope, if any.
4. Whether `expand` should return source text for a label's lines or only identities and summaries.

## 13. Decisions taken at implementation

Where this document left a choice open, the implementation took these. None of them changes R3, R4, R5 or R6.

1. **Compact claim field.** The red claim names its closed consequence `security_predicate`, not `predicate`.
2. **Package v6.** `appsec-review/review-package/6` stores the `neighborhood`; the labelled view is built at cell time
   and is not stored. The reuse basis stays the hash of the stored package. Non-material gaps stay in the stored
   package; the view writes them to a hash-referenced `gaps.jsonl` listed under `files`.
3. **Extra labels.** `M` (SVF memory context), `O` (other context), and `A` (a claim's affected entities in blue and
   verifier cells) join the letters of section 4.2. A row returned by a tool keeps its package label when it has one,
   otherwise it gets the next `Q` label.
4. **Source labels.** An `S` label's identity is the function symbol when the graph names one, otherwise the lead
   observation; a type declaration label is the declaration entity when it is in the package scope, otherwise the
   function span's identity.
5. **`expand`.** Granted to every review cell by the application; it is not in the MCP catalog or any role allowlist.
   It runs a fixed plan of typed requests per identity kind through the cell capability, counts as one query, and
   returns each row with its label. `IN_PROCESS_TOOLS` therefore differs from the published catalog by exactly
   `expand`, and `tests/review/test_capability.py` states that.
6. **Locator.** `locator: {path, line}` is a parameter of `find`, `query_observations` and `query_codeql`; the path must
   be a path the package view names. A flat `path` stays a forbidden parameter.
7. **Denial policy.** A denied request costs one query, is returned with a corrected shape, and is a security event but
   not a gap. The second identical denial in a cell ends it `invalid` with one `authority_error` gap.
8. **Forgiving `query_code_graph`.** A `depth` or class filter the mode ignores is dropped; a call site, sink, entry
   point, guard, range, path or located observation is replaced by the one identity a mode needs when that identity is
   unique. The response names the change.
9. **Omitted lead.** A lead that no claim, `no_claim` or `blocked` entry accounts for is expanded as `blocked` with a
   `missing` named gap. The previous behaviour (an `invalid` cell) is gone.
10. **Bounded investigation details.** Red claims can carry obligations, provenance-labelled taint paths and
    evidence requests, and red results can carry chain seeds. Blue and verifier can request evidence too.
    `compact-investigation.schema.json` defines exact closed shapes and bounds; see the
    [red output contract](red-discovery-output.md) for expansion, nomination and uncertainty semantics.
    Request questions, resolved anchors and optional specialists survive ledger projection, without expanding
    worker authority. A `poc_basis` remains a separate non-evidentiary brief.
11. **Blue authority is enforced before expansion.** Blue `supports` is rejected by the compact schema rather
    than advertised to a worker and subsequently rejected by the relation-authority table. Only verifier and
    red support citations can nominate support within their existing roles.
12. **Leads in the view.** The view lists leads under `leads` for both lanes (a lane A package has one); there is no
    separate `lead` object, which would repeat the row.
13. **`claim` in blue and verifier answers** is advisory: the cell is bound to one claim, and the application fills
    `claim_id`.
14. **Format enforcement.** `--json-schema` was not tried (no live model available to this change); tolerant parsing is
    unchanged.
