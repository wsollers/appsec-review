# Review protocol v2: the model-facing layer

Status: design; implementation follows this document. Observed behavior comes from the first live
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
- the tag assignments and corroborating observations at the same location.

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
separate, read-only surface for external clients and the OWASP workbench. Runtime skills under
`pipeline/skills/` serve the build and planning workers and say nothing about review retrieval.

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
    "predicate": "affected_construct",
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
- A hunt-lane answer uses the same shape, with `units` in place of `leads`.

### 6.3 Blue

```json
{"action": "final", "result": {
  "claim": "c1",
  "stance": "contradicts",
  "predicate": "missing_or_ineffective_guard",
  "cites": ["G2", "S1"],
  "why": "The guard at line 13 rejects short input."
}}
```

`stance` is one of `supports`, `contradicts`, `qualifies`, `unresolved`. The application turns each
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

### 6.5 Label resolution

- A label resolves through the package and the cell's own retrieval receipts. A label from another
  cell, or one that does not exist, is dropped with feedback, and the claim loses that support.
- A stance without a resolvable citation is recorded as `unresolved`.
- A raw ref is accepted wherever a label is, if the cell received it.

## 7. From stance to state

The model never sets a state. For each cited label the application records an evidence relation to a
predicate (`supports`, `contradicts`, `qualifies`), re-resolves it under `evidence-admissibility/2`,
and R5 evaluates the claim.

| What a cell says | What the application records | Effect |
|---|---|---|
| Red `support[p]: [labels]` | `supports` relation per label, per predicate | Counts as direct support only if the row is direct and resolves. |
| Red `counter[p]: [labels]` | `qualifies` | Never contradicts. Contradiction belongs to blue and the verifier. |
| Blue `contradicts p` with cites | `contradicts` relation per label | A direct contradiction defeats the predicate (R5 rows 3 and 4). |
| Blue `supports` or `qualifies` | `supports` or `qualifies` | Adds weight; cannot confirm. |
| Verifier `disposition` | recorded as `proposed_disposition` | A proposal; R5 decides. |
| Any `unresolved` or empty cite list | no relation | The predicate stays open (R5 row 6 or 7). |

Worked outcome for the `packet.cpp:16` claim: `affected_construct` has direct support from the sink
fact. `attacker_input_control` cites source text. `missing_or_ineffective_guard` is contested: the
dominating guard G2 compares the input size with the length field, not with the capacity of
`out.name`. Under the R3 mapping a dominating guard contradicts this predicate. That would wrongly
refute a real overflow.

**Open question 1 (needs a decision).** The `guard_fact` does not say what its condition bounds. Either
(a) extend the graph export so a guard fact records the compared operands, letting the application
treat a guard that does not reference the sink's destination as `qualifies`; or (b) treat a
dominating guard as `qualifies`, never `contradicts`, unless a blue or verifier cell cites both the
guard and the source text that shows it bounds the destination, and the application can confirm the
destination appears in the guard's condition. This spec recommends (a) with (b) as the interim rule.

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

## 12. Open questions

1. Guard facts and the meaning of a dominating guard (section 7).
2. Whether `--json-schema` is enforced and accepts the compact schemas (section 9).
3. Which hunt-lane units a role may expand beyond its package scope, if any.
4. Whether `expand` should return source text for a label's lines or only identities and summaries.
