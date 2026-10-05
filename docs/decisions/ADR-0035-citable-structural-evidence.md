# ADR-0035: Citable structural evidence from code queries

Status: **Accepted** (2026-10-05, owner-approved brief "structural-evidence"). Builds on
[ADR-0032](ADR-0032-structural-query-tools.md) (structural query tools) and
[ADR-0013](ADR-0013-run-to-report-first.md).

## Context

On hello-autotools run `20261004T054551Z-357581` every claim ended UNRESOLVED or REFUTED, so no report
can hold a verified finding:

- `09-independent-verification` had no way to produce new independent evidence. Its runtime
  instructions said "never emit VERIFIED" and `claim_review_derive.STAGE_DISPOSITIONS` excluded it.
- `claim_lifecycle_core.verify` needs, for VERIFIED, every obligation SATISFIED and citations that are
  new relative to the red/blue citations and produced by the verifier itself. Derive could only resolve
  upstream citation ids, so that rule could never be met.
- 08/09 `tooling_feedback`: blue-team REFUTED and reachability conclusions rested on `code_callers` /
  `code_path` answers "described in prose but never captured as a citation_id", so the verifier could
  not check them.

## Decision

### 1. Scope: which answers are citable

A structural answer is citable when it is a deterministic function of a hash-bound index, so that
Python can recompute it later:

| Citable | Not citable (answer carries `citation_gap`) |
|---|---|
| `code_symbol`, `code_locate`, `code_callers`, `code_callees`, `code_path` | `code_search`: fuzzy discovery, not a fact about the program |
| `code_calls_to` without `partition_id` / `component_id` (those filters read the cell's pinned maps, which are not available when the record is checked) | `code_type_info`, `code_overrides`: name heuristics without inheritance edges |
| `code_definition`, `code_references`, `code_call_hierarchy` when every row came from the precomputed `02-lsp-xref` database (`answered_from == "precomputed"`) | `code_address_taken` (never complete), `code_file_outline`, `code_exports`, `code_hover` (server text) |
| | any lsp answer that used the live or recorded broker: re-running it is not hermetic |

### 2. Record shape

`tool_evidence.py` writes one record per citable answer. Python writes it from the answer the tool
returned; the model never writes it. The file is
`runs/<run>/data/tool-evidence/<job>/<attempt>/<hex>.json` with these fields:

- `schema` `appsec-review/tool-evidence/1.0`, `citation_id`, `content_sha256`;
- `body`, the hashed part: `tool`, normalized `arguments` (the `query` the tool echoed after path
  normalization), `index` (kind `code-index` or `lsp-xref`, the pinned summary ref, its sha256, the
  producer attempt and database sha256), `answer_sha256`, `complete` (the tool's `complete` and not
  `truncated`), `reasons`, `escapes` (count of escape rows plus `code_path` escapes), and the invoking
  `job_id` and `attempt_id`;
- `answer`: the full tool answer without its constant `note`. It holds the rows, `complete`, the
  reasons, the escapes and `source`;
- `cell` (the invocation's output root) and `recorded_at`. These two are outside the hash.

`content_sha256 = sha256(canonical body)`. `citation_id = "tev:" + content_sha256[:32 hex]`.
The id has a `:` separator and a digest-length hex run, so the V06 redactor leaves it alone (a
`prefix-<hex>` run is treated as a secret). The same query on the same index in the same attempt gives
the same id. A record that already exists is never rewritten, so its file sha256 stays stable.

### 3. How models cite

A citable answer carries `citation_id`. A model that wants to rely on the answer puts that id in
`citation_ids`, next to the upstream ids, and never writes a path or a hash. `claim_review_derive`
resolves `tev:` ids against the invocation's own records (`job_id` = stage, `attempt_id` = the
cell's request attempt), then builds the canonical `claim-lifecycle-citation`:

- `producer_job_id` / `producer_attempt_id`: the invoking job and attempt, which are the reviewer's
  or verifier's actor identity;
- `artifact_path`: `tool-evidence/<job>/<attempt>/<hex>.json`, relative to the run's `data/`
  (like `jobs/...` citations in the ledger);
- `artifact_sha256`: the record file's sha256;
- `locator_json`: canonical JSON `{"tool", "arguments", "complete"}`;
- `observed_fact`: a summary Python builds from the answer, for example
  `code_callers(copy_into_fixed) -> src/main.cpp:42, src/runner.cpp:9 [complete]` or `[incomplete: 2 escape row(s) ...]`.

A `tev:` id that does not resolve sends the reply back for repair. Unlike an unknown upstream id, it is
not dropped silently. Records travel with the decision: an 08 refutation's records become part of the
claim's `refutation_citations`, so 09 sees them as prior citations.

### 4. Validation: re-run, never trust the file

Each time a record is resolved, in derive and again when the pool merge is validated (at merge and on
every resume post-validation), Python:

1. checks the record's path, `job_id` / `attempt_id`, `content_sha256` and `citation_id` (this catches
   a tampered record), and that the citation equals the one rebuilt from the record;
2. re-opens the bound index read-only. The index summary's sha256 must match, and so must the database
   sha256 (re-hashed by `CodeIndex` / `LspIndex`). An lsp re-run is given a broker that refuses, so it
   can never start a server;
3. re-runs the query with the recorded arguments and requires the new answer's sha256 to equal
   `answer_sha256` (this catches a forged or edited answer, and an index or tunable change).

### 5. Independence rule (09), enforced in `claim_lifecycle_core`

- 07/08 may cite their own `tev:` records (producer = this stage's reviewer) in addition to the
  upstream citations. 09 may cite prior citations and its own records, and nothing else.
- **VERIFIED** at 09 needs all of these:
  - every obligation is SATISFIED and cites at least one citation;
  - every citation was produced by the verifier, which means the verifier re-ran the structural
    queries itself, so a red/blue record can never carry a VERIFIED decision;
  - every cited record is complete (`complete=true`, no escapes, not truncated);
  - at least one cited record is new relative to the red and blue citations.
- **An incomplete record supports only UNRESOLVED or BLOCKED** at 09. A decision citing one cannot be
  VERIFIED or REFUTED.
- What static structure proves: that a definition exists, who calls a function, that a call path
  exists in the resolved graph, and what arguments a call site has. Under a complete answer, it also
  proves that no resolved caller or path exists.
- What static structure does not prove: exploitability, runtime reachability under real inputs or
  configuration, attacker control of data, impact, or the absence of indirect calls the graph did not
  model. An obligation that needs any of these stays UNRESOLVED. The model is told so. Python cannot
  read obligation semantics, so this part of the rule is the verifier's judgment, constrained by the
  mechanical rules above.

### 6. Runtime instructions and `STAGE_DISPOSITIONS`

`STAGE_DISPOSITIONS["09-independent-verification"]` regains VERIFIED. The 09 runtime rule now states the
independence rule above, in place of "never emit VERIFIED". The citation rule for 07/08/09 names
`citation_id`s from the cell's own code-query answers. `code_graph.md` (v2) gains one line on citing.

### 7. Trust boundary

Records are produced by Python, from accepted, re-hashed indexes, and the producer identity comes from
the invoker's trusted request. The model only chooses which queries to run and which ids to cite. Rows
remain target data (names, code text). They are never instructions, and `observed_fact` quotes only
locators and names.

### 8. Fingerprint and cache impact

- `claim_review_derive.py`, `claim_reviewer_pool.py` and `claim_lifecycle_core.py` are part of the
  pool's `_code_hashes`, and `claim_lifecycle_core.py` is part of the stage's. So the pool and the
  lifecycle stage of 07, 08, 09 and 12 re-execute on the next resume. `tool_evidence.py` joins the
  pool's code hashes.
- The persona cache key covers the prompt text, which includes the tool guides, but not the appended
  runtime instructions. Changing `code_graph.md` changes the key of every cell granted
  `code_callers`/`code_callees`/`code_path`, but only for cells that run again. Upstream jobs (05 hunts and
  others) do not fingerprint tool guides, so they do not re-run. For 07/08/09/12 the cached replies
  would miss anyway, because a cached reply that cites `tev:` ids of another attempt does not resolve.
  The 09 decision changes, so 09 and 12 need fresh model calls in any case.
- `input_mcp.py` writes records only for citable answers, and the retrieval audit is unchanged.

## Consequences

- 09 can legitimately reach VERIFIED (or REFUTED) from a complete structural answer it re-ran itself.
  A prose description of a query is never evidence.
- The report gets citations whose artifact is a tool-evidence record and not a `jobs/` attempt.
  `report_input_assembly._verify_citation` and the final ledger have to resolve
  `tool-evidence/<job>/<attempt>/<hex>.json` under the run's `data/`, ideally through
  `tool_evidence.verify_citation`. That is a hand-off to their owners.
- Native code with indirect calls often gives `complete=false` answers. Those can never verify, which
  is accurate.
