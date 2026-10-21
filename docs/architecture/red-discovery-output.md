# Red discovery output contract

The red pool emits a typed **proposal**, never a finding. Its machine-readable contract is
[`red-discovery-result.schema.json`](../schemas/inference-security-review/red-discovery-result.schema.json),
version `appsec-review/red-discovery-result/1`. It is the single output contract of both
`hypothesis_hunter` and `red_team_analyst` (design decision 10; the earlier `red-result/1` is
retired). The former may propose a new condition within a hunt package; the latter may develop a
finding lead into an explicit attack hypothesis. Neither role sets a claim state, severity, CVSS,
exploitability rating, PoC eligibility, or final attack-chain identity.
`src/appsec_review/review/red_discovery.py` implements the admission rules below, and
`jobs/job_inference_security_review/teams.py` normalizes admitted results.

## The compact layer (review protocol v2)

A red cell does not write this document. It answers in `red-compact/1`
([`red-compact.schema.json`](../schemas/inference-security-review/red-compact.schema.json)): claims with label
citations, `no_claim` and `blocked` leads, and an optional bounded `poc_basis` per claim. The application expands that
answer into `red-discovery-result/1` (`review/compact.py`, `expand_red`) before any validator runs, so every `v1`
document in the ledger comes from an expansion and the admission rules below, normalization, R3, R5 and R6 are
unchanged. See [review protocol v2](review-protocol-v2.md) section 6 for the shape and the expansion table. The
expansion fills the schema, package echo, role and round, local ids, `source_lead_ids`, the evidence references
(`supports` for `support`, `qualifies` for `counter`; a locator of kind `unresolved`, because the application
re-resolves the identity), and the lead accounting: a lead no claim develops and the answer does not list under
`no_claim` or `blocked` becomes `blocked` with a named `missing` gap. The compact form carries no taint paths, chain
seeds or evidence requests; those fields are empty in an expanded result.

`poc_basis` has no closed field in this document. Its labels are resolved to identities and its texts bounded, and the
application stores it as the optional `proposal.poc_basis` field, which `teams.py` copies to the run-owned
`poc-basis.json` beside the lane ledger. The artifact is a brief for a later proof-of-concept job: it is not a claim,
not evidence and not code, and no claim state, relation or score reads it. Where a closed field exists it is filled too
(`attacker_entry.entity_id` from the first cited entry point, closed `preconditions/1` members).

## Result contents

| Field | Meaning |
|---|---|
| `package`, `role`, `round_id` | Echo the invocation block the cell is given: the package's reuse basis (`package.basis_sha256`), the worker role, and the round. The application checks the echo against the invocation rather than trusting it. The run, accepted manifest, and package identity and hash are bound by the application-held cell capability and fingerprint, never by the echo: the worker's package view deliberately omits them, so that a cell stays reusable across manifests whose shards it does not read. |
| `lead_accounting` | One entry for **every** lead in the package: `proposal`, `no_proposal`, or `blocked`. `no_proposal` means only that this bounded worker did not propose a claim; it is not clean coverage. Blocked entries name gaps. |
| `proposals` | Local, provisional claim IDs; source lead IDs where applicable; affected entities; weakness (a CWE id or `null`) and mechanism; the security predicate (a `security-predicates/1` member); attacker-controlled entry with its preconditions (`preconditions/1` members); trigger; suspected security consequence; free-text assumptions; cited support and counterevidence; open obligations. A novel hunt proposal may have no source lead ID but must cite a package-scoped affected entity; a lead analyst's proposal names the lead it develops. |
| `taint_paths` | Candidate source-to-sink paths with ordered nodes and edges. Each edge identifies its basis (`accepted_tool_path`, `source_mapped_analysis`, or `analyst_hypothesis`), citations, and any unresolved continuity. Guards, sanitizers, macro/template expansion, and configuration conditions remain explicit. A scanner-reported path is a report, not proof of an executable path. |
| `chain_seeds` | Ordered attacker-step hypotheses with the objective, prerequisite/result of each step, and proposed continuity between steps. These are seeds for later chain composition, not confirmed chains or fixed kill-chain stage labels. |
| `evidence_refs` | Package-scoped logical entity, accepted shard identity (`<index>/<shard>` and its hash, or `null` when the worker did not learn them), relation (`supports`, `contradicts`, `qualifies`, or `nominates`) to one R4 obligation predicate, and a source-line or run-artifact locator when available. An unresolved locator is marked unresolved. Raw source excerpts and protected build arguments are not copied into the result. |
| `evidence_requests`, `gaps` | Bounded questions for later retrieval or review, and named missing/partial coverage. Unsupported predicates remain open. |

Each proposal names its security consequence as one closed `security_predicate` member and
explains the condition in plain terms: what attacker-controlled value or capability enters, how it
reaches an affected construct under an identified configuration, what guard may stop it, and what
security consequence would follow. The red result can cite evidence
that supports or contradicts each predicate. It cannot mark a predicate satisfied; normalization,
blue refutation, blind verification, and deterministic adjudication decide that later.

For C/C++, accepted source-mapped post-macro and template-expanded Clang views can be cited to
describe the compiled construct. If the exact build unit, configuration, or source mapping is
uncertain, the red result records that as an assumption or gap. Package creation does not have to
resolve it first.

## Taint and chain semantics

A taint path is an ordered **candidate dataflow** within one proposed issue. It may mix reported
and inferred segments, but every segment labels its origin; a hypothesized hop cannot be silently
promoted to an accepted graph edge. The source, transformations, guards/sanitizers, trust-boundary
crossings, and sink are distinct nodes. A path with a missing edge remains `partial` or
`hypothesized`. Counterevidence such as an effective sanitizer is retained as a separate citation.
A red worker may use an accepted scanner-reported path, mapped compiled evidence, or accepted
code-graph facts within its grant. `query_code_graph` is a red tool; a cell is granted it within
its package's accepted graph scopes, and the `call_site`, `sink_site`, `entry_point`,
`dataflow_path`, `guard_fact` and `range_fact` rows it returns may be cited by a hop
([code-graph precomputation](code-graph-precomputation.md) sections 3 and 6). For an unavailable
hop, the worker emits an evidence request and a gap instead of inventing a complete path.

A chain seed is an ordered **candidate sequence of attacker actions or effects**. It can reference
local proposals in the same result and can request an external prerequisite, but it cannot assert a
claim in another package. Every proposed step-to-step link records which of identity, privilege,
trust-boundary, deployment-artifact, and temporal continuity need checking. The later chain
composer may link adjudicated claims across packages and must verify all five dimensions; it cannot
inherit a red seed as a confirmed chain.

## Admission rules for deterministic normalization

Rules 1 to 3 run as the cell's final-result validation (`red_discovery.admission_errors`). Any
violation makes the cell's result invalid: the cell ends `invalid` with a `schema_error` gap and
exactly one terminal record, and it is retried only as the retry policy allows. The validator
version of a red cell names the admission rules (`red-discovery-admission/1`) and a hash of the
resolved limits, so changing either invalidates red cell reuse.

1. Validate the closed schema and the limits on bytes, counts, text lengths, path depth (nodes per
   path), chain steps, and evidence requests. The schema's `maxItems`/`maxLength` are hard
   ceilings. The run's limits come from the resolved `settings.red_output` table, which may only
   tighten them.
2. Verify the echoed package basis, role, and round against the invocation. Each referenced
   entity must have been returned in this cell's own retrieval transcript or supplied in its
   package (the cell executor's citation check), so references to another worker's transcript or an
   ungranted package are rejected.
3. Require local ID uniqueness (one namespace for top-level objects; node and step IDs unique within
   their path or seed) and exact lead accounting: every package lead exactly once, no foreign lead,
   `proposal` entries naming proposals that cite the lead (and every proposal named by each of its
   source leads), `no_proposal` entries naming none, and `blocked` entries naming a gap. A package
   lead missing from `lead_accounting` is therefore a `schema_error` cell gap. Also require
   reference closure (evidence, obligations, taint paths, gaps, and requests resolve to their
   owners; support cites no `contradicts` reference and counterevidence cites only `contradicts`
   or `qualifies`), forward-ordered and therefore acyclic taint edges and chain links, a citation
   on every observed (`accepted_tool_path` or `source_mapped_analysis`) hop, no hypothesized hop in
   a `reported` path, which must connect its source to its sink, and at least one gap in a
   `partial` result. A chain seed has at least two steps.
4. Normalize proposal identity from affected entities, weakness, security predicate, and
   preconditions (`review/claims.py`, design R7). Worker prose and local IDs do not define the
   canonical `claim_id`. Exact duplicates merge; possible semantic duplicates remain separate
   nominations. A precondition outside `preconditions/1` rejects that proposal at the triage gate
   with an `evidence_gap`; the rest of the result is kept.
5. Turn citations into evidence relations only through `review/evidence.py::resolve_relation`. A
   proposal's relations are its `evidence_ids`, its `counterevidence_ids`, and the citations of
   the observed hops of its own taint paths. A hop whose basis is `analyst_hypothesis` never
   becomes a relation, `nominates` references only guide search, and red counterevidence is
   recorded as `qualifies`, because contradiction is reserved to the blue refuters and the blind
   verifier. A cited shard or source-line locator that disagrees with the re-resolved entity is an
   `evidence_gap`, and so is an unresolvable citation.
6. Record each proposal's evidence requests in the ledger, record the worker's named gaps
   (`unresolved` and `ambiguous` gaps as `evidence_gap`, others as `coverage_gap`), and
   summarize each package lead across the package's succeeded red cells as `proposal`,
   `blocked`, `no_proposal`, or `unaccounted` in the lane document. Those summaries feed the
   handoff accounting (`leads_expected`, `leads_by_outcome`). Admitted chain seeds go to the lane's
   bounded `chain-seeds.json` (`appsec-review/red-chain-seeds/1`), with the claim ids their steps'
   proposals normalized to. They are inputs for the later chain slice and never claims.
7. Publish one terminal record for every expected worker cell, including invalid output, timeout,
   or no proposals. A malformed cell is a named gap; it does not erase accepted leads or imply a
   clean target.

The red output is an input to [inference security review](inference-security-review.md). Blue and
blind verifier pools receive normalized claims and original cited evidence under separate bounded
capabilities. Attack-chain composition and refutation occur after claim adjudication.
