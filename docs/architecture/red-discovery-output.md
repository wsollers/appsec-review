# Red discovery output contract

The red pool emits a typed **proposal**, never a finding. Its machine-readable contract is
[`red-discovery-result.schema.json`](../schemas/inference-security-review/red-discovery-result.schema.json),
version `appsec-review/red-discovery-result/1`. Both `hypothesis_hunter` and `red_team_analyst`
use it. The former may propose a new condition within a hunt package; the latter may develop a
finding lead into an explicit attack hypothesis. Neither role sets a claim state, severity, CVSS,
exploitability rating, PoC eligibility, or final attack-chain identity.

## Result contents

| Field | Meaning |
|---|---|
| `package`, `role`, `round_id` | Echo the pinned run, accepted manifest, package ID/hash, worker role, and round. The application checks these against the invocation rather than trusting the echo. |
| `lead_accounting` | One entry for **every** lead in the package: `proposal`, `no_proposal`, or `blocked`. `no_proposal` means only that this bounded worker did not propose a claim; it is not clean coverage. Blocked entries name gaps. |
| `proposals` | Local, provisional claim IDs; source lead IDs where applicable; affected entities; weakness/mechanism; attacker-controlled entry; trigger; suspected security consequence; assumptions; cited support and counterevidence; open obligations. A novel hunt proposal may have no source lead ID but must cite a package-scoped affected entity. |
| `taint_paths` | Candidate source-to-sink paths with ordered nodes and edges. Each edge identifies its basis (`accepted_tool_path`, `source_mapped_analysis`, or `analyst_hypothesis`), citations, and any unresolved continuity. Guards, sanitizers, macro/template expansion, and configuration conditions remain explicit. A scanner-reported path is a report, not proof of an executable path. |
| `chain_seeds` | Ordered attacker-step hypotheses with the objective, prerequisite/result of each step, and proposed continuity between steps. These are seeds for later chain composition, not confirmed chains or fixed kill-chain stage labels. |
| `evidence_refs` | Package-scoped logical entity and accepted shard identity, relation to a predicate, and a source-line or run-artifact locator when available. An unresolved locator is marked unresolved. Raw source excerpts and protected build arguments are not copied into the result. |
| `evidence_requests`, `gaps` | Bounded questions for later retrieval or review, and named missing/partial coverage. Unsupported predicates remain open. |

Each proposal states the **necessary security predicate** in plain terms: what attacker-controlled
value or capability enters, how it reaches an affected construct under an identified configuration,
what guard may stop it, and what security consequence would follow. The red result can cite evidence
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
The current scoped MCP slice supplies exact entity and precomputed-fact reads; it does not provide
a general graph-path query. A red worker may use an accepted scanner-reported path or mapped
compiled evidence within its grant. For an unavailable hop, it emits an evidence request and a gap
instead of inventing a complete path. Wider path retrieval requires its own accepted index and
package-scoped capability before workers can use it.

A chain seed is an ordered **candidate sequence of attacker actions or effects**. It can reference
local proposals in the same result and can request an external prerequisite, but it cannot assert a
claim in another package. Every proposed step-to-step link records which of identity, privilege,
trust-boundary, deployment-artifact, and temporal continuity need checking. The later chain
composer may link adjudicated claims across packages and must verify all five dimensions; it cannot
inherit a red seed as a confirmed chain.

## Admission rules for deterministic normalization

1. Validate the closed schema and centrally configured limits on bytes, counts, text lengths,
   path depth, and evidence requests. These limits come from the resolved run configuration.
2. Verify the echoed package hash, run, manifest, role, and round. Each referenced entity and
   shard must belong to the accepted manifest and the package capability. Resolve cited source
   lines or run artifacts; preserve unresolved references as gaps.
3. Require local ID uniqueness, exact lead accounting, reference closure, ordered and acyclic
   taint/chain edges, and citations for every claimed observed segment. A chain seed has at least
   two steps. Reject references to another worker's transcript or an ungranted package.
4. Normalize proposal identity from affected entities, mechanism, security predicate,
   preconditions, and scope. Worker prose and local IDs do not define canonical `claim_id`.
   Exact duplicates merge; possible semantic duplicates remain separate nominations.
5. Publish one terminal record for every expected worker cell, including invalid output, timeout,
   or no proposals. A malformed cell is a named gap; it does not erase accepted leads or imply a
   clean target.

The red output is an input to [inference security review](inference-security-review.md). Blue and
blind verifier pools receive normalized claims and original cited evidence under separate bounded
capabilities. Attack-chain composition and refutation occur after claim adjudication.
