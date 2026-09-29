# Brief T: attack trees consumed by attack chains (branch `trees-into-chains`) - CLOUD agent
William, 2026-09-29. The threat workbench (ADR-0019, job `03-threat-model-dfd-stride`) publishes `attack_trees` with
content-derived, replay-stable ids, and lane 14 (ADR-0016, `attack_chain_*`) composes chains from verified claims, but
the two never meet: `attack_chain_seeds.py` uses CPG entry calls, threat-model actors and claim zones, not the trees.
This is the open TODO row "ADR-0016 chain composition: consume `attack_trees`". Goal: use the trees as HYPOTHESES that
guide and prioritise chain composition, without ever letting a tree stand in for evidence.

Read first: `docs/agent-briefs/00-common.md`, `docs/decisions/ADR-0016-attack-chain-composition.md` and
`ADR-0019-threat-workbench-slice-1-and-privacy.md`, `attack_chain_seeds.py`, `attack_chain_composition.py`,
`attack_chain_derive.py`, `attack_chain_refute.py`, `attack_chain_report.py`, `threat_workbench.py` (the tree shape:
nodes, AND/OR gates, leaves, ids), `threat_model_reconciliation.py` (what 03-reconciliation does with trees),
`schemas/attack-chain-*.schema.json`, `mitre_feed.py` claim and chain tags (ADR-0026) and TODO section "Attack chains".

## T1. Tree-to-graph mapping (deterministic, no model)
New module `attack_chain_trees.py`. Input: the accepted (reconciled) threat model's `attack_trees`, the claim ledger's
latest states, the fact menu. For each tree: map every LEAF to the claims and facts that could realise it, by
deterministic joins only (same component or element id, same CWE family, same file/function locator, same CAPEC/ATT&CK
tag from the validated feed, threat-model flow id). Output per tree: `covered` leaves (at least one verified or narrowed
claim), `open` leaves (only open claims), `uncovered` leaves (no claim: a coverage gap, and an explicit list of what
evidence would close it), and the AND/OR-evaluated tree state:
- an AND node is `SUPPORTED` only if every child is supported; an OR node if at least one child is;
- a node with only open claims is `UNVERIFIED`, never `SUPPORTED`;
- refuted or superseded claims never support a leaf.
Cycles or malformed trees are recorded as gaps. Ids stay the content-derived ones from the workbench.

## T2. Seeds and clusters use the trees
Extend `attack_chain_seeds.py` (behind tunable `chain_use_attack_trees`, default OFF; with it off the output is
byte-identical, golden-hash test):
- a tree whose root goal is (partly) `SUPPORTED` or `UNVERIFIED` with at least one covered leaf becomes a cluster
  seed of its own kind (`tree`), even when no CPG entry call reaches it;
- a cluster inherits the tree's leaf list so the composer workspace shows which steps of the hypothesised attack are
  backed by claims and which are not; ranking adds tree state as a tie-breaker AFTER the existing keys (P1 count,
  verified count, boundaries crossed), so trees can never outrank verified evidence;
- workspaces carry the tree id and leaf-to-claim mapping as read-only context. The composer may only cite claims and
  facts the workspace lists, exactly as today; a tree node is never a citable fact.

## T3. Composer and refuter contracts
- The composer persona prompt gains a short "attack tree context" section: the tree is an unverified hypothesis
  from another persona; a chain step needs cited claims/facts; an uncovered leaf must stay a stated gap, not be
  bridged. Persona prompt bytes for other personas stay identical; update only this persona and its role record.
- Derive step (ADR-0013): Python fills `tree_id`, `leaf_ids`, `covered_leaf_ids` and `tree_state` on the chain record
  from the workspace; the model echoes nothing of that (add to `attack_chain_derive` and its drift test).
- The refutation cell receives the same tree mapping and must explicitly address each `uncovered` leaf the chain
  relies on; a chain that depends on an uncovered leaf cannot be `SUPPORTED`.

## T4. Report and feedback
- `attack_chain_report.py` / the report's section 3A: per chain, show the tree it realises (id, root goal), the
  covered/open/uncovered leaf counts and the uncovered-leaf evidence wish-list. Also list high-value trees that
  produced NO chain, with their state (this is the "attack paths we considered but could not support" section reviewers
  ask for). Optional report keys; older reports stay valid.
- Feed the uncovered-leaf list back as targeted hunt hints to `07-hypothesis-discovery` in the NEXT run only through
  the existing dynamic-rescope or resynthesis loop (`synthetic-hypothesis-resynthesis`), bounded by its existing
  tunables; do not add a new loop. If that wiring is bigger than one commit, document it as follow-up.

## T5. Tests
Fixtures: a tree fully covered by verified claims (chain seeds, tree_state SUPPORTED), a tree with one uncovered leaf
under an AND (never SUPPORTED), an OR with one covered branch, a tree over refuted claims (no support), a malformed
tree (gap), and the default-OFF byte-identical check. A test proves a tree node id can never appear as a chain
citation and that ranking never lets a tree outrank a P1 verified cluster.

## Rules
- Deterministic code plus one prompt section; no new model call. Every new state and key in schemas and closed
  vocabularies; regenerate catalogs; never hand-edit generated files.
- ADR-0031 (proposed) or an ADR-0016 addendum if no new decision is needed. List fingerprints that move by job id
  (`14-attack-chain-composition`, `14-attack-chain-refutation`, `10-synthesis-report`, personas hashes). Update
  `TODO.md` (section T) and `prompts/README.md`.
