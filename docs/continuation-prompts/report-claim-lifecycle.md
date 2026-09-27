# Continuation prompt — first-report claim lifecycle

## Objective

Reach the first immutable evidence-backed **draft** report without pulling deferred recovery, load,
or platform hardening onto the critical path. Build the nominal claim lifecycle only after the F01
index and OWASP T11–T13 join/report core are qualified.

## Parallel ownership

### Lane A — L01 append-only claim ledger

Own a deterministic, hash-linked claim/decision ledger that accepts only candidate routes from the
qualified threat and OWASP cores. Preserve exact evidence citations, producer/attempt identities,
component and source generations, proof obligations, dissent, status and supersession links.
Reject stale/mixed generations, duplicate/conflicting IDs, broken chains and unsupported status
transitions. A candidate is never a finding merely because it entered the ledger.

Do not edit shared graph, parity, Dagster, launcher, generated catalogs or `TODO.md`. Defer crash
recovery, load and dynamic rescope. Publish a clean candidate with focused tests and serialized
integration requests.

### Lane B — L05–L08 nominal decision chain

Consume only accepted ledger candidates and build the smallest deterministic happy path through
red-team hypothesis, blue-team refutation, independent verification, and scoring/prioritization.
Each stage must preserve citations and dissent and must reject stale or self-verifying evidence.
High/Critical claims require an independent verification disposition; unverifiable candidates stay
explicitly unresolved and unscored or conservatively scored according to the contract. No target
execution, remediation loop, fuzzing, dynamic rescope, completeness feedback or recovery hardening.

Keep the four stage contracts distinct even if they share one implementation module. Do not edit
shared graph/parity/Dagster/launcher/catalog/TODO surfaces. Publish a clean candidate plus exact
tests and integration requests.

## Master integration and report exit

The master agent serially integrates qualified candidates, then implements `10-synthesis-report`
and the draft publication package. The report must consume accepted component, threat, OWASP,
verification and scoring outputs; show every coverage gap and unresolved candidate; keep selected,
applicable, assessed and satisfied OWASP denominators separate; and trace every statement to the
claim ledger and immutable evidence. The first milestone is `DRAFT_EVIDENCE_BACKED`, not `FINAL`:
human final signoff, full L09–L11 feedback loops and deferred hardening remain visible blockers.

## Common verification

- focused deterministic positive and mutation fixtures;
- generic contract/claim-ceiling validation;
- exact upstream pointer, artifact and generation revalidation;
- forbidden finding/severity/runtime/compliance promotion tests at every pre-verification stage;
- F02/ledger citation dereference checks;
- `qualify_phase1.py --check-contracts`, design parity, compilation and `git diff --check`.
