# OWASP standalone-chain qualification

Date: 2026-09-27

Scope: exercise the production contracts from accepted `01-component-characterization` through
T03 (`04-owasp-intel-lane-in`), component routing, T04 applicability, T05 batching, T06 handoff,
and onward only as far as the tracked workers permit. The fixture is a Freeciv-like source tree
partitioned into server, client, protocol, and ruleset-loader components. No legacy pointer was
synthesized and no test-only validator registry was substituted.

## Result

The T03 compatibility gap is closed. T03 now recognizes the common
`appsec-review/accepted-worker-result/1.0` pointer and passes it through the common publication
verifier. Admission additionally requires the requested artifact path and SHA-256 to occur exactly
once in the verified immutable envelope. The verified pointer fingerprint, run, job, attempt,
latest-attempt state, complete attempt-tree hashes, envelope hash, artifact path, and artifact hash
are therefore all bound before admission. A malformed common pointer is never reinterpreted as a
legacy pointer.

The live qualification reaches these accepted results:

- T03 lane-in: `OK`
- component routing: `OK_WITH_GAPS`
- T04 applicability: `OK_WITH_GAPS`
- T05 batching: accepted (`OK` or `OK_WITH_GAPS`)
- T06 validator handoff: accepted (`OK` or `OK_WITH_GAPS`)
- T10 dispatch/accounting: accepted; every expected static cell ran through the tracked validator
  composition and every candidate passed T07 with canonical component-scoped evidence
- T14 deterministic join/publication: accepted (`OK` or `OK_WITH_GAPS`) as a bounded manifest and
  multiple matrix pages

The four components are all retained. No target is converted to technical not-applicable. Server
targets are assigned under the approved ASVS L2 server scope; unresolved client/runtime
classification remains `cannot_determine` and rescope-visible.

The validator registry gap is closed without changing the existing worklist composition.
`04-owasp-validator-cell` selects the existing `owasp-validator`,
`standards-control-validator`, and `owasp-application-controls` records with a new bounded
`owasp-control-validator` tooling profile and `owasp-control-assessment-candidate` output contract.
Its ceiling allows `control_verdict`, `coverage_gap`, `dynamic_test_request`, and
`candidate_followup`; it expressly prohibits finding, severity, exploitability, runtime,
remediation, compliance, and certification claims. The worklist builder still forbids verdicts.

Canonical component evidence routing is now closed. A T03 entry may carry an explicit
`component_scope` only when it is current, canonical, raw, accepted producer output. The scope
pins the complete accepted component-map binding and names resolved component IDs. The assembler
projects those entries separately as `evidence_input_ids`; classification remains bound only to
the locator-only component map. T04 preserves the separate IDs, T05 requires the component context
to match them exactly, and T06 includes the canonical roots in its component handoff. Empty evidence
sets remain empty rather than being padded with locator-only intelligence. Stale evidence, mixed
component generations, unresolved component IDs, producer-pointer tampering, and artifact-hash
tampering fail closed.

The T14 publication-size gap is closed without raising the common 8 MiB artifact safety limit.
The publisher retains a small `owasp-control-status-matrix-manifest.json` plus deterministic
`owasp-control-status-matrix-pages/page-NNNN.json` artifacts capped at 7 MiB. The manifest binds the
logical matrix hash, ordered-row hash, exact row count and denominators, and every page's ordinal,
path, byte count, SHA-256, row count, and inclusive row range. Validation reconstructs the logical
matrix in exact source order and rejects missing, additional, duplicated, reordered, substituted,
oversized, or mixed pages before accepting the common envelope.

## Remaining integration boundary

There is no remaining blocker in this standalone T03-through-T14 happy path. The integrator still
owns registration in the shared lifecycle graph, Dagster definitions, launch surface, and parity
manifest; those shared surfaces were intentionally excluded from this qualification branch. A real
deployment must also supply its approved `PersonaInvoker`; this repository's retained live fixture
is deterministic and model-free.

## Retained executable evidence

`appsec-review-process/tests/test_owasp_chain_qualification.py` publishes the four-component map
through the common worker-result helper, admits a separately scoped canonical server/config
artifact, runs the real T03/routing/T04/T05/T06/T10/T07 path, and proves every dispatched result is
valid before retaining and revalidating an accepted, multi-page T14 result. Mutation tests prove
stale, mixed-generation, unresolved-scope, envelope-binding, missing-page, duplicate-page,
reordered-page, and substituted-page changes are rejected.

Run from `appsec-review-process`:

```bash
python -m unittest -v tests.test_owasp_chain_qualification
python -m unittest -v tests.test_owasp_join_publisher
python -m unittest -v tests.test_owasp_lane_in tests.test_owasp_component_routing
```
