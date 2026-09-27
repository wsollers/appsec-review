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

## First remaining blocker

The full four-component ASVS L2 run now derives the T11-T13 matrix successfully, but T14 cannot
publish its common envelope because `owasp-control-status-matrix.json` is larger than the common
per-artifact limit:

```text
worker result validation failed: declared result artifact exceeds 8388608 bytes
```

The failed T14 attempt is not accepted. This is a publication-shape/size blocker, not an assessment
or evidence-lineage failure: every dispatched T10 cell completed, every candidate passed T07, and
verified accounting retained the results before join/report publication was attempted.

## Retained executable evidence

`appsec-review-process/tests/test_owasp_chain_qualification.py` publishes the four-component map
through the common worker-result helper, admits a separately scoped canonical server/config
artifact, runs the real T03/routing/T04/T05/T06/T10/T07 path, and proves every dispatched result is
valid before retaining the exact T14 size refusal. Mutation tests prove stale, mixed-generation,
unresolved-scope, and envelope-binding changes are rejected.

Run from `appsec-review-process`:

```bash
python -m unittest -v tests.test_owasp_chain_qualification
python -m unittest -v tests.test_owasp_lane_in tests.test_owasp_component_routing
```

## Required next closure

Define a bounded publication shape for large OWASP matrices without raising the common artifact
limit globally. The preferred closure is deterministic partitioning or paging with a small manifest
that binds every part, exact row coverage/order, denominators, and hashes; validation must reject
missing, duplicate, reordered, mixed-generation, or oversized parts. Then rerun this qualification
through accepted T14 publication. Compacting the matrix is acceptable only if it preserves every
selected target, status, citation, dissent, rescope, and accounting link.
