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
- T10 dispatch/accounting: `OK_WITH_GAPS`; every expected static cell ran through the tracked
  validator composition and every candidate was submitted to T07

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

## First remaining blocker

The full-review evidence route supplies only the derived component map as each component's evidence
root. That artifact is correctly admitted by T03 as locator-only derived intelligence and may not
support a control verdict. The deterministic validator fixture therefore produces candidates from
the bytes it was handed, but T07 rejects every candidate because locator-only intelligence was
presented as canonical evidence. T10 retains the outcome as `validation_refused` and `not_assessed`
for every dispatched cell; it does not adopt any result.

```text
locator-only or derived intelligence was presented as canonical evidence
```

This is the first remaining happy-path blocker. It is not a registry or dispatch failure: all
expected cells launched and completed through the tracked composition, and T10 published verified
degraded accounting. T11-T14 can report that degraded state, but doing so would not qualify the
intended assessed-control happy path, so no successful assessment publication is claimed here.

## Retained executable evidence

`appsec-review-process/tests/test_owasp_chain_qualification.py` publishes the four-component map
through the common worker-result helper, runs the real T03/routing/T04/T05/T06 workers, and asserts
that the tracked composition launches every expected T10 cell, T07 refuses the unsupported
locator-only verdict candidates, and T10 accounts every refusal as not assessed. A mutation test
changes the envelope binding while updating the request's pointer hash and proves T03 still rejects
the common publication.

Run from `appsec-review-process`:

```bash
python -m unittest -v tests.test_owasp_chain_qualification
python -m unittest -v tests.test_owasp_lane_in tests.test_owasp_component_routing
```

## Required next closure

Admit canonical source/configuration evidence at T03 and deterministically assign exact evidence
roots to components before T05. The routing must use component path/scope lineage, reject ambiguous
or unassigned evidence, and keep indexes and the component map locator-only. Then rerun this
qualification so validator candidates cite those canonical roots, pass T07, and continue through
T11 join and T14 publication. This is not permission to treat classification intelligence as proof
or to weaken T07 citation validation.
