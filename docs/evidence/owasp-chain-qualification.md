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

The four components are all retained. No target is converted to technical not-applicable. Server
targets are assigned under the approved ASVS L2 server scope; unresolved client/runtime
classification remains `cannot_determine` and rescope-visible.

## First remaining blocker

T10 verifies the real T06 publication and then refuses the untouched tracked persona composition
with code `registry_refused`:

```text
the registered composition cannot run a validator cell inside the handoff's claim boundary
```

The only tracked composition naming `owasp-validator` uses the OWASP worklist-builder tooling
profile, whose claim ceiling does not permit the `control_verdict` claim class required by the T10
dispatch configuration. The test-only registry mutation used by T10 unit tests was intentionally
not used here. Consequently no validator cells were launched and T07/T11-T14 were not claimed as
integrated live results. T08/T09 are optional message/request processes rather than a bypass for
this dispatch boundary.

## Retained executable evidence

`appsec-review-process/tests/test_owasp_chain_qualification.py` publishes the four-component map
through the common worker-result helper, runs the real T03/routing/T04/T05/T06 workers, and asserts
the exact T10 fail-closed code and message. A mutation test changes the envelope binding while
updating the request's pointer hash and proves T03 still rejects the common publication.

Run from `appsec-review-process`:

```bash
python -m unittest -v tests.test_owasp_chain_qualification
python -m unittest -v tests.test_owasp_lane_in tests.test_owasp_component_routing
```

## Required next closure

Register a production OWASP validator composition whose role and tooling profile permit the
required bounded `control_verdict` claim while preserving every prohibition in the T06 handoff.
Then rerun this qualification with a real integrator-supplied `PersonaInvoker`, allow T10 to submit
the resulting candidates through T07, and continue into T11 join and T14 publication. This is a
registry/persona integration task, not permission to weaken T10's claim-ceiling check.
