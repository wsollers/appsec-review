# OWASP standalone-chain qualification

Date: 2026-09-27

Scope: exercise the production contracts from accepted `01-component-characterization` into T03
(`04-owasp-intel-lane-in`), then component routing, T04, and onward through T14 only as far as the
tracked workers permit. The fixture is a Freeciv-like source tree partitioned into server, client,
protocol, and ruleset-loader components. No legacy pointer was synthesized and no test-only
validator registry was substituted.

## Result

The first real blocker is the producer/consumer publication contract at T03. The accepted
component-characterization producer publishes the common
`appsec-review/accepted-worker-result/1.0` pointer. That pointer binds the immutable attempt with
`hashes`, `envelope_path`, and `envelope_sha256`. T03's accepted-output admission still requires a
legacy top-level `artifacts` map and refuses the valid common pointer with:

```text
component-map: accepted pointer does not publish an artifact map
```

This refusal occurs during T03 input validation, before T03 allocates an attempt. Therefore there
is no accepted T03 publication for component routing to consume and no truthful integrated result
for T04-T14 in this chain. The downstream unit qualifications remain useful, but they do not close
this live producer-to-consumer boundary because their T03 fixture uses the legacy pointer shape.

## Retained executable evidence

`appsec-review-process/tests/test_owasp_chain_qualification.py` publishes the four-component map
through the common worker-result helper, submits it to the real T03 worker with the pinned ASVS
5.0.0 L2 snapshot, asserts the exact fail-closed reason, and asserts that neither a T03 attempt nor
a component-routing publication was created.

Run from `appsec-review-process`:

```bash
python -m unittest -v tests.test_owasp_chain_qualification
```

## Required closure

T03 must validate accepted run output through the common pointer/envelope verifier, then bind the
requested artifact to the envelope's artifact records and hashes. Compatibility must preserve the
exact producer attempt, pointer hash, envelope hash, artifact hash, run identity, job identity, and
newest-accepted status. It must not accept an unverified legacy pointer as a fallback. Once that is
implemented, rerun this qualification and continue to the next boundary; based on existing T10
tests, the tracked validator composition's `control_verdict` claim ceiling is expected to be the
next integration question, but it was not reached by this live chain and is not claimed here as the
current blocker.
