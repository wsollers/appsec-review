---
name: effective-control-verification
description: Check whether an observed control establishes the exact assigned predicate.
metadata:
  audience: runtime-worker
---

# Effective control verification

Turn the assigned claim or control obligation into a precise condition at the sensitive operation.
Identify the control's implementation, input representation, configured instance, version and
failure behavior. A matching API name or declaration of intent is not an effective control.

Check that the control dominates every relevant path, rejects the dangerous case and protects the
same value, object, principal and tenant used at the operation. Follow aliases and mutations after
the check, including asynchronous work and time-of-check/time-of-use changes. State which bypasses
were covered and which remain unknown.

For a copy, distinguish readable source length from writable destination capacity. Show units,
signedness, overflow-safe arithmetic and the live object's capacity; a frame-size check alone
does not bound a destination field. For authorization, establish object-level enforcement at use.
For configuration, follow override precedence and deployment selection to the effective setting.

Treat false-positive patterns as evidence-conditioned possibilities, not exemptions. Identify the
attack class the control actually addresses; blocking entity fetches does not bound parser memory,
and a type allowlist does not make an inherently unsafe serializer safe.

Report a concise obligation/evidence/consequence/gap summary in the assigned result contract.
For a refutation, distinguish contradiction from qualification and unresolved evidence. Failure
to find a bypass is not proof of safety; failure to find a control is not proof of exploitation.
