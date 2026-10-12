---
id: business_logic_abuse
version: 1
covers: ["cwe:472", "cwe:602", "cwe:642", "cwe:799", "cwe:837", "cwe:840", "cwe:841", "cwe:1284"]
standards: ["cwe", "capec", "asvs5", "api-top10-2023"]
max_tokens: 1500
---
## Viewpoint
A fraud analyst. Every individual request is valid and authorized; the abuse is in the sequence,
the quantity, the timing, or the assumption the developer made about what a reasonable user does.
The question is which business invariant (money conserved, one coupon per user, steps in order)
the server actually enforces.

## Coverage
GENERATED

## Likely failure modes
- Client-side enforcement only: price, discount, quantity, or eligibility computed in the browser
  or app and accepted by the server; hidden form fields or signed-looking but unverified state.
- Negative, zero, fractional, or huge quantities and amounts (`qty=-1` refunds, `amount=1e309`,
  integer wrap in totals, rounding exploited across currency conversions).
- Workflow bypass: calling the final step (`/checkout/place-order`, `POST /kyc/complete`) without
  the earlier steps; reusing a step token; going backwards after payment.
- Races on single-use resources: coupon redemption, gift-card balance, withdrawal, invitation
  acceptance, or vote implemented as read-check-write without a transaction or unique constraint.
- Missing rate or volume limits on costly or enumerable operations: OTP sends, password resets,
  sign-ups, bulk exports, SMS or email triggers, LLM or compute-heavy endpoints.
- Trust in externally controlled state: role or plan stored in a client cookie, order status from a
  payment callback without verifying the provider signature and amount.
- Idempotency keys absent on payment or transfer endpoints that clients retry.

## Effective controls
- Server-side recomputation of every price, total, and eligibility from authoritative data.
- Range and sign validation on amounts with decimal types, not floats.
- An explicit server-side state machine that rejects out-of-order transitions.
- Atomicity: `SELECT ... FOR UPDATE`, conditional updates (`UPDATE ... WHERE balance >= ?`),
  unique constraints on redemption tables, optimistic version checks, idempotency keys.
- Per-account and per-resource rate limits on expensive or abusable actions.
- Verification of payment-provider callbacks by signature and by matching amount and order.

## False positives
- Client-side validation that is only for user experience when the server repeats it.
- Apparent races where the database constraint or transaction isolation level already prevents
  the second write.
- Unlimited operations that are cheap, idempotent, and expose nothing enumerable.

## Evidence by predicate
- `affected_construct`: the handler or service method that changes balances, orders, quotas, or
  workflow steps.
- `attacker_input_control`: the amount, quantity, step id, coupon, or request timing and
  repetition the user controls.
- `source_to_sink_reachability`: the path from the request to the write that alters the
  business invariant, including asynchronous workers.
- `missing_or_ineffective_guard`: no server recomputation, no state transition check, no lock or
  constraint, or no rate limit on that path.
- `configuration_enables`: feature flags, rate-limit settings, transaction isolation, payment
  provider modes, and plan entitlements.
- `security_impact`: financial loss, free goods or services, quota evasion, mass account creation,
  or messaging abuse charged to the operator.

## Hand-offs
Ownership and tenant checks go to `authorization_access_control`. Brute force against login or
reset goes to `authentication_session`. Integer overflow in native totals goes to
`memory_safety_native`. Resource exhaustion of the process goes to `filesystem_resources`.
