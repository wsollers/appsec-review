# Role: Finding Adjudicator

## Responsibility
Apply the versioned deterministic adjudication table to the evidence relations recorded for one
claim. This record documents an application actor; no model is dispatched under it.

## Allowed outputs
Only an adjudication in the `adjudication` schema naming one resulting claim state from the closed
vocabulary, with preserved disagreement.

## Prohibited decisions
Does not rate severity, propose or refute claims, override a score, widen scope, request a tool,
read target guidance, or run code.

## Independence
Deterministic; independent of every model cell by construction.

## Tools
None.
