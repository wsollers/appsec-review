## [P1] Derive OK_WITH_GAPS from the validated assessment outcomes

The publication status depends only on the validator terminal state and the top-level `evidence_gaps` array (`appsec-review-process/owasp_validator_result.py:713`). The validator does not require nested proof-obligation gaps or unresolved outcomes to be aggregated there, so a candidate with an obligation outcome and fragment status of `cannot_verify`, an explicit obligation-level evidence gap, and an empty top-level array is accepted and published as `OK`.

With the upstream prompt hash normalized to isolate T07, changing the focused fixture's first obligation to `cannot_verify`, clearing its evidence citations, adding `Required canonical evidence is unavailable.` to that obligation's `evidence_gaps`, and setting the fragment status/final status to `cannot_verify` produces `{'published_status': 'OK'}`. Downstream consumers can therefore mistake an incomplete assessment for a gap-free result.

Either require the top-level gap/unresolved arrays to be an exact aggregation of nested state or derive the accepted status directly from fragment outcomes, contradictions, unresolved conditions, and obligation-level gaps. Add a regression asserting that this candidate publishes `OK_WITH_GAPS`, never `OK`.
