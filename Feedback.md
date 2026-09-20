# Feedback

## [P1] A challenge author can still clear its own open challenge without a response

The new backward-reference and ownership checks resolve the two original findings, but `_check_resolution()` permits the author of an earlier record to resolve it with any status in `RESOLVING_STATUSES` (`appsec-review-process/threat_workbench_intercom.py:287-293`). The error text says the record may be “withdrawn by its author,” but the code also accepts `answered`, `accepted`, and `rejected`.

I replayed the golden transcript through `ic-0003`, then appended a wave-3 `coverage_gap` from `challenge-refutation-cell` with `status: accepted` and `resolves_record_id: ic-0003`. The append succeeded and `sweep()` removed the open challenge from `unresolved`, even though there was no response:

```text
stored ic-hide-challenge
unresolved: [ic-0002, ic-0001]
dissent: ic-0003 unresolved, response_record_id null
```

This creates contradictory join projections and lets the challenger bypass the rule that only the challenged record owner may answer. When the resolver is the earlier record's author rather than its target, require `status == "withdrawn"` (and consider constraining challenge resolution to a valid response/withdrawal record type). Add a test covering an author attempting to resolve its own challenge as `accepted`.

## Validation

- Focused intercom and schema suites: `83 passed`.
- The two original review reproductions are now rejected/handled as intended.
