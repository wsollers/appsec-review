# Feedback

## [P1] A persisted decision's expiry can be extended without invalidating the decision

`validate_decision()` validates the capability fingerprint but does not relate `valid_until` to `grants_applied` (`appsec-review-process/permission_capabilities.py:575-588`). `require_granted()` then trusts that unbound field as the expiry gate (`:602-604`).

Using the golden fixtures, I evaluated a valid grant expiring on `2026-09-26`, changed only `decision["valid_until"]` to `2099-01-01T00:00:00Z`, and observed:

```text
validation_errors= []
gate_count= 7
```

The modified decision was accepted for new work in 2027, after every applied grant had expired. This defeats the intended pre-work expiry check on any persisted decision that is corrupted or modified independently of the original grants.

At minimum, cross-field validation should require `valid_until` to equal the earliest `grants_applied[].expires_at`, require non-empty applied grants for a non-empty `GRANTED` capability set, validate the timestamps as real UTC instants, and reject inconsistent records. The persisted-decision boundary should also ensure these authorization fields are covered by a trusted artifact hash or revalidated from the hashed grant inputs; the capability-only fingerprint intentionally cannot provide that integrity.

## Validation

- Focused suite: `36 passed, 139 subtests passed`
- Full suite could not be collected in this host environment because `PHASE1_TEST_DATA` and the `dagster` package are absent; those collection failures are unrelated to this PR.
