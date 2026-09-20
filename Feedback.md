# Feedback

## [P1] Response authorization is bypassed when the authorship map is omitted

`IntercomTranscript.append()` turns a missing `model_record_authors` argument into an empty map (`appsec-review-process/threat_workbench_intercom.py:154`). The response check then treats every challenged model record as having unknown ownership (`:232-236`) and accepts the response solely because the challenge named that workcell as its target.

That makes the default API weaker than the ADR/T06 contract that “a response may only be authored by the workcell that authored the challenged record.” A challenge can name a record owned by `architecture-dfd-mapper`, target `stride-enumerator`, and a `stride-enumerator` response is accepted whenever the caller omits the optional map. I reproduced this by changing the golden challenge subject to `flow-login` and calling `append(response)` without `model_record_authors`; `ic-0004` was stored.

Make authoritative model-record ownership mandatory for challenges/responses (or persist it in the transcript/manifest and resolve it internally), and fail closed when any challenged subject has no known owner. Add a test for the omitted-map and mis-targeted-challenge case.

## [P1] An open record can resolve itself (or be resolved from the future) and disappear from the sweep

`sweep()` records every non-null `resolution.resolving_record_id` without checking that the resolver is a distinct, later record (`appsec-review-process/threat_workbench_intercom.py:276-278`). Consequently an open record with `resolving_record_id` equal to its own ID produces an empty `unresolved` set. A record can likewise point at an ID that has not appeared yet and suppress it once it is added.

This violates both the function contract (“no later record resolves”) and T06 acceptance (“every open record appears exactly once in the unresolved set”). Only a distinct record later in the append sequence should resolve an earlier record; reject self/forward references or ignore them during the sweep, and add mutation tests for both cases.

## Validation

- Focused suite: `25 passed`
- Full suite could not be collected in this host environment because `PHASE1_TEST_DATA` and the `dagster` package are absent; those collection failures are unrelated to this PR.
