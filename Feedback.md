## [P1] Require the accepted pointer to publish every admitted artifact

`_accepted_producer()` validates the producer pointer's status and identity and checks that the requested file is beneath the named attempt, but it never verifies that the pointer's `artifacts` map actually publishes that file (`appsec-review-process/owasp_lane_in.py:67-97`). A file that was never part of the accepted producer output can therefore cross the T03 trust boundary as `accepted_run_output`.

This is reproducible with the focused fixture by writing `outputs/unpublished.json` under `jobs/02-evidence-index/whole/attempts/attempt-1/`, changing the `source-index` entry to that path and its real hash, and leaving the accepted pointer unchanged (the fixture pointer has no `artifacts` entry). `owasp_lane_in.admit()` returns `OK`. This permits unvalidated or attacker-planted attempt data to be treated as admitted intelligence and given accepted-producer lineage.

Require the normalized attempt-relative artifact path to appear in the accepted pointer with the same hash (and reject pointers that do not publish an artifact set). Add a regression test proving that an on-disk file beneath an accepted attempt is rejected unless the accepted pointer explicitly lists it.
