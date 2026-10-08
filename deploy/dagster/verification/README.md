# Dagster live verification evidence

`live-acceptance.json` is the concise, non-secret report produced by
`deploy/dagster/bin/verify.py` after a fresh manual launch through the live Dagster instance. It
records the two run identities, all 12 application unit statuses and resolving receipt paths, the
four published snapshot identities, the live job, console health, and the enabled schedule resolved
from `appsec-review.toml`.

`failure-propagation.json` records the bounded live failure observed while repairing the first
container integration defect. It proves that an application terminal failure produced a failed
Dagster step and run instead of a false green result. The automated failure fixture remains the
repeatable regression test.

`live-metadata.json` lists the structured metadata keys read back from the successful Dagster run.
Bulk feeds, generated run contents, database files, logs, volumes, and secrets are deliberately not
copied here. Receipt and snapshot paths resolve against the repository's ignored `runs/` and
`data/` state on the accepting host.

`wave1-live-acceptance.json` records the successful manual `wave1_review` launch, its Dagster and
application run identities, both accepted handoff hashes, every Wave 1 unit state, gaps, and
resolving receipt paths. It contains no target contents, bulk indexes, logs, secrets, or database
state.
