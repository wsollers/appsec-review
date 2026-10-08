# Dagster live verification evidence

`wave1-live-acceptance.json` is the current concise, non-secret acceptance report. It records live
Dagster run `87fffd7b-a14f-4fd5-9cef-97b5b9862a08` and application run `2026-10-08-0023`, all four
accepted job handoffs, 94 successful Dagster nodes, 19 producer dispositions and shards, the
combined manifest identity, a peak of six overlapping scanner intervals, and proof that manifest
assembly started after every producer index completed. The correlated rerun reused all 19 producer
shards and truthfully completed with upstream planning gaps. It contains no target contents, raw
scanner output, databases, logs, or secrets.

`live-acceptance.json` is the earlier third-party data-sync acceptance record. It retains the feed
snapshot identities and resolving paths from that bounded historical run.

`failure-propagation.json` records the bounded live failure observed while repairing the first
container integration defect. It proves that an application terminal failure produced a failed
Dagster step and run instead of a false green result. The automated failure fixture remains the
repeatable regression test.

`live-metadata.json` lists the structured metadata keys read back from the successful Dagster run.
Bulk feeds, generated run contents, database files, logs, volumes, and secrets are deliberately not
copied here. Receipt and snapshot paths resolve against the repository's ignored `runs/` and
`data/` state on the accepting host.

`static-analysis-live-acceptance.json` is retained as the pre-concurrency static-analysis baseline.
Its `dispatch_wave1_review` and monolithic `build_indexes` names describe the superseded graph and
must not be used as evidence for the current topology. The current record above replaces it.
