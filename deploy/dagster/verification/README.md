# Dagster live verification evidence

`dotnet-capture-live-acceptance.json` is the authoritative bounded .NET/C# fixture report for
Dagster run `34cd763a-8798-4dc7-a27c-34cc6006c9e5` and application run
`2026-10-09-0012`. The verifier required the `dotnet` family and resolved the complete command and
wrapper streams, protected argv, syscall/envp/connect capture, gitleaks artifacts, generated
artifacts, workspace/topology records, CodeQL database/query identities, and normalized observation
shards. The .NET language receipt and both C# CodeQL profiles are zero-gap `SUCCEEDED`; unrelated
application-wide scanner scope gaps remain explicitly recorded.

`wave1-live-acceptance.json` is a concise, non-secret historical acceptance report for Dagster run
`d51d396c-4f0f-4386-a503-859b399f1449` and application run `2026-10-08-0081`. It records 248
successful Dagster steps and detailed receipts for the job publications that the verifier captured
at that time. It contains no target contents, raw scanner output, databases, logs, or secrets.

The report is retained evidence for that exact run and tree, not proof that the current checkout or
live deployment is healthy. Its embedded deployment inventory is also historical. Run
`python deploy/dagster/bin/verify.py` against the live stack, and use `--run-id` plus a new
`--evidence` destination when current acceptance evidence is required.

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
must not be used as evidence for the current topology. Newer historical reports provide broader
coverage, but none replaces live verification of the current tree.

`codeql-cross-language-live-acceptance.json` records the fresh bounded CodeQL acceptance for
exact-tree Dagster run `0958c6ff-907d-43fc-b82a-004243f3a573`, application run
`2026-10-09-0007`, and accepted `attempt_0006`. The report records whole-job reuse after producer
run `e596f2f0-3b47-4263-973e-e0bc0362fe5a`; all seven selected orchestration steps succeeded in
both runs. The report resolves every one of
37 profile shards, records 30 successful database/query scopes and 30 normalized observations,
and retains 26 explicit coverage gaps. It also records checkpoint reuse, exact per-language and
per-profile counts, PHP/WebAssembly non-applicability, the accepted manifest identity, and the
resolving run-owned receipts. Go remains an honest gap because its exact accepted recipes did not
compile source; C# and Rust were excluded at planning by their recorded prerequisites.
