# Budget Policy

This process harness cannot hard-limit model billing tokens by itself. Budgets here are operational
contracts that each task must follow and report against.

## Budget Types

- `probe`: smallest useful test; one or two artifacts, a few clusters, short output.
- `standard`: normal lane run over a bounded component or worklist.
- `full`: complete lane run for the current target, still with batching and stop points.

## Default Budgets

| Budget | Max Clusters | Max Components | Max Source Files | Max Output Lines | Stop Rule |
|---|---:|---:|---:|---:|---|
| `probe` | 3 | 3 | 12 | 120 | stop after first useful defect in process/artifacts or after budget exhausted |
| `standard` | 25 | 15 | 80 | 350 | stop and summarize if remaining work is repetitive or needs a new batch |
| `full` | all | all | bounded by lane | 800 | batch large outputs; write continuation points |

## Required Task Behavior

Every lane task must state:

- selected budget
- scope included
- scope excluded
- artifacts read
- work completed
- work intentionally deferred due to budget
- recommended next batch, if any

## Probe Test Plan For EASTL

Before the huge repo, run:

1. `01-component-characterization` with `probe`
2. `05-native-memory` with `probe` on the first 3 deep-confirmed clusters
3. `08-blue-team-refutation` with `probe` against one native-memory claim
4. `09-independent-verification` with `probe` against the same claim
5. `10-synthesis-report` with `probe` using only those outputs

Then run the same sequence with `standard` or `full` on EASTL before moving to the huge repo.

