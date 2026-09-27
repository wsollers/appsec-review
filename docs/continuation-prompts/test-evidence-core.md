# E09-E10-core — nominal test execution, results and coverage

Work from current `main` in an isolated worktree. Read `AGENTS.md`, the Independent work protocol,
E09-E10, accepted native-build contracts and target-execution permission guidance before editing.

Own only new test-execution, test-result-ingest and test-coverage-ingest workers, their dedicated
schemas/contracts/registry records, fixtures and focused tests. Do not edit shared graph/parity,
Dagster/launcher/runtime, TODO/docs/catalogs or E03-E08 files.

Implement the nominal path from exact accepted native-build/source/binary identity and an explicit
target-execution grant to one bounded declared test plan, then normalized per-test results and
source-linked coverage. Record exact argv, environment, timeout and network/credential/mutation
decisions; bind raw result/coverage hashes and prohibit flaky retries. Passing, failing, skipped and
unsupported results are evidence, not findings; missing/partial/unsupported coverage remains an
explicit gap. Cover deterministic happy-path output and malformed/stale/mismatched inputs. Do not
spend this lane on recovery/cancel/live hardening.

Commit but do not merge. Report tests, limitations, branch/commit and exact shared integration needs.
