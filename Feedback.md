# Review Feedback for PR #33 (B15, DRAFT)

Reviewed at head `83279f6` (diff vs `claude/b14-persona-invocation-adapter`). Every finding was
reproduced twice against unmodified code (review subagent, then coordinator). The PR is a draft and
its own two unmet clauses (live service qualification; manifest/generated views/TODO after #30)
still stand — they are not repeated as findings. Note also that the base of this stack, PR #29, has
open round-2 feedback.

## [P1] B15 + open PR #30 = red main: 9 errors in `test_vendor_prepass_graph`

The merge is textually clean but semantically broken. #30's
`appsec-review-process/tests/test_vendor_prepass_graph.py` (~`:431-464`) extracts `blocked_op` by AST
and execs it in a hand-built namespace. B15 makes `blocked_op` reference a module global
(`dagster_workflow.py:294`, `tags=NOT_IMPLEMENTED`) that namespace does not supply. Whichever PR
merges second turns main red.

```bash
git worktree add --detach /tmp/wtmerge 83279f6 && cd /tmp/wtmerge
git merge --no-edit origin/claude/v02-declare-vendor-prepass-nodes
cd appsec-review-process && python3 -B -m unittest discover -s tests -p "test_vendor_prepass*.py"
```

Observed: `Ran 15 tests … FAILED (errors=9, skipped=1)`, nine times
`NameError: name 'NOT_IMPLEMENTED' is not defined`. The same module is `OK (skipped=1)` on #30 alone.
On the merged tree `validate_design_parity.py` (51 jobs), `--check-contracts`, the pool suite and the
parity suite still pass — the +4-line parity check does not break #30.

Fix direction: the second PR to merge supplies
`"NOT_IMPLEMENTED": resource_pools.unassigned("worker_not_implemented")` to that namespace and —
the regression — asserts each new stub's declared tags equal it. After #30 the body's counts become
45 stubs / 61 unassigned.

## [P2] `verify_state_file` accepts JSON with repeated keys

`resource_pools.py:497` uses plain `json.loads`; the last repeated key wins. A file whose bytes carry
`"result":"FAIL"`, the overflow error and overlapping `runs`, followed by a PASS copy of the same
keys, verifies: `result=PASS problems=[]`. This is lesson 18, fixed in B14 one PR down the stack —
reuse that `object_pairs_hook` loader. Regression: a duplicated `result` key returns a problem.

## [P2] The non-finite refusal is bypassed by float overflow

`parse_constant` only sees the literals `NaN`/`Infinity`. `1e999` parses to `inf` silently. Two
`memory` steps (limit 1) with `"started": 1e999, "ended": null` contribute zero overlap, so a
document recording a limit violation verifies `PASS`; `_canonical` then emits `Infinity`
(`allow_nan` is not `False`). Fix: reject non-finite `started`/`ended` after parsing, require
`started >= 0`, `allow_nan=False`. The existing test covers only the literal `-Infinity`.

## [P2] Trusted fields of the pool-state document that nothing binds

Each edited ALONE, then resealed consistently (`observed_overlap`, `errors`, `result`,
`state_sha256` re-derived with the module's own functions). All verify `result=PASS problems=[]`:

| edit | note |
|---|---|
| `declaration_sha256` → all zeros | never compared with the module's hash; a document from another limits table verifies |
| `dagster_version` → `0.0.1` | not tied to the pinned 1.13.21 |
| `pools[0].claimed_slots` = 99 (limit 3), = -9; `pending_steps` = -1 | `_state_errors` ignores both; schema has no floor (`schema_validate` has no `minimum`, so check in code) |
| overlapping steps with `pool_id` `"Memory"` or `"unassigned"` | schema allows any `\S{1,200}`; `overlap_by_pool` silently drops undeclared ids. Same steps with `memory` correctly give `FAIL` |
| `assignments` emptied; one (job, op) listed as pooled AND unassigned | neither checked |
| `runs: []` | `PASS` with no contention evidence at all, yet doc step 11 treats "result PASS" as qualification evidence (`state` without `--run-id` produces exactly this) |

What IS sound: limits, pool order, default limit, slot-release seconds and outer limits are checked
against the code table, not the document; bool/float limits, an extra pool row and negative observed
limits are rejected; only fixed strings are returned (nothing echoed).

Fix direction: enum the step `pool_id` (pool ids + `unassigned`) and count/flag per spec; bound the
slot counters and make claimed > limit an error; compare `declaration_sha256` with the current
module or document it as informational; require ≥ 1 run with ≥ 1 pooled step for a qualification
PASS (or drop the wording); reject a duplicated (job, op). The host suite has no `verify_state_file`
test at all — the verifier is exercised only inside one Dagster-only test
(`test_resource_pools_dagster.py:~249-309`) — so add host-runnable tamper tests (every field, one at
a time, consistent reseal).

## [P2] Doc claim not backed by a test

`docs/resource-pools.md` says a test ties the tables on the page to the module.
`Documentation.test_doc_table_is_the_declaration` covers the pools table, budget classes, precedence
line and permission-kind rows, but never reads the "Worker kind | Pool" table. (Found by reading.)

## Probes that held

- `derive_pool`: 4096 cases (every worker kind × every subset of permission kinds × `memory_heavy`,
  list/tuple/set/duplicated) against an independent oracle of the documented precedence — zero
  mismatches; matches permission-capabilities follow-up 8; unknown/case/whitespace/bytes/unhashable
  inputs raise. `persona_slot_request` = 1/2/3 per ADR-0008 Decision 6; unknown class, `True`, or a
  class above the pool limit raise (no deadlock).
- `require_explicit_assignments` under Dagster 1.13.21 (isolated throwaway container, torn down):
  silent op caught inside graph-in-graph, asset jobs, sensor-only and schedule-only jobs; unknown
  pool, pool + unassigned, bad reason, reason without state all caught; legacy
  `dagster/concurrency_key` is not a bypass.
- Guard sensor: idempotent (6 corrected, then 0); never raises a limit above the table; a foreign
  pool fails the tick visibly and is not deleted; no network call.
- `dagster.yaml` loads in 1.13.21 (default 1, free-slots 120). Three unpooled ops under
  `max_concurrent=3` reached overlap 3 with no pool rows — the PR's claim is true.
- Counts verified: 23 pooled (cpu 16, docker 2, memory 2, network 3); 52 unassigned (36/13/3).
- Tests: pool suites 42 OK in the container, 24 OK + 1 skipped on the host; parity 23 OK.

## Not covered

Live stack / Postgres / run-queue behaviour; the `concurrency.pools` config-conflict claim;
`_run_record` with retried steps (`started` overwritten on retry, `STEP_UP_FOR_RETRY` unhandled —
suspicion only); whole 1067-test suite not rerun.
