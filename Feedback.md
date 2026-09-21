# Review Feedback for PR #35 (C02) — design review

Reviewed at head `d5fdbeb` (diff vs the C01 branch) against `origin/main` `9e4da0e`. This is a
**design** review: does C02 meet its goal, can C03/C04/T10 build on it, does it obey the contracts,
schemas and conventions. **No P1.** Every clause of `TODO.md` C02 is met and test-backed except one
cancel path (F1); the largest open item is a design decision (Q2). F1 and F2 were reproduced by the
coordinator as well as the reviewer. PR #34 (C01) has its own open feedback; F2, F4 and Q3 share
root causes with it and are best fixed there first.

## Goal mapping (`TODO.md` C02)

| Clause | Status | Where |
|---|---|---|
| bounded non-busy waiter | met | one `threading.Condition` (`pool_rendezvous.py:~594-625`), bounded by min(spec timeout, runtime limit) + drain; `test_the_wait_is_event_driven_not_a_poll` |
| missing workers never an empty success | met | `_entry`; `ZeroOneManyTests`, `test_a_worker_that_returns_success_and_leaves_nothing_on_disk_is_missing…` |
| late finish · failure · timeout | met | `LateFinishTests`, `AdapterOutcomeTests` |
| cancel | met during the wait; **not during the drain** | F1 |
| crash · restart · duplicate terminal · missing instance | met | `RestartTests` (incl. a real SIGKILLed coordinator), `DuplicateTerminalTests`, `MissingInstanceTests` |
| publication never occurs early | met | `PublicationTests` |
| owner requirement 2026-09-21: C02 builds a reviewer's producers and owns chain independence | not addressed, not mentioned | Q1 |

## [P2] F1. An interrupt during the drain publishes nothing — and a later run then adopts the late result

`docs/pool-rendezvous.md:189-190`: "`KeyboardInterrupt` or `SystemExit` in the coordinator is treated
as a cancel and re-raised after publication." The `except (KeyboardInterrupt, SystemExit)` at
`pool_rendezvous.py:~626` covers only the main wait loop. The drain (`:~630-638`, up to 180 s — when
an operator is most likely to press Ctrl-C), `derive_manifest`, `manifest_errors` and `_publish` are
outside it. Observed (interrupt raised in a `Condition.wait` after `ledger.close()`):

```
R2 KeyboardInterrupt re-raised; manifest published? False
R2 a later run_rendezvous publishes: ['succeeded'] COMPLETE
```

So the instance that was LATE in the interrupted rendezvous is adopted as `succeeded` by the next
one — the "a late result is never adopted" property does not survive an interrupt. The doc lists
"deadline forgotten across restarts" as a limitation, but this path is an ordinary Ctrl-C, not a
crash. The suite's interrupt test raises only inside the main wait.

Direction: hold interrupts across the whole post-launch section (wait → close → drain → derive →
publish) and re-raise after `_publish`; or, if that is not wanted, publish a manifest that records the
interruption before re-raising. Regression: raise in a `Condition.wait` after `ledger.close()`; the
manifest must be published with the late instance `rendezvous_timed_out`, and a second
`run_rendezvous` must raise `RendezvousPublishedError`.

## [P2] F2. `verify_manifest` tolerates pool-root changes that `run_rendezvous` refuses

`expansion_errors` (`:~750-754`) drops two C01 findings by matching their MESSAGE TEXT
(`_ROOTS_LISTING`, `_ROOTS_IDENTITY`). The first also fires for an unexpected EXTRA root under
`instances/` and for `instances/` not being a real directory — cases no classification rule covers,
although the doc says the tolerated findings are "left to the classification rule".

```
R1 C01 verify_expansion: ['the instances directory does not hold exactly one private root per expected instance']
R1 C02 verify_manifest with an unexpected extra root in instances/: []
```

Executor and verifier apply different rules (the pattern of B13's round-1 P1), and C02's behaviour
depends on C01's wording. Direction, while #34 is open (its feedback item 2): C01 exports structured
findings or an expected-roots check, and C02 tolerates only a missing / linked / replaced EXPECTED
root. Regression: an extra root is refused by `verify_manifest`.

## [P2] F3. The live suite is not hermetic: 9 of 10 runs passed

Run 4 failed in `tearDown` of
`test_a_pool_cancel_stops_a_running_container_and_the_next_one_is_never_launched`:
`AssertionError: Lists differ: ['127950bbfb77'] != [] : a container was left behind`.
The leftover check (`b13_live.labelled_containers()`) is host-wide, and another session (the #34
reviewer) was running labelled B13 containers at that moment. The alternative — a container created
after B13's removal proof, which would make `container_removed: true` untrue — was probed 65 times
(40 under full CPU load) and did NOT reproduce. Either way a suite that fails when anything else on
the host uses the adapter will bite in CI and on the shared Linux host. Direction: compare against
THIS test's own derived container names (and keep one host-wide check out of the per-test teardown).
The same applies to B13's own live module on `main`.

## [P2] F4. Layering, and what a consumer has to do after `load_verified_manifest`

- 14 calls into C01 privates (`ps._real_directory` ×5, `ps._listing` ×4, `ps._identity` ×2,
  `ps._chain` ×2, `ps._read_regular` ×1) and `pi._bytes_sha` — export them in C01 (#34 feedback 2).
- `load_verified_manifest` runs every adapter verifier, then discards the verified results. C03 must
  re-verify each `succeeded` instance itself with about ten arguments, and must use
  `ps.plan_expansion`, not `ps.load_verified_expansion`, which raises for any pool with a `missing`
  instance — a trap the doc does not mention.

Direction: a public `load_verified_instance_result(...)`, or return the verified results with the
manifest. Try writing C03's first ten lines against the API; that is the test of this item.

## Questions for the owner

**Q1. Chain independence (your decision of 2026-09-21, recorded under C02 in `TODO.md`).** Decided
after this PR opened, so it is a gap to record, not a defect: the PR neither builds a reviewer's
`producers` / `producer_result` inputs nor mentions ancestors; reviewer requests are fixed at C01
expansion and C02 runs one pool. There is a clean place for it — a helper over
`load_verified_manifest` that emits producer pins and walks each result's own `producers` — but the
manifest carries no persona/model identity per instance, so that helper must read result files.
*Recommended:* add a "Not done: producers and chain independence" section to the doc now and track
it as C02b or inside T10.

**Q2. In-process threads vs B15's Dagster pools — decide before T10 builds on `run_rendezvous`.**
The rendezvous op is `unassigned('coordination_only')`, holds no slot, and runs up to 6 instances
itself. That under-counts: two concurrent runs can run 2 containers with `docker` limited to 1, or 6
personas with `persona_llm` limited to 3; `persona_slot_request` is per run in B15 but applied per
pool here; and B15's live-qualified cancellation / slot-release behaviour does not apply to these
instances. The doc is honest about it, but it bypasses what B15 exists to enforce. Options:
(a) accept for T10 with at most one rendezvous at a time, and record that constraint in
`docs/resource-pools.md`; (b) launch instances as dynamically mapped POOLED ops with C02 as the
collector (changes the API shape); (c) a host-wide semaphore keyed by pool id. *Recommended:* (a) now
with the constraint written down and enforced (a run-level tag limit), (b) as the target design.

**Q3. `host_facts` vs `PoolContext`.** A later process (C03) must re-supply `docker_executable` and
`container_user` from somewhere; they are recorded nowhere, and a mismatch rejects the whole pool's
manifest. *Recommended:* add both to `PoolContext` in #34 (its feedback item 1) and drop the argument.

**Q4. State model.** Eleven states (the PR body says eight); closed, total, unambiguous table;
`instances == expansion list` is the right contract. But `invalid` merges four causes (verifier
refused · root not private · evidence nobody launched · OK result whose writer has not stopped) and
`missing` merges three (root gone · adapter left nothing · worker thread could not start), and a
never-launched instance can become `rendezvous_timed_out` with `worker_stopped: false` if an
interrupt lands between `pending.remove` and thread start (`:~609-611`). C03/C04 will want to tell
these apart. *Recommended:* a closed `state_reason` enum now — cheap today, a schema id bump later.

## Docs and PR body vs `main`

- The PR body says the `wait-all-rendezvous` capability record "is in `docs/pool-rendezvous.md`"; the
  doc has one sentence and no record content.
- The doc says PR #30 owns `design-parity-manifest.json`; #30 merged on 2026-09-21. `main`'s manifest
  still lists `waiter_missing` and `terminal_instance_manifest_missing`, and `TODO.md` says
  "C02 — BLOCKED(C01)". Fold the record, the regenerated views and the TODO status into this PR (as
  B15 did in `9fc4010`), with concrete gaps removed, readiness and references.

## Held

Both schemas: supported keyword subset only, closed, every property required, `\Z` patterns, id
convention, README entry; state and cause enums tied to the module's and the adapters' constants by a
test; manifest validated before publication and on read; adapter results read only through
`ce.load_verified_result` / `pi.load_verified_result`; caps from `rp.LIMITS` and
`rp.AGGREGATE_STEP_CEILING`, not a copied table; every safety argument required, returned values
frozen, fixed-text errors; no third-party deps, nothing under `scripts/`, files via `ROOT`; redactor
and cross-slice tests present; per-pool lock is an `flock` on a separate descriptor (excludes a second
coordinator even in one process); PR boundary statement true (9 files, all new but `schemas/README.md`).

Merge-readiness: `origin/main` merges clean into the head; C02 + C01 + B13 + B14 suites 326 OK; whole
host suite 1337 run with only the 8 known host errors; `validate_design_parity.py` PASS (51 jobs);
`--check-contracts` PASS; no containers left.

## Not covered

Windows; a code-server run; ADR-0008's text; mutation testing; which F3 hypothesis is the cause.
