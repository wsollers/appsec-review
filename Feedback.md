# Review Feedback for PR #34 (C01) — design review

Reviewed at head `c295498` against `origin/main` `9e4da0e`. This is a **design** review: does C01
meet its goal, is the design one the next batches can build on, does it obey the contracts, schemas
and conventions. **No P1.** The Deliver and Acceptance clauses of `TODO.md` C01 are met (list under
"Held"); the three P2s below are about what C01 hands to its consumers, and the first consumer
(C02, PR #35) is the evidence. Every finding was checked by the coordinator as well as the reviewer.

## [P2] 1. `PoolContext` duplicates the adapters' runtimes and is already incomplete

`pool_specification.py:119-141` copies five `PersonaRuntime` facts (plus `invoker_id`) and three
`ContainerRuntime` facts, field by field. It does not carry `docker_executable` or `container_user`,
which `verify_container_result` / `load_verified_result` / `to_worker_envelope` have REQUIRED on
`main` since the B13 review (PR #29). `docs/pool-specification.md` ("What C02 and T10 need") says a
terminal state means `verify_container_result` passes "for that instance's ids and request" and does
not mention them.

What that cost the first consumer (`origin/claude/c02-wait-all-rendezvous:pool_rendezvous.py`):
a second carrier `ContainerHostFacts` (`:177-192`) for the two missing fields, and `_binding_errors`
(`:241-270`) with eleven field-by-field equality checks to keep `PoolContext` in agreement with the
two runtimes. One fact now lives in three carriers, and the next required adapter fact will be missed
the same way.

Direction: compose `PoolContext` from records the adapters export (a frozen host-facts record from
B13, the non-launch part of `PersonaRuntime` from B14) instead of re-declaring their fields; add a
test that the context covers every non-launch field of `ContainerRuntime` and `PersonaRuntime`.
PR #35 raises the same point as an open design question — the answer is "yes, fix it in C01".

## [P2] 2. The public API does not give the next consumer what it needs

In `pool_rendezvous.py` (PR #35):

- 14 calls into C01 privates: `ps._real_directory` ×5, `ps._listing` ×4, `ps._identity` ×2,
  `ps._chain` ×2, `ps._read_regular` ×1;
- the attempt root rebuilt by hand (`pool_root.joinpath(*entry["attempt_root"].split("/"))`) and
  `plan.manifest["instances"][i]` paired with `plan.requests[i]` by index;
- `verify_expansion` errors filtered by COPYING two message literals (`pool_rendezvous.py:~744-754`:
  `_ROOTS_LISTING`, `_ROOTS_IDENTITY`, equal to the strings at `pool_specification.py:~736,740`).
  Rewording either message in C01 silently changes what C02 accepts.
- `load_verified_expansion` (`:744-750`) derives the plan a second time, so the plan it returns is
  not the object it verified; `expand_pool` derives twice as well.

Direction: export the path/identity helpers C02 needs; give `ExpansionPlan` a per-instance accessor
returning (manifest entry, request, `attempt_root_path(pool_root)`); give verifier findings stable
codes or exported constants (lesson 4: messages say what is enforced — consumers must not parse
them); have verification return the plan it used.

## [P2] 3. "Every published document survives the redactor unchanged" depends on how a host path is spelled

A tool group's absolute `target_mounts[].host_path` is copied into `specification.json` and
`requests/<id>.json`. A path segment of mixed letters and digits trips V06's high-entropy rule.

```bash
cd appsec-review-process
mkdir -p /tmp/c01plain /tmp/c01r/runs-20260921T101500Z-4f3a9c2e
TMPDIR=/tmp/c01plain python3 -B -m unittest tests.test_pool_specification_cross_slice.RedactionSurvivalTests   # OK
TMPDIR=/tmp/c01r/runs-20260921T101500Z-4f3a9c2e python3 -B -m unittest tests.test_pool_specification_cross_slice.RedactionSurvivalTests   # FAILED (failures=2)
```

The second spelling is the shape of this repo's own run ids, i.e. exactly where real targets will be
mounted from. The suite only ever uses the default temp directory (lesson 12: cross-slice tests must
use producible states). `docs/pool-specification.md:~102` ("no host path … in the derivation") is
also not quite true for tool groups: instance ids derive from a specification that contains the path.

Direction — see Question 1; at minimum document the dependence and add a test with such a path.

## Questions for the owner

1. **Absolute host paths in tool groups.** Persona inputs use a root id + relative path; tool mounts
   carry absolute host paths. A `mount_root_id` + relative path resolved from `context.mount_roots`
   (which becomes a mapping) would make specifications and instance ids portable between hosts and
   removes finding 3. *Recommended.* It changes the specification schema, so it is cheapest now.
2. **Parity capability record.** `TODO.md` lists it under C01's primary paths; the PR defers it
   because "open PR #30 edits those" — #30 merged on 2026-09-21. The proposed
   `persona-tool-pool-dispatch` record still fits `main`'s manifest (gaps are free text, `unit` is a
   level in use, the validator passes), but until it lands `main` says `pool_schema_missing` and
   `TODO.md` says "C01 — BLOCKED(B15)". *Recommended:* fold it into this PR now (as B15 did in
   `9fc4010`), including the `TODO.md` status.
3. **Expired grants.** A decision is evaluated at its own `evaluated_at` (`:~375-377`), so a
   specification with an already-expired grant expands and every instance then fails at launch.
   Documented. Alternative: a trusted `now` in the context. *Recommended:* keep, but C02 must make a
   whole pool of denials obvious.
4. **Zero-count groups are never validated by their adapter.** With `count: 0` an unallowed model,
   the wrong invoker, an unregistered image and a mount of the pool parent are all accepted (state
   `EMPTY`), and `identity_sha256` hashes the template rather than the adapter identity.
   *Recommended:* validate the template anyway — a specification should mean the same thing at
   count 0 and count 1.

## For `main`, not for this PR: a published B13 attempt does not survive the redactor

The PR body's out-of-scope note is CONFIRMED on `origin/main` `9e4da0e` (B13 as merged, with
`observation.json`). The container name `appsec-<32 hex>` matches V06's high-entropy rule:

```python
name = container_execution.container_name(run_id, job_id, attempt_id)   # appsec-2c3cf226…
# a file {"container_name": name} through evidence_redaction.redact_tree(...)
# -> disposition "redacted", value "[REDACTED:high-entropy:1]"
```

On a real run `command.json` (`argv[3]`, `argv[7]`, `argv_prefix[3]`), `container-result.json`
(`.container_name`) and `events.jsonl` come out `redacted`, and the published copy fails
`verify_container_result` ("container-result.json fails its closed schema"). C01 sidesteps the shape
(bare hex ids, name derived not recorded). It needs its own change in B13 or V06 — derive the name at
verification instead of recording it, or exempt that exact shape — before any B13 worker publishes.
The coordinator is raising it separately.

## Held

- **Deliver:** versioned closed schemas covering lane, worker kind, persona/tool identity, count,
  scope, inputs, budget, permissions, timeout, pool and `wait_all`; deterministic unique instance ids;
  private run-owned roots.
- **Acceptance**, each with a test that fails if it breaks: zero/one/many (`CountTests`); duplicates
  (`test_duplicate_personas…`, `test_groups_have_one_spelling…`); mixed kinds (`MixedKindTests`);
  invalid counts/scopes (`CountTests`, `PersonaScopeTests`, `ToolScopeTests`); id collisions
  (`CollisionTests`); cross-instance path access (`CrossInstanceAccessTests`).
- **Schemas:** all four use only the `schema_validate.py` keyword subset, `^…\Z` patterns, closed
  objects, every property required, `$ref` to sibling files only; `schemas/README.md` entry present;
  copied template properties tied to the adapters' schemas by a test; vocabularies tied to
  `resource_pools`, `persona_invocation`, `container_execution`.
- **Layering:** reuses the adapters' own validators and `resource_pools.derive_pool`; only private
  reach is `pi._bytes_sha`; `resource_pools.py` and the hard-boundary files untouched. PR boundary
  statement true: the diff is the 10 C01 files.
- **API:** no optional safety inputs; returned plans deeply immutable; closed state and reason sets.
- **Verifier** (from the first, attacker-style pass, before the owner clarified the review stance):
  every add/delete/link/FIFO/chmod-000 under the pool root caught; 493 single-leaf edits with
  consistent resealing refused; repeated keys, BOM, bool/float/NaN/out-of-range ints, `wait_all`
  variants refused; key-order independent; 709 hostile-marker cases, 0 echoes.
- **Merge-readiness:** the branch already contains `main`; C01 suites 86 OK; whole host suite on the
  merged tree 1256 run with only the 8 known host errors; `validate_design_parity.py` PASS (51 jobs);
  `--check-contracts` PASS; `git diff --check` clean; no containers left.

## Not covered

Windows; a code-server run; races during a crashed expansion; mutation testing.
