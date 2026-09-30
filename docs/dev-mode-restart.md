# Dev-mode restart (operator view)

ADR-0025. Prod fingerprints are the evidence rule: any change to a job's code, contract or upstream
attempt reruns it and everything after it. That is right for a deliverable and wrong while you edit
and rerun. Dev mode decides from **data**. It is for iteration only: **a dev result is never
evidence**.

## Turning it on

| What | How |
|---|---|
| Mode of the Dagster code location (where the work runs) | start it with `APPSEC_RUN_MODE=dev orchestrator/dagster/code-location.sh`. Unset or `prod` is prod; any other value refuses to start work. |
| Mode of a launch | `launch_job.py --mode dev ...` (default: `$APPSEC_RUN_MODE`, else prod). The run is tagged `appsec/run_mode=dev`, and the item executor refuses a run whose tag and process mode disagree. |
| Preview, no submission | `launch_job.py --run-id R --job full_review --mode dev --explain` |
| Rerun one job regardless | `--force <job-id>` (dev, repeatable). Plain `--force` still reruns everything, as before. |

## What dev decides, per job, in graph order

`--explain` prints one line per job: `REUSE` / `RERUN` / `REWIND`, the cause, and what prod would do
on code alone. For example:

```
RERUN  02-operations-doc-ingest: own static_intelligence_core.py changed; prod would have invalidated because code hash of static_intelligence_core.py changed
REUSE  02-evidence-index: early cutoff: 02-operations-doc-ingest reran with byte-identical output
```

1. Each consumed input artifact gets a **content hash** and a **shape hash**. The shape covers the
   JSON keys and value types, where an array's shape is the set of its element shapes. Values, key
   order and array length do not affect it.
2. All input content unchanged since the job's last accepted run: **REUSE**.
3. Some input content changed but every shape is the same: **RERUN**.
4. An input's shape differs from what the job recorded: **REWIND**. The producer of that input reruns
   first (and, since every job is checked, so does any producer whose own input shape changed). Then
   the pass continues forward. `--explain` names the rewind point. Only item producers rewind: a
   legacy producer's prod fingerprint already covers all its code, so its output is never stale.
5. **Early cutoff:** a rerun that publishes byte-identical output leaves every downstream input
   unchanged, so downstream jobs REUSE.
6. A job's own config, contract, schema, prompt and implementation files count as inputs. Shared
   runtime (`SHARED_RUNTIME`) and other jobs' implementation files do not.

## Which jobs follow these rules

Only jobs that run through the generic item executor (`job_executor.py`, `appsec-review-process/items/`).
Every other (legacy) job keeps its own prod fingerprint **in both modes**. Their inputs pin upstream
attempt ids, so they have no early cutoff. `--explain` predicts them from their recorded code hashes
and upstream reruns ("legacy fingerprint: ..."). Porting a job to the executor is what brings it
under the dev rules. Legacy fingerprints were deliberately not changed: any edit to them would
change prod fingerprints.

## Guard rails

- Every executor receipt carries `mode` and `evidence_grade`. A dev receipt is always `mode: "dev"`,
  `evidence_grade: false`.
- A prod run never reuses a dev-published result. It recomputes: the dev and prod fingerprints differ
  by mode, and the executor also refuses a dev receipt.
- `final_publication.publish` refuses a dev process, and refuses any run with an accepted dev result.
  `launch_job.py --mode dev --job final_publication_gate` is refused. After a dev loop, relaunch in
  prod: the dev results are recomputed.
- Dev never relaxes scanning rules. A tool that did not run, or a partial scan, is a gap and never
  "no findings", in either mode.

## Tool-output cache and per-item memo (brief N)

Two content-keyed caches cut the relaunch tax: work re-executed after a fingerprint change that did
not change its inputs (freeciv21: 60 min in scancode; multi-vuln: 41 min re-planning 53 units). Both
store **pointers, not evidence**: a hit is re-verified as strictly as a fresh result, and a hit that
fails is invalidated and redone.

| | Tool-output cache (`tool_output_cache.py`) | Per-item memo (`item_memo.py`) |
|---|---|---|
| What | Pinned B13 tool runs: syft, grype, osv-scanner, scancode (`dependency_b13_adapters.execute`) | Loop items: 02-build-plan units and 02-build-resolution units |
| Key | image digest from the B16 record, argv, environment, limits, network, container paths, B13 boundary hash, host binding, run, job, mode, and sha256 digests of the mounted bytes computed by the adapter (the offline registry's re-hashed snapshot identity for a vulnerability database) | the unit's plan-unit request, its classification and index entries, catalog, per-unit prompt bytes, contract, schema, template, the run's pinned model, source snapshot, run, mode |
| Scope | the same run and job (B13 requests bind the run) | the same run |
| A hit | reuses the earlier B13 attempt only after full independent re-verification (retained result hash, output hash, re-derived receipt, exact offline permission decision); `dependency_workers` re-verifies it again. The new attempt directory gets `tool-output-reuse.json` with `reused_from` | re-reads the earlier persona attempt's result and summary, checks their hashes and the readable target, re-applies the orchestrator fill, `finalize` and the full unit check with citations. `status.json` marks the unit `reused_from: item-memo` and keeps the original persona attempt id |
| Never stored | canceled, blocked, tampered or non-zero-exit attempts; a mounted tree that changed during the run. A TIMEOUT / OOM_KILLED gap is stored and reused only under the same limits (limits are in the key) | a unit whose plan failed today's validation |
| Tunable | `tool_output_cache` | `item_memo` |

Rules shared by both:

- **Target-controlled content is hashed, never trusted.** No key contains a value read out of a tool
  output, a model reply or a target file; the adapter and the memo compute every digest themselves.
  A mount with a link or a special file is not cached (the tool still runs).
- **Mode is part of the key.** Settings are `off`, `dev` (default: on only when
  `APPSEC_RUN_MODE=dev`) and `on` (both modes). Prod stays off until the controller sets `on`, and
  a prod run never reuses an entry a dev run stored.
- **Store:** `data/caches/tool-output/` and `data/caches/item-memo/` at the repository root
  (git-ignored; `APPSEC_CACHE_ROOT` moves it). One small JSON entry per key, pruned oldest-first
  beyond `tool_output_cache_max_entries` / `item_memo_max_entries`; invalidations and prunes are
  logged to `events.jsonl` there. `python3 appsec-review-process/tool_output_cache.py stats|prune|clear`
  (`prune` also drops entries whose attempt directory is gone).

**02-build-resolution units.** Keyed by the unit's plan entry, its sealed base (and fallback)
records, the control's build behaviour (not grant timestamps), intake's content fingerprint of the
checkout, the toolchain, B13 limits and boundary, the trial runner, `cow_install.py` and the host
facts. Only successful units are memoised. A hit reuses the earlier attempt's copy-on-write image,
verified trial and compile database: B13 binds a trial to the path it ran in, so the trial stays in
its owner attempt and the receipt names it (`owner_attempt_id`); the lock's `successful_attempt`
carries `image_reused: true` and `reused_from`. The hit re-checks the image is still present, the
trial request against today's request, the exact two-capability grant it ran under (re-evaluated at
its recorded time), the full B13 result, the trial's commands and the compile-database and install
hashes; `_compile_db` then runs on this attempt's copy and every later validation re-verifies the
trial in its owner attempt. Deleting that owner attempt makes the reusing attempt fail validation.

The per-unit build-plan prompt now names the unit id and root at the top and again at the end (a
small model anchored on the first unit it read). A unit id that is not plain path text is not pasted
into the prompt; the prompt points at `plan-unit.json` instead.
