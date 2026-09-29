# Brief N: tool-output cache and per-item memo (branch `caches`) - CLOUD agent
START AFTER brief I is merged (it changes the staleness decision and adds the generic executor).

From TODO "Relaunch tax": multi-vuln spent 41 min re-planning 53 units and 12.6 min re-assembling evidence; freeciv21
spent 60 min in scancode, all after a fingerprint change that did not alter the inputs of the work.
1. Tool-output cache: a pinned-tool run (scancode, syft, grype, semgrep, ...) keyed by image digest + argv + source
   snapshot hash; on a hit reuse the verified B13 result WITH provenance (`reused_from`). Never trust an output hash
   without re-verification; canceled/blocked/tampered attempts are never cached; a TIMEOUT/OOM gap is cached only for
   the same resource limits. Tunable `tool_output_cache` (default on in dev mode, off in prod until the controller flips it).
2. Per-item memo in loops (ADR-0014 item 6): build-plan units, build-resolution units (image + plan commands + trial
   inputs), IR/SAST invocations, keyed by content, reused across attempts and across a fingerprint change that did not
   alter that item's inputs. Also state the unit id in the per-unit build-plan prompt (TODO breakage log: a small model
   anchored on the first unit it read).
3. Cache store location, size cap and pruning under `data/`, git-ignored; docs in `docs/dev-mode-restart.md`.
## You own
New `tool_output_cache.py`, `item_memo.py`, and the narrow call sites in the B13 adapters and per-unit loops.
## Do not touch
`execution_state.py` decision logic (brief I), persona files, `claim_ledger.py`.
## Acceptance
Hit/miss/invalidate tests including tampered and timeout cases; prod default unchanged; baseline failures unchanged.
