# 01 -- Execute the docs/ reorganization (moves only, no deletions)

Goal: move every file classified **keep** in `docs/REORG-2026-09-21.md` §1 into its target bucket,
fix every inbound link, and update the generators so the generated views land in the new place.
Nothing is deleted in this chunk.

## Inputs
- `docs/REORG-2026-09-21.md` §1 (target path per file) and §4 (what breaks).
- `appsec-review-process/validate_design_parity.py`, `phase1.py` (line ~558), `qualify_phase1.py`
  (lines ~26/61/175), `tests/test_design_parity.py`, `tests/test_phase1.py`,
  `tests/test_vendor_prepass_graph.py`.

## Steps
1. `git mv` each keep file to its target path from §1. Two renames: `phase-1-operations.md` ->
   `dagster/operations.md`; `phase-1-job-graph.mmd` -> `design-parity/job-graph.mmd`.
   Leave `decisions/`, `proposals/`, `continuation-prompts/` and `agent-reader.md` where they are.
2. Update the generator output paths and the three tests to the new locations. Run
   `python -B appsec-review-process/validate_design_parity.py` and `python -B appsec-review-process/phase1.py graph`
   so the generated files are regenerated at the new paths, then `pytest appsec-review-process/tests/test_design_parity.py appsec-review-process/tests/test_phase1.py appsec-review-process/tests/test_vendor_prepass_graph.py`.
3. Fix inbound links. Find them with, for each moved basename:
   `git grep -n "<basename>" -- '*.md' '*.mmd' '*.py' '*.json' '*.yaml'`
   Expect hits in `README.md`, `AGENTS.md`, `appsec-review-process/README.md`, `TODO.md`,
   `initiate.md`, `orchestrator/README.md`, `orchestrator/dagster/README.md`, `images/*/README.md`,
   lane `config.md`/`prompt.md` files, `schemas/README.md`, and other docs. Relative links inside
   `docs/` change depth (`../` prefixes) -- check each.
4. Add `docs/README.md`: one paragraph per bucket saying what lives there, plus a changelog line.

## Done when
- `git status` shows only renames and link edits; the three tests pass; every link in the files
  above resolves (spot-check with `git grep -n "docs/" README.md AGENTS.md` and open a sample).
- `docs/REORG-2026-09-21.md` §1 "Target path" column matches `git ls-files docs/`.

## Touches
All of `docs/` (renames), the four generator/test files above, and every file with an inbound link.
Exclusive while running.
