# 02 -- Flat-remove the disposed docs

Goal: delete the 24 files in `docs/REORG-2026-09-21.md` §2 outright (`git rm`), after doing the
per-file "Before removing" action listed there. They stay in git history; no archive folder.

## Inputs
- `docs/REORG-2026-09-21.md` §2 -- the list and the per-file prerequisite.
- Chunk 04 must be done first ONLY for `design-review-2026-09-11.md` (its six open items are
  ported there). Everything else can go as soon as 01 is in.

## Steps
1. For each row in §2, perform the "Before removing" action (drop the README entry, redirect the
   link, remove the `initiate.md:63` pointer, replace the eleven `phase-1-acceptance.md` links with
   the one-line acceptance fact, drop `appsec-review-process/README.md` lines 44-45, etc.).
2. Remove the nine continuation-prompt rows from `docs/continuation-prompts/README.md`'s index.
3. `git rm` the 24 files.
4. `git grep -n` each removed basename across `*.md *.py *.json *.yaml`; zero hits allowed except
   historical cites inside ADRs (ADR-0010 lines 36-41 and 39 may keep their cites as history).

## Done when
`git ls-files docs/` contains none of the §2 paths and the grep in step 4 is clean.

## Touches
The 24 files, `README.md`, `appsec-review-process/README.md`, `initiate.md`, `TODO.md`,
`orchestrator/*/README.md`, `docs/continuation-prompts/README.md`, `docs/personas-and-registry/persona-catalog.md`,
`docs/evidence/evidence-index-metrics.md`, `appsec-review-process/registry/README.md`.
