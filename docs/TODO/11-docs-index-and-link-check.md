# 11 -- docs/README.md index and an automated link check

Goal: make the tree self-describing and stop links from rotting again.

## Inputs
- The final tree after chunks 01-10.
- `appsec-review-process/tests/` conventions (plain `unittest`/`pytest`, dependency-free).

## Steps
1. `docs/README.md`: one line per bucket (what it holds, when to read it), generated-file warning
   for `design-parity/`, the rule that dated status logs go in `continuation-prompts/` or nowhere,
   and a changelog line per reorg chunk.
2. `appsec-review-process/tests/test_docs_links.py`: walk `README.md`, `AGENTS.md`, `docs/**/*.md`,
   `appsec-review-process/**/*.md`, `images/**/README.md`, `skills/**/*.md`; every relative
   markdown link and every backticked repo path that looks like a path (`docs/...`,
   `appsec-review-process/...`, `schemas/...`, `images/...`, `skills/...`) must exist. Allowlist
   the historical cites in ADRs.
3. Delete `docs/REORG-2026-09-21.md` and this folder's completed chunks; record the commit in the
   changelog line.

## Done when
The link test passes on a clean tree and fails when a link is broken (prove it once).

## Touches
`docs/README.md`, `appsec-review-process/tests/test_docs_links.py`, `docs/REORG-2026-09-21.md`, `docs/TODO/`.
