# docs/TODO -- task chunks toward the target documentation architecture

Each file here is one independent, bounded task. Completing all of them turns `docs/` from the
organic tree it grew into (dated status logs, superseded proposals, engagement one-offs mixed with
live specs) into a finite, succinct information base of the current architecture, partitioned by
component, plus a reworked `skills/` tree.

Rules for a chunk:

- One owner at a time. Claim it by adding `Owner:` and a date at the top; remove the file when done
  and record the commit in `docs/README.md`'s changelog line.
- Every chunk lists **Inputs** (what to read first), **Steps**, **Done when**, and **Touches** (the
  files it edits). Two chunks that touch the same file must not run concurrently.
- `docs/REORG-2026-09-21.md` is the accepted classification these chunks execute. Do not
  re-classify a file inside a chunk; if a verdict looks wrong, raise it, do not silently change it.
- A chunk never deletes evidence under `appsec-review-process/runs/` and never edits generated
  views by hand (`design-parity-*.md`, `full-review-workflow.mmd`, `job-graph.mmd`).

Order that avoids conflicts: 01 -> 02 -> (03, 04, 05 in any order) -> (06, 07, 08 in any order)
-> 09 -> 10 -> 11. Chunks 03-08 can run in parallel with each other once 01 and 02 are in.

| Chunk | Status |
|---|---|
| 01-docs-reorg-execute | done 2026-09-21 |
| 02-remove-disposed-docs | done 2026-09-21 |
| 03-design-v3-split-and-adr-0004 | ready |
| 04-port-design-review-open-items | done 2026-09-21 |
| 05-refresh-stale-trackers | ready |
| 06-write-review-lanes-docs | ready |
| 07-write-images-and-tools-docs | ready |
| 08-write-processes-overview | ready |
| 09-skills-rework | blocked on 08 |
| 10-agent-reader-refresh | blocked on 06, 07, 08, 09 |
| 11-docs-index-and-link-check | blocked on 10 |
