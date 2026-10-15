---
name: docs-sync
description: Repository-agent procedure for rolling the documentation forward over the cumulative code delta since the last reconciled main commit, so README.md, the architecture, operations and design docs, and the container READMEs stay true to the code. Use it after a batch of merged pull requests, or when the delta since docs/docs-sync.json's synced_commit is large.
metadata:
  audience: repository-agent
---

# Rolling the docs forward over the code delta

Pull requests often update the documentation they touch, but not every page that describes the
behavior they change. This procedure reconciles the documentation against everything that reached
`main` since the last reconciliation, in one bounded pass. Root `AGENTS.md` governs. Follow
`.claude/skills/multi-session-coordination/SKILL.md` before starting: another session may already
be running this procedure.

`docs/docs-sync.json` records where the last pass stopped:

```json
{"schema": "appsec-review/docs-sync/1", "synced_commit": "<40-hex main commit>", "synced_at": "<ISO date>"}
```

`synced_commit` is the last `main` commit whose code the documentation was reconciled against.
`tests/test_docs_sync.py` checks only the record's shape and that the commit is in history; it never
fails because `main` has moved on. Noticing staleness is this procedure's job, not CI's.

## When to run

- After a batch of merged pull requests, especially ones that changed behavior, configuration,
  container images, schemas or job topology.
- When `git diff --stat <synced_commit>..origin/main` is large (dozens of files or thousands of
  lines), even if each pull request looked self-documenting.
- Before a release, handoff, or acceptance write-up that quotes the docs.

## Procedure

1. **Find the delta.** `git fetch origin`, read `synced_commit` from `docs/docs-sync.json`, and fix
   the end of the range as the current `origin/main` commit (`git rev-parse origin/main`). Branch
   from that commit.
2. **Survey it.** Over `<synced_commit>..<end>`:
   - `git log --first-parent --oneline` for the merged pull requests;
   - `git log --oneline` for the commits inside them;
   - `git diff --stat` for the files touched.

   Code, configuration (`appsec-review.toml`, `containers/catalog.toml`, `deploy/`), container
   definitions, rules, schemas and tests are all in scope. Tests matter: a changed assertion often
   records a changed contract.
3. **Read the real changes.** Read the diff of every behavior change, not the commit messages. A
   message says what the author intended; only the code says what happens. Note each change in
   observable behavior: names, schemas, bounds, defaults, gap texts, file paths, image bases,
   pins, counts, job order, and anything removed.
4. **Map each change to the docs that describe it.** Search by symbol, path, setting name and gap
   text (`grep -rn`) across:
   - `README.md`;
   - `docs/architecture/*` and `docs/operations/*`;
   - design and implementation records under `docs/reviews/`, where they state current behavior;
   - `containers/README.md`, `containers/TODO.md`, `containers/buildenv/README.md` and each image's
     own `README.md`;
   - `docs/TODO.md` (done items, stale open questions, new remaining work);
   - `docs/agent-reader.md` navigation (new pages or skills, renamed or removed ones).

   Many pages will already be correct because the pull request updated them. Verify them anyway;
   do not assume either way.
5. **Check stated counts and lists** against the code and configuration, not against other docs:
   registered jobs (`runtime/registry.py`, `[jobs.*]` tables), the direct and Dagster job topology
   and run order (`cli.py`, the Dagster adapter), enabled catalog images by kind (tool, base,
   buildenv), build profiles, schema identifiers, and any enumerations the docs repeat.
6. **Correct only what is wrong or missing.** Fix false statements, add behavior the docs omit
   where a reader would otherwise be misled, and remove claims about code that no longer exists.
   Do not rewrite for style, reorganize pages, or restate what a page already says correctly.
   Generated views are regenerated, never hand-edited.
7. **Record the reconciliation.** Set `synced_commit` to the `main` commit you reconciled (the end
   of the range, not your branch head) and `synced_at` to today's date. If `main` moved while you
   worked, either extend the pass to the new commit or leave `synced_commit` at the one you
   actually checked; never claim a commit you did not read.
8. **Verify.** Run `tests/test_documentation.py`, `tests/test_skill_separation.py` and
   `tests/test_docs_sync.py`, plus the suites for any area whose files you touched, with a unique
   `--basetemp=test/tmp/<session>`.
9. **Land it as a pull request.** Merge `origin/main` before pushing; never force-push. The
   description lists each page corrected and what was wrong, the counts verified, and anything the
   code could not settle (left for the owner rather than guessed). Remove your `test/tmp/`
   material afterwards.
