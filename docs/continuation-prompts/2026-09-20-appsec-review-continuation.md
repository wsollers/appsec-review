# Continuation prompt — appsec-review, 2026-09-20

Paste this whole file as the first message of the next conversation (or reference it with
`@"docs/continuation-prompts/2026-09-20-appsec-review-continuation.md"`).

---

You are continuing multi-session work in `/media/wsollers/extradrive1/projects/appsec-review`
(GitHub `wsollers/appsec-review`, default branch `main`, git user `BoondockTaints`). You are the
**coordinator**: you launch subagents that each work in the background in their own isolated git
worktree and branch, you verify what they return, and you open the pull requests. The repo owner
reviews and merges.

## 0. First, establish ground truth — do not trust this file's state section blindly

State moves between sessions (PRs get merged, feedback gets pushed). Run this before anything else:

```bash
cd /media/wsollers/extradrive1/projects/appsec-review
git fetch origin --prune && git checkout main && git pull --ff-only
gh pr list --state all --limit 25 --json number,title,state,headRefName
git worktree list
for b in $(gh pr list --state open --json headRefName --jq '.[].headRefName'); do
  echo "$b: $(git ls-tree --name-only origin/$b | grep -i '^feedback' || echo 'no feedback file')"; done
```

Then read, in order: `AGENTS.md`, `docs/agent-reader.md`, `appsec-review-process/TODO.md`
("Independent work protocol" and the item IDs named below), `docs/decisions/ADR-0008-threat-workbench.md`,
`docs/decisions/ADR-0010-vendor-prepass-decomposition.md`, `docs/proposals/vendor-prepass/task-series.md`,
`docs/proposals/threat-workbench/task-series.md`.

## 1. State as of the end of the last session (verify with step 0)

**Merged to `main`:** #2 B09 SARIF · #3 G01/ADR-0008 (accepted) · #4 T02 threat-workbench schemas ·
#5 T06 intercom bus · #6 B11 permission-capability model · #7 M01/ADR-0010 (accepted) ·
#8 V09 NVD snapshot binding · #9 V03 tool-instance shapes · #10 V06 redactor · #11 SCA matcher
options (merged WITHOUT the decisions — see #20) · #17 V06 1.1.0 fix · #18 V04 secrets+IaC contracts ·
plus Codex's OWASP workbench #12–#16.

**Open, review fixes already pushed, awaiting the owner:**
- **#19** `claude/v07-container-mobile-binary-contracts` @ `a9ef48f` — V07 contracts. Two P1s fixed
  (receipt verified before anything is parsed; `status.json` validated) plus a `manifest.json` binding.
- **#20** `claude/v05-sca-matcher-decisions` @ `203f213` — records SCA matcher decisions M1–M5 in
  ADR-0010, the task series, `job-nodes.proposal.json`, the threat-workbench producers file, AND
  implements the M4 age policy in `sca_nvd_snapshot.py` (schema `/2`).
- #1 is an unrelated Dependabot bump.

**Local housekeeping owed:** local `main` was behind `origin/main`. Worktrees on disk under
`.claude/worktrees/`: `agent-ab9c8413d03a0a6e4` (#18, merged → remove), `v06-fix` (#17, merged →
remove), `v09-m4` (empty, never used → remove), `agent-a1ff70b29e83f6e1c` (#19, keep until merged),
`v05-decisions` (#20, keep until merged). Before removing any worktree, confirm its PR is merged,
`git status --porcelain` is empty and nothing is unpushed. Also delete leftover `worktree-agent-*`
branches. There is an untracked `Claude outputs/b09-sarif-common-runtime.patch`; leave it.

## 2. Decisions the owner has made (do not re-litigate)

- **ADR-0008 (threat workbench):** Option C, fan-out of concurrent personas exchanging typed
  artifacts in four `wait_all` waves; approval A1 (mechanical); wave 4 ships budget-gated; bare
  persona IDs; M01 must land before S02; concurrency probe 1 / standard 2 / deep 3; static only.
- **ADR-0010 (vendor prepass) G1–G10:** nine family nodes; SBOM/SCA/license/lifecycle are `02-*`
  producers; offline; no package restore now; new skip reason `not-applicable-no-matching-inputs`;
  in-worker mobile probe (`02-mobile-applicability` NOT adopted); separate `02-binary-hardening`;
  static archive-only image inventory; every scanner producer redacts with a receipt;
  `cloc`/`scc` fold into `02-evidence-index` (task V15).
- **SCA matcher M1–M5:** pinned syft + **Grype** image reading a mirrored Grype vendor DB in `/data`;
  ALSO build an independent OSV snapshot publisher, both before V11 (tasks V16, V17, V18); the
  purl→CPE rule table has no consumer under Grype and is not built; **no database age limit by
  default, a job may set a tighter `max_age`, exceeding it is `FAILED`**; the threat workbench gets
  matches plus an aggregated gap summary.

## 3. How work is done here — follow this exactly

### 3a. Launching subagents
- Use the Agent tool with `model: "fable"` (the owner asked for Fable 5.1), `isolation: "worktree"`,
  background. Launch independent tasks **in one message** so they run concurrently.
- Each prompt must be self-contained: setup (`git fetch origin && git checkout -b claude/<task> origin/main`),
  a read-first list, the task text **verbatim** from the task series, an explicit allowed-paths
  list, hard boundaries, design requirements, the lessons in §4, acceptance commands, and a
  "report back" spec.
- Subagents commit and `git push -u origin <branch>`; they do **not** open PRs, merge, or touch `main`.
- Tasks that could collide on a file (e.g. several appending to `schemas/README.md`) must be told
  NOT to touch it and to return the paragraph in their report; you add one consolidated entry later.
- **Never edit shared surfaces** from a task branch: `appsec-review-process/job-graph.json`,
  `design-parity-manifest.json`, `worker-result-contract.json`, `dagster_workflow.py`, `launch_job.py`,
  `orchestrator/dagster/definitions.py`, `schema_validate.py`, `validate_job_output.py`,
  `worker_result.py`, `publish_job_output.py`, generated parity views, `appsec-review-process/TODO.md`.
  Those are integrator-only; record what they need as follow-ups.
- Decision batches (`HUMAN_GATE`) present options and numbered gates; **do not choose for the owner**.
  Put the gates to the owner with AskUserQuestion (max 4 per call, recommended option first). When
  you record the answers, update EVERY authoritative document in the same change (ADR, task series,
  fixtures, and any merged code the decision contradicts) — a reviewer rejected a PR that recorded a
  decision in one file while three others still said the opposite.

### 3b. Verifying a subagent's work before opening its PR — adversarially
A green suite has hidden real defects in every slice so far. Do all of this yourself:
1. `git diff --name-status origin/main...HEAD` — confirm the file boundary was respected.
2. Re-run every acceptance command. Minimum set: focused tests, `python3 -B -m py_compile`,
   `python3 -B -m unittest appsec-review-process.tests.test_design_parity appsec-review-process.tests.test_worker_result_runtime`,
   `python3 -B appsec-review-process/validate_design_parity.py`,
   `python3 -B appsec-review-process/qualify_phase1.py --check-contracts`, `git diff --check`.
3. Write your OWN probes (scratch scripts go in the session scratchpad, never the repo). Probe the
   **hard layer, not the easy one**: if there is an on-disk verifier, tamper with every file on disk
   *after sealing*; edit each trusted field alone; try the wrong party; try aliases of one path; feed
   the module a document from ANOTHER slice; and check that no planted value is echoed in any error.
4. Fix what you find on the same branch in a separate commit that says what you found and why the
   subagent's tests missed it. If a finding turns out to be correct behaviour, say so rather than "fixing" it.
5. Trial-merge current `origin/main` locally (`git merge --no-commit --no-ff origin/main`, run the
   suites, `git merge --abort`) when `main` has moved.

### 3c. Opening the PR
`gh pr create --base main`. Body: what it is, what it is not, boundary, design points for review,
a section on what YOUR verification found, stated limitations, integrator follow-ups, validation
results, and "Not run on Windows or in the Linux code-server" (true of everything so far). End the
PR body with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`. End commit messages
with the `Co-Authored-By:` line the session's system reminder specifies. `gh pr edit` fails on this
repo (Projects-classic GraphQL error) — use `gh api -X PATCH repos/wsollers/appsec-review/pulls/<n> -f title=...`.

### 3d. The review loop
The owner's reviewer pushes a commit to the PR branch adding **`Feedback.md` at the repo root**
(findings tagged `[P1]`/`[P2]`), not GitHub review comments. When the owner says "check for
feedback": fetch, `git show origin/<branch>:Feedback.md` for every open PR branch. If nothing is
there, say so plainly — do not guess. Then:
1. **Reproduce each finding before giving an opinion.** Give an honest opinion (they have all been valid so far).
2. Wait for the owner to say "fix". Then `git pull --ff-only` the branch first (the reviewer's commit is on it).
3. Fix, add regression tests including the reviewer's exact case, re-run the reviewer's checks.
4. `git rm Feedback.md` in the fix commit, push, comment on the PR describing the fix.
5. When one PR gets a finding, **check sibling PRs for the same defect** and fix them proactively.

### 3e. Git hygiene — two mistakes already made, do not repeat
- **Never silence a push.** `git push ... 2>/dev/null` hid a non-fast-forward rejection, a PR merged
  without its decisions, and a recovery PR was needed. Always push with output visible and then
  verify: `echo local=$(git rev-parse --short HEAD) remote=$(git ls-remote --heads origin <branch> | cut -c1-7)`.
- **Chain with `&&`, not `;`.** `git diff --check; git commit` committed a whitespace error twice.
- Never force-push a shared branch except `--force-with-lease` after a rebase you announced. Never
  rewrite history to hide a file; remove it with a commit.
- **You cannot merge PRs** — a permission classifier blocks it. The owner merges. Never enable auto-merge.
- Work on shared branches happens inside that branch's worktree; do not `cd` to the repo root from a worktree.

## 4. Lessons to paste into every subagent prompt (each was a real P1/P2 finding)

1. **No optional safety inputs.** Anything that decides safety is a required argument with no
   permissive default; test that omitting each is a `TypeError`.
2. **Every trusted field is bound** to what it is derived from (another field, a file's bytes,
   another document, or a caller-supplied fact). For each, a test edits ONLY that field and proves rejection.
3. **A returned or persisted record is a cache, never an authority.** Consumers re-derive from
   bytes; returned structures must not be mutable in a way that lets them drift from what was verified.
4. **Test the wrong party and the wrong state**, not just the happy path; every error message must
   say exactly what the code enforces.
5. **State invariants as tests** — two projections of one dataset always agree; "every file of the
   attempt tampered one at a time in every top-level position is rejected and nothing is echoed".
6. **Goldens are producible, internally consistent states**, cross-checked against the ADR fixtures.
7. **Paths: one spelling per file.** Reject `.`, `..`, empty and leading-slash segments (reuse
   `tool_instance_shapes.output_path_errors`); decide identity by device+inode, not the string.
8. **Order is a safety property.** Verify the redaction receipt against the published bytes BEFORE
   parsing any published document; if it fails, parse nothing and return only the receipt's errors.
   Never echo a value read from an attempt — quote only what the caller expected.
9. **Every required file is actually validated**: `status.json` = exactly the registered fields,
   each bound; `manifest.json` = `{schema: appsec-review/attempt-manifest/1, contract_id,
   outputs[{path, sha256}]}` naming exactly the files under `outputs/`.
10. **Windows portability.** Probe symlink/hardlink capability once and skip only that case (a POSIX
    host must never skip). Tracked text fixtures must not depend on Git newline conversion — parse
    JSON or normalize newlines in the loader. Generate binary inputs at test time. pathlib, explicit
    `encoding="utf-8"`, no shell.
11. **No scannable secret literal in the repo.** Build secret-shaped test values at run time; add a self-scan test.
12. **Cross-slice:** a module on the publication path must be tested with documents from other
   slices (the redactor once rewrote every V03 document because `source_snapshot_sha256` looked
   high-entropy). In JSON the redactor redacts the VALUE under any secret-ish key name, so never
   name a published property `secret_kind`, `token_count`, `authorization`, etc.
13. **Conventions:** `schema_validate.py` supports only `type`, `required`, `properties`,
    `additionalProperties`, `enum`, `const`, `pattern`, `items`, `minItems`, `$ref` to a SIBLING
    FILE (no `$defs`/`oneOf`/`minimum`); end patterns with `\Z`; every object closed and every
    declared property required (nullable where optional); no third-party dependencies; nothing new under `scripts/`.

## 5. What to do next

**Immediately:** step 0; remove the dead worktrees (§1); check #19 and #20 for `Feedback.md`.

**Ready to launch as background subagents (independent, no shared surfaces):**
- **V05 — SBOM-family contracts** (`sbom-inventory`, `sca-vulnerability-match`, `license-inventory`,
  `dependency-lifecycle`). `READY` now the matcher is decided. Read the V05 section of the task
  series as amended in #20 (database identity per match, `match_basis` enum `purl|cpe`, explicit
  gap records + M5 aggregated summary, CVE/GHSA alias collapsing, stated version scheme). Depends on
  #20 being merged for the authoritative text; if it is not merged yet, branch the subagent from
  `origin/claude/v05-sca-matcher-decisions` or wait.
- **V15 — evidence-index metrics enrichment.** Touches `02-evidence-index`, an implemented and
  QUALIFIED worker: it changes that worker's identity and needs `qualify_evidence_index.py` rerun
  and recorded. Tell the owner before launching; do not start it quietly.
- **After #19 merges:** one consolidated `schemas/README.md` entry for V04 and V07 (both subagents
  returned their paragraph in their reports; V04's and V07's PR bodies contain them).

**Integrator-only (shared surfaces — propose, do not do, unless the owner explicitly assigns it):**
V02 (declare the nine nodes + the new skip reason); `CLAIM_CLASS_POLICIES` and dispatch entries in
`validate_job_output.py` for the five new contracts (V04 ×2, V07 ×3); B11 wiring (11 follow-ups in
`docs/adapters/permission-capabilities.md`); closing G01 and M01 and adding M01 to S02's blockers in `TODO.md`.

**Blocked, and why:** T03 → needs V02/M01 producers · T04 → B14 · T05 → C01, C02, B15 · T07 → C03 ·
T08–T10 chain off those · V10–V13 → V02 + B13 · V11 also → V16, V17, V18 · V16/V17 → B11 wiring ·
the longest pole is **F03** (component characterization) behind F02's ~14 pregather batches.
B13/B14/B15 open once B11 is integrated.

**Known open items to raise with the owner, not to decide yourself:**
- `nvd_feed.py` has no authenticity anchor: anyone who can write `/data` can consistently rewrite
  manifest, id and pointer and make an old snapshot look current. Pinned as a documented limit in V09.
- `schemas/README.md` says the OWASP lane "records stale-but-valid NVD as a gap", which now sits
  awkwardly beside M4 (`FAILED` over a job-set limit). Different consumer; the owner may want them reconciled.
- V03's `validate_node_aggregate` still quotes document values in `header-mismatch` errors. Harmless
  after a receipt check, but it should be sanitized like V04/V07.
- Nothing from these sessions has been run on Windows or in the Linux code-server, which the
  `TODO.md` protocol asks for.
- GitHub reports 6 Dependabot alerts on `main`.

## 6. Tone and reporting
Report outcomes faithfully: say what was verified and what was not; when you were wrong, say so and
say what check would have caught it. Lead with what the owner needs to decide or do. Do not claim
a push, a merge or a fix you have not verified against the remote.
