# Continuation prompt — appsec-review (refreshed late 2026-09-20; supersedes every earlier file here)

Paste this whole file as the first message of the next conversation (or reference it with
`@"docs/continuation-prompts/2026-09-21-appsec-review-continuation.md"`). It is self-contained.

---

You are continuing multi-session work in `/media/wsollers/extradrive1/projects/appsec-review`
(GitHub `wsollers/appsec-review`, default branch `main`, git user `BoondockTaints`). You are the
**coordinator**: you launch Fable subagents in isolated worktrees, verify what they return
adversarially, and open the pull requests; the owner reviews and merges (or names PRs for you to
merge). **This Linux host runs the live Dagster stack and the owner wants Linux-first testing** —
every slice is verified inside the code-server before its PR is opened. Your memory directory holds
the standing rules; read `MEMORY.md` first.

**You are not the only session.** Other Claude sessions (same git identity) and Codex work in this
repo concurrently. Do not touch worktrees, branches or PRs you did not create in your own
conversation unless the owner tells you to; say plainly when something was not your work.

## 0. First, establish ground truth — do not trust section 1 blindly

```bash
cd /media/wsollers/extradrive1/projects/appsec-review
git fetch origin --prune && git checkout main && git merge --ff-only origin/main
gh pr list --state all --limit 12 --json number,title,state,isDraft,headRefName
git worktree list
for b in $(gh pr list --state open --json headRefName --jq '.[].headRefName'); do
  echo "$b: $(git ls-tree --name-only origin/$b | grep -i '^feedback' || echo 'no feedback file')"; done
docker compose ls          # which compose.yaml is the live stack running from?
```

(`git pull --ff-only` fails in this checkout with "Cannot fast-forward to multiple branches"; use
`git merge --ff-only origin/main`. The reviewer's file is sometimes lowercase `feedback.md` — the
`grep -i` above covers it; remove the exact name you find.)

Then read: `AGENTS.md`, `docs/agent-reader.md`, `appsec-review-process/TODO.md` ("Independent work
protocol"), `docs/decisions/ADR-0010-vendor-prepass-decomposition.md` (reconciled with the V05
contracts; see its revision notes), `docs/proposals/vendor-prepass/task-series.md`,
the 2026-09-20 Linux host baseline (in git history; its durable facts live in `orchestrator/dagster/README.md`),
`orchestrator/dagster/README.md` ("Native Linux host").

## 1. State when this was written (verify with step 0)

**`main` = `ec7b2d0`. No open PRs.** #1 (Dependabot pip bump) was **closed** by the owner.

**Merged in the 2026-09-20 sessions:** #21 V04 recovery · #23 V05 SBOM-family contracts (+ ADR-0010
and fixtures reconciled) · #24 Codex T09 · #26 Linux host bring-up + baseline · #25 V15
evidence-index metrics (requalified on Linux twice, `metrics_sha256` identical) · #27 the three
baseline defects · #28 consolidated `schemas/README.md` entry (**written by another Claude session**,
reviewed and merged; this coordinator did not verify its content). Earlier: #2–#20, #22.

**Whole unit suite inside the code-server, on `main`: 857 tests, OK (1 skip).** That is the bar; a
slice must not lower it.

**The live stack** (compose project `appsec-review`, UI http://127.0.0.1:3000) runs **from the main
checkout** (`orchestrator/dagster/compose.yaml`), containers as uid/gid 1000. Its ignored
`orchestrator/dagster/.env` holds the Postgres password bound to the `postgres-data` volume (copy
the file between checkouts, never regenerate it) and `APPSEC_NVD_SCHEDULE=stopped` on purpose. An
unrelated `compose-postgres` project also runs on this host; leave it alone.

**Shared ignored data, all in the MAIN checkout — do not delete:** `targets/freeciv21` (rev
`0ce1c60acf1140d6c5c5a5cd6bef2507bd072319`, remote `https://github.com/longturn/freeciv21`),
`data/feeds/nvd/` snapshot, and `appsec-review-process/runs/` (21 runs, including the qualification
reports whose sha256 values are recorded in `docs/evidence/evidence-index-metrics.md` and the baseline doc).

**Other sessions' worktrees seen at the time of writing (not this coordinator's — leave alone):**
- `.claude/worktrees/agent-a233808d8c5aa6b62` on **`claude/b13-pinned-container-adapter`** — B13 in
  progress: branch pushed at `99642d4`, plus a local merge of `main` and uncommitted edits
  (`container_execution.py`, its tests, `docs/adapters/pinned-container-adapter.md`, `schemas/README.md`).
  No PR yet. `TODO.md` still marks B13 `BLOCKED(B11)`; the owner evidently started it anyway. B13
  unblocks `qualify_build_execution` and, with V02, the worker tasks V10–V13.
- `.claude/worktrees/schemas-readme` (#28, merged — cleanable by its owner session or on request).
- `~/.codex/worktrees/review-pr-27`, `review-pr-28` — the reviewer's.
- **There is one live stack.** Starting it from a worktree replaces the running one. If another
  session needs it for qualification, coordinate through the owner.

## 2. Decisions the owner has made (do not re-litigate)

- ADR-0008 (threat workbench): Option C, four `wait_all` waves, approval A1, wave 4 budget-gated,
  bare persona IDs, M01 before S02, concurrency probe 1 / standard 2 / deep 3, static only.
- ADR-0010 G1–G10: nine family nodes; SBOM/SCA/license/lifecycle are `02-*` producers; offline; no
  package restore; skip reason `not-applicable-no-matching-inputs`; in-worker mobile probe; separate
  `02-binary-hardening`; static archive-only image inventory; every scanner producer redacts with a
  receipt; `cloc`/`scc` fold into `02-evidence-index` (V15, done).
- SCA matcher M1–M5: pinned syft + Grype over a mirrored vendor DB in `/data`, plus an independent
  OSV snapshot (V16, V17, V18 before V11); purl→CPE table not built; **no DB age limit by default, a
  job-set `max_age` exceeded is `FAILED`**; the workbench gets matches + an aggregated gap summary.
- **`02-license-scan` depends on `02-sbom-inventory`** (PR #23 review, option A).
- The SARIF transform is a deliberately **standalone** registered job, not a graph node;
  `02-repository-partition-discovery` is a hand-off gate and correctly `implemented: false`.
- Linux is the primary test host; Windows is a periodic portability check.
- PR #1 closed: the pip bump was inert (below).

**Undecided — raise, do not decide:**
- V15's metrics live inside `manifest.json` under a new additive `member_schemas` contract key
  (merged that way). The alternative, a required sibling `metrics.json`, needs integrator edits and
  another identity change.
- Freeciv21's bundled code under `dependencies/` is labelled `first-party`: that name is not in
  metrics rules v1's vendored table. Adding it = rules bump = identity change.
- **pip pin is inert.** `requirements.lock.txt` lists `pip==…` only as a constraint; nothing installs
  it, so the image keeps the base image's pip (25.0.1, matching by coincidence). A real upgrade
  needs a Dockerfile step + a build-time version check. The Dockerfile is in every job's fingerprint,
  so batch it with the next stack change. 6 Dependabot alerts remain on `main`.
- A01 (see §5). `nvd_feed.py` has no authenticity anchor. `schemas/README.md`'s "stale-but-valid NVD
  is a gap" vs M4. V03's `header-mismatch` errors still quote document values.

## 3. How work is done here — follow this exactly

### 3a. Launching subagents
Agent tool, `model: "fable"`, `isolation: "worktree"`, background; independent tasks in ONE message.
Self-contained prompt: setup (`git fetch origin && git checkout -b claude/<task> origin/main`),
read-first list, task text **verbatim**, explicit allowed paths, hard boundaries, design
requirements, the lessons in §4, acceptance commands, a "report back" spec. Subagents commit and
`git push -u`; they never open PRs, merge, or touch `main`. Colliding tasks must NOT touch
`schemas/README.md`; they return the paragraph. **Never edit shared surfaces from a task branch**
(`job-graph.json`, `design-parity-manifest.json`, `worker-result-contract.json`,
`dagster_workflow.py`, `launch_job.py`, `orchestrator/dagster/*`, `schema_validate.py`,
`validate_job_output.py`, `worker_result.py`, `publish_job_output.py`, generated parity views,
`TODO.md`, accepted ADRs and `docs/proposals/` fixtures) unless the owner explicitly assigns an
integrator task (as for #26, #27 and the #23 ADR reconciliation). Tell the owner before starting
anything that changes a QUALIFIED worker's identity. Decision batches: put gates to the owner with
AskUserQuestion (max 4, recommended first), never choose for them; when recording an answer, update
EVERY authoritative document in the same change — ADR decision table AND the tables further down
the same ADR, every fixture under `docs/proposals/`, the task series, contract records, code — and
add a test that ties them together. #20 and #23 were both rejected for leaving two sources of truth.

### 3b. Verifying a subagent's work — adversarially, and in the code-server
1. `git diff --name-status origin/main...HEAD` — boundary.
2. Merge current `origin/main` into the branch; re-run every acceptance command on the host:
   focused tests, `python3 -B -m py_compile`, `test_design_parity` + `test_worker_result_runtime`,
   `validate_design_parity.py`, `qualify_phase1.py --check-contracts`, `git diff --check`.
3. **Run the focused suites — and the whole suite if a shared module changed — inside the
   code-server**, with the stack started from that branch's worktree (copy `.env`, symlink
   `targets`, then move the stack back to the main checkout afterwards):
   `docker compose -f orchestrator/dagster/compose.yaml exec -T -e PHASE1_TEST_DATA=/tmp/p1 -w /opt code-server sh -c 'mkdir -p /tmp/p1 && python -B -m unittest discover -s /opt/process/tests -p "test_*.py"'`
   Container layout: `/opt/process`, `/opt/schemas`, `/opt/docs`, `/opt/data/reference`.
   If the slice changes a QUALIFIED worker, rerun its `qualify_*.py` and record report path + sha256.
   Host-only note: the host has no `libfuzzy`/`dagster`; `test_evidence_store` and `test_dagster`
   only run in the container.
4. Write your OWN probes (scratchpad only, never the repo). Probe the hard layer: **resealed
   mutations** from a dishonest producer who seals correctly; tamper every file after sealing; each
   trusted field alone; the wrong party; path aliases; documents from another slice; nothing planted
   echoed. Treat every PUBLISHED file as a claim surface, including third-party formats. Check a
   probe is not a no-op before calling its result a hole.
5. Fix findings on the same branch in a separate commit saying what was found and why the suite
   missed it; if a "finding" is correct behaviour, say so. Test your own fixes.

### 3c. Opening the PR
`gh pr create --base main`. Body: what it is / is not, boundary, design points, what YOUR
verification found, stated limitations, integrator follow-ups, validation — and exactly where it ran
("Linux host and Linux code-server; not Windows"). Open as **draft** when an acceptance clause is
unmet, and say which. End with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`;
commits end with the session's `Co-Authored-By:` line. `gh pr edit` fails on this repo — use
`gh api -X PATCH repos/wsollers/appsec-review/pulls/<n> -f title=... -F body=@file`.

### 3d. The review loop
The reviewer pushes `Feedback.md` (or `feedback.md`) to the PR branch with `[P1]`/`[P2]` findings,
not GitHub comments; a clean verdict is the same file saying "No objections". On "check for
feedback": fetch, `git show origin/<branch>:<file>` for every open branch; say plainly if none. The
owner may also just say a PR "has been reviewed" — check its state, it may already be merged.
Reproduce each finding before giving an opinion; wait for "fix"; confirm the PR is OPEN;
`git pull --ff-only` the branch; fix + regression tests incl. the reviewer's exact case; `git rm`
the feedback file in the fix commit (a verdict file too, before any merge); push; comment on the
PR. Check sibling PRs for the same defect.

### 3e. Git, merge, worktree and stack hygiene
- Never silence a push; verify `local == remote` SHA. Chain with `&&`, never `;`.
- **Before pushing to a PR branch confirm the PR is OPEN**: a push to a merged branch succeeds and
  orphans the commit (#21 existed only for that).
- **Merging:** only PRs the owner names explicitly: `gh pr merge <n> --merge --match-head-commit
  <sha>`. GitHub may answer "not mergeable" for ~30 s after a push — poll `mergeable`. Afterwards
  `git merge-base --is-ancestor <sha> origin/main`. Never enable auto-merge. Never force-push a
  shared branch; never rewrite history to hide a file.
- Before removing a worktree: its PR merged, porcelain empty, `git rev-list --count
  origin/main..<branch>` is 0, its ignored `appsec-review-process/runs/*` moved to the main checkout,
  the stack not running from it. In worktrees `targets` is an untracked symlink — never
  `git add -A` there; add files by name.
- Never edit files while a `qualify_*.py` runs (they fingerprint the code before and after).
  `qualify_phase1.py` needs a run from `run_process.py --start`; `qualify_build_execution.py
  --run-id` wants the engagement holding an accepted build-discovery branch.
- Before any `compose up`, read `definitions.py` for default-on schedules/sensors.
- `compose.yaml`, `Dockerfile`, `definitions.py`, `dagster.yaml` are in every job's runtime
  fingerprint: changing them makes all accepted pointers non-current. Batch such changes.
- Downloads, system packages and sudo are the owner's: ask, state what and from where.

## 4. Lessons to paste into every subagent prompt (each was a real P1/P2 or probe finding)

1. **No optional safety inputs.** Anything that decides safety is a required argument with no
   permissive default; test that omitting each is a `TypeError`.
2. **Every trusted field is bound** to what it is derived from (another field, a file's bytes,
   another document, or a caller-supplied fact). For each, a test edits ONLY that field and proves
   rejection.
3. **A returned or persisted record is a cache, never an authority.** Consumers re-derive from
   bytes; returned structures must not be mutable so as to drift from what was verified.
4. **Test the wrong party and the wrong state**, not just the happy path; every error message says
   exactly what the code enforces.
5. **State invariants as tests** — two projections of one dataset always agree; "every file of the
   attempt tampered one at a time in every top-level position is rejected and nothing is echoed".
6. **Goldens are producible, internally consistent states**, cross-checked against the ADR fixtures.
7. **Paths: one spelling per file.** Reject `.`, `..`, empty and leading-slash segments (reuse
   `tool_instance_shapes.output_path_errors`); decide identity by device+inode, not the string.
8. **Order is a safety property.** Verify the redaction receipt against the published bytes BEFORE
   parsing any published document; if it fails, parse nothing and return only the receipt's errors.
   Never echo a value read from an attempt — quote only what the caller expected.
9. **Every required file is actually validated**: `status.json` = exactly the registered fields plus
   the closed set of runtime identifiers, each BOUND (`run_id`, `attempt_id`; `dagster_run_id` to a
   required `expected_dagster_run_id`; `job_id` to the contract's job id); `manifest.json` =
   `{schema: appsec-review/attempt-manifest/1, contract_id, outputs[{path, sha256}]}` naming exactly
   the files under `outputs/`.
10. **Windows portability.** Probe symlink/hardlink capability once and skip only that case (a POSIX
    host must never skip). Tracked text fixtures must not depend on Git newline conversion. Generate
    binary inputs at test time. pathlib, explicit `encoding="utf-8"`, no shell.
11. **No scannable secret literal in the repo.** Build secret-shaped values at run time; self-scan test.
12. **Cross-slice:** a module on the publication path is tested with documents from other slices;
    run the V06 redactor over every golden and prove it changes nothing. In JSON the redactor redacts
    the VALUE under any secret-ish key name, so never name a published property `secret_kind`,
    `token_count`, `authorization`, etc.
13. **Conventions:** `schema_validate.py` supports only `type`, `required`, `properties`,
    `additionalProperties`, `enum`, `const`, `pattern`, `items`, `minItems`, `$ref` to a SIBLING FILE
    (no `$defs`/`oneOf`/`minimum`); end patterns with `\Z`; every object closed and every declared
    property required (nullable where optional); dynamic-key maps become sorted arrays of records; no
    third-party dependencies; nothing new under `scripts/`.
14. **Every published file is a claim surface**, including third-party formats: allow-list its
    sections and run the forbidden-claim check over it (CycloneDX `vulnerabilities[].analysis` got
    past V05's suite). Free-text-capable fields (e.g. licence expressions) get a grammar/shape check,
    not just a character class.
15. **Locate files the way the worker does** (`schema_validate.SCHEMAS_DIR`, the module's `ROOT`),
    never via `<repo>/appsec-review-process`: the suite must import and pass in the code-server
    layout (`/opt/process`). A repository-path identifier inside a request resolves with
    `owasp_batching.tracked_file` semantics, and a helper must honour a caller's relocated roots.
16. **When the task text and the ADR/fixtures disagree, stop and report it** — do not pick one and
    list the conflict as a follow-up. The coordinator must not add design requirements that the task
    text and ADR do not contain without checking the graph first.

## 5. What to do next

**Immediately:** step 0. There was nothing open and nothing owed when this was written.

**Nothing independent is launchable without an owner decision.** The contract/schema layer of the
vendor-prepass series is complete (V01, V03–V07, V09, V15 done); everything else needs shared
surfaces or blocked prerequisites. Lead with this and propose a concrete, small integrator scope —
the owner has assigned such work readily when asked (#26, #27):

1. **V02 + validator dispatch (recommended).** Declare the nine nodes, the new skip reason and the
   license→SBOM edge in `job-graph.json` / parity manifest / `worker-result-contract.json` /
   generated views; add `CLAIM_CLASS_POLICIES` + dispatch in `validate_job_output.py` for nine
   contracts (V04 ×2, V07 ×3, V05 ×4; each module exports its policies; V04's and V05's
   `verify_*_attempt` take a required `expected_dagster_run_id`). Unblocks V08 and T03, and with B13
   the four worker tasks V10–V13. Requalify what the graph change touches; whole suite must stay 857+ OK.
2. **Status hygiene (tiny, integrator-only):** task-series lines still say V04/V07 "in review" and
   V05/V15 `READY`; `TODO.md` closures for G01, M01, F01/V15 and M01 into S02's blockers;
   `docs/evidence/evidence-retrieval.md` pointer to `docs/evidence/evidence-index-metrics.md`.
3. **B11 wiring** (11 follow-ups in `docs/adapters/permission-capabilities.md`) → opens B14, B15, V16, V17.
4. **B13** is being worked by another session (§1). When its PR appears and the owner asks, verify
   it like any slice; `qualify_build_execution` is its live acceptance test.

**Blocked, and why:** V08 → V02 · V10–V13 → V02 + B13 · V11 also → V16–V18 · V16/V17 → B11 wiring ·
V14 → V10–V13, M06, and V15 verified on **Windows** · T03 → V02/M01 producers · T04 → B14 ·
T05 (threat) → C01, C02, B15 · T07 → C03 · T08–T10 chain · longest pole **F03** behind F02's ~14
pregather batches. `qualify_tooling` needs `audit-buildenv-*` images built on this host.

**A01 (explain if asked):** `qualify_phase1.py` gate A01 = contracts pass AND code identity stable
AND a run-level `data/acceptance/prompt-vetting.json` whose `prompt_sha256` equals the hash of
`appsec-review-process/phase-1-implementation-prompt.md` with `requirement_blockers: []`. That file
is a line-by-line review record of the implementation prompt against the owner's requirements
(the historical `docs/phase-1-prompt-review.md`, now only in git history; the original is in run `20260919T104300Z-ba7b4c` on the machine
that did the first acceptance). On Linux A02–A16 pass; A01 was **not attempted**: a fresh run has no
such record and the coordinator must not fabricate one. Offer: do the line-by-line review and put it
in front of the owner to approve, then rerun — or the owner accepts A02–A16 as the Linux baseline.

**Nothing has been run on Windows.** Outstanding there: V15's `GOLDEN_SHA256`, the focused suites of
V03–V09/V05/V15, and starting the stack on Docker Desktop with the new compose file (the default
`user: 0:0` is unchanged by construction, but unverified).

## 6. Tone and reporting
Report outcomes faithfully: what was verified and what was not; when you were wrong, say so and say
what check would have caught it. The 2026-09-20 sessions' own errors, for calibration: a fix commit
orphaned by pushing to a merged branch; a no-op probe reported as a hole; an unapproved scheduled
network call after `compose up`; two wrong statements in the baseline doc (since corrected); a
proposed graph node the design doc already ruled out; a coordinator-added requirement that
contradicted the accepted graph. Lead with what the owner needs to decide or do. Do not claim a
push, merge or fix you have not verified against the remote, and do not claim another session's work.
