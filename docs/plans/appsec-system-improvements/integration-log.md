# Fleet integration log

This log records observations and integration receipts, not package-state authority.
The coordinator's SQLite ledger is authoritative; `ledger.json` is its published
snapshot. The approved review is historical analysis of its named source revision,
not evidence that every finding survives the implementation baseline.

## 2026-11-06 - F00 documentation bootstrap

### Scope and ownership

- Coordinator: `02825845-7ac6-4a31-b648-999b3823ecf5`.
- F00 session: `053e6dce-78d3-428d-ac36-f1811056dd67`.
- Assigned branch: `william-sollers-xbox-fleet-integration-and-parity`.
- This session cannot inspect or mutate either canonical main checkout. The
  coordinator narrowed F00 to owned-worktree documentation, candidate preparation,
  verification where permitted, and coordinator-supplied ledger snapshots while
  resolving a separately permitted landing owner. Plan version 1.1 then identified
  landing-only session `969abd85-9a4e-42a5-a323-34843205448e` and narrowed this
  session's assignment to the isolated documentation bootstrap only.
- The user explicitly approved documentation-only work in this assigned Windows
  worktree, including a fast-forward to the approved baseline, documentation checks,
  and a commit. This exception does not authorize Windows code tests, canonical-main
  access, or a Linux worktree outside this session's permitted workspace.
- No Linux integration worktree or private Python environment was created. Those
  capabilities were not established by this bootstrap; candidate execution belongs
  to the separately designated landing owner.
- No bootstrap landing was authorized or attempted. No worker or merge monitor was
  started, and no push or pull request was made.

### Source identity

| Observation | Exact value |
|---|---|
| Initial assigned HEAD | `dc263b305e500df398b19398260e619253e855a7` |
| Initial assigned tree | `95dbf22734e821c2590f0a8e0e697976477aa936` |
| Approved implementation baseline | `f9bb376e02aaef166bc71e736eaba7ee677ce97c` |
| Baseline tree | `b433dc16bd187f679a763103b78151ca1fbc4645` |
| Shared Windows `refs/heads/main`, read from the assigned worktree | `f9bb376e02aaef166bc71e736eaba7ee677ce97c` |

The assigned worktree was clean at its initial HEAD. The required baseline was not
an ancestor of that HEAD; the reverse ancestry check succeeded. After the user's
documentation-only approval, an ordinary `git merge --ff-only` advanced only this
assigned branch to the exact baseline. Its status remained clean and the baseline
ancestry check then succeeded. This was not a main-branch landing.

Reading a shared branch ref does not verify a canonical checkout's current branch,
working tree, index, operation markers, source freeze, or active lock ownership.

### Canonical parity and lock evidence

The coordinator supplied the previous integration owner's report that Windows
`F:\XBOX-Repositories\appsec-review` and WSL
`/home/wsollers/projects/appsec-review` were both on `main` at the approved baseline,
with no landing, held integration lock, or source freeze. That report also identified
untracked WSL `data/feeds/` to preserve and an active `-n 8` unit gate in
`/home/wsollers/copilot-worktrees/gate-f9bb376e`.

Those are reported facts, not a fresh two-main parity or lock receipt from F00.
Neither canonical checkout, the active gate, nor its files or processes was accessed
or changed by this bootstrap.

Existing checked-in receipts establish the historical local integration mechanism:

- `docs/tasks/2026-11-06-operator-mcp-development-skills.md:238-247` records
  `appsec-independent-main-integration.lock` in the canonical Git common directory,
  opened with `FileStream` using `OpenOrCreate`, `ReadWrite`, and `FileShare.None`.
  The owner held the exclusive handle through state checks and the merge, then
  released it in `finally`.
- `docs/tasks/2026-11-06-worker-prompt-contracts.md:263-281` records a verified
  local Git bundle with an exact prerequisite, ready SHA, and SHA-256 digest,
  followed by the same exclusive-handle gate.
- These receipts do not establish that a lock is currently held or available.
  F00 did not acquire a lock or introduce a competing mechanism.

Any later authorized landing still needs a permitted owner to recheck the exact
expected base, checkout state, source freeze, existing lock, and both resulting
HEAD/tree identities. No parity success is claimed here.

### Published coordinator snapshot

The published plan is version **1.1** and the final bootstrap ledger is event
sequence **15**, frozen by the coordinator after the initial sequence-14 commit.
The approved review retains its original review baseline
`967a1072bc19feeb320ce4b44d6c056616c94d7b`. No package status, event, dependency,
owner, implementation claim, or review conclusion was independently changed.

The coordinator authorized two presentation-only transformations for repository
copies: CRLF to LF for the authored Markdown/JSON, and Markdown links using `ghapp`
rendered as their unchanged labels followed by the original URI in inline code.
Six links were transformed in the plan and two in the review. JSON URI values were
not rewritten. This preserves the existing documentation checker's URI policy
without changing its code or any byte-pinned evidence.

Original session artifacts were left unchanged. Byte-exact sequence-14 and final
sequence-15 captures were retained in this session's `files/f00-source-snapshot-14`
and `files/f00-source-snapshot-15` artifact directories so verification does not race
a later coordinator snapshot. The table below identifies the final publication.

| Coordinator artifact | Repository copy | Source SHA-256 | Published SHA-256 |
|---|---|---|---|
| `fleet-plan.md` | `README.md` | `ada31dc6a7c7c60540fd49249fce2ed0030c46cc6590a7a154935b079597e40b` | `8a8bd26d70afd9cab460d5519ac7c7b499e645ed14b498fe571b662668b1e674` |
| `appsec-system-review.md` | `approved-review.md` | `497debc7e9570025fadcecb104420d59e016cd877a580c2bf2365a2d1a72d8e7` | `54bb83e12dfa4b35e2e3c349e3b308640287920adf0f5e1e4c5e638d8c6f0489` |
| `fleet-ledger.json` | `ledger.json` | `7bc1b5f5e09fc483dde6296dbd2da678434bd831d61ca945c8d495075a38025e` | `ac968afee6c7c06a7b26948188f5b78ca43d32904d8a5c33a58b94bf8a9bdedd` |

### Landing-owner preflight and final freeze

After initial documentation commit
`3dfe503182762c20850a8fbb2adb0b8188886bcd`, the coordinator supplied sequence **15**
as the final bootstrap snapshot. The plan and approved-review bytes were unchanged.
The ledger update and this receipt were prepared as an additional documentation
commit; the initial commit was not amended, reset, or landed.

Sequence 15 identifies landing owner `969abd85-9a4e-42a5-a323-34843205448e`, with
this session retained as bootstrap support. Its preflight evidence is the owner's
`files/landing-preflight.json`, schema `appsec-review/fleet-landing-preflight/1`,
checked at `2026-11-06T12:24:27.7468579-05:00`. The exact source artifact is:

```text
C:\Users\william.sollers\.copilot\session-state\969abd85-9a4e-42a5-a323-34843205448e\files\landing-preflight.json
```

Its SHA-256 is
`842fe67023e53ea5507aee5e7a4a3a740af23d79545b4ea22d3af9cc16b6a5cb`;
an exact copy is retained beside the sequence-15 source snapshot. F00 read that
receipt, not the canonical checkouts. The receipt reports:

- Both canonical mains at `f9bb376e02aaef166bc71e736eaba7ee677ce97c`, tree
  `b433dc16bd187f679a763103b78151ca1fbc4645`, with no refs moved. Windows was clean;
  WSL tracked content was clean and untracked `data/feeds/` was preserved.
- Existing Windows exclusive-handle and WSL nonblocking exclusive `flock` probes
  succeeded and were released without writing. No new lock was created or held
  after preflight.
- No Git operation markers or observed main-bound review processes. The unrelated
  prior-owner gate was untouched; the receipt requires a fresh check under the
  integration gate before a landing.
- A clean, detached Linux candidate at the exact baseline with its own environment
  and verified editable source; a small local bundle verified on both sides with
  matching hashes and without importing or advancing refs.
- No merge authorization and no unit/integration/acceptance/live execution.

These are attributed, point-in-time landing-owner observations. They are not this
session's direct inspection, a landing receipt, a held source freeze, or continuing
authorization. Later ledger events belong in separate updates, not this frozen
bootstrap snapshot.

### Documentation verification

The focused verifier is a persistent session artifact, not repository code:
`files/verify-f00-docs.py`. It compares all three copies byte-for-byte against the
captured sources after only the authorized transformations, checks LF bytes,
validates ledger schema/base/owner and all 19 package IDs, verifies dependency
closure and acyclicity plus event continuity, checks the frozen preflight receipt's
identity and agreement with the ledger when supplied, and applies the unchanged `LINK`
parser and local-target rules from `tests/test_documentation.py` to these three
Markdown files only.

Run from the assigned worktree:

```powershell
$artifacts = Join-Path $env:USERPROFILE '.copilot\session-state\053e6dce-78d3-428d-ac36-f1811056dd67\files'
python (Join-Path $artifacts 'verify-f00-docs.py') --source (Join-Path $artifacts 'f00-source-snapshot-15') --root . --ghapp-as-code
git diff --cached --check
git ls-files --eol -- docs/plans/appsec-system-improvements
```

The initial focused check rejected CRLF in the newly authored `integration-log.md`;
the copied snapshots already matched the authorized transforms. That failure's
elapsed time was not captured. The log was then formatted to LF; no assertion,
checker, approved content, or test limit was weakened.

The initial corrected checks used the command above with
`f00-source-snapshot-14` and ran on baseline
`f9bb376e02aaef166bc71e736eaba7ee677ce97c` plus only these four documentation files:

| Check | Result | Elapsed wall time |
|---|---|---|
| Focused verifier, sequence-14 capture | PASS; 19 packages, 14 events, three Markdown files, exact transformed copies | 0.288 s (0.024 s inside the verifier) |
| `git diff --cached --check` | PASS; no whitespace errors | 0.150 s |
| `git ls-files --eol -- docs/plans/appsec-system-improvements` | All four files `i/lf`, `w/lf`, `eol=lf` | 0.082 s |

After the coordinator's final freeze, the sequence-15 update was checked on
`3dfe503182762c20850a8fbb2adb0b8188886bcd` plus only the ledger/log changes:

| Check | Result | Elapsed wall time |
|---|---|---|
| Focused verifier, sequence-15 capture | PASS; 19 packages, 15 events, three Markdown files, exact transformed copies, matching pinned preflight receipt | 0.373 s (0.1031 s inside the verifier) |
| `git diff --cached --check` | PASS; no whitespace errors | 0.117 s |
| `git ls-files --eol -- docs/plans/appsec-system-improvements` | All four files `i/lf`, `w/lf`, `eol=lf` | 0.083 s |

The staged scope contained only `README.md`, `approved-review.md`, `ledger.json`,
and `integration-log.md` in this directory. The historical review's companion
source inventory and Glasswing mockup are not included in this bootstrap.

Application unit tests, full-suite checks, integration/acceptance/live validations,
review runs, deployments, and fuzz campaigns were not run. This documentation-only
check establishes neither implementation quality nor canonical-main parity.

## 2026-11-06 - F00 exact bootstrap landing

The coordinator separately authorized landing only the frozen bootstrap commit
`23b5a5bcde9a8e35d4f39799ccecc5c60a14aef6`, tree
`4e00db3a00a92be08e400ef21332de5b2ace34df`, onto both canonical mains at
`f9bb376e02aaef166bc71e736eaba7ee677ce97c`. The landing completed at
`2026-11-06T12:33:51.1117175-05:00`; no additional commit was created.

- Windows `F:\XBOX-Repositories\appsec-review` and WSL
  `/home/wsollers/projects/appsec-review` both reached that exact HEAD and tree.
  Windows was fully clean; WSL tracked state was clean and untracked `data/feeds/`
  was preserved, including its directory identity and modification time.
- The existing Windows exclusive `FileStream` and WSL nonblocking exclusive
  `flock` were held together across baseline/freeze/operation checks, both
  `git merge --ff-only --no-edit` operations, and ancestry/parity/EOL verification.
  Both locks were released. The separate unit gate was untouched.
- `f00-landing-journal.jsonl` records the intermediate Windows-advanced,
  WSL-at-base state before the second fast-forward. The transaction took 3.8133 s.
- The 47,094-byte bundle verified on both sides with SHA-256
  `b080688e39923c123eff41f814d14d80f2f910930d50a8a5182c4a17326cdd8b`.
- In the isolated Linux candidate, the frozen-source/link/JSON verifier passed
  in 0.2184 s wall time (0.0508 s inside the verifier), covering 19 packages,
  15 events and three Markdown files. Whitespace and four-file LF checks passed.

The immutable receipt is retained at:

```text
C:\Users\william.sollers\.copilot\session-state\969abd85-9a4e-42a5-a323-34843205448e\files\f00-landing-receipt.json
```

Receipt SHA-256:
`da534a4492249459c01951cc9bf72fee37b4dfbc24fa0ca257f6b9fab2b8a24e`.
The journal and `f00-docs-verification.json` are beside it. No application unit,
full-suite, integration, acceptance, live, Docker, model or target execution
was performed for this documentation-only landing; no remote push occurred.

### Separately authorized ledger snapshot

The coordinator subsequently authorized publishing frozen ledger sequence **28**
while preparing the F01 candidate, with LF-only normalization and no semantic
edits. Its captured source SHA-256 is
`27a29402f7b28fe2fe53d98cdb2a9adaa0adceedb6df68e98723a0587c487556`.
The source is retained as `files/fleet-ledger-seq28.json` in the landing session.
Plan v1.1 and the approved-review copy remain unchanged. This snapshot and the
receipt above do not authorize or claim an F01 landing; later events remain
separate from this frozen candidate.

## 2026-11-06 - F01/F09 receipts and ledger checkpoint 48

The following are attributed observations from landing owner
`969abd85-9a4e-42a5-a323-34843205448e`, not fresh canonical-main inspection by this
documentation session. The supplied receipts were read and their exact hashes
verified. Both remain in that owner's session `files` directory:

| Receipt | SHA-256 |
|---|---|
| `f01-landing-receipt.json` | `14413d358d9c508b11e9bc2a38ba3b321677077413f8317eef2beaa4e6950406` |
| `f09-landing-receipt.json` | `4920f9d02169ffb988e55e761abad22d80bb1c55637a9eafaff20cbff4f6603d` |

### F01 landing

- Both mains advanced from `23b5a5bcde9a8e35d4f39799ccecc5c60a14aef6` to candidate
  `d4d68d2d99c681437f896bec35043c9b6fb22340`, tree
  `b1661412793e8c4653edfcc9971237bef4eca17c`; worker ready SHA
  `808f6944665eddab46f4f5354e29ea3f385a2607` is an ancestor.
- Completed at `2026-11-06T12:51:57.2874188-05:00` in 7.5487 s. The receipt reports
  parity, clean Windows/WSL tracked state, preserved WSL `data/feeds/` directory
  identity, 15 changed LF paths, and released locks; no new commit or remote push.
- The exact candidate had 79 previously passed cases; landing ran no new tests.
  Two larger inventory-resume cases and manual integration/acceptance/live validation
  remain outside that evidence. The landing retained frozen ledger 28 unchanged.

### F09 landing

- Both mains advanced from `d4d68d2d99c681437f896bec35043c9b6fb22340` to candidate
  `f40ca7733246003a580ac4a3823fd523740510e4`, tree
  `1de326e9685818d70bacc353623eceee860fc120`; worker ready SHA
  `a7257269a310eff285defc3758dc8152d2d7cb40` is an ancestor.
- Completed at `2026-11-06T13:03:34.5797217-05:00` in 5.7841 s. The receipt reports
  parity, clean Windows/WSL tracked state, preserved WSL `data/feeds/` directory
  identity, all eight paths matching committed bytes, and released locks. The
  fixture's `-text` attribute and exact bytes were preserved without normalization.
- The candidate had 78 previously passed cases plus prior type/lint verification;
  landing ran no new tests or metadata updates. Full maximal aggregation and manual
  integration/acceptance/live/campaign execution remain unrun. Runtime consumer and
  job-test mapping work belongs to F10; no current consumer is implied.

### Frozen checkpoint

The coordinator authorized a separate documentation checkpoint from
`f40ca7733246003a580ac4a3823fd523740510e4`, tree
`1de326e9685818d70bacc353623eceee860fc120`. This session fast-forwarded only its clean
owned branch to that exact base under the existing documentation-only Windows
exception. It did not access either main checkout, acquire an integration lock,
run code tests, or perform a landing.

Coordinator ledger **48** was frozen as this session's
`files/fleet-ledger-snapshot-48.json`; later events are not included. Its source
SHA-256 is `3c627dec28b1965ee1c9007c072f03c58178fae4a309b17ddd0b0ceef7f908ca`.
The only publication transform was CRLF to LF, producing SHA-256
`4468d4d2e7ee03007ba94f8fea73a6679e9bd0c5f2cf3a8b679e21aeccdf9e0f`.
No ledger values were independently changed. Only `ledger.json` and this appended
log changed; plan `README.md` and `approved-review.md` retain their exact base bytes.

Focused documentation verification uses the session artifact
`files/verify-checkpoint48.py`:

```powershell
python (Join-Path $env:USERPROFILE '.copilot\session-state\053e6dce-78d3-428d-ac36-f1811056dd67\files\verify-checkpoint48.py')
git diff --cached --check
git ls-files --eol -- docs/plans/appsec-system-improvements
```

It checks the exact normalized copy, duplicate-free JSON, 19 package identities,
48 contiguous events, state/dependency/DAG consistency, pinned receipt agreement,
append-only log preservation, unchanged plan/review bytes, exact two-path scope,
and changed-document links/LF using the unchanged repository link parser.

Results on the exact checkpoint base plus these two docs: verifier PASS in
0.714 s wall (0.4591 s internally); staged whitespace check PASS in 0.131 s;
line-ending inspection PASS in 0.088 s, with all four plan-directory files
`i/lf`, `w/lf`, `eol=lf`. No application unit, broad-suite, integration, acceptance,
live, deployment, model, or target validation was run for this checkpoint.
