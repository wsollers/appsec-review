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

## 2026-11-06 - X01/F08/F05 receipts and checkpoint 71

These are attributed observations from landing owner
`969abd85-9a4e-42a5-a323-34843205448e`, not direct canonical-main inspection by this
documentation session. The exact receipts remain in that owner's session `files`
directory; their supplied SHA-256 identities were verified before use:

| Receipt | SHA-256 |
|---|---|
| `x01-landing-receipt.json` | `d44f5132d7114f56ce123acd35977f1627d002617b39ace55aeaf52889ca3fc8` |
| `f08-landing-receipt.json` | `ed3672aa38c81dd359f37692fca03e54aac64e0d78fc7f9e6530f4de2baf3303` |
| `f05-landing-receipt.json` | `2b1ad572f57dc565d09fd4b6772196375e308e9a5d295ec05fc285c7ad71df4a` |

### X01 landing

- Both mains advanced from `f0a0f354f130899b4e2fec451d362be2bcaec964` to candidate
  `b202e887a997ab4294264e3aa22e33e5479853fc`, tree
  `f2d0f886d52fe22a7265efd6ed6037302ed4d4ae`; worker ready SHA
  `be6386e40586855d56c2ab52f2f08dfad3d2471e` is an ancestor.
- Completed at `2026-11-06T13:28:07.7659725-05:00` in 7.0198 s. The one-file
  inherited collection-fixture repair had nine previously passed cases.
  The worker branch was preserved; no broader fleet validation gap was closed.

### F08 landing

- Both mains advanced from `b202e887a997ab4294264e3aa22e33e5479853fc` to candidate
  `9932eed5fbac85562cb579f14950b330542bdcfe`, tree
  `b21b768472dcfea11fd9e472b67fadffa33d5cff`; worker ready SHA
  `bc50376e91462ab1224f23a8810a88e5fcce59bb` is an ancestor.
- Completed at `2026-11-06T13:35:50.9778123-05:00` in 7.837 s. The exact 24-file
  candidate had 342 previously passed cases and prior lint verification. Two
  `-text` fixtures retained exact bytes without normalization.
- Live-provider acceptance and model efficacy remain unexecuted. The F02-owned
  obsolete all-registered assertion and pre-existing global target-link gaps
  were not changed by the landing.

### F05 landing

- Both mains advanced from `9932eed5fbac85562cb579f14950b330542bdcfe` to candidate
  `11b1046f7d670cdec188719223c882d3aa68c6e1`, tree
  `e27f2c74319f9716c2f6b63001824ca21bc6f5cb`; worker ready SHA
  `7a9a03ef398b48cd1f221e6405ab80c0c1612752` is an ancestor.
- Completed at `2026-11-06T13:40:01.8227866-05:00` in 5.4453 s. The exact 20-file
  candidate had 148 previously passed cases and prior type/lint verification.
  Five `-text` fixtures retained exact bytes without normalization.
- Central admission, wiring, publication, retrieval, and applicable test-map work
  remain with F06. Bounded static support is not runtime exposure, connected
  collector, or commissioning evidence.

All three receipts report both-main HEAD/tree parity, clean tracked content,
exact committed-byte agreement, preserved WSL `data/feeds/` directory identity,
and released locks. The transactions created no new commits, ran no new tests,
and made no remote push or extra metadata update. Full/manual/live validation
and service, model, build, campaign, cloud, or target execution were not performed.

### Frozen plan and ledger

The coordinator authorized this separate documentation checkpoint from
`11b1046f7d670cdec188719223c882d3aa68c6e1`, tree
`e27f2c74319f9716c2f6b63001824ca21bc6f5cb`. This session fast-forwarded only its clean
owned branch to that base under the existing documentation-only Windows exception.
It did not inspect a canonical checkout or perform a landing.

The source capture is this session's `files/checkpoint71-sources` directory.
Plan **1.2** and ledger **71** are frozen; future events are excluded. The plan
retains the original 18 implementation packages, explicitly adds supplemental
infrastructure repair X01 to F17's dependencies, and defers current APS child
ownership/status to the ledger. The ledger contains 20 records: F00-F17, X01,
and external dependency EXT-APS.

| Source | Published copy | Source SHA-256 | Published SHA-256 |
|---|---|---|---|
| `fleet-plan.md` | `README.md` | `be2d24b3dc647bf0ae674d548f86d6c1587ce963f71490ed72e40197a4b3f7d6` | `9ce99844be6f23a05db2b03e62dd1e16d02c21e480e403b1ca662ea5b7907f61` |
| `fleet-ledger.json` | `ledger.json` | `c35c9993fe9ae7a473b3e768a36afd51c93c734142ecf88609b16123f7ac3c16` | `2577b1d489b713ca76a92556d5571ddce0fa93751621e73275029fb737ca02ed` |

Only the approved presentation transforms were applied: CRLF to LF, plus six
plan Markdown links using `ghapp` rendered with unchanged labels and inline-code
original URIs. JSON URI values and all semantic ledger fields are unchanged.
Only `README.md`, `ledger.json`, and this append-only log changed;
`approved-review.md` retains its exact base bytes.

Focused documentation verification uses the session artifact
`files/verify-checkpoint71.py`:

```powershell
python (Join-Path $env:USERPROFILE '.copilot\session-state\053e6dce-78d3-428d-ac36-f1811056dd67\files\verify-checkpoint71.py')
git diff --cached --check
git ls-files --eol -- docs/plans/appsec-system-improvements
```

It checks exact source-normalized equality, duplicate-free JSON, the 20 explicit
records with supplemental X01 and F17 dependency, all 18 original plan headings,
71 contiguous events, state/dependency/DAG consistency, the pinned receipt chain
and ledger agreement, unchanged approved review, append-only log, exact three-path
scope, and changed-document links/LF using the unchanged repository link parser.

Results on the exact checkpoint base plus these three docs: verifier PASS in
0.633 s wall (0.3888 s internally); staged whitespace check PASS in 0.140 s;
line-ending inspection PASS in 0.081 s, with all four plan-directory files
`i/lf`, `w/lf`, `eol=lf`. No source, tests, global checker, or approved-review edits
were made; no code, broad-suite, integration, acceptance, or live checks were run.

## 2026-11-06 - X02 receipt and checkpoint 96

The X02 landing observations below are attributed to landing owner
`969abd85-9a4e-42a5-a323-34843205448e`, not direct canonical-main inspection by this
documentation session. The source receipt is that owner's
`files/x02-landing-receipt.json`, SHA-256
`8dc5d179d773fa2687c096eded591660a16aec7d6b2cc82a7679afbb75d7036a`.
Its exact bytes were verified and captured beside this checkpoint's source snapshot.

### X02 landing and retained limitations

- Both mains advanced from checkpoint `4833894300452c13e825f73bc01a720cb98be8b6`,
  tree `97fe7fcacdb58a3fa70a3f798d4a4794d3755347`, to candidate
  `17e5bd3f73ca6d27a126b74d8111b7c6d77daa64`, tree
  `d133dabff064aff6a8ecb3e35429b1df2bee9255`; worker ready SHA
  `9e02798191c632f5e48ce78c86057166ca7bbdde` is an ancestor.
- Completed at `2026-11-06T14:46:57.7471526-05:00` in 5.3384 s. The three changed
  paths were `src/appsec_review/jobs/build_iterations.py`,
  `tests/test_build_topology_refinement.py`, and `tests/job-test-map.json`.
  The receipt reports both-main HEAD/tree parity, clean tracked content, exact
  committed-byte agreement, LF bytes, preserved WSL `data/feeds/` directory
  identity, an unchanged worker branch, and released locks.
- The exact candidate had **41 previously passed focused cases**, not a broad-green-suite
  result. **11 known baseline failures** remain: two explicit topology-refinement
  deselections and nine build-iteration cases. Their retained failure-ID sets matched
  in worker-owned candidate/base runs; the broad counts are attributed worker reports.
- The **full pristine baseline log was overwritten**. Retained matching failure-ID
  artifacts, not a complete pristine-run log, are the available baseline evidence.
  The receipt pins `x02-known-baseline-failures.json` at SHA-256
  `84dcf026e154621315c3724757eeabf9ff90e5a403b0fbd43f37a4c3bb4691ad`.
  Those failures and the missing-log limitation were not resolved by landing.
- No new tests or commits, remote pushes, extra metadata, other packages, or services
  ran in the landing transaction. There is no broad-suite, live, production-review,
  compiler, Docker, model, or target validation claim.

### Frozen plan, ledger, and exact exceptions

The coordinator authorized a separate docs-only checkpoint from
`17e5bd3f73ca6d27a126b74d8111b7c6d77daa64`, tree
`d133dabff064aff6a8ecb3e35429b1df2bee9255`. Only this session's clean owned branch was
fast-forwarded to that base, under the existing documentation-only Windows exception.
No canonical checkout was accessed and no main landing was performed.

Plan **1.3** and ledger **96** are frozen in this session's
`files/checkpoint96-sources` directory; later events are excluded. There are exactly
21 records: the original F00-F17, supplemental X01/X02, and external dependency
EXT-APS. F17 explicitly depends on both supplemental repairs.

Plan 1.3 records the APS user's current deterministic-JSON-replay/build-only
milestone: preserve Lean models, validate/reset inputs, control time, and make zero
OS network sends. Campaigns, ACK-loss investigation, security-finding workflows,
and a finding reducer are excluded from that milestone. No tested runner is claimed,
and downstream F12/F13 capability and execution gates remain.

The two user-approved offline unit exceptions are copied without expansion:

| Exact node ID | Maximum total duration |
|---|---|
| `tests/test_review_data_indexing.py::test_inventory_audit_matrices_links_and_fts_validation` | 45 seconds |
| `tests/test_review_data_indexing.py::test_package_job_publishes_accepted_manifest_and_receipts` | 60 seconds |

Both limits cover setup, call, and teardown together. All other unit cases retain
the ten-second limit. This checkpoint makes no global timeout, tier, durability,
admission, assertion, or execution-policy change and runs neither exception.

| Source | Published copy | Source SHA-256 | Published SHA-256 |
|---|---|---|---|
| `fleet-plan.md` | `README.md` | `25ba757a4530a634e4e3a6839aa81158583621ca3f9bc123ffe46eab02b2890b` | `9017a266d156d0b5484a6c0361a0c6a538d681de36e26a81b2c03784c6a9eb91` |
| `fleet-ledger.json` | `ledger.json` | `ebc5fcf971000539bb1fbb37e8f3bf35b2aa4e1282fc7df770e92020384604a5` | `a87c7a9ec065bee7b722a0965dd42023e53080f3478b6c1e109ada36bd684fd2` |

Only approved presentation transforms were applied: CRLF to LF and six plan
Markdown `ghapp` links rendered with unchanged labels and inline-code original URIs.
JSON URI values and semantic fields remain unchanged. The only modified repository
paths are `README.md`, `ledger.json`, and this append-only log in the plan directory;
`approved-review.md` retains its exact base bytes.

Focused documentation verification uses the session artifact
`files/verify-checkpoint96.py`:

```powershell
python (Join-Path $env:USERPROFILE '.copilot\session-state\053e6dce-78d3-428d-ac36-f1811056dd67\files\verify-checkpoint96.py')
git diff --cached --check
git ls-files --eol -- docs/plans/appsec-system-improvements
```

It checks exact frozen projections, duplicate-free JSON, 21 required records,
X02/F17 dependencies, 96 contiguous events, states/DAG, exact exception node IDs
and full-phase bounds, APS scope, pinned receipt/ledger/Git-object chain agreement,
41-focused-pass versus 11-baseline-failure accounting, unchanged approved review,
append-only log, exact three-path scope, and changed-document links/LF using the
unchanged repository link parser.

Results on the exact checkpoint base plus these three docs: verifier PASS in
1.046 s wall (0.7906 s internally); staged whitespace check PASS in 0.130 s;
line-ending inspection PASS in 0.081 s, with all four plan-directory files
`i/lf`, `w/lf`, `eol=lf`. No source, tests, global checker, or approved-review edits
were made; no code, broad-suite, integration, acceptance, or live checks were run.

## 2026-11-06 - X03 step 1, external APS evidence, and checkpoint 113

### Attributed X03 step-1 landing

Landing owner `969abd85-9a4e-42a5-a323-34843205448e` supplied
`files/x03-landing-receipt.json`, SHA-256
`89506b0093840b79401ac3c5f18d00f91e08907202e63ec85703a0616861c398`.
Its exact bytes were verified and captured with the checkpoint sources. This is
receipt inspection, not this documentation session's inspection of either main.

- Both mains advanced from `4062fa4da5820f82a50961eeb742ba1ff4254bee`, tree
  `1781a435f4618454b63bcd976f1de4cc1fa111db`, to ready/candidate
  `7acc8040c8a42ae9f342424a609b06596f251fe6`, tree
  `37c3a6179eb57c5ac2b75e585d20a49cd4ccc181`.
- Completed at `2026-11-06T15:35:17.4086687-05:00` in 7.7357 s. The exact three
  new files were `container_runtime/compiler_profiles.py` under `src/appsec_review`,
  `tests/test_compiler_profiles.py`, and `docs/plans/native-compiler-profiles.md`.
  The receipt reports matching HEAD/tree and committed bytes, clean tracked content,
  LF bytes, preserved WSL `data/feeds/` identity, unchanged worker branch/worktree,
  and released locks.
- The candidate had 130 previously passed unit cases plus strict mypy, Ruff, and
  documentation verification. Landing ran no new tests and created no new commit,
  metadata update, remote push, or service activity.
- Only step 1 is implemented; steps 2-8 remain proposed and unconsumed. Synthetic
  transcripts/ELF fixtures are not live-image commissioning. Derived collection is
  refused before Docker/verifier calls. Real transport/image copying, downstream
  admission wiring/enforcement, TOML/image pins, and signing-policy changes were not
  performed. Hashing image-exported bytes is not independent image-layer authenticity.

### External deterministic APS subset

Frozen ledger 113 records foundation commit
`4cb6ee15f572873df9dec31fa182a20de3d4e6f7`, tree
`83d6b49574b4bcea39ca07fc7aa87b84b30c931f`, and optional tests/docs-only successor
`630fdd82fc34c2d7a625caa5df679b5fa6c3310c`. The successor is a separate build/evidence
record, not a replacement for foundation pins. Its producer-reported 4/4 CTest result
in 2.61 s is retained by the coordinator; this session did not inspect that build.

This session read and verified only the following foundation evidence identities
in producing session `029a7295-c5c8-49b3-91c4-a6a1bdd300d2`, under
`files/ddnet-replay-evidence`:

| Evidence | SHA-256 |
|---|---|
| `build.json` | `23d8e09f37aeaa20a98612738f2d0e9fd657d02cde6792ae616b8305e44d1b5c` |
| `tests.txt` | `6bac178a66bafeb12d96b2e181802fb7e28dbf75d6e68ebf868db0d3f794f9df` |
| `validation-summary.json` | `925f85dffce6d6382bdc971739f06a5c5ba8babcdac087aa20180e9c2ccd0cf1` |

Foundation build identity remains
`a88ae8110d8993849af5e249e5737d649732c8304b638b243d29f3ceff549a1e`,
binary SHA-256 `76b25d4ad840a628c75f56d115954ebba5321572100f589053d3bd67b10488f1`.
The retained producer report says 3/3 CTest targets passed in 2.27 s. One identity
distinction remains explicit: `build.json` names `tests_sha256`
`b3d266cbaaf42bedf8461eb92d8fe86d4ad5c3e608d0fc6336c074e1c37c24ab`, which is not the
supplied `tests.txt` hash above. The latter is independently pinned producer evidence;
this checkpoint does not claim the build's internal field binds that supplied file.
No evidence bytes or pins were rewritten to make those identities agree.

The coordinator's prior source-byte-map checks and producing project's results are
attributed evidence, not this session's source verification, fleet rebuild/replay,
or authenticity attestation. No APS source, executable, or run was copied or executed.
CLI 1.0.0 is a synchronous deterministic subset (`build`, `inspect`, `validate`,
`replay`) for the documented Linux x86_64 Clang 14 profile, native allocator and
stop-on-queue-failure mode. The supplied summary has empty finding oracles, zero
campaigns, and no candidate schedule execution. No campaign, finding reducer,
logical ACK-age ledger, async MCP, or Lean differential API is supplied. Synthetic
component replay does not establish caller/live-network reachability; F12/F13
capability and execution gates and the user's excluded scope remain unchanged.

### Frozen checkpoint and verification

The coordinator authorized only a documentation checkpoint from
`7acc8040c8a42ae9f342424a609b06596f251fe6`, tree
`37c3a6179eb57c5ac2b75e585d20a49cd4ccc181`. This session fast-forwarded only its clean
owned branch under the existing docs-only Windows exception. No canonical-main
access or landing occurred.

Plan **1.4** and ledger **113** are frozen in this session's
`files/checkpoint113-sources`; later events are excluded. There are 22 records:
F00-F17, X01/X02/X03, and EXT-APS. Incoming X03 is a separately user-directed step,
not a new whole-native-rollout dependency for F17. F17 retains F01-F16 and X01/X02.
The exact two user-approved 45/60-second node exceptions still include setup, call,
and teardown; all other unit cases retain the ten-second limit.

| Source | Published copy | Source SHA-256 | Published SHA-256 |
|---|---|---|---|
| `fleet-plan.md` | `README.md` | `49420a6d54af14865a164e0db3c43d14ec865fbf4d989efaf9bc063759057e36` | `9366d7d85d52ffb0074978b51d75ab4841d4676445105cab8c35e6e326f4972a` |
| `fleet-ledger.json` | `ledger.json` | `481118d3218660f46d12677731a927abbd95575c0b125ee947b1433161c8a2cf` | `47f9a1791373026bf57f65ed10be3379270a41db248e82b53ede5a9b70a8eb8a` |

Only CRLF-to-LF normalization and the six approved plan Markdown `ghapp` presentation
conversions were applied. JSON URI values and semantic fields remain unchanged.
Only plan-directory `README.md`, `ledger.json`, and this append-only log changed;
`approved-review.md` retains its exact base bytes.

Focused documentation verification uses session artifact `files/verify-checkpoint113.py`:

```powershell
python (Join-Path $env:USERPROFILE '.copilot\session-state\053e6dce-78d3-428d-ac36-f1811056dd67\files\verify-checkpoint113.py')
git diff --cached --check
git ls-files --eol -- docs/plans/appsec-system-improvements
```

It checks exact projections, 22 records/113 contiguous events/states/DAG, unchanged
F17 dependency scope, exact timing exceptions, the X03 receipt/Git-object chain,
the three read-only APS evidence hashes and foundation identities, separately pinned
test-report status, unchanged review, append-only log, three-path scope, links, and LF.

Results on the exact checkpoint base plus these three docs: verifier PASS in
0.834 s wall (0.6031 s internally); staged whitespace check PASS in 0.123 s;
line-ending inspection PASS in 0.081 s, with all four plan-directory files
`i/lf`, `w/lf`, `eol=lf`. No source, tests, global checker, or approved-review edits
were made; no code/manual tests, APS replay, live images, or runtime work were run.
