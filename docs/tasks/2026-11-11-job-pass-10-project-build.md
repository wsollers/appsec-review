---
title: "Job pass 10 - `job_project_build`"
kind: "task"
subsystem: "target acquisition and build"
status: "historical"
jobs: ["job_project_build"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Job pass 10 - `job_project_build`

This pass advances T-057 using the user's capture-proven native-build direction of
2026-11-11. T-035, T-036 and T-037 remain parked. It supersedes the earlier proposed
native commissioning path for this c094 pass; no image rebuild or capture bypass is authorized.

**Result: accepted.** Fresh run `2026-11-11-0003` accepted job 10 at
**2026-11-11 16:10:18 America/New_York** (21:10:18 UTC): real c094 binary, eight
capture-backed compile entries, one `captured_invocation` / `proven` enforcement record,
and zero canonical job-10 gaps. Finding-to-first-acceptance turnaround is **5 h 31 min 18 s**
using the user-supplied 10:39 minute-precision start. The final result and evidence are below;
earlier failed attempts remain historical evidence.

## Starting evidence and ownership

The run-0003 audit was supplied by the read-only Run audit report session. Its canonical
gap counts come from each hash-pinned `outcomes.json`, not recursive check summaries:
source history 18, build environment 1, planning 52 and project-build 122 (193 total).
Project-build `attempt_0001`, dispatch `16b50491-2f9c-4267-97e7-b02e2ee3322f`,
resolved eleven existing base-image references but compiled nothing. Every probe was not
applicable; no accepted artifact was the c094 binary. The native c094 unit was blocked by
`unenforced_native_target` at `outcomes.json:gaps[27,68,110]`.

The audit's earlier repair-turnaround intervals retain their original uncertainty. This pass
uses the user-supplied **2026-11-11 10:39 America/New_York** finding boundary
(15:39 UTC, minute precision) to the first accepted job-10 result on the fresh scoped run.
That interval is not a fabricated timestamp for an earlier failed check.

The referenced `claude/prompt-prime-run-wsollers1-2026-11-10.md` was not present in mounted
main or the audit checkout; the audit session also had no copy. No missing instructions
from it are assumed. The explicit pass-10 prompt and available standing review-loop
instructions govern this work.

Parent session `83ad90fb-4e0a-4161-aa81-57e1bc0bd04f` owns mounted-main integration and
all live operations. One isolated implementation checkout,
`william-sollers-xbox-redesigned-disco`, is prepared at
`e2bb58e245b0b5096c78778c31b53f056da5289d`, containing main
`d01b9e3a510430b8ef247a884b7d2d401ef5c6ed`. Its own editable environment resolves there.
The old run and all accepted keys/attempts remain evidence, not inputs to rewrite.

## User-authorized target scope

With all 31 old dispatches verified stopped and the target clean, the parent applied cone-mode
sparse checkout for `projects/native/case-094`. Git 2.34.1 requires setting cone mode with
`sparse-checkout init --cone`, then `sparse-checkout set projects/native/case-094`.
The verified sparse list contains only that directory. Root files are retained by cone mode.

Target HEAD remains `bd69bfe83fec49155366303604475512c98c4ce6`, exact tag
`appsec-multi-vuln-c094-v1`; Git status is clean. The scoped raw fingerprint is
`a62432fbcad51e7de705a2a2118ce86b0083f2c749cc872b7fdd80e4f61629b6`.
A new application run is required. Run `2026-11-10-0003` will not be repaired onto this
different target fingerprint, and its corpus keys will not be overwritten.

## Required behavior and acceptance criterion

- Pre-build refusal protects capture trust: dynamic commands, compiler-resolution/environment
  escape, network-required steps, missing/invalid recipes and unknown operations remain blocked.
  The old static target proof may remain an annotation, not permission to execute.
- After execution, derive one source- and image-bound enforcement record for each native unit
  from observed compiler invocations, target flags/triples and translation units. The c094
  record must use `proof_kind: captured_invocation`, `status: proven`, and exactly one axis set
  compatible with selection policy. Recipe declarations and a merely generated compile database
  are not execution proof.
- Unknown compilers, mixed/disallowed targets and empty capture produce scoped
  `producer-gap/1` records, not silent success or a job failure.
- The existing pinned C++ image must compile c094 without deriving or rebuilding an image.
  Publish the actual binary and nonempty captured compile database in accepted artifacts.
  Keep one authoritative build and wire downstream consumption without treating a static
  annotation as mandatory proof or silently rebuilding accepted work.
- `stepwise check` must enforce the c094 binary, exactly one proven capture-derived native
  enforcement record and a nonempty compile database before job-10 acceptance.
- Jobs 1-9 on the new run require individual content checks. Canonical gaps must concern c094
  or explicit tooling limits, not omitted corpus cases.

The scoped walk uses these per-job content criteria, in addition to framework integrity:

| Job | Scoped criterion |
| --- | --- |
| 1 model connectivity | Configured provider/models are available; no missing-model or transport gap. |
| 2 image pins | Every frozen selected image reference matches its immutable local ID; no image mutation. |
| 3 target acquisition | Explicit target remains `NOT_REQUESTED`; no pull or target acquisition. |
| 4 intake | Exact tag/HEAD and scoped fingerprint above, clean target, verified configuration/guidance. |
| 5 catalog | Exactly one c094 CMake build unit; inventory resolves to retained root files or c094; no other corpus unit. Compile database may be absent before building. |
| 6 history | Source binding and symbols concern accepted scoped files; distinguish selected mainline from review HEAD and retain any honest binding/tooling limitation. No other-case parser/bound gaps. |
| 7 CI | Four retained root definitions (Azure, GitLab, Bitbucket, Jenkins); other provider branches not applicable. Observations/source spans and actual tool counts agree. |
| 8 environment | No selected shell/batch environment scripts and no retained PowerShell inputs: zero declarations, not-applicable coverage, no unsupported-other-case gap. |
| 9 planning | One c094 unit/recipe, offline pinned native profile, reproducible graph, no byte-budget exhaustion or unrelated-unit abstention. |
| 10 project build | Actual binary, nonempty correlated compile database, one proven capture-derived compatible enforcement record; checked by `stepwise check`. |

## Verification and live receipt

Implementation, focused commands/counts/timings, the T-047 differential, coverage, exact ready
commits and live identities will be recorded here as they are established. No passing unit test
is a substitute for the requested c094 build and accepted artifact proof.

Required runner-driven cases cover a successful CMake capture, mixed targets, a compiler outside
the pinned image, empty capture, pre-build dynamic/PATH refusal, and direct-compiler parity.
Each uses real configuration and the real runner, faking only the executor boundary and
finishing under ten seconds. Exact selectors and inspected counts use the guarded test runner;
no directory/full-suite selector or unrequested heavy-tier validation is authorized.

The final receipt will include the new run ID, canonical gap table for jobs 1-10, c094 enforcement
record, accepted binary/compile-database references and finding-to-first-acceptance turnaround.

## Implementation and focused verification

Ready commit `114f51197080483b5a9ea76565784d4618034c07` was integrated on mounted main
as `c2899203c`. Project-build dispatch is now `/3`, language-build handoff `/2`, and captured
native enforcement `/2`; the affected typed consumer declarations were changed together,
without dual-reading the old output shape. Independent native units execute once in job 10;
connected units retain their iteration owner. Later consumers retain unit gaps and consume
the accepted build instead of silently rebuilding it. Binary-evidence indexing remains an
intake-only producer, not a consumer of build output.

`probe_receipts[]` carries the accepted binary in `artifacts`, one capture-derived `enforcement`
record, the correlated `native_compile_database`, and the retained original CMake
`declared_compile_database`. Unproven outputs are diagnostic `rejected_artifacts`; typed gaps
retain their build-unit scopes. The stepwise content gate checks the actual single-c094 planning
input, binary type/hash, proven enforcement and correlated/nonempty compile database.

| Before | After / focused assertion |
| --- | --- |
| Native static target uncertainty prevents a CMake build | Capture-trust refusals remain pre-build; CMake executes and its observed target is checked afterward |
| Non-Unity job-10 probes are no-ops | Independent native execution publishes real build/capture artifacts; language-build consumes that result |
| No job-10 binary/content gate | `stepwise check` and acceptance reject missing binary, missing/unproven enforcement or empty/uncorrelated compile data |
| Static-proof tests encode refusal | Tests now cover CMake/direct compiler parity, mixed/disallowed targets, unknown compiler, empty capture, and pre-build dynamic/environment/network/recipe/operation refusals |
| Consumer artifacts could omit new unit evidence | Focused publication/consumer cases retain proof, scoped gaps and rejected-artifact diagnostics |

All commands below use the checkout's own environment, two workers, seed 11110, exact selectors,
and the unchanged 200-node / 30-second collection / 300-second total guard.

```sh
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 21 --parallel \
  --test-workers 2 --shuffle-seed 11110 --strict -- tests/test_project_build_capture.py
```

Final isolated result: **21 passed in 76.64 s / 83.477 s total**, no case over ten seconds.
Mounted-main result: **21 passed in 65.44 s / 71.294 s total**, no case over ten seconds;
`test/tmp/reports/tests-custom-20261111-122200-874252-49723.json`.
Coverage from the isolated exact core run is retained in `test/tmp/pass10-coverage-final.json`:
native enforcement 90%, whole project-build package 46%. The uncovered package lines are
principally legacy probe/repair and other-family paths, not claimed covered by this c094 pass.
The enforcement report names its 15 uncovered lines explicitly. Syntax and Ruff passed for the
58 affected Python files. Whitespace inspection preserves the existing CRLF fixture.

The scoped pre-pass baseline at
`e2bb58e245b0b5096c78778c31b53f056da5289d` collected 94 cases: 89 passed, five failed,
34.944 s total (`tests-custom-20261111-110248-810990-37159.json` in the repair checkout).
The final exact affected differential collected 125 cases: **123 passed, two unchanged
failures, zero new failures and three fixed**, 26.25 s pytest / 32.408 s total
(`tests-custom-20261111-121241-879693-47606.json`). Its expanded command and exact selector
manifest are retained in that report; baseline file is `test/tmp/pass10-prepass-failures.txt`.
The selectors cover native enforcement, topology refinement, the three existing project-build
preparation cases, language-build unsupported/unresolved receipt publication, review metrics,
job-control schemas and five compiler-profile boundary cases.

The two unchanged failures are
`test_direct_resume_planner_reuses_valid_releases_and_rejects_stale_recipe` and
`test_task_checkpoint_requires_the_same_recipe_refinement_before_reuse` in
`tests/test_build_topology_refinement.py`. They respectively expect REUSE where the baseline
returns RUN, and attempt an immutable checkpoint replacement which the baseline refuses.
Neither was changed or weakened, and neither is presented as passing.
Historical T-047/`fe328d76` failure evidence was unavailable: this is a measured **pre-pass**
differential, not a fabricated historical T-047/full-suite result. No broad suite was run.
Intermediate failing/slow fixtures remain in the repair checkout's guarded reports.

## Source deployment and fresh-run boundary

After the UI warning, `scripts/stack-restart.sh --code-location-only` re-signed/reloaded mounted
sources and restored five healthy services without rebuilding an image. Measured release:
`427d2c281c808fbdf4031775a009f1cfbf83ac3881ee84d6c85522fbe95bf3f8`.
The application tooling image remains
`sha256:29682648dd80ac803efe7cde0ce362098782312b7f44a1a658873823ac522d2b`.
Mounted/deployed enforcement bytes both hash to
`30b9a73925a32d293aa748e76a2e2e55e40a45725b6d6538899db90a0bec0b3d`.

Fresh application run **`2026-11-11-0002`** was initialized against the scoped target.
Its first model-connectivity dispatch is `a1f6312e-0864-4812-9adb-200c57703767`;
configured Sonnet/Opus availability, transport and zero gaps were verified.
Initial acceptance under a new scoped corpus name was refused because the operator coupled
the key-directory name to a target Git tag. No old key or target tag was modified. A narrow
operator-only follow-up separates the explicitly verified target tag from the new corpus-key
namespace; it must retain the target-tag/HEAD check and all existing acceptance guards.

The follow-up `6438da6888f0bc68f0fb7e77517521d02eb32d6c` integrated as `cccd98aa6`.
The walk uses `--tag appsec-multi-vuln-c094-scoped-v1 --target-tag appsec-multi-vuln-c094-v1`
on each acceptance. No runtime source, image, target tag or old key was changed by that fix.
Its exact seven-case selection is `tests/test_stepwise_target_tag.py` plus
`tests/test_stepwise_rewind.py::test_matching_replay_reaccepts_without_replacing_key_provenance_or_seed`.
The parent's first invocation omitted the latter node; the count guard refused six versus seven
before execution. Restoring the complete selection passed seven cases in 6.50 s with no slow cases
(`tests-custom-20261111-124011-605963-51497.json`).

## First live job-10 result: capture-wrapper classification defect

Jobs 1-9 were individually accepted after their scoped criteria held. The catalog has 17 files
and one CMake unit. All nine c094 code files have complete history-symbol coverage; the history
gaps concern root CI-file symbols and the root README's differing selected-mainline binding.
CI has four definitions, nine observations/findings and no owned gaps. Environment analysis is
not applicable with no gaps. Planning has one valid offline native recipe and no contradiction,
abstention or feedback-budget failure.

Job-10 dispatch `953f9f42-f943-402c-a296-f5c051e4216a`, `attempt_0001`, ran
**2026-11-11 18:25:17.591-18:27:41.420 UTC** (143.828 s total job duration).
The native build itself took **16.935 s**, produced eight correlated compile-database entries
and an actual 160384-byte x86-64 ELF executable:

```text
data/build/probes/units/build-unit-adf13d8306cb272dea43/attempts/attempt_0001/workspace/projects/native/case-094/build/case094
SHA-256: 569b207768a1fc228d1642429657e920133ce1674705361edff69fb72bbdd347
```

The content check correctly refused acceptance at **18:28:20.906 UTC**. The binary remains in
`rejected_artifacts`, not accepted evidence. Native enforcement incorrectly classified eleven
`/bin/sh` launchers and nine `/usr/bin/python3 /capture/tool-wrapper.py` logger invocations as
compilers because their argv contains `-c`. Their all-null axes were mixed with the genuine
Linux/x86-64/GNU compiler axes, yielding `unknown_compiler_in_capture` and
`mixed_targets_in_capture`. All fifteen actual Clang executions were trusted and agreed.

The resolving sanitized events are command-002 ordinals 300/306 (shell `-c` command strings)
and 315/414 (the platform capture wrapper forwarding compiler arguments). Its `events.jsonl`
hash is `d8ccdca0e3be8ef6a91ee879a78a4c57781c89a7dcf0017d0626d6dc4facff24`.
The correction is limited to distinguishing proven capture scaffolding from actual compiler
execution; unknown compilers and missing underlying compiler execution must still fail closed.
All ten dispatches were verified stopped before the bounded repair.

Canonical first-attempt gap counts, from hash/size-verified handoff `outcomes` references:

| Job | Canonical gaps | Content disposition |
| --- | ---: | --- |
| 1 model connectivity | 0 | accepted |
| 2 image pins | 0 | accepted; 58 immutable references matched |
| 3 acquisition | 0 | accepted; not requested |
| 4 intake | 0 | accepted; scoped fingerprint/17 files |
| 5 catalog | 28 | accepted; absent optional documents/package manifests/compile data and Git exclusion |
| 6 history | 6 | accepted; root CI symbol support and README/mainline binding limitations |
| 7 CI | 0 | accepted; four definitions/nine source-bound findings |
| 8 environment | 0 | accepted; not applicable |
| 9 planning | 18 | accepted; pre-build absence/policy and bounded dependency-discovery limitations |
| 10 project build | 4 | **not accepted**; two false classifier reasons declared by two units |

These are not the recursively repeated gap strings printed by framework checks. No other corpus
case is in the accepted source inventory. The first accepted job-10 result and final turnaround
remain pending; compiled-but-rejected output is not counted as acceptance.

## Bounded classifier repair and admitted replay

Ready classifier fix `f3e10214a77a14a8a54092214a7768df1938c39d` integrated as `673b178b5`.
It recognizes only the reserved capture-wrapper forms, including the observed shell/Python
frames, and excludes them only when their tool identity and exact arguments match a successful
image-profile compiler execution in the same capture. It does not trust a shell command string
as compiler proof or exempt arbitrary interpreters. Missing-inner, mismatched-wrapper and unknown
interpreter-compiler cases remain gaps. The original false gap was reproduced before correction.

The exact guarded selection was
`tests/test_project_build_capture.py::test_capture_intermediaries_require_correlated_real_compiler_execution`
plus the `mixed-mixed_targets_in_capture`, `outside-unknown_compiler_in_capture` and
`empty-capture_empty` cases of
`test_native_target_is_proven_only_by_captured_execution`, using `--expect-tests 8`,
`--parallel --test-workers 2 --shuffle-seed 11110 --strict`.
Eight passed in 27.08 s / 32.311 s total in the isolated checkout. Mounted main passed eight in
27.63 s with no case over ten seconds:
`test/tmp/reports/tests-custom-20261111-134521-468656-60456.json`.

A source-only reload, with the UI interruption announced, produced release
`35a3fa344ff7cec950501f34bbd3f3674c8a9d6f0d8e1205df3a91e09ad90894`.
The image, scoped target fingerprint and frozen configuration remained unchanged. Plan
`d94906ea03d8ecf3503403220c5f80136133abb004f069192a41885527fff0b1` was inspected and
explicitly admitted from `runs/c094-scoped-capture-wrapper-repair-plan.json`, then applied with
stepwise recovery. Existing import closures require history/CI/environment replays and invalidate
planning/project-build, in addition to the three always-execute early gates. Intake and catalog
remain reused. No release-scoping redesign or forced reuse was introduced.

The history replay again exposed an operator comparison limitation: this time scratch/gitdir
mounts changed from native paths to Desktop aliases while target mounts stayed native.
The same user-authorized, receipt-backed comparison repair was extended symmetrically, retaining
the closed source-history execution/artifact scope and all original-reference, content, suffix,
permission and claim checks. Desktop-to-different-Desktop remaps remain outside the rule.
Ready commit `d9dfb28292bec4445cd2cdc5dd54cc44a37d5280` integrated as `5443ab252`.

The reversed/mixed-root regression first reproduced all ten differences. The exact
`tests/test_stepwise_mount_paths.py` selector, with `--expect-tests 65 --parallel
--test-workers 2 --shuffle-seed 11110 --strict`, passed 65 cases in 56.43 s in the repair
checkout and **52.74 s** on main, no slow cases; main report:
`test/tmp/reports/tests-custom-20261111-142207-396926-63311.json`.
The existing history attempt was rechecked, not rerun: four artifact proofs and fifteen mapping
receipts accounted for the ten differences, while retaining the unadjusted differences and raw
evidence. It was individually reaccepted. This operator-only change needed no source reload
or new admission.

CI then exposed the same mount-alias drift in three Checkov scan/normalization copies.
All fifteen observation lists and all nine findings were independently identical. The closed
CI receipt-proof extension `e0d086a5756cd5e1c8c2866e4bbc70609dd24696` integrated as
`660bd177d`. It covers only the observed Azure/Bitbucket/GitLab Checkov branches and their
hash-pinned raw copies; source, permissions, image/argv/environment identities and all remaining
content stay strict. The existing CI attempt rechecked from fifteen differences to zero with
nine artifact proofs, without rerun/reload. The exact guarded files
`tests/test_stepwise_ci_mount_paths.py tests/test_stepwise_mount_paths.py`
(`--expect-tests 109`, two workers, seed 11110, strict) passed 109 cases in 106.19 s in the
repair checkout and **97.40 s** on main, with no case over ten seconds. Main report:
`test/tmp/reports/tests-custom-20261111-145823-738388-66941.json`.

## Final frozen-source walk

At the user's request, incoming `origin/main` commit `8caee22` was merged with all local fixes
as `cce1d5bc5a8fda02f2ec1c8ce1a74c38a0154602`. The merge was prepared in an independent
scratch clone with no conflicts. An existing empty Git ref blocked import into the live clone;
the user explicitly authorized backing up and removing that single invalid ref. No other ref,
commit, worktree data or old evidence was removed.

The merged scoring/quality files passed their exact guarded 54-case selection in 2.86 s:
`tests/test_detector_scoring.py tests/test_operations_quality.py`, two workers, seed 11111,
report `test/tmp/reports/tests-custom-20261111-152455-645392-69506.json`.
Source-only reload produced release
`b220130047a71101e9715ef914235bf566386a834b9082e9a2d6942a1773d96d`.
The inspected merged-source repair plan invalidated all ten jobs. It was not admitted:
instead, a fresh scoped run avoided further backward comparisons while preserving `0002`
and the original full-corpus `2026-11-10-0003`.

The final walk is **`2026-11-11-0003`**, with new corpus namespace
`appsec-multi-vuln-c094-scoped-v2` and actual target tag `appsec-multi-vuln-c094-v1`.
Source commit `cce1d5bc5` stayed fixed for the entire walk. No jobs after job 10 were launched.

| Job | Canonical gaps | Accepted content / remaining limitation |
| --- | ---: | --- |
| 1 model connectivity | 0 | configured Sonnet/Opus models and transport available |
| 2 image pins | 0 | all 58 frozen image references matched |
| 3 acquisition | 0 | explicit target; no acquisition requested |
| 4 intake | 0 | clean tagged target, scoped fingerprint and 17 files |
| 5 catalog | 28 | one c094 unit; optional-document/package-manifest/pre-build-data absence and Git exclusion |
| 6 history | 6 | all nine c094 code files complete; root CI symbol support and README/mainline binding limitations |
| 7 CI | 0 | four definitions, fifteen dispositions, nine source-bound observations/findings |
| 8 environment | 0 | no environment scripts; not applicable |
| 9 planning | 18 | one valid offline recipe; pre-build absence and bounded dependency-discovery limitations |
| 10 project build | **0** | actual binary, eight captured compile entries, one proven native enforcement record |

All ten rows are operator-accepted. Counts come from each handoff's verified `outcomes`
reference, not recursively repeated check strings. The full table is retained in
`runs/metadata/stepwise/2026-11-11-0003/checks/pass10-canonical-gaps.json`.
The remaining 52 records describe scoped pre-build absence/policy/tooling limitations, not
the other fifty corpus units. This is build acceptance, not a claim that c094 is vulnerability-free.

### Actual build and enforcement

Job-10 dispatch: `d3b3e010-b9f0-4404-a6bf-571041bb7956`, `attempt_0001`.
The job ran **21:02:19.675-21:04:44.061 UTC**, 144.385 s. Its native build took **17.398 s**.
The actual compilation image was `audit-buildenv-cpp:local`,
`sha256:fead8bd920407a830b4872eb390eba8aa0973104023e678f0d316f5f481852cf`;
`customized` is false. All 47 host-pinned tags remained at their original IDs. No image was rebuilt.

Accepted artifact paths, relative to `runs/2026-11-11-0003/`:

```text
Binary:
data/build/probes/units/build-unit-adf13d8306cb272dea43/attempts/attempt_0001/workspace/projects/native/case-094/build/case094
SHA-256: 569b207768a1fc228d1642429657e920133ce1674705361edff69fb72bbdd347
160384 bytes; ELF64, machine 62 (x86-64)

Captured/correlated compile database (8 entries):
data/build/probes/units/build-unit-adf13d8306cb272dea43/attempts/attempt_0001/native-compile-commands.json
SHA-256: 6cda842587f1cb3895ad1ae2dd42eb887b264459a0c7ad156c28b251e396ba51

Retained CMake compile_commands.json (8 entries):
data/build/probes/units/build-unit-adf13d8306cb272dea43/attempts/attempt_0001/workspace/projects/native/case-094/build/compile_commands.json
SHA-256: ac91538870deb0308749f5ebed0f310b2929595621c3ad36e5a7628882681fa1
```

The binary is referenced by the accepted handoff, not merely present in scratch. Every correlated
compile entry names one of the verified capture records. There are two complete captures and
fifteen trusted compiler executions at `/usr/bin/clang++` or `/usr/lib/llvm-18/bin/clang`.
The observed explicit triple is `x86_64-pc-linux-gnu`; profile defaults and captured invocations
agree. Translation units are `access.cpp`, `blocks.cpp`, `console.cpp`, `directory.cpp`,
`echo.cpp`, `main.cpp`, `notes.cpp` and `title.cpp`.

The one enforcement record has this summary:

```json
{
  "schema": "appsec-review/native-target-enforcement/2",
  "enforcement_id": "e95cc3460f88ac207f2291f740c116b22b068744ec4790555ed5b509fe8f230d",
  "build_unit_id": "build-unit-adf13d8306cb272dea43",
  "proof_kind": "captured_invocation",
  "status": "proven",
  "proven_axes": {
    "os": "linux",
    "isa": "x86_64",
    "abi": "gnu",
    "sdk": null,
    "deployment": null,
    "device_kind": null,
    "hardware_generation": null
  },
  "unresolved_inputs": []
}
```

Its authoritative location is
`data/jobs/job_project_build/attempts/attempt_0001/steps/probe/tasks/native/result.json`,
at `receipts[0].enforcement[0]`. The complete extracted record, including pinned profiles,
compiler invocations, target flags, source/recipe/selection identities and capture references,
is in `runs/metadata/stepwise/2026-11-11-0003/checks/c094-enforcement-attempt_0001.json`.
The independently verified acceptance/timing receipt is
`runs/metadata/stepwise/2026-11-11-0003/checks/pass10-content-acceptance.json`.

### Turnaround and commit series

The first explicit job-10 acceptance is **21:10:18.054665 UTC / 16:10:18.054665 EST**.
From the user-supplied **10:39 EST** finding boundary, using second zero for that minute,
the recorded interval is **19878.054665 seconds: 5 h 31 min 18 s**. The final frozen-source
walk alone took **36 min 22 s**, measured from its first job's persisted attempt start
(20:33:56.052424 UTC), not from an invented dispatch timestamp.
The much larger total includes implementation, unit verification, earlier repair/comparison
cycles, requested documentation/remote integration work, and operator/agent overhead; it is
not native compiler runtime.

| Main commit | Purpose |
| --- | --- |
| `1e304804c` | pass-10 criterion, audit baseline and sparse scope |
| `c2899203c` | capture-proven execution, publication, consumers, tests and parked-item notes |
| `406400cc2` | initial verification and fresh-run receipt |
| `cccd98aa6` | independent corpus namespace and verified target tag |
| `44850359b` | requested unit/live/recovery protocol and `AGENTS.md` reference |
| `48d56b0ae` | first scoped acceptances and captured-build fault |
| `673b178b5` | exact correlation of capture intermediaries to actual compiler executions |
| `5443ab252` | symmetric/mixed source-history mount evidence proof |
| `18958a674` | classifier repair/replay receipt |
| `660bd177d` | closed CI Checkov mount evidence proof |
| `cce1d5bc5` | user-requested remote merge; final tested/deployed source freeze |

The exact implementation-agent SHAs and all focused commands/results are recorded in the
sections above and their linked local reports. No historical T-047 result was fabricated.
T-035/T-036/T-037 remain parked; the full corpus and later review jobs are not certified by this pass.

Final documentation links and the three named acceptance/evidence report paths were checked,
and `git diff --check` passed. On source commit `cce1d5bc5`, the required registry gate
`.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 5 --parallel --test-workers 2 --shuffle-seed 11111 --strict -- tests/test_todo_registry.py`
passed all five cases in 1.96 s, none over ten seconds; report:
`test/tmp/reports/tests-custom-20261111-162421-916269-72514.json`.
The final receipt and generated scoped-v2 keys/provenance/seed manifests are committed locally;
run-owned binaries, captures and reports remain outside Git.
