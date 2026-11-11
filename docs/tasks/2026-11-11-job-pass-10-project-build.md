# Job pass 10 - `job_project_build`

This pass advances T-057 using the user's capture-proven native-build direction of
2026-11-11. T-035, T-036 and T-037 remain parked. It supersedes the earlier proposed
native commissioning path for this c094 pass; no image rebuild or capture bypass is authorized.

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
