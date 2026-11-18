# Job 24/47 audit — `job_sanitizer_build`

## Result and authority

- **Revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, branch `main`.
- **Checkout:** `/home/wsollers/projects/appsec-review`, Ubuntu-22.04, accessed through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the authorized UNC root. The default Windows checkout was not audited or tested.
- HEAD, cleanliness, ancestry and editable-import location were checked. Import resolved to `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. Final inspected Git status was clean.
- **Findings:** one high, two medium and two low. Four function-level reproductions completed in **0.835 s**; a separate real publisher/inventory projection reproduction completed in **0.599 s**. The latter demonstrates a downstream data-shape mismatch, not a complete accepted retrieval run.
- **Focused units:** **60 passed**: 57 job-specific cases plus three environment-guard cases; **5.32 s** pytest time, **13.414 s** supervised wrapper total. Zero failures/skips; zero cases over ten seconds; two workers, shuffled.
- No repository/source/configuration/environment edits, installs, subagents, commits, pushes, real builds, compilers, sanitizers, providers, services, target execution, or integration/acceptance/live/Dagster runs. Only this report and private ignored test evidence were created.
- Passing tests do not establish real toolchain behavior, complete immutable publication, or useful live sanitizer evidence.

## Registration, activation and intended contract

`src/appsec_review/runtime/registry.py:162` registers this factory. `job.py:448-456` defines exactly three units. `datasets.py:35-58` declares a review-graph job, target-checkout access, `always_execute=False`, `propagate_handoff=True`, scheduled after `job_language_build`.

The dev recipe enables it (`appsec-review.toml:1839-1868`). `runtime/selection.py:11-43` removes jobs with `settings.enabled=false` from active selections; `orchestration/topology.py:46-87` projects disabled vertices transparently. Focused topology tests confirm the sole direct scheduling consumer is `job_review_data_indexing`; ordinary CodeQL, C/C++, Clang, post-build assessment and security-tagging lanes do not consume sanitizer outputs.

**Purpose:** replay accepted native build commands in a separate workspace with configured compiler/linker flags, verify required ASan/UBSan references by reading produced ELF bytes, and publish a hash-bound output catalog and honest gaps. This is build/readiness evidence, never a runtime test or proof of safety.

### Accepted inputs

All six declarations are handoff-channel, producer-evidence inputs from `job_language_build`:

| Dataset | Schema | Availability / missing |
|---|---|---|
| `handoff` | `appsec-review/job-handoff/2` | Required / reject |
| `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | Optional / gap |
| `build_actions` | `appsec-review/retrieval-index/2` | Optional / gap |
| `jvm_build_actions` | `appsec-review/retrieval-index/2` | Optional / gap |
| `language_build_receipts` | `appsec-review/language-build-handoff/2` | Optional / gap |
| `build_workspaces` | `application/octet-stream` | Optional / gap |

The actual loader (`job_language_build/job.py:127-173`) calls `accepted_upstream`, verifies the receipt-document digest/schema and build-outcome vocabulary, then returns the envelope digest. `runtime/consume.py:173-208` requires a declared envelope and admitted pin inside runtime scope. Sanitizer load additionally checks snapshot identity and duplicate IDs, sorts native IDs, and retains omitted/nonnative units.

**Existing observation gap, not another new finding:** this loader directly reads the receipt JSON without `observe_output(language_build_receipts)`. Sanitizer also directly reads protected argv and baseline bytes. The envelope is observed, but those payload dataset reads are not individually recorded. This repeats the already reported language/project-build reader issue (LB report / PB-F04 theme). Hash checks remain present; declaration or supply must not be described as observed payload consumption.

## Every task and processing boundary

All paths in this table are under `src/appsec_review/`.

| Step/task | Actual implementation | Checks, output and coverage limit |
|---|---|---|
| `load.accepted_native` | `jobs/job_sanitizer_build/job.py:387-406` | Parse exact settings; read accepted language build; compare source fingerprint; reject duplicate unit IDs; sort native receipts; select `max_units`; retain every omitted native unit and nonnative `SKIPPED_NA`. Bind selection to upstream handoff hash. No model/prompt/tool launch. |
| `build.units` | `job.py:408-424` | Re-read accepted handoff; reject changed digest; select original receipts; run `_build_unit` in `PublicationThreadPoolExecutor` using `settings.workers`; aggregate unit gaps and explicit omitted-unit gaps. No native work means `NOT_APPLICABLE`; otherwise all units must be instrumented for `SUCCEEDED`. |
| `build.units` — replay admission | `job.py:75-116,264-281`; `job_codeql_analysis/planning.py:110-130` | Require `build_succeeded` and configured build system. Resolve complete configure/build role sequence, including legacy unlabeled commands. Hash-check protected JSON, argv identity, working directory and image identity. Missing/redacted/schema-invalid command is a gap; changed hash/identity raises integrity failure. Reject argument/environment flag conflicts. **SB-F04**. |
| `build.units` — workspace/executor | `job.py:246,283-343`; `job_language_build/job.py:265-302` | Remove prior sanitizer tree, copy unit-root target source plus declared dependencies, create declared build directory, protect replay JSON, snapshot before build, resolve accepted image and replay commands. Retain bounded streams/exits/timing; stop on first failure; check target fingerprint after command loop. **SB-F01/F02**. |
| `build.units` — artifact evidence | `job.py:122-224,344-369`; `evidence.py:34-77` | Replay accepted tree dispositions; prune dependency/excluded/bookkeeping content; catalog changed native objects/executables/shared libraries. Read symbol tables and linked runtime names, compare optional normal-build control, judge required references, hash catalog and write final workspace manifest. **SB-F03**. Static archives are deliberately not inspected. |
| `acceptance.publish_handoff` | `job.py:426-445` | Count planned/omitted/instrumented/nonnative units and individually instrumented outputs; write summary with upstream, settings/output-policy identities and gaps; return summary artifact, counts and aggregate status. Per-output instrumentation can be true while the enclosing unit is incomplete. Downstream metadata loses per-unit readiness: **SB-F05**. |

`_validate` checks exact configured step/task order (`job.py:377-383`). No declared task is unreachable. The job has no model, persona, task prompt or runtime-skill selection; no sanitizer entry was found in the guidance registry. Formal deterministic/tool task-binding metadata remains **T-147**, not evidence that the build task does not execute.

### Flags, bounds and failure semantics

- Shipped flags: `-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1`, prepended to recorded `CFLAGS`, `CXXFLAGS`, `LDFLAGS`; extra environment `ASAN_OPTIONS=detect_leaks=0`. Recorded sanitizer selections or contradictory configured environment produce gaps rather than silently replacing them.
- `required_evidence=["address"]`; UBSan is recorded but intentionally not required for code with no UBSan-instrumentable operation. Required names must be a nonempty subset of selected sanitizers. Build systems: CMake, autotools, Meson, make.
- Positive integer bounds: two internal build workers; 1,800 s per command; 8 MiB retained per stream; 10,000 output artifacts per unit; 32 selected native units. Snapshot file bound is **10 × artifact_count_limit**, not the same count. Extra flags and environment entries are capped at 16; environment values at 1,024 bytes.
- Unit reasons are deduplicated to 20 plus an explicit omitted-reason count; aggregate preserves per-unit prefixes and omitted IDs.
- A failed command/image has nested `terminal_status=FAILED`, but the task returns `COMPLETED_WITH_GAPS` when any planned unit is uninstrumented. This documented distinction is intentional; it does not request an automatic retry.
- `build_succeeded` honors typed `build_outcome`, so a built receipt with provenance gaps remains replayable. This is more accurate than the canonical operations page's literal “prior SUCCEEDED status” wording.
- Config/settings identity in the summary is a byte-affecting subset. Whole-job frozen configuration identity also includes selection/time/worker bounds, so their absence from `settings.identity()` alone is not a demonstrated stale-cache bug.
- No per-unit sanitizer checkpoint exists. A fresh attempt reconstructs its workspace; **SB-F01** concerns that reconstruction overwriting earlier evidence, not ordinary successful whole-job reuse.

### Evidence and no-execution invariant

`evidence.py:34-64` calls only the repository ELF reader. It recognizes `__asan_*` / `__ubsan_*` symbols or matching runtime `DT_NEEDED` library names. `resolved`, `no_symbol_tables`, `unparsed`, and `not_inspected` remain distinct. Objects retain compact counts/booleans; linked outputs retain up to eight symbol names. Missing/changed baseline bytes yield unavailable/changed controls, not negative evidence.

`job_language_build/elf.py` was read fully: class/endian/header/segment/section bounds, bounded dynamic entries/names, two symbol tables, four-million-symbol limit. It never loads or executes bytes. Symbol presence is the selected reference-evidence criterion, not proof of executed sanitizer checks or complete instrumentation of every translation unit.

The job invokes only accepted recipe commands through `BuildContainerExecutor` and never invokes a cataloged output afterward. Accepted builds may run their own generators/compiler probes; the operations document explicitly permits that normal-build behavior. This audit executed neither builds nor those helpers.

The real executor's inspected path (`container_runtime/build_executor.py:262-567`) checks immutable image identity/signing policy, validates working-directory containment, grants/closes workspace write access, constructs nonroot/read-only/capability-dropped/PID-bounded Docker argv, and retains timeout/stream outcomes. Sanitizer uses default **bridge** networking; `recipe.network_required` is recorded, not an enforcement switch. This is documented behavior, not a newly invented offline requirement. Native broker behavior, actual isolation, signing and process cleanup were not exercised.

## Publication, schemas and downstream consumption

| Dataset | Actual path / declaration | Result |
|---|---|---|
| `sanitizer_build_summary` | `data/jobs/job_sanitizer_build/attempts/*/steps/acceptance/tasks/publish_handoff/*.json`; `sanitizer-build-handoff/1`; artifact-only | Actual summary matches glob and step. Contains flags/settings identity, output-policy identity, per-unit outputs/evidence/controls, counts and gaps. |
| `sanitizer_build_workspaces` | `data/sanitizer/**`; octet streams; protected/sensitive | Owns workspaces, exact replay argv/environment, bounded logs and workspace manifests. No text index or executable consumption grant. Non-attempt-qualified layout causes **SB-F01**. |

Internal document identifiers are `sanitizer-build-unit/1`, `sanitizer-build-replay/1`, `sanitizer-runtime-evidence/1`, protected-build-command `/2`, and build-workspace-manifest `/1`. These are domain identifiers/ad hoc checks; no dedicated sanitizer JSON-schema validator or output validator is attached to this job. Common publication validates control status/gap shapes, not every nested sanitizer payload (`interchange.py:521-573`).

The job uses legacy gap strings (`strict_gaps=False`). Common `_producer_outcome` canonicalizes them, preserving aggregate partial coverage and false retryability; nested `units[]` statuses are not standalone task outcomes (`runtime/handoff.py:198-265`).

`runtime/handoff.py:61-108` collects and verifies declared run-path/hash references. `runtime/runner.py:1000-1087` validates outcomes, output references, input-read closure and admission before writing an accepted handoff/pointer. That code does not relocate these raw sanitizer paths into a new immutable attempt namespace. Focused tests exercise direct handler publication and file ownership, **not** complete JobRunner/admission/retry publication.

The only declared consumer is review-data indexing (`job_review_data_indexing/datasets.py:312-317`). It reads the accepted handoff/statuses and publishes inventory metadata. It does not read instrumented binaries or create a sanitizer `build_security` shard. `query_sanitizer_readiness` nevertheless expects per-unit fields absent from that inventory (**SB-F05**).

## Findings

### SB-F01 — High: a fresh attempt destroys an earlier attempt's referenced sanitizer evidence

- **Evidence:** `src/appsec_review/jobs/job_sanitizer_build/job.py:246,283-290,294-300,324-337,364-368`; reference collection `src/appsec_review/runtime/handoff.py:61-108`; publication `src/appsec_review/runtime/runner.py:1036-1087`.
- **Trigger:** a native build unit is recomputed in the same run after an earlier sanitizer attempt produced evidence.
- **Expected:** old accepted artifact references remain valid regardless of the new attempt's outcome.
- **Actual:** the root is `data/sanitizer/<build_unit_id>`, without attempt identity. `_build_unit` removes the entire root before image resolution/replay, then rewrites replay/log/manifest paths. A failed replacement can leave the old binary absent while the earlier summary/handoff still references it.
- **Bounded reproduction:** real `_build_unit` with a fake executor produced `SUCCEEDED`; real `collect_artifacts` verified eight references. Changing only the context attempt ID to `attempt_0002` and making the fake executor fail the first command produced `FAILED`, reused the identical workspace path, removed the old binary and made old-reference collection raise `ValueError: target evidence integrity mismatch`.
- **Impact:** retry/recompute can invalidate previously published evidence and downstream verification even when the new attempt is never accepted.
- **Confidence:** high on function-level invalidation and publication path trace. Full accepted JobRunner retry was not executed.
- **Smallest correction:** make all sanitizer workspace/replay/log/manifest paths attempt-qualified, or publish immutable content-addressed snapshots; never remove a prior accepted attempt's tree. Regress successful first attempt followed by failed second attempt and verify every original reference.
- **Overlap:** same immutability failure class as artifact-security audit **ASA-F07**, but a distinct job/path/root cause. No sanitizer-specific matching TODO was found.

### SB-F02 — Medium: the supposedly fresh source copy retains target-owned build caches

- **Evidence:** `src/appsec_review/jobs/job_sanitizer_build/job.py:288-305`; imported `src/appsec_review/jobs/job_language_build/job.py:265-288`; `src/appsec_review/jobs/build_discovery.py:1304-1327`; explicit promise `docs/operations/sanitizer-build.md:45-63`.
- **Trigger:** the accepted target contains an existing CMake build directory/cache under the selected unit root.
- **Expected:** sanitizer configure starts without stale compiler/linker cache state, since environment injection relies on the first configure.
- **Actual:** `_copy_source` excludes only `.git`, `.hg`, `.svn`, copying build directories and `CMakeCache.txt`. `ensure_declared_build_dir` preserves an existing directory. No sanitizer-specific cache reset occurs.
- **Bounded reproduction:** place `native/build/CMakeCache.txt` with `CMAKE_CXX_FLAGS:STRING=-O0` in the synthetic target; call the real copy helper. The cache survives byte-for-byte and appears in the sanitizer prebuild snapshot.
- **Impact:** a fresh filesystem directory can still contain a nonfresh build cache that ignores the injected initial flags, reuses outputs or refers to old source paths. This can yield avoidable uninstrumented/no-output/configure gaps. No actual CMake invocation was used to demonstrate those downstream compiler behaviors.
- **Confidence:** high for the copy defect/documented invariant; compiler consequences are source-derived, not live-tested.
- **Smallest correction:** remove/reinitialize only accepted generated build state inside the new sanitizer workspace, with an explicit in-source-build policy; do not delete target files or arbitrary directories by name.
- **Overlap:** T-039/T-040 concern component/sibling materialization, not stale caches. Related helper, different defect; no exact sanitizer cache TODO found.

### SB-F03 — Low: exactly reaching the artifact limit is falsely reported as truncation

- **Evidence:** `src/appsec_review/jobs/job_sanitizer_build/job.py:187-197,350-357`.
- **Trigger:** a unit produces exactly `artifact_count_limit` eligible outputs.
- **Expected:** retain all outputs and succeed if their required evidence and manifest are complete.
- **Actual:** the catalog appends its Nth output, immediately emits a truncation gap and breaks without checking whether any N+1th eligible output exists.
- **Bounded reproduction:** fake build emits one instrumented ELF executable with limit one. The actual output is instrumented, but the unit is not and returns `COMPLETED_WITH_GAPS` with the sole reason `instrumented output catalog truncated at the configured count bound`.
- **Impact:** false coverage gap and instrumented-unit undercount at a legitimate boundary.
- **Confidence:** high, real catalog/judgment/build-unit path.
- **Smallest correction:** report truncation only on observing an additional eligible output beyond the retained count; test N-1, N, N+1.
- **Overlap:** T-113 records high historical sanitizer unit coverage, but the current boundary test only uses more outputs than the limit. No matching TODO found.

### SB-F04 — Low: valid split CMake `-D` arguments bypass masking-flag detection

- **Evidence:** `src/appsec_review/jobs/job_sanitizer_build/settings.py:29-34,102-115`; prebuild gate `job.py:273-281`; accepted CMake parser supports `-D` operands at `src/appsec_review/jobs/build_recipe_commands.py:63-67`.
- **Trigger:** an accepted configure command spells a flag cache assignment as `-D CMAKE_CXX_FLAGS=-O0`, rather than `-DCMAKE_CXX_FLAGS=-O0`.
- **Expected:** both equivalent forms are recognized as masking the sanitizer environment and rejected before rebuilding.
- **Actual/reproduction:** `argument_conflicts` returns one conflict for the attached form and `[]` for the split form. Its loop only matches each token independently.
- **Impact:** an avoidably uninstrumented rebuild can run to completion/timeout before evidence rejection instead of producing the intended upfront conflict. This does **not** demonstrate false-positive runtime evidence; later byte checks remain.
- **Confidence:** high for the pure detector; no compiler executed.
- **Smallest correction:** parse recognized split and attached driver options before applying conflict policy, retaining command ordinals.
- **Overlap:** no exact TODO found; current tests cover attached forms only.

### SB-F05 — Medium: per-unit sanitizer readiness is not delivered to its advertised retrieval query

- **Evidence:** producer `src/appsec_review/jobs/job_sanitizer_build/datasets.py:11-28`; inventory `src/appsec_review/indexing/inventory.py:502-520,618-632`; indexing projection `src/appsec_review/jobs/job_review_data_indexing/job.py:603-631,679`; consumer `src/appsec_review/retrieval/core.py:2102-2168`.
- **Trigger:** query `query_sanitizer_readiness(build_unit="<accepted native unit>")` after successful sanitizer publication.
- **Expected:** expose that unit's sanitized readiness/counts/gaps without exposing or executing protected binaries.
- **Actual:** sanitizer emits no `build_security` shard. The fallback inventory contains dataset-level `scope="run"` rows, not top-level `build_unit_id`, per-sanitizer or per-unit status fields; the query rejects every such row when a build-unit filter is supplied.
- **Bounded reproduction:** all three real handlers with fake accepted-input/executor boundaries published one instrumented unit and output. Real `build_inventory` produced sanitizer dataset rows with no `build_unit_id`; the equivalent SQLite job/unit filter matched **zero** rows. The inventory fixture did not run accepted-handoff admission, and the complete RetrievalCore envelope was not executed.
- **Test mismatch:** `tests/unit/test_t172_indexing_and_retrieval.py:515-520,566` fabricates a `build_security/sanitizer-main` shard with per-unit sanitizer fields and attributes it to this producer, despite that shard not being in its actual dataset contract. That queried fixture is not evidence that real sanitizer publication supplies it. This unrelated broader test file was inspected only, not run.
- **Impact:** existing generic inventory metadata is queryable, but the advertised per-build readiness lookup returns no actual sanitizer result.
- **Confidence:** high on producer-to-consumer shape mismatch; full indexed/accepted retrieval integration remains unverified.
- **Smallest correction:** have an authorized indexing projection read the hash-verified summary and emit a declared, sanitized per-unit readiness dataset, or narrow the query contract to actual dataset-level coverage. Preserve artifact protection and the no-execution boundary.
- **Overlap:** directly overlaps the sanitizer-readiness goal of **T-172**, currently marked done; do not treat its historical completion/test claim as current end-to-end proof.

## Documentation drift and known/deferred limits

- **Low documentation drift:** `docs/operations/sanitizer-build.md:214` names nonexistent `tests/test_sanitizer_build.py`. The current map/canonical page correctly names the three `tests/unit/job_sanitizer_build/` files. Update the operator command after the T-113 relocation; no obsolete selector was executed.
- The canonical process's literal requirement for prior `SUCCEEDED` should describe `build_succeeded` / typed `build_outcome=built`; provenance-gap receipts can legitimately be replayed.
- **T-147:** missing formal task/tool bindings remains open and was not fixed.
- **T-175 / T-026:** dynamic sanitizer/PoC execution remains separately authorized/deferred. This audit neither proposes nor performs it.
- **T-039 / T-040:** component/sibling-source materialization remains open. The sanitizer copy uses the same limited helper. Product-dependent shared `/install` replay was not established; normal language execution can supply such mounts while sanitizer calls plain `execute`. Reachability for current accepted native project-owned receipts was not fully traced, so this is an explicit gap, not a sixth defect.
- Symbol-reference evidence, object-only success, optional normal-build controls, ASan-only required evidence, dependency-tree exclusion and bridge networking are decided current semantics, not silently widened requirements.

## Focused validation commands and results

All Linux commands used this transport (no `wsl -e`, no default Windows checkout):

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# exact Linux command below
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Identity/preflight:

```bash
git rev-parse HEAD
git branch --show-current
git status --short
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

The inherited `APPSEC*`, `DAGSTER*`, `PYTEST*`, `PYTHON*` selector search printed no values. No environment reset/install was necessary.

**Only pytest invocation (wrapper-owned sequential preflight/execution):**

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 241118 \
  --max-tests 60 --expect-tests 60 -- \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_sanitizer_build/test_contract.py \
  tests/unit/job_sanitizer_build/test_handlers.py \
  tests/unit/job_sanitizer_build/test_settings_and_evidence.py
```

Wrapper-expanded execution:

```bash
/home/wsollers/projects/appsec-review/.venv/bin/python -m pytest \
  -p ops_test_guard -c /home/wsollers/projects/appsec-review/pyproject.toml \
  --rootdir=/home/wsollers/projects/appsec-review -o addopts= -q -rfE \
  --basetemp=test/tmp/tests-custom-20261118-124419-008239-2988444 \
  --junitxml=test/tmp/tests-custom-20261118-124419-008239-2988444.junit.xml \
  -o junit_family=legacy -n 2 --shuffle-seed=241118 \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_sanitizer_build/test_contract.py \
  tests/unit/job_sanitizer_build/test_handlers.py \
  tests/unit/job_sanitizer_build/test_settings_and_evidence.py
```

Collection used that exact command without `-n 2`, with `--collect-only`, sequentially in the wrapper's fresh private directory. Reviewed/expected/collected/executed count: **60**. Defaults retained: collection cap 30 s; total cap 300 s.

| Check | Count / outcome | Elapsed |
|---|---|---|
| Wrapper collection | 60 nodes, exit 0 | 3.951 s supervised |
| Unit execution | 60 passed; 0 failed/skipped; 0 over 10 s | 5.32 s pytest; 9.138 s supervised process |
| Whole wrapper | Exit 0; both cleanup records confirmed, 0 remaining processes | 13.414 s |
| Four SB-F01–F04 assertions | All confirmed; no external process/tool boundary used | 0.835 s |
| SB-F05 projection/filter assertions | Confirmed; no full acceptance/query-envelope claim | 0.599 s |

Persisted wrapper evidence under authorized checkout:

- `test/tmp/logs/tests-custom-20261118-124419-008239-2988444.log`
- `test/tmp/logs/tests-custom-20261118-124419-008239-2988444.collection.log`
- `test/tmp/tests-custom-20261118-124419-008239-2988444.collection.json`
- `test/tmp/tests-custom-20261118-124419-008239-2988444.junit.xml`
- `test/tmp/tests-custom-20261118-124419-008239-2988444.timings.sqlite`
- `test/tmp/reports/tests-custom-20261118-124419-008239-2988444.json`

### Reproduction commands

Both programs ran using `.venv/bin/python - <<'PY' ... PY` inside the SSH-transported bash script. They created unique descendants of `test/tmp/`, not system temporary directories. These are bounded reproductions, not added unit tests.

SB-F01–F04 program:

```python
from pathlib import Path
from types import SimpleNamespace
import json, time, uuid
from tests.unit.job_sanitizer_build.test_handlers import _synthetic_fixture, _settings
from tests.sanitizer_support import instrumented_elf
from appsec_review.jobs.job_sanitizer_build import job as sut
from appsec_review.jobs.job_sanitizer_build.settings import argument_conflicts
from appsec_review.runtime.handoff import collect_artifacts

started = time.monotonic()
base = Path('test/tmp') / ('job-audit-sanitizer-repro-' + uuid.uuid4().hex)
base.mkdir(parents=True)
base = base.resolve()
class FakeBuild:
    def __init__(self, fail=False): self.fail = fail
    def resolve(self): pass
    def execute(self, argv, *, workspace, working_directory, environment):
        if '--build' in argv and not self.fail:
            binary = workspace / working_directory / 'build/sample'
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(instrumented_elf())
        return SimpleNamespace(exit_code=2 if self.fail else 0, timed_out=False,
            stdout=b'fake boundary only', stderr=b'fake compile failure' if self.fail else b'',
            stdout_bytes=18, stderr_bytes=20 if self.fail else 0,
            stdout_truncated=False, stderr_truncated=False, stderr_tail=b'')

results = {}
_, _, _, run, receipt, ctx = _synthetic_fixture(base / 'rerun')
first = sut._build_unit(ctx, receipt, _settings(), lambda *_: FakeBuild())
assert first['instrumented']
refs = collect_artifacts(run, {'units': [first]})
old_binary = run / first['outputs'][0]['path']
ctx.job.attempt_id = 'attempt_0002'
second = sut._build_unit(ctx, receipt, _settings(), lambda *_: FakeBuild(fail=True))
assert second['terminal_status'] == 'FAILED' and not old_binary.exists()
try:
    collect_artifacts(run, {'units': [first]})
except (ValueError, OSError) as exc:
    invalidated = f'{type(exc).__name__}: {exc}'
else:
    raise AssertionError('prior artifact references unexpectedly remained valid')
results['rerun_invalidation'] = {'first_status': first['terminal_status'],
    'initial_verified_refs': len(refs), 'second_status': second['terminal_status'],
    'same_workspace': first['workspace'] == second['workspace'],
    'old_binary_exists': old_binary.exists(), 'prior_reference_error': invalidated}

_, _, _, run, receipt, ctx = _synthetic_fixture(base / 'exact-bound')
at_limit = sut._build_unit(ctx, receipt, _settings(artifact_count_limit=1), lambda *_: FakeBuild())
assert len(at_limit['outputs']) == 1 and at_limit['outputs'][0]['instrumented']
assert at_limit['terminal_status'] == 'COMPLETED_WITH_GAPS'
results['exact_bound'] = {'outputs': len(at_limit['outputs']), 'limit': 1,
    'output_instrumented': at_limit['outputs'][0]['instrumented'],
    'unit_instrumented': at_limit['instrumented'], 'gaps': at_limit['gaps']}

_, target, _, run, receipt, ctx = _synthetic_fixture(base / 'cache')
cache = target / 'native/build/CMakeCache.txt'
cache.parent.mkdir(parents=True)
cache.write_text('CMAKE_CXX_FLAGS:STRING=-O0\nCMAKE_HOME_DIRECTORY:INTERNAL=/workspace/native\n')
receipt['recipe']['build_dir'] = 'native/build'
workspace = run / 'fresh-workspace'
sut._copy_source(ctx, receipt, workspace)
retained = workspace / 'native/build/CMakeCache.txt'
assert retained.read_bytes() == cache.read_bytes()
results['copied_cache'] = {'cache_retained': retained.exists(),
    'cache_content': retained.read_text(),
    'in_prebuild_snapshot': 'native/build/CMakeCache.txt' in sut._snapshot(workspace, 100)}

attached = argument_conflicts([['cmake', '-S', '.', '-B', 'build', '-DCMAKE_CXX_FLAGS=-O0']])
split = argument_conflicts([['cmake', '-S', '.', '-B', 'build', '-D', 'CMAKE_CXX_FLAGS=-O0']])
assert len(attached) == 1 and split == []
results['split_define'] = {'attached_conflicts': attached, 'split_conflicts': split}
results['elapsed_s'] = round(time.monotonic() - started, 3)
results['scratch'] = str(base)
print(json.dumps(results, indent=2))
```

Actual scratch: `test/tmp/job-audit-sanitizer-repro-f04e76b6b2a348138bdde1963e527e15`.

SB-F05 program:

```python
from pathlib import Path
from types import SimpleNamespace, MappingProxyType
from unittest.mock import patch
import json, sqlite3, time, uuid
from tests.unit.job_sanitizer_build.test_handlers import _synthetic_fixture
from tests.sanitizer_support import instrumented_elf
from appsec_review.jobs.job_sanitizer_build import job as sut
from appsec_review.jobs.job_sanitizer_build.datasets import DATASETS
from appsec_review.runtime import UnitContext
from appsec_review.indexing.inventory import InventoryInputs, build_inventory

start=time.monotonic()
base=(Path('test/tmp')/('job-audit-sanitizer-readiness-'+uuid.uuid4().hex)).resolve()
base.mkdir(parents=True)
_,_,snapshot,run,receipt,ctx=_synthetic_fixture(base)
class FakeBuild:
    def resolve(self): pass
    def execute(self,argv,*,workspace,working_directory,environment):
        if '--build' in argv:
            p=workspace/working_directory/'build/sample'
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(instrumented_elf())
        return SimpleNamespace(exit_code=0,timed_out=False,stdout=b'',stderr=b'',
            stdout_bytes=0,stderr_bytes=0,stdout_truncated=False,
            stderr_truncated=False,stderr_tail=b'')
job=sut.build_job(executor_factory=lambda *_:FakeBuild())
accepted={'source_fingerprint':snapshot,'language_build_handoff_sha256':'a'*64,'receipts':[receipt]}
with patch.object(sut,'load_accepted_language_build',return_value=accepted):
    loaded=job.units[0].handler(ctx)
    built=job.units[1].handler(UnitContext(ctx.job,'build.units','build','units',ctx.unit_root,
        MappingProxyType({'load.accepted_native':loaded})))
    published=job.units[2].handler(UnitContext(ctx.job,
        'acceptance.publish_handoff','acceptance','publish_handoff',ctx.unit_root,
        MappingProxyType({'load.accepted_native':loaded,'build.units':built})))
assert published['counts']['instrumented_units']==1
inventory=build_inventory(InventoryInputs(run,run.name,snapshot,
    {sut.JOB_ID:('load','build','acceptance')},{sut.JOB_ID:DATASETS},
    {sut.JOB_ID:('job_language_build',)}, {},
    {sut.JOB_ID:{'load.accepted_native':'SUCCEEDED','build.units':'SUCCEEDED',
        'acceptance.publish_handoff':'SUCCEEDED'}},[]))
rows=[row for row in inventory['rows'] if row['job_id']==sut.JOB_ID]
assert any(row['output_kind']=='sanitizer_build_summary' for row in rows)
assert not any('build_unit_id' in row for row in rows)
with sqlite3.connect(':memory:') as db:
    db.execute('CREATE TABLE entities(payload_json TEXT)')
    db.executemany('INSERT INTO entities VALUES(?)',[(json.dumps(row),) for row in rows])
    count=db.execute(
        "SELECT count(*) FROM entities WHERE json_extract(payload_json,'$.job_id')=? "
        "AND COALESCE(json_extract(payload_json,'$.build_unit_id'),'')=?",
        (sut.JOB_ID,'unit-1')).fetchone()[0]
assert count==0
print(json.dumps({'published_counts':published['counts'],
    'inventory_datasets':[{'output_kind':r['output_kind'],'scope':r['scope'],
        'build_unit_id':r.get('build_unit_id')} for r in rows],
    'per_unit_inventory_filter_matches':count,'scratch':str(base),
    'elapsed_s':round(time.monotonic()-start,3),
    'limit':'Real handler publication and inventory projection plus equivalent SQLite filter; '
        'not full accepted GraphRunner/RetrievalCore execution'},indent=2))
```

Actual scratch: `test/tmp/job-audit-sanitizer-readiness-731a0f87674d412bacdcdf37b0e564df`.

There were no failed pytest or reproduction assertions. Read-only inspection limitations: UNC glob returned no skill matches (resolved with SSH `find`); Linux `rg` was absent (resolved with the UNC `rg` tool and Python/grep); guessed `schemas`, `operator`, `native_build.py`, and `runtime/unit.py` paths did not exist and were replaced by actual source locations. One oversized shell inspection was reread directly from source. None is a passing test or a source defect.

## Read coverage and material gaps

**Read fully**

- Authorized `AGENTS.md`, canonical multi-session coordination skill, shared audit brief.
- All five `src/appsec_review/jobs/job_sanitizer_build/*.py` files.
- Both sanitizer operations documents; `docs/architecture/job-input-contracts.md` through its current verification surfaces.
- All three mapped sanitizer unit files, `tests/sanitizer_support.py`, root/unit conftest files, and `tests/test_000_unit_environment_guard.py`.
- `job_language_build/elf.py`; `build_recipe_commands.py`; `build_output_scope.py`; `runtime/selection.py`; `storage/atomic.py`; `jobs/engineering_contracts.py`; shell wrapper and common launcher.

**Sampled/targeted**

- Language-build accepted loader, source copy, snapshot/kind/catalog boundary, interface environment, native/shared executor and protected-command recording; CodeQL replay resolver; declared-build-dir/symlink/recipe grammar helpers; raw source fingerprint.
- Real build executor constructor/resolve/signature/working-directory/ordinary execution path; beginning of captured executor only. Native broker, compiler measurement and capture internals not audited.
- Runtime registry/topology, consume through accepted readers, control validation, reference collection, producer outcome, required-output checks, final publication and shared publication/thread context. Whole runner/admission/resume state machine not read in full.
- Inventory row construction/artifact projection; review-data indexing consumption/metadata publisher; per-unit sanitizer query; the T-172 query fixture only.
- Sanitizer TOML, map entry, guidance-registry absence, relevant TODO entries (T-039/T-040, T-113 sanitizer section, T-147, T-172/T-175, T-003/T-026 context), and prior language/project/artifact-security/cumulative reports for overlapping findings.
- Testing architecture's selector/count/authorization working loop and supervised test wrapper sections.

**Material unread/unexecuted**

- Mapped integration `tests/integration/job_sanitizer_build/test_sanitizer_build_graph.py` and live `tests/live/test_sanitizer_live.py` bodies were not audited or executed.
- Real CMake/Meson/autotools/make, actual Clang/GCC and sanitizer runtime libraries, missing-runtime diagnostic diversity, PE/Mach-O/native cross-targets, large/stripped production ELF, sanitizer-instrumented dependency builds and shared install-product replay.
- Full accepted JobRunner/Dagster execution, real dataset/admission closure, cross-attempt concurrency, full per-unit readiness retrieval envelope, end-to-end downstream inference/report usefulness.
- No actual run artifacts or target-owned repository contents were read to assess live findings. Current symbol/control evidence is synthetic; no runtime behavior or target safety conclusion is made.
- No exhaustive read of unrelated job packages, whole TODO registry, image recipes, release/signature policy implementations, or every shared ELF/build parser test.

The checkout root was inspected for accidental audit output; only private ignored evidence directories and this session report were authored. No processes/services were left running. Audit stops after this job.
