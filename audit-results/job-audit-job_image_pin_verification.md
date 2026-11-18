# Job 2/50 audit — job_image_pin_verification

## Scope and verdict

- Audited **main at `3d1dc3d7304b829bd9750e359cb417661af54b9a`**, `/home/wsollers/projects/appsec-review`, through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`. HEAD, branch, clean tracked/untracked status and editable import provenance were verified before testing; HEAD and cleanliness were rechecked afterward.
- Read-only functional audit: no source edits, commits, image/service operations, models, targets, integration tests, acceptance tests or review runs.
- Every declared step/task was traced. **One newly isolated medium support-path defect, one reproduced previously reported medium gate-coverage defect, and one low documentation discrepancy** are recorded below.
- **125 unit cases passed**: 122 mapped job cases plus three environment-guard cases; 6.17 s pytest elapsed, 14.06 s supervised-wrapper elapsed, 14.260 s shell elapsed. No failures, errors, skips, xfails or tests over ten seconds.
- This is not certification of exact correctness, actual daemon readiness, successful live publication or downstream review quality.

## Registration, activation and input/output contract

`src/appsec_review/runtime/registry.py:67-68,119` registers the job with `container_runtime.build_executor._run`; `jobs/job_image_pin_verification/__init__.py` exports its factory. `appsec-review.toml:528-552` declares one worker for the job and each of its three steps, and `settings.enabled=true`. `config/image_pin_verification.py:19-37` accepts exactly that Boolean setting; `config/loader.py:1455-1457` applies the typed parser.

`jobs/job_image_pin_verification/datasets.py:28-36` declares:

- No accepted upstream inputs (`CONSUMES=()`).
- `schedule_after=("job_model_connectivity",)` — scheduling, not permission to consume its payload.
- Review-graph dispatch; `target_access=none`; `always_execute=True`; `propagate_handoff=False`.
- The next gate declares a scheduling dependency on this job (`jobs/job_target_acquisition/datasets.py:44`). Disabled-job graph contraction is implemented by `runtime/selection.py:11-44` and `orchestration/topology.py:47-83`; Dagster filters disabled registered jobs at `orchestration/dagster/adapter.py:409-411`.

Actual external inputs are the repository catalog, run-owned frozen `data/configuration/resolved.json`, run-owned frozen `host-pins.toml`, and inspection results. No target or other producer payload is read by any handler. The host file is checked against both its frozen SHA-256 and parsed document before pin selection (`job.py:74-91`). Catalog and frozen configuration hashes are recorded, not replaced with guessed values.

The sole declared dataset, `image_pin_verification`, is publication-step, internal, artifact-only, operational-authority metadata with schema `appsec-review/image-pin-verification/1`. Its three globs match:

1. `data/jobs/job_image_pin_verification/attempts/*/steps/selection/tasks/resolve_pins/image-pin-plan.json` — payload schema `appsec-review/image-pin-plan/2`.
2. `.../steps/verification/tasks/inspect_images/image-pin-verification.json` — payload schema `/image-pin-verification/1`.
3. `.../steps/publication/tasks/publish_handoff/image-pin-verification-handoff.json` — payload schema `/image-pin-verification/1`.

The plan's different domain schema is intentional, not an indexed-shard schema mismatch. The dataset exposes sanitized inventory metadata, not target-security evidence or payload retrieval (`datasets.py:7-18`; `runtime/datasets.py:143-148`). The artifacts have run-relative paths, hashes and byte sizes (`job.py:56-59`; `jobs/cataloging.py:274-277`).

`job_review_data_indexing` explicitly declares this producer's `/job-handoff/2` envelope and `/image-pin-verification/1` dataset as operational inputs (`jobs/job_review_data_indexing/datasets.py:62-65`). Actual downstream consumption was not executed.

## Complete step/task trace

All three tasks are present in both TOML and `TOPOLOGY`, and the claim validator rejects changed step/task ordering or an unwired inspection runner (`job.py:41-72`). No task has a model, persona, prompt, runtime-skill load or model invocation. Source inspection—not the generated “Undeclared” cells—establishes this.

| Declared step/task | Actual dispatch, input and processing | Validation and published output | Mismatch / coverage limit |
| --- | --- | --- | --- |
| `selection.resolve_pins` | `job.py:74-104`; dependency-free `Unit` at line 146. Reads catalog and two frozen input files; parses TOML/JSON; verifies host bytes/document; binds enabled non-manual catalog tags; recursively discovers image pairs in enabled jobs and enabled telemetry PDF reporting. | Typed settings, required files, parsing, frozen-host identity, catalog bindings and nonempty selection; writes hashed `image-pin-plan/2`; returns pins/count/artifact. | IP-F02: preinstalled CodeQL runtime IDs are explicitly excluded by the shared discovery walker. All normal file/refusal and host-hash branches have focused tests. |
| `verification.inspect_images` | `job.py:106-135`; depends on selection at line 147. Copies predecessor pins. `pins.py:54-90` runs one injectable `docker image inspect TAG --format {{.Id}}` per distinct tag, fixed 60 s timeout; retains separate source/expected-ID rows for duplicate tags. | Exact lowercase SHA-256 output check; missing/mismatch/inspection-error classifications; records plan reference, all results and one scoped retryable `producer_blocked` gap per failed reference. Emits events; writes evidence before `ImagePinVerificationFailed`. Success returns projected image fields and count. | The unit logic and error shapes are tested with fake runners, not live Docker. Direct `_run` subprocess/native/safety transport behavior was read selectively, not exercised. IP-D01 contradicts the diagnostic-gap behavior. |
| `publication.publish_handoff` | `job.py:137-143`; depends on verification at line 148. Reads only the successful verification output; does not inspect again. | Writes handoff payload with verification artifact and image rows; returns pin count, `terminal_status=SUCCEEDED`, `gaps=[]`. No bespoke output validator; generic runtime receipt/control/reference validation applies. | Focused tests verify exact payload, result, hash/size/path and dataset glob. Actual runtime finalization/admission is a deliberately unexecuted integration boundary. |

Runtime dispatch creates a Dagster op for every `Unit`, retaining dependency edges (`orchestration/dagster/adapter.py:250-278`), and calls the handler after verified dependency receipts (`runtime/runner.py:635-708`). The verification step maps to `owasp_verification`, selection/publication to the application fallback; this is existing routing, not evidence of a model call (`adapter.py:133-151`).

Failed tasks cannot reach accepted publication: `runtime/runner.py:969-976` verifies successful hashed task results, `:992-993` refuses an already-failed attempt, and `:1014-1020` rejects failed execution outcomes. Artifact collection checks referenced bytes and sizes (`runtime/handoff.py:61-111`). The legacy `UnitExecutor.execute` similarly records failure and skips blocked descendants (`runtime/units.py:103-120,164-178`).

Freshness is job-level (`runtime/resume.py:80-81`). Cross-attempt repair checkpoints are conservative: all three outputs contain `artifact`, which makes them nonportable (`runtime/checkpoints.py:25-40`), so they cannot be transplanted into a fresh attempt. Same-attempt unit retry receipt reuse exists in the shared runner; no broad live-resume guarantee was tested.

## Findings

### IP-F01 — Medium — Default pin updater still requires retired manual Joern/SVF images

- **Classification:** reproduced functional failure in the job-owned operator support path, not a failure of one of the three gate handlers. Newly isolated relative to the prior reports inspected.
- **Evidence:** `src/appsec_review/jobs/job_image_pin_verification/pins.py:121-134` selects every enabled catalog tag without the gate's `manual` exclusion and returns failure before publishing any host bindings if an unused image is absent. `containers/build.py:193-199` now excludes manual images from ordinary `--all` builds. `containers/catalog.toml:847-855,867-875` marks SVF/Joern manual; `appsec-review.toml:1791-1792,2333-2337` disables their jobs. `deploy/dagster/bin/ops_readiness.py:192-196` calls this updater, and `src/appsec_review/cli.py:188-201` turns its failures into exit status 1.
- **Trigger:** a newly provisioned host, or one that removes retired optional images, has every currently needed image but no Joern/SVF image.
- **Expected versus actual:** the default active-image build/pin sequence should not require rebuilding retired unused tools. The gate correctly selects 58 references/46 distinct tags and all match in the fake-daemon reproducer; the updater nevertheless checks 48 tags and refuses with exactly two missing-image failures for Joern/SVF.
- **Impact:** default `run-readiness pin`/`update-image-pins --write` cannot bootstrap or refresh otherwise-valid bindings. Existing WSL readiness evidence with all 48 tags available does not expose this clean-host failure.
- **Confidence:** high for reproduction and call-path impact. The updater historically intentionally included manual images; the inconsistency is with the newer default build/retirement policy, not an allegation that its old tests are failing.
- **Smallest correction:** exclude *unreferenced* manual catalog images from the default updater set, while retaining configured job/report references and an explicit operator path for manual images. Keep typed candidate validation and atomic publication. Add a real-config/fake-daemon regression with Joern/SVF absent. Existing `test_update_boundaries.py:63-65` actually asserts unconditional manual-image inclusion and therefore cannot detect this workflow mismatch.
- **Existing tracking:** T-168 (retirement, done), T-177 (active-image readiness, done), T-051 (host binding, done). No exact open TODO found.

### IP-F02 — Medium — Gate omits declared preinstalled CodeQL runtime IDs

- **Classification:** reproduced existing coverage defect, **not new**; narrowed reconfirmation of `docs/reviews/system-review-2026-11-13.md:735-744`, C04-F02.
- **Evidence:** `src/appsec_review/jobs/job_image_pin_verification/pins.py:40-46` delegates enabled-job discovery to `config/host_pins.py:87-99`, whose line 96 skips `preinstalled_runtimes`. Those declarations are present in the effective configuration (`host_pins.py:110-116`). `appsec-review.toml:1894-1902` says a declared environment uses its preinstalled runtime without fallback. Later runtime resolution inspects that exact ID and rejects its absence (`src/appsec_review/codeql/runtime.py:289-291`).
- **Trigger:** CodeQL is enabled and a valid frozen host file declares a runtime image that is absent when a new review starts—for example, removed after the prior operator pin update.
- **Expected versus actual:** an image-availability gate advertised as verifying the images selected by frozen review configuration should account for a declared preinstalled runtime, or explicitly narrow that promise. With the repository's valid synthetic preinstalled declarations, the real loader accepts two runtime IDs, but the gate's selector/verifier still reports all 58 references matched across 46 tags with **zero runtime-ID inspections**, even when the fake runner would report both runtimes missing.
- **Impact:** false-positive run-start readiness for those runtimes; failure is deferred until CodeQL resolution. This audit does **not** claim execution of an unverified runtime, a signing bypass, or that the current WSL inventory contains such missing runtimes.
- **Confidence:** high for selection omission and later static rejection path; conditional on a nonempty declaration set. Current host inventory was intentionally not inspected.
- **Smallest correction:** verify declared runtime/build IDs for enabled CodeQL alongside tag pins, preserving exact-ID semantics and existing signing policy. Do not change signature enforcement. If exclusion is retained as a deliberate boundary, explicitly state it in the gate's purpose/output claim rather than describing complete configured-image readiness.
- **Existing tracking:** C04-F02; T-051 is related and marked done. The unit `test_configured_pins_include_step_list_and_image_tag_pairs_but_not_preinstalled_runtime_ids` intentionally asserts the omission; passing it does not establish full configured-runtime coverage.

### IP-D01 — Low — Architecture and module prose still say failures never record gaps

- **Classification:** verified documentation drift, overlapping earlier C04-F03 rather than a new runtime defect.
- **Evidence:** `docs/architecture/jobs-and-runtime.md:507-512` says every enabled catalog image is checked and failures “never record[] a gap”; `src/appsec_review/jobs/job_image_pin_verification/job.py:7-8` repeats the no-gap claim. The actual selector excludes manual rows (`pins.py:33-35`), and the handler creates/persists one typed diagnostic gap per failed reference (`job.py:112-119`).
- **Trigger:** an operator reads the architecture/module summary while interpreting missing-image diagnostic artifacts.
- **Expected versus actual:** distinguish excluded manual catalog rows and retained diagnostic gaps from an **accepted** handoff containing gaps. The current canonical operations page already makes that distinction correctly.
- **Impact:** misleading expectations about the verified image set and location/existence of failure diagnostics; not erroneous accepted publication.
- **Confidence:** high.
- **Smallest correction:** align the two summaries with `docs/operations/job_image_pin_verification.md` and its “Gaps” section; keep failed attempts rejected.
- **Existing tracking:** C04-F03 (`docs/reviews/system-review-2026-11-13.md:746-755`); T-147 separately tracks undeclared task-binding metadata, not permission to infer execution or change pools.

## Prior-report reconciliation and preserved boundaries

- Prior job-pass/T-051 reports document catalog hashing, claim-time runner validation, typed failure evidence and frozen host bindings. Current source and focused tests cover them.
- C04-F02's broad “missing host binding becomes passing unpinned row” claim is **not reproduced through the real gate**: `bound_catalog_images` refuses absent enabled non-manual bindings (`host_pins.py:129-141`), and typed host parsing requires exact IDs. Low-level `verify_pins` still permits `present` for `image_id=None`, but the ordinary bound catalog path does not create those rows. Removing `present` is not justified by this audit alone.
- C04-F02 also mentions legacy `("image", "image_id")` discovery. That pair remains absent from `PIN_PAIRS`; the shipped `image=` setting belongs to third-party maintenance. No additional distinct active-review image miss was established, so it is not counted as another confirmed defect here.
- C04-F01 concerns other jobs' launch-time catalog binding; those call sites were not re-audited. Signature verification remains a separate configured policy, not an obligation newly imposed on this job.
- C04-F03's suggestion that failed jobs should have an accepted envelope is not adopted. Failure diagnostics and rejection are intentional. Its historical description of this gate emitting signature failures/`JOB_WARNING` does not match the handlers read here.
- T-147 remains an explicit declaration/documentation metadata gap. Source tracing confirms the actual deterministic tasks and Docker inspection, despite missing generated binding declarations.

## Validation commands and outcomes

All Linux commands below ran via the authorized SSH alias, using base64 transport from PowerShell when quoting was needed. No command used the Windows source checkout.

Common verification and environment preamble:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
[ "$(git rev-parse HEAD)" = 3d1dc3d7304b829bd9750e359cb417661af54b9a ]
[ -z "$(git status --porcelain)" ]
for name in $(compgen -e); do
  case "$name" in
    APPSEC_REVIEW_*|APPSEC_NATIVE_*|APPSEC_ACCEPTANCE_*|DAGSTER_HOME|PYTEST_ADDOPTS|APPSEC_PYTHON|PYTHONPATH)
      unset "$name" ;;
  esac
done
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Import result: `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. The pytest fixture layer supplies inert host pins under `test/tmp`, not production inventory.

### Exact collection

```bash
TIMEFORMAT='collection elapsed: %3R seconds'
time .venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-job_image_pin_verification-collect-20261118 \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_image_pin_verification/test_configuration.py \
  tests/unit/job_image_pin_verification/test_contract.py \
  tests/unit/job_image_pin_verification/test_host_pins.py \
  tests/unit/job_image_pin_verification/test_image_pin_update.py \
  tests/unit/job_image_pin_verification/test_job_graph.py \
  tests/unit/job_image_pin_verification/test_pins.py \
  tests/unit/job_image_pin_verification/test_update_boundaries.py
```

**125 collected, 2.36 s pytest / 3.781 s shell, exit 0.** Inspected all listed unit files and their fixtures before execution; external inspection is always faked.

### Guarded, bounded, shuffled execution

```bash
TIMEFORMAT='wrapper shell elapsed: %3R seconds'
time scripts/run-tests.sh --expect-tests 125 --parallel --test-workers 2 --strict -- \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_image_pin_verification/test_configuration.py \
  tests/unit/job_image_pin_verification/test_contract.py \
  tests/unit/job_image_pin_verification/test_host_pins.py \
  tests/unit/job_image_pin_verification/test_image_pin_update.py \
  tests/unit/job_image_pin_verification/test_job_graph.py \
  tests/unit/job_image_pin_verification/test_pins.py \
  tests/unit/job_image_pin_verification/test_update_boundaries.py \
  --shuffle-seed=20261118
```

**125 passed, 6.17 s pytest / 14.059546583 s wrapper / 14.260 s shell, exit 0.** Default bounds unchanged: maximum 200 tests, 30 s collection, 300 s total. Both collection/execution supervision reported cleanup confirmed and zero remaining processes. No test exceeded 10 s; slowest was `test_image_pin_update.py::test_write_changes_only_ignored_host_bindings_and_loads_every_consumer`, **0.438378 s** including setup/call/teardown.

| File under `tests/unit/job_image_pin_verification/` | Passed |
| --- | ---: |
| `test_configuration.py` | 9 |
| `test_contract.py` | 5 |
| `test_host_pins.py` | 8 |
| `test_image_pin_update.py` | 7 |
| `test_job_graph.py` | 33 |
| `test_pins.py` | 39 |
| `test_update_boundaries.py` | 21 |
| Environment guard (outside job directory) | 3 |

**Scratch naming limitation:** explicit collection used the requested job-prefixed scratch. The required wrapper owns/rejects overrides of its basetemp and uses its own unique `tests-custom-*` prefix; no guard was bypassed to rename it.

Retained evidence:

- `test/tmp/logs/tests-custom-20261117-233422-879301-106015.log`
- `test/tmp/tests-custom-20261117-233422-879301-106015.junit.xml`
- `test/tmp/tests-custom-20261117-233422-879301-106015.timings.sqlite`
- `test/tmp/tests-custom-20261117-233422-879301-106015.collection.json`
- `test/tmp/reports/tests-custom-20261117-233422-879301-106015.json`

### In-memory reproducer 1 — retired manual images

After the same environment cleanup, executed `time .venv/bin/python -` with:

```python
import json, time, tomllib
from pathlib import Path
from appsec_review.config import load_config
from appsec_review.config.host_pins import HostPins, bound_catalog_images, serialize_host_pins
from appsec_review.jobs.job_image_pin_verification.pins import configured_pins, update_pins, verify_pins
from tests.host_pins_support import fixture_bindings
root = Path.cwd()
start = time.monotonic()
host = root / 'test/tmp/job-audit-job_image_pin_verification-reproducer-20261118.host-pins.toml'
assert not host.exists()
images = tomllib.loads((root / 'containers/catalog.toml').read_text())['images']
bindings = fixture_bindings()
config = load_config(root / 'appsec-review.toml', profile='dev', overlay='',
                    host_pins=HostPins(host, serialize_host_pins(bindings, [])))
resolved = json.loads(config.resolved_json)
pins = configured_pins(bound_catalog_images(images, resolved), resolved)
missing = {row['tag'] for row in images if row['id'] in {'tool-joern', 'tool-svf'}}
assert len(missing) == 2
calls = []
def fake_inspect(argv, timeout):
    assert tuple(argv[:3]) == ('docker', 'image', 'inspect') and timeout == 60
    tag = argv[3]
    calls.append(tag)
    if tag in missing:
        return 1, b'', f'No such image: {tag}'.encode(), False
    return 0, (bindings[tag] + '\n').encode(), b'', False
verification = verify_pins(pins, fake_inspect)
assert all(row['status'] == 'matched' for row in verification)
assert not missing.intersection(calls)
print(json.dumps({'gate_references': len(pins), 'gate_distinct_tags': len(calls),
                  'gate_status': 'all matched',
                  'joern_enabled': resolved['jobs']['job_cpg_analysis']['settings']['enabled'],
                  'svf_enabled': resolved['jobs']['job_svf_alias_analysis']['settings']['enabled']}))
calls.clear()
report = update_pins(config_path=root / 'appsec-review.toml',
                     catalog_path=root / 'containers/catalog.toml', host_path=host,
                     profile='dev', write=False, runner=fake_inspect)
assert not report['written'] and len(report['failures']) == 2 and missing.issubset(calls)
assert not host.exists()
print(json.dumps({'updater_checked': report['checked'], 'updater_failures': report['failures'],
                  'written': report['written'], 'core_seconds': round(time.monotonic() - start, 4)}, indent=2))
```

**Exit 0; 0.9156 s measured core / 1.489 s shell.** Assertions demonstrate IP-F01, not correct expected workflow behavior: gate all matched (58/46), updater checked 48 and failed on exactly Joern/SVF. No files were written by this reproducer.

### In-memory reproducer 2 — missing declared preinstalled runtimes

After the same environment cleanup, executed `time .venv/bin/python -` with:

```python
import json, time, tomllib
from pathlib import Path
from appsec_review.config import load_config
from appsec_review.config.host_pins import HostPins, bound_catalog_images, serialize_host_pins
from appsec_review.jobs.job_image_pin_verification.pins import configured_pins, verify_pins
from tests.host_pins_support import fixture_bindings, fixture_preinstalled
start = time.monotonic()
root = Path.cwd()
bindings, runtimes = fixture_bindings(), fixture_preinstalled()
host = HostPins(root / 'test/tmp/job-audit-job_image_pin_verification-preinstalled-20261118.host-pins.toml',
                serialize_host_pins(bindings, runtimes))
config = load_config(root / 'appsec-review.toml', profile='dev', overlay='', host_pins=host)
assert config.job('job_codeql_analysis').settings['enabled'] is True
resolved = json.loads(config.resolved_json)
catalog = tomllib.loads((root / 'containers/catalog.toml').read_text())['images']
pins = configured_pins(bound_catalog_images(catalog, resolved), resolved)
missing = {item.runtime_image_id for item in config.job('job_codeql_analysis').typed_settings.preinstalled_runtimes}
assert len(missing) == 2
assert not missing.intersection(bindings.values())
calls = []
def fake_inspect(argv, timeout):
    assert tuple(argv[:3]) == ('docker', 'image', 'inspect') and timeout == 60
    ref = argv[3]
    calls.append(ref)
    if ref in missing:
        return 1, b'', f'No such image: {ref}'.encode(), False
    return 0, bindings[ref].encode(), b'', False
result = verify_pins(pins, fake_inspect)
assert all(item['status'] == 'matched' for item in result)
assert not missing.intersection(calls)
print(json.dumps({'declared_runtime_ids_missing': sorted(missing),
                  'gate_references': len(result), 'inspected_tags': len(calls),
                  'gate_result': 'all matched', 'runtime_inspections': len(missing.intersection(calls)),
                  'core_seconds': round(time.monotonic()-start, 4)}, indent=2))
```

**Exit 0; 0.9211 s measured core / 1.506 s shell.** Real typed configuration with two declared runtime IDs (`sha256:` followed by 64 `a` or `b` characters) produced zero inspections of either and 58 matched rows/46 inspected tags. This confirms IP-F02's omission; it is not a real-daemon or full-job run.

## Read coverage and material gaps

**Fully read:** authorized `AGENTS.md` and multi-session skill; both image-pin operations pages; all four job-package Python files; typed image-pin config; `config/host_pins.py`; `runtime/selection.py`, `runtime/units.py`, `runtime/checkpoints.py`; `orchestration/topology.py`; all seven mapped unit files plus their `support.py`; `tests/host_pins_support.py`; `tests/test_000_unit_environment_guard.py`; `scripts/run-tests.sh`; historical image-pin job-pass, Freeciv image-pin walk, T-051 and T-177 task records.

**Read in relevant ranges/searches:** base TOML job/CodeQL/retired-job blocks; catalog manual-image entries and machine-read catalog tags; config-loader dispatch; runtime registry; runner claim/reuse/execute/finalize/publication paths; handoff artifact validation and required-output entry; dataset helpers; Dagster op/pool/disabled selection wiring; `jobs/cataloging.py` write helper; build executor `_run`; native inspection/mapping functions and contract mapping; CodeQL job resolution/preflight and runtime-ID rejection; target-acquisition and review-data-indexing input declarations; test-map entry; conftest safety/timing/collection portions; guarded test-wrapper argument/command/report functions; operator test documentation; architecture interchange and image-gate sections; TODO T-051/T-147/T-168/T-177 and image-related search hits; earlier system review C04-F01–F03 and model-gate session report references.

**Material unread/unexecuted scope:**

- All integration, acceptance and live cases. The two mapped integration files were identified but not executed; actual graph publication, Dagster composition, fresh-attempt resume and immutable admission have static traces only.
- No real host pins, live Docker, signature envelopes, image contents, image-build/smoke, native broker/socket, safety controller or actual CodeQL runtime was probed.
- Native and execution-safety transport implementations were not audited end-to-end; their scoped routing is not a claim of plain-Docker equivalence.
- Other jobs were read only at directly relevant input/output or runtime-consumer boundaries, not audited. Full schema engine, retrieval inventory implementation, signer and target/build execution paths remain outside this job audit.
- No coverage instrumentation, alternate shuffle-seed run, exhaustive configuration enumeration or full suite. All 122 mapped cases passed once in parallel/shuffled execution; this is not proof of every possible ordering.
- Diagnostic artifacts from failed real attempts and quality of any real downstream output remain unverified. Historical successful host observations are prior reports, not current validation.

Owned synthetic fixture directories and their synthetic host-pin files were removed after testing; the listed logs, manifests, reports, junit and timing evidence remain. Final SSH verification still reported clean `main` at `3d1dc3d7304b829bd9750e359cb417661af54b9a`.

No repository changes were made. Stop after this job.
