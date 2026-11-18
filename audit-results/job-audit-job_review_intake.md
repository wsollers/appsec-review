# Job 4/47 correctness audit — `job_review_intake`

## Scope and verdict

- **Revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, branch `main`, clean before collection, execution, reproductions and completion.
- **Authorized source:** `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 on WSOLLERS1, accessed through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`. Python imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- **Scope:** this job's five steps and ten tasks, typed contract, configuration, registry/topology, necessary inventory/acquisition/publication/read-receipt helpers and downstream input expectations. No repository changes, commits, provider calls, target execution, Docker/service operations, integration/acceptance/live/Dagster runs or nested delegation.
- **Outcome:** two newly identified **medium** acquisition-boundary defects, plus the confirmed **medium** duplicate-gap defect already tracked as **T-095**. Existing model-catalog normalization drift is carried forward, not counted as another new finding.
- **Validation:** all **133 job-specific unit cases + 3 environment-guard cases passed**; pytest 6.67 s, wrapper shell 15.334 s. No failures, skips, xfails or cases over 10 s. Three in-memory characterizations confirmed the reported defects; they are not additional regression-test passes.
- Passing direct-handler units does not certify complete production execution or the usefulness of live output.

## Registration, activation and intended contract

`runtime/registry.py:121` registers the job with the real `inference.check_models` callback. `appsec-review.toml:578-611` declares the same five-step/ten-task order as `job.py:21-27,462-475`. No job-level `settings.enabled=false` is present: the central selection policy enables it (`runtime/selection.py:11-24`). The configured preflight timeout is 120 seconds; the input validator requires an integer in `[1,600]` and exact task order (`job.py:130-138`).

The typed contract is `jobs/job_review_intake/datasets.py:33-53`:

| Input interface | Schema | Treatment |
|---|---|---|
| `job_target_acquisition / target_acquisition` | `appsec-review/target-acquisition/1` | External, optional/gap, operational authority, partial coverage permitted |
| `job_target_acquisition / system_acquisition` | `appsec-review/target-system-acquisition/1` | External, optional/gap, operational authority, partial coverage permitted |
| `binary_publication / decompilation` | `appsec-review/binary-decompilation/1` | External, optional/gap, producer-evidence authority; configured individual binaries can nevertheless be required |

It schedules after `job_target_acquisition`, dispatches in the review graph, has checkout access, is reusable (`always_execute=False`), propagates its handoff and is strict about canonical gaps. `CONSUMES=()` is correct: there are no handoff-channel inputs. An acquisition job handoff is not interchangeable with the external manifest interface. Shared topology projects these scheduling edges and removes disabled vertices (`orchestration/topology.py:46-83`; `runtime/dependencies.py:12-54`).

Additional mandatory operational inputs are the run-owned frozen configuration, target root and planned raw source fingerprint. `Job.bind_input_identity` freezes one closed external-selection document and hashes that same selection (`runtime/job.py:110-128`). Intake includes the acquisition manifest digest and resolved binary identity/digest or named absence (`job.py:237-270`).

### Published outputs

All three declarations are internal artifact-only datasets, not retrieval indexes (`datasets.py:12-27`):

| Dataset/schema | Actual output relative to the attempt | Downstream expectation |
|---|---|---|
| `model_preflight`, `appsec-review/model-preflight/1` | `steps/model_preflight/tasks/verify_models/model-preflight.json` | Self-contained model-readiness evidence. Deliberately absent when a fixture constructs intake without a callback. |
| `binary_evidence`, `appsec-review/binary-evidence-intake/1` | `steps/binary_evidence/tasks/resolve_publications/binary-evidence.json` | Binary indexing reads the accepted intake reference, checks its digest/schema, then re-verifies the frozen publication's identity, binary hash and manifest hash (`job_binary_evidence_indexing/job.py:78-113`). |
| `review_intake`, `appsec-review/review-intake/1` | `steps/publish_intake/tasks/publish_handoff/review-intake.json` | Carries configuration, target path, raw fingerprint, coverage/acquisition, preflight and binary references. Tree-sitter/history/prioritization compare the fingerprint with accepted catalog data; evidence collection extracts the target path. |

The actual emitted paths match the declared globs. A copied `target-acquisition.json` is an observed external input, not a fourth dataset. Source history expects its `manifest` and `manifest_sha256` from `fingerprint.acquisition` (`job_source_history_analysis/job.py:190-207`).

The job has no bespoke output validators or result transform. Framework validation checks task result/receipt integrity, strict control fields, artifact hashes and declared required outputs; it does not supply semantic validation of every nested domain payload (`interchange.py:521-567`; `runtime/runner.py:960-1062`; `runtime/handoff.py:466-515`). The three dataset declarations themselves are optional. No missing artifact/glob mismatch was observed in the exercised ordinary handler paths.

## Every declared step and task

Paths in this table refer to `src/appsec_review/jobs/job_review_intake/job.py` unless otherwise specified.

| Step / task | Inputs, actual processing and outputs | Mismatch or validation limit |
|---|---|---|
| `model_preflight.resolve_models` | `:277-281`; hash-verified `resolved.json`; traverses mapping-valued model settings, ignores pending jobs, splits enabled-job/enabled-model references from disabled ones; returns required/optional reference lists and distinct required-pair count. Shared functions `:141-183`. | Direct units cover ordering, deduplication, enabled policy and resolved rather than base config. No inference/prompt generation here. |
| `model_preflight.verify_models` | `:283-311`; depends on resolution; checks sorted distinct names once per provider with the configured timeout; writes the full diagnostic and completion event before required-model refusal; optional failures become retryable `producer_blocked`. An unwired fixture returns explicit `NOT_APPLICABLE` without a file or completion event. | Intended T-053 boundary preserved. Actual provider/SDK/network behavior not exercised. Existing volatile-catalog comparison defect remains; see carry-forward. |
| `resolve_configuration.fetch_config` | `:313-315`; reads the first manifest source identity. | Deliberately not a current-host-file read. Corruption handling is covered by config units and runtime binding, not this small selector alone. |
| `resolve_configuration.resolve_layers` | `:317-377`; depends on source; verifies resolved-document hash, required final host-pins layer and its actual bytes/document; checks profile/overlay identities, order, allowed keys and recorded keys; returns ordered layers/profile/strategy. | All four layer combinations and host/profile/overlay mismatch branches exercised. Profile/overlay identities are verified against frozen records, not re-read mutable host files. |
| `resolve_configuration.freeze_config` | `:379-384`; depends on layers; returns the run-owned base TOML path/current digest and verified layers/profile. | Runtime `_bind_configuration` independently checks existing frozen base/resolved/host-pins hashes (`runtime/runner.py:61-113`). No requirement to rewrite or re-fetch configuration inferred. |
| `prepare_target.resolve_target` | `:386-388`; strict path resolution; returns absolute path and directory kind. | Existing/missing/None paths covered; actual large target directories not inspected. Inventory subsequently rejects an empty/nonusable target. |
| `prepare_target.validate_target` | `:390-399`; inventories with effective per-file bound and exclusions; rejects no retained bounded files; publishes counts, raw gaps, canonical gaps, exclusions/assets and discovery counters. | **RI-F02/T-095:** its canonical gaps are published again. Tests exercise size boundary, symlink, exclusion and empty/binary/oversize input. Shared inventory uses descriptor treatment and a NUL-sample heuristic; not a full text-decoding guarantee. |
| `prepare_target.fingerprint_target` | `:401-407`; depends on validation; hashes all regular non-VCS bytes and symlink identities, including catalog exclusions; refuses divergence from planned fingerprint; copies/observes matching acquisition. | **RI-F01, RI-F03** affect acquisition. Legacy algorithm label is documented, not proof of bounded hashing. Real content-change unit passed; external acquisition is mocked in job-specific units. |
| `binary_evidence.resolve_publications` | `:409-436`; resolves every configured current publication without Ghidra; verifies store chain; checks processor/compiler/loader/debug-symbol request identity; required failure rejects, optional failure records bounded reason and retryable `input_unavailable`; observes resolved identities, writes evidence/events. | Fake publication-store boundaries in unit tests; real store verifier reviewed statically. Existing publication coverage/gaps remain payload details for indexing; a valid partial publication is not falsely represented as fully decompiled. |
| `publish_intake.publish_handoff` | `:438-460`; depends on all four branches; writes the aggregate intake artifact and references; converts inventory/acquisition gaps; leaves binary/preflight gaps on their observing units. | **RI-F01:** absent acquisition becomes no acquisition gaps even if previously admitted. **RI-F02:** duplicates inventory gap ownership. Actual job finalization/dataset inventory not executed in this audit. |

All ten tasks are reachable and have matching configuration entries. Dependency closure gives publication access to target resolution through validation/fingerprinting and to model resolution through verification. Independent branch failure prevents publication without needing to discard other diagnostic outputs.

### Guidance and provider boundary

There are no intake bindings in `pipeline/guidance/registry.json`. The implementation performs deterministic configuration/target/publication work and availability checks, not a review role/persona/task prompt. The generated “Undeclared” tool bindings are the existing **T-147** declaration gap, not evidence that no provider operation occurs.

`inference/__init__.py:101-126` chooses the registered provider availability implementation, normalizes requested-model absence and preserves provider errors. Copilot's implementation lists catalog/policy state (`inference/copilot_sdk.py:90-100`), not inference execution. Live credentials, transport, optional first-error safety policy and downstream inference budgets were not tested.

## Findings

### RI-F01 — Medium — A claimed acquisition can disappear and become successful “no acquisition”

- **Classification/confidence:** reproduced handler/read-boundary defect, high confidence. Complete runner publication/reuse was not executed; acceptance/reuse consequences are supported by the static runtime trace.
- **Evidence:** selection pins an available acquisition at `src/appsec_review/jobs/job_review_intake/job.py:242-254`; execution re-discovers it at `src/appsec_review/target_acquisition/acquire.py:548-550`. `_acquisition` only observes non-None results and otherwise returns None (`job_review_intake/job.py:99-110`). Publication treats None as an empty acquisition-gap list (`:452-455`). All acquisition requirements are optional (`datasets.py:35-40`), so `runtime/inputs.py:587-607` requires no receipt for the previously supplied selection.
- **Trigger:** the selected external manifest is removed, renamed, becomes unreadable, or becomes undiscoverable after claim creation but before the fingerprint task reads it. A temporary disappearance followed by restoration is especially important.
- **Expected:** preserve the exact claimed acquisition or reject its loss/mismatch; an initially absent manifest may legitimately remain not applicable.
- **Actual:** the real helper returns None, records no read receipt, and the publication handler returns `SUCCEEDED` with no acquisition gaps. The original acquisition can contain `component_not_acquired`, yet that information disappears. Restoring identical manifest bytes restores the original external-input identity.
- **Impact:** intake and source-history consumers can lose provenance and acquired-coverage gaps without a corresponding failure/gap. Since no retryable gap remains and resume compares the restored identity (`runtime/resume.py:133-135,187-188`), the identity check does not itself force repair of this missing-evidence result.
- **Reproduction:** claimed an available system manifest containing a missing-component gap, made the discovery boundary return None during the real `_acquisition` call under `input_read_scope`, invoked the real publication handler and `verify_external_inputs`, then restored selection. Observed `acquisition=None`, zero read receipts, `SUCCEEDED`, `gaps=[]`, unchanged restored input identity.
- **Smallest correction:** make acquisition lookup consume/check the claim's selection, refusing a missing selected manifest rather than collapsing it to initial absence. Add a direct unit for available → missing (and malformed/unreadable) transitions with actual read-scope enforcement.
- **Existing tracking:** no matching item found in the relevant TODO/prior-report searches. Related declared invariant: `docs/architecture/job-input-contracts.md:83-94`.

### RI-F02 — Medium — Every inventory omission is counted twice (existing T-095)

- **Classification/confidence:** reproduced canonical-gap defect, high confidence; **already tracked**, not new.
- **Evidence:** `src/appsec_review/jobs/job_review_intake/job.py:396` emits each inventory gap under `prepare_target.validate_target`; `:452` emits it again under `publish_intake.publish_handoff`. `src/appsec_review/interchange.py:578-584` includes unit identity in the gap ID. `src/appsec_review/runtime/handoff.py:318-325` merges by that ID and counts both records.
- **Trigger:** any non-policy inventory gap, such as `file_too_large` or `symlink_excluded`.
- **Expected:** one canonical omission record per actual missing path/cause; the intake document can still repeat its raw coverage detail.
- **Actual/impact:** one oversized path produces two distinct canonical gap IDs. Outcome gap counts and consumers that echo them overstate missing coverage twofold. This is not two separate missing files.
- **Reproduction:** invoked the actual coverage converter and actual publication handler for one `large.py / file_too_large` record; each returned one canonical record, with different gap IDs.
- **Smallest correction:** give one unit ownership of canonical inventory gaps; retain the raw coverage list and keep terminal coverage accurate. Verify one canonical record through runner accounting when that validation is authorized.
- **Existing tracking:** **T-095**, `docs/TODO.md:1659-1672`; historical Freeciv walk references the same issue. Existing unit tests assert both handler behaviors separately and therefore do not expose the aggregate duplication.

### RI-F03 — Medium — Acquisition payloads are copied without validating gap shape or identity consistency

- **Classification/confidence:** reproduced malformed-input acceptance, high confidence at the intake helper. It requires a malformed/corrupted imported acquisition record; no claim that the ordinary acquisition producer currently emits this shape.
- **Evidence:** `src/appsec_review/target_acquisition/acquire.py:578-583` selects on recognized schema and target path. `:551-555` parses/copies the manifest and silently drops every non-mapping gap member; `:560-563` copies `identity`/`identity_sha256` without checking their relationship. In contrast, the producer constructs the identity digest at `:156` and `:464`. Intake merely hashes the copied bytes for the external observation (`src/appsec_review/jobs/job_review_intake/job.py:102-109`); a digest of current bytes is not validation of the payload's internal claims.
- **Trigger:** a matching JSON manifest with an invalid gap member and/or inconsistent `identity_sha256`, while its target tree digest still matches.
- **Expected:** reject malformed acquisition evidence explicitly (or preserve a named invalid-input gap), rather than quietly converting its missing coverage into absence. Validate the existing identity representation; no new signing policy is proposed.
- **Actual/impact:** a manifest with `gaps=["component_not_acquired"]` and an incorrect identity hash is copied, returns `tree_matches=True`, an empty gap list and the incorrect identity hash. Publication can then omit the malformed coverage fact. Downstream source-history input sees this as the accepted acquisition binding.
- **Reproduction:** ran the real `intake_record` parser/copy/projection against in-memory filesystem bytes, faking only manifest discovery and filesystem operations. It accepted the inconsistent hash, dropped the gap and copied the original malformed bytes.
- **Smallest correction:** validate the selected acquisition schema/required field types and canonical identity digest before copying/projection; reject invalid gap entries instead of filtering them. Add focused valid-system/component and malformed-gap/hash tests.
- **Existing tracking:** no matching TODO found. The operations page overstates this boundary: it calls the copied manifest “verified” (`docs/operations/job_review_intake.md:151`) and says invalid manifests reject (`:207-208`). Fixing the code and tightening that description belong together; this prose discrepancy is not a separate new defect.

## Prior findings and preserved decisions

- **Existing medium normalization drift, not a new job-audit finding:** unrelated advertised model IDs still enter the preflight artifact through `inference/copilot_sdk.py:90-100` and `job_review_intake/job.py:207-208,295-298`. `acceptance/normalize.py:249-263,324-333` signs normalized JSON artifacts, retaining this volatility. The current source was inspected; live baseline comparison was not run. This is the same root cause as prior **MC-F01** and the intake-specific historical note in `docs/tasks/2026-11-08-job-pass-04-review-intake.md:153-169`, tracked under **T-057**. Do not double-count it in the cumulative audit.
- **T-053:** keeping intake's self-contained model preflight and explicit unwired-fixture behavior is a recorded decision. Duplicate provider checking is not reopened as a new correctness defect.
- **T-054:** historical downstream undeclared-consumption fixes are marked done. Relevant current binary-indexing declarations/read path were checked, not reported again.
- **T-147:** generated task/tool-binding declarations remain incomplete. The real handlers were traced rather than interpreting “Undeclared” as nonexecution.
- Prior jobs 1–3 reports remain evidence for their older `3d1dc3...` revision, not validation of this revision. Their findings were searched for overlap; no re-audit or rerun of those jobs occurred.
- A component-root lookup beneath the newer nested acquisition layout, binary/text descriptor edge cases, and exhaustive malformed provider-response shapes were not established as additional defects. They are outside the executed cases and are not asserted failures here.

## Focused validation commands and results

### Transport, identity and environment

Linux scripts below were sent unchanged by base64 transport:

```powershell
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
    "printf %s $encoded | base64 -d | bash"
```

Before tests/reproductions:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
env | cut -d= -f1 | grep -E '^(APPSEC_|DAGSTER_HOME$|PYTEST|PYTHON)' || true
export PYTHONDONTWRITEBYTECODE=1
```

No matching inherited configuration/test/Python environment selectors were present. The existing environment guard ran, including xdist preflight. No packages were installed and no guards/bounds/assertions were relaxed.

### Collection

```bash
TIMEFORMAT='collection shell elapsed: %3R seconds'
time .venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-job_review_intake-collect-20261118 \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_review_intake/test_binary_evidence.py \
  tests/unit/job_review_intake/test_configuration.py \
  tests/unit/job_review_intake/test_contract.py \
  tests/unit/job_review_intake/test_models.py \
  tests/unit/job_review_intake/test_target.py
```

**136 collected**, pytest 2.77 s, shell 4.437 s, exit 0. Every selected job file and its support fixture was read before execution. Provider checks, publication store and acquisition boundaries are synthetic/faked; the selection does not launch real Git/P4/Ghidra/Docker/provider commands.

### Guarded execution

```bash
TIMEFORMAT='wrapper shell elapsed: %3R seconds'
time scripts/run-tests.sh --expect-tests 136 --parallel --test-workers 2 \
  --shuffle-seed 20261118 --strict -- \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_review_intake/test_binary_evidence.py \
  tests/unit/job_review_intake/test_configuration.py \
  tests/unit/job_review_intake/test_contract.py \
  tests/unit/job_review_intake/test_models.py \
  tests/unit/job_review_intake/test_target.py
```

**136 passed**, pytest **6.67 s**, shell **15.334 s**, exit 0. Supervised collection 4.223644 s; supervised execution 10.547444 s. Default limits unchanged: 200 tests, 30-s collection, 300-s total. Both process-supervision stages confirmed cleanup with zero remaining processes.

| Selection | Passed |
|---|---:|
| `test_binary_evidence.py` | 30 |
| `test_configuration.py` | 48 |
| `test_contract.py` | 16 |
| `test_models.py` | 20 |
| `test_target.py` | 19 |
| Environment guard | 3 |

No FAILED/ERROR nodes, skips, xfails or >10-s cases. Slowest case: `tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing`, **0.397566 s** including setup/call/teardown.

The wrapper owns basetemp and rejects overrides, so execution used its unique `test/tmp/tests-custom-*` scratch rather than the requested job-prefix naming; collection used the job-prefix path. This existing harness restriction was not bypassed. Only this invocation's disposable fixture directories and corresponding host-pins files were removed. Reports/logs/junit/timings were retained:

- `test/tmp/logs/tests-custom-20261118-102945-969048-2196865.log`
- `test/tmp/logs/tests-custom-20261118-102945-969048-2196865.collection.log`
- `test/tmp/tests-custom-20261118-102945-969048-2196865.collection.json`
- `test/tmp/tests-custom-20261118-102945-969048-2196865.junit.xml`
- `test/tmp/tests-custom-20261118-102945-969048-2196865.timings.sqlite`
- `test/tmp/reports/tests-custom-20261118-102945-969048-2196865.json`

No coverage instrumentation was run; prior full-line/branch-coverage claims in TODO were not adopted as this audit's measurement.

### Exact in-memory reproduction

The same source/cleanliness checks and `PYTHONDONTWRITEBYTECODE=1` preceded this command. All paths below are synthetic names; filesystem writes are intercepted.

```bash
TIMEFORMAT='reproducer shell elapsed: %3R seconds'
time .venv/bin/python - <<'PY'
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from time import perf_counter
from appsec_review.jobs.job_review_intake import job as intake
from appsec_review.runtime import inputs
from appsec_review.target_acquisition import acquire

started = perf_counter()
root = Path.cwd()
run = root / 'test/tmp/job-audit-job_review_intake-memory-20261118/run'
unit_root = run / 'data/jobs/job_review_intake/attempts/attempt_0001/steps/prepare_target/tasks/fingerprint_target'
manifest_path = root / 'test/tmp/job-audit-job_review_intake-memory-20261118/records/system/manifest.json'
schema = 'appsec-review/target-system-acquisition/1'
document = {'runtime': {'data_dir': 'data'}, 'jobs': {}}
manifest = {'schema': schema, 'target_path': str(root), 'status': 'PARTIAL',
            'tree': {'sha256': 'a' * 64}, 'gaps': [{'path': 'missing', 'reason': 'component_not_acquired'}]}
raw = json.dumps(manifest).encode()
context = SimpleNamespace(run_root=run, repository_root=root, target_root=root,
                          config=SimpleNamespace(job_id='job_review_intake'),
                          contract=intake.CONTRACT, upstream_handoffs={}, optional_prior_handoffs={})
unit = SimpleNamespace(job=context, unit_id='prepare_target.fingerprint_target', unit_root=unit_root)
job = intake.build_job()
original_read_bytes = Path.read_bytes

def read_bytes(path):
    if path == manifest_path:
        return raw
    if path == run / 'data/configuration/resolved.json':
        return json.dumps(document).encode()
    return original_read_bytes(path)

saved = []
def write_json(path, value):
    payload = json.dumps(value, sort_keys=True).encode()
    saved.append(value)
    return {'path': str(path), 'sha256': hashlib.sha256(payload).hexdigest(), 'size_bytes': len(payload)}

with patch.object(intake, 'resolved_configuration', return_value=document), \
     patch.object(acquire, 'find_acquisition', side_effect=[manifest_path, None, manifest_path]), \
     patch.object(Path, 'read_bytes', read_bytes), patch.object(intake, 'write_json', write_json):
    initial_identity, context.external_input_selection = job.bind_input_identity(root, run, repository_root=root)
    selected = context.external_input_selection['inputs'][1]
    assert selected['status'] == 'available'
    with inputs.input_read_scope(context) as reads:
        record = intake._acquisition(unit, 'a' * 64)
    assert record is None and reads.document()['reads'] == []
    outputs = {
        'resolve_configuration.freeze_config': {'path': 'data/configuration/appsec-review.toml', 'sha256': 'b' * 64},
        'prepare_target.resolve_target': {'path': str(root), 'kind': 'directory'},
        'prepare_target.fingerprint_target': {'sha256': 'a' * 64, 'coverage': {'coverage_gaps': []}, 'acquisition': record},
        'model_preflight.verify_models': {'schema': intake.PREFLIGHT_SCHEMA, 'verified': []},
        'binary_evidence.resolve_publications': {'schema': intake.BINARY_EVIDENCE_SCHEMA, 'binaries': []},
    }
    publish = next(u.handler for u in job.units if u.unit_id == 'publish_intake.publish_handoff')
    publication_unit = SimpleNamespace(job=context, unit_id='publish_intake.publish_handoff',
                                      unit_root=run / 'data/publication', output=outputs.__getitem__)
    result = publish(publication_unit)
    inputs.verify_external_inputs(context, [])
    restored_identity, _ = job.bind_input_identity(root, run, repository_root=root)
    assert result['terminal_status'] == 'SUCCEEDED' and result['gaps'] == []
    assert initial_identity == restored_identity
    print('RI-F01: admitted available acquisition -> disappearance -> no receipt, acquisition=None, SUCCEEDED/no gaps; restored selection identity unchanged')
    gap = {'path': 'large.py', 'reason': 'file_too_large'}
    validation_gaps = intake.coverage_gap_records('prepare_target.validate_target', [gap])
    outputs['prepare_target.fingerprint_target']['coverage']['coverage_gaps'] = [gap]
    publication_gaps = publish(publication_unit)['gaps']
    assert len(validation_gaps) == len(publication_gaps) == 1
    assert validation_gaps[0]['gap_id'] != publication_gaps[0]['gap_id']
    print('RI-F02/T-095: one omitted path produces two distinct canonical gap IDs in validate and publish')

# Real intake_record parser and selector; the filesystem is an in-memory external boundary.
raw = json.dumps({**manifest, 'status': 'COMPLETE', 'identity': {'component': 'changed'},
                  'identity_sha256': '0' * 64, 'gaps': ['component_not_acquired']}).encode()
writes = []
with patch.object(acquire, 'find_acquisition', return_value=manifest_path), \
     patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'mkdir'), \
     patch.object(Path, 'write_bytes', lambda path, data: writes.append((path, data)) or len(data)):
    record = acquire.intake_record(repository_root=root, records_dir='data/target-acquisitions',
                                   target_root=root, tree_sha256='a' * 64,
                                   destination=unit_root / 'target-acquisition.json')
    assert record['tree_matches'] is True and record['gaps'] == []
    assert record['identity_sha256'] != hashlib.sha256(acquire._canonical(record['identity'])).hexdigest()
    assert writes[0][1] == raw
    print('RI-F03: invalid acquisition gap member silently dropped; inconsistent identity_sha256 accepted and copied')
print(f'Reproducer body: {perf_counter() - started:.6f}s; no files written or providers called')
PY
```

Exit 0. All three printed defect characterizations confirmed. Measured body **0.035323 s**, shell **0.527 s**. These assertions deliberately characterize incorrect behavior; no corrective regression was added in this read-only audit.

## Read coverage and explicit gaps

**Fully read:** authorized `AGENTS.md`; canonical multi-session coordination skill; operations `job_review_intake.md`; job package `__init__.py`, `job.py`, `datasets.py`; all five `tests/unit/job_review_intake/test_*.py` files and `support.py`; environment guard; `jobs/cataloging.py`; `config/binary_decompilation.py`; `runtime/job.py`, `runtime/selection.py`, `runtime/dependencies.py`, `runtime/units.py`, `runtime/resume.py`; `docs/architecture/job-input-contracts.md`; historical `docs/tasks/2026-11-08-job-pass-04-review-intake.md`; test shell/common wrappers.

**Read in relevant ranges/searches:** `target_acquisition/acquire.py` 1–207 and 325–584, with materialization/export search excerpts; binary publication verification and current-resolution functions; runtime inputs 1–320 and 330–610; runner configuration binding, task/read-scope execution and final publication; handoff artifact collection, producer-gap accounting and required-output validation; interchange control/gap helpers; registry registration; topology projection; downstream binary-indexing 1–175, Tree-sitter 45–90, source-history 175–210, and evidence-collection/prioritization input-use searches; base TOML job block; guidance registry search; exact job-test-map entry; test harness/conftest 1–300 and operator parser/execution sections; testing architecture selector/wrapper sections; TODO T-053/T-054/T-057/T-095/T-147 and relevant searches; previous session audit finding sections; model catalog/acceptance-normalization ranges; acquisition helper fixture tests 663–685 by search excerpts. Integration test names were inspected only, not executed.

The pointer skill initially exposed the default Windows checkout's `AGENTS.md`/skill listing before the brief was read. No job implementation or tests from that checkout were audited or executed; all source evidence and validation above are from the authorized UNC/SSH WSL checkout.

**Material unverified scope:**

- Full runner/graph execution, accepted artifact inventory, production publication and actual resume/reuse of this job. The mapped integration files and Wave 1 resume selections were not run.
- Live model authentication/availability, first-error safety cancellation, provider payload shape variations, binary store/Ghidra execution, and real acquired-system/component trees/artifacts.
- Downstream job execution and end-to-end finding/report quality. Only relevant reader expectations were inspected; those jobs were not separately audited.
- Exhaustive inventory bounds/permissions/special-file/mutation races, binary verifier efficacy and complete malformed-domain-schema cases. Existing direct units fake the store/acquisition boundaries, so they do not prove those dependencies correct.
- Performance on large targets: inventory and fingerprinting both traverse/hash target bytes; no benchmark or live target scan was authorized.
- Historical acceptance records and external manifests were not treated as fresh validation. No integration/acceptance/live test was represented as passing.

Completion inspection found the authorized checkout still clean at the exact required SHA. Unrelated existing ignored root material was left untouched. This report is the only authored deliverable; stop after `job_review_intake`.
