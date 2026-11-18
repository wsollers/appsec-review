# Job 17/47 audit — `job_profile_data`

## Scope and verdict

- Audited **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, branch `main`, in **`/home/wsollers/projects/appsec-review`**, Ubuntu-22.04 through `ssh wsl-ubuntu` and the authorized UNC path. HEAD and clean status were verified before and after testing. The editable import resolved to that checkout's `src/appsec_review/__init__.py`.
- Read-only functional audit. No repository/environment edits, installs, services, profilers, models, target execution, integration/live/Dagster runs, or subagents. Only this session report was written; the existing unit wrapper produced isolated ignored test evidence.
- **57 focused units passed**: 51 dedicated job cases, five relevant shared admission/disabled-producer cases, and the environment guard. Pytest **7.52 s**, wrapper **16.805274734 s**, no failures/skips/tests over 10 s.
- **Ten findings below: seven medium and three low**, including one narrowed reconfirmation of an existing historical finding. Passing units do not establish profile correctness: several tests assert the currently incorrect producer/consumer behavior.
- No high-severity finding, live output-quality certification, or admitted stale-cache failure is claimed.

## Registration, inputs, outputs, and configuration

`runtime/registry.py:83,153` registers the factory. It is enabled by default: the central job has no `settings.enabled=false`; `runtime/selection.py:11-24` enables such jobs. Computed enabled topology gives the immediate predecessor **`job_artifact_indexing`**. Contract dispatch is `review_graph`, target access is `checkout`, `always_execute=False`, and `propagate_handoff=True` (`jobs/job_profile_data/datasets.py:68-72`). No direct target tree scan occurs.

### Accepted input inventory

All 19 declarations use handoff-channel producer evidence and allow partial coverage. The three envelope declarations are actually read through `accepted_upstream`; declaration is not proof of reading every constituent dataset.

| Producer | Every declared input | Actual use |
| --- | --- | --- |
| `job_target_catalog` | `handoff` required/reject; optional/gap `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents` | `_load_catalog_identity` reads the bound catalog publication, checks its tag/fingerprint and optional bound manifest. It does not load catalog source rows or resolve profiler names to source locations. |
| `job_language_build` | `handoff` when-enabled/reject; optional/gap `topology_refinement_inputs`, `build_actions`, `jvm_build_actions`, `language_build_receipts`, `build_workspaces` | `load_accepted_language_build(..., for_execution=False)` supplies receipt JSON. Only receipt artifacts with `kind=execution-profile` are ingested. No build is executed or rediscovered. |
| `job_artifact_indexing` | `handoff` when-enabled/reject; optional/gap `artifact_catalog`, `archive_members`, `artifact_relationships`, `artifact_index_summary` | Accepted summary/snapshot and verified inherited index manifest; profile candidates still come from language-build receipts, not an artifact-tree scan. |

Declarations: `jobs/job_profile_data/datasets.py:24-67`. Readers: `job.py:70-124,291-317`; language reader `jobs/job_language_build/job.py:128-172`; artifact reader `jobs/job_artifact_indexing/job.py:958-977`.

The actual shared-unit fixture's `load.accepted_inputs/status.json` recorded two envelope reads (`job_target_catalog/handoff`, `job_language_build/handoff`) when artifact indexing was disabled. Its normalize/index/acceptance read arrays were empty. These private JSON/file reads are not separately observed dataset reads; `docs/architecture/job-input-contracts.md:121-165` explicitly describes bounded instrumentation, not arbitrary-filesystem observation. Do not claim all 19 datasets were consumed.

### Every declared task/step

| Step.task | Implementation and processing | Publication/error behavior and audit result |
| --- | --- | --- |
| `load.accepted_inputs` | `job.py:291-317`; catalog identity, optional accepted build and artifact-index loaders, snapshot comparison, upstream hashes, manifest fallback. | Required/enabled envelope absence rejected by admission. Disabled upstreams add explicit unavailable text gaps. Artifact-disabled fallback verifies the attempt input manifest or catalog manifest. Dedicated/shared units exercise these branches. |
| `normalize.profile_data` | `job.py:319-321` → `ingest_profile_artifacts`, `:174-255`; sorted units/artifacts, kind filter, origin/hash/path checks, duplicate path/hash check, bounds, format detection, parser dispatch, row provenance, ranks/population and coverage. | Integrity contradictions raise; parser `ValueError` becomes `malformed_profile`; missing/opaque/ambiguous/truncated data produces gaps. PD-01–04 and PD-09 concern this path or its output. |
| `index.profile_data` | `job.py:323-373`; verify inherited manifest; remove only `analysis/profile-data-*`; fingerprint per build; build/attest immutable SQLite; one hotspot per row plus one coverage row; write/reverify composed manifest. | PD-01 aborts the real index handler before publication. Existing reuse with unchanged inputs is tested. Missing bounds in local keys is a conditional concern, not a demonstrated admitted runtime defect. |
| `acceptance.publish_handoff` | `job.py:375-394`; JSON `/1` summary with upstream hashes, parser identities, build units, interpretation/gaps and manifest; `item_count=sum(len(rows))`. | `COMPLETED_WITH_GAPS` if any load/normalization reason; else `SUCCEEDED` with units, `NOT_APPLICABLE` without units. Counts are normalized rows, not reports or total samples. PD-04 demonstrates malformed input reaching success. |

All four task dependencies are explicit (`job.py:396-406`). The real runner invokes these handlers under admitted upstream/read/publication scopes (`runtime/runner.py:683-724`); handler failure records a failed task and prevents dependent normal publication. The simpler `UnitExecutor` also preserves dependency failures (`runtime/units.py:83-209`). There is no job-specific prompt/model/converter/tool invocation; no matching job entry was found in the guidance registry or container catalog. Missing declared task bindings remain **T-147**, not proof supplied by generated documentation.

### Bounds and parser semantics

`appsec-review.toml:1624-1654` sets identities `/1`, 256 artifacts, 33,554,432 bytes/artifact, 250,000 input/normalized rows per artifact, 65,536 bytes/line and 256 frames/sample. `_validate_config` requires exact step/task order, a bounds mapping and exact identity strings (`job.py:266-287`). `ProfileBounds.from_mapping` integer-coerces known keys, ignores unknown keys and defaults missing keys; it checks positivity, not a separate hard ceiling (`:52-66`). Job/step worker settings are capacity declarations; each step contains one actual handler and normalization itself loops serially.

| Format | Actual aggregation and mapping |
| --- | --- |
| Folded stacks | Every retained frame occurrence contributes its stack count. Aggregates by frame string; source/module/line remain null. Keeps the last bounded frames and records truncation. Inclusive per-frame semantics are explicitly documented; recursive-frame counting is not reclassified here as a new defect. |
| Perf script | Recognized sample header opens an event; indented frames contribute one count each, with optional module. Unknown symbols and excess frames create gaps. PD-03: period-bearing headers split one event into several. |
| Callgrind | Resolves file/function reference IDs, absolute/relative/repeated positions and event columns. Emits symbol/event/source/line rows. PD-02: call-edge costs combine callee identity with caller position, without distinguishing self and inclusive call costs. |
| LLVM sample | Only top-level textual function headers contribute total samples; indented body/inline records are intentionally ignored. PD-04 concerns malformed **top-level headers**, not the intentionally excluded body. |

All parsers reject NUL/invalid UTF-8, bound retained input lines/line bytes, and reject wholly empty/unrecognized results. Row expansion is aggregated before the ingestion-level normalized-row slice; peak memory at maximum bounds was not tested. Ranks sort descending count, then event/symbol/module/source/line/report hash, across reports/events within one build. The canonical page expressly warns that these populations are not statistically comparable; no scoring-policy change is inferred.

### Datasets, schemas, downstream use

- `profile_data`: `analysis` SQLite `/2`, prefix `profile-data-`, stage `indexed`; indexed payloads are `hotspot` entities with no `SourceLocation`.
- `profile_data_handoff`: `/1`, stage `artifact_only`, glob `data/jobs/job_profile_data/attempts/*/artifacts/profile-data/*.json`, matching `accepted-profile-data.json`.
- Real publication/glob/schema parity is covered by `test_contract.py`. The profile-domain schema is an identity constant (`jobs/engineering_contracts.py:26`); no dedicated closed profile JSON schema was found under `docs/schemas`. The shared control validator checks statuses/gaps, not arbitrary domain payload keys (`interchange.py:521-579`). This is an explicit validation limit, not a claimed schema violation.
- `load_accepted_profile_data` verifies accepted envelope binding for summary/manifest, summary schema/`context_only`, file identities and the manifest graph (`job.py:409-427`).
- Current declared consumers: `job_document_issue_analysis`, `job_inference_security_review`, `job_owasp_control_assessment`, `job_review_data_indexing`, `job_review_package_assembly`, `job_review_prioritization`, `job_security_tagging`.
- Actual downstream slices inspected: declared inventory route; `RetrievalCore.query_engineering_signals`; profile selection in `review/scope.py:152`; `_engineering_context` and same-build attachment; prioritization `_load_profile_data`. Whole downstream jobs were not re-audited.
- Folded/perf/LLVM producer rows have no source path, and prioritization skips every row without `source`/`path` (`composite.py:302-305`). Thus the real folded-profile fixture imports no numeric hotpath maps even though build-wide context remains available. This is a **T-171 integration/coverage limitation**, not a recommendation to invent source locations or reinterpret context as findings.

## Findings

### PD-01 — Medium — Identical report copies at different paths abort indexing

- **Evidence:** `src/appsec_review/jobs/job_profile_data/job.py:198-203,238-242,351-356`; `src/appsec_review/retrieval/index.py:113-122`.
- **Trigger:** one accepted build retains `a.folded` and `b.folded` with identical bytes.
- **Expected/actual:** ingestion retains both because their path/hash pairs differ. Index identity omits report path, while payload includes it and a different rank. Real `IndexBuilder` raises `ValueError: index shard analysis/profile-data-u has conflicting entities for identity ...` instead of a publishable result.
- **Impact:** harmless copied profiles fail the index task and block dependent acceptance.
- **Confidence:** reproduced through real ingestion, index handler and builder conflict detection; only file/manifest boundaries faked.
- **Smallest correction:** distinguish complete report identities in logical keys, or deliberately coalesce byte-identical reports while preserving provenance and consistent rank/accounting.
- **Overlap:** no exact profile TODO/prior finding found. Sibling coverage audit **TC-02** identifies the analogous bug in the separate coverage producer; do not deduplicate away this producer-specific fix.

### PD-02 — Medium — Callgrind call costs are attached to the wrong source line

- **Evidence:** `src/appsec_review/jobs/job_profile_data/parsers.py:201-223`; existing `tests/unit/job_profile_data/test_parsers.py:103-105` asserts callee rows at caller cost positions.
- **Trigger:** `cfl=callee.c`, `cfn=callee`, `calls=1 7`, then `100 9`.
- **Expected:** retain caller-site position 100 separately from callee position 7, or preserve the call-edge distinction without inventing a callee location.
- **Actual:** the parser ignores `calls=` positions, parses the following caller cost position as `current_line`, then emits **`callee.c:100 / callee / Ir=9`**, no gap. With a callee self row at line 7, it also emits `callee.c:7 / Ir=9`; self and inclusive call costs share an undifferentiated event population.
- **Impact:** wrong reported source tuples and misleading hotspot population reach indexing, exact-path context and line-level prioritization.
- **Confidence:** reproduced with real parser; the input explicitly contains both distinct positions.
- **Smallest correction:** parse call-edge/callee position state and keep self/call-inclusive accounting distinct; never combine one side's path/function with the other side's position.
- **Overlap:** C10-F02 addresses other profile mapping/ranking issues, not this callsite/callee-position mismatch. No exact TODO found.

### PD-03 — Medium — Perf sample periods become part of the event identity

- **Evidence:** `src/appsec_review/jobs/job_profile_data/parsers.py:28,99-104,124`.
- **Trigger:** valid period-bearing sample headers `w 1 1.0: 100 cycles:` and `w 1 2.0: 200 cycles:` for the same `hot (app)` frame.
- **Expected:** one `cycles` event row with count 2 under the documented one-count-per-frame semantics; any period information is separate metadata.
- **Actual:** two rows, event `"100 cycles"` count 1 and event `"200 cycles"` count 1; no gaps.
- **Impact:** varying sampling periods fragment one symbol/event population and distort ranks instead of aggregating the samples.
- **Confidence:** reproduced with real parser.
- **Smallest correction:** parse optional period separately from the event name; preserve normal period-less input and event qualifiers.
- **Overlap:** no exact TODO/prior finding found. Existing perf test headers omit the period.

### PD-04 — Low — Malformed LLVM function headers are silently omitted and published successful

- **Evidence:** `src/appsec_review/jobs/job_profile_data/parsers.py:230-242`; `src/appsec_review/jobs/job_profile_data/job.py:219-221,250-255,392-394`.
- **Trigger:** `hot:9:1` followed by malformed top-level header `broken:-7:1`.
- **Expected:** a malformed-profile disposition or explicit partial gap, while preserving any valid data deliberately retained.
- **Actual:** unmatched top-level lines are ignored. Real ingestion returns one complete/no-gap row; real publication returns **`SUCCEEDED`, `item_count=1`, `gaps=[]`**.
- **Impact:** invalid named-function/sample population disappears without telling downstream consumers that coverage is incomplete.
- **Confidence:** reproduced parser → ingestion → publisher; output storage boundary faked.
- **Smallest correction:** distinguish permitted comments/ignored bodies from malformed top-level header candidates and reject or gap the latter.
- **Overlap:** no exact TODO found. Current `test_parses_llvm_sample_profile_function_headers_only` includes an unrecognized top-level line without asserting a gap.

### PD-05 — Medium — The declared dataset retrieval route cannot retrieve the dataset

- **Evidence:** `src/appsec_review/jobs/job_profile_data/datasets.py:8-11`; `src/appsec_review/retrieval/precomputed.py:18-24`; `src/appsec_review/retrieval/core.py:1260-1292`.
- **Trigger:** follow advertised `query_precomputed query_set=profile_data`.
- **Expected/actual:** retrieve profile hotspots; instead the actual entry point immediately raises **`ValueError: invalid precomputed query set`**. Even admitting the name would not suffice: this route queries `precomputed_fact` entities in `precomputed`, while this producer publishes `hotspot` entities in `analysis`.
- **Impact:** inventory-directed access fails even with a valid accepted profile shard.
- **Confidence:** reproduced route guard plus static storage/query mismatch.
- **Smallest correction:** declare the existing `query_engineering_signals signal_family=profile` route, with the PD-06/07 issues addressed, and invoke the real route in a contract test.
- **Overlap:** related **T-147/T-172**; analogous sibling coverage **TC-03**, not an exact existing profile fix.

### PD-06 — Medium — Engineering-signals path filtering discards profile rows with that exact source

- **Evidence:** producer `src/appsec_review/jobs/job_profile_data/job.py:351-356`; consumer `src/appsec_review/retrieval/core.py:2026-2029`.
- **Trigger:** a profile hotspot has `payload.source="src/a.c"` and no verified `SourceLocation`, as actually emitted by this producer.
- **Expected:** filtering profile context by that exact reported source should retain it without upgrading it to a verified source citation.
- **Actual:** `row_path` checks SQL location, `subject_path`, and `path`, but **not `source`**. The in-memory SQLite fixture returned two rows unfiltered and zero for `path="src/a.c"`.
- **Impact:** the actual engineering route loses source-scoped profile context even when the recorded source already matches the requested repository-relative path.
- **Confidence:** reproduced real query selection/SQL/filtering; only database access and transport/audit wrapper faked.
- **Smallest correction:** support the profile payload's source field as context-only filtering, or introduce an explicit compatible normalized field without manufacturing verified locations.
- **Overlap:** **C10-F02** already noted absent/unbound source mapping. This narrower failure also occurs with an exact relative reported source and concerns the newer engineering-query filter. Related **T-172**.

### PD-07 — Medium — Engineering-signals retrieval drops existing profile coverage gaps

- **Evidence:** `src/appsec_review/retrieval/core.py:1991-2038`; compare gap-preserving search at `:649-652`; response projection `:532-547`.
- **Trigger:** an accepted profile shard has a partial coverage row and manifest gap `row_truncation: omitted samples`.
- **Expected/actual:** return the known incompleteness with the retained rows. Instead the query never reads coverage rows or shard gaps and returns an empty gap list. `_envelope` projects that as empty `coverage_gaps`.
- **Impact:** inference using this route loses the producer's explicit omitted-sample warning. The gap still exists in other artifacts/routes; this finding does not claim global deletion.
- **Confidence:** reproduced real query operation against in-memory SQLite containing the gap in both places.
- **Smallest correction:** forward applicable shard and coverage-table gaps using the same bounded pattern as existing retrieval methods.
- **Overlap:** related **T-172**, no exact prior finding/TODO found.

### PD-08 — Low — Prioritization labels an accepted profile publication UNAVAILABLE

- **Evidence:** `src/appsec_review/jobs/job_review_prioritization/composite.py:270-277,825`; producer `src/appsec_review/jobs/job_profile_data/job.py:392-394`.
- **Trigger:** consume the real accepted `/2` envelope emitted by the selected profile runtime unit.
- **Expected/actual:** envelope `completion_status` and domain publication `terminal_status` were both **`COMPLETED_WITH_GAPS`**; consumer returned **`UNAVAILABLE`** because it reads nonexistent envelope `terminal_status`.
- **Impact:** `engineering_sources.profile_data` contradicts actual accepted consumption. Numeric weights can still use path-bearing imported rows; this is not a claim that this status alone disables weighting.
- **Confidence:** reproduced against the untouched handoff generated by this audit's real unit fixture.
- **Smallest correction:** use the current envelope completion/coverage fields or explicit domain publication status, with a deliberate legacy fallback.
- **Overlap:** related **T-171**; sibling coverage **TC-08** reports the same shared-consumer mistake for coverage. Coordinate one coherent consumer fix rather than count separate fixes to the same status convention.

### PD-09 — Low — Valid UTF-8 profiles are rejected when the detection prefix splits a character

- **Evidence:** `src/appsec_review/jobs/job_profile_data/job.py:145-147`.
- **Trigger:** valid 65,540-byte `valid.folded` with a two-byte `é` straddling the fixed 65,536-byte detector prefix.
- **Expected/actual:** parse the valid folded report within all configured bounds; instead strict decoding of the truncated prefix reports **`unsupported_profile_format: ... unrecognized opaque profile`**. Parsing the full exact bytes directly succeeds with two aggregate rows.
- **Impact:** ordinary valid non-ASCII symbols can cause entire reports to be discarded as opaque.
- **Confidence:** reproduced; no oversized lines, invalid bytes or external converter involved.
- **Smallest correction:** use bounded incremental decoding with an incomplete trailing code point withheld, rather than treating a prefix boundary as invalid encoding.
- **Overlap:** no exact TODO/prior finding found.

### PD-10 — Medium — Already located profile rows are also broadcast to every same-build review unit

- **Evidence:** `src/appsec_review/review/units.py:85-95,266-268`; all producer rows have `build_unit_id` at `jobs/job_profile_data/job.py:238-242`.
- **Trigger:** profiles for `src/a.c` and `src/b.c` share a build unit.
- **Expected:** matching file-specific rows plus a deliberately bounded aggregate/unmapped build context.
- **Actual:** both rows are added to `by_build`, even when also mapped by source. The real `_engineering_context` reproduction returned one exact a.c entry but two build-wide entries; every same-build unit receives the latter.
- **Impact:** unrelated profile rows occupy bounded review context and can crowd out local evidence.
- **Confidence:** reproduced real consumer with canned scope rows.
- **Smallest correction:** keep mapped records file-scoped; use an explicit bounded summary/unmapped policy for build-level context.
- **Overlap:** **existing C10-F02**, `docs/reviews/system-review-2026-11-13.md:1861-1872`, narrowed reconfirmation, **not new**. Historical severity high is not adopted wholesale; current context-only semantics and caps narrow this audit's severity. No exact dedicated TODO found.

## Documentation, known boundaries, and unproven concerns

- **T-147:** generated task bindings remain undeclared. Actual handlers were traced; no fabricated model/tool binding is inferred.
- **T-113:** the four dedicated files now have 51 cases, as its ledger records. High line/branch coverage does not validate parser meaning or downstream compatibility.
- **T-026:** producing new dynamic execution evidence remains deferred; not launching profilers/converters is correct for this job.
- **T-171/T-172:** done entries describe downstream rewiring; PD-05–08 and source-less numeric-map limitations qualify that completion, not authorization to invent a new scoring/source-mapping design.
- **Conditional cache concern excluded:** local fingerprint omits explicit bounds/normalized rows (`job.py:334-346`). `docs/architecture/scanners-and-evidence-collection.md:135-158` and **T-159** explicitly narrow this: frozen same-run configuration and repair admission block the proposed changed-bounds path. No supported stale reuse was demonstrated or counted.
- **Callgrind format limitation:** a `positions: instr line` fixture failed with `zip() argument 2 is longer than argument 1`. The parser assumes one position column. This was observed, but treated separately as a supported-dialect coverage limit rather than another silent-corruption finding; ingestion would catch this `ValueError` as a gap.
- **Stale test command:** `docs/operations/profile-data.md:73-77` points to nonexistent `tests/test_profile_data.py`; `docs/architecture/engineering-security-signals.md:320` repeats it. Use the mapped unit files. Related T-113.
- **Prerequisite prose drift:** `docs/architecture/profile-data.md:17-21` unconditionally requires three handoffs, while the typed contract and tested implementation permit disabled build/artifact-index producers with gaps. Canonical job page describes the conditional path.
- Runtime shared control validation is not a closed schema validator for profile rows. Source names/lines remain unverified context. No claim of line citation fidelity or hostile-workload reachability is made.

## Validation commands and evidence

All Linux bodies below ran in the authorized checkout through:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# Linux command/body below
'@
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
    "printf %s $encoded | base64 -d | bash"
```

Preflight commands: `git rev-parse HEAD`, `git branch --show-current`, `git status --short`, `git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD`, and `.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'`. `offending_environment(os.environ)` returned `[]`. Final HEAD/status/root-untracked checks remained unchanged/empty.

### Focused unit run

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 1717 \
  --max-tests 57 --expect-tests 57 --timeout-seconds 180 -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_profile_data/test_contract.py \
  tests/unit/job_profile_data/test_ingestion.py \
  tests/unit/job_profile_data/test_job_graph.py \
  tests/unit/job_profile_data/test_parsers.py \
  tests/unit/runtime/test_wave3_contracts.py::test_wave3_contract_input_policies_match_confirmed_decisions \
  tests/unit/runtime/test_wave3_contracts.py::test_wave3_admission_rejects_missing_required_and_enabled_conditional_handoffs \
  tests/unit/runtime/test_wave3_contracts.py::test_wave3_admission_rejects_missing_artifact_indexing_when_language_build_disabled \
  'tests/unit/runtime/test_wave3_contracts.py::test_coverage_and_profile_publish_unavailable_gaps_when_build_and_artifact_indexing_disabled[profile]' \
  'tests/unit/runtime/test_wave3_contracts.py::test_coverage_and_profile_ingest_language_receipts_when_only_artifact_indexing_disabled[profile]'
```

- Exact collection **57**, exit 0; **57 passed**, pytest 7.52 s; wrapper total 16.805274734 s. Supervised collection 4.717716150 s and execution process 11.741165031 s include interpreter/plugin overhead.
- Zero failures, skips or tests over ten seconds. Both process-cleanup reports confirmed zero remaining processes.
- Unique wrapper run name: **`tests-custom-20261118-122346-548512-2829833`**.
- Evidence under `test/tmp/`: `<name>.collection.json`, `<name>.junit.xml`, `<name>.timings.sqlite`, `logs/<name>.log`, `logs/<name>.collection.log`, `reports/<name>.json`, `<name>.processes/`.
- The existing wrapper gives its internal collection and execution subprocesses the **same fresh per-wrapper basetemp**, sequentially (`ops_tests.py:402-410`); it does not give each an additional different suffix. This differs from a literal per-subprocess reading of the brief's uniqueness requirement. No default or other auditor's scratch was used, and the wrapper/source was not modified to change that behavior.
- Before execution, all selected test files and their root/unit conftests, synthetic handoff/build/release helpers and environment guard were inspected. Unit-tier external-process/network/Dagster guards remained active. The recorded build fixture publishes canned JSON and never invokes a build.

### Reproduction A — real parser/normalizer/index/query logic, in-memory boundaries

Ran `.venv/bin/python -` with the following body via the transport above. Exit **0**, **0.006427 s** after imports. No filesystem writes: the nonexistent root assertion held both before and after. SQLite used `:memory:`; file custody, accepted manifests and query transport were explicit fakes, not the behavior under test.

```python
from contextlib import nullcontext
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace
from unittest.mock import patch
import json, sqlite3
from appsec_review.jobs.job_profile_data import job, parse_profile
from appsec_review.jobs.job_review_prioritization import composite
from appsec_review.retrieval import EntityKind, LogicalIdentity
from appsec_review.retrieval.core import RetrievalCore, RetrievalLimits
from appsec_review.retrieval.index import _SHARD_TABLES
from appsec_review.review.units import _engineering_context

start = perf_counter()
root = Path.cwd() / 'test/tmp/job-audit-profile-data-inmemory-1717'
assert not root.exists()
class MemoryFile:
    def __init__(self, data): self.data = data
    def stat(self): return SimpleNamespace(st_size=len(self.data))
    def read_bytes(self): return self.data
def ingest(profiles):
    files = {name: MemoryFile(data) for name, data, fmt in profiles}
    artifacts = [{'path': name, 'workspace_path': name, 'sha256': sha256(data).hexdigest(),
                  'kind': 'execution-profile', 'profile_format': fmt} for name, data, fmt in profiles]
    with patch.object(job, '_safe_file', side_effect=lambda r, ident, label: files[ident['path']]):
        return job.ingest_profile_artifacts(root, [{'build_unit_id': 'u', 'root': '.', 'artifacts': artifacts}])
def unit(outputs):
    return SimpleNamespace(job=SimpleNamespace(run_root=root, source_fingerprint='snap',
        attempt_root=root/'attempt', attempt_id='attempt_0001', run_id='fixture',
        target_root=root, repository_root=root), unit_id='index.profile_data', output=outputs.__getitem__)
handlers = {u.unit_id: u.handler for u in job.build_job().units}

dup = ingest([('a.folded', b'hot 9\n', 'folded-stacks'), ('b.folded', b'hot 9\n', 'folded-stacks')])
outputs = {'load.accepted_inputs': {'upstream_manifest': {'path': 'manifest.json', 'sha256': 'a'*64}},
           'normalize.profile_data': dup}
with patch.object(job, '_safe_file', return_value=root/'manifest.json'), \
     patch.object(job, 'load_verified_manifest', return_value=({'indexes': []}, None)):
    try:
        handlers['index.profile_data'](unit(outputs))
    except ValueError as exc:
        assert 'conflicting entities' in str(exc)
        print('DUPLICATE_REPORT_INDEX', json.dumps({'normalized_rows': len(dup['units'][0]['rows']), 'gaps': dup['gaps'], 'error': str(exc)}))
    else: raise AssertionError('expected duplicate identity failure')
assert not root.exists()

call = parse_profile(b'events: Ir\nfl=caller.c\nfn=caller\n10 1\ncfl=callee.c\ncfn=callee\ncalls=1 7\n100 9\nfl=callee.c\nfn=callee\n7 9\n', 'callgrind')
assert any(r.symbol == 'callee' and r.source == 'callee.c' and r.line == 100 for r in call.rows)
print('CALLGRIND_CALLSITE', json.dumps({'rows': [asdict(r) for r in call.rows], 'gaps': call.gaps}))
try:
    parse_profile(b'positions: instr line\nevents: Ir\nfl=a.c\nfn=f\n0x100 10 9\n', 'callgrind')
except ValueError as exc: print('CALLGRIND_MULTI_POSITION', str(exc))

perf = parse_profile(b'w 1 1.0: 100 cycles:\n    7fff hot (app)\n\nw 1 2.0: 200 cycles:\n    7fff hot (app)\n', 'perf-script')
assert [r.event for r in perf.rows] == ['100 cycles', '200 cycles']
print('PERF_EVENT_PERIOD', json.dumps({'rows': [asdict(r) for r in perf.rows], 'gaps': perf.gaps}))

bad = ingest([('bad.llvm-sample', b'hot:9:1\nbroken:-7:1\n', 'llvm-sample')])
outputs = {'load.accepted_inputs': {'upstream_handoffs': {}, 'gaps': []},
           'normalize.profile_data': bad,
           'index.profile_data': {'index_manifest': {'path':'manifest.json','sha256':'a'*64}}}
with patch.object(job, '_artifact', return_value={'path':'summary.json','sha256':'b'*64}):
    published = handlers['acceptance.publish_handoff'](unit(outputs))
assert published['terminal_status'] == 'SUCCEEDED' and bad['gaps'] == []
print('LLVM_MALFORMED_SUCCESS', json.dumps({'publication': published, 'rows': bad['units'][0]['rows']}))
try: RetrievalCore.query_precomputed(SimpleNamespace(), query_set='profile_data')
except ValueError as exc:
    assert str(exc) == 'invalid precomputed query set'
    print('ADVERTISED_ROUTE', str(exc))

connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
for ddl in _SHARD_TABLES: connection.execute(ddl)
profile_rows = []
for source in ('src/a.c', 'src/b.c'):
    payload = {'symbol': source, 'source': source, 'line': 7, 'build_unit_id': 'u', 'count': 9,
               'hotness_rank': 1, 'hotness_population': 2, 'semantics': 'context_only'}
    ident = LogicalIdentity.derive(EntityKind.HOTSPOT, 'snap', {'source': source}).value
    connection.execute('INSERT INTO entities VALUES (?,?,?,?,?,?)', (ident,'hotspot',source,source,source,json.dumps(payload)))
    profile_rows.append({'identity':ident,'payload':payload})
connection.execute('INSERT INTO coverage VALUES (?,?,?)', ('profile-data:u', 'partial', 'row_truncation: omitted samples'))
shard = {'name':'analysis', 'shard_id':'profile-data-u', 'producer':{'job':'job_profile_data'},
         'gaps':['row_truncation: omitted samples']}
core = object.__new__(RetrievalCore)
core.limits = RetrievalLimits(); core.clock = lambda: 0
core.indexes = {'analysis': (shard,)}
core._database = lambda ident, deadline: nullcontext(connection)
core._execute = lambda tool, params, operation: operation(1)
unfiltered = core.query_engineering_signals(signal_family='profile')
filtered = core.query_engineering_signals(signal_family='profile', path='src/a.c')
assert len(unfiltered[0]) == 2 and filtered[0] == []
assert unfiltered[1] == [] and filtered[1] == []
print('ENGINEERING_ROUTE', json.dumps({'unfiltered_rows':len(unfiltered[0]),'filtered_rows':len(filtered[0]),'gaps':unfiltered[1]}))
connection.close()

scope = SimpleNamespace(producer=lambda name: SimpleNamespace(shards=(shard,) if name == 'profile_data' else ()),
    shard_sha256=lambda s: 'a'*64, store=SimpleNamespace(entities=lambda shards, kinds: profile_rows))
by_path, by_build, _ = _engineering_context(scope)
assert len(by_path['src/a.c']) == 1 and len(by_build['u']) == 2
print('BUILD_CONTEXT_BROADCAST', json.dumps({'exact_a':len(by_path['src/a.c']),'build_wide':len(by_build['u'])}))
folded = ingest([('a.folded', b'root;hot 9\n', 'folded-stacks')])
doc = {'schema':'appsec-review/profile-data-handoff/1', 'build_units':folded['units']}
handoff = {'completion_status':'SUCCEEDED', 'outputs':{'acceptance.publish_handoff':{'terminal_status':'SUCCEEDED','artifact':{'path':'summary.json','sha256':'b'*64}}}}
with patch.object(composite, 'has_handoff', return_value=True), patch.object(composite, 'accepted_handoff', return_value=(handoff,'a'*64)), patch.object(composite, 'read_json', return_value=doc):
    status, files, symbols, lines = composite._load_profile_data(root, True)
assert status == 'UNAVAILABLE' and not files and not symbols and not lines
print('PRIORITIZATION_PRODUCER_SHAPE', json.dumps({'status':status, 'input_rows':len(folded['units'][0]['rows']), 'files':files, 'symbols':symbols, 'lines':lines}))
assert not root.exists()
print('PURE_REPRO_ELAPSED', round(perf_counter()-start,6))
```

Observed outputs: duplicate normalized rows 2/no gaps then conflict error; Callgrind callee rows at 100 and 7 both cost 9/no gaps; perf events `"100 cycles"` and `"200 cycles"` count 1 each/no gaps; malformed LLVM one successful row/no gaps; invalid advertised route; engineering query 2 unfiltered/0 filtered/empty gaps; mapped a.c context 1/build context 2; source-less folded rows yielded empty prioritization maps and `UNAVAILABLE`.

### Reproduction B — real accepted unit artifact and UTF-8 prefix

Ran `.venv/bin/python -` with the body below, exit **0**, **0.025491 s** after imports. Only read this audit's own synthetic accepted run and processed a small in-memory buffer.

```python
from pathlib import Path
from time import perf_counter
import json
from appsec_review.runtime.consume import upstream_scope
from appsec_review.storage.validation import validation_scope
from appsec_review.jobs.job_review_prioritization import build_job
from appsec_review.jobs.job_review_prioritization.composite import _load_profile_data
from appsec_review.storage import file_sha256
from appsec_review.jobs.job_profile_data import detect_profile_format, parse_profile
start=perf_counter()
base=Path('test/tmp/tests-custom-20261118-122346-548512-2829833')
paths=sorted({p.resolve() for p in base.glob('popen-gw*/test_coverage_and_profile_inge*/runs/*/data/jobs/job_profile_data/attempts/attempt_0001/handoff.json')})
assert len(paths)==1, paths
handoff_path=paths[0]
root=handoff_path.parents[5]
handoff=json.loads(handoff_path.read_text())
job=build_job()
with validation_scope(root), upstream_scope(root, job.job_id, {'job_profile_data':file_sha256(handoff_path)}, contract=job.contract):
    status, files, symbols, lines=_load_profile_data(root, True)
print('REAL_ACCEPTED_PROFILE_STATUS', json.dumps({'root':str(root), 'envelope_completion':handoff['completion_status'], 'publication_terminal':handoff['outputs']['acceptance.publish_handoff']['terminal_status'], 'consumer_status':status,'files':files, 'symbols':symbols,'lines':lines}))
assert status=='UNAVAILABLE'
data=b'a 1\n'*16383 + 'xxxé 1\n'.encode()
assert data[:65536].endswith(b'\xc3')
assert len(parse_profile(data,'folded-stacks').rows)==2
fmt,gap=detect_profile_format('valid.folded',data)
print('UTF8_DETECTION_PREFIX', json.dumps({'size':len(data),'format':fmt,'gap':gap}))
assert fmt is None and gap
print('REPRO_ELAPSED',round(perf_counter()-start,6))
```

Output: both real completion fields `COMPLETED_WITH_GAPS`, consumer status `UNAVAILABLE`; 65,540 valid bytes detected as opaque.

One **initial reproduction lookup failed before either case**: it used `paths=sorted(base.glob(...))`, then asserted length 1, but pytest's `...inge0` and `...ingecurrent` symlink yielded two names for the same fixture. Exit 1; elapsed was not captured. The retry above resolves/deduplicates paths. This was an audit-fixture lookup error, not a failing application unit, and no test/environment/source was changed.

## Read inventory and material gaps

**Read fully**

- Authorized `AGENTS.md`, canonical multi-session coordination skill, complete updated audit brief.
- `jobs/job_profile_data/{__init__,datasets,job,parsers}.py`.
- All four `tests/unit/job_profile_data/test_*.py`; `tests/unit/runtime/test_wave3_contracts.py`; root/unit conftests; environment guard; `tests/handoff_fixture.py`, `tests/artifact_input_support.py`, `tests/release_support.py`.
- `docs/operations/job_profile_data.md`, `docs/operations/profile-data.md`, `docs/architecture/profile-data.md`, `docs/reviews/profile-data-and-dependency-exposure-implementation.md`.
- `tests/test_engineering_signal_integration.py` read, **not executed**.
- `runtime/units.py`, `runtime/selection.py`, `retrieval/precomputed.py`; shell test wrapper/common launcher.

**Read relevant ranges/search results**

- Central TOML profile block; test-map entry; registry/graph selection/Dagster selection; runtime runner execution and interchange control validator; `engineering_contracts.py`.
- Language-build accepted loader/safe artifact reader and profile filename classification; artifact-index accepted loader.
- `retrieval/index.py:1-230` and SQLite table declarations; `retrieval/core.py` constructor/context, database/entity/response helpers, precomputed route, engineering-signals route and neighboring gap handling.
- `review/units.py:1-155,245-280`, profile producer selection; consumer contracts; `job_review_prioritization/composite.py:260-335` and profile status publication; profile fixtures/expectations in `test_signals_and_rewiring.py`.
- Architecture input-contract, engineering-security-signal and scanner/cache-identity sections cited above; TODO T-026/T-113/T-132/T-147/T-159/T-171/T-172 relevant entries; T-171 task doc excerpts; historical C10-F02; prior session reports, especially coverage findings and current cumulative ownership.
- Wrapper Python option/collection/execution/report paths; generated focused-run report and actual profile task read receipts.

**Not verified / material unread scope**

- No external format-conformance suite or real perf/Callgrind/LLVM exporter invocation; full optional dialects, multi-position/compressed event variants, recursion policy alternatives and maximum-size memory behavior are not certified.
- No source-location resolution implementation exists in this job to certify; accepted report symbols/paths are context, not proof of corresponding catalog symbols or source lines.
- Whole upstream producers, every downstream job, full retrieval manifest/custody internals, generic scheduler/checkpoint/import/repair combinations and security boundary implementations were not re-audited.
- No malformed-accepted-envelope matrix beyond the dedicated tests; no domain-wide closed JSON-schema proof.
- The four unselected shared Wave 3 cases concern other jobs/coverage or language configuration, not this producer's requested focused slice.
- No integration (`tests/integration/test_signal_job_acceptance.py`), acceptance, live/Dagster review, actual workload/output evidence or target-backed fixtures read or executed. No quality claim follows from unit success.
- Test evidence was intentionally retained under the wrapper's own ignored `test/tmp` paths; no unrelated files were removed and no completed code work awaits integration.
