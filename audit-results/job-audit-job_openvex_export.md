# Job 44/47 — job_openvex_export

## Scope, verdict and attribution

**Revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, clean `main` in `/home/wsollers/projects/appsec-review`, Ubuntu-22.04, accessed through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the authorized UNC path. HEAD, cleanliness and editable-install location were checked before testing; HEAD and cleanliness were checked again after cleanup. The Windows working checkout was not audited.

**Result:** confirmed the already-reported **High DI-05** dependency-companion task-key failure; **do not count it again**. Five additional **medium** functional defects and one **low** telemetry wiring defect are recorded below. The existing cross-job payload-read-observation gap also affects this job; group its correction with TA-F04/PB-F04/TS-F09 rather than creating another unrelated discovery.

**Validation:** **211 passed**, no failures/skips/cases over 10 seconds; **63.23 s pytest / 71.551 s supervised wrapper**, two workers, shuffled. Two additional offline programs reproduced the findings. Main projection tests passed, but they do not establish real gate/review acceptance or useful target findings.

**Important limitation:** DI-05 prevents the normal accepted dependency producer from reaching the rest of the companion. The downstream companion findings were isolated using a synthetic accepted boundary containing the consumer's currently expected `publication.publish_handoff` key. That is deliberately **not** the actual producer shape. No production code was patched, and these are latent defects behind DI-05, not claims that a real run reached them.

No source/configuration/environment edits, installs, commits, pushes, providers, scanner execution, target execution, network lookups, services, integration/live reviews or nested agents. Only permitted private test state and this report were written. Audit-created probe fixtures were removed; unit logs/JUnit/timing evidence was retained.

## Intended contract, registration and identity

* `runtime/registry.py:108,179` registers the factory. `appsec-review.toml:3513-3546` enables it, declares one application worker and all three tasks. The release label is `openvex-export-2` (`appsec-review.toml:98`).
* `datasets.py:35-91` declares **19 input requirements**, four possible producer envelopes: required gate and inference review; optional intake and dependency intelligence. Gate/review payload datasets include the six decision-audit kinds. It is `REVIEW_GRAPH`, `ACCEPTED_EVIDENCE`, reusable (`always_execute=False`), with propagated handoff and explicit `schedule_after=job_final_publication_gate`. Typed semantic predecessors plus redundant-edge projection place it after the gate; final report is an independent gate-only peer.
* The primary product is the reviewed repository namespace, exact source snapshot and **full resolved configuration**, not a release or binary hash. The primary vulnerability URI hashes repository/snapshot/claim; sorted unique finding packages yield one `affected` statement each, only for gate `publishable` confirmed packages. Backlog/withheld packages remain explicit exclusions. No inferred fix, vendor issuance or exploitation claim is added.
* Five **protected**, sensitive, non-indexed dataset declarations cover verified inputs, primary VEX, primary result/manifest, dependency VEX and dependency accounting (`datasets.py:5-27`). Paths are attempt-local. Retrieval routes expose inventory metadata, not these payloads.
* Optional dependency export consumes accepted SCA `/1` records, not adjudicated finding packages. The runtime adapter only permits `affected` for `symbol_reachable` plus nonempty call sites; every other state becomes `under_investigation`. It forcibly supplies incomplete coverage, so its use of the more general public helper cannot emit `not_affected`. The pure public helper can emit a negative given explicit complete/unreachable input; that is not the job adapter's authority.

### Actual accepted inputs and payload reads

`inputs._accepted` (`inputs.py:263-311`) uses `accepted_upstream`, the current claim pins and declared envelope permissions, not an independently decoded latest pointer. It validates common envelope run/job/status, bounds and hashes declared artifacts, checks claim/result/outcome/unit-status closure, then invokes the shared verified/consumed handoff reader. Reproof compares the same admitted identity. Optional unsupplied dependency data stays absent even when another accepted pointer exists; the focused tests exercise that distinction and movement of a supplied pointer.

`verify_inputs` (`inputs.py:568-654`) reads:

1. Immutable configuration manifest/resolved bytes; exact export settings, full configuration hash, semantic inference-review hash and ship-block-policy hash (`:314-337`).
2. Gate and review envelopes; gate's upstream review digest must equal the admitted review. Both configuration digests must equal the frozen configuration (`:576-584`).
3. Gate document, every certified binding and nested input/capability/attachment reference (`:585-595`).
4. Review document, scope, both lane sets/manifests/packages, ledger receipt/JSONL/projection/shards, chain manifest/items/referenced files/actor cell receipts, coverage, all finding and score packages (`:340-412`). Chain-cited non-review files are hash-read as bytes, not incorrectly parsed as object JSON.
5. Real `load_accepted_review(..., include_decision_audit=True)`, whose implementation verifies ledger reconstruction, package/score/state/provenance/chain membership, PoC and remediation/backlog partitions and the protected audit. The exporter reclassifies this same audited document with the **certified** completion snapshot, not current optional producer heads. Exact canonical gate equality, counts, shared gate snapshot and policy hashes are checked (`:602-633`).
6. Accepted scope/index manifest and transitive shard bytes; exact scope shard set and target snapshot. Optional intake/acquisition binds configuration, reviewed snapshot, source kind/revision, acquisition identity/tree qualification and any explicit repository IRI (`:417-535`). Automatic mode retains a snapshot namespace even with acquisition metadata.
7. Per-finding score objects and evidence relation membership in the accepted projection (`:538-565`).

The durable inventory binds these measured bytes, excluding only exact operational pointer families. Ten hash-pinned schema/license/lock resources are copied into the attempt and join that inventory. The optional dependency reader separately validates its envelope/configuration, SCA schema and source fingerprint, reads the SCA artifact, projects rows and rechecks its own inventory (`dependencies.py:25-69`). **That separate inventory is not merged with the main inventory: OX-05.** Dataset-level read receipts are also incomplete, as separately attributed below.

## Every declared step/task

| Step/task | Actual implementation | Result and limit |
| --- | --- | --- |
| `load.verify_inputs` | `job.py:125-140`; `verify_inputs`, pinned schema snapshots, immutable verified-inputs JSON; dependency projection runs once to retain its source tuple | Gate/review/source/config checks above. Emits start/verified events. Normal dependency output hits known DI-05 before successful load. Dependency reads are outside the saved primary inventory. |
| `export.assemble` | `job.py:142-162`; reload verified record, reprove authoritative inputs/schema copies, pure primary assembly, offline schema and exact semantic validation, immutable writes; regenerate/persist dependency companion | Main membership/exclusion/status/product/time mapping is explicit and tested. Empty primary output has no VEX document. Companion has OX-01/02/03/04/05. |
| `acceptance.publish_handoff` | `job.py:164-198`; reprove inputs, regenerate dependency bytes and compare source/results, rebuild expected primary bundle, compare every output byte/ref, reject an unexpected primary document when empty, reprove again | Returns primary statement count and combined primary/dependency gaps; common runner owns acceptance. OX-04 can fail here after successful assembly. OX-05 permits a combined inventory above its bound. |

All units are wrapped by `measured` (`job.py:228-265`): frozen settings must be enabled, `claim.started_at` supplies the attempt deadline, monotonic checks surround work/final result reads, and exceptions emit closed reason/phase failure events before rethrow. No model/task prompt, provider, subprocess or container is dispatched.

### Configuration, output validation and consumers

* `settings.py` rejects unknown/missing keys, non-boolean enablement, bool-as-integer/out-of-range bounds, unsafe/plain-text/UTF-8 overflows and invalid repository identity. Enabled prerequisites are also enforced centrally (`config/loader.py:1516-1520`). Disabled graph/manual dispatch is tested; there is no opt-out bypass.
* Main record constructors freeze JSON, bound depth/counts/bytes, reject duplicate finding/claim identities, require exact gate membership and certify all referenced context. `projection.py:20-71` independently checks configured bounds, exact bucket counts/membership and review provenance.
* `validation.py` hash-verifies the local schema closure, denies remote resolution, applies timestamp/IRI formats and reassembles the exact expected primary output. Schema validity alone is not accepted as semantic correctness.
* `_write` (`job.py:52-78`) permits identical existing bytes only, uses exclusive/no-follow creation, private file/directory modes, flush/fsync and re-read checks. `reporting.read_output` (`reporting.py:26-50`) rejects non-private regular files/hardlinks, size/hash/inode/mtime changes. The main acceptance path explicitly rejects an unexpected document on an empty export (`job.py:187-191`).
* Historical `read_accepted_export` (`reporting.py:81-181`) checks the common envelope, verified inputs, primary canonical/schema/semantic bundle, configuration/upstream/release identities, runtime artifact union and exact bound bytes. It does not require the historical pointer to remain latest. `load_export` (`:188-247`) additionally checks current gate/review/configuration/release and reruns main input verification; stale states expose no links/counts.
* `metrics.py` correlates domain/runtime events, rejects unsupported acceptance as semantic evidence, deduplicates accepted handoffs, preserves unknown timings/counts and separates failed runtime finalization from domain completion. It obtains accepted primary counts through the full reader. `observability/telemetry.py:1576-1585` invokes it before generic lifecycle deduplication. Dependency CVE telemetry is not wired: OX-06.
* The final report **intentionally does not consume OpenVEX**: its `job.py:102-135` reads/reproves the gate and assembles its own report. Wiring tests assert report `consumes == (gate,)`. Do not “repair” this decided architecture by adding export fan-in.

## Findings

### Known High DI-05 — Actual dependency producer task key crashes load

**Evidence:** dependency producer `src/appsec_review/jobs/job_dependency_intelligence/job.py:712-719,743-748`; consumer `src/appsec_review/jobs/job_openvex_export/dependencies.py:31`; call `job.py:129-130`.

Reproduced `KeyError('publication.publish_handoff')` with a producer-shaped `outputs["acceptance.publish_handoff"]`. The existing dependency publication test creates the wrong `publication.publish_handoff` key itself (`tests/unit/job_openvex_export/test_dependency_publication.py:34`), so passing it does not cover the real seam. **Correction:** read the actual producer key/shared typed loader and test producer-shaped output. Already owned by prior report **DI-05**; no duplicate finding.

### OX-01 — Medium — Dependency product omits source/configuration identity

**Evidence:** `src/appsec_review/jobs/job_openvex_export/dependencies.py:52-54`; compare correct primary `projection.py:105-106`, identity formula `contracts.py:346-350`, and `docs/operations/openvex-export.md` “Product, vulnerability and time identity.”

**Trigger/repro:** project the same dependency row twice with the same explicit repository IRI and timestamp but full resolved configuration hashes `a*64` and `d*64`. Both pass the adapter's configuration equality check against their synthetic accepted dependency input. The generated documents are **byte-identical**, with product `https://example.test/repository`, although the corresponding `source_product_id` values differ. With explicit repository identity, snapshot changes are also absent from this product formula; that further consequence is static, not separately run.

**Expected/actual:** statements must identify the reviewed source/configuration product. The companion passes the repository namespace itself, unlike the primary export. Its source result pins do not restore scope inside the standalone VEX assertion.

**Impact:** downstream VEX consumers cannot distinguish configuration-specific dependency reachability; explicit repository identity broadens the apparent assertion beyond the reviewed snapshot. **Confidence:** high, reproduced.

**Smallest correction:** pass `source_product_id(repository_iri, target_snapshot, resolved_config_sha256)` and retain the dependency as its subcomponent. Add same-repository/different-config and different-snapshot regressions. **Overlap:** T-176 completion work; no exact dedicated TODO found.

### OX-02 — Medium — Empty/all-positive dependency export drops upstream coverage gaps

**Evidence:** `dependencies.py:55-57,67-68`; `cve_reachability.py:446-458`; final handoff `job.py:196-198`.

**Trigger/repro:** valid SCA documents with `gaps=["osv_index_unavailable","source_file_limit_exceeded"]` and an output gap were projected with (a) zero advisories and (b) one reachable advisory. Both returned **`terminal_status="SUCCEEDED", gaps=[]`**; case (a) had no document.

**Expected/actual:** accepted missing/truncated dependency coverage must remain a named export gap independently of whether an advisory happens to need investigation. The adapter reduces all upstream gaps to a boolean. The projector only emits gap records for `under_investigation` decisions, so empty/all-affected inputs erase them. In positive statement notes, the original reasons are replaced by generic coverage wording.

**Impact:** a missing OSV index or truncated source scan can yield a success-shaped, ungapped dependency result, including the most misleading zero-advisory case. This does not mean it emits `not_affected`; it loses coverage accounting instead. **Confidence:** high, both branches reproduced.

**Smallest correction:** carry/deduplicate source gap identities/reasons into the companion independently from per-statement statuses, and derive terminal status from both. Preserve affected statements without inventing negative conclusions. **Overlap:** T-170/T-176 and the general gap contract; no identical dedicated item found.

### OX-03 — Medium — Producer-valid nullable package coordinates fail the entire export

**Evidence:** `docs/schemas/dependency-intelligence/sca-reachability.schema.json:100-108` permits nullable PURL/ecosystem; real producer `job_dependency_intelligence/reachability.py:807-818,904-922`; consumer `dependencies.py:35-52`; `cve_reachability.py:157-169,252-253`.

**Trigger/repro:** real `evaluate_sca_reachability`, with OSV/reachability disabled and one scanner observation `{advisory:"CVE-2026-12345", package:"sample", version:"1.0"}`, produced a schema-valid row with `purl=None, ecosystem=None`. The real companion reader successfully schema-validated it, then raised **`ValueError: advisory CVE-2026-12345 requires a PURL or CPE23 component identifier`**. There is no CPE field in this SCA schema/adapter projection to rescue that branch.

**Expected/actual:** the optional companion needs an explicit policy for the producer's supported incomplete identity state. Instead, a valid partial dependency inventory passes validation and aborts primary OpenVEX load. This is a compatibility/availability defect; failing closed is safer than inventing a coordinate.

**Impact:** merely fixing DI-05 still leaves valid scanner-derived records capable of preventing export of unrelated confirmed gate findings. **Confidence:** high, real producer output reproduced through the consumer; accepted-envelope retrieval alone was doubled.

**Smallest correction:** align the producer/consumer contract for unresolved coordinates: preserve a verified available identity, or account the unprojectable advisory explicitly with a named gap/exclusion rather than silently guessing or losing it. If hard rejection is the chosen policy, make that requirement explicit at admission and document the whole-export consequence. **Overlap:** T-099/T-105/T-5050 already cover upstream coordinate completeness; this is their concrete additional OpenVEX failure consequence, not a new dependency-normalization finding.

### OX-04 — Medium — Dependency result is read with the document byte limit only at acceptance

**Evidence:** `job.py:212-224`, especially `:217`; creation `_write` at `:52-78`.

**Trigger/repro:** valid settings `max_document_bytes=1`, zero primary findings, and an empty accepted dependency SCA document. `load.verify_inputs` and `export.assemble` succeed; both VEX document references are null. The **690-byte dependency result** is written, but acceptance fails `bound_exceeded: export artifact exceeds its byte bound`.

**Expected/actual:** absent VEX documents do not exceed their document byte limit. Result/manifest accounting needs its own consistent bound, enforced before writing and during reproof. The same `persist` helper uses `max_document_bytes` for both document and result, and only applies it in the `create=False` branch.

**Impact:** supported lowered document limits admit/load/write a valid empty export which cannot be accepted; larger companion-accounting output has similarly inconsistent creation/reproof limits. **Confidence:** high, all three real unit handlers exercised with only the existing authoritative-review fixture boundary doubled.

**Smallest correction:** give `persist` an explicit artifact-specific bound and use it consistently for pre-write validation and re-read. Do not enlarge configured limits to conceal the mismatch. **Overlap:** T-176 extension; no matching TODO found.

### OX-05 — Medium — Separate dependency reader bypasses aggregate input limits

**Evidence:** main reader `inputs.py:574,651-652`; companion's new reader `dependencies.py:25`; independent counters `inputs.py:105-107,139-146,176-177`; main inventory saved before companion read `job.py:127-130`; reproof only combines main plus schemas `job.py:106-110,119-123`.

**Trigger/repro:** the small empty primary fixture measured **50** input/schema bindings. A fresh fixture with `max_bindings=50` and the optional dependency companion loaded, assembled and passed the acceptance handler. Its saved main inventory remained 50; the separately measured dependency inventory added 7 disjoint paths: **57 unique verified bindings under a limit of 50**.

**Expected/actual:** the configured unique-binding/aggregate-input limits should apply to the export's complete admitted input set. Each independent reader enforces only its own subtotal; dependency bindings never enter `VerifiedInputs.input_inventory` or `OPENVEX_INPUTS_VERIFIED` counts.

**Impact:** aggregate input bounds and observed input accounting understate actual export work. The same counter separation also applies to `max_total_input_bytes`; a large-byte case was not executed. **Confidence:** high for binding-count violation, static for byte analogue.

**Smallest correction:** include the admitted dependency source and measured binding union in the verified-input boundary, deduplicate by path/hash, enforce global bounds and reprove the same union. **Overlap:** no exact existing TODO; part of companion wiring under T-176.

### OX-06 — Low — Declared CVE status telemetry is computed then discarded

**Evidence:** `cve_reachability.py:475-487` creates `openvex.cve_statements_by_status`, total statements and coverage-gap statements. `dependencies.py:52-69` drops `bundle.telemetry`. `job.py:221-226` only returns dependency references/gaps/counts; its events do not publish those metric names. `metrics.py:117-126,411-445` aggregates only primary affected-findings data. T-176's task document explicitly lists `openvex.cve_statements_by_status` under telemetry.

**Expected/actual:** a successful admitted dependency companion should expose its separately attributed CVE counters. The only test assertion for the dotted metric uses the pure helper's in-memory return; it is not wired into published attempt telemetry/accepted aggregation.

**Impact:** the promised companion metrics never appear, especially when dependency statements exist but the primary export has zero statements. Primary finding counts must **not** be inflated to compensate. **Confidence:** high static trace; full runtime acceptance with a real dependency producer was not possible because of DI-05.

**Smallest correction:** persist/aggregate separate dependency counters through the verified companion result, with acceptance and deduplication semantics matching primary metrics. **Overlap:** explicitly in completed T-176 scope, not a new observability redesign.

## Known shared gap and documentation/test drift

### Payload reads lack dataset-level observations — known cross-job class

`BoundedInputReader.read/json` (`inputs.py:189-199`) verifies physical bytes but does not call `observe_output`; `jobs/bound_artifacts.py:32-58` likewise only resolves/hashes/parses. The envelope path records `handoff` observations (`runtime/consume.py:162-209`, `storage/shared.py:566-575`), not payload reads. Instrumented output reading exists at `runtime/inputs.py:527-552` but is not used on these paths.

A real `load.verify_inputs` inside `input_read_scope`, with declared gate/review pins and the fixture's expensive review authority doubled, produced **two reads, both `output_kind="handoff"`**, while retaining **50 measured input/schema bindings**. In particular there was no gate `publication_gate_decisions` read observation. The dependency direct reader has the same static omission.

This is not missing physical verification or permission to use arbitrary latest data. It is missing dataset-level read attribution/enforcement at those private reader boundaries. Decision-audit internals can record their own explicit output observations in real reviews; the fixture's audit is legacy/unrecorded, so the probe does not claim every real run has exactly two observations. Group with the coordinator's established **TA-F04/PB-F04/TS-F09/change-context** correction. `docs/architecture/job-input-contracts.md` explicitly acknowledges remaining private-reader instrumentation limitations.

### Low documentation/selection drift

* `tests/job-test-map.json:475-484` and the generated job page omit existing `test_contract_declares_decision_audit.py`, `test_cve_reachability_openvex.py` and `test_dependency_publication.py`. These were explicitly included here.
* The generated job page's step narrative only explains primary export despite listing companion datasets. `docs/operations/openvex-export.md:37-50` is the more complete current companion description.
* Architecture text read at `docs/architecture/openvex-export.md:99-104` still says seven schemas/nine snapshots; current code has eight schemas/ten resources. The detailed operator page correctly says ten. Its later product prose remains primary/v1-oriented despite the added companion.
* The **State** field of T-176 references absent `docs/tasks/2026-11-17-t176-executive-report-dossier-and-12axis-radar.md`. The different `...expanded-radar-executive-dossier-redesign.md` task plan exists and was read. This missing record is not evidence that implementation never happened.
* T-147/T-157 are existing declaration-documentation gaps, not missing dispatch handlers. Historical broad coverage claims in TODO and `docs/reviews/openvex-export-implementation.md` do not certify the newer companion.

## Focused validation record

### Safety and source checks

The selected unit bodies and their fixtures were inspected first. `AcceptedInputDisk` creates small hash-bound run artifacts and doubles only `load_accepted_review`; the real gate classifier, common handoff verification and export handlers run. `ExportUnits` directly calls handlers; it does **not** launch a `JobRunner` review. Its synthetic handoff helper sees an already-created resolved configuration, so its fallback runner-binding branch is not used. The CVE/projector tests are pure local schema checks. Wiring only loads/describes configuration and replaces the forbidden disabled CLI runner. Metric tests double their accepted-reader boundary. No selected test launches a provider, real tool or service.

Preflight:

```bash
cd /home/wsollers/projects/appsec-review
git rev-parse HEAD
git branch --show-current
git status --short
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Result: exact required SHA, `main`, clean, import `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. A Python preflight asserted `not offending_environment(os.environ)` and absent `PYTEST_ADDOPTS`; wrapper interpreter override was absent. No environment was repaired or installed.

All Linux commands used the brief's base64-over-SSH transport. Forward slashes below are Linux command arguments inside SSH, not paths used against the Windows checkout.

### Collection and execution commands

The collection command was:

```bash
.venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-openvex-collect-20261118-44 \
  -o cache_dir=test/tmp/job-audit-openvex-collect-cache-20261118-44 \
  tests/test_openvex_job_units.py tests/test_openvex_settings.py tests/test_openvex_wiring.py \
  tests/unit/job_openvex_export \
  tests/test_openvex_projection.py::test_automatic_defaults_generate_valid_local_files_without_operator_setup \
  tests/test_openvex_projection.py::test_exact_selection_sets_counts_and_empty_nonclean_outcomes \
  tests/test_openvex_projection.py::test_review_dimensions_and_resolving_evidence_remain_verbatim \
  tests/test_openvex_projection.py::test_deterministic_order_independent_replay_and_output_prefix \
  tests/test_openvex_inputs.py::test_common_envelopes_use_the_real_shared_reader_and_bind_accounting_before_authority \
  tests/test_openvex_inputs.py::test_every_common_accounting_file_is_bounded_before_shared_authority \
  tests/test_openvex_inputs.py::test_common_accounting_transitive_references_are_bounded_before_authority \
  tests/test_openvex_inputs.py::test_common_envelope_accounting_counts_once_and_obeys_lowered_limits \
  tests/test_openvex_metrics.py::test_fresh_mixed_accepted_counts_come_from_verified_bytes_not_accounting_events \
  tests/test_openvex_metrics.py::test_accepted_empty_is_explicit_zero_not_unavailable_or_zero_size_sample \
  tests/test_openvex_metrics.py::test_completed_events_and_files_are_not_accepted_semantic_success \
  tests/test_openvex_metrics.py::test_runtime_failure_still_prevents_fresh_semantic_totals_after_an_acceptance_event
```

**211 collected in 2.19 s**, exit 0. No tests executed by collection.

The first wrapper attempt used those same selectors, including the directory, with `--parallel --test-workers 2 --shuffle-seed 44047 --max-tests 211 --expect-tests 211 --timeout-seconds 180`. It refused before collection/execution: **exit 2**, `selector must name an existing, unredirected test file under tests/: 'tests/unit/job_openvex_export'`. Elapsed time was not supplied by that early refusal; no test failure or skip occurred.

The corrected command expanded that directory to the four inspected files, without changing the collection:

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 44047 \
  --max-tests 211 --expect-tests 211 --timeout-seconds 180 -- \
  tests/test_openvex_job_units.py tests/test_openvex_settings.py tests/test_openvex_wiring.py \
  tests/unit/job_openvex_export/test_contract_declares_decision_audit.py \
  tests/unit/job_openvex_export/test_coverage_edges.py \
  tests/unit/job_openvex_export/test_cve_reachability_openvex.py \
  tests/unit/job_openvex_export/test_dependency_publication.py \
  tests/test_openvex_projection.py::test_automatic_defaults_generate_valid_local_files_without_operator_setup \
  tests/test_openvex_projection.py::test_exact_selection_sets_counts_and_empty_nonclean_outcomes \
  tests/test_openvex_projection.py::test_review_dimensions_and_resolving_evidence_remain_verbatim \
  tests/test_openvex_projection.py::test_deterministic_order_independent_replay_and_output_prefix \
  tests/test_openvex_inputs.py::test_common_envelopes_use_the_real_shared_reader_and_bind_accounting_before_authority \
  tests/test_openvex_inputs.py::test_every_common_accounting_file_is_bounded_before_shared_authority \
  tests/test_openvex_inputs.py::test_common_accounting_transitive_references_are_bounded_before_authority \
  tests/test_openvex_inputs.py::test_common_envelope_accounting_counts_once_and_obeys_lowered_limits \
  tests/test_openvex_metrics.py::test_fresh_mixed_accepted_counts_come_from_verified_bytes_not_accounting_events \
  tests/test_openvex_metrics.py::test_accepted_empty_is_explicit_zero_not_unavailable_or_zero_size_sample \
  tests/test_openvex_metrics.py::test_completed_events_and_files_are_not_accepted_semantic_success \
  tests/test_openvex_metrics.py::test_runtime_failure_still_prevents_fresh_semantic_totals_after_an_acceptance_event
```

**211 passed, 0 failed, 0 skipped, 0 >10 s**, exit 0. Pytest **63.23 s**; wrapper **71.55092332593631 s**. Supervised collection **3.359 s**, execution **67.827 s**; both report cleanup confirmed and zero remaining processes. The wrapper owned fresh base temp `test/tmp/tests-custom-20261118-135205-028948-3587047`, reused sequentially for its own collection/execution only.

Retained evidence under the authorized checkout:

* `test/tmp/logs/tests-custom-20261118-135205-028948-3587047.log`
* `test/tmp/logs/tests-custom-20261118-135205-028948-3587047.collection.log`
* `test/tmp/tests-custom-20261118-135205-028948-3587047.collection.json`
* `test/tmp/tests-custom-20261118-135205-028948-3587047.junit.xml`
* `test/tmp/tests-custom-20261118-135205-028948-3587047.timings.sqlite`
* `test/tmp/reports/tests-custom-20261118-135205-028948-3587047.json`

### Offline reproduction programs

Both commands were `.venv/bin/python - <<'PY' ... PY`, transported over SSH from the authorized checkout. No code file was created. These programs wrote only inert fixtures beneath unique `test/tmp/job-audit-openvex-*` directories. Timings below are measured program-body times after imports, not process startup.

**Program 1 — 0.062 s, exit 0:** actual dependency key, product identity, gap loss, nullable-coordinate consumer failure. Reproduction body:

```python
import json, hashlib, time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from appsec_review.jobs.job_openvex_export import contracts as c, dependencies as d
from appsec_review.jobs.job_dependency_intelligence.reachability import (
    evaluate_sca_reachability, DependencyIntelligenceSettings)
from tests.openvex_support import ROOT, enabled_settings

start = time.perf_counter()
root = Path("test/tmp/job-audit-openvex-probes-20261118-44").resolve()
root.mkdir(parents=True, exist_ok=False)
settings = enabled_settings()
snapshot = "f" * 64
verified = SimpleNamespace(
    run_id=root.name,
    source=SimpleNamespace(target_snapshot=snapshot, repository_iri=settings.repository_iri),
    provenance=SimpleNamespace(resolved_config_sha256="a"*64,
                              gate=c.ArtifactRef("data/gate.json", "b"*64)),
    gate_completed_at="2026-11-18T00:00:00Z", gate={"limitations": []})
row = {
    "advisory_id": "CVE-2026-12345", "cve_ids": ["CVE-2026-12345"],
    "package_name": "sample", "package_version": "1.0", "purl": "pkg:pypi/sample@1.0",
    "ecosystem": "pypi", "severity": "high", "direct": True, "match_sources": ["scanner"],
    "affected_symbols": ["parse"], "affected_modules": ["sample"],
    "reachability": "symbol_reachable", "ffi_mechanisms": [],
    "call_sites": [{"path": "source.py", "line": 3, "symbol": "parse"}],
    "dependency_ids": ["dep-1"]}

def document(rows, gaps=()):
    return {
        "schema": "appsec-review/sca-reachability/1", "source_fingerprint": snapshot,
        "configured_osv_mode": "disabled", "osv_matching_mode": "disabled",
        "advisories": rows, "gaps": list(gaps), "coverage": "partial" if gaps else "complete",
        "telemetry": {"advisories_matched": len(rows), "osv_matching_mode": "disabled",
                      "symbol_reachable_count": sum(r["reachability"] == "symbol_reachable" for r in rows),
                      "ffi_boundary_matches": 0}}

def project(doc, *, key="publication.publish_handoff", output_gaps=()):
    path = root / "data" / "sca.json"
    path.parent.mkdir(exist_ok=True)
    raw = c.canonical_bytes(doc)
    path.write_bytes(raw)
    ref = {"path": "data/sca.json", "sha256": hashlib.sha256(raw).hexdigest()}
    accepted = SimpleNamespace(
        path="data/jobs/job_dependency_intelligence/attempts/attempt_0001/handoff.json",
        sha256="c"*64,
        handoff={"resolved_config_sha256": verified.provenance.resolved_config_sha256,
                 "outputs": {key: {"sca_reachability": ref, "gaps": list(output_gaps)}}})
    with patch.object(d, "_accepted", return_value=accepted):
        return d.dependency_projection(root, verified, settings, ROOT, "audit")

try:
    project(document([row]), key="acceptance.publish_handoff")
    raise AssertionError("expected producer-key mismatch")
except KeyError as exc:
    print("DI-05 confirmed:", repr(exc))
_, first = project(document([row]))
first_expected = c.source_product_id(verified.source.repository_iri, snapshot, "a"*64)
verified.provenance.resolved_config_sha256 = "d"*64
_, second = project(document([row]))
second_expected = c.source_product_id(verified.source.repository_iri, snapshot, "d"*64)
assert first == second and first_expected != second_expected
print("OX-01 product/config:", json.loads(first)["statements"][0]["products"][0]["@id"],
      "identical_document_across_configs=", first == second)
for rows in ([], [row]):
    result, payload = project(
        document(rows, ["osv_index_unavailable", "source_file_limit_exceeded"]),
        output_gaps=["dependency_lookup_incomplete"])
    assert result["gaps"] == [] and result["terminal_status"] == "SUCCEEDED"
    print("OX-02 upstream gaps lost:", len(rows), "advisories ->", result["terminal_status"],
          result["gaps"], "document_present=", payload is not None)
sca = evaluate_sca_reachability(
    source_fingerprint=snapshot, repository_root=ROOT, run_root=root, target_root=None,
    dependencies=[{"dependency_id": "dep-1", "name": "sample", "version": "1.0"}],
    scanner_advisories=[{"advisory": "CVE-2026-12345", "package": "sample", "version": "1.0"}],
    settings=DependencyIntelligenceSettings(osv_version_matching="disabled", reachability_enabled=False))
assert sca["advisories"][0]["purl"] is None and sca["advisories"][0]["ecosystem"] is None
try:
    project(sca)
    raise AssertionError("expected incomplete-identity failure")
except ValueError as exc:
    print("OX-03 real producer nullable identity:", type(exc).__name__, str(exc))
print("probe_elapsed_seconds=", round(time.perf_counter()-start, 3))
```

**Program 2 — exit 0:** real task handlers, real input-read scope, and fixture authoritative review boundary. Branch timings: **0.929 s** missing observations; **2.148 s** wrong result cap; **2.712 s** split input bound.

```python
import json, time
from dataclasses import replace
from pathlib import Path
import pytest
from appsec_review.jobs.job_openvex_export import contracts as c, dependencies as d, inputs
from appsec_review.jobs.job_openvex_export.datasets import CONTRACT
from appsec_review.runtime.inputs import input_read_scope
from tests.openvex_input_support import AcceptedInputDisk
from tests.openvex_support import ROOT, enabled_settings
from tests.test_openvex_job_units import ExportUnits

root = Path("test/tmp/job-audit-openvex-units-20261118-44").resolve()
root.mkdir(parents=True, exist_ok=False)
def fixture(name, settings=None):
    p = root/name
    p.mkdir()
    mp = pytest.MonkeyPatch()
    disk = AcceptedInputDisk(p, mp, buckets=(), settings=settings)
    return disk, ExportUnits(disk), mp
def dep(disk):
    body = {
        "schema": "appsec-review/sca-reachability/1", "source_fingerprint": disk.snapshot,
        "configured_osv_mode": "disabled", "osv_matching_mode": "disabled", "advisories": [],
        "gaps": ["osv_matching_disabled"], "coverage": "partial",
        "telemetry": {"advisories_matched": 0, "osv_matching_mode": "disabled",
                      "symbol_reachable_count": 0, "ffi_boundary_matches": 0}}
    ref = disk.put(
        "data/jobs/job_dependency_intelligence/attempts/attempt_0001/sca-reachability.json", body)
    value = disk.handoff(d.DEPENDENCY_JOB, {"publication.publish_handoff": {
        "sca_reachability": ref, "gaps": ["osv_matching_disabled"]}})
    value["attempt_id"] = "attempt_0001"
    return disk.publish(d.DEPENDENCY_JOB, value)

t = time.perf_counter()
disk, units, mp = fixture("observations")
try:
    units.context = replace(units.context, contract=CONTRACT, upstream_handoffs={
        inputs.GATE_JOB: disk.gate_job_ref["sha256"], inputs.REVIEW_JOB: disk.review_job_ref["sha256"]})
    with input_read_scope(units.context) as reads:
        loaded = units.execute("load.verify_inputs")
        observed = reads.document()["reads"]
    verified = c.VerifiedInputs.from_mapping(json.loads((disk.root/loaded["artifact"]["path"]).read_bytes()))
    limit = len(verified.input_inventory)
    assert len(observed) == 2 and {r["output_kind"] for r in observed} == {"handoff"}
    print("Shared observation gap:", [(r["producer"], r["output_kind"]) for r in observed],
          "physical_verified_bindings=", limit, "elapsed=", round(time.perf_counter()-t, 3))
finally:
    mp.undo()
t = time.perf_counter()
disk, units, mp = fixture("result-bound", enabled_settings(max_document_bytes=1))
try:
    dep(disk)
    assembled = units.assemble()
    resultref = assembled["dependencies"]["artifact"]
    size = (disk.root/resultref["path"]).stat().st_size
    assert assembled["document"] is None and assembled["dependencies"]["document"] is None
    try:
        units.execute("acceptance.publish_handoff")
        raise AssertionError("expected wrong result-byte-bound failure")
    except c.ExportError as exc:
        assert exc.reason == c.ExportFailureReason.BOUND_EXCEEDED
        print("OX-04 wrong result limit: assemble passed; accept failed:", exc.reason.value,
              str(exc), "result_bytes=", size, "max_document_bytes=", 1,
              "elapsed=", round(time.perf_counter()-t, 3))
finally:
    mp.undo()
t = time.perf_counter()
disk, units, mp = fixture("combined-bound", enabled_settings(max_bindings=limit))
try:
    dep(disk)
    units.assemble()
    published = units.execute("acceptance.publish_handoff")
    verified = c.VerifiedInputs.from_mapping(json.loads(
        (disk.root/units.outputs["load.verify_inputs"]["artifact"]["path"]).read_bytes()))
    reader = inputs.BoundedInputReader(disk.root, disk.settings)
    inputs._accepted(reader, d.DEPENDENCY_JOB)
    union = {r.path for r in (*verified.input_inventory, *reader.inventory)}
    assert len(union) > limit
    print("OX-05 combined input limit:", len(union), "unique verified inputs > max_bindings=", limit,
          "main=", len(verified.input_inventory), "dependency=", len(reader.inventory),
          "accept_succeeded=", bool(published["artifact"]), "elapsed=", round(time.perf_counter()-t, 3))
finally:
    mp.undo()
```

Minor inspection issues, not test failures: the initial skill glob found no files, corrected by listing skills over SSH; Linux `rg` was unavailable, so searches used the UNC tool or standard `grep`; one guessed operations-directory search failed before locating `deploy/dagster/bin/ops_tests.py`; the T-176 State-linked task document was absent. No installation or source changes were used to work around these.

## Read scope and named unverified gaps

**Read fully:** shared brief; authorized `AGENTS.md` and coordination skill; canonical generated operation page; all twelve Python modules inside `src/appsec_review/jobs/job_openvex_export/`; SCA schema and dependency-result schema; `jobs/accepted_review.py`, gate `verify.py`, `jobs/bound_artifacts.py`, `runtime/consume.py`; test modules `test_openvex_job_units`, `test_openvex_settings`, `test_openvex_wiring`, all four selected `tests/unit/job_openvex_export/test_*.py`; `openvex_support`, `openvex_input_support`, `handoff_fixture`, unit-environment guard; prior dependency-intelligence audit; the existing T-176 expanded-radar task plan.

**Sampled/narrow reads:** architecture OpenVEX lines 1-280; detailed operator OpenVEX page 1-230; implementation review 9-108; job-input-contracts architecture; TOML/release/config loader and registry/topology wiring; runtime input-observation and job context/identity paths; shared handoff verification/consumption; dependency producer handoff and SCA merge/publication; telemetry dispatch; final-report gate load/assembly; review-data inventory and retrieval metadata route; test-wrapper scripts; exact selected bodies/helpers in `test_openvex_inputs` (1-201), `test_openvex_projection` (1-213), `test_openvex_metrics` (1-245); relevant TODO sections and cumulative prior findings.

**Material unread/unexecuted scope:**

* `tests/test_openvex_contracts.py` and the unselected portions of input/projection/metrics suites were not executed or fully read. The 211 cases are a bounded selection, not the historic 551-case claim or all current OpenVEX cases.
* The complete upstream OpenVEX/final-report schema texts and every transitive shared validator, ledger merge, package verifier, chain verifier and decision-audit implementation were not independently re-audited. Actual schema pin verification ran. The gate has its own independent auditor; this report does not rely on an unfinished gate verdict.
* No real accepted review chain, complete `JobRunner`/Dagster admission-finalization/reuse cycle, mounted release/signature behavior, live target output or whole-job content acceptance was exercised. Direct handler acceptance is not runtime acceptance.
* Accepted-review authority was explicitly doubled in disk/unit probes; positive results do not prove real ledger/cell/audit data revalidates. The nullable-coordinate probe used the real local SCA producer with all external/target work disabled.
* Full dependency bytes/status telemetry after genuine runtime acceptance, current dependency-head invalidation in an operator view, and large-byte analogue of OX-05 were not executed. Historical primary readers do hash-check the common runtime artifact list; this audit does not allege dependency files are wholly unbound.
* No actual PURL ecosystem corpus, real advisories, feed freshness, vulnerable-call reachability, vendor assertion, release applicability, exploitation or target finding quality was verified. Prior DI-02/DI-03 reachability/identity defects remain attributed upstream, not rediscovered as exporter defects.
* No full protected-dataset retrieval/indexing lifecycle was run. Declarations and the bounded metadata route were inspected; no payload was disclosed externally.

Final root inspection preserved unrelated existing files. Only this auditor's two probe directories and collection host-pins fixture were removed. `git diff --check` and `git status --short` remained clean at the required exact revision. **Audit complete for this job only; stop here.**
