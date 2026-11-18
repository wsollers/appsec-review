# Job 43/47 — job_final_publication_gate

## Result and authority

- Audited **clean `main`, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, at `/home/wsollers/projects/appsec-review` in Ubuntu-22.04 through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the corresponding `\\wsl.localhost\Ubuntu-22.04\home\wsollers\projects\appsec-review` view. Initial, pre-test and final checks agreed. Python imported this checkout's `src/appsec_review/__init__.py`.
- Read the complete updated assignment brief, authorized AGENTS, canonical coordination skill and prior inference report. This was one read-only functional auditor, not a penetration test or pipeline run.
- **Two new medium-severity certification defects reproduced:** a verified unit-context file is omitted from the durable snapshot binding list; and the seal/shared reader accept contradictory bucket memberships/counts.
- **122/122 focused units passed, 6.32 s pytest time, 14.315364 s wrapper total**, two workers, shuffle seed `43047`. No failed/skipped/over-ten-second cases. Every mapped gate unit file was included.
- A separate pinned-head observation establishes documentation drift, **not a third functional defect**. Existing upstream findings are attributed separately below.
- No source edits, installs, environment repair, models, providers, compilers, target execution, services, integration/acceptance/live/Dagster reviews, subagents, commits or pushes. Synthetic files existed only under this auditor's `test/tmp/job-audit-final-gate-43-repro-20261118a`, then were removed. Wrapper evidence remains in its private run directory.

**This is not a correctness certificate.** The reproductions demonstrate bounded verification behavior, not a false real-target vulnerability, a production-corrupted finding, or an end-to-end accepted review. The normal classifier produced correct buckets in the inspected tests.

## Registration, configuration and contract

Factory registration: `src/appsec_review/runtime/registry.py:107,178`. The resolved dev activation probe returned **True**. `appsec-review.toml:3493-3511` declares one job worker, one worker per step, `enabled=true`, `max_packages=10000`, and exactly:

1. `load.verify_review`
2. `gate.classify`
3. `acceptance.publish_handoff`

`settings.py:14-35` accepts exactly `enabled` and `max_packages`; the latter must be a non-Boolean integer in `[1,10000]`. There is no model profile, prompt, role, retrieval tool or runtime skill dispatched by this job. The operations page's generated “Undeclared (T-147)” labels are incomplete task-binding metadata, not missing handlers.

`datasets.py:27-102` supplies `REVIEW_GRAPH`, `ACCEPTED_EVIDENCE`, `always_execute=False`, `propagate_handoff=True`. Its five explicit scheduling predecessors are inference, PoC, planning, validation and dossier publication; `orchestration/topology.py:46-81` combines these with semantic inputs, projects disabled vertices and removes transitive edges. The current generated operations graph shows dossier as the reduced direct predecessor. `Job.consumes` is derived, not a second authority.

The runtime probe counted **45 requirements across 15 producers**, all handoff-channel inputs:

| Producer(s) | Requirements | Actual use / admission |
| --- | ---: | --- |
| `job_inference_security_review` | 14 | Required/reject envelope; accepted scope, triage, review packages/cells, ledger, chains and scores/findings; six protected operational audit outputs. Main review loader performs the actual reads. Audit metadata is when-declared/gap; the other five audit families are when-declared/not-applicable. Historical declaration absence is explicit `legacy_unrecorded`, not newly assigned provenance. |
| `job_poc_generation` | 4 | When-enabled/reject envelope; summary, writer cells, reproducer/provenance artifacts. Explicit exact upstream PoC supply also enables otherwise-disabled manual PoC admission. |
| `job_remediation_planning` | 3 | When-enabled/reject envelope; planning summary and proposals. Confirmed-only exact intake. |
| `job_remediation_validation` | 3 | When-enabled/reject envelope; summary and validation receipts. Requires the accepted planning wrapper and matching plan/patch. |
| `job_dossier_publication` | 2 | When-enabled/reject envelope and dossier publications; exact confirmed-finding plus admitted-PoC domain, with capped omissions. |
| `job_language_build` | 1 | Optional envelope, read only when an admitted PoC names its language-build handoff digest. |
| Artifact security, CI, Clang, CodeQL, compiled C++, dependency intelligence, evidence collection, post-build assessment, review-data indexing | 2 each | Optional envelopes plus the specific original observation/precomputed shard families listed in `jobs/decision_audit_inputs.py:26-38`. These support audit source verification, not a whole pre-review coverage census or worker retrieval grant. |

`indexing/store.py:36-51` uses `runtime.consume.accepted_upstream`, verifies the handoff and consumes its shared provenance. Inside an attempt, `runtime/consume.py:170-212` requires declared envelope permission and exact admitted claim pins. Optional unsupplied input returns `None`; an undeclared read fails. `runtime/inputs.py:270-303` rejects missing required/enabled envelopes before the job's callbacks. An accepted envelope can still have partial item coverage.

### Every step/task

All paths in this table are under `src/appsec_review/jobs/job_final_publication_gate/` unless qualified.

| Declared task | Actual execution | Output, validation and limit |
| --- | --- | --- |
| `load.verify_review` | `job.py:64-122`: shared accepted-review verification with `max_packages` and explicit protected-audit opt-in; typed audit summary; frozen configuration identity; configured completion enablement plus explicit PoC admission; verify attachments and upstream equality; retain the frozen configuration binding idempotently; emit bounded capability/review telemetry. | `verified-review.json`, containing projected review, packages, partition, capabilities, attachments, bindings and sanitized `_decision_audit`. Returns `SUCCEEDED` only after this loading work; domain limitations are classified later. No model/tool task. FPG-F01 concerns missing transitive binding retention. |
| `gate.classify` | `job.py:124-130`, `classify.py:67-214`: hash-read the load result; deterministic ID-sorted placement; preserve accepted state/ship-block; compute bucket counts and ordered limitations. | `classification.json`, `package_counts`, publication status, empty handler gap list. `PUBLISHABLE_WITH_LIMITATIONS` is not execution failure. Nonpartitioned ordinary packages raise; reference-unavailable packages are withheld. |
| `acceptance.publish_handoff` | `job.py:132-157`: hash-read both inputs, assemble `/2` document, rehash loaded snapshot and reselect accepted upstream identities, validate gate schema and total/list-length accounting, write final artifact, emit metrics. | `final-publication-gate.json`; handoff `/2`, counts/limitation IDs; only `kind=gap` becomes handler gap text, yielding `COMPLETED_WITH_GAPS`; notices/not-run do not. FPG-F02: it does not rederive or fully reconcile the classification. |

`job.py:159-168` wires task dependencies exactly. `runtime/units.py:142-211` records handler exceptions as failed tasks and blocks dependent completion; returned domain dispositions remain separate from successful handler execution. The job uses the legacy human-readable gap path, not `strict_gaps=True`; no new terminal vocabulary is introduced.

## Accepted review, source, hash, seal and attachment trace

### Review revalidation

The entire `jobs/accepted_review.py` was read:

- `:197-229`: accepted review envelope/output/schema/run identity, accepted-scope manifest identity, and package limit.
- `:148-174`: both lane manifests and lane sets; manifest content identities, package bytes, optional behavior-model artifact references. `review/packages.py:2452-2493` also verifies content-addressed unit contexts and merges referenced context into package bodies. **Those context reads are not returned as bindings; FPG-F01.**
- `:114-145`: ledger receipt, merged ledger/shard hashes and row counts, per-shard chain verification, projected head/hash, byte-for-byte ledger/projection reproduction and exact ledger gap IDs.
- `:230-232` plus `jobs/job_inference_security_review/chains.py:492-557`: exact chain ledger/manifest membership, candidate accounting, proposals, challenges, decisions, actor-cell identity/status and original actor receipt hashes/request identities.
- `:234-278`: coverage file/hash and row count; schema/identity/ledger-presence checks on scores; finding schema, ID, claim/state, provenance, policy hash, accepted chain membership, listed score IDs and recorded judge verdict identities.
- `:280-312`: no duplicate finding IDs/claims; PoC basis hashes and candidate/finding agreement; exact confirmed/supported partition and row fields; recount ship-block totals/by-lane.
- `:314-363`: retain explicit artifact bindings, preserve projected fields without adjudicating again, and merge all actual protected-audit read receipts when opted in.

Important limits: this is not a fresh compiler/source analysis or semantic re-adjudication. Source fingerprint/target/config/attempt accounting is verified by the common handoff layer (`runtime/handoff.py:412-460`). The gate does not compare to a live target checkout. Hash verification proves accepted bytes, not source entailment, exploitability, or completed investigation.

The shared loader does not itself fully reconcile every finding projection field against every ledger fact. For example, `accepted_review.py:244-251,270` checks score ownership only as “claim exists” plus listed score ID; OpenVEX separately checks score claim/projection equality at `job_openvex_export/inputs.py:559-563`. This ownership cross-product was **not reproduced or counted as a new finding** here. Full score/evidence-factor and conditional decision-audit combinations remain an explicit unread/unexecuted matrix.

### Decision audit and known blindness seam

`review/decision_audit/reader.py:652-762` verifies protected output declarations, attempt-root custody, descriptor, frozen policy, target/run/manifest/review/ledger origins, canonical manifests/shards/continuations and configured byte/record limits. Unavailable descriptors are validated, not replaced with a fabricated empty audit. Its bounded reader hashes opened bytes and retains read receipts (`:129-242`).

`_authority_sources` (`:245-315`) admits original cell receipts/request checks and selected original shards. `_membership` (`:318-424`) cross-checks claim/cell/package/adjudication/relations/score references. `_verification_facts` (`:587-614`) compares recorded structural checks and, when present, request-check bytes. `_observed_sources` (`:617-649`) verifies actual observed own-read receipt relationships. Membership-specific proposal helpers `:427-586` were not fully read.

`classify.decision_audit_summary:28-55` requires a typed `AcceptedAudit` for the exact review wrapper. It exposes only availability, closed absence reason and incomplete population class names. `unknown expected`, omitted/unavailable counts, and unavailable lead membership generate `decision_audit_partial`; counts are population classes, not mixed record units. Audit narratives/records are not placed into the public gate.

**ISR-F02 remains a known upstream seam, not a new gate defect:** the prior inference report reproduced missing request-check evidence being interpreted as independent confirmation under its short-marker/reuse conditions. This gate intentionally preserves accepted claim state; it does not rerun R5/R6 adjudication. Reading the audit is not proof that the missing upstream blindness evidence has been repaired. No end-to-end final-gate acceptance of that exact ISR-F02 fixture was executed here, and this report does not claim it was.

### Completion attachment matrix

`attachments.py` was read in full.

| Capability | Checks and exact accounting | Projection / failure behavior |
| --- | --- | --- |
| PoC | `:95-160`: summary schema/nonexecution; same accepted manifest; optional exact language handoff; actual review candidate parser; candidate/omitted IDs exactly partition candidates; candidate status counts; finding/hash/state/judge/basis/package agreement. Source-bearing outcomes validate provenance and compile schema/status/claim; `compile_verified` requires files. Nested row references rehashed. | Sorted claim IDs, sanitized fixed description, function metadata/file refs, `runtime_verified=false`, no execution/result ID. Candidate omissions and failure statuses become capability gaps, not claim refutations. This does not recompile or reexecute. |
| Planning | `:163-206`: plan/summary schemas; exact confirmed finding digest, claim and adjudication; artifact run/status/reason/upstream; assurance; all nested plan refs. Successful proposal requires an artifact; rows uniquely equal confirmed intake. | Only finding binding, status, plan ref, gap IDs and nonexecution. Full plan prose/patch content remains protected. |
| Validation | Same helper; exact accepted planning handoff, matching finding plan and patch, schemas/run/adjudication/status/reason; runtime regression must be `not_performed_by_policy`. | Checked/manual/rejected/inconclusive/capped statuses never clear or promote findings. Receipt/schema validation is not fresh semantic or compiler validation. |
| Dossiers | `:209-241` calls `job_dossier_publication.job.verify_publication:291-334`: count/kind/status/duplicate checks; JSON/LaTeX/PDF/receipt refs and render consistency. Gate checks finding/run/dossier identity, exact confirmed-plus-PoC candidate set, cap and omission reason. | Protected contents are not inlined. Missing PDF is consistent with `latex_only`/render failure and a capability gap; corrupt referenced bytes are errors. |
| Attack chains | `:321-374`: already bound review manifest; schema/run identity; exact proposed/admitted/assessed/capped/rejected/deduplicated accounting and dispositions; bounded frontier with accepted claims; unique chains, components, artifact/manifest identities/status/limitations/membership. | Sorted sanitized attachments and candidate/status counts. Qualified-supported chains are not unconditionally withheld; insufficient evidence/caps/gaps remain limitations. No independent new chain proposal occurs here. |

Common envelope checks at `attachments.py:243-320` bind same run and review, stale/unadmitted optional producer references, exact item/gap envelope agreement, and supported terminal classes. `SKIPPED_NA` is permitted only for empty rows. Disabled producers are not discovered as evidence. `bind_tree:52-64` rehashes discovered nested references; bindings are deduplicated/sorted at `:375-377`.

`capability:67-85` chooses:

- disabled → `SKIPPED_POLICY`;
- enabled missing summary, omitted work, or gap count → `GAP`;
- verified empty eligible scope → `SKIPPED_NA`, explicitly **not clean coverage**;
- otherwise → `SUCCEEDED`, explicitly **not runtime proof**.

Current configuration deliberately requires enabled producer envelopes. Consequently the low-level “enabled but no handoff → GAP” helper branch is normally blocked earlier by typed admission, not a fallback for failed enabled jobs. The current operations and architecture pages explicitly describe this decided behavior. The older system report C16-F05 criticized it; **it is not re-counted or proposed for unilateral relaxation here**.

### Classifier conditions, incomplete and error cases

| Condition | Result |
| --- | --- |
| Referenced PoC status/result has no matching accepted attachment | `withheld`, `poc_outcome_unavailable`. |
| Referenced chain identity absent from accepted attachments | `withheld`, `attack_chain_unavailable`. |
| No withholding reason; confirmed intake | `publishable`, state and ship-block unchanged. |
| No withholding reason; supported intake | `verification_backlog`, unconfirmed label retained. |
| Neither accepted state/partition matches | `IntegrityError`; normal admitted review partition is checked earlier. |
| Degraded/empty/incomplete review or degraded/failed/canceled lane | Ordered `review_degraded`, `review_empty`, `review_incomplete`, `lane_degraded` gaps as applicable. |
| Ledger gaps/nonreviewed lane-B rows | `gaps_recorded`, `coverage_incomplete`; this is not a whole-target coverage percentage. |
| Distinct-verification pending, unrated technical severity, decision pending, absent scores | Four separately named gaps; not low severity or shipment clearance. |
| Withheld packages / duplicate pairs | Named counted gaps. |
| Five completion capabilities | `*_not_run` for policy-disabled; `*_gap` for capability gap. Accepted empty scope remains explicit in capability reason. |
| Audit disabled/historical / unavailable / partial / available | `not_run` / `gap` / population-class `gap` / traceability-only notice. |
| All cases | `compile_only_nonexecution` notice. Only actual gap limitations change status to `PUBLISHABLE_WITH_LIMITATIONS`. |

There is no configured “require every finding confirmed,” “require runtime PoC” or global no-gaps publication veto. The gate can legitimately publish an empty or incomplete result **with limitations**. It is not a release-approval gate.

### Snapshot versus current acceptance

`attachments.reverify_snapshot:380-394` hashes the frozen binding list and compares selected accepted wrapper refs for review and enabled completion capabilities. **R3 proved a scope-dependent documentation discrepancy:** under a real `upstream_scope`, an unchanged claim-pinned `attempt_0001` is still selected after `latest.json` advances to `attempt_0002`; revalidation succeeds. Unscoped operator lookup rejects that same mismatch. This follows `runtime/consume.py:153-165`'s intentional historical-by-digest selection.

Thus the function's “refuse a concurrent upstream acceptance” docstring and architecture “pointer stability” wording are too broad. Actual protection is pinned-input/binding stability during runtime, and latest-pointer comparison outside runtime. **Do not replace it with unauthorized latest reads:** the immutable-input design is deliberate. No complete runner-level concurrency race was executed, so this is recorded as documentation drift/coverage limit, not a new runtime defect.

## New findings

### FPG-F01 — Medium — Verified package unit contexts are omitted from the durable gate binding closure

- **Evidence:** `src/appsec_review/jobs/accepted_review.py:148-174` retains lane set, manifest, optional model and package refs, but never returns `manifest["unit_contexts"]` refs. Actual context bytes are read and checked at `src/appsec_review/review/packages.py:2465-2474,2483-2492`. Snapshot consumers only rehash listed bindings at `src/appsec_review/jobs/job_final_publication_gate/verify.py:24-44`; they do not recursively reopen package manifests.
- **Trigger:** a verified hunt unit-context artifact later disappears or changes after the gate has sealed, while its manifest, wrapper and package bytes remain unchanged.
- **Expected / actual:** the certification should retain every verified dependency needed to revalidate the accepted package view. R1 passed two schema-valid synthetic lane manifests containing unit-context files through the real `_verify_package_manifests`: **two contexts verified, four bindings returned, zero contexts bound**. After changing one context file, `verify_gate_snapshot` succeeded; the real `verify_package_manifest` rejected that same tree with `package unit context does not match its reference`.
- **Impact:** the durable snapshot can remain acceptable to the final report's shared verifier after package evidence/routing context needed to reconstruct the accepted review is no longer reproducible. This is not a demonstrated alteration of the public finding text, nor proof that every production run misses every related backing artifact.
- **Confidence:** high for the missing closure and reproduced verifier disagreement. The demonstrator uses schema-valid context-bearing manifests with **empty package lists**, isolating the read/retention defect; it is not a full nonempty hunt/producer run. Static tracing shows the same omission when hunt packages reference those contexts.
- **Smallest correction:** retain run-relative `{path,sha256}` for every verified manifest unit-context entry, with the same containment checks and deduplication as other bindings. Add a direct downstream snapshot regression for post-seal context mutation/deletion.
- **Overlap:** T-5000 introduced shared hunt context and tests its immediate verifier; it does not list final-gate binding retention. T-5045 concerns lead admission/chart data, not this context integrity hole. T-5038 is the different shared-feed replay problem. No exact duplicate found in inspected reports/TODO entries.

### FPG-F02 — Medium — Gate sealing and the shared certificate reader accept contradictory bucket/count projections

- **Evidence:** `src/appsec_review/jobs/job_final_publication_gate/job.py:134-147` assembles the stored classification and checks only total package count and the sum of bucket-list lengths. `src/appsec_review/jobs/job_final_publication_gate/verify.py:71-78` checks total/list ID multiset but not each package's bucket, per-bucket count or state/withholding agreement. `docs/schemas/final-report/common.schema.json:928-963` constrains count types and `exact=true`, not those cross-field equalities.
- **Trigger:** a hash-bound classification/certificate is internally inconsistent, e.g. a faulty producer or coherently rewritten synthetic artifact. **No current normal classifier path producing this inconsistency was observed.** Ordinary byte corruption without updating the recorded hash is correctly rejected.
- **Expected / actual:** sealing must refuse a classification that disagrees with its verified source, and shared certificate validation must reconcile all duplicated accounting. R2 swapped publishable/backlog ID lists, kept the per-package buckets unchanged, and reported `{publishable:0, verification_backlog:0, withheld:2, total:2, exact:true}`. The real publication callback returned **`SUCCEEDED`**; the real closed schema and `load_accepted_gate` accepted it. R2b repeated the shared-reader check with a structurally complete synthetic handoff and **no accepted-handoff double**; it again accepted.
- **Impact:** downstream report counts can say two withheld while the report lists one publishable finding and one backlog item. `job_final_report_publication/report.py:79-82,119-134` selects sections from row buckets but copies the conflicting counts. OpenVEX has a stronger independent classifier-equality check (`job_openvex_export/inputs.py:613-619`) and should reject this inconsistent certificate rather than export it; that consumer was inspected, not executed.
- **Confidence:** high for the missing certification checks and reproduced acceptance; bounded integrity case, not a claim of production misclassification or an attacker bypass.
- **Smallest correction:** recompute `classify(verified)` at seal and require exact equality with the stored classification. In the shared reader, require unique package IDs, exact per-bucket ID sets/counts, row bucket/state/withheld-reason consistency, and total equal to all numerical bucket counts. Do not widen authority or recompute claim truth.
- **Overlap:** T-5043 records older final-report fixture/test defects; T-147 concerns generated task/dataset documentation. Neither covers these missing cross-field checks. No exact duplicate in the inspected C16 findings or per-job reports.

## Existing seams and non-findings

1. **ISR-F02:** missing verifier-blindness receipt can yield confirmation upstream. Incorporated as above, not recounted; no final-gate reproduction of that upstream fixture.
2. **POC-F09:** the prior PoC report records nested compile/brief qualifications lost before publication. Gate `attachments.py:145-148,315-320` validates receipt shape/status and uses top-level gaps/statuses; it does not independently recover those hidden upstream qualifications. This remains the PoC report's finding, not a new gate issue.
3. **Historical C16-F01:** pre-review coverage is not comprehensively unioned into gate limitations. Current protected audit source reads add traceability but do not establish whole-run scanner/build coverage. This audit did not run a missing-producer-to-review-to-gate cycle, so it does not certify the older claimed severity or call it newly reproduced.
4. **Historical C16-F05:** missing enabled completion envelopes remain a hard admission failure, now explicitly documented in the current architecture/operations contract. Not silently reinterpreted as a bug to relax.
5. **T-5043:** `tests/test_final_report.py` still contains heavy whole-review module fixtures and stale reader doubles. Its mapped acceptance selector was not executed. The fast mapped units replace neither that acceptance nor a connected review.
6. **T-5045:** lead-admission chart binding work remains an existing item; not duplicated here.
7. `compile_verified`, `build_checked`, `static_checked`, rendered dossiers and traceability are deliberately not runtime proof or a finding-state upgrade.

## Publication, schemas and downstream

One declared output, `publication_gate_decisions`, uses `artifact_only`, family `inference_review`, schema `appsec-review/final-publication-gate/2`, declared step `acceptance`. Its three globs cover `attempts/*/steps/load/**`, `/gate/**`, and `/acceptance/**` (`datasets.py:9-19`), including the intermediate verified/classification documents. No retrieval index is emitted. Inventory/coverage routes expose metadata, not protected attachment payloads; referenced protected PoC/audit/dossier outputs do not become new retrieval grants.

The final gate schema was read fully. It closes top-level keys, fixed five-capability/attachment maps, package/bucket arrays, status and limitations. Packages cap at 10,000, bindings at 30,000, limitations at 64; actual full binding volume/resource cost was not stress-tested. Common definitions were read for capabilities, attachments, finding projection through evidence fields, accounting/counts and coverage; remaining property details were sampled by executed schema tests, not manually exhausted.

`load_accepted_gate` verifies accepted wrapper/schema/output count and gate run/shape/bindings, optionally pins the expected wrapper digest, and deliberately does not discover later optional heads. Final report's `load.accepted_gate` (`job.py:102-114`) uses this reader and declares only the gate. OpenVEX additionally bounds/rehashes its inputs, reloads authoritative review/audit, checks binding inclusion, rederives the exact classifier document, checks frozen semantic settings/policy and validates resolving evidence/score ownership (`inputs.py:534-565,568-649`). The gate therefore is not the only check OpenVEX uses, but remains the report's certificate authority.

No final report rendering, PDF/SARIF execution or OpenVEX export was run.

## Validation commands and outcomes

Every Linux command used this transport, never the default Windows checkout:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# exact Linux command/script shown below
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Initial/pre-test identity commands:

```bash
git rev-parse HEAD
git status --short
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
find .claude/skills -name SKILL.md -print
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
git branch --show-current
```

### Collection

```bash
.venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-final-gate-43-collection-20261118a \
  tests/test_completion_publication.py \
  tests/test_gate_snapshot.py \
  tests/unit/job_final_publication_gate/test_classify_and_verify.py \
  tests/unit/job_final_publication_gate/test_contract_and_settings.py \
  tests/unit/job_final_publication_gate/test_job_and_attachments.py \
  tests/unit/review_decision_audit_wiring/test_classification.py \
  tests/unit/review_decision_audit_wiring/test_gate_handler.py
```

**122 collected, 1.79 s, exit 0.** File counts respectively **44, 13, 5, 2, 3, 27, 28**.

All seven files were read fully before execution. They use local JSON/ledger-shaped inputs, `Fixture`/`gate_fixture`, fake accepted-review boundaries and synthetic compiler receipts; no actual compile/model/provider callback is commissioned. Inspected the relevant fixture helpers, source-only `relay` constants, remediation `answer`, common pytest guards and `tests/unit/conftest.py`. The tests' `ROOT` paths resolve to the WSL source. The normal harness owns its unit host-pin fixture/umask; this auditor did not alter shared environment variables.

### Execution

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 43047 \
  --max-tests 122 --expect-tests 122 --timeout-seconds 180 -- \
  tests/test_completion_publication.py \
  tests/test_gate_snapshot.py \
  tests/unit/job_final_publication_gate/test_classify_and_verify.py \
  tests/unit/job_final_publication_gate/test_contract_and_settings.py \
  tests/unit/job_final_publication_gate/test_job_and_attachments.py \
  tests/unit/review_decision_audit_wiring/test_classification.py \
  tests/unit/review_decision_audit_wiring/test_gate_handler.py
```

- **122 passed, 6.32 s**, exit 0; zero failures/errors/skips/slow tests.
- Wrapper collection **3.032635 s**, execution supervisor **10.911713 s**, total **14.315364 s**.
- Collection/execution cleanup both confirmed; no remaining processes.
- Private base: `test/tmp/tests-custom-20261118-134909-955206-3546735`.
- Log: `test/tmp/logs/tests-custom-20261118-134909-955206-3546735.log`.
- Collection log: same log stem plus `.collection.log`; manifest: `test/tmp/tests-custom-20261118-134909-955206-3546735.collection.json`.
- JUnit/timings: `test/tmp/tests-custom-20261118-134909-955206-3546735.junit.xml`, `.timings.sqlite`.
- Complete command arrays, timings and fixed report: `test/tmp/reports/tests-custom-20261118-134909-955206-3546735.json`.

### R1/R2 exact bounded Python command

Run via the same transport as `.venv/bin/python - <<'PY' ... PY`; no pytest or external execution:

```python
from pathlib import Path
from copy import deepcopy
from time import perf_counter
from types import SimpleNamespace
import json
import pytest
from appsec_review.jobs import accepted_review
from appsec_review.jobs.job_final_publication_gate import classify, verify, job, attachments
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.packages import verify_package_manifest, UNIT_CONTEXT_SCHEMA, ASSEMBLY_RULE
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import IntegrityError
from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA, FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA
from appsec_review.storage import canonical_json
from tests.unit.review_decision_audit_wiring.helpers import gate_fixture, put, ROOT, HASH
start = perf_counter()
base = Path('test/tmp/job-audit-final-gate-43-repro-20261118a')
base.mkdir(mode=0o700, parents=True, exist_ok=False)
root = (base / 'unit-context').resolve(); root.mkdir()
outputs = {}; review = {}; contexts = []
for lane in ('lead', 'hunt'):
    directory = 'data/' + lane
    scope = {'component_id': 'component-1', 'trust_boundary_id': None, 'build_unit_id': None, 'source_ids': []}
    context = {'schema': UNIT_CONTEXT_SCHEMA, 'assembly_rule': ASSEMBLY_RULE, 'unit_key': 'unit-1',
               'scope': scope, 'context': [], 'entity_ids': [], 'facets': {
                   'rule': 'appsec-review/unit-facets/2', 'obligation_rule': 'appsec-review/hunt-facet-obligations/1',
                   'tags': [], 'target_classes': [], 'obligations': []}}
    digest = sha256_hex(context); relative = 'unit-context/' + digest + '.json'
    counts = {'context_entries': 0, 'source_ids': 0, 'entity_ids': 0}
    ref = put(root, directory + '/' + relative, context); contexts.append(ref)
    entry = {'unit_key': 'unit-1', 'schema': UNIT_CONTEXT_SCHEMA, 'path': relative,
             'sha256': digest, 'bytes': len(canonical_json(context)), 'counts': counts}
    manifest = {'schema': 'appsec-review/review-package-manifest/1', 'assembly_rule': ASSEMBLY_RULE,
                'package_schema': 'appsec-review/review-package/7', 'run_id': root.name,
                'manifest_sha256': HASH, 'target_snapshot': HASH,
                'settings': {'admit_severities': [], 'slice_strategies': []}, 'graph_settings': {}, 'admission': [],
                'source_dispositions': {'rule': 'appsec-review/source-disposition/1',
                                        'vendored': [], 'sdk': [], 'generated': [], 'test': []},
                'rules': {'families': {}, 'rank': 'appsec-review/rank/1', 'obligations': 'appsec-review/obligations/1',
                          'neighborhood': 'appsec-review/package-neighborhood/3', 'slice': 'appsec-review/package-slice/2'},
                'inputs': [], 'evidence_map_sha256': HASH, 'packages': [], 'unit_contexts': [entry],
                'units': [], 'gaps': [], 'cwe_reference': None,
                'counts': {'leads': {}, 'admitted': {}, 'kev_admitted': {}, 'non_lead_observations': {},
                           'dispositions': {'rule': 'appsec-review/source-disposition/1', 'files': {}, 'leads': {}},
                           'packages': {'finding_lead': 0, 'hunt': 0}, 'units': {'total': 0, 'hunted': 0, 'below_cutoff': 0},
                           'neighborhood_bounds': {'call_depth': 0, 'dataflow_path': 0}},
                'audit': {'lane_a': {'status': 'passed', 'expected': 0, 'packaged': 0, 'by_family': {},
                                     'suppressed': 0, 'duplicates': 0, 'kev_admitted': 0},
                          'lane_b': {'status': 'passed', 'listed_leads': 0}, 'families_available': {}}}
    manifest['content_sha256'] = sha256_hex(manifest)
    manifest_ref = put(root, directory + '/package-manifest.json', manifest)
    lane_ref = put(root, directory + '/lane.json', {'package_manifest': manifest_ref,
                   'package_manifest_content_sha256': manifest['content_sha256'], 'packages': []})
    outputs['packages.assemble_' + lane + '_packages'] = {'artifact': lane_ref}
    review['lead_package_manifest_sha256' if lane == 'lead' else 'package_manifest_sha256'] = manifest['content_sha256']
bindings = accepted_review._verify_package_manifests(root, outputs, review)
print('R1 verified_contexts=', len(contexts), 'returned_bindings=', len(bindings),
      'contexts_bound=', sum(ref in bindings for ref in contexts))
(root / contexts[-1]['path']).write_bytes(b'changed after initial verification')
verify.verify_gate_snapshot(root, {'run_id': root.name, 'bindings': bindings, 'inputs': {}, 'capabilities': {}, 'attachments': {}})
print('R1 snapshot_reverification=ACCEPTED changed context')
try:
    verify_package_manifest(root / 'data/hunt/package-manifest.json', run_root=root)
except IntegrityError as exc:
    print('R1 actual_manifest_reverification=REJECTED', str(exc))
print('R1 elapsed=', round(perf_counter()-start,6))
start = perf_counter()
f = gate_fixture(base / 'classification')
verified_ref = put(f.root, 'data/verified.json', f.document)
classified = classify.classify(f.document)
classified['buckets']['publishable'], classified['buckets']['verification_backlog'] = (
    classified['buckets']['verification_backlog'], classified['buckets']['publishable'])
classified['package_counts'].update(publishable=0, verification_backlog=0, withheld=2)
classification_ref = put(f.root, 'data/classification.json', classified)
with pytest.MonkeyPatch.context() as mp:
    mp.setattr(attachments, 'accepted_handoff', lambda root, producer: SimpleNamespace(**f.document['inputs']['job_handoff']))
    result = job.build_job(repository_root=ROOT).units[2].handler(f.unit('acceptance.publish_handoff', {
        'load.verify_review': {'artifact': verified_ref}, 'gate.classify': {'artifact': classification_ref}}))
    published = json.loads((f.root / result['artifact']['path']).read_bytes())
    ah = AcceptedHandoff('job_final_publication_gate', {'job_id': 'job_final_publication_gate',
                         'outputs': {'acceptance.publish_handoff': result}}, HASH, 'data/gate-handoff.json')
    mp.setattr(verify, 'accepted_handoff', lambda root, producer: ah)
    _, accepted = verify.load_accepted_gate(f.root, SchemaSet(ROOT / 'docs/schemas/final-report'))
    print('R2 publish_terminal=', result['terminal_status'], 'accepted_counts=', accepted['package_counts'])
    print('R2 row_buckets=', [p['bucket'] for p in accepted['packages']],
          'list_memberships_agree=', all(p['finding_package_id'] in accepted['buckets'][p['bucket']] for p in accepted['packages']))
print('R2 elapsed=', round(perf_counter()-start,6))
print('REPRO_BASE=', base)
```

Observed: R1 `2 / 4 / 0`, snapshot accepted changed context, actual manifest rejected; **0.092923 s**. R2 `SUCCEEDED`, counts `0/0/2`, row buckets publishable/backlog, membership agreement false; **0.033756 s**. Command exit 0.

### R2b/R3 complete handoff follow-up

The final attempted script was the following, also `.venv/bin/python - <<'PY' ... PY`:

```python
from pathlib import Path
from time import perf_counter
import json
from appsec_review.config import load_config
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.review_decision_audit_wiring.helpers import put, ROOT, HASH
from appsec_review.jobs.job_final_publication_gate import verify, attachments
from appsec_review.jobs.job_final_publication_gate.datasets import CONTRACT
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.storage import file_sha256
from appsec_review.runtime.consume import upstream_scope
start = perf_counter()
base = Path('test/tmp/job-audit-final-gate-43-repro-20261118a').resolve()
frozen = json.loads(load_config(ROOT / 'appsec-review.toml').resolved_json)
root = base / 'classification/run-wiring'
config_ref = put(root, 'data/configuration/resolved.json', frozen)
put(root, 'data/configuration/manifest.json', {'resolved_sha256': config_ref['sha256']})
result_path = root / 'data/jobs/job_final_publication_gate/attempts/attempt_0001/steps/acceptance/tasks/publish_handoff/final-publication-gate.json'
gate = json.loads(result_path.read_bytes())
gate['bindings'] = [config_ref if row['path'] == config_ref['path'] else row for row in gate['bindings']]
result_ref = put(root, result_path.relative_to(root).as_posix(), gate)
result = {'schema': 'appsec-review/final-publication-gate-handoff/2', 'artifact': result_ref,
          'item_count': 2, 'terminal_status': 'SUCCEEDED', 'gaps': []}
handoff_path = root / 'data/jobs/job_final_publication_gate/attempts/attempt_0001/handoff.json'
write_fixture_handoff(root, handoff_path, {'job_id': 'job_final_publication_gate',
                      'outputs': {'acceptance.publish_handoff': result}}, target_snapshot=HASH)
put(root, 'data/jobs/job_final_publication_gate/latest.json', {
    'handoff_path': handoff_path.relative_to(root).as_posix(), 'handoff_sha256': file_sha256(handoff_path)})
accepted, gate = verify.load_accepted_gate(root, SchemaSet(ROOT / 'docs/schemas/final-report'))
print('R2b real_handoff_reader=ACCEPTED', gate['package_counts'])
print('R2b elapsed=', round(perf_counter()-start,6))
start = perf_counter()
root = base / 'pinned-heads'; root.mkdir(mode=0o700)
put(root, 'data/configuration/resolved.json', frozen)
refs = []
for number in (1, 2):
    path = root / ('data/jobs/job_inference_security_review/attempts/attempt_%04d/handoff.json' % number)
    write_fixture_handoff(root, path, {'job_id': 'job_inference_security_review', 'outputs': {}}, target_snapshot=HASH)
    refs.append({'path': path.relative_to(root).as_posix(), 'sha256': file_sha256(path)})
put(root, 'data/jobs/job_inference_security_review/latest.json', {'handoff_path': refs[1]['path'], 'handoff_sha256': refs[1]['sha256']})
snapshot = {'bindings': [], 'inputs': {'job_handoff': refs[0]}, 'capabilities': {}}
with upstream_scope(root, 'job_final_publication_gate', {'job_inference_security_review': refs[0]['sha256']}, contract=CONTRACT):
    attachments.reverify_snapshot(root, snapshot)
    print('R3 active_pinned_scope=ACCEPTED original while latest=attempt_0002')
try:
    attachments.reverify_snapshot(root, snapshot)
except Exception as exc:
    print('R3 operator_unscoped=', type(exc).__name__, str(exc))
print('R3 elapsed=', round(perf_counter()-start,6))
```

R2b **accepted with the same contradictory counts, 0.250326 s**, using real common handoff/accounting verification. This invocation then failed in R3 because the synthetic `pinned-heads` setup lacked its configuration manifest. It did **not** invalidate the completed R2b observation.

Two preceding attempts at that follow-up failed before R2b completion because the helper's minimal `jobs={}` frozen fixture was not a complete runtime configuration:

1. Using the original `gate_fixture` configuration, without the `frozen/config_ref/gate binding rewrite` setup above: `KeyError: 'job_final_publication_gate'` at `runtime/handoff.py:177`.
2. Replacing it with `{'jobs': {'job_final_publication_gate': {'settings': {'enabled': True, 'max_packages': 10}}}}` and updating the synthetic bound configuration reference: `KeyError: 'build_capture'` at `runtime/handoff.py:178`.

Both were **reproducer setup failures, exit 1, not unit failures or product findings**. Elapsed time was not captured before those exceptions; it is an explicit measurement gap, not an estimated duration. The successful follow-up used the source's complete resolved dev configuration only as inert JSON inside owned test scratch; it did not change source or process environment.

R3 was completed with this exact corrective command:

```python
from pathlib import Path
from time import perf_counter
import json
from tests.unit.review_decision_audit_wiring.helpers import put
from appsec_review.jobs.job_final_publication_gate import attachments
from appsec_review.jobs.job_final_publication_gate.datasets import CONTRACT
from appsec_review.storage import file_sha256
from appsec_review.runtime.consume import upstream_scope
start=perf_counter()
root=Path('test/tmp/job-audit-final-gate-43-repro-20261118a/pinned-heads').resolve()
put(root,'data/configuration/manifest.json',{'resolved_sha256':file_sha256(root/'data/configuration/resolved.json')})
path=root/'data/jobs/job_inference_security_review/attempts/attempt_0001/handoff.json'
ref={'path':path.relative_to(root).as_posix(),'sha256':file_sha256(path)}
snapshot={'bindings': [],'inputs':{'job_handoff':ref},'capabilities':{}}
with upstream_scope(root,'job_final_publication_gate',{'job_inference_security_review':ref['sha256']},contract=CONTRACT):
    attachments.reverify_snapshot(root,snapshot)
    print('R3 active_pinned_scope=ACCEPTED original while latest=attempt_0002')
try:
    attachments.reverify_snapshot(root,snapshot)
except Exception as exc:
    print('R3 operator_unscoped=',type(exc).__name__,str(exc))
print('R3 elapsed=',round(perf_counter()-start,6))
```

Observed **pinned scope accepts attempt 1 while latest is attempt 2; unscoped operator raises `IntegrityError: accepted job_inference_security_review changed during gate publication`**, **0.035777 s**, exit 0.

Read-only lookup mistakes also included a nonexistent `config/` search root, two guessed package schema/module paths, and an out-of-range `runtime/datasets.py` view. Correct authorized source paths were then used. No installs, source changes, or altered test assertions followed.

### Final cleanup and source check

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
import shutil
root=Path('test/tmp/job-audit-final-gate-43-repro-20261118a')
assert root.is_dir() and not root.is_symlink()
print('removing_own_repro_tree=',root)
shutil.rmtree(root)
print('repro_tree_removed=',not root.exists())
PY
git rev-parse HEAD
git branch --show-current
git status --short
git diff --check
find . -maxdepth 1 -mindepth 1 -printf '%f\n' | sort
```

Owned repro tree removed; expected SHA, `main`, empty status and clean diff check. Repository-root inspection found no root-level material created by this auditor; unrelated existing files were left alone.

## Read/unread matrix

| Scope | Read coverage | Executed coverage / material gap |
| --- | --- | --- |
| Job package | **All seven Python files fully**, including init, settings, contract, classifier, attachments and both verifiers. | All three callbacks represented by the mapped units; two additional boundary reproductions. No real runtime review graph. |
| Canonical intent | Gate operations page **fully**; reporting architecture `1-74`; completion architecture `1-112`; input-contract architecture `1-130`; relevant testing workflow/wrapper passages. | Documentation compared with code, never treated as proof. Older retained design tables distinguished from current behavior. |
| Accepted review | `jobs/accepted_review.py` **fully**; package manifest/context verifier and behavior-model checks; chain-publication/actor-receipt checks. | Full real nonempty ledger/package/scoring/chain review loader not executed here. No independent evidence/source-truth verification. |
| Audit | Reader `1-426`, `587-777`, exact job adapter summary; no unit-context references found in audit package search. | Proposal membership helpers `427-586`, full audit contract/projection implementation and all capacities/record classes not exhaustively read or tested. |
| Runtime/custody | `consume.py` fully; accepted store adapter; bound-artifact module; relevant handoff identity/claim/config checks, shared verification, admission, UnitExecutor and topology. | Full signing/release/reuse/admission-cache/source-freeze/concurrency implementation not audited. No service/image trust verification; no active-run race. |
| Schemas/datasets | Gate, review-package manifest and unit-context schemas fully; common capability/attachment/accounting/count/coverage and finding-prefix ranges. All 45 input declarations and output globs read. | Full referenced PoC/remediation/dossier schema property cross-product and generic inventory/export enforcement not independently replayed. |
| Downstream | Final-report load and report builder core; OpenVEX bounded reader and authority/score/classification equality sections. | No renderer, PDF, SARIF or OpenVEX execution. No third-party parser or output quality validation. |
| Tests | **All seven mapped unit files fully**, common guards, fixture helper fully, relevant source-only relay/remediation helpers. | **122 passed**. Unmapped cross-system contract tests, `tests/test_final_report.py` acceptance/whole-chain fixtures, integration and live paths unexecuted. |
| Prior findings/TODO | Full inference report; targeted PoC/planning/validation report sections; historical C16 gate findings; T-147/T-5000/T-5038/T-5043/T-5045 and adjacent entries. | Not the entire TODO registry or all prior reports. Dossier producer was not re-audited. |

Remaining matrices include changed-source/read races; all optional capability enablement × explicit supply × historical schemas; nonempty chained findings plus dossier caps; every score-provider/evidence relation ownership combination; all audit absence/partial-population shapes; maximum package/binding budgets; generic dataset read-observation closure; and actual accepted output usefulness. Passing the mapped units establishes none of those unexecuted outcomes.
