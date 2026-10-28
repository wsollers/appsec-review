# Evidence completion documentation inventory

Date: 2026-10-28. Phase: source inventory and delivered-contract reconciliation.
Inspected source: `5f5548da3d039f73c7d6858d2b28a4593a264efe`; ancestry verified with
`git merge-base --is-ancestor`. Delivered source `b702eb7` and assurance fix `7641fa5` are now
merged into the isolated documentation branch, followed by checkpoints `18eae9f`, `e769645f`,
`3f28d871`, final integration `dd9c9ad`, dossier rendering follow-up `e9a8333a` and metric
parity `0ece65d3` (source checkpoint `885175060097870a1b12a085bccd356a55b56157`);
then combined source `6975aef29eb09e1fb57385db98cb7d859108e362`, which contains documentation
correction `bcb982c4` and main `093f26d5`, followed by stable
`a709a10b01eac70f5f449db5be478b910178f884`. Its product trees are identical to the owner-tested
`039b24e4125a7e969c2fd32766abfed756d55759`; subsequent changes through that stable checkpoint are
test expectations and operating documentation. Final source
`967d1c7f55f7741bedd9b07ef740b5b746ddde09` then merges strict OpenVEX contracts/fixtures
`f4f746bf`, without changing gate/common source or commissioning an exporter.
Final contract/acceptance boundaries are recorded below.
The controlling delivery decisions are
[completion design section 11](../architecture/evidence-completion-and-remediation.md#11-parallel-implementation-decisions).
This is a documentation implementation record. Historical owner-reported all-lane semantics,
controlled boundary doubles and remaining current-main/live validation are distinguished below.

## Delivered inventory

The [dossier data inventory](../architecture/dossier-data-inventory.md) records:

- accepted configuration/guidance/review/package/ledger/evidence/adjudication/independence/score/
  shipment/coverage identities and resolver references;
- all 20 public retrieval tool names, bounded selectors, syntax/graph modes, neighborhood families
  and consumer-specific source windows; 18 logical SQLite indexes and their shard ownership,
  plus the separate six-family OWASP store;
- all 16 allowed precomputed query-set names, the 10 actual producers and 6 pending products;
- all 120 baseline dataset output kinds / 37 modules, first expanded to 126 / 40 and now
  **132 kinds / 42 registered/configured producers**: 46 indexed, 57 artifact-only, 29 protected;
- source/build/document, CodeQL/Clang/AST/IR/CPG/SVF, artifact/dependency/CVE/SBOM,
  CI/IaC/hardening, coverage/profile/history/change/control/tag/prioritization data, and
  compile-only PoC/developer artifacts, with explicit provenance and evidence ceilings.

Sources were inspected as repository implementation, not target/evaluator data.
No target checkout, evaluator ground truth, runtime skill instructions, raw prompt or credential
was loaded for this work. No product/config/schema/test/container/pin edits were authored here;
delivered implementation commits were merged for source verification.
The relevant `docs-sync` procedure was applied to the bounded effective-input/consumer delta,
not the entire unrelated main history. Main's inherited `docs/docs-sync.json` remains at
`aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4`; no new watermark is asserted by this feature checkpoint.

## Documentation map

| Page | Initial-phase change / later reconciliation |
| --- | --- |
| [Dossier data inventory](../architecture/dossier-data-inventory.md) | New source-verified inputs/query/index/dataset catalog and architecture change map. Later add actual completion producer schemas, outputs, visibility and consumers. |
| [Dossier operations](../operations/dossier-publication.md) | New explicitly proposed operational boundary: membership, pre-gate placement, protected deterministic artifacts, render gaps, assurance and recovery. Later replace proposed settings/commands/receipts only from implemented code. |
| [Completion design](../architecture/evidence-completion-and-remediation.md) | Link inventory/operational boundary; preserve proposed status and existing decisions. Later distinguish implemented slices from remaining design. |
| [Jobs/runtime](../architecture/jobs-and-runtime.md) | Mark pending topology/schema/resume/inventory changes without altering the current 37-job inventory. Later enumerate actual new jobs and dependencies. |
| [PoC operations](../operations/poc-generation.md) | Mark current gate dependency/mutable path as a transition boundary, not the new design. Later update shared verifier, pre-gate binding, immutable attempt paths, handoff/schema, manual admission and settings. |
| [Final report operations](../operations/final-report.md) | Distinguish existing post-gate outcome discovery and stale hardcoded PoC limitation from intended single snapshot. Later document certified attachments/capability accounting, schema and public references. |
| [Inference operations](../operations/inference-security-review.md) | Mark chain producer/ledger stages as pending; preserve single-ledger/nonexecution policy. Later document real composition/challenge bounds, events, manifests and gaps. |
| [Report rendering](../operations/report-rendering.md) | Distinguish broad standalone diagnostic rendering from the narrower protected dossier/public projections. Later document actual job reuse, receipts, sample and failure behavior. |
| [Telemetry architecture](../architecture/telemetry.md), [metrics operations](../operations/metrics.md) | Inventory existing correlated event writers, receipt-resolved scope/usage and regenerable summary; require completion stage/candidate/outcome/gap/duration and adapter/render tracking from first implementation. Later reconcile exact events/fields/schema and low-cardinality/redaction coverage. |
| [Architecture navigation](../architecture/README.md), [agent navigation](../agent-reader.md) | Link inventory, proposed dossier operations and this record without introducing authority. |
| [Wave1 operations](../operations/wave1-review.md), [inference design](../architecture/inference-security-review.md), [review package contract](../architecture/review-package-contract.md), [red output](../architecture/red-discovery-output.md), [indexing design](../architecture/indexing-and-query-reuse.md) | Integration follow-up: reconcile precise producer placement, package/reference schemas, chain publication, input matrix and availability; do not rewrite unrelated historic design. |

## Rollout decisions and implementation boundary

After the initial inventory commit, the user explicitly selected **Run both automatically for new
reviews** for remediation planning and bounded nonexecuting validation. The manager will enable
both in central new-configuration defaults; automatic compile-only PoC and dossier publication
are also intended after implementation acceptance. Existing runs must retain their immutable
frozen configuration rather than inherit changed checkout defaults. This records the user-directed
decision; central defaults were subsequently source-verified in `b702eb7`. Runtime reproduction,
negative-control execution and `fixed` assurance remain unauthorized and unclaimed.

The user additionally requires telemetry and metrics from the outset. Existing
`observability/events.py::EventLog` / `PipelineLog` and
`observability/telemetry.py::aggregate_run_metrics` were inspected for the follow-up inventory.
Completion-specific observations and summary fields were subsequently delivered in part by
`b702eb7`, not a separate Azure/backend. Track stages/candidates, model usage where emitted, low-cardinality
outcomes, durations, caps, adapter/render failures and integrity/coverage gaps. Producer allowlists
must exclude raw source/patch/PoC/prompt/credential content before writing either local or central
events; central key redaction does not sanitize the earlier local write.

## Original contract-time gaps

At the original baseline, the source only declared completion schema constants, `FindingBinding` and nonexecution helpers
in `jobs/completion_contracts.py`. Chain composition/ledger events, remediation producers, dossier
job/renderer and their accepted artifacts are not implemented here. Final versions and exact shapes
of review/PoC/gate/report summaries, optional-job admission, frozen snapshot binding, validation
adapters, rendering receipts, settings/defaults, dataset visibility and live PDF sample await
implementation-owner commits.

Important source-verified distinctions for integration:

| Surface | Evidence / implication |
| --- | --- |
| Document-origin findings | `document_issues.verify_document_issue_ledger` rejects published findings/scoring inputs; automatic mapping has no proof reviews. Inference declares only indexing as input. Dossier eligibility must use **accepted confirmed packages**, not label document candidates confirmed or limit dossiers to document-origin claims. |
| Package versions | Pre-adjudication `review_packages.py` uses `review-package/3` / manifest `/2`; inference `review/packages.py` uses package `/6` / manifest `/1`. They are separate surfaces, not interchangeable schema versions. |
| Planned graph/query features | Nine graph modes exist; alias/slice/layout/buffer-bound modes do not. Six query-set names are accepted API vocabulary but `pending_follow_up`. SVF memory and bounded producer flow/CPG rows exist without implying those missing APIs. |
| Publication ordering | PoC currently consumes gate; report separately discovers a gate-bound PoC handoff. Gate hardcodes PoC/chain/remediation absence. Integration must remove the cycle risk and post-gate discovery, not run the gate twice. |
| Protected content | Existing PoC source is declared artifact-only/internal, not automatically public. New developer dossiers are explicitly protected and must exclude secrets/raw prompts/transcripts. Standalone diagnostic interchange is not the dossier allowlist. |
| Assurance | Compile-only PoC, instrumentation and build-checked patches never prove runtime reproduction, passing negative controls, fixed/resolved findings or deployment. |

## Delivered-source reconciliation

| Source | Documentation reconciliation |
| --- | --- |
| `b702eb7183642bbce9398a736b02d41f7bbf631f` | Includes chain `ec9257bf`, dossier `065f736c`, remediation `6278e580`; registers 40 jobs, 126 dataset outputs, typed central/profile configuration, new-run automatic defaults, pre-gate direct/Dagster ordering, validation/planning constraint, CLI manual-PoC flag and completion metrics. |
| `7641fa50f91597a6dcdbe9a15147198dc34ac455` | Restores embedded nonexecution-assurance validation for schema-validated full producer rows, with a safe Mapping guard. The earlier exact-key regression is not retained as a current gap. |
| `18eae9fd189c66303cf4e9bdd6a871d1713438ff` | Includes reader `/3` alignment `6f168400` and metric parity: all seven actual PoC statuses/native outcomes, fixed capability counts/dispositions/enabled maps, flags/dimensions, configured-limit ranges, separate null-token measurements and missing-turn counters. |
| `e769645f4628039cb9aa8fbf4bb7354764b2df52` | Preserves unknown remediation token dimensions and genuine zero, emits unavailable metadata, validates/closed-scopes shared governing fragments and role responsibility with exact bundle pinning, and reports uncommissioned native `BuildProfile` as manual validation. |
| `3f28d871455707f2c7e27d230d6765c9cc5ae6ba` | Extends active pre-review downstream exclusions to the new completion jobs; preserves **all** `registry_providers` file ownership/declarations for resume auditing. The reported indexing-admission regression is resolved at this source boundary. |
| `dd9c9adac140a1a4f5eb43e67962545f0edcf48f` | Includes chain final `dd1f8018` and PoC/gate/report `c44eddc1`: protected immutable PoC source/provenance `/2`, exact candidate partition/bindings, five-capability gate `/2`, authenticated disabled-manual-PoC admission and report `/2` reading only certified bindings. Removes the gate-to-PoC dependency and post-gate producer discovery. |
| Chain final | Charges every physical native `trace`/`find` under per-edge/run budgets; incomplete/capped evidence cannot prove continuity, configuration contradictions refute it. Exact actor/terminal-cell/original-receipt checks and `base_review_projection` isolate ordinary enhancement failures/gaps from base completeness while retaining full ledger/publication accounting. |
| `e9a8333ab8b3914ccdb8b8ec90186cbb8c282a6e` | Template checksum/rerun warning covers changed `.toc` even when `LastPage` is unchanged; preserves chain identity text in the protected dossier projection. No image pin change. Owner reports actual navigation/determinism acceptance; retained sample references are recorded separately from all-lane semantics. |
| `0ece65d3c37af71a131c8f071d68b648feaf9133` | Adds actual chain `not_launched` outcomes and a complete `CellStatus`-shaped aggregate regression, resolving the reported status allowlist gap. Parent reports 25 metric/log regressions passing. |
| `6975aef29eb09e1fb57385db98cb7d859108e362` | Merges main `093f26d5`, preserving topology-derived CLI `_graph_order` and linear direct execution over the same enabled jobs as Dagster. Registry/config/producer declarations now total 42 jobs / 132 datasets; accepted binary shards, syntax-only navigation, OWASP full-citation projection and expanded telemetry are inventoried. Both required hunt/lead manifest hashes are checked; PoC brief entry/path identities resolve through `ref`, never display labels. Source integration is not acceptance. |
| `dbfe7973`, `872ca63df503d6cac562487c3bb5db3f47d9998d` | Generation regressions persist/replay summaries, replace stale caches, preserve source-log bytes, incorporate newly appended events without recounting old events, and retain fixed `certified_outcome_counts` including zero. Source has the report-count checkpoint at `872ca63d`; it is not an outcome-disposition field. |
| `967d1c7f55f7741bedd9b07ef740b5b746ddde09` | Strict OpenVEX shared contracts/fixtures align only to gate `/2`, require exact nested inputs/capability/attachment refs in certified bindings and refresh transitive schema locks. Gate/common producer source is unchanged; no exporter, report fan-in/links or new registered job is commissioned. Owner reports 309 focused Linux passes, including both OpenVEX files and coupled completion/integrity/profile checks. |
| Shared review acceptance | Now verifies `/3`, run identity, duplicate identities, canonical PoC-basis digest, individual review-package refs and ledger-bound chain publication/memberships. The reader mismatch is resolved; real producer registration is still not a full accepted-run result. |
| Remediation operations | Added a focused operating page for exact inert patch bytes, confirmed-only accounting, seven assurance dimensions, native syntax-only coverage, defaults/profiles, protected artifacts, statuses and telemetry. |
| Dossier operations | Reconciled exact units, source/producer verification, bounds/pin, attempt-owned files, closed projection, render status/receipt and failure-retention behavior from source. |
| Metrics | Reconciled `run-metrics/3.completion` / `completion-process-metrics/1`, seven fixed lanes, per-event counters/outcomes/durations, explicit-null usage and bounded measurement gaps. These count attempted work/retries, not accepted findings; overlapping stages are not additive. |

The original native all-lane check now has a bounded owner-reported result in the
[acceptance ledger](#acceptance-ledger); it is not live compiler/model/renderer reproduction or
current-main authorization. Consumer compatibility and residual historical metadata
are recorded separately; the final focused OpenVEX result closes that compatibility failure.
The aggregate `not_launched`
status parity gap is resolved. Source contracts, registration, disabled-manual admission
and snapshot isolation are implemented, not still proposed. The parent reported
152 central checks and 42 contract/dossier checks passing on its source commits; those are not
relabelled as tests run by this documentation session or as end-to-end acceptance. The parent
also reports 24 metrics/pipeline-log/review regressions passing at `18eae9f`; the remediation owner
reports 241 Windows unit passes / one privilege skip for its follow-up. Those results are not
relabelled as local documentation checks or Linux real-review semantic acceptance.
The parent additionally reports PoC 219 fast / nine report tests, chain 178 fast / six earlier
real workflow tests; the dossier owner's final result is 387 passed / 14 skipped, including
accepted review `/3` to dossier and two live repeat-render tests. Its baseline
agent attributes the Linux preflight `RUN/RUN` versus `RUN/REUSE` failure to pre-existing
`5f5548da`, not this completion delta. None of those reports is relabelled as a local execution,
target vulnerability, actual target PoC compile or full native all-lane pass.

An earlier parent report described a frozen native `aeb6d11c` batch with 828 coupled units passed,
two deselected and one Dagster C++ AST-to-IR topology assertion failure under baseline
investigation. The known preflight baseline failure was excluded from that batch. That batch is
historical, not a clean all-lane or full-suite result; the later native result is recorded below.

Subsequent QA stopped incomplete and found that plain `git archive` on Windows converted
shell/fixture bytes to CRLF. Its contaminated 42 failures / 28 errors cannot classify either the
product delta or a broad baseline. Byte-exact snapshots require
`git -c core.autocrlf=false archive <commit>`. Later byte-exact checks and baseline classifiers
supersede the initial pending reruns; their bounded results appear below. The contaminated counts
and narrow preflight attribution must not be promoted to a broad clean-baseline claim.

The user reiterated unit coverage for telemetry/metrics generation. The initially pending
persistence/replay/source-log-immutability regression is now delivered in `dbfe7973`, with
certified report count coverage in `872ca63d`. The later all-lane owner also checked actual
producer events and summary derivation. Unit generation coverage alone does not establish
that separate result or live execution.

## Combined-source checkpoint and current acceptance

The current inventory was remeasured directly from source `6975aef2`, not old document counts.
New `job_target_acquisition` supplies run-owned system/component provenance before intake;
`job_binary_evidence_indexing` re-verifies intake-frozen Ghidra publications and publishes
bounded `binary` shards/pseudo-C. New `query_syntax` reads exact signed source/AST projections
from Tree-sitter `analysis` shards. These surfaces do not establish deployment, semantic binding,
flow, guard sufficiency or vulnerabilities merely because retrieval succeeds. Dossiers still
project only cited, bounded accepted material; there is no automatic wholesale dataset inclusion.

`run-metrics/4` adds CodeQL execution/query views while retaining completion semantics `/1`,
OWASP/review-flow, Tree-sitter receipt/resource accounting and correlated nullable model usage.
Zero completion measurement gaps is distinct from legitimate review evidence/source/redaction
gaps; the all-lane owner's `ab25bff8` and final `c0e6be00` tests check that propagation.
Metric fix `b9e69d17` scopes capability `enabled`/`dispositions` maps to the gate certification
event, rather than misclassifying generic step lifecycle lists. The same 770-record owner log
(reported hash prefix `51101028`) replays with measurement gaps reduced from 23 to zero while
retaining true producer buckets; the parent reports 48 focused Windows metric/log/review passes.
These are attributed historical results, not tests newly executed by this documentation session.

OpenVEX shared settings/contracts, schema locks and design documents exist, but no exporter
job/configuration/dataset/metrics producer is registered. It is not counted as a 43rd job or a
dossier input. Its inherited post-gate PoC sibling diagram and report `/1` proposal predate
current pre-gate PoC and certified report `/2`; future implementation must reconcile them
explicitly. The operations boundary now names that mismatch without claiming exporter delivery.
Final `967d1c7f` reconciles the shared records and fixtures with gate `/2` only: legacy `/1`
and `unavailable_inputs` are rejected, every nested input/capability/attachment reference must
belong to certified gate bindings, and offline transitive schema hashes are refreshed.
The [shared-contract README](../schemas/openvex-export/README.md) records this boundary;
it does not implement filesystem acceptance, export assembly or report fan-in.

### Acceptance ledger

This ledger is bounded to the named snapshots. It is not a full-repository clean result,
shipping approval, proof of exploit execution or authorization for a new/live main review.
Root `AGENTS.md` leaves integration, acceptance and live Dagster validation user-owned.
The branch inventory remains 42 jobs / 132 dataset kinds; later main symbol/SBOM changes and
its final combined validation belong to the separate main owner and are outside this source.

| Reported validation | Current attribution / limit |
| --- | --- |
| Prior LF-exact `afbbc875` suite | Parent reports passed. This is a prior checkpoint, not combined main acceptance. |
| Remediation `68915bb7bc7abd15013030761f9bd22e9e09e279` | Owner reports Linux 256 passed / zero skips on the exact remediation snapshot. It does not certify every combined lane. |
| Dossier `e9a8333a` | Owner reports 387 passed / 14 skipped, including two real PDF tests; sample/gallery and receipt hashes remain as recorded. |
| Certified report metrics `872ca63d` | Parent reports focused tests passed on Windows and Linux, covering summary persistence/replay/cache/source-log integrity. |
| Native all-lane source `039b24e4` | Owner reports **2 passed in 306.43 s**: configuration equality and genuine review-emitted candidate through all seven lanes, unchanged states/scores/ship decisions, exact gap inheritance, sanitized gate-only report, ignored corrupted optional pointers and deterministic second JSON/Markdown hashes. Model/compiler/renderer boundaries use offline doubles; this is not live runtime/compiler reproduction. Owner retains artifacts in `combined-results/`. |
| Stable source `a709a10b` | Product trees remain identical to `039b24e4`. Test-only updates include the three commissioned chain guidance tasks (106 guidance checks passed), shared-reader monkeypatch retargeting (three integrity checks passed) and a separate four-profile automatic PoC/planning/validation/dossier defaults check (passed). None makes OWASP opt-in. |
| Coupled core `7f4c9b0a` | Parent reports 542 passed / three failed in 667.007 s. Two OWASP package `/6` `oneOf` failures independently reproduce on main `093f26d5`; the third stale gate-private monkeypatch is corrected by targeting the shared reader (`d788`), with three integrity checks passing. These phases are not added as independent unique tests. |
| Runtime profiles `a709a10b` | Owner reports 62 passed / four failed in 9.71 s. Exact main `093f26d5` independently reproduces all four stale `OWASP True is False` expectations in 2.56 s, with archived test/config bytes matching Git blobs. OWASP assessment remains enabled by default; no default was changed to satisfy stale assertions. |
| Final deduplicated coupled-unit ledger | Across incremental frozen XMLs, with final OpenVEX results replacing the three old integration failures, parent reports **1527 unique passed, six independently main-baseline failures (two OWASP + four profiles), one optional PowerShell-parser skip**. All 40 selected files were exercised. This combines phases, not one clean aggregate run or the full repository; named phase results remain the primary attribution and overlapping totals must not be added. |
| Broad 111-file attempts | Partial, not a full-repository pass. Initial root-user/capability failures are environment limitations, not silently counted as product passes. Correct HOME/tmp and empty HOSTNAME make main's multiprocess Dagster timing control pass; no product defect is inferred from that earlier environment. |
| Narrow OpenVEX compatibility `967d1c7f` | Owner reports **309 passed in 7.80 s** on immutable Linux source: both full OpenVEX contract/settings files (180 cases), completion contracts/wiring/publication/metrics, shared integrity and new four-profile defaults. All 15 baseline failures are independently proven on main `093f26d5`; no residual feature-coupled failure is reported. This commissions no exporter, report links/fan-in or 43rd job and is not a full-suite result. |

The owner-observed native scenario has two confirmed findings (native and CI), one
`compile_verified` PoC outcome at the doubled compiler boundary, planning outcomes
`proposal_generated: 1` / `manual_design_required: 1`, validation outcomes `build_checked: 1` /
`manual_validation_required: 1`, and three rendered dossier outcomes at the doubled renderer
boundary with four truthful inherited/source gaps. The gate binds eight attachments; report
counts are publishable 2 / backlog 2 / withheld 0. Certified attachment counts are
`attack_chains: 0`, `dossiers: 3`, `poc_generation: 1`, `remediation_planning: 2`,
`remediation_validation: 2`. The observed chain lane has no admitted chain: observation is not
proof of deployed-chain continuity. All seven lanes are observed with zero telemetry measurement
gaps, while review/source/evidence/redaction limitations remain intact. Real seeded PDF rendering
is the separate sample result below, not the native test's renderer double.

#### Independently reproduced baseline selectors

Parent/QA reports **15 named failing selectors** reproduced on exact main `093f26d5`, not a
generally clean baseline. The groups are three CodeQL integration selectors; preflight
`RUN/RUN` versus `RUN/REUSE`; the stale Dagster intake `target_acquisition` versus old
image-verification expectation; two binary UID/schema `1000` versus `10001` expectations;
two binary CLI fake-lambda `profile` keyword cases; two OWASP package `/6` `oneOf` cases;
and four runtime-profile `OWASP=False` assertions against main's unchanged `True` default.
Shell/golden controls pass on LF-verified snapshots. The OpenVEX failures were feature-coupled,
not baseline; final contracts/fixture alignment and focused Linux verification close them.
Neither correction nor baseline classification excuses unexecuted coverage.

This authored checkpoint changes only documentation; merged owner contracts/schema/fixture
changes remain attributed to `f4f746bf`. It does not advance the main sync watermark or alter image bytes.
The dossier image gallery and sample files inherited from main are preserved. The user approved
these final compatibility/test-fixture/docs edits in existing Windows worktrees with **Linux-only
validation**; no Windows test or live-review run is authorized by this update.

## Retained sample and release boundary

[Dossier operations](../operations/dossier-publication.md#verified-seeded-sample) records the exact
PDF/receipt paths, byte counts and hashes for owner-retained `runs/dossier-navigation-final`.
The parent verified eight manifest hashes and execution/template/document receipt identities
against integrated source, then inspected page 1 and 2 previews. The owner checked all seven TOC
entries, including "Finding brief" on page 2; `application_risk_matrix/3` is preserved.
These are attributed seeded presentation/nonexecution checks, not PDFs regenerated or visually
inspected by this documentation session, target vulnerability evidence or native all-lane acceptance.

Source verification of `runtime/job.py::Job.identities` confirms the existing
[operator-declared release policy](../operations/performance-assurance.md#operator-declared-releases):
legacy `runtime_identity` callbacks are not reuse authority. Render receipt template hashes
establish provenance, not automatic code/template-edit invalidation. An intended supplied-software
update needs the appropriate declared release, new versioned run and explicit new attempt;
old frozen configuration/releases are not rewritten. No automatic payload-hash hook is promised.

## Checks and limitations

At source commit `5f5548da3d039f73c7d6858d2b28a4593a264efe`, the standard-library link test
`tests/test_documentation.py::test_current_documentation_local_links_resolve` was invoked with
`runpy` without installing dependencies. **Baseline: exactly two unresolved links**, both in
`docs/architecture/build-environments-and-execution-capture.md`:

```text
../../targets/appsec-multi-vuln/support/project-matrix.json
../../targets/appsec-multi-vuln/README.md
```

They refer to an uninstalled user-owned target, not a documentation regression from this work.
Do not install/edit that target or remove unrelated links to make the check green.
The post-edit link test reports **exactly the same two missing target links and no introduced
failure**. A focused standard-library AST check confirms all 120 dataset output kinds appear in
the correct indexed/artifact-only/protected column across all 37 producer modules. It also checks
the exact 19 public tool names, 17 logical indexes and 16 allowed query-set names against their
source declarations. The six pending query products remain explicitly distinguished from the
ten implemented ones.

After merging `b702eb7` and `7641fa5`, the same link check still reports exactly those two
uninstalled-target links. The focused AST completeness/disposition check now passes for all
**126 outputs across 40 producer modules**. No target, runtime pipeline, compiler or renderer
was run to substitute for the pending integration acceptance.

`git -c core.whitespace=cr-at-eol diff --check` passes, preserving the already tracked CRLF style
of the two navigation pages rather than treating carriage returns as added trailing whitespace.
The repository root was inspected; this work created no disposable root material and made no
non-documentation changes.
No model, runtime pipeline, build container, target analysis, remediation execution or live PDF
was exercised in this initial documentation phase.

Final local reconciliation at source checkpoint `8851750` again reports exactly the same two
baseline missing links, no introduced link failures, and all 126 dataset outputs in their correct
disposition columns across 40 modules. Standard-library source checks cover all seven real
`CellStatus` values and seven PoC statuses in the metrics allowlist, seven lanes, and disjoint
configured-limit/counter vocabularies; a full zero-valued cell-status map introduces no measurement
gap. The seeded-sample section anchor and whitespace check pass. Root/status inspection shows
only the 18 intended documentation files changed, with no disposable root output or authored
product changes. Real PDF and native test results above remain attributed, not local executions.

At combined source `6975aef2`, a standard-library AST/TOML check matches all 42 registry/config/job
declaration identities and every exact dataset disposition column: 132 kinds (46 indexed,
57 artifact-only, 29 protected). It also verifies the exact 20 tool names, 18 index names,
16 query-set names and all current graph sink-class values against the inventory. No target
or evaluator data was scanned.

The checkout initially lacked pytest; dependencies were installed into its own `.venv`, and
`appsec_review.__file__` was verified inside this worktree before running the relevant
documentation/skill-separation/sync-record/completion-metrics selection. Result: **26 passed,
two failed**. One failure is the same two known missing target links; the other is Windows
`WinError 1314` when the existing skill-separation test creates a symlink without the required
host privilege. Neither was hidden by editing tests, targets or skip policy. All completion
metric and sync-record tests in that selection passed; this is not broad pipeline acceptance.
The ten implemented `PRODUCT_SETS`/`PRODUCT_RULES` and six pending query names are checked
separately rather than counting all API vocabulary as produced data. Post-edit links still have
exactly the two known target failures; whitespace checks pass. Only seven scoped documentation
files change relative to `6975aef2`; the inherited watermark, gallery and samples are unchanged.
The checkout-local environment is retained for later checks; this selection's named
`test/tmp/docs-combined-6975` fixture directory is removed after verification.

The final bounded revision integrates `967d1c7f` by ancestry and authors only architecture,
operations and this review record. It updates stale pending-native claims and the metrics
heading/links, corrects OWASP's actual default-enabled behavior, and preserves the 42-job /
132-dataset inventory, main sync watermark and real sample/gallery bytes. Owner-attributed
native, remediation, renderer, baseline and final compatibility checks above are not relabelled
as local executions. Under the user's final approval, documentation edits use the existing
Windows worktree, Git diff/newline hygiene is inspected there, and documentation/skill/sync
validation is Linux-only. No Windows test, live review or new target/compiler/runtime acceptance
run is performed by this documentation revision.
