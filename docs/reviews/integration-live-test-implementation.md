# Bounded integration and live acceptance

Implementation record for the approved integration/live coverage plan, based on `fcac4306`.
The original audits and approval plan are retained in the coordinating session's Library.

Operator instructions are in [bounded integration acceptance](../operations/bounded-acceptance.md);
the [architecture](../architecture/bounded-acceptance.md) describes the authentic seams and
current-report oracle. This is a revision-bound implementation/evidence record, not a claim that
all inventory members or optional live profiles have executed.

## Current reconciliation checkpoint

The documentation checkpoint is `bfe7f38b`, containing latest-main `d4cd9737` completion,
OpenVEX and interchange changes. The W0 driver/inventory, W2 process/transport, W3 controls/feed,
W4 graph/helper and authentic review/oracle work are integrated. Final public-driver
calibration is still in progress. Do not describe latest-main `quick` as green or its
under-ten-minute target as achieved on the strength of the older measurements below.

Framework fixtures now use `tests.handoff_fixture.write_fixture_handoff` for `handoff/2`.
Review/gate/report domain `/2` contracts remain unchanged. The final-report job is gate-only,
with no OpenVEX fan-in. The current-report oracle delegates to certified `load_accepted_gate`
and source-resolving current accepted-manifest validation; scanner hits or orphan/historical
shards cannot establish final survival. PoC planning consumes the direct accepted review and
strict candidate eligibility, and does not dispatch compilers/models without an accepted build.

### Latest-main source transition remains in progress

The coordinator is correcting shared fixtures, not production behavior: framework `handoff/2`
requires the actual configuration to be frozen before synthetic upstream handoffs and an
explicitly claimed upstream digest. The native candidate chain follows the current direct
review -> PoC dependency without a prerequisite gate; the CI oracle keeps the actual
review -> gate -> report chain.

Bounding the fixture to one explicitly configured lead package and no hunt is a valid tiny
selection, not permission to weaken contracts. Oracle evaluation uses a fresh per-call
production `validation_scope`, with no cached validation across tamper attempts; unchanged
negative expected identities can be batched in one evaluation.

This transition has no final latest-main pass at this update. Earlier measurements remain
revision-scoped; fixture corrections and reduced work alone do not complete public calibration.

W5's interim public W0-supervised attempt exposed a shared guard/source incompatibility after
`bfe7f38b`: `tests/acceptance_plugin.py` rejects all reads beneath repository `data/`, while
the real review job's `_taxonomy` reads tracked
`data/reference/taxonomy/vocabulary.json`. All three new consumer nodes therefore fail at
`packages.assemble_lead_packages` with `PermissionError`; owned cleanup is confirmed with zero
remaining processes. This is a shared runner-policy blocker, not evidence that the consumer
joins passed or that production mutable-data access should be enabled. A policy correction
must distinguish required pinned read-only application taxonomy from production mutable state;
copying/substituting the taxonomy or weakening the guard is not an acceptance result.

Direct W5 triage/referral executions were reported passing at approximately 45 seconds, and
publication reached the real accepted report/render path at approximately 112 seconds before
final assertion refinement. These are interim direct-test observations, not final public
verification; exact revision, artifacts and a passing post-correction run remain outstanding.

## Shared decisions

1. Acceptance state lives only under a unique `test/tmp/acceptance/<invocation>/<lane>/`.
   Fixture runs, admission ledgers, caches and metrics must never use production `runs/`.
   Redirected scratch directories are rejected.
2. Reuse production `PipelineLog`, `EventLog` and operation spans for telemetry. The driver
   stream, fixture job streams, results and elapsed/resource metrics remain test-owned.
   Acceptance uses an explicit namespace, not production metrics destinations.
3. Each lane declares exact selections, prerequisites, per-case/suite deadlines and at most
   two workers. Missing required coverage is failure, not successful skipped acceptance.
4. Hermetic lanes may run alongside reviews: no production service commands, target access,
   production ledger/cache mutation, shared Docker cleanup or automatic acquisition.
   Optional real-tool lanes need private mounts/state, explicit capability selection and
   resource limits. They never restart the review stack.
5. Timing claims require actual timed lane executions with commit, result, prerequisites,
   cleanup and metrics artifacts. Targets are initially unmeasured, not guarantees.
6. External inference, cold builds and native commissioning remain separately authorized.
   Unavailable features/platforms retain named deferrals rather than fabricated coverage.
7. Agent chunks import `appsec_review.acceptance.lanes` without editing its shared contract.
   The coordinator owns integration and changes to this contract.

## Partition and verification

The shared contract is implemented first. Isolated agents then own runner/telemetry,
authentic PoC/oracle seams, and process/review integration. Following chunks cover signal
jobs and tool/graph boundaries. No agent pushes or changes production host state.

Per-lane measurements, merged commits, reconciliations and outstanding host-dependent
obligations are recorded here as chunks arrive. No passing lane or runtime claim is made
by this initial contract.

## Initial measured slices

The shared-contract tests passed three portable cases in 2.04 seconds (4.47 seconds wall);
the actual directory-symlink case was unavailable without Windows symlink privileges.
It is not counted as demonstrated symlink coverage.

The coordinator added an accepted signal-job slice: real intake/catalog, artifact indexing,
all four coverage formats, populated profile indexing and immutable publication. Recorded
build receipts replace the external compiler boundary. A companion case mutates a profile
and requires `ProfileIntegrityError`, no accepted publication, and a production-schema
failure event identifying `normalize.profile_data`.

The two signal cases plus the existing mixed-language artifact-index regression passed:
3 tests in 116.19 seconds, 118.10 seconds including interpreter startup, under a real
240-second subprocess watchdog. The signal cases individually assert a 120-second limit;
the bounded runner adds enforced per-case deadlines when integrated. Fixture job logs and
driver operation spans remain beneath their own `test/tmp/acceptance/` invocation roots.

An existing broad four-package review-to-report baseline did not finish in several minutes
and its owned process tree was stopped. It is not a passing result or a quick-lane candidate
without reduction. No production service, ledger, target, cache or metrics path was changed.

The dependency-job slice runs real accepted input loading, native metadata/link normalization,
repository deduplication, Scorecard response retention, exposure indexing and immutable
publication twice. Compiler/SBOM input and HTTP response are explicit recorded boundaries;
this is not evidence that current compiler, Syft or public Scorecard services work. Two
native dependencies share one repository/request; DEBUG versus runtime evidence resolves to
PROD without losing either source, while the separate QA dependency remains QA. A second
accepted attempt uses the private fresh cache without another request and preserves the
first index bytes.

That second attempt reproduced a production defect: index fingerprints included upstream
handoffs but omitted changing Scorecard/provenance/cache context, causing an immutable-shard
conflict. The fingerprint now also binds the exact normalized dependency, Scorecard and gap
content. The new case passed in a combined 28.70-second run (30.52 seconds wall); that run
also passed 25 existing dependency cases. One existing integrity-error wording assertion
failed identically with the pre-change dependency implementation: it expects `index integrity
mismatch` while the shared verifier returns `target evidence integrity mismatch`. This is a
named baseline failure, not a passing suite or a reason to weaken acceptance.

The real MCP subprocess workstream found malformed-first-message session termination and
stale request-id reuse. Focused regressions reproduced both before the correction; the
protocol now returns a null-id JSON-RPC parse error and continues. A separate owned-process
test confirms review-style heartbeat events remain in a disjoint stream while acceptance
events are written. It passed in 1.91 seconds (3.67 seconds wall). This demonstrates local
process/storage isolation, not zero CPU/I/O contention with a production review.

## Integrated seams and narrow corrections

- **W0 public execution:** `run-tests --acceptance <profile>` reads exact inventory obligations,
  supervises collection and individual cases, always applies strict adequacy, and emits a
  revision/source-bound result. The ordinary 60-second case cap has explicit 15/30/120-second
  obligation exceptions. The quick target is under ten minutes with a hard twelve-minute cap,
  not a completed final calibration.
- **W2 local execution:** real Dagster multiprocess configuration, worker death/resume,
  durable submission/reconciliation, MCP stdio discovery/error recovery, record/replay and
  sensor paths have bounded selections. The supervisor uses Windows Job Objects or Linux
  subreaper/identity-based cleanup; Linux-specific execution is not proven on Windows.
- **W3 controls/feeds:** configured source/standards normalization and loopback TLS use real
  application normalization/publication. A positive source-bound OWASP assessment/review hook
  remains absent. Valid JSON with a truncated HTTPS `Content-Length` is now rejected rather
  than accepted as a complete response.
- **W4 graphs/helpers:** source-resolving recorded graph rows reach actual semantic consumers;
  safe/unguarded, same-row and vacuous-subject negatives are explicit. The SQLite helper is an
  actual local CLI. This does not establish current CodeQL/graph-engine compatibility.
- **Authentic review/oracle:** real accepted review/gate/PoC planning and current final-report
  authority replace synthetic cross-contract assumptions. Benign/blocked publication and
  corrupted/stale accepted bytes are distinct from raw scanner detection.

The narrow production corrections observed by these seams are MCP malformed-first-message
parse-first/null-id recovery (without stale-id reuse), dependency context fingerprinting and
truncated HTTPS response rejection. Other work was not removed merely to turn the selection
green: the detailed PoC unit/job tests remain present.

## Revision-specific measurements

These are different evidence classes. A focused pytest result, a guarded nested-plugin run
and a public W0 invocation are not interchangeable. Times are stated at the scope actually
reported; setup duration is unavailable unless captured separately.

| Revision / scope | Recorded outcome | Limitation |
| --- | --- | --- |
| `bbcbf0b1`, public `signals` | 3/3 passed, 161.535 s | Public-driver evidence for that revision only; not latest-main quick calibration |
| Before latest-main merge, direct authentic review/oracle | 13 passed, reported 304.33 s | Direct test timing, not public W0; exact tested revision/setup duration not supplied in this handoff |
| `ec653020`, W4 focused tests | 40 passed, 18.09 s wall | Focused tests, not public W0 |
| `ec653020`, W4 local audit | 22 passed, 15.15 s wall | Local audit, not public W0 |
| Earlier W3 public controls/feed selection | 6 passed, 110.830 s | Control body 87.355 s; feed bodies below 1 s; older selection/revision |
| `495f4300`, public TLS selection after truncation fix | 7 passed, 27.654 s | TLS cases only, not a final integrated profile |
| `495f4300`, related focused tests | 15 passed, reported 5.99 s | Focused test timing, not public W0 |
| `ec48a7c0`, W2 nested Windows warm runs with exact extracted W0 guard/plugin | 14/14 selected cases passed in each of 216.859 / 218.118 / 214.753 s, cleanup confirmed | Three guarded nested runs, not integrated public-driver calibration |
| Same W2 measurements | Maximum tagged case 52.435 s including cleanup, below its 60 s cap | Does not establish every new integrated case's budget |
| Latest-main reconciliation, first public `review` attempt | 6 cases failed, 49.071 s | Active coordinator debugging; neither a passing profile nor a final diagnosis |

Final result paths, exact calibration revision, working-tree/source identities, per-case budgets,
collection/setup overhead and cleanup must come from the corresponding public driver's
`result.json` and referenced process artifacts before updating the integrated budget claim.
Do not reconstruct unavailable setup metrics by subtracting unrelated test-body timings.

## Named remaining gaps and baseline failures

- Linux guardian and peer-credential cases are implemented but unexecuted in the Windows
  measurements; actual WSL dispatch is also unexecuted. Windows PowerShell with a private
  transport is not WSL/native compatibility evidence.
- The pinned `DagsterRun` lacks `create_timestamp`; queue-delay timing is unavailable.
- Actual native containers/daemon/provider compatibility, cold builds, current CodeQL,
  Lua/native variants and the full runtime/language matrix have not been authorized/executed.
  The `tools`, `deployed`, `provider`, `guidance`, `codeql-warm` and `native` public profiles
  deliberately fail as unimplemented, not successfully skipped.
- Positive source-bound OWASP assessment-to-review remains unverified. Unknown original
  recorded-feed production cannot be claimed as a real live computation.
- New triage/referral/presentation joins belong to the separate W5 workstream and remain
  unverified at this checkpoint.
- Two existing ELF catalog tests assert an exact gap count and fail after the new
  `delivery_fact_unavailable` gap. The dependency verifier error-wording discrepancy described
  above is also baseline. Neither is silently converted into passing acceptance.

The acceptance guard is a regression guard, not a hostile-code sandbox. Fixture subprocesses
must use invocation-owned, short Windows working directories and must not run child git; the
supervisor exports `APPSEC_ACCEPTANCE_TESTED_COMMIT`. All state and production-format telemetry
remain in unique `test/tmp/acceptance/` roots with separate private runs/driver/HOME/TEMP and
DAGSTER_HOME. No target, production run/data tree or production service is needed. This permits
concurrent process/storage isolation but makes no zero-contention CPU/I/O guarantee; serial is
the default and host load still affects calibration.
