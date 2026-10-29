# Bounded acceptance architecture

The acceptance path exercises real application producer/consumer joins without taking ownership
of a production review. The [operator guide](../operations/bounded-acceptance.md) defines commands,
profiles, artifacts and failure policy; the
[implementation record](../reviews/integration-live-test-implementation.md) separates measured
revisions from outstanding commissioning.

## Two graphs, one set of application contracts

The public driver in `deploy/dagster/bin/ops_tests.py` reads the explicit feature-to-node inventory,
creates a `LaneWorkspace`, verifies a checkout-owned environment, supervises collection and then
runs each collected case in a fresh guarded process. Staged obligations dispatch only when
their explicit predecessor has passed custody checks. Default concurrency is one; at most
two dependency-ready cases run concurrently.

```text
scripts/run-tests.{sh,ps1} --acceptance PROFILE
  -> inventory obligations + prerequisites + caps
  -> unique test/tmp/acceptance/<invocation>/<profile>
  -> supervised collection -> exact collected parameter cases
  -> dependency-ready producer phases -> frozen inputs + predecessor checkpoints
  -> post-exit/cleanup supervisor seal -> verified fresh private consumer
  -> confirmed process cleanup + strict obligation accounting -> result.json
```

The fixture's application graph is distinct from this driver graph. Its real job attempts,
configuration, immutable publications, validation, retrieval and downstream consumption use the
private `runs/` root. Production `PipelineLog`, `EventLog` and operation spans instrument both
levels without sharing production log files or metrics destinations.

The inventory is a selection and coverage contract, not a second application registry. Its job,
MCP-tool and provider snapshots detect drift; they do not prove execution of every member.
Every executable obligation declares a bounded question, source nodes, variants, substitutions,
prerequisites and deferrals. Current profile membership cannot retrospectively turn an old
measurement into evidence for newly added cases.

## Integrated staging and custody

The documentation branch incorporates exact parent `a4ce5459`, including detachment
`1d7d621a`, immutable-check optimization `881b8709` and helper-budget consistency `85d39172`.
Optimized public Windows review passed all 13 core cases, including native candidate,
fresh corruption/empty readers and the CI review/gate/report/oracle private consumer chain.
All three two-worker quick warm runs at that frozen source passed 38/38, demonstrating the
runtime target for that concurrency only. Corrected named portable process passed 13/13 with
one worker in 351.471 seconds at the same frozen source. The first exhaustive profile failed on individual/
suite deadlines, so overall acceptance is not finally green.

Variant-specific producers run prepare -> review -> PoC for native-positive, prepare ->
review for native-empty, and prepare -> review -> gate -> report for CI variants. Each
variant has one producer chain and one terminal sealing phase. Frozen configuration,
overlay, target bytes, fixture metadata and declared immutable inputs cannot be rewritten
between phases. The supervisor verifies predecessor tree checkpoints and immutable-input
receipts; after successful interpreter exit and owned cleanup it checkpoints and, at the
terminal phase, seals the resulting tree outside that tree.

The invocation seal is **`appsec-review/acceptance-invocation-seed/1`**, not the operator
`appsec-review/acceptance-seed/1` protocol. It binds invocation, variant, exact tested commit,
source identities, producer, immutable inputs and bounded tree records including bytes,
paths and ordinary permission bits. `source-identities.json` pins all `src/**/*.py`, the
local test-helper import closure, selected tests/driver/configuration/static inputs, and all
files under `docs/schemas/` and `pipeline/`. Pre/post source checks and the source-manifest
digest bind that byte provenance rather than trusting a commit label alone.

Each consumer receives a newly verified ordinary copy with a separate materialization
receipt. Reader run/runs loci relocate; authenticated source/configuration paths and sealed
absolute references stay frozen. No accepted handoff, claim, hash or configuration is
rewritten for relocation. Mutation vectors receive separate fresh copies and independent
production validation, never a cross-case validation cache.

When a consumer executes, its current spans/metrics have a separate private `consumer-telemetry/<uuid>/` root
and `telemetry-origin.json` (`appsec-review/acceptance-consumer-telemetry/1`). Its sidecar
identifies current metric paths and marks retained copied producer telemetry as
`execution_evidence: false`. Copied producer logs/metrics remain history, not evidence that
the consumer reran those producers.

Custody requires bounded ordinary files with `st_nlink == 1`; links, redirected ancestors
and special files fail. Failed or incomplete producers invalidate seal availability and
leave descendants explicitly blocked/unexecuted. Blocked requirements fail adequacy even
when cleanup succeeds; they cannot become skipped passes or executed coverage.

`custody.detach_producer_outputs` now handles real publisher aliases before checkpoint/seal.
It requires successful kernel-owned cleanup, accounts every device/inode/link-count group
entirely within one run's registered named/content-addressed outputs and freshly verifies
production bindings. External/unaccounted, unclassified, cross-run or immutable groups fail.
Exclusive copies are hashed, fsynced, mode-preserved and replaced; strict ordinary-tree and
frozen-input verification still run before publication. Its sidecar is
`appsec-review/acceptance-producer-detachment/1`, with
`acceptance.stage.producer_publication` spans. Failed/partial/deadline operations leave no
usable checkpoint/seal and are not retried.

The guard permits links only in mutable producer locations, not sealed/private reader or
immutable input paths. Verified anonymous stdio PIPE wrapping is distinct from filesystem
descriptor mutation: unresolved, off-root or immutable file-descriptor writes remain denied.
The actual Windows review detached 114 files across native-positive, native-empty and CI
review producers, preserving bytes/modes/bindings. All native and CI core consumers passed
without binding rewrites, with cleanup zero and no production services touched. The Windows
verification todo is **done for this demonstrated publication/staged-review scope**, not
Linux, actual WSL or general Windows `WinError 5` reliability.

`capture_inputs` now freshly traverses/hashes the declared immutable union once per scope,
including the declaration; overlapping paths count once. Missing/extra entries, same-size
edits, ordinary-file identity and depth/entry/file/byte/deadline limits remain checked.
Mutable outputs are not rehashed for every immutable check. Whole producer inspection,
checkpoints, seals and full source checks remain; this is neither a cross-call proof cache
nor a cap increase or omission of full custody checks.

## Authentic joins and explicit substitutions

| Seam | Application behavior exercised | Boundary not established by that evidence |
| --- | --- | --- |
| Signals | Real catalog to artifact indexing, coverage formats, profile indexing, source/context semantics and immutable publication over tiny recorded build receipts | Current compilers and full produced-binary/tool compatibility |
| Dependencies | Accepted build/SBOM input to metadata normalization, repository deduplication, Scorecard retention, exposure indexing and cache-bound immutable publication | Live compiler/Syft/Scorecard availability |
| Graphs/helpers | Source-resolving graph rows to real consumers; safe/unguarded and same-row positive/negative semantics; real SQLite helper build/verify/query | Current graph-engine/CodeQL exports and complete language matrix |
| Process/control plane | Real subprocess/Dagster configuration, worker death/resume, durable intent/reconciliation, MCP stdio errors/recovery, record/replay and sensor observations | Deployed service, provider and native commissioning; Linux paths need Linux execution |
| Controls/feeds | Explicit OWASP qualification, authentic document/catalog context, accepted Workbench retrieval and real tiny loopback HTTPS fetch/publication/failure preservation | Genuine assessment, positive assessment/source binding, precomputed control facts, review join and public-feed live computation |
| Review/publication | Real review producer, accepted review/gate, PoC eligibility/planning and current final-report consumer/oracle | Real model quality, compiler execution, PoC success and optional OpenVEX/completion fan-in |
| Triage/referral/presentation | Real triage ordering/admission and bound review handoff; foreign-anchor repair, next-round referral deduplication and stable convergence; accepted gate/report counts, states, gaps and provenance rendered to HTML/LaTeX | Exhaustive consumer coverage, specialist dispatch/resolution, cross-package/lane referrals, saturation and stale/historical renderer selection |

Scripted inference answers only the external model boundary. Recorded receipts/rows answer only
the declared compiler, graph or HTTP boundary. Assertions must consume the application's accepted
output rather than separately inventing both sides of a producer/consumer contract.
Useful negatives include corrupt bytes, missing fields versus an explicitly empty candidate
list, stale identities, cache-context changes, truncated transports and blocked/benign findings.
Skipped/unavailable coverage stays a named gap, not evidence that a target is clean.

The latest dependency/native seam corrections retain strict reference authority. Production
fix `75383329` treats `native_artifacts` rows as source inventory rather than declaring their
display paths to be run artifacts; nested `evidence_source.artifact` and explicit `run_path`
references are still collected and verified. Fixture correction `67944818` makes workspace
manifests and protected compile-command artifacts direct accepted-handoff members.
Package-local fixture `e9b336e8` separates dependency roots and uses a static QA archive rather
than accidental SONAME evidence, so a sibling does not acquire false production exposure.
These are real contract fixes exercised with recorded native inputs, not native execution or
tool/daemon compatibility proof.

Inventory revision `09cbf227` separates representative `quick` from full signals, graphs,
process, controls and review matrices without removing negative variants. It enrolls the
three consumer nodes in a separate `consumers` profile. The ordinary 60-second limit and
explicit 15/30/120-second obligation caps remain distinct from suite caps; process startup/replay
has explicit 120-second allowances within its 480-second suite.
The current staged inventory further separates 13 core `review` cases from 24
`review-exhaustive` cases (full integrity/benign/blocked variants). Both retain 600-second
suite ceilings; exhaustive calibration is unproved. Current `quick` has 35 selectors resolving
to 38 cases, including its staged prerequisites, without increasing its 720-second cap.

The application supports genuine OWASP assessment mode, but this bounded control fixture
explicitly uses `QUALIFICATION` with worker/reviewer inference disabled and five pinned
abridged catalogs. Accepted Workbench rows are `qualification_only` / `fixture_only`,
non-lead-eligible, and retain missing-evidence gaps. Document/source integrity and accepted
context are exercised; positive assessment/source binding, precomputed facts and review
consumption are not. Older claims that the configured producer lacks an assessment hook are
not descriptions of current application capability.

## Review, PoC and final-survival authority

The authentic fixture attaches source-resolving call-chain evidence to an accepted index set and
runs the current inference-review job using scripted inference. Framework handoff envelopes use
`handoff/2` through `tests.handoff_fixture.write_fixture_handoff`. The current review domain is
`/3`; gate and report domains remain `/2`. These domain versions are separate from the
framework envelope and must not be changed to make fixture integration pass.

PoC planning consumes the direct accepted review and its strict candidate eligibility rules.
The native candidate fixture therefore follows review directly, without a prerequisite gate;
the CI final-survival fixture follows the actual review -> gate -> report chain.
The no-accepted-build case proves that eligible candidates retain the missing-build disposition:
planning does not dispatch a compiler or model without an accepted build. It is not a successful
PoC experiment. Empty candidate lists are valid explicit outcomes; missing/corrupt contracts must
fail before dispatch.

Final publication remains **gate-only**. The final-report job consumes the accepted publication
gate; there is no OpenVEX fan-in. Latest-main completion/OpenVEX/interchange changes must not be
papered over by synthetic dependencies or weakened domain schemas.

The current-report oracle resolves the accepted final report, delegates gate validation to
`load_accepted_gate`, and verifies that the accepted review, package projection, configuration,
ledger/policy pins and current accepted manifest still agree. Finding evidence must resolve
through that manifest to the current source bytes. Answer-key survival includes finding-package
and claim identity, source location, state and final bucket, not just a matching scanner message.

Scanner observation enumeration remains useful diagnostic detection data, but cannot establish
final survival. Orphan/historical shards, missing current reports, changed accepted bytes and
stale review/gate references cannot satisfy this oracle. Benign/blocked publication is tested
separately rather than equated with an empty scanner index.

The consumer extension at `06a4ea6c` uses the existing typed synthetic accepted-index producer
and scripts only the external inference callable. Its real review, gate and report outputs are
not injected. CI-only fixtures omit unrelated build/component/reference shards and feeds;
missing facts remain gaps. Three exact nodes passed under the actual supervisor/plugin, but
that is not a named inventory/profile CLI execution or exhaustive consumer coverage.
The later `09cbf227` enrollment does not retroactively turn that run into named-profile proof.
There is now separate actual named `consumers` CLI proof at `1ff86556`: 3/3 passed in
207.438 seconds. It covers these bounded nodes, not the remaining consumer matrices.

The renderer test has one authentic hash-bound current publication. `reporting.sources.RunReader`
still selects by globs rather than a current-accepted renderer API; this test does not establish
stale/historical selection or tamper rejection by rendering. That limitation is separate from
the current-report oracle's certified accepted-reference validation.
Next-round referral transport, deduplication, foreign-anchor repair and convergence are proven
for this fixture, while `unresolved_specialist_referral:ci_cd_pipeline` remains explicit.

Latest-main fixture reconciliation must freeze the actual configuration before constructing
synthetic upstream handoffs and bind the explicitly claimed upstream digest. A one-lead-package,
no-hunt configuration is a legitimate tiny selection when declared explicitly; it must not
silently disable the contract being tested.

Each oracle evaluation needs a fresh production `validation_scope`. It may batch unchanged
negative expected identities into one evaluation, but must not reuse a validation cache across
tamper attempts. These reconciliation requirements do not themselves establish a passing
latest-main execution.

## Isolation and evidence boundaries

`LaneWorkspace` confines state to a fresh root below `test/tmp/acceptance`; the driver gives it
private home/temp/Dagster paths and a separate fixture runs directory. An audit-hook regression
guard rejects accidental protected-tree access, off-root writes, external sockets and unowned
executables. Parent correction `19c7c000` permits only two supervisor-hash-pinned read-only
application inputs under the protected data tree: `data/reference/taxonomy/vocabulary.json`
and `data/reference/taxonomy/crosswalk.json`. Their identities are validated before the guard
hook is installed and recorded in source identities. All mutations and other protected data
remain denied; this is not general production-data access. The guard is not a hostile-code
sandbox.

Each supervised process records its pinned static input identities; the driver rejects a
case whose identities disagree with the suite's source hashes, even after successful pytest
execution. Mutation detection includes descriptor truncation/append flags. These checks do
not replace the named timing and host-dependent gaps in the implementation record.

Historical parent `1ff86556` contained then-main `a8883acc`, source-history/OpenVEX changes and
the native/reference corrections. Its capacity overlay no longer forces three review teams:
production/Copilot production profiles retain seven, while the overlay selects four I/O and
four scanner slots. Explicit one-team acceptance fixtures are bounded test configuration,
not a description of production capacity or a shared-host reservation.

The named `process` profile has a revision-bound 13/13 public CLI pass at `16a520f4`, and named
`consumers` passed 3/3 at `1ff86556`; Linux-specific obligations remain outside those proofs.
An exact-node dependency pass at `1ff86556` likewise does not establish a whole signals/quick
pass. Planner `81ada94f`'s read-only
`staged-authentic-producer/private-verified-materialization` proposal is historical: its
staged implementation now exists as described above. Output detachment is now separately
implemented and has a complete timed Windows core-review pass. Its scoped verification todo
and three-warm two-worker quick calibration are done; corrected named portable process also
passes. The exhaustive gate remains: its failure includes an own-deadline integrity timeout
and a gate stopped by remaining suite budget; its blocked report/consumer are unexecuted coverage, not
semantic gate failures. A narrow per-vector/subprofile proposal awaits approval and is not
implemented. No prior approval grants a budget or validation waiver for that new proposal.

The process gate, Windows Job Object and Linux subreaper supply owned-tree lifecycle control.
Collection, execution and cleanup all consume declared deadlines; unconfirmed cleanup is failure.
The supervisor supplies the tested commit to guarded children, which must not shell out to git.
Windows child working directories must stay short as well as invocation-owned.

Results retain commit/source hashes, exact selected/collected/executed cases, substitutions,
prerequisites, logs, wall time and production-format resource measurements. Null resource fields
retain their reasons; process CPU is not total descendant CPU, and a process high-water mark
is not claimed as case-attributable RSS. Timings from direct tests, extracted-plugin nesting and
the public driver are different evidence classes.

These boundaries support concurrent review storage/process isolation, not guaranteed zero host
contention. Serial is the default. Live tools, provider quality, deployed/native compatibility,
Linux-specific execution, unselected record/replay/sensor variant matrices and the final
integrated quick budget require their own authorized, revision-bound evidence.
