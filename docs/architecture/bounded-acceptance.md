# Bounded acceptance architecture

The acceptance path exercises real application producer/consumer joins without taking ownership
of a production review. The [operator guide](../operations/bounded-acceptance.md) defines commands,
profiles, artifacts and failure policy; the
[implementation record](../reviews/integration-live-test-implementation.md) separates measured
revisions from outstanding commissioning.

## Two graphs, one set of application contracts

The public driver in `deploy/dagster/bin/ops_tests.py` reads the explicit feature-to-node inventory,
creates a `LaneWorkspace`, verifies a checkout-owned environment, supervises collection and then
runs each collected case in a fresh guarded process. At most two cases run concurrently.

```text
scripts/run-tests.{sh,ps1} --acceptance PROFILE
  -> inventory obligations + prerequisites + caps
  -> unique test/tmp/acceptance/<invocation>/<profile>
  -> supervised collection -> exact collected parameter cases
  -> owned pytest process -> real application producer -> accepted handoff/index -> consumer
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

## Authentic joins and explicit substitutions

| Seam | Application behavior exercised | Boundary not established by that evidence |
| --- | --- | --- |
| Signals | Intake/catalog to artifact indexing, coverage formats, profile indexing, source/context semantics and immutable publication | Current compilers and full produced-binary/tool compatibility |
| Dependencies | Accepted build/SBOM input to metadata normalization, repository deduplication, Scorecard retention, exposure indexing and cache-bound immutable publication | Live compiler/Syft/Scorecard availability |
| Graphs/helpers | Source-resolving graph rows to real consumers; safe/unguarded and same-row positive/negative semantics; real SQLite helper build/verify/query | Current graph-engine/CodeQL exports and complete language matrix |
| Process/control plane | Real subprocess/Dagster configuration, worker death/resume, durable intent/reconciliation, MCP stdio errors/recovery, record/replay and sensor observations | Deployed service, provider and native commissioning; Linux paths need Linux execution |
| Controls/feeds | Configured document/standards normalization and real tiny loopback HTTPS fetch/publication/failure preservation | Positive source-bound assessment/review hook and public-feed live computation |
| Review/publication | Real review producer, accepted review/gate, PoC eligibility/planning and current final-report consumer/oracle | Real model quality, compiler execution, PoC success and optional OpenVEX/completion fan-in |

Scripted inference answers only the external model boundary. Recorded receipts/rows answer only
the declared compiler, graph or HTTP boundary. Assertions must consume the application's accepted
output rather than separately inventing both sides of a producer/consumer contract.
Useful negatives include corrupt bytes, missing fields versus an explicitly empty candidate
list, stale identities, cache-context changes, truncated transports and blocked/benign findings.
Skipped/unavailable coverage stays a named gap, not evidence that a target is clean.

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
Linux-specific execution and the final integrated quick budget require their own authorized,
revision-bound evidence.
