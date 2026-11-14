---
title: "Appsec-review: system review and downstream verification plan"
kind: "review"
subsystem: "testing and operations"
status: "historical"
jobs: ["job_build_environment_analysis", "job_build_iteration", "job_document_issue_analysis", "job_inference_security_review", "job_language_build", "job_poc_generation", "job_review_data_indexing", "job_sanitizer_build", "job_security_tagging", "job_target_analysis_plan", "job_target_catalog"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Appsec-review: system review and downstream verification plan

**Reviewed 6 November 2026.** Local source: `wsollers/appsec-review` at
`967a1072bc19feeb320ce4b44d6c056616c94d7b`.

> **Status (2026-11-08).** This is the design review the "appsec implementation fleet" (packages
> F00–F17, retired 2026-11-08) was dispatched from; it is kept as the rationale behind those goals.
> The fleet's plan, ledger and integration log were deleted from `docs/plans/appsec-system-improvements/`
> (history: `git log -- docs/plans/appsec-system-improvements`). What landed is in `main`'s ancestry;
> every goal that did not land is registered in `docs/TODO.md` **T-059**, each gated on the first
> scored review run (T-057). Section 14's implementation plan and the package boundaries are
> historical; current sequencing is T-057 → T-059.

## Executive judgment

**Keep the architecture; close its integration seams and complete the evidence loop.**
This is already much more than a collection of scanner prompts. It has a substantial
evidence store, immutable handoffs, bounded retrieval, explicit uncertainty, independent
review roles, centralized model execution, and repair admission. The largest remaining
opportunities are not another general-purpose agent or a Rust rewrite:

1. Repair publication/inventory contract drift that can block a default review.
2. Establish deployment, service, listener and threat-model facts as first-class inputs.
3. Turn findings into faithful, bounded runtime experiments, then reproducible regressions.
4. Measure retained true findings, missed coverage, and useful yield, not just completed jobs.
5. Make stop/fix/test/resume work predictably across supported execution modes.

The recent six-package integration already addresses many earlier concerns about thin
worker prompts, duplicated model-call mechanics, operational inspection and repair.
Do not implement those capabilities again under new names.

### Scope and confidence

I statically inventoried **659 Python files, 178,657 physical lines**, all **46 registered
job constructors**, the **45 job dataset-declaration modules**, job-test mappings,
configuration, prompts and runtime skills. I traced the important publication, inventory,
retrieval, recovery, inference, PoC and reporting boundaries directly. The file/line count
includes comments and blanks; it is not a coverage metric.

This is **not a line-by-line audit of every source file**, a vulnerability scan, or an
end-to-end execution certification. No target, build, test suite, model review, installation,
deployment or fuzz campaign was executed. Source-level defects below are distinguished
from observed runtime failures. The primary checkout remained unchanged at the reviewed SHA.
The accompanying `source-inventory.json` preserves the static inventory and declarations.

Literature input includes the completed
Glasswing evidence review (`ghapp://sessions/67c66298-7ac8-484d-ac62-1b542028d774`),
OpenAnt primary source at `9143061f93c546493dea96394b6e6d4c5f29311d`, and the APS Lean
model and latest local DDNet fuzzing design supplied by that project's coordinator.

## 1. What is already good

| Area | Existing strength worth preserving |
|---|---|
| Job lifecycle | One composed `Job`/`JobRunner`, explicit units, accepted/rejected handoffs, immutable attempts and a commit marker; scanner execution, admission and coverage are separate. |
| Provenance | Source/configuration/guidance/build identities, hash-bound artifacts, shared computation receipts and explicit validation of reuse origins. |
| Retrieval | Bounded accepted indexes; exact identities, schemas, pagination, scope denials and missing-coverage accounting rather than arbitrary model filesystem access. |
| Worker guidance | Rich domain personas, separate roles/tasks, shared governing rules, allowlisted runtime skills, immutable bundles, and generated Capability & Artifact Cards. |
| Review reasoning | Lead and hunt lanes; red, blue, blind verifier and judge; deterministic adjudication/scoring; high-risk independence policy and retained disagreement. |
| Model execution | Shared deadlines, cancellation checkpoints, bounded calls/bytes, retry categories, usage accounting and hash-only execution receipts. |
| Operations | Canonical event stream, job/unit/tool/model spans, progress, storage counters, operator-only MCP inspection, repair planning and explicit stop verification. |
| Publication | PoC/remediation/dossiers precede a single certifying gate; report and OpenVEX consume its frozen snapshot rather than discovering later mutable outputs. |
| Honest limitations | Sanitizer compilation is not execution; document claims are provisional; missing producers are gaps; Lean model proofs are not C++ refinement. |

These are foundations to extend, not replace. [C1-C8]

## 2. Highest-priority source findings

Priority below is engineering priority, **not vulnerability severity**.

### P0: the inventory does not own newer recovery/publication artifacts

`runtime/repair.py` writes `data/recovery/current.json`, release snapshots, worker records
and admission locks. `runtime/runner.py` now writes each attempt's `published.json`;
`runtime/checkpoints.py` publishes task `checkpoint.json`.

`indexing/inventory.py:runtime_claims` does not declare these recovery paths or the two
new lifecycle filenames. Its strict scanner walks `data/`, treats an unmatched non-index
file as unaccounted, and turns that into an audit violation. The indexing job then raises
on violations. Strict assurance is the checked-in default.

**Consequence:** current source has an integration mismatch that can reject legitimate
runtime-owned files before review packaging. It is not necessary to weaken the audit:
declare these exact runtime-owned artifact classes, with appropriate protected/operational
dispositions. Preserve audit failure for genuinely undeclared files.

**Required regression:** construct a real minimal runner publication and failed-unit
checkpoint, then inventory its actual tree under strict assurance. Include recovery
binding/worker records, accepted and rejected attempts, commit markers and a deliberately
undeclared file. Test managed-publication accounting separately. This was identified
from source; I did not run that reproduction. [C2]

### P0: the internal build-iteration job is treated as a declared inventory producer

`job_build_iteration` is intentionally not an unconditional review-graph job. Its factory
returns an always-executed, non-propagating `Job` with **no datasets**, and it has no
`datasets.py`. It is nevertheless registered and configured, with no disabling flag.

`job_review_data_indexing.registry_providers()` skips the missing module, while `load()`
includes enabled configured jobs except its downstream list. That includes
`job_build_iteration`. The audit explicitly rejects any such job with no declarations.

**Consequence:** the inventory's definition of "could run" disagrees with the registry's
internal-job semantics. This is another source-level default-path blocker.

**Fix:** represent dispatch class explicitly: review graph, internal child transaction,
or external maintenance. Give internal iteration artifacts an explicit owner/contract;
do not solve this by globally ignoring internal-job files or disabling the build facility.
Inventory should account for internal attempts when present without requiring an
unconditional top-level handoff.

**Required regression:** default resolved config plus the real registry must produce
correct inventory eligibility, both with and without an internal iteration. [C3]

### P1: scheduling, consumption, input matrices and retrieval ownership can drift

There are multiple manually maintained descriptions of the same system:
`registry.py`, `topology.py`, each job's `CONSUMES`, dataset declarations,
`indexing/input_matrix.py`, the test map and documentation.

Concrete discrepancies:

- `job_build_environment_analysis` is registered/default-enabled but absent from
  `INPUT_SOURCES`; reconciliation reports a registered producer missing from the matrix.
- `job_security_tagging` declares `CONSUMES = ()`, although it opens the accepted input
  manifest and reads its producer shards.
- Review-data indexing consumes OWASP state and inventories tagging/environment
  publications, but its `CONSUMES` list does not express all of those dependencies.
- OWASP's upstream allowlist still names unregistered `job_target_documents`, although
  actual target documents are published by `job_target_catalog`.

The graph's transitive input projection currently supplies more context than `CONSUMES`
alone describes. Thus these discrepancies are **not proof that all runtime inputs are
missing**. They make the claimed consumption matrix unreliable and increase repair/reuse risk.

**Recommendation:** extend the existing job contract with typed input requirements:
producer/output kind, schema, required/optional/conditional status, missing-input policy,
and evidence authority. Retain explicit scheduling-only edges, but validate them against
data dependencies. Generate inventory and documentation from that contract; check release
closure and test-map completeness against it. Do not create another parallel registry.

Record actual admitted reads against the contract. Distinguish "artifact exists,"
"artifact supplied," "worker retrieved it," and "artifact used in the final reasoning."
Those are four different assertions. [C4]

### P1: document-issue production has no completed adjudication path

The document job deliberately emits a private candidate ledger and always returns
`COMPLETED_WITH_GAPS`; its own message says finding publication is not implemented.
The inference job does not read that candidate-ledger contract, even though topology
orders it after the document job. Ordering is not consumption.

Document/source navigation already exists elsewhere, so this does **not** mean all
document evidence is absent. It means this particular candidate-producing job has no
completed route to independently adjudicated findings.

Either feed its neutral, source-mapped candidates into existing hunt/review packages,
retaining their provisional status, or make the stage explicitly optional until that
route exists. Do not run an expensive-looking "map_and_adjudicate" stage whose contract
stops before adjudication. It is also the only registered job with **no handler-specific
unit selector** in the current test map; two integration selectors are not a fast repair
loop. This is a mapping gap, not proof that no relevant tests exist anywhere. [C5]

### P1: "stop, fix A, resume A" is supported only conditionally

The basic mechanisms exist, but the stronger operational promise is not yet universal:

- Successful upstream jobs can be reused only with matching inputs, implementation,
  schema, validation, deployment and artifact identities.
- A repaired job gets a **new immutable attempt**; its affected downstream closure reruns.
- Generic successful-unit reuse excludes paths, artifacts, workspaces, budgets and
  process state. Many expensive jobs return exactly those objects. It also requires
  matching implementation identity, so an actual implementation repair often prevents
  reuse inside A even when some work succeeded.
- First-error controller identity cannot be reopened in place. The documented successor
  route currently imports **no successes** and reruns everything.
- Native first-error cancellation/cleanup is explicitly not commissioned.
- Application code is baked into images; a source edit is not a deployed job hot reload.

Therefore: **yes for ordinary admitted DAG repair; no for arbitrary mid-job or every
first-error/native run without lost work**. See section 7 for the completion plan. [C6]

### P1/P2: telemetry exists, but some operational/quality interpretations are weak

`DAGSTER_QUEUE_DELAY` is calculated at each job claim as current time minus the
**Dagster run's creation time**. For later jobs, that includes predecessor execution,
not just scheduler queue time. The common metrics rollup also aggregates fields named
`queue_delay_ms`, including resource-admission waits.

Rename/split these measurements into run admission, dependency wait, scheduler wait,
resource wait, launch and execution. Otherwise a long upstream build can look like
downstream queue saturation.

The optional `BoundedOTLP` helper exists, but no runtime caller was found in the inspected
source. It is not evidence of a commissioned exporter, dashboard or alerting deployment.
Its in-memory queue is not the durable source; use the existing canonical event log as
a replayable export source if remote export is enabled.

Quality adapters correctly label several fields unmeasured, and the realistic multi-turn
competence harness currently supports **the independent verifier only**. That is good
honesty, but insufficient evidence of the whole system's discovery effectiveness. [C7]

## 3. Redundancies and the right common boundaries

The exact-AST duplicate search found one cross-file function-body duplicate above its
12-line threshold: `_mapped` in .NET and Rust build handling. This is narrow evidence,
not a claim that the rest is duplication-free.

| Candidate | Recommended change | Avoid |
|---|---|---|
| Workspace path mapping | Extract the identical `.NET`/Rust `_mapped` behavior into a tested build-capture helper. Keep language-specific argument parsing separate. | A universal compiler adapter that hides real language differences. |
| Artifact reads/publication | Standardize existing `storage.shared`, `bound_artifacts` and local `_artifact`/`_read` conventions around typed references and explicit policy. Current readers differ in size bounds, reference shape, path checks and exceptions. | Replacing every reader blindly: source evidence, protected inputs and immutable shared objects have different trust requirements. |
| Accepted build API | Extract stable public readers for accepted recipes, workspaces, outputs and replay commands. Sanitizer code imports private language-build helpers and CodeQL planning helpers today. | Making sanitizer/fuzz consumers depend on private implementation details of unrelated producers. |
| Input-contract declarations | Make one input/output contract authoritative and validate scheduling edges against it. | Another YAML/Markdown source of truth. |
| Retrieval authorization | Share transport-neutral grant/schema/scope checking where semantics coincide between MCP and in-process cells. Preserve MCP token/session handling separately. | Forcing all internal reads through an MCP transport or deleting intentional capability differences. |
| Model loops | Keep `inference.execution.Execution` as the common mechanism; retain specialized retrieval and final-answer validators. | Reimplementing budget/retry/usage mechanics per new fuzz planner or threat-model worker. |
| Large modules | Split by stable domain boundaries: build planning vs execution vs publication; telemetry derivation vs receipt verification; review-team scheduling vs stage transitions. | File-count reduction for its own sake or a framework of empty abstractions. |

The largest modules are about 1,600-2,000 lines, including language builds, topology,
telemetry, packages, retrieval and review teams. More importantly, the strict mypy file
allowlist is small relative to the system. Expand typed public contracts first, especially
artifact references, accepted build context, job results and input requirements.
`dict[str, Any]` at every boundary makes semantic drift expensive to detect. [C8-C10]

### Python, skill or MCP?

**Python/native code owns correctness:** canonicalization, authorization, hashing, schema
validation, publication, cache keys, timeout enforcement, tool execution and adjudication.
None of that becomes reliable by moving it into a prompt.

**Skills own reusable procedure:** threat-model construction from supplied facts,
service-exposure interpretation, harness-design checklists, oracle selection,
reproducer minimization and evidence interpretation. Use the repository's existing
separation: development skills under `.claude/skills`; job-loaded runtime guidance under
`pipeline/skills`. Do not copy APS's repository-specific skill path into this repository.

**MCP exposes bounded capabilities across processes/clients:** keep existing evidence
retrieval and operator inspection; add service-topology/threat-model queries when those
datasets exist. A future fuzz MCP should wrap the same runner, not implement another
engine, store or policy.

Do not install unrestricted filesystem, SQL, shell or browser tools into review workers
to compensate for missing indexes. Repair the producer/query route and capability card.

## 4. Prompts, personas, roles and artifact awareness

**The primary personas are already sufficiently substantive.** They name likely failure
modes, effective controls, conditional false positives, evidence per predicate and
cross-specialist cues. `api_web` and `deployment_operations` map to rich successor
personas. Short registry descriptions are not the full effective prompt.

The newly shared worker contract is also strong: selected governed bundles, exact
operation schemas, citation formats, remaining limits, admitted artifact cards and
explicit refusal/abstention. Keep deterministic scorers, adjudicators and completeness
auditors deterministic. Registered `poc_designer`/`poc_verifier` are not dispatched by
the current PoC writer path; installing more agents does not activate them. [C11]

Remaining improvements:

1. **Give every security question an explicit attacker profile.** Distinguish anonymous
   remote user, authenticated tenant, malicious uploaded file, adjacent process, plugin,
   compromised dependency and privileged operator. Attach permitted capabilities and
   entry points to each hypothesis. Do not assume every application is a browser service.
2. **Add an environment/evidence card, not more general prose.** Include selected deployment
   variant, listener/service relationships, identity and trust boundary, build flags,
   supplied/excluded datasets, freshness, and unresolved configuration assumptions.
   Existing cards can carry this once real producers exist.
3. **Make evidence acquisition actionable.** When a worker cannot prove a predicate, return
   a typed request for an upstream artifact, service observation or approved experiment.
   The controller decides whether to schedule it. Workers do not self-grant tools.
4. **Test useful retrieval, not just valid JSON.** Cover the right excerpt being on page 2,
   a guard in another file, misleading comments, conflicting environment overlays,
   wrong-build symbols, unavailable APIs, negative controls and justified abstention.
   Extend competence evaluation beyond the verifier to discovery, planning and remediation.
5. **Keep blinded independence real.** Different roles on one model are not independent
   error sources. Dev uses one profile and correctly leaves distinct-verification
   ship-blocking conclusions pending. Prod selects a distinct verifier/judge model;
   measure its benefit, and use held-out human adjudication for evaluation.
6. **Represent logical/stateful properties explicitly.** The native persona mentions races,
   but a reusable state-machine procedure would improve sequencing, retries, ownership,
   idempotency, transaction boundaries and resource accounting. Add it as a selected skill,
   not another always-on panel.
7. **Use marginal yield to allocate workers.** The default 3-red/2-blue/verifier plus judge
   structure may be expensive. Compare incremental unique validated findings and TP retention
   per role/round. Keep every-claim judging until an approved ablation justifies changing it.

The default hunt limit is 50 units and medium/low exploration is off in dev; prod enables
exploration but still has bounded scope. Those are legitimate cost controls, not exhaustive
coverage. Report their excluded populations prominently. Stability after one unchanged
round is a stopping heuristic, not evidence of recall. [C12]

## 5. Deployment inventory and threat models

### The gap

The system **ingests existing threat-model/DFD documents** and joins them to source/API
context. That is not a job that generates and maintains an evidence-backed system threat
model. `deployment_topology` is explicitly planned, and `dynamic_traces` is a future
producer in the input matrix. There is no corresponding registered job. [C4, C13]

Build topology answers "what gets built, from what, with which settings." Deployment
topology answers "what runs, where, as whom, and who can reach it." Both are necessary;
they must not share one ambiguous topology object.

### Proposed producers

| Producer | Inputs | Outputs and important boundary |
|---|---|---|
| `job_deployment_topology` | Accepted catalog; IaC and rendered/selected overlays; Compose/Kubernetes/Helm/Terraform/CloudFormation/Bicep descriptors; CI deployment declarations; build artifacts; source routes/listeners; dependency inventory. | Versioned components/services/listeners/edges/identities/data stores, evidence references and conflicts. Static declarations do not establish deployed state. |
| `job_service_exposure_observation` (optional) | Explicitly authorized environment and resource IDs; pre-approved collectors or imported operator snapshots; expected static topology. | Time-bound observed listeners, owning process/container, bind address, effective configuration, relevant routing/policy, and drift. No broad network scan or cloud access by default. |
| `job_threat_model` | Those topologies; component classification and security tags; OWASP applicability; data sensitivity; API/message contracts; build variants; operator-approved attacker/environment assumptions; existing design documents as untrusted context. | Machine-readable assets, actors, trust boundaries, data flows, threats, mitigations, proof obligations, unknowns and per-claim citations; a rendered human view derived from the same object. |

Start with static topology after catalog/build evidence. Generate a preliminary model
from available facts, then refine it before hunt/package assembly. Avoid a cycle in which
OWASP cannot run without the threat model while the threat model requires OWASP findings:
share classification/applicability facts and use a bounded refinement stage.

Threat-model outputs are **reasoned context**, not direct proof that a mitigation is
effective. Operator policy owns scope and accepted attacker assumptions. Target-owned
documents cannot declare themselves out of scope or suppress findings.

### Common software and cloud-service coverage

Use a versioned, extensible **signature and evidence-extractor catalog**, not one enormous
prompt list. Every match needs evidence, environment, identity confidence and uncertainty.

| Family | Initial examples | Facts to capture |
|---|---|---|
| Edge/proxy/web | Nginx, Apache httpd, IIS, Envoy, HAProxy, Traefik, Caddy | Listener/bind/TLS, virtual hosts, proxy routing, forwarded-header trust, admin endpoints, effective config. |
| Databases | PostgreSQL, MySQL/MariaDB, SQL Server, MongoDB, Amazon RDS/Aurora, Azure SQL, Cloud SQL | Exact engine where known, auth, tenancy, reachability, TLS, backups, public/private endpoint and IAM relationships. |
| Cache/search | Redis/Valkey, Memcached, Elasticsearch/OpenSearch | Client/admin ports, ACL/auth, dangerous capabilities, persistence and sensitive-data role. |
| Messaging | Kafka, RabbitMQ, NATS, SQS/SNS, Azure Service Bus, Pub/Sub | Producer/consumer identity, topic/queue ACLs, deserialization, replay, ordering and dead-letter handling. |
| Storage | S3, Azure Blob, GCS, SMB/NFS, local volumes | Read/write principals, public access, mount boundaries, encryption, retention and data classification. |
| Compute/platform | Kubernetes, ECS, EC2, AKS, GKE, Functions/Lambda/Cloud Run/Container Apps | Service accounts, instance/workload identity, metadata access, network policies, ingress/egress and privileged settings. |
| Identity/secrets | Entra ID, Cognito, Keycloak, Vault, cloud KMS/secret stores | Issuers/audiences, role/trust bindings, delegation, secret references and boundary crossings. |
| Admin/observability | Metrics/debug/health endpoints, dashboards, management consoles | Exposure, sensitive output, authorization and tenant boundaries. |

A default port is a **hint**, not identification. `EXPOSE`, a connection string, installed
software, a source `listen()` and an observed reachable endpoint are different evidence
classes. A server version banner does not prove effective configuration or vulnerability.
Managed services may not expose an exact patch version; record that instead of inventing one.

Do not reuse the platform's own Garnet/Redis service as target inventory. The scope
boundary must distinguish supplied analysis infrastructure from customer software.

## 6. Rust cache interface or native file interchange?

**Do not write a Rust Redis/Garnet wrapper now.** The blue-result memo exchanges small
receipt pointers through an existing Redis client; it does not transfer large source trees.
It is run-scoped, revalidates results, excludes red/verifier/judge memoization, and treats
cache outages as logged lost savings rather than correctness failures. Network/service
latency and model latency are more plausible costs than Python pointer encoding. [C14]

Also distinguish three caches:

- External blue-cell memo: optional answer reuse, never truth or evidence.
- Shared content-addressed artifacts/computation receipts: provenance and publication.
- Validated index/digest reuse: evidence-read performance under an assurance policy.

A native project aimed at the first may do nothing for bottlenecks in the other two.

**A narrow native artifact service is worth considering only after profiling.** Good
candidates are bulk manifest verification, descriptor-relative path custody, atomic
no-replace publication, streaming copies and batched metadata operations. Hashing and
SQLite already spend substantial work in native implementations; filesystem journal waits
and repeated work will not disappear because the caller is Rust.

Before choosing:

1. Use existing hash/copy/fsync/lock/index spans to measure cold/warm behavior, source size,
   bytes reverified, object count, cache hits, blocked time and end-to-end review time.
2. Remove avoidable verification/copy repetitions within existing safe custody scopes.
3. Benchmark one isolated native prototype against the real workload and all integrity
   controls. Keep Python as the orchestration/schema-policy layer.
4. Require a meaningful end-to-end improvement or a clearly needed custody/durability
   guarantee, not a microbenchmark win.

If justified, use a versioned local CLI/library interface with bounded requests and typed
results. Preserve canonical bytes, digest domains, immutable conflicts, protected artifacts,
cross-filesystem behavior and Windows/WSL distinctions. Differential tests must cover malformed
JSON, Unicode, integer bounds, symlinks, interrupted publication and storage exhaustion.

**Durability caveat:** the inspected writers fsync file contents then rename/link; they
do not visibly fsync parent directories at those publication sites. Process-crash recovery
and power-loss durability are different contracts. Specify the required guarantee and test
it on supported filesystems before claiming either Python or a native replacement is
power-loss durable. Do not rewrite the entire store to answer that question. [C8]

## 7. Finish the job-A repair loop

Build on the existing `failure-replay`, `select-job-tests`, `verify-repair-stop`,
`plan-repair`, `admit-repair` and resume commands.

The intended operator flow should be:

```text
Failure in A
  -> stop admission of new affected work; verify owned-worker cleanup
  -> retain failure manifest, inputs, source/config/build identities and diagnostics
  -> reproduce with a focused handler/contract regression
  -> repair in an isolated development checkout
  -> build/identify only the affected deployment
  -> compute and approve compatibility/invalidation plan
  -> create fresh A attempt; reuse admissible predecessors and independent branches
  -> regenerate downstream evidence and the final publication snapshot
```

Required completion work:

| Requirement | Acceptance condition |
|---|---|
| One supported operational path | Demonstrate the real chosen deployment's failure/stop/repair/resume lifecycle; separate direct, Dagster and native support claims. |
| Typed subjob checkpoints | Expensive path-bound work reuses immutable artifact references with producer identity and dependency validation, not blanket copying of result dictionaries. |
| Precise invalidation | A changed A/helper invalidates its actual computation dependents; unrelated branches remain usable. Scheduling-only barriers should not automatically imply data dependence. |
| Successor reuse | Either safely import verified compatible predecessor publications into a successor, or explicitly present the cost of the existing all-rerun behavior. |
| Deployment identity | Paired source-release/image identity; no claiming a Python edit updated a baked image. A future script mount needs a supported immutable per-run snapshot. |
| Unit coverage | Fill the document-job mapping; demonstrate each selected regression exercises the failing behavior rather than only schema fixtures. |
| Operator experience | Show why each job/unit is REUSE/RUN/INVALIDATE and what input or implementation changed, with estimated lost/reused work. |
| Failure injection | Exercise interruption before/after each publication boundary, stale plans, missing artifacts, model timeouts, storage errors and cancellation uncertainty. |

Do not auto-execute captured commands from diagnostics. A failure bundle is evidence for
a developer, not an executable repair instruction.

## 8. Telemetry and job tracking: sufficient for what?

**Good for bounded local diagnosis; not yet sufficient to establish production usefulness.**
Existing traces, usage receipts, progress, custody counters and operator inspection deserve
credit. More logs are not the principal need.

Add or make first-class these derived views:

| View | Required dimensions |
|---|---|
| Execution SLO | Per-stage wait/launch/runtime, cancellation-to-cleanup time, failed/retriable units, lost/reused work, repair-to-resume interval. |
| Evidence coverage | Eligible/analyzed/built/extracted/retrieved/reviewed/reproduced populations; disabled, omitted, unsupported, truncated, stale and failed separately. |
| Finding funnel | Raw observations -> deduplicated leads -> admitted packages -> proposed claims -> adjudicated findings -> experiment-eligible -> harness-valid -> reproduced -> patch-regressed. |
| Evidence use | Producer output supplied/retrieved/cited; relevant evidence requests denied/unfulfilled; orphan outputs with no consumer. |
| Cost and value | Actual vs unavailable/estimated usage; cost/time per unique adjudicated TP; marginal yield by scanner, persona, strategy and round. |
| Reproducibility | Root-cause identity, frozen comparison groups, launch-order run indices, adjacent run-over-run Jaccard and mean pairwise stability separately; replay results, flaky cases and corpus snapshots. |
| Quality | Known-TP retention, FP removal, precision of retained findings, novel-findings adjudication, abstention, unsupported conclusions, calibrated-severity errors and uncertainty. |

Alerts should cover stuck work without progress, cancelled work with retained active resources,
publication integrity failure, quota/disk exhaustion, unavailable model usage and major
coverage loss. Export only allowlisted metadata; keep raw source, prompts, secrets and
protected experiment evidence local to their approved scope.

Do not label hash-revalidated receipts as fresh scanner work. Do not sum process-inclusive
resources across overlapping spans. Both limitations are already recognized in the design.

## 9. What to learn from OpenAnt

Primary comparison:
[repository at reviewed commit](https://github.com/knostic/OpenAnt/tree/9143061f93c546493dea96394b6e6d4c5f29311d)
and [OpenAnt paper](https://arxiv.org/html/2606.19149).
The paper, documentation and current source describe different revisions in places;
the inspected source is the reference for implementation observations here.

| Borrow | Adaptation for appsec-review |
|---|---|
| Explicit application context and attacker profiles | Make them evidence-backed, operator-scoped and consistent between discovery and verification. Avoid generic browser-only assumptions. |
| Reachability-focused analysis units | Use existing code graphs/packages to prioritize work and reduce irrelevant context. Retain unmodeled/unreachable/unknown populations and sample excluded units for recall checks. |
| Adversarial challenge after discovery | Already present here. Measure its incremental benefit; do not add another near-identical verifier. |
| Finding-specific dynamic experiments | Add a bounded downstream execution stage using exact target/build context and retained observations. |
| Typed dynamic outcomes | Preserve reproduced, not reproduced, blocked, inconclusive and operational error separately. |
| Finding-specific language/runtime selection | Select from the finding/build, not only the repository's dominant language. Unsupported targets become explicit gaps. |
| Resume identity includes prompt behavior | Keep the existing frozen guidance/implementation identities; test that routing changes invalidate affected results too. |

Important things **not** to copy:

- OpenAnt's current dynamic generator allows unpinned dependencies except where
  version-specific, and permits a newer runtime on retry with a recorded deviation.
  For this system's evidence standard, use exact accepted dependencies/builds first;
  changed environments are separate experiments, not verification of the original one.
- Its result collector accepts the generated test's structured status from stdout.
  That is a useful interchange format, **not an independent oracle**. A script printing
  `CONFIRMED` must not be enough to confirm an appsec finding.
- Aggressive reachability pruning can remove genuine library, parser, callback, plugin
  or adjacent-attacker paths. Unknown reachability is not unreachability.
- Repository-provided threat-model exclusions must not become authority to suppress
  a customer's security review. Use them as context requiring admission and evidence.
- Keep original/minimized inputs, exact build/symbols, harness and observations.
  Ephemeral workers are desirable; ephemeral evidence is not.

OpenAnt is an excellent design comparator, not a justified wholesale replacement or an
agent to install automatically. Its reported **376 candidates -> 190 after adversarial
verification -> 144 dynamically reproduced** is a funnel, not a full independently
adjudicated confusion matrix or transferable precision/recall guarantee. [E1-E4]

## 10. Literature implications from Glasswing

The completed Glasswing review is more useful as experimental-design guidance than as
a leaderboard.

| Evidence | Lesson for this system |
|---|---|
| Tencent industrial LLM4PFA: reported 0.93 precision with 0.75/0.79 recall on 433 selected warnings | Measure both queue improvement and retained true bugs. A precision-oriented verifier can suppress real findings. |
| Original LLM4PFA on CodeQL null-pointer warnings: 0.42 precision, 0.91 recall | Do not transfer the best result across datasets, analyzers or bug classes. Relevant path context helps; it is not a universal 90% solution. |
| CodeQL embedded study: 258 candidates, 156 built after setup, 123 in FP analysis | Build/extraction attrition is part of the result. Repository LOC is not measured analysis coverage. |
| RepoAudit: custom navigation, memory and validation; reported 40 TP/11 FP in its main evaluation | Structure and bounded validation matter. Installing a stock agent with the same model does not reproduce the system. |
| Project-scale agent study: small sampled counts and Codex-assisted labeling | Separate detector performance from assessor performance; avoid the same model judging its own results as ground truth. |
| Snyk five-repeat JS study: 80/161 unmatched signatures appeared once; 22/161 in all five | Measure recurrence using root-cause identities. Stability is not truth, and unmatched does not automatically mean false. |
| LLMxCPG/ConfColl threshold and confidence evidence | Model confidence, vote fraction and tuned decision thresholds are not calibrated correctness probabilities. |

Use two distinct scorecards:

1. **Fixed-warning triage:** on the user's human-labeled warning set, measure known-TP
   retention, known-FP suppression, retained precision, abstention and cost.
2. **Open-world discovery:** independently adjudicate novel root causes; report unique
   TP yield, precision at a frozen alert budget, known-bug recall, unresolved outcomes
   and coverage. Unknown total vulnerabilities mean open-world recall is unknown.

Do not call FP/(TP+FP) "FPR"; that is false-discovery rate. Do not choose a confidence
threshold on the same data used to announce quality. Pre-register repeated-run sample
size or use a valid sequential method; repeatedly checking ordinary confidence intervals
until success does not preserve nominal coverage.

For fuzzing, the reviewed literature does not establish a transferable accuracy boost
for this specific pipeline. Evaluate it as a new stage with its own selection, harness
validity, reproduction, false-oracle and cost measurements. [E5-E10]

### Updated Glasswing measurement contract

The user-directed Glasswing revision adds a useful distinction to implement in the
quality/telemetry layer. These are **proposed metrics and UI behavior, not additional
empirical findings or a validated certification threshold**.

Let `A_r` be the deduplicated root-cause set emitted by run `r` at one fixed pipeline stage.

| Metric | Definition and use |
|---|---|
| Run-over-run Stability (RoR) | `J(A_(r-1), A_r) = intersection_size / union_size`; adjacent scheduled-run change. |
| Mean Pairwise Stability (MPS) | Mean Jaccard over valid unordered completed-run pairs; order-independent experiment summary. |
| Retention | `intersection_size / previous_set_size`; directional, not interchangeable with Jaccard. |
| Recurrence | Completed eligible runs containing one root cause divided by completed eligible runs, including completed-empty runs. |
| Change accounting | Retained, new-to-previous, dropped, first-seen and reappearing counts; new-to-previous need not mean newly discovered. |

Freeze `comparison_group_id` over source/scope, source-only or build-context condition,
configuration, guidance, model/agent/tool and decoding identities, normalizer version,
and pipeline stage. Detection candidates, post-verification findings and reproduced
findings need separate series. Assign `run_index` at launch, not completion.

The first run has no RoR value. Failed, partial or incomparable adjacent runs give
**N/A**; never skip a failed predecessor and compare with an earlier run instead.
One completed-empty and one nonempty set score zero; two completed-empty sets are
N/A and counted separately. A five-transition rolling display must show its valid
sample count. Out-of-order completion can require recomputing both affected adjacent
transitions.

Persist immutable run records, raw-to-root-cause membership, versioned adjudications,
per-run metrics and versioned aggregates with their included run IDs and label snapshot.
A root-cause merge requires an explicit aggregate rebuild. Label-only corrections
must not look like detector instability or improvement: recompute label-stratified
history under one declared label revision.

Recommended dashboard panels are the run ledger; distinct TP/FP/unresolved yield and
precision; separate RoR/MPS trends; root-cause recurrence heatmap; confidence bins with
counts; and coverage/cost. Show failed/empty states and a stable false finding rather
than interpolating gaps away. Pending-label bounds are **not confidence intervals**;
missing inferential policy means no certification.

For MPS uncertainty, resample whole runs and recompute the statistic, not individual
pairs that share runs. Adjacent transitions also share runs; their rolling values are
not independent observations. Any inferential RoR interval needs a predeclared
dependence-aware method and sufficient data. Repeated discovery of the same root cause
does not create independent evidence of correctness.

The companion Glasswing HTML mockup is synthetic and remains in the
Glasswing session (`ghapp://sessions/67c66298-7ac8-484d-ac62-1b542028d774`);
it is not a deployed appsec dashboard or an observed experiment.

## 11. Downstream fuzzing: integrate the APS work, do not duplicate it

### Current APS evidence and boundary

The source-informed model is
[`Gaming-Security/aps-lean@f56c574b542159886807f65b4eeb67cad62e0133`](https://github.com/Gaming-Security/aps-lean/tree/f56c574b542159886807f65b4eeb67cad62e0133).
It models selected token-protected DDNet 0.6 admission and known-sequence ONLINE
transport against
[`ddnet/ddnet@2e93b5e431bf651a6c989adcf2f0b067c678abd5`](https://github.com/ddnet/ddnet/tree/2e93b5e431bf651a6c989adcf2f0b067c678abd5).

The latest local design at `925510da2ac7cab302fab15b337754a6fa125d0d` is in
`docs/ddnet-fuzzing/{README,design,toolchain,workflow,agent-integration,artifacts}.md`.
I read those six documents. They are **design, not a working JSON exporter, C++ runner,
corpus or MCP API**, and the local design commit was not assumed remotely available.

Important reusable lessons:

- `Fin 1024` sequence labels; proof preservation assumes an outstanding arc **<512**.
- Inclusive backroom comparison is **<=512**, and ACK removal is a **prefix**, not a filter.
- Vital queue attempts consume sequence before allocation; failure need not roll it back.
- A bound on saved bytes/entries does not imply a bound on sequence distance.
- Reset/admission invariants do not prove callers preserve them forever.
- Allocation results/charges, clocks, Flush effects and caller failure policy are explicit
  correspondence obligations, not facts manufactured by the model.

The kernel-checked example with 29 saved 1023-byte payloads at supplied 1104-byte
charges, 511 allocation failures, ACK 29, a later saved sequence 541 and repeated ACK 29
is a **model counterexample to a stronger desired property**, not an observed DDNet exploit.
The actual allocator schedule, legitimate caller continuation and security impact remain
to be established.

### Recommended architecture

```text
accepted findings + unresolved testable hypotheses + accepted build/evidence context
    -> experiment planning and admission
    -> exact-build harness validation
    -> deterministic replay
    -> bounded coverage-guided/stateful fuzzing
    -> independent observation/oracle evaluation
    -> replay and reduction
    -> optional Lean differential projection / proof-obligation assessment
    -> re-adjudication and a new versioned publication snapshot
    -> patch regression on original and repaired builds
```

Do not restrict all experiments to already-confirmed findings. Include sufficiently
grounded unresolved hypotheses where a runtime observation can discharge a missing
predicate. Keep purely speculative or unsafe experiments out through admission.

Start with a **separate downstream campaign graph**, anchored to the accepted review.
This avoids making every ordinary review wait for a fuzz budget and preserves the current
compile-only contract. Later, an explicitly enabled bounded verification tier can gate
a new final report. Never mutate the old certified snapshot when new evidence arrives.

### Proposed jobs and contracts

These are proposed semantic stages; combine tiny stages as units until independent
scheduling/checkpointing is actually useful.

| Stage | Required inputs | Required outputs |
|---|---|---|
| `job_experiment_planning` | Finding/claim ID, required predicates, source/sink and path, attacker model, exact source/build variants, existing tests/PoC, coverage gaps, approved policies. | Bounded plan, oracle and harness specifications, selected engine/profile, seed/corpus basis, required assumptions, resource limits, eligibility or explicit refusal. |
| `job_fuzz_harness_validation` | Plan; accepted recipe/compile commands, generated source, libraries, symbols and sanitizer evidence; harness patch. | Harness/source/build hashes, link closure, instrumented-SUT proof, positive/negative controls, reset/determinism evidence, supported reachability/projection boundary. |
| `job_fuzz_campaign` | Admitted harness/build, exact initial corpus manifest, engine/config/version, plan approval and limits. | Durable campaign handle, progress, raw interesting inputs, coverage, observations, partial/terminal outcome, stop/cleanup receipt. |
| `job_reproducer_validation` | Original input, exact build, independent oracle, negative controls, optional reduction budget. | Same-input replay results, minimized derivative with parent hash, preserved predicate/preconditions, flaky/inconclusive results and source-symbolized evidence. |
| `job_formal_evidence` (optional) | Pinned Lean model/toolchain, explicit projection, actual observed environment choices, claimed theorem and hypotheses. | Projection validity, model execution comparison, hypothesis applicability, kernel-check receipt where performed, or unsupported/mismatch outcome. |
| Existing review/publication path | New admitted experiment evidence and original claims. | Fresh adjudication/versioned findings/report; runtime evidence never retroactively relabels an old artifact. |

A generated harness must exercise the **real implementation**, not reimplement the
suspected defect. Instrument the SUT objects, not only the harness. Compilation alone
does not establish sanitizer coverage or attacker reachability.

### First pilot: the existing DDNet design

Use the APS plan's real `CNetConnection` and static resend ring, real packing/Flush,
captured final sends and controlled time. Keep original queue IDs, saved-instance IDs,
emission IDs and logical ACK witnesses separate from 10-bit labels.

Start with deterministic native-allocation replay and a stop-on-failure caller policy.
Continue-after-failure and deny-only allocation injection are separate explicit modes,
not a hidden way to force the desired result. Use structured stateful actions rather
than random packets for this question.

Keep at least five independent outcomes:

| Outcome | Meaning |
|---|---|
| `assumption_escape` | Execution leaves a proof hypothesis; not a falsified theorem or automatically a bug. |
| `logical_candidate` | An older witnessed logical ACK removes a later saved send-instance. |
| `coverage_candidate` | A later eligible retransmission fails to retain/emit that instance, with ordering and Flush accounted for. |
| `sanitizer_failure` | Concrete instrumented failure in this exact profile. |
| `model_mismatch` | Supported projected native behavior differs from the executed Lean model; investigate source, projection, harness and model. |

Missing allocator charge, ambiguous epochs, unsupported lifecycle or absent emission
provenance is **inconclusive**, not a guessed failure. A component experiment does not
establish actual network/caller reachability. Fuzz both proof-respecting cases and
separately labeled assumption-boundary cases: restricting every input to `TraceAllowed`
would hide the most interesting caller-contract escape.

### Engines and tools

- First native/stateful pilot: matched Clang/LLVM/compiler-rt, ASan+UBSan,
  `llvm-symbolizer`, CMake/Ninja, deterministic runner and regression framework.
  Reuse accepted toolchain capability when available; do not assume the current
  native image contains a usable libFuzzer runtime merely because Clang is present.
- Use libFuzzer as an initial adapter if commissioned by the APS implementation;
  keep the runner engine-neutral. AFL++ is a later option, not a second mandatory engine.
- Later language adapters: Atheris for Python, Go's native fuzzing, cargo-fuzz for Rust,
  Jazzer for JVM, and schema/stateful API tests where crash-only oracles are inadequate.
- ASan/UBSan will not find every authorization, sequencing or business-logic defect.
  Those need independent state/response invariants, differential or metamorphic checks.
- Run Lean comparison only against the pinned model/toolchain; a Lean MCP is optional
  development convenience, not a proof authority or a necessary runtime dependency.

The APS native component pilot does not need Docker. An appsec-review campaign service
may use the existing isolated-execution architecture for untrusted targets. Preserve
the same harness contract while making containment requirements explicit per host.

### Persistence and restart

Persist plan/source/build/harness/oracle/engine/schema identities, exact input bytes,
corpus snapshot, random seed, environment mode, coverage and original/minimized parentage.
The seed alone cannot reproduce an evolving parallel campaign.

Checkpoint at campaign chunks and immutable corpus commits, not arbitrary process memory.
After a harness/oracle fix, create a new build/campaign identity and replay retained cases;
do not reuse prior classification as if the experiment were unchanged. After infrastructure
failure, resume only compatible chunks, retaining failure/partial evidence.

Use separate lifecycle and finding outcomes. A timeout may leave a valuable finding;
a completed campaign may find nothing without proving safety. Cancel only owned processes,
verify cleanup and reserve disk for terminal evidence.

## 12. Agents, MCPs and installation recommendations

**No new general-purpose security agent is justified as a prerequisite.** Existing
specialized roles already cover most needed viewpoints. Missing evidence producers
and actual tool commissioning are the bottlenecks.

| Capability | Recommendation |
|---|---|
| Existing appsec retrieval MCP | Keep and verify discovery/schema parity for intended external clients. Internal model cells remain application-mediated. |
| Existing operator MCP | Keep read-only. Extend it with bounded failure-manifest/test-selection/repair-plan views if needed; mutations stay separately authorized. |
| Threat-model/runtime-service skills | Add after their input/output contracts and producers exist. Skills teach interpretation, not scanning authority. |
| Fuzz runner skill | Add a small appsec runtime planning/interpretation skill and a separate repository-development workflow skill. Reuse APS's concepts, not its repository paths. |
| Fuzz MCP | Defer until repeated asynchronous status/cancel/artifact access warrants it; wrap one CLI/runner with plan hashes, idempotency, scoped approval and bounded reads. |
| Cloud inventory access | Prefer imported or read-only, scoped evidence collectors. Install a provider MCP only for an explicitly authorized environment and a concrete missing capability. |
| Code navigation extras | Existing CodeQL/AST/clangd/debug-symbol indexes are extensive. Commission missing API/framework models before adding another generic code-search agent. |
| OpenAnt | Use as a controlled comparator on approved targets, not an automatic second scanner or source-upload path. |

The repository declares substantial tooling already. This review checked declarations
and architecture, **not installed executable versions, model entitlements, container
readiness or connected MCP authentication**. Add one capability/preflight report that
distinguishes configured, installed, reachable, compatible, commissioned and permitted.
Missing tools should identify the affected coverage and approved installation path;
never auto-install tools while reviewing customer code.

## 13. Job-by-job input/output review

This matrix covers all 46 registered jobs. Inputs below are semantic requirements
inferred from declarations and inspected composition, **not a claim that every live
artifact was produced or read**. Per-job raw declarations are in `source-inventory.json`.
Output validation often lives on `Unit` or in producer/publication code: the empty
top-level `Job.output_validators` tuple is not, by itself, a missing-validation finding.

| Job (`job_` prefix omitted) | Inputs -> principal exports | Assessment/action |
|---|---|---|
| third_party_data_sync | Feed configuration/sources -> verified feed snapshots/indexes | Maintenance outside review; retain snapshot identity/freshness in consumers. |
| model_connectivity | Resolved enabled model profiles -> readiness receipt | Fresh gate is appropriate; readiness is not review quality. |
| image_pin_verification | Enabled images/configured pins -> verification receipt | Preserve fail-closed configured policy; distinguish actual deployed app identity. |
| target_acquisition | Approved system/component sources -> acquired-source manifest | Preserve per-component omissions/failure, not just composed directory existence. |
| review_intake | Target/config/acquisition/binary publications -> intake, preflight and binary bindings | Good source boundary; acquisition consumption is richer than its empty `CONSUMES`. |
| target_catalog | Intake/source snapshot -> source, components, declarations, documents, build units | Existing threat-model ingestion, not generation; add deployment descriptors to typed context. |
| build_environment_analysis | Catalog/environment declarations -> static environment receipt | Default-enabled; missing from input-source matrix. |
| source_history_analysis | Intake/catalog/Git and optional review metadata -> history signals/raw provenance | Priority context, not proof of defects; preserve shallow/missing-history gaps. |
| ci_configuration_analysis | Catalog/CI definitions -> CI observations/findings/tool evidence | Feed selected deployment/build facts into topology without treating declarations as execution. |
| target_analysis_plan | Catalog/history/environment and scheduled CI context -> scanner/build plan, feedback receipts | Explicit abstention/whole-bundle build topology are strengths; make required data inputs authoritative. |
| project_build | Accepted plan/profiles -> image/probe/dispatch receipts | Keep build-repair classification bounded; separate image from source-layout failures. |
| language_build | Accepted project/recipe/workspace -> actions/artifacts/build receipts | Central future harness input; extract stable accepted-build API. |
| build_iteration | Immutable controller request -> one selected build transaction | Internal, non-propagating; missing datasets/dispatch-class inventory handling. |
| tree_sitter_ast | Catalog/source/generated-build context -> syntax/node/coverage shards | Syntax is not semantic call resolution; preserve generated-source identity. |
| change_context_analysis | Catalog/history/AST -> change signals and provenance | No causal vulnerability claim from ownership or review metrics. |
| artifact_indexing | Catalog/language build -> artifact/member/relation catalog | Use to bind exact experiment binaries, libraries and symbols. |
| debug_symbol_indexing | Accepted artifacts/build -> normalized symbols/layout/coverage | Keep compiler/ABI/build-specific identity in consumers. |
| test_coverage | Catalog/build/artifact inputs -> imported coverage and gaps | Importer, not a test-execution job; require profile/source identity and distinguish fuzz coverage. |
| profile_data | Catalog/build/artifact inputs -> imported execution profiles | Profiles indicate observed workload, not all reachable behavior. |
| artifact_security_analysis | Accepted build artifacts -> scanner observations/raw receipts | Keep immutable native evidence separate from normalized summaries. |
| evidence_collection | Catalog/intake/analysis plan -> source/IaC/secrets/SBOM/static evidence | Broad useful base; scanner output is not confirmed finding. |
| cpp_compiled_analysis | Accepted native builds and graph-scheduled seeds -> AST/IR/binary/Infer/coverage | Declared consumption is narrower than effective inputs; avoid losing failed-unit denominator. |
| clang_static_analysis | Accepted C++ scopes -> Clang diagnostics and scope coverage | Use path evidence as experiment hints, not oracle truth. |
| svf_alias_analysis | Accepted C++ bitcode -> alias/cross-check/coverage | Disabled by default; enable only for measured target benefit and commissioned capability. |
| cpp_symbol_index | Accepted C++ scopes -> clangd symbols/coverage | Good navigation input; unresolved dispatch remains unknown. |
| cpg_analysis | Accepted C++ scopes -> Joern/coverage | Deprecated/disabled in shipped config; do not re-enable just to add tooling. |
| sanitizer_build | Accepted native recipe/workspace -> instrumented build/catalog | No execution and no current substantive downstream consumer; primary fuzz integration seam. |
| binary_evidence_indexing | Intake-frozen decompilation -> binary-function retrieval/coverage | Pseudo-C is reconstructed evidence, not original source or build fidelity. |
| post_build_security_assessment | Actual build/compiled/artifact properties -> hardening assessment | Keep requested flags -> observed actions -> actual binary chain. |
| dependency_intelligence | Catalog/build/artifact/static evidence -> component context, SPDX/provenance, advisories | Extend to deployed third-party services separately; dependency presence is not service exposure. |
| codeql_analysis | Plan/build/source/scanner/compiled context -> SARIF, DB/export and scope receipts | Rich context but broad scheduling barriers; profile critical path before splitting source/build lanes. |
| review_prioritization | Intake/catalog/AST/history/scanners -> ranked items/flow context | Ranking/cutoff is not coverage; report excluded items and sample for false negatives. |
| code_graph_index | CodeQL and cross-check producer shards -> normalized graph facts | Correct place for source-to-sink/path/guard context; align declared consumption with supported producers. |
| security_tagging | Accepted producer manifest/taxonomy -> qualified tag assignments | `CONSUMES` empty despite actual reads; tags route work, not prove controls. |
| owasp_control_assessment | Accepted source/build/scanner/tag/classification context + standards -> applicability/obligations/results | Existing upstream chain is meaningful; no generated deployed-state threat model; clean stale producer name. |
| review_data_indexing | Accepted handoffs/manifests/datasets/feed pins -> audit, links, precomputed facts, coverage matrix | Repair runtime artifact ownership/internal-job drift; producer-consumer matrix must reflect actual reads. |
| review_package_assembly | Accepted inventory/index -> frozen lead/hunt packages | Good explicit output checks; ensure new topology/threat/experiment context reaches relevant packages. |
| document_issue_analysis | Accepted document hunts/package manifest -> private candidate ledger | Always provisional/gapped; finish candidate-to-review route and unit-test mapping. |
| inference_security_review | Accepted scope/packages/config/guidance -> cells, claims, adjudications, scores, chains, PoC candidates | Strong evidence discipline; document ledger not consumed; dynamic proof not available yet. |
| poc_generation | Accepted review + exact language build -> benign test/control functions, compile checks | Compile-only and primarily native; not linked/executed reproduction. |
| remediation_planning | Confirmed findings/source/build context -> inert exact patches/regression specifications | Conservative scope good; future experiment evidence can strengthen regression design. |
| remediation_validation | Accepted plans/review/build -> applicability/static/compile/semantic results | Not runtime patch verification; needs original-vs-fixed replay downstream. |
| dossier_publication | Accepted review/PoC/remediation -> protected evidence dossiers | Include experiment assumptions, unresolved results and exact build once available. |
| final_publication_gate | Accepted review + enabled completion artifacts -> certified frozen classification | Preserve immutable boundary; explicitly account for any enabled downstream verification tier. |
| final_report_publication | Accepted final gate -> deterministic JSON/Markdown | Never discover late artifacts; issue new snapshot/report for new evidence. |
| openvex_export | Same accepted gate/review snapshot -> validated OpenVEX | Keep conservative statements; non-reproduction alone cannot justify not-affected. |

## 14. Prioritized implementation plan

| Phase | Scope | Exit evidence |
|---|---|---|
| **A. Make the current path coherent** | Fix inventory ownership, internal-job eligibility, input-matrix/`CONSUMES` drift and document unit mapping; classify all registered jobs. | Minimal real-runner contract fixture reaches package assembly with strict audit; undeclared files still fail. No target/model execution needed for this fixture. |
| **B. Prove recoverability** | Exercise real chosen deployment stop/repair/admission/resume; precise invalidation; add safe typed checkpoints where expensive work benefits; state native/successor limits. | Failure in A, focused regression, changed release, retained independent predecessor, fresh A attempt, correct downstream invalidation and cleanup receipts. |
| **C. Supply missing system context** | Static service/deployment topology, signature catalog, evidence-backed threat model; optional observation imports; complete document-candidate routing. | Seeded multi-service fixture with IaC/classification/build links; declared-vs-observed conflict stays explicit; relevant workers receive/cite the correct context. |
| **D. Deliver one faithful downstream experiment** | Integrate APS DDNet deterministic replay and exact artifact contract; independent oracles, native allocator, controls and source/build fidelity. | Honest candidate outcome, reproducible retained input, working negative controls, no live network, no invented allocation or reachability evidence. |
| **E. Add search and formal bridge** | Stateful coverage-guided engine, corpus/reduction/checkpointing, optional observed-trace Lean comparison; original/fixed patch replay. | Findings/minimized cases retain predicate and evidence class; interrupted work resumes compatibly; unsupported projections remain explicit. |
| **F. Evaluate and optimize** | Held-out triage/discovery scorecards, live worker competence, coverage/value metrics, role/round ablations; only then native hot-path prototype. | Measured yield/TP-retention/cost/coverage improvement, not just passing infrastructure checks or faster serialization. |

Do not parallelize all phases as independent implementations: B depends on A's contracts;
D depends on accepted build/experiment contracts and the APS harness; E depends on D's
fidelity/oracles. Some telemetry and static-catalog work can proceed independently once
shared schemas and ownership are agreed.

**Definition of done:** a flaw is connected to its source/build/environment assumptions,
an approved experiment can supply independent observations, failures are repairable
without silently discarding evidence, and final claims state exactly what is established
and what remains unknown.

## Source evidence

All `C` locators refer to the pinned local appsec-review SHA above, unless explicitly APS.

| ID | Source locators |
|---|---|
| C1 | `src/appsec_review/runtime/job.py:17-112`; `runtime/registry.py:49-177`; `runtime/runner.py:915-1005`; `orchestration/topology.py:50-260`. |
| C2 | `runtime/repair.py:114-156`; `runtime/runner.py:626-627,989-993`; `runtime/checkpoints.py:40-49`; `indexing/inventory.py:78-170,272-325,640-642`; `jobs/job_review_data_indexing/job.py:430-469`; `appsec-review.toml:43-44`. |
| C3 | `jobs/job_build_iteration/job.py:89-114`; `jobs/job_review_data_indexing/job.py:51-74,254-263,454-457`; `runtime/selection.py:27-38`; `appsec-review.toml:1214-1219`. |
| C4 | `indexing/input_matrix.py:21-132,155-199`; `jobs/job_security_tagging/datasets.py:13`; corresponding `job.py:105-140`; `jobs/job_review_data_indexing/datasets.py:15-25`; corresponding `job.py:489-504`; `owasp_workbench/evidence.py:20-32`; `runtime/dependencies.py:45-51`. |
| C5 | `jobs/job_document_issue_analysis/job.py:27-30,120-134`; `jobs/job_inference_security_review/datasets.py:15`; `tests/job-test-map.json` entry for `job_document_issue_analysis`; `development/test_selection.py:239-268`. |
| C6 | `runtime/resume.py:75-242`; `runtime/checkpoints.py:14-101`; `runtime/repair.py:159-223,279-420`; `docs/operations/recovery-repair.md`. |
| C7 | `orchestration/dagster/adapter.py:217-224`; `observability/telemetry.py:1716-1717,1839-1841`; `observability/otlp.py:12-58`; `observability/quality.py:37-132`; `review/competence.py:34-67`. |
| C8 | `storage/atomic.py:17-108`; `storage/shared.py:54-203`; `jobs/bound_artifacts.py:19-56`; `jobs/job_target_analysis_plan/job.py:75-95`. |
| C9 | `jobs/job_language_build/dotnet.py:217-237`; `jobs/job_language_build/rust.py:170-191`; `jobs/job_sanitizer_build/job.py:24-35`; `pyproject.toml` mypy/public-contract configuration. |
| C10 | `inference/execution.py:1-280`; `mcp/capability.py:24-140`; `review/capability.py:35-91`; `runtime/job.py:62-79`. |
| C11 | `docs/architecture/worker-prompt-contracts.md`; `guidance/cards.py:69-203`; `pipeline/guidance/registry.json`; `pipeline/prompt-fragments/governing-rules.md`; deployment/network/native persona files; `pipeline/skills/predicate-verification/SKILL.md`. |
| C12 | `appsec-review.toml:2732-2757,2815-2915`; `profiles/prod.toml:51-106`; `review/competence.py:34-67`. |
| C13 | `indexing/input_matrix.py:112-119`; `indexing/products.py:1329-1393`; `jobs/job_target_catalog/datasets.py:27-30`; `jobs/job_poc_generation/job.py:1-11`; `jobs/job_sanitizer_build/job.py:1-11`. |
| C14 | `review/result_cache.py:1-104,140-263`; `config/inference_review.py:343-375`. |

### External primary sources and related project

- **E1:** [OpenAnt paper](https://arxiv.org/html/2606.19149).
- **E2:** [OpenAnt attacker/threat-model rendering](https://github.com/knostic/OpenAnt/blob/9143061f93c546493dea96394b6e6d4c5f29311d/libs/openant-core/prompts/threat_model_render.py)
  and [verification prompts](https://github.com/knostic/OpenAnt/blob/9143061f93c546493dea96394b6e6d4c5f29311d/libs/openant-core/prompts/verification_prompts.py).
- **E3:** [OpenAnt dynamic generator](https://github.com/knostic/OpenAnt/blob/9143061f93c546493dea96394b6e6d4c5f29311d/libs/openant-core/utilities/dynamic_tester/test_generator.py)
  and [collector](https://github.com/knostic/OpenAnt/blob/9143061f93c546493dea96394b6e6d4c5f29311d/libs/openant-core/utilities/dynamic_tester/result_collector.py).
- **E4:** [OpenAnt dynamic-testing reference](https://github.com/knostic/OpenAnt/blob/9143061f93c546493dea96394b6e6d4c5f29311d/libs/openant-core/utilities/dynamic_tester/DYNAMIC_TESTER_REFERENCE.md).
- **E5:** [Tencent industrial LLM4PFA](https://arxiv.org/html/2601.18844v1), Table 2;
  [original LLM4PFA](https://arxiv.org/html/2506.10322v1), Tables 1-5.
- **E6:** [CodeQL embedded experience report](https://arxiv.org/html/2310.00205), section 5.2.
- **E7:** [RepoAudit, ICML 2025](https://proceedings.mlr.press/v267/guo25n.html).
- **E8:** [Project-scale vulnerability detection](https://arxiv.org/html/2601.19239v2), Table VII and section V-B.
- **E9:** [Snyk repeatability preprint](https://arxiv.org/html/2606.15762v1).
- **E10:** [LLMxCPG, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/lekssays);
  [ConfColl, EMNLP 2025](https://aclanthology.org/2025.emnlp-main.1071/).
- **APS:** [Admission/source map](https://github.com/Gaming-Security/aps-lean/blob/f56c574b542159886807f65b4eeb67cad62e0133/APS/TeeWorlds/DDNet/DESIGN.md);
  [transport contracts](https://github.com/Gaming-Security/aps-lean/blob/f56c574b542159886807f65b4eeb67cad62e0133/APS/TeeWorlds/DDNet/TRANSPORT.md);
  [executable examples](https://github.com/Gaming-Security/aps-lean/blob/f56c574b542159886807f65b4eeb67cad62e0133/APS/TeeWorlds/DDNet/TransportExamples.lean).
  Later fuzzing design reviewed locally at `925510da2ac7cab302fab15b337754a6fa125d0d`;
  publication/implementation status must be rechecked before implementation.
