# Inference security review: slice 1 implementation record

Record of the 2026-10-12 work on branch `ccr-67a0aeda-uyt6x6`. It took the
[inference security review design](../architecture/inference-security-review.md) from "approved
for planning" to a registered, tested slice 1 of `job_inference_security_review`. This is a
historical and decision record. The design and the
[operations page](../operations/inference-security-review.md) remain the current authority. The
reusable procedure is in the development skill [`.claude/skills/parallel-implementation`](../../.claude/skills/parallel-implementation/SKILL.md).

## 1. Readiness review

The design's authority model, invariants, lifecycle and safety posture were sound. Eight contracts
were missing or contradicted the runtime, and are now settled as design decisions R1–R8:

| Gap found | Decision |
|---|---|
| Design assumed Dagster dynamic fan-out and a round cycle; `ExecutionPlan` is a static DAG | R1: each fan-out stage is one visible unit running an in-unit cell executor; rounds use an in-application controller |
| Every model transport runs with no tools, so workers could not query retrieval | R2: application-mediated retrieval loop with typed `retrieve`/`final` turns and in-process `RetrievalCore` |
| "Direct evidence" was undefined | R3: evidence relations plus an admissibility table by entity kind |
| No proof-obligation vocabulary | R4: six closed predicates |
| No adjudication algorithm | R5: ordered decision table |
| "Independent" was vague | R6: testable independence criteria |
| Claim identity unstable | R7: normalization of entities, CWE and preconditions |
| Ledger, schemas, inputs, configuration and scorer unspecified | R8 |

Consistency fixes were also made: the package schema link, persona ids, and the TOML step names.

## 2. Product decisions made with the user

- **Two intake lanes, fully parallel, one shared back end.**
  - Lane A reviews reported critical, high and unknown leads from every finding family.
  - Lane B is open discovery over ranked review units.
- **Review team.** 3 red, 2 blue and 1 blind verifier is the unit of capacity. `review_teams`
  defaults to 5, and a local capacity overlay sets it to 1.
- **Budget split.** Even split between lanes; unused share flows to the other lane.
- **Failure handling.** Every ordinary failure, up to a whole lane, is a recorded gap and the
  result publishes `DEGRADED`. Only framework-integrity failures block publication.
- **Personas.** 14 personas partition the security tag taxonomy, and their coverage text is
  generated from the taxonomy. Stack profiles such as `cpp_rpc_service` are a separate,
  knowledge-only dimension. Stacks are never roles.
- **Duplicates.** Claim ids are identity-only. A second proposal of the same claim merges into it
  and is counted as a duplicate proposal. The `duplicate` state is reserved for distinct ids judged
  equivalent.
- **Default model.** The current Haiku model, `claude-haiku-5-5`, until a real review run. Upgrade
  steps are in the operations page.

## 3. Work partition

The shared contract (`review/models.py` for closed enums and core records, and `review/identity.py`
for canonical ids) was committed first, as `9828c4b`. Seven agents then worked in parallel. Each
had its own git worktree and exclusive file ownership, and wrote its own unit tests. An eighth agent
integrated their work.

| Chunk | Delivered | Merge |
|---|---|---|
| C1 | Hash-chained ledger, order-independent merge, projection, exact accounting, `review_incomplete`, 14 schemas under `docs/schemas/inference-security-review/` | `ae3a48a` |
| C2 | Obligations and preconditions, evidence admissibility and re-resolution, claim normalization, R5 adjudication, R6 independence, scoring interface, `application_risk_matrix/1` | `291ba74` |
| C3a | Shared guidance composer (the OWASP composer now delegates to it), fragment validator, taxonomy coverage generation, persona/stack/hunt-panel routing, partition check, role files, task prompts | `c73f721` |
| C3b | 14 personas and 16 stack profiles, with a partition test | `8e7ac85` |
| C4 | Typed settings, capacity overlay, cross-process review-team semaphore, fair-share scheduler, job budget, job-aware pools | `c06809c` |
| C5 | `ReviewModelRequest`, `CellCapability`, bounded retrieval cell executor, retries, receipts, `cell/v1` fingerprints, reuse | `ddfcea1` |
| C6 | Accepted scope, lead families, lane A admission, lane B unit ranking and cutoff, package schema /2, membership audits, fixture accepted index builder | `ba2cc79` |
| C7 | Job wiring (12 units), team handler, triage, merge, adjudication, scoring, completeness, publication, registry, Dagster acceptance | `7fbbb71` |

At every merge I verified that:
- the branch descends from the contract commit;
- the diff stays inside the chunk's owned files, or any exception is reviewed and justified;
- the combined test set passes before the push.

## 4. Reconciliations at merge time

- **Worktree base.** Agent worktrees were created on an old `main`. Each agent hard-reset its clean
  worktree onto the working branch before starting. Future briefs state this step explicitly.
- **Out-of-scope change (C4).** A one-line change to `runtime/runner.py` was reviewed and accepted:
  it lets the configuration manifest record each layer with its own hash.
- **Pending job.** The job was held in `PENDING_JOBS` until C7 registered it. This kept the
  configured-jobs-equal-registered-jobs checks passing.
- **Persona text versus the validator.** The validator rejected six legitimate domain terms (OAuth
  `state`, RBAC `role`, "certificate authority", gRPC's concurrent-streams setting, AI "tool calls").
  The content was reworded and the validator stayed strict (`3349f82`).
- **Hunt membership.** The design required every High lead to appear on a hunt menu, which cannot
  hold once lane B has a cutoff. The design now matches the contract: leads in units below the
  cutoff are covered by a `below_hunt_cutoff` gap (`46ed8c4`).
- **Integration (C7):**
  - Lane budgets are allocated deterministically from the manifest's queue lengths instead of by
    live cross-lane signalling.
  - Cell fingerprints use a reuse basis of the package content plus the shards that hold its
    entities, so one changed shard reruns only dependent cells. Receipts omit durations so they are
    byte-stable.
  - Retrieval integrity failures raise a typed exception instead of being detected by message text.
  - The gap constructor moved into the shared contract.

## 5. Verification

The test environment uses system `python3` with pytest, Dagster 1.13.21, hypothesis and jsonschema
installed. After C7 the combined regression set was 707 passed, 1 skipped, 2 failed. Both failures
are in `tests/orchestration/dagster/test_definitions.py` and already failed before this work: one
needs the `tool-tree-sitter` image, and the other counts the wave-1 topology as 6, not 7. Other
environment-dependent tests also fail on the base commit:
- `tests/test_applicability.py`, which needs `targets/appsec-multi-vuln`;
- live-toolchain and target tests in the CI-configuration, cppcheck/PMD, static-adapter and
  live-build suites.

The Dagster acceptance test (`tests/orchestration/dagster/test_inference_security_review.py`) uses
a scripted, deterministic fake model. It proves the slice 1 definition of done:
- both lanes run in parallel;
- identical canonical outputs at 1 and at 5 teams;
- every claim state and gap type occurs, with exact accounting;
- a whole lane failing publishes `DEGRADED` and `review_incomplete`;
- full cell reuse on re-execution, and shard-scoped invalidation;
- tampering blocks publication;
- the verifier is blind to red and blue narratives;
- no capability reaches evaluator, target-guidance or arbitrary paths.

No live model has been run.

## 6. Follow-up in progress and outstanding

- **In progress.** The CWE check moves to the run's pinned MITRE catalog; until then it uses
  scanner-rule CWEs plus the crosswalk. Also in progress: an NVD lookup index, new KEV and EPSS sync
  steps, advisory enrichment of `dependency_advisories`, KEV-based lane A admission, KEV/EPSS lane B
  ranking signals, package schema /3 advisory context, and scorer reference inputs.
- **Needs user review.** The 26-entry CWE-to-impact table, the lane B ranking weights, and the
  default caps.
- **Not built.**
  - Round 1 and variant hunts.
  - The `entry_down` and `control_gap` strategies' data sources.
  - The PoC lane, attack chains, and the CVSS v4, CVSS v3.1 and SSVC scorers.
  - The planned dataflow, call-graph, guard and entry-point queries.
  - A closed `security_predicate` vocabulary (design open question 10).
  - Live-model acceptance.

## 7. Skill separation (follow-up)

The procedure from this work was first committed under the old top-level `skills/` directory. Three
jobs loaded runtime guidance from that directory, and the Dagster image copied it, so a development
procedure could have reached job runs. Skills are now split:
- development skills live in `.claude/skills/` (`audience: repository-agent`);
- runtime skills live in `pipeline/skills/` (`audience: runtime-worker`). They are registered with
  their allowed jobs in `pipeline/guidance/registry.json` and loaded only through
  `guidance.skills.load_runtime_skill`.

`tests/test_skill_separation.py` enforces:
- there is no top-level `skills/` directory;
- runtime skills match the registry and carry the runtime audience;
- development skills are never registered and carry the development audience;
- `pipeline/` carries no development material;
- application code names no skill location outside the loader;
- the runtime image copies no development skills, and `.dockerignore` excludes `.claude`;
- the loader rejects development, unregistered, unauthorized, wrong-audience and symlinked skills.

Codex and Gemini CLI do not scan `.claude/skills/`; they, Copilot and Cursor read
`.agents/skills/`. That location holds only a `repository-development-skills` pointer to the
canonical `.claude/skills/`, so nothing there needs refreshing. The test also requires
`.github/skills`, `.gemini/skills`, `.codex/skills` and `.cursor/skills` to stay absent. `audience`
sits under the standard Agent Skills `metadata` map so those tools accept the files.

Adding, then moving, the `audience` line changed the three runtime skills' bytes. Their guidance hashes therefore
changed once, which invalidates cached model calls for those three jobs.

## 8. Reference-feed enrichment (follow-up)

One agent implemented pinned reference-feed enrichment (merge `a3db635`).

**Data flow:**
- **MITRE.** Claim CWEs validate against the run's pinned MITRE CWE catalog. An unpinned,
  mismatched or stale catalog falls back to rule and crosswalk CWEs, with a recorded
  `reference:mitre_cwe` gap.
- **NVD.** `nvd_sync` publishes a hash-pinned `index/nvd.sqlite`.
- **KEV and EPSS.** New `kev_sync` and `epss_sync` steps publish `index/kev.sqlite` and
  `index/epss.sqlite`, and feed pinning enforces a freshness bound for each feed.
- **Product.** `dependency_advisories/2` joins NVD, KEV and EPSS by CVE id, recording gaps for each
  join.
- **Packages.** Package schema /3 carries `advisory_context`, `advisory_summary` and `weaknesses`.
- **Lane A.** Admission takes NVD's CVSS band when the scanner gave none, and admits KEV-listed
  advisories. This is configured by `lanes.lead_admission_kev`, which defaults to true.
- **Lane B.** Ranking gains KEV and EPSS signals.
- **Scorer.** It receives `reference_cvss`, `kev_listed` and `epss` as labelled reference inputs.
- **Evidence status.** Advisory records are INDIRECT evidence for every predicate.

**Fixed at merge:**
- **Input-source matrix.** The docs gained KEV and EPSS rows without matching `INPUT_SOURCES`
  entries in code; the entries were added.
- **"Flaky" package-schema test.** It was deterministic and order-dependent. It picked the first
  finding package by hash, which after schema /3 had an empty `context` list. It now picks by
  content.

**Not exercised live.** The feed URLs and formats are configured but have never been fetched. This
covers the EPSS host and comment-line format, and the KEV field names. All feed tests use offline
fixtures through the real normalize, index and publish code.

**Open items:**
- A stale KEV feed still admits to lane A, with a gap.
- Only NVD `vulnStatus` is captured; CVE "disputed" tags are not.
- Reference scorer inputs come only from lane A packages.
- The failing wave-1 Dagster tests write run directories into the repository `runs/` directory.
  This was already the case before this work and should be fixed separately.
