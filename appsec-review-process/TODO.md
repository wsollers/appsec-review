# AppSec Review Process TODO

## Step 4 plan: run-owned evidence collection, proven on the `hello-autotools` fixture (2026-09-21)

This is the first thing to do. It is the executable plan for taking the engagement flow
(`docs/processes/engagement-start.md`) through step 4 -- deterministic evidence collection as
run-owned Dagster jobs -- and proving it end to end on a tiny fixture target instead of a real
repository, so every job can be exercised in minutes. The phases below are ordered by dependency;
each names the batch ids it closes so the batch table further down stays the status authority.

### Decisions this plan is built on (record as ADR-0011 in phase 2)

- **Dagster stays.** It walks the process, holds state, retries and routes errors. It never
  references, pulls, builds or runs an image.
- **Python jobs do the work, on the host.** The code location runs as a host gRPC server
  (`dagster api grpc`); ops execute as host processes with the host's Docker. The compose stack
  keeps only postgres, webserver and daemon. Nothing mounts the Docker socket into a container.
- **B13 is the only code that composes `docker run`.** Every container a job starts goes through
  the pinned-container adapter: image resolved from `registry/container-images/` to a digest, argv
  array, boundary flags, one writable scratch mount, files in, files out, streams as diagnostics.
- **Build environments are provisioned before the engagement, not by it.** A supplied, tracked
  `buildenv.lock` (image digest, Dockerfile hash, configure argv) is produced by an agent/human loop
  and validated on read; `build_execution` replays it.
- **Persona-dependent discovery nodes used the supplied pattern until D01 landed.** A validated,
  hand-supplied record stood in for `02-dev-project-discovery`, `02-devops-project-discovery` and
  `02-sre-operations-topology` so the build chain was not blocked on pool dispatch. **Correction,
  William 2026-09-24: this was right for getting the gate/schema/chaining plumbing built (SAT
  stages 6-9), but the SAT does not get to call itself done that way. A gate that only checks "does
  the supplied file validate" while a human hand-writes the file it is checking is a test of the
  JSON schema, not of the system.** D01 (Phase 5b, below) closed this for `02-repository-partition-
  discovery` the same day with a clean live `--dispatch` SAT PASS against a real `claude` CLI call
  -- see Phase 5b for the full bug-fix sequence. D02-D04 (dev/devops/sre project discovery) still
  use the supplied pattern; they follow the identical D01 shape once their task prompts are
  authored (Phase 5b's closing note). SAT stages 7-9 remain to be re-proven against automatic
  dispatch once D02-D04 land, the same way stage 6 (partition discovery) was just re-proven here.
- **The fixture is its own repository, cloned in like any real target.** Step 1 of the
  engagement flow is: clone the system under test into `targets/<name>/` (git-ignored here).
  The fixture follows that same rule rather than being a special case -- it's tracked at
  `github.com/wsollers/hello-autotools`, not committed into this repo's tree, and lands at
  `fixtures/targets/hello-autotools/` by cloning it there, the same command a real engagement
  would run.
- **Multi-ecosystem provisioning is out of scope for the hello-autotools chain.** Ecosystem
  detection (Java, Go, Node/TypeScript, VC++ `.sln`/`.vcxproj`, Rust, clang, plus license-gated
  engines) stays a declared capability of the buildenv catalog, but hello-autotools proves only
  the single C++/autotools case end to end. A second, purpose-built polyglot fixture proves
  multi-ecosystem detection and per-partition provisioning, so neither slows down nor risks
  phase 1-11's ten-minute bar.
- **Every catalog ecosystem declares a provisioning mode.** `auto` (the LLM-driven
  discover/hydrate/infer/build loop may run unattended, bounded by attempt count) or `supplied`
  (a human pre-provisions and registers the image; the loop never attempts it). Unity and Unreal
  are `supplied` unconditionally -- licensed Editor installs and activation are not something the
  loop proposes or installs; detection still has to recognize them so it routes straight to the
  human-supplied path instead of burning retry attempts.
- **Working-tree cleanup between build attempts is pluggable and fails closed.** `automatic` uses
  the target's own VCS-native reset (`git clean -xfd && git checkout .`, `p4 sync -f`/`p4 revert`,
  `make clean`, ...), detected the same deterministic way build tooling is. `manual` deletes and
  re-fetches from an explicitly recorded `target` (git remote+ref, Perforce depot path+client
  spec, or a supplied-archive location) captured at intake; if `manual` is selected and no
  `target` is recorded, the loop refuses and fails rather than deleting anything.

### Done when

`launch_job.py --job full_review` on the fixture reaches an accepted `02-evidence-assembly` with
every `02-*` node either accepted or `SKIPPED` under a declared `allowed_skip_reasons` value, zero
`WORKER_NOT_IMPLEMENTED`, all evidence under `runs/<run_id>/data/`, `validate_design_parity.py`
PASS with the readiness view regenerated, and the whole chain under ten minutes on the fixture.

### Phase 1 -- fixture target (fast lane; no batch) -- DONE (2026-09-21)

- Delivered as its own repository, `github.com/wsollers/hello-autotools`, not committed into
  this repo's tree -- see the updated decision above. It lands at `fixtures/targets/hello-autotools/`
  the same way any real target would: `git clone https://github.com/wsollers/hello-autotools.git
  fixtures/targets/hello-autotools`.
- Contains `configure.ac`, `Makefile.am`, `src/`, `tests/run.sh` wired to `make check`,
  `README.md`/`docs/` stating it is a fixture, `.gitignore` for autotools output. Builds with
  `autoreconf -fi && ./configure && make && make check` on a stock toolchain. No IaC, containers,
  mobile code, or lockfiles, so those scanners exercise their zero-input skip paths.
- Four seeded, documented defects, not one -- CWE-121 stack buffer overflow (`strcpy`,
  `src/greet.cpp`), CWE-134 format string (`src/logger.cpp`), CWE-78 command injection
  (`src/runner.cpp`, only reachable with `--report`), and CWE-787/CWE-120 out-of-bounds write
  (`src/store.h`, only reachable with `--store`). All four verified to actually trigger.
  `docs/VULNERABILITIES.md` in that repo names each one with CWE, root cause, and exact trigger
  command. Source/native SAST should expect 3 unconditional hits (VULN-01, VULN-02, VULN-04)
  plus VULN-03 as a reachability-analysis case gated behind `--report`.
- VULN-04 specifically is a control, not just a fourth data point: it's the same defect class
  as VULN-01 (unbounded copy into a fixed buffer) but reached only through a macro expansion
  (`STORE_INTO`) into a C++ template instantiation (`copy_into_fixed<16>`), rather than a plain
  unwrapped function call. Macro/template handling is a known blind spot for source-based static
  analysis, so a tool finding VULN-01 but missing VULN-04 tells us something specific and
  actionable about that tool's expansion/instantiation fidelity -- worth checking per-tool once
  D09/E03 (phase 7/8) are live, not just recording pass/fail on the hit count.
- Also vendors one real third-party dependency -- cJSON 1.7.18 (MIT), linked as its own
  convenience archive (`libcjson.a`) so the build produces a genuine compile/archive/link chain,
  and exercised via a `--json` flag. Chosen deliberately at a version within a real, currently
  open CVE's affected range (CVE-2025-57052) so the vendored copy is already a valid target for
  SCA/dependency-vulnerability matching (`02-sca-vulnerability-match`, phase 7) once that scanner
  is live -- this goes beyond the original "no third-party code" scope on purpose, to give that
  node something to actually find later instead of only exercising its zero-input skip path.
  See `docs/DEPENDENCIES.md` and `vendor/cJSON-1.7.18/VENDORED.md` in that repo.
- Done when: the four commands succeed on Linux/WSL2 and the tree is committed -- DONE: verified
  clean-checkout `autoreconf -fi && ./configure && make && make check` passes, `--json` and
  `--report` paths hand-verified, pushed to https://github.com/wsollers/hello-autotools.

### Phase 2 -- ADR-0011 and the host code location (full protocol: `orchestrator/dagster/`)

- `docs/decisions/ADR-0011-orchestration-boundary.md`: the decisions above, the alternatives
  rejected (socket in the code-server, socket proxy, a custom host executor, switching engines) and
  why, with the engine criterion list (fork/join, pools, human gates, loops, external waits, UI).
- `orchestrator/dagster/workspace.yaml`: `grpc_server` -> `host.docker.internal:4000`;
  `compose.yaml`: `extra_hosts: ["host.docker.internal:host-gateway"]` on webserver and daemon,
  remove the `code-server` service and the `/runs`, `/opt/process`, `/opt/schemas`, `/targets/*`
  mounts it existed for (webserver/daemon need only postgres and `dagster.yaml`).
- `orchestrator/dagster/code-location.sh` (+ `.ps1` twin for a Windows host that runs it under
  WSL): starts `dagster api grpc -h 0.0.0.0 -p 4000 -f appsec-review-process/../orchestrator/dagster/definitions.py`
  with `APPSEC_RUNS_ROOT=<repo>/appsec-review-process/runs`, `DAGSTER_HOME` pointing at a host
  copy of `dagster.yaml`, the repo venv, and a health check; a systemd user unit example.
- Runs become host-owned: `run_process.py --start` and `stage_artifacts.py` run on the host and
  `--target` is a host path (the fixture: `fixtures/targets/hello-autotools`). Delete the
  "create inside the code-server / Linux-owned" rule from `docs/dagster/dagster-launching.md`,
  `docs/dagster/operations.md`, `orchestrator/dagster/README.md`, `00-intake-recovery/config.md`;
  keep the execution-platform check (host platform recorded in the manifest).
- Update `setup.py`, `qualify_dagster.py`, `tests/test_dagster.py`, `tests/test_phase1.py`
  fixtures that assume `/runs` and `/opt/process`.
- Done when: smoke job, `phase1_intake` and `engagement_workflow` pass on the fixture from the
  host code location; a deliberately failed op is re-executed from failure in the UI and skips
  the successful ops; `qualify_dagster.py` passes. Closes the "B13 build execution" open.

### Phase 3 -- B13 into service (B13 follow-up + new batch B16 "container image registry")

- Decide the open B13 question: `verify_container_result` / `load_verified_result` /
  `to_worker_envelope` **require** an externally held `expected_result_sha256`. Recommendation:
  require it; the hash is returned by `run_container` and kept in the attempt's `command.json`
  outside the scratch mount. Record in `docs/adapters/pinned-container-adapter.md`.
- B16: `registry/container-images/<image_id>.json` for every image a step-4 worker uses
  (`audit-static`, `audit-buildenv-cpp`, `audit-native`, `audit-iac`, `audit-container`,
  `scancode-toolkit`, `audit-binary-analysis`), generated from `images/.build-state/<id>/latest.json`
  by a new `images/registry_records.py` (digest, Dockerfile hash, build attempt id); a test ties
  each record's digest to the local image (`docker image inspect`) and fails on drift. Local builds
  get `digest_kind: "image-id"` until a registry push exists.
- Done when: a Dagster op on the host runs `fixture-harmless` through B13 and publishes a verified
  envelope; every step-4 image has a registry record; `test_container_execution.py` live tests pass
  against the host Docker.

### Phase 4 -- build-environment provisioning (supplied) and the C++ buildenv

> **Superseded 2026-09-24** by build resolution ([docs/processes/build-resolution.md](../docs/processes/build-resolution.md),
> ADR-0012): a deterministic build index, an LLM build plan, a bounded image-build + trial loop
> (`build_resolution_attempts`, default 3) and a host-local `image_build_<id>` catalog with reuse
> (`build_image_reuse`). The lock shape and the validate-on-read rule below carry over; the
> hand-supplied lock and the `provision-buildenv.md` skill do not. The build fields of the Phase 5
> developer-discovery record become an answer key for the SAT, not an input.

- `images/audit-buildenv-cpp`: add `autoconf automake libtool pkg-config make bear`; catalog
  markers add `configure.ac`, `Makefile.am`, `configure`. Rebuild, record the B16 entry.
- `schemas/buildenv-lock.schema.json` and `registry/buildenv-locks/<project>.json`: image id +
  digest, Dockerfile sha256, ordered argv arrays for configure / build / test, `compile_commands`
  producer (`bear -- make`), attempts log summary, provisioning authority and date.
- Validate-on-read in `build_execution.py` (and intake's native plan): lock present, digest matches
  a registry record, Dockerfile hash matches; otherwise `BLOCKED(BUILDENV_LOCK_MISSING)`.
- `skills/agents/claude/provision-buildenv.md` (+ Codex wrapper): the bounded loop -- read
  `build-discovery.md`, propose or amend a Dockerfile/lock, `docker build`, run configure+build in
  the B13 boundary, on failure revise, at most N attempts then a human gate, on success write the
  lock. First real use of `skills/agents/`.
- `schemas/buildenv-lock.schema.json` and the catalog also carry: a `provisioning` field
  (`auto`/`supplied`) per ecosystem entry, and a `cleanup` field (`automatic`/`manual`) with
  `manual` requiring a `target` (VCS remote/ref, Perforce depot+client, or supplied-archive path)
  -- refuse and fail, never delete, if `manual` is chosen with no `target` recorded. Unity/Unreal
  entries are `provisioning: supplied` from the start.
- Done when: `registry/buildenv-locks/hello-autotools.json` exists and `build_execution` replays
  it to a non-empty `compile_commands.json` under the run.

### Phase 5 -- discovery chain via supplied records (B10; D02 deferred)

- Author the fixture's supplied `02-repository-partition-discovery` and `02-dev-project-discovery`
  records (one component, one native family, autotools build route), validated on read through
  the existing supplied-envelope path (B10). **2026-09-24 (William): `02-devops-project-discovery`
  and `02-sre-operations-topology` are not skipped -- the fixture has a Dockerfile, so intake marks
  both required. Both are real gated records, same shape as partition and dev discovery**
  (`discovery_gate.py`, SAT stages 8-9): devops reads the accepted partition map (same
  `project-discovery` contract, devops-persona partitions -- the Dockerfile as build/release route,
  not a second native build); SRE chains after the accepted devops record (`operations-topology`
  contract, new schema). Fixture records: `fixtures/supplied/hello-autotools/
  02-devops-project-discovery.json` and `02-sre-operations-topology.json` -- both done 2026-09-24;
  all four discovery gates (SAT stages 6-9) built and confirmed live on the host (SAT
  `20260924T161102Z` through stage 8; stage 9 built on the same SAT record, needing no further
  `discovery_gate.py` edit).
- Done when: all four discovery nodes are accepted on the fixture and `02-build-configure`'s
  dependency is satisfied without persona dispatch. Superseded by the correction above: accepted
  on the fixture via a supplied record is not the finish line for the discovery chain; automatic
  dispatch (Phase 5b) is.

### Phase 5b -- D01: automatic persona dispatch for repository-partition-discovery (unpooled) -- DONE

**Started 2026-09-24 (William's correction); closed 2026-09-24 with a clean live SAT PASS (see item
8's final bullet below).** The goal: `02-repository-partition-discovery`
actually reads the target and produces its own discovery record, dispatched to a real model, with
the SAT proving that live -- not copying in a hand-authored fixture file. This is D01 from the
batch table below, built in its simplest, unpooled form (see scope note).

**Scope decision, stated explicitly, not hidden:** the batch table marks D01
`BLOCKED(B14,C01,C02,C03)`. B14 (persona invocation adapter) is done. C01/C02 (pool specification,
wait-all rendezvous) are implemented-not-qualified; C03 (deterministic typed merges) does not exist.
All three are concurrent multi-tool, multi-partition fan-out machinery for the *full* review, where
many personas run in parallel and their results merge. A single fixture with one partition is one
persona call -- it needs none of that. D01 is built here **unpooled**: one job template, one
invocation, one result, the same "single-agent, unpooled" shape `review_cli.py` already uses for
itself. Pooled D01 (fan-out across many partitions on a real target) stays tracked separately and
is not required for the SAT to prove the discovery chain for real. If a future real engagement needs
concurrent partition dispatch, that revisits C01-C03; it does not block this.

**What already exists (no new registry records needed for D01):**

- Job template `registry/job-templates/02-repository-partition-discovery.json` -- composition
  already resolved: persona `developer-engineer`, role `repository-partition-mapper`, domain
  `repository-partitioning`, tooling profile `static-repo-project-inspector`, output contract
  `repository-partition-map`.
- All five composed registry records exist and validate (`registry/personas/developer-engineer.json`,
  `registry/roles/repository-partition-mapper.json`, `registry/domains/repository-partitioning.json`,
  `registry/tooling-profiles/static-repo-project-inspector.json`,
  `registry/output-contracts/repository-partition-map.json`).
- The task prompt already exists and needs no new authoring for D01:
  `appsec-review-process/02-evidence-pregather/repository-partition-discovery.md`.
- The buildenv catalog the `buildenv_catalog` prompt section renders already exists:
  `appsec-review-process/tooling/buildenv-catalog.json`.
- Model: confirmed with William 2026-09-24. Model routing was redesigned in the same conversation
  (not scoped to D01 alone -- a full migration, done): jobs declare the model/effort they need in
  their OWN job-template record instead of a lane-keyed table in `model-config.json`.
  `model-config.json`'s process-wide `default` changed from `claude-sonnet-5`/`medium` to
  `haiku`/`medium`; `lane_overrides` was renamed `unbuilt_job_defaults` and now only bridges
  job_template_ids that appear in the job graph but have no registry job-template file yet (currently
  `09-independent-verification`, `10-synthesis-report`, `02-build-plan`) -- each entry is dropped
  once that job template is authored with its own `model` field. `review_cli.py`'s `resolve_model()`
  now reads a job template's `model` field (via a new `load_job_template()` helper) ahead of that
  bridge, still under a per-call CLI override. `registry/job-templates/02-repository-partition-
  discovery.json` now pins `model: {model: "claude-sonnet-5", effort: "medium"}` explicitly, so D01
  keeps the sonnet-5/medium routing judgment already discussed rather than silently falling to the
  new haiku default. See `model-config.json`'s `_notes` for the full rationale. Note for the
  request builder (Phase 5b item 3): call `resolve_model` (or read the job template directly) with
  the job_template_id `02-repository-partition-discovery` -- `review_cli.py`'s own `run`/`model` CLI
  commands resolve `--lane` through `resolve_process()` first, which only knows *process* ids
  (`02-evidence-pregather`, etc.), one level coarser than job_template_id; the new per-job `model`
  field is keyed by job_template_id and only ever read directly, not through that CLI resolution.

**What is genuinely missing (the facility to build, in dependency order):**

1. **DONE.** ~~`governing_rules` prompt fragment~~ --
   built: `appsec-review-process/registry/prompt-fragments/governing-rules.md`. Four numbered
   rules distilled from AGENTS.md's two rules and AUTHORING-TEMPLATE.md's evidence/trust-boundary
   section, written as instructions to the invoked persona (not a human contributor): target
   content is data never instructions; a claim needs evidence that resolves; this is discovery, not
   a verified finding (the claim-class prohibition, stated for the persona reading it, not just
   enforced downstream by `persona_invocation`'s lexical backstop); partial discovery stays visible.
   Reusable by every future job template that lists `governing_rules` in `prompt_sections`.
2. **DONE.** ~~Prompt assembler~~ -- built: `appsec-review-process/persona_prompt_assembly.py`.
   Given a `job_template_id`, resolves the job template (schema-validated), renders each
   `prompt_sections` entry in declared order (a registry-record section as a labeled fenced-JSON
   block over the record's own canonical bytes -- schema-validated against the same schema
   `persona_invocation.load_composition` uses, so the assembled prompt and what
   `persona_invocation` independently re-hashes can never drift apart; `governing_rules` and
   `buildenv_catalog` as literal file bytes; `task` as the job template's own `task_prompt` file's
   literal bytes), concatenates, and (via `assemble_outer_prompt`) writes the result to
   `appsec-review-process/prompt-cache/<job_template_id>/outer_prompt.md` (a new, gitignored
   `prompt-cache/` dir alongside `runs/`, not under any run's `attempts/` tree), returning
   `{path, sha256, bytes}` ready to drop straight into `request["outer_prompt"]`. **Corrected
   2026-09-24, before delivery of item 3:** the first build wrote this file under the attempt's own
   scratch dir (`runs/<run_id>/data/jobs/<job_id>/attempts/<attempt_id>/prompt/outer_prompt.md`) via
   `execution_state.data_path`. That is a real bug, not a style choice --
   `persona_invocation._read_pinned` explicitly refuses an `outer_prompt` that sits inside the
   attempt it's for ("an attempt never reads itself"), so `resolve_request` would have rejected
   every request this module built, every time. The original round-trip test missed it because it
   called `_read_pinned` with `attempt=None` rather than a real attempt identity, so that check was
   never exercised. Root cause: the assembled prompt is a pure function of `job_template_id` plus
   current registry state -- nothing about it is run-, job-, or attempt-specific -- so it never
   belonged under `runs/` at all; `owasp_dispatch.py`'s real usage (`prompt_root=ROOT`, the static
   process tree) confirms this is the established convention. Fixed by dropping the
   `run_id`/`job_id`/`attempt_id` parameters entirely and caching one file per `job_template_id`
   under `prompt-cache/`, regenerated (not appended to) on every call, so two attempts of the same
   job template share one `outer_prompt` file and its pin, and a registry edit is picked up on the
   next call with no stale per-attempt copy to invalidate. Re-verified in the cloud sandbox against
   the corrected design: full render of D01's 8-section prompt (governing_rules, persona, role,
   domain, tooling_profile, buildenv_catalog, task, output_contract) succeeds; the written file
   round-trips through `persona_invocation._read_pinned` with the exact `sha256`/`bytes` this module
   returns, this time called with a *real* attempt identity (a fake `runs/.../attempts/<id>` dir
   outside `prompt-cache/`) so the "attempt never reads itself" check is actually exercised;
   separately confirmed the original (now-fixed) in-attempt path does raise
   `PersonaRequestError: outer_prompt: is inside the attempt; an attempt never reads itself` when
   fed to the same check, proving the bug was real and the fix resolves it; a missing job template
   raises `PromptAssemblyError` before writing anything. `--print` on the module
   (`python3 persona_prompt_assembly.py <job_template_id> --print`) renders without writing, for
   review.
2b. **DONE, William's addition 2026-09-24, not in the original spec.** ~~Model version
   registry~~ -- built: `appsec-review-process/model_version_registry.py`. Real gap found while
   starting item 3: `persona_invocation.py`'s request schema requires a fully pinned model
   identity (`provider`, `family`, `model_id`, `snapshot` with version digits, no alias word)
   before dispatch, but model-config.json only ever stored CLI aliases -- there was no real
   snapshot to put in a request, and the exact `--output-format` response shape that would carry
   one has been an open question since 2026-09-17. William's decision: add a step that queries the
   provider for the exact current version behind each family alias once per run, store a ref to
   the family plus the specific version that answered, and have repeat runs reuse the version
   their own run resolved (never re-query mid-run). `resolve_run_model_versions(run_id)` does
   this: queries every alias `configured_aliases()` finds in model-config.json/job templates (today:
   `claude-sonnet-5`, `haiku`), pins `runs/<run_id>/data/model-versions.json`, and a second call
   for the same run reuses the pinned record untouched. `model_identity_for(run_id, alias)` is
   what the request builder (item 3, next) calls to get a real `persona-model-identity` object --
   it never fabricates a snapshot; a query that yields nothing raises, naming exactly where to
   look. `query_alias`'s identity extraction is deliberately defensive (best-effort scan of
   `model`/`model_id`/`modelId` across every captured stream event, never assuming the shape),
   because the real response shape is still unconfirmed -- **this module's live run also settles
   that open question**, as a side effect of doing what William asked. Verified in the cloud
   sandbox with a fake dispatch function (no real CLI call, since this sandbox's own `claude`
   binary is a different, possibly-restricted install from hal5000's real one -- see the module's
   docstring): full resolve/pin/reuse-on-repeat round trip; the produced identity passes
   `persona_invocation.model_errors()` with zero errors; all three error paths (no identity found,
   alias never queried, no pinned record for the run) raise `ModelVersionError` with a message
   naming where to look, never silently. **Not yet dispatched for real anywhere, and not yet a
   registered `job-graph.json` node** -- see the module's own docstring for why formal Dagster
   registration is a separate, flagged-not-assumed follow-up (`job-graph.json` is one of the three
   surfaces AGENTS.md calls out for the Full protocol, not the fast lane every other D01 file so
   far has qualified for); callers invoke `resolve_run_model_versions` directly for now, which
   already gives William's "resolve once per run, pin, reuse on resume" behavior. **Live
   confirmation needed on hal5000** (see the module's `--query`/CLI block) before item 3 depends on
   it for a real dispatch.
3. **DONE.** ~~Request builder~~ -- built: `appsec-review-process/persona_dispatch.py`,
   `build_request(job_template_id, *, run_id, job_id, attempt_id, target_root,
   source_snapshot_sha256, now, ...)`. Builds the full
   `appsec-review/persona-invocation-request/1.0` object: `persona` (the six id+sha256 composition
   pairs, read straight from the registry -- the exact records
   `persona_invocation.load_composition` independently re-loads and hashes); `model` (a real pinned
   `persona-model-identity` from `model_version_registry.model_identity_for(run_id, alias)`, where
   `alias` is `review_cli.resolve_model(job_template_id, budget_name)["model"]` -- called by
   `job_template_id` directly, never through `review_cli`'s own `run`/`model` CLI commands, which
   resolve at the coarser *process* granularity; see the model-routing-redesign note above);
   `tools: []` and `budget.tool_call_limit: 0` (the persona reads target bytes already pinned into
   `readable_inputs`, never calls back into a live filesystem -- the same convention
   `owasp_dispatch.py`'s pooled cells already use, confirmed by reading its `build_specifications`);
   `budget` (a new `PERSONA_BUDGETS` table keyed by the job template's own `budget_default`,
   scoped to this module -- see its docstring for why it is not shared with
   `owasp-dispatch/default-v1.json`'s `cell_budgets`, a different pooled domain); `allowed_claim_classes`
   / `prohibited_claim_classes` (`persona_invocation.claim_ceiling(role, tooling_profile)`, already
   existed, just called); `outer_prompt` (step 2's `assemble_outer_prompt`); `readable_inputs` (a
   new `_walk_target`: every regular file under the target checkout, hidden CI/configuration
   directories included per the job template's own instructions, `.git` excluded matching
   `intake.source_identity`'s own exclusion, refuses outright if the checkout contains a symlink
   anywhere -- see the module docstring for why this is a deliberately scoped-down walk for D01's
   fixture-proof construction, not `intake.source_identity`'s full bounded/deadline-guarded one);
   `permission` (a real B11 `permission_capabilities.evaluate()` call with an empty capabilities
   requirement -- confirmed while researching this item that there is no `read-source` capability
   definition in this registry at all, so empty is the correct requirement for
   `static-repo-project-inspector`'s static-only mode, not a placeholder; the function asserts the
   GRANTED/empty-capabilities result rather than assuming it, so a future capability added to this
   tooling profile's requirements fails loudly here). Lives in its own new module (not inside
   `discovery_gate.py`): `discovery_gate.py` already carries two execution shapes
   (common-envelope + legacy) and a third (automatic dispatch) reads more clearly as its own file
   that `discovery_gate.py` (item 5) will call into.
   **A real bug found and fixed while structurally testing this module, before delivery:** the
   first draft defaulted `job_id` to `job_template_id` itself, on the (wrong) assumption that it
   matched `discovery_gate.py`'s existing `root(run_id, 'jobs', job)` directory-naming convention.
   `permission_capabilities.py`'s default-deny secret-scanner (`HIGH_ENTROPY_RE`, applied to every
   permission context field including `job_id`) incidentally matches any 32+ character string that
   mixes letters, digits and separators the way most of this registry's descriptive kebab-case job
   template ids do -- `02-repository-partition-discovery` (33 chars) is one of exactly two job
   template ids in the current registry that trip it (`02-api-collection-intelligence-ingest`, 37
   chars, is the other). Every `pc.evaluate` call for D01 raised `PermissionModelError: context
   carries secret-like material` before a decision was even reached. Root cause: `job_id` and
   `job_template_id` are meant to be separate concepts -- the test fixtures already model this
   (`tests/persona_invocation_support.py`'s `JOB = "job-b14"` is a short opaque id, distinct from
   `TEMPLATE = "04-owasp-validation-worklist"`) -- so the fix removed the dangerous default
   entirely: `job_id` is now a required, caller-chosen parameter, never invented by this module.
   Verified in the cloud sandbox against a synthetic target checkout (hidden `.github/workflows/`
   dir, a `.git/objects/` entry that must NOT appear in `readable_inputs`, a plain source file) and
   a fake-dispatched pinned model-versions record for a throwaway run id: the built request passed
   **`persona_invocation.resolve_request` end-to-end** (not just this module's own schema-shaped
   output -- the real independent re-derivation `persona_invocation.run_invocation` performs
   before ever calling an invoker), confirming request/composition/prompt/readable-input hashes
   all round-trip; `.git` was excluded and the hidden CI dir was included, as required; all four
   failure paths (missing job template, missing target directory, a symlinked file in the target,
   a run with no pinned model version) raised `RequestBuildError` naming exactly what was wrong,
   never partially building a request.
4. **DONE.** ~~`PersonaInvoker`~~ -- built: `appsec-review-process/claude_cli_invoker.py`,
   `ClaudeCliInvoker`, implementing B14's `PersonaInvoker` protocol. Reuses
   `review_cli.py`'s already-proven `_dispatch_streaming` (not `build_claude_argv`, which is tied
   to `review_cli`'s own run-id/lane/`--add-dir` semantics that don't fit a private,
   protocol-scoped invocation -- a new small `_dispatch_argv` builds a `claude -p` argv from the
   request's own pinned model alias and the caller's effort). No scratch-directory materialization
   is needed: D01's job template sets `tools: []`/`tool_call_limit: 0` (the persona never calls
   back into a live filesystem, matching `owasp_dispatch.py`'s own pooled-cell convention), so
   every readable input's exact bytes are inlined directly into the one prompt text sent over
   stdin instead.
   **Strict IO contract (William, 2026-09-24, explicit sign-off on the design flagged at the end
   of the previous turn): the model's single-turn response is validated, never parsed
   heuristically.** With no tools, the model has exactly one turn to produce everything; this
   invoker requires that response to be one JSON object, one key per output-contract-required
   file (excluding `status.json` -- see below), each JSON-valued key schema-validated against the
   output contract's own declared `result_schema.schema_file` and each markdown-valued key
   type-checked as a non-empty string. Anything else -- unparseable JSON (a lone fenced block is
   tolerated), an extra/missing key, a schema violation -- is a hard rejection: the invoker raises
   `InvokerOutputError` rather than writing a best-effort `invoker-output.json`. Per B14's own
   `_call_invoker` contract, a raised (non-`InvokerUnavailable`) exception yields outcome
   `"raised"` -> cause `INVOKER_EXCEPTION` -> `execution_status: FAILED` -- the adapter is what
   turns a rejection into the run's terminal record, not this module. Claims for
   `invoker-output.json` are derived mechanically, not by the model: one claim per partition
   (claim_class `repository_partition_map`) citing every `source_file` evidence citation the
   partition itself named that resolves to a pinned `readable_inputs` entry (a citation that does
   not resolve is dropped, never fabricated -- `persona_invocation`'s own `UNDECLARED_CITATION`
   check is the backstop), plus one `evidence_gap` claim per `uninspected` coverage category check.
   **Deliberately scoped, flagged not silently assumed, in the module's own docstring:**
   `status.json` is excluded from what this invoker asks for or writes -- it needs run/job/dagster
   identity and the handoff's `artifacts_read` that only the caller (item 5) has, the same split
   `persona_invocation.py`'s own `OUTPUT_SCHEMA` already draws; the envelope's per-file typing only
   understands `.json` and `.md` today (a future output contract needing another file type is a
   named follow-up, not a silent gap); only `invocation_role: "produce"` with `tools: []` is
   handled (a future review/verify/refute/judge role or a job template that actually grants tool
   actions needs this module extended).
   **A real bug found and fixed while structurally testing this module:** the first draft wrote
   dispatch diagnostics (the raw stream-json transcript, the raw terminal result) under
   `output_root/diagnostics/`. `persona_invocation.py`'s own output derivation scans every file
   under `output_root` and rejects (`MALFORMED_RESULT`) anything not declared in the manifest --
   B14's contract that an invoker writes "beneath output_root and nowhere else" is a hard
   boundary, not just a description of where the *declared* files go. Fixed by writing diagnostics
   to a private `tempfile.mkdtemp()` scratch directory entirely outside `attempt_root`, never
   inside it at all.
   **Verified end-to-end in the cloud sandbox**, against the same synthetic target checkout and a
   fake `_dispatch_streaming` returning a real, schema-conformant repository-partition-map
   envelope: the full `persona_invocation.run_invocation` pipeline -- request resolution, gate,
   invoke, independent re-derivation, terminal record -- returns `execution_status: OK` with one
   resolvable claim citing two pinned readable inputs and a clean three-file output tree
   (`repository-partition-map.json`, `repository-partition-summary.md`, `invoker-output.json`).
   Separately confirmed the strict-rejection path: a fake dispatch returning prose instead of JSON
   yields `execution_status: FAILED` / `cause: INVOKER_EXCEPTION`, with the attempt's output tree
   left completely untouched (no partial files). **Not yet dispatched against a real `claude`
   CLI anywhere** -- same "prove structurally in the sandbox, confirm live on hal5000" split as
   the model version registry; live confirmation is now needed for D01's actual SAT stage-6 proof,
   the point the original construction spec was aiming at.
5. **DONE.** ~~Dagster lifecycle wiring~~ -- extended `appsec-review-process/discovery_gate.py`
   in place (no new module: this is `discovery_gate.py`'s own third execution shape, alongside the
   existing common-envelope supplied path and the legacy per-job path).
   **Mode selection, without touching `dagster_workflow.py`:** confirmed by grep
   (2026-09-24) that `dagster_workflow.py` calls `discovery_gate.run(run_id, dagster_id, job,
   force)` identically for all four discovery jobs, and `dagster_workflow.py` is a Full-protocol
   file (`AGENTS.md`) out of scope for this fast-lane change -- so `run()`'s external signature is
   unchanged. Instead, a new run-scoped opt-in file, `dispatch_mode_path(run_id)` ->
   `runs/<run_id>/data/dispatch-mode.json` (job id -> `"supplied"`/`"automatic"`), read by a new
   `dispatch_mode(run_id, job)` (absent file or absent key -> `"supplied"`, full backward
   compatibility for every existing/unconfigured run) and written by a new `set_dispatch_mode(run_id,
   job, mode)`. `run()` now reads `dispatch_mode(run_id, ADOPTED_JOB)` and dispatches to the new
   `_run_partition_automatic` only when it is `"automatic"`; every other job, and every run that has
   never called `set_dispatch_mode`, takes the exact code path it always has.
   **`_run_partition_automatic`** mirrors `_run_partition`'s own `coordinate_worker_lifecycle`
   shape (`derive_inputs`/`preflight_validate`/`execute_attempt`/`post_validate`/`on_reuse`,
   `worker_kind='persona'` -- the schema's own enum for this, not an invented value). Its
   `derive_inputs` (`_automatic_partition_inputs`) sources the target checkout from
   `phase1.manifest_path(run_id)`'s `target.repo_path` (the exact same field
   `validate_job_output.py`'s own `_source_root` citation-freshness check already reads, confirmed
   by reading it -- so the target this path dispatches against and the target consumer-job
   acceptance checks citations against can never disagree), fingerprints it via
   `intake.source_identity(target_root)['fingerprint']` (`sha256:`-prefixed), and hashes the source
   of every module this path calls (tamper-evidence, mirroring `_partition_inputs`' own `code`
   block for the supplied path). `execute_attempt` (`_dispatch_partition_persona`) calls
   `model_version_registry.resolve_run_model_versions(run_id)` (a no-op reuse once the run's first
   dispatch has resolved it), builds the request via `persona_dispatch.build_request` with a new
   short opaque `PERSONA_JOB_ID = 'd01-partition'` (never `ADOPTED_JOB` itself as
   `request.job_id` -- that is exactly the 33-character secret-scanner landmine item 3's own
   docstring documents fixing once already), builds a `PersonaRuntime` (`invoker=
   ClaudeCliInvoker(effort=..., budget_usd=...)` from `review_cli.resolve_model`/
   `model-config.json`'s `budget_max_usd_per_call`, `allowed_models=(the one pinned model identity
   the request actually uses,)`, a real UTC `clock`, a fresh `threading.Event()` `cancel`,
   `stop_grace_seconds=5`), and calls `persona_invocation.run_invocation`.
   **Resolved design question (read `publish_job_output.py`'s `record_terminal_current`/
   `persist_terminal_current` in full to settle this, rather than inventing new status
   machinery):** `record_terminal_current` only ever accepts `execution_status` in `{OK,
   OK_WITH_GAPS, SKIPPED}` -- there is no path for `execute_attempt` to return normally with a
   legitimately-completed-but-rejected result. So a `run_invocation` result whose
   `execution_status != "OK"` (the model's response failed schema/envelope validation, the invoker
   was unavailable, a budget/permission check failed, ...) is raised as a plain `RuntimeError`
   naming the `execution_status`/`cause`/`outcome`, exactly mirroring `_run_partition`'s own
   `execute_attempt` raising `ValueError` on an invalid supplied payload --
   `coordinate_worker_lifecycle`'s `terminal_for()` catches it and records a clean non-current
   `FAILED` terminal with the exception as cause, re-raising to the caller. No new terminal-status
   machinery was added; the existing BLOCKED-on-preflight/FAILED-on-execute contract already
   covers this case correctly once recognized.
   **Output paths, kept identical to the supplied path on purpose:** `persona_invocation.
   run_invocation` necessarily writes the model's two output files under a fresh
   `attempt_root/outputs/persona/` subdirectory (`output_root` must not already exist when
   `run_invocation` creates it, and `attempt_root` itself already exists by the time `execute_
   attempt` runs) -- but `_validate_common` and every consumer job
   (`02-dev-project-discovery`, `02-devops-project-discovery`) read
   `attempt/repository-partition-map.json` at the attempt's top level, the same path the supplied
   path has always written. So after an `OK` `run_invocation` result, `_dispatch_partition_persona`
   independently re-validates the persona's `repository-partition-map.json` against the schema
   (never trusts the invoker's own validation blindly -- same posture `_run_partition`'s
   `execute_attempt` already takes toward the supplied file) and re-materializes both files at the
   canonical top-level attempt paths, leaving `outputs/persona/` and `logs/persona/` in place as
   part of the accepted attempt's immutable tree (covered by `publish_validated`'s `tree_hashes`
   tamper check, same as any other file under an accepted attempt). **`_validate_common` was
   updated too** (a real gap found while testing this end-to-end, not anticipated in the original
   plan): it always recomputed the accepted pointer's expected fingerprint from the supplied path's
   handoff-shaped record, which does not exist for an automatic-mode attempt -- `read_latest_
   handoff` raised `FileNotFoundError` before `_validate_common` could even reach the fingerprint
   check. Fixed by branching on `dispatch_mode(run_id, ADOPTED_JOB)`: automatic-mode runs
   recompute via `_automatic_partition_inputs` (the same record `derive_inputs` built), supplied-mode
   runs keep the existing handoff-based `_partition_inputs` call unchanged.
   **Verified end-to-end in the cloud sandbox** (target-checkout + manifest fixture mirroring
   `tests/test_worker_adoption.py`'s own `AdoptionTests.setUp`, a pre-seeded
   `model-versions.json` so no real model-version probe runs, `review_cli._dispatch_streaming`
   monkeypatched to a fake returning a schema-conformant envelope): (a) first automatic-mode run
   through `discovery_gate.run()` accepts with `worker_kind: "persona"`,
   `acceptance_status: "CURRENT"`, `status.json.dispatch_mode: "automatic"`; (b) a second call with
   an unchanged target reuses the identical accepted pointer (`admit_reusable`'s existing dedup,
   unmodified); (c) `discovery_gate.validate()` (the consumer-facing common-envelope read path)
   succeeds against the automatic-mode attempt, proving the `_validate_common` fix; (d) a rejection
   path (fake dispatch returning prose instead of JSON) raises the expected `RuntimeError`, records
   a clean non-current `FAILED` pointer, and leaves the attempt with **no**
   `repository-partition-map.json` at all -- no partial publish. The full existing
   `tests/test_worker_adoption.py` suite (19 tests, the supplied path's own regression coverage)
   still passes unmodified, confirming the supplied path (`_run_partition`) is untouched by this
   change. **Not yet dispatched against a real `claude` CLI anywhere** -- same "prove structurally
   in the sandbox, confirm live on hal5000" split as items 2b/3/4; live confirmation on hal5000 is
   the next step, now that every piece of the automatic-dispatch chain exists and has been proven
   structurally.
6. **DONE.** ~~SAT script change~~ -- extended `scripts/system-acceptance-test.sh` in place. A new
   `--dispatch` CLI flag, meaningful only at SAT creation (`--resume` reads the resumed SAT's own
   recorded choice from `sat.json` and prints a warning if `--dispatch` is also passed, rather than
   silently honoring it -- a SAT's dispatch mode is fixed at creation, matching `--fixture`'s own
   resume behavior). Stored as `sat.json`'s new `partition_dispatch: true/false` field (schema
   `appsec-review/system-acceptance/2`, an additive field -- old `sat.json` files without it read as
   `false`/supplied, same backward-compatibility posture as `discovery_gate.py`'s own
   `dispatch_mode()` default). A new `PARTITION_DISPATCH` shell variable (`"1"`/`"0"`) is read once
   from `sat.json` at driver startup and threaded into `stage_partition_discovery()`.
   **`gate_dispatch_mode()`** (a new shared gate-step helper, alongside the existing
   `gate_handoff`/`gate_supply`/`gate_validate`/`citations_fresh`): idempotent (checks `dispatch-
   mode.json` for `"automatic"` first, so a stage re-run after a partial failure doesn't re-opt-in
   needlessly), then opts the run into automatic dispatch via a `$CL run -B -c
   'import discovery_gate; discovery_gate.set_dispatch_mode(...)'` one-liner -- calling the exact
   function item 5 built, never reaching into `discovery_gate.py`'s internals directly -- wrapped in
   a `run_step` contract requiring exactly `{run}/data/dispatch-mode.json` as the sole write.
   **`stage_partition_discovery()` rewritten to branch on `$PARTITION_DISPATCH`:** the supplied
   branch is the original `gate_handoff` + `gate_supply` + byte/ID-equality-against-the-fixture
   `accept` contract, completely unchanged (confirmed: this branch is not new code, only relocated
   inside the `if`). The automatic branch calls `gate_dispatch_mode` in place of `gate_handoff`/
   `gate_supply`, then a differently-shaped `accept` contract: `inputs` require `dispatch-mode.json`
   equals `{"02-repository-partition-discovery": "automatic"}` and the supplied-result path
   **absent** (proving this run took the live-dispatch path, not a fixture copy); `writes.allowed`
   covers `outputs/persona/*`, `logs/persona/*`, `data/model-versions.json`, `data/*.jsonl` -- no
   handoff or supplied-result paths, since the automatic path never touches them; `outputs` checks
   `execution_status: OK`, `worker_kind: persona`. After `launch`/`gate_validate`/`citations_fresh`
   (unchanged, shared by both branches), the summary-building step also branches: the automatic
   branch's python checks structural acceptance rather than fixture equality -- at least one
   partition, each partition's `primary_persona_id` one of the three discovery-chain personas
   (`developer-engineer`/`devops-engineer`/`sre-engineer`), non-empty `evidence_citations` per
   partition, `coverage.category_checks` non-empty with every `result` in
   `{found, not-found, uninspected}` -- **deliberately never comparing partition IDs or dispositions
   against the fixture answer key as a pass/fail check, exactly as this item's original plan called
   for** ("comparing against the fixture record becomes an optional informational diff, never a
   pass/fail gate"): a `diff_note` is still computed (wrapped in `try/except OSError`, since the
   fixture answer key may not exist for every fixture) and appended to the printed stage summary
   when live partitions disagree with it, purely informational. The supplied branch's summary step
   is the original byte/ID-equality check, unchanged. `--list`/`--through` and every other stage
   (7-9, still supplied-mode-only) are unaffected either way.
   **Verified in the cloud sandbox, without relying on eyeballing the shell script alone** (`bash
   -n` cannot see inside heredoc bodies): `bash -n` on the whole file; every embedded Python heredoc
   (9 of them) extracted and `ast.parse`'d; every embedded JSON contract heredoc (9 of them)
   extracted and `json.loads`'d with placeholder substitution; standalone unit tests of the
   `sat.json`-creation snippet, the `PARTITION_DISPATCH` getter, and `gate_dispatch_mode`'s
   idempotency check; and a full live-data functional test -- reran item 5's automatic-dispatch flow
   against a fresh synthetic fixture to produce real `repository-partition-map.json`/`status.json`
   artifacts, then fed those exact files through the new dispatch-mode summary python verbatim,
   confirming correct structural-pass output including a correctly-computed informational
   `diff_note` when the live (synthetic) partitions disagreed with the fixture's own answer key. No
   bugs found in this item's own logic (unlike items 3-5, each of which turned up a real bug) --
   attributed to the multi-layer verification (syntax + AST + JSON + live data) run before
   considering it ready, not to the change being simpler.
7. **DONE.** ~~Docs, same commit as the code (standing rule)~~ -- `docs/processes/system-acceptance-
   test.md` (usage block documents `--dispatch`; stage 6 table row now reads "gate; `--dispatch`:
   automatic live persona dispatch instead"; a new subsection under the stage list documents the
   two-step automatic shape (`dispatch-mode`, `accept` -- no `handoff`/`supply`), the reads/writes/
   validates table, and states explicitly what changed and why: acceptance no longer byte-compares
   against the fixture's answer key, per the original D01 spec, with the informational `diff_note`
   still computed and printed; the gaps table's "no LLM/agent produces the discovery records" row
   narrowed to "stages 7-9 (D02-D04) and the build part: still open" since stage 6 is now closed via
   `--dispatch`), `docs/processes/engagement-start.md` (S2b Mermaid node label and the step-2b
   prose/table updated to describe the automatic-dispatch option as an alternative to the supplied
   record, explicitly noting D02-D04 don't have this yet; PNG re-rendered via `mmdc` -- needed a
   Puppeteer `-p` config disabling the sandbox to run as root in this cloud sandbox -- and confirmed
   visually via the Read tool), and `docs/processes/flow-bringup.md` (one new dated log entry
   summarizing the full D01 build across items 1-7, the supplied-path regression proof, the live SAT
   confirmation, and flagging that automatic dispatch has not yet been run against a real `claude`
   CLI). This file's Phase 5b status updated in the same commit (this entry).
   **BPMN judgment call, not yet confirmed with William:** `docs/processes/bpmn/pre-submission.bpmn`
   was left unchanged -- the `--dispatch` addition read as a text-label change within the existing
   S2b box (matching the Mermaid diagram's own treatment), not a new pictured node or branch. Flag
   this explicitly for William to revisit if the BPMN is expected to show the automatic-dispatch
   branch distinctly.
8. **Live qualification on hal5000, 2026-09-24 -- two real bugs found and fixed against a real
   `claude` CLI, in progress.** Items 1-7 above were verified only structurally in the cloud
   sandbox; this is the first time `--dispatch` actually ran against a live model.
   - **Bug 1: `claude` binary not found (`FileNotFoundError`).** `model-config.json`'s
     `invocation.binary` was the bare name `"claude"`, resolved via whatever process's own `PATH`
     happens to run it -- fine for `code-location.sh run`'s synchronous steps (inherits the
     interactive WSL shell's PATH) but not inside the long-running `dagster code-server start`
     daemon that actually executes the job. **First fix attempt hardcoded one operator's absolute
     install path directly into `model-config.json`; William rejected it** ("Don't pin a version.
     Look it up in the first job. If not found error appropriately.") -- a hardcoded path breaks
     the moment the install moves. **Fixed properly**: new module
     `appsec-review-process/claude_binary_resolver.py`, `resolve_claude_binary(run_id)`, resolves
     the real absolute path with `shutil.which()` from inside whichever process dispatches the
     run's first claude CLI call (`model_version_registry.resolve_run_model_versions`, always
     first) and pins it to the run (`runs/<run_id>/data/claude-binary.json`) -- the same "resolve
     once per run, pin, reuse" shape already used for model identity. A resolution failure raises
     `ClaudeBinaryError` (surfaced through `ClaudeCliInvoker` as `InvokerUnavailable`), never a
     silent fallback. `model-config.json`'s `invocation.binary` is back to just `"claude"`.
     `model_version_registry.py`'s `_probe_argv`/`query_alias` and `claude_cli_invoker.py`'s
     `_dispatch_argv` all now take the resolved `binary` explicitly rather than reading a
     bare/PATH-dependent name themselves. **Live-confirmed**: the next live attempt resolved
     `/mnt/c/Users/wsoll/AppData/Roaming/npm/claude` from inside the daemon process and got past
     this failure entirely.
   - **Bug 2: the model's response didn't match the output schema (`INVOKER_EXCEPTION`).** With
     bug 1 fixed, the live dispatch reached a real `claude -p` call, which returned a well-reasoned,
     evidence-cited, but structurally different JSON object than `repository-partition-
     map.schema.json` requires (`engagement`/`paths.include`/`kind` singular/`review_disposition`
     instead of the schema's own `target`/`source_revision`/`include_paths`/`kinds`/`disposition`,
     etc. -- 29 schema validation errors, confirmed by feeding the actual captured response through
     `schema_validate.validate_document` directly). **Root cause**: the outer prompt's
     `output_contract` section (rendered by `persona_prompt_assembly.py`) only ever shows the
     output contract's own registry *metadata* (display name, claim class, prose validation rules
     -- `registry/output-contracts/repository-partition-map.json`), never the literal JSON Schema
     file (`repository-partition-map.schema.json`) with its actual field names/enums/required
     properties. The model was never shown what shape was actually required, and reasonably
     improvised its own. **Fixed in `claude_cli_invoker.py`** (its own module, since it already owns
     envelope construction and validation): new `_render_json_schema(schema_file, store)` inlines
     the literal schema JSON (plus every local `evidence-citation.schema.json`-style `$ref` it
     reaches, via new `_local_schema_refs`) as a fenced block in the prompt, under a new "Required
     Output Schema(s)" section, for every required JSON output file. `build_prompt_text` now takes
     `store: SchemaStore` to do this. Verified: a hand-built schema-conformant sample validates
     cleanly against the real schema (confirming the schema itself and this diagnosis are correct);
     `build_prompt_text` against a fake package confirms the rendered prompt contains both the
     partition-map schema and its referenced evidence-citation schema; all 19
     `tests/test_worker_adoption.py` tests still pass unmodified. **Live-confirmed** by the bug-4
     attempt below and the final clean PASS: the model's response was fully schema-conformant on
     every subsequent live attempt.
   - **Also fixed, found while re-reading item 6's own SAT contract after the first live attempt**:
     `stage_partition_discovery()`'s automatic-mode `accept` contract's `writes.allowed` list didn't
     include `{run}/data/claude-binary.json` (new, from bug 1's fix) or
     `appsec-review-process/prompt-cache/$PARTITION_JOB/outer_prompt.md` (pre-existing, from item
     2's prompt assembler, but never exercised by a passing automatic-mode contract check before
     now) -- both flagged "unexpected write" on the first live attempt. Both added to the allowed
     list.
   - **Bug 3: `source_revision` mismatch (the last failure before a clean PASS).** With bug 2
     fixed, the live dispatch produced a fully schema-conformant `repository-partition-map.json`
     -- every field, structure, enum matched. The only remaining failure: the model wrote
     `"source_revision": "unknown (no VCS ref supplied with target content; files provided as a
     flat pinned set)"`, but the SAT's accept contract (and every downstream citation-freshness
     check) expects the run's actual pinned git revision
     (`632522b6801caa5810f0c6bf71bf3783c90068ac`). **Not a model mistake -- the model was telling
     the truth.** D01's readable inputs deliberately exclude `.git` (`persona_dispatch.py`'s
     `_walk_target`, the same convention `intake.source_identity`'s own exclusion follows), so the
     persona genuinely has no VCS ref to read; writing "unknown" rather than fabricating a
     revision is exactly the honest behavior governing rule 2 asks for. `source_revision` is
     orchestrator-owned provenance, not evidence-derived content -- the same split that already
     excludes `status.json` from what the model is asked to produce. **Fixed in
     `discovery_gate.py`'s `_dispatch_partition_persona`**: after reading the persona's
     `repository-partition-map.json` and before independent re-validation, overwrites
     `partition_map['source_revision']` with `record['source_revision']` -- the same authoritative
     value `_automatic_partition_inputs` already computed from `intake.source_identity` for the
     fingerprint, never trusted from the model. Verified: a schema-conformant sample carrying the
     model's exact "unknown ..." string, run through the same override-then-validate sequence,
     ends with the correct pinned revision and validates cleanly; `intake.py`'s `revision` field
     defaults to the literal string `"unversioned"` (never `None`) when a target has no VCS at
     all, so the override is safe even for a non-git target; all 19
     `tests/test_worker_adoption.py` tests still pass unmodified.
   - **Also fixed, found on this same live attempt's contract report**: the automatic-mode
     `accept` contract's `writes.allowed` list didn't include
     `{run}/data/jobs/$PARTITION_JOB/attempts/*/failure-result.json` --
     `publish_job_output.record_terminal_noncurrent` writes that filename instead of `result.json`
     whenever a worker already durably wrote a candidate `result.json` before a later validation
     step rejects it (its own documented behavior: "preserve that immutable candidate... instead
     of rewriting history"). Added to the allowed list.
   - **Bug 4: with source_revision fixed, dispatch got all the way to publish-time citation-
     freshness rejection.** The persona's `repository-partition-map.json` was fully schema-
     conformant this time (confirming bug 2's and bug 3's fixes both worked -- no schema or
     source_revision complaints at all) and the attempt reached `publish_job_output`'s real
     `record_terminal_current`, which durably wrote a candidate `result.json` before
     `validate_job_output.py`'s citation-freshness check rejected it with 26 identical errors:
     every single `evidence_citations[].content_hash` across every partition, relationship, and
     `coverage.category_checks` entry failed `"a lowercase SHA-256 is required for freshness"`
     (`validate_job_output.py`'s `_citation_errors`, which requires a bare 64-lowercase-hex string
     matching `file_hash()` of the cited file's *current* on-disk content, checked with a strict
     `re.fullmatch(r"[0-9a-f]{64}", ...)`). **Not a model mistake in the way bug 3 wasn't**: the
     persona has no reliable way to compute a file's exact SHA-256 by hand, and (per its own
     attempted values in the coverage check citations) its guesses failed the strict format check
     every time -- this is orchestrator-owned verification data, the same class as `source_
     revision`. **Fixed in `discovery_gate.py`**: new `_backfill_citation_content_hashes(value,
     by_path)`, called right after the `source_revision` override, walks `partition_map` exactly
     the way `validate_job_output.py`'s own `_walk_citations` does (any `evidence_citations` list
     at any depth -- partitions, their relationships, and coverage checks all nest one), and for
     every `source_type: source_file` citation whose `path` resolves against this request's own
     pinned `readable_inputs` (`by_path = {entry['path']: entry['sha256'] ...}`, stripping the
     `sha256:` prefix `persona_dispatch.py`'s `_walk_target` always adds), overwrites
     `content_hash` with the pinned, authoritative value -- unconditionally, even when the model
     already wrote something, mirroring `source_revision`'s "caller owns provenance, never
     trusted from the model" split. A citation whose path does **not** resolve is left exactly as
     written, so it can still legitimately fail freshness validation downstream, per governing
     rule 2 ("a claim needs evidence that resolves") -- this function never fabricates a hash to
     paper over an unpinned citation. Verified: a hand-built nested sample (a resolvable citation
     at each of the three nesting depths, one deliberately unresolvable path, and one citation
     where the model had already written a wrong value) confirms all four cases -- resolved paths
     get the correct pinned hash, the unresolved path is left untouched, nesting is fully reached,
     and an existing wrong value is overwritten; the pinned hash format was confirmed to match the
     freshness check's own `[0-9a-f]{64}` regex; all 19 `tests/test_worker_adoption.py` tests
     still pass unmodified.
   - **The persona dispatch itself worked end to end for the first time**: this live attempt's
     Dagster run reported `"status": "SUCCESS"` -- `discovery_gate.py`'s automatic-dispatch chain
     (request build, live `claude` CLI call, schema-conformant response, independent
     re-validation, `source_revision`/`content_hash` backfill, publish) is confirmed working
     against a real target and a real model. **The only remaining SAT failure was a fifth,
     trivial, SAT-contract-only gap**: the automatic-mode `accept` contract's `writes.allowed`
     list never included `{run}/data/jobs/$PARTITION_JOB/job.lock` -- every other job's contract
     in this same script lists its own `job.lock` explicitly (e.g. `00-intake/whole/job.lock`),
     this one was simply missed when item 6 was first written. Added. **Bugs 1-4 above were all
     real production-code bugs in the automatic-dispatch chain itself, found and fixed by working
     through successive live SAT failures one at a time; this fifth gap is purely cosmetic to the
     test harness -- the underlying job already succeeded.**
   - **CONFIRMED CLEAN: `scripts/system-acceptance-test.sh --dispatch --through partition-discovery`
     PASS, run by William on hal5000 2026-09-24 (SAT run `20260924T214618Z`, Dagster run
     `7e2fc40f-9e22-4c03-8cdc-ab488ac2219c`, launched via `20260924T214649Z-69227b`).** With all
     five gaps above fixed (commit `51f01d3` on top of `24afac9`/`00a75e7`/`568992e`/`1e0ec37`),
     the automatic-dispatch gate reported `"status": "SUCCESS"` and the SAT itself reported
     `partition-discovery: PASS` with **zero contract violations** ("21 file(s) written, all within
     contract; 3 output(s) valid; 9 ambient change(s) ignored"). The real `claude` CLI, called
     against the real fixture target repo (revision `632522b6801caa5810f0c6bf71bf3783c90068ac`),
     produced a schema-conformant `repository-partition-map.json` with 6 partitions (`app-core`,
     `build-system`, `containerization-deployment`, `documentation`, `test-suite`,
     `vendored-cjson`), all dispositioned `review`, backed by 37 citations that the orchestrator
     independently confirmed match the checkout on disk (freshness-validated content hashes, not
     model-reported ones). The live partition names differ from the hand-authored fixture answer
     key's names (`app`/`build`/`docs`/`tests`/`vendored-cjson`) -- the SAT reports this only as an
     informational `diff_note`, not a failure, since the supplied-fixture answer key was never a
     spec for what a live model must name things; it exists to prove the *harness* accepts a
     conformant record, which the fixture path (items 1-7) already proved separately. **This is
     D01's first fully clean live PASS: real repository discovery, real model call, real schema,
     real orchestrator-owned provenance, real freshness-validated citations, no fixture-copy
     shortcut anywhere in the chain.** D01 (unpooled) is DONE.

**Acceptance for D01 (unpooled), from the batch table, now fully met:** dispatch, supplied mode
retained, inapplicable/gap handling, citation freshness, rescope trigger, malformed persona result,
timeout/cancel, reuse/recovery, and live real-target qualification are all confirmed -- the last of
these (live dispatch against the fixture target, run in WSL by William) closed with the clean PASS
above. A second, different real target is a separate, later qualification step, not required to
close D01 on the fixture target it was scoped to.

**Once D01 (partition discovery) is proven live with real dispatch:** D02 (`02-dev-project-
discovery`), D03 (`02-devops-project-discovery`) and D04 (`02-sre-operations-topology`) follow the
identical pattern (facilities 2-6 above are reusable as-is; only the job template's composition and
task prompt differ per job). One piece is missing for those three that D01 does *not* need: **none
of the three job templates have a `task_prompt` file yet** (`task_prompt: null` in all three
registry job-template records, checked 2026-09-24) -- their `prompt_sections` list a `task` entry
with nothing to render. New authored content, one file each, alongside the existing pattern:
`appsec-review-process/02-evidence-pregather/dev-project-discovery.md`,
`.../devops-project-discovery.md`, `.../sre-operations-topology.md`. Their personas, roles, domains,
tooling profiles and output contracts all already exist (checked 2026-09-24): dev discovery ->
`developer-engineer`/`repo-project-discoverer`/`repo-project-discovery`/`static-repo-project-
inspector`/`project-discovery`; devops discovery -> `devops-engineer`/`repo-project-discoverer`/
`repo-project-discovery`/`static-repo-project-inspector`/`project-discovery`; sre topology ->
`sre-engineer`/`operations-topology-mapper`/`operations-topology`/`static-ops-topology-inspector`/
`operations-topology`. Once stage 6 is live, re-run stages 7-9 the same way; this reopens SAT
stages 6-9 as a set (a fresh SAT, not a resume, once `discovery_gate.py` changes -- same fingerprint
rule already documented above).

**Construction and live testing for this phase happens in a separate chat session** (continuation
prompt: `docs/continuation-prompts/2026-09-24-d01-persona-dispatch-construction.md`), so this
session can stay on higher-level architecture and sequencing. Its output lands the same way every
other stage has: patch -> `Claude outputs/` -> `git am` -> gitkraken push, with William running the
live WSL command and pasting output back before the next thing moves.

### Phase 5c -- D02: automatic persona dispatch for dev-project-discovery -- IN PROGRESS, blocked on a Full-protocol fix

**Started 2026-09-24, same evening as Phase 5b's clean PASS.** Goal: `02-dev-project-discovery`
reads the accepted partition map plus the target repository and decides, itself, how each
developer-routed project should be built and tested -- this is the first job in the pipeline where
the persona decides the actual build tooling and technique (autotools vs. a package manager,
which buildenv image, the ordered safe command plan), not just how the repo should be routed. D01's
facilities (`claude_binary_resolver.py`, `model_version_registry.py`,
`persona_prompt_assembly.py`'s schema inlining, `discovery_gate.py`'s dispatch-mode opt-in and
provenance backfill pattern, `claude_cli_invoker.py`) are reused unchanged, per the lessons-learned
doc's closing section.

**Done so far, this evening:**

1. **LLM transcript persistence, a tunable (not D02-specific, but built to support reviewing D02's
   reasoning once it dispatches live).** New `model-config.json` field
   `invocation.save_llm_transcripts` (default `false`). When `true`, `claude_cli_invoker.py`
   additionally copies each dispatch's raw stream-json transcript and raw terminal response from
   its private `/tmp` diagnostics directory to
   `runs/<run_id>/data/llm-transcripts/<job_id>/<attempt_id>/{transcript.jsonl,raw-response.json}`
   -- durable, outside the attempt tree B14's contract scans, so it can never trip a
   MALFORMED_RESULT check, and never read back by any other code (diagnostics only). Wired in a
   `finally` around the whole dispatch, so a failed or timed-out attempt is captured too, not just
   a successful one -- gated by the tunable, and never itself raises. New
   `appsec-review-process/tests/test_claude_cli_invoker.py` (9 tests, all passing) covers the
   default-off behavior, the durable copy, a missing diagnostics file, missing run identity, and a
   nonexistent diagnostics directory -- all silent no-ops, never a raise. Default is `false`: a
   real (non-fixture) target's readable_inputs are the whole repo inlined verbatim, so a saved
   transcript can be as large and sensitive as the target itself; turn it on deliberately per
   review session. `scripts/system-acceptance-test.sh`'s automatic-mode `writes.allowed` for
   partition-discovery already covers the new path (added alongside, so the tunable can be
   exercised on stage 6 too, not just D02, without a further SAT contract gap).
2. **`appsec-review-process/02-evidence-pregather/dev-project-discovery.md` authored** (task
   prompt, `prompt_sections`' `task` entry). Scopes work to partitions the accepted map routed to
   `developer-engineer` (primary or supporting); tells the persona to enumerate manifests/
   lockfiles/workspace files per in-scope area, distinguish real project roots from vendored/
   generated/example code, choose a candidate buildenv image per project from the buildenv
   catalog, and produce an ordered, authorization-labeled (`read-only`/`network-required`/
   `script-execution-required`) safe command plan with concrete side effects and citations --
   proposing the plan, never executing it. Modeled directly on the existing supplied fixture
   (`fixtures/supplied/hello-autotools/02-dev-project-discovery.json`) so the live persona is asked
   for exactly the shape that fixture already demonstrates is achievable for this target.
3. **`registry/job-templates/02-dev-project-discovery.json`: `task_prompt` wired to the file
   above, `model` pinned to `claude-sonnet-5`/`medium`** (same reasoning as D01's pin -- this is a
   judgment call over an unknown target, not classification). Both are Fast-lane edits (job
   templates are not in AGENTS.md's Full-protocol list; this session already edited
   `02-repository-partition-discovery.json`'s own `model` field the same way during D01
   construction without objection).
4. **Structurally verified**: `persona_prompt_assembly.assemble_outer_prompt('02-dev-project-
   discovery')` succeeds and produces a pinned, hashed prompt file -- the task prompt, registry
   composition, and buildenv catalog all render cleanly together.

**Found, NOT fixed (Full-protocol scope -- this session deliberately did not touch it, the same
judgment call made about `design-parity-manifest.json` during Phase 5b): a real, pre-existing gap
in `registry/output-contracts/project-discovery.json` that will hard-block D02's first live
dispatch attempt.** Reproduced directly (not guessed): that output contract's `required_files` is
`["project-inventory.json", "project-discovery-summary.md", "safe-command-plan.json",
"status.json"]` -- four entries -- but `schemas/project-discovery.schema.json` (the
`result_schema.schema_file` for the *one* declared JSON result artifact, `project-inventory.json`)
already defines `safe_command_plan` as a top-level field **inside** `project-inventory.json`,
alongside `projects` and `coverage_gaps` -- there is no second JSON document. The existing supplied
fixture (`fixtures/supplied/hello-autotools/02-dev-project-discovery.json`) and both
`validate_job_output.py` and `scripts/system-acceptance-test.sh`'s own dev-discovery checks already
treat it as one document (`out.get('safe_command_plan', [])` off the single result). Only the
output contract's `required_files` list (and the job template's descriptive, non-authoritative
`outputs.files` list, which duplicates the same mistake) disagree. Left as-is, `claude_cli_invoker
.build_prompt_text` will raise `InvokerOutputError` on the very first live attempt, at the exact
line that checks every declared JSON required file against `result_schema.artifact` (added during
D01's bug-2 fix, Phase 5b item 8) -- confirmed by direct reproduction, not by reading the code and
guessing:
```
$ python3 -c "..." # walks required_files against result_schema.artifact
WOULD RAISE InvokerOutputError: 'safe-command-plan.json' is not the declared result_schema.artifact 'project-inventory.json'
```
**The fix is one line each, in two files**: drop `"safe-command-plan.json"` from
`required_files` in `registry/output-contracts/project-discovery.json`, and drop it from
`outputs.files` in `registry/job-templates/02-dev-project-discovery.json` (already touched this
evening for `task_prompt`/`model`, so this second edit is small in the same place). This is
squarely `registry/output-contracts/` = "worker contracts... output contracts" from AGENTS.md's
Full-protocol list, which needs the Independent work protocol (branch, batch claim) before editing
-- confirm with William whether this narrow, mechanical, already-reproduced fix can go in this same
D02 construction effort (as D01's schema/prompt fixes did, all Fast-lane files) or needs its own
formal batch first. **Do not skip this check and edit the output contract without asking** -- it is
explicitly called out as Full-protocol scope, unlike everything else D01/D02 construction has
touched so far.

**Output-contract gap: FIXED 2026-09-25** on branch `d02-output-contract-fix`, commit `e17e23e`
(William chose a separate Full-protocol branch; pushed, not merged): `safe-command-plan.json` is no
longer a required file of the `project-discovery` output contract or an output of the job template;
job catalog regenerated. Baseline for the branch: `qualify_phase1.py --check-contracts` fails with
`diagram drift` on untouched `origin/main` (`08f84ef`) too -- pre-existing and unrelated
(`docs/design-parity/job-graph.mmd` vs the rendered graph); not addressed in this batch.

**Automatic-dispatch wiring: BUILT 2026-09-25 and LIVE-CONFIRMED the same night (first attempt).**
Same branch. 47 focused tests, `bash -n`, design parity, catalog, then a real run on
`zarathustra`: fresh SAT `20260925T032354Z` (UTC), run `20260925T032715Z-440faf`, `--dispatch
--through dev-project-discovery` -- stages 1-7 PASS, stage 7's Dagster run `29545922`, ~65 s, 15
citations fresh, validator OK. The model identified `hello-autotools` (C++/C, autotools), image
`audit-buildenv-cpp:local`, and planned `autoreconf -fi`, `./configure`, `make`, `make check`
(`script-execution-required`) plus `docker build -t hello-autotools .` (`network-required`).
**Open finding (William's call):** live D01 routed the build manifests and the Dockerfile to
`devops-engineer` partitions, but this job's task prompt scopes work to `developer-engineer`
partitions -- D02 planned from those files anyway. Decide the scope wording (proposal: scope decides
which code gets a project; build manifests are readable wherever routed) and whether the
devops-routed `docker build` belongs in this plan or in D03.

- `persona_dispatch.build_request(upstream_root=...)`: optional second readable root
  (`UPSTREAM_ROOT_ID = "upstream-artifacts"`) pinning an upstream job's accepted artifacts;
  omitted, requests are unchanged (D01 unaffected).
- `claude_cli_invoker.py`: claims built per result schema (`_CLAIM_BUILDERS`;
  `_claims_from_project_inventory` = one `project_inventory` claim per project, one
  `safe_command_plan` claim per command, each rejected unless it cites a resolvable file); the
  upstream artifact is rendered under its own "Upstream Accepted Artifacts / NOT repository
  evidence" heading and excluded from citation resolution; fixed a latent `AttributeError` in
  `_citation_for` (a citation to an unpinned path was documented as "dropped" but crashed).
- `discovery_gate.py`: `_run_dev_automatic`, `_dispatch_dev_persona`, `_automatic_dev_inputs`,
  `_stage_upstream_partition_map`. Deliberately NOT on `coordinate_worker_lifecycle`: this job was
  never on the common envelope and its consumers read the legacy accepted-record shape
  (`accepted.json`, `attempts/<id>/output.json`); only the *source of the value* changed. The
  persona's own attempt tree lives under `persona-attempts/<id>/`. Orchestrator-owned fields
  overwritten after the response (lesson 2): `source_revision`, every citation `content_hash`, and
  `target` (from the accepted partition map). The input fingerprint includes the accepted partition
  map's hash, so a changed upstream re-dispatches. **Any live SAT after this must be fresh.**
- SAT: `--dispatch` now also puts stage 7 in automatic mode (same recorded `partition_dispatch`
  flag; D03/D04 stay supplied); accept contract + structural post-checks; fixture answer key diff is
  informational. Also fixed stage 6's contract to allow the `d01-partition` transcript path.
- Tests: `tests/test_dev_dispatch.py` (19 tests; the model call is stubbed everywhere).
- Judgment calls, not confirmed: the whole accepted partition map is passed to the persona rather
  than pre-filtered to developer-engineer partitions (the task prompt scopes it); BPMN and S2b
  diagram label unchanged (text-level change inside the existing box); a target with no buildable
  project was rejected as "nothing to claim" (same stance as D01 for zero partitions) -- **changed
  2026-09-25 (Phase 5d): now accepted when a coverage gap explains it.**

### Phase 5d -- D03: automatic persona dispatch for devops-project-discovery -- BUILT and LIVE-CONFIRMED

Built and confirmed 2026-09-25 on the same branch (`d02-output-contract-fix`). Fresh SAT
`20260925T044159Z`, run `20260925T044606Z-ee7f02`, `--dispatch --through devops-project-discovery`:
stages 1-8 PASS on the first attempt (D03 Dagster run `f8b78648`, ~38 s). Result: one unit
`container-image` (Dockerfile, base `debian:bookworm-slim`), plan `docker build -t container-image .`
(`network-required`), 10 coverage gaps, 2 fresh citations.

- Task prompt `02-evidence-pregather/devops-project-discovery.md`, composed from three independent
  drafts (Opus structure; no-placeholder argv rule; `status.json` is runtime-supplied; zero-unit
  clause). Job template `02-devops-project-discovery.json`: `task_prompt` added, model pinned to
  `claude-sonnet-5`/`medium` like D02, the unsupported `pipeline_artifacts` prompt section replaced by
  `buildenv_catalog` (it would have raised "unknown prompt section" at assembly), `outputs.files`
  trimmed to the contract's real files.
- `discovery_gate.py`: one shared path for D02 and D03 (`AUTOMATIC_PROJECT_JOBS`,
  `_run_project_automatic`, `_dispatch_project_persona`, `_automatic_project_inputs`); persona
  identities `d02-devproject` / `d03-devops`. `02-sre-operations-topology` is deliberately not in the
  map (different upstream, schema and claim builder).
- `claude_cli_invoker._claims_from_project_inventory`: a result with no project and no command is
  valid when `coverage_gaps` says why (the schema has no minimum on `claims`), rejected otherwise.
- SAT stage 8 `--dispatch`: same checks as stage 7 plus two that test the prompt's own boundaries
  (no native build tool as `argv[0]`; no deploy/publish-style token). Fixture diff informational.
- Tests: `tests/test_dev_dispatch.py` extended (D03 routing and identity, the zero-unit rule, the
  SRE job rejected). William ran the focused suites (`test_dev_dispatch`, `test_worker_adoption`,
  `test_claude_cli_invoker`) after the live run: **50 tests, all OK** (47 before D03).
- **Accepted by William:** both D02 and D03 may read the Dockerfile; the duplicate `docker build`
  entries (`-t hello-autotools` vs `-t container-image`) are left for the build lane to reconcile.
- **Fixed 2026-09-25 (prompt wording only; not yet re-run live):** D03's image tag came from the
  project's own generic ID (`container-image`), which carries no meaning. The prompt now says to take
  an image name or tag from what the repository declares, else the target's own name (the `target`
  value in the accepted partition map), never a generic unit ID. Confirm on the next fresh SAT
  (`--dispatch --through devops-project-discovery`): the plan's `-t` value should be
  `hello-autotools` or a repository-declared name, not `container-image`. No process or diagram
  change (flow, gates, steps and order are unchanged).
- **Open:** the D02 scope wording (build manifests readable wherever routed) is still not changed; low
  priority since the live D02 run behaved sensibly.

**Next:** (1) merge review for branch `d02-output-contract-fix` (Full-protocol contract fix
`e17e23e`, D02 `9434b2b`, records, D03) -- not merged; (2) D04 (`02-sre-operations-topology`):
different upstream (the accepted devops record, `output.json`, not the partition map), different
schema (`operations-topology.schema.json`) and its own claim builder -- not a mechanical repeat of the
project-discovery path; (3) write the D04 continuation prompt and update
`docs/continuation-prompts/2026-09-24-d02-dev-project-discovery-construction.md`'s status; (4) the
`diagram drift` failure of `qualify_phase1.py --check-contracts` is still untriaged.

### Phase 5e -- D04: automatic persona dispatch for sre-operations-topology -- BUILT and LIVE-CONFIRMED

Branch `d04-sre-operations-topology-dispatch` (cut from `main` = `3f7b283`). Closes the last supplied
discovery stage: with `--dispatch`, SAT stage 9 still installs the hand-authored fixture
(`fixtures/supplied/hello-autotools/02-sre-operations-topology.json`), which tests the schema, not
the system.

**Decisions (William, 2026-09-25):**

1. `live-state-followups.json` dropped from the `operations-topology` contract's `required_files` and
   the template's `outputs.files` (Full-protocol, own commit `aedb4eb`) -- same bug and fix as D02's
   `safe-command-plan.json`: the invoker only renders a schema for `result_schema.artifact`, so the
   first live dispatch would fail before the model is called. Live follow-ups go in
   `operational_notes`, each prefixed `Live follow-up:`.
2. Zero services is valid only when `coverage_gaps` says why (the D03 rule); otherwise rejected.
3. Upstream scope = the accepted devops record **and** the accepted partition map. Both are staged
   into one content-addressed `upstream/<digest>/` directory (`devops-project-inventory.json`, a copy
   of `02-devops-project-discovery`'s `attempts/<id>/output.json`; `repository-partition-map.json`),
   because `persona_dispatch.build_request(upstream_root=...)` pins every regular file beneath one
   root. Both are scope, never evidence.

**Design:**

- Read first (2026-09-25): role `operations-topology-mapper` allows `service_inventory`,
  `runtime_dependency_map`, `health_check_inventory`, `observability_gap`, `live_state_followup`;
  profile `static-ops-topology-inspector` has no `allowed`/`forbidden` lists, and its
  `observed_topology: forbidden` key only adds to the prohibited set. `claim_ceiling` therefore
  allows all five role outputs.
- Claim builder `claude_cli_invoker._claims_from_operations_topology` (for
  `operations-topology.schema.json`): one `service_inventory` claim per service, one
  `runtime_dependency_map` claim per dependency, citations resolved only to pinned target files; a
  claim with no resolvable citation is a hard rejection. `operational_notes` and `coverage_gaps` are
  plain strings with no evidence of their own and stay in the artifact (same reasoning as D02).
  No services and no gap is rejected.
- `validate_job_output._operations_topology_errors` requires every `dependencies[].target_service_id`
  to be a service in the same record, so a dependency on something the repository does not declare as
  a service (an external database, a registry) cannot be a dependency entry. The prompt routes those
  to `operational_notes`/`coverage_gaps`.
- `discovery_gate.py`: the D02/D03 path is generalized to a per-job spec (persona id, result and
  summary file names, upstream list), so D04 shares `_run_project_automatic`'s acceptance steps
  (schema, `_require_upstream_inputs`, and the unchanged `accepted.json`/`attempts/<id>/output.json`
  shape stage 9's consumers read). Persona identity `d04-sretopology`. Orchestrator overwrites
  `source_revision`, `target` (from the partition map, as in D02/D03) and every citation
  `content_hash`. The fingerprint covers both upstream files. Fix the wrong comment above
  `DEV_PERSONA_JOB_ID` (the id is 24 characters; the scanner needs 32+; the short ids are convention).
- Template `02-sre-operations-topology.json`: `task_prompt`
  (`02-evidence-pregather/task-sre-operations-topology.md`), model pin `claude-sonnet-5`/`medium`, and the
  unsupported `ops_artifacts` prompt section removed (it would raise "unknown prompt section"; the
  buildenv catalog D03 used in its place is irrelevant to topology).
- SAT stage 9 `--dispatch`: mirrors stage 8 (dispatch-mode step, accept contract with the extra
  allowed writes, structural checks: at least one service or an explaining gap; unique ids; every
  dependency resolves; same `target`/`source_revision` as the accepted devops record; every service
  and dependency cites evidence). Fixture diff informational.
- Tests beside `tests/test_dev_dispatch.py` (model stubbed): claim builder, upstream staging of both
  files, routing and identity, the zero-service rule.

**Built 2026-09-25:** task prompt + template (`31ff6b5`); gate wiring (`AUTOMATIC_JOBS`, two-file
upstream staging, `d04-sretopology`) and `_claims_from_operations_topology` (`bfe12c6`); 10 new tests,
62 OK on William's Windows/Python 3.13; SAT stage 9 `--dispatch` branch and docs (SAT doc stage 9
subsection and gaps table, engagement-start).

**Live 2026-09-25:** fresh SAT `20260925T170552Z`, run `20260925T170620Z-c6a12e`, stages 1-9 PASS
(hal5000 WSL). Stage 9 Dagster `6ea8a93b`, ~31 s: `hello-autotools` (`cli-batch`), 6 gaps, 9 notes
(2 live follow-ups), 3 fresh citations. Two prompt-wording fixes found live first: D01 coverage path
fields (`e915d92`) and the invoker envelope's nested-object rule (`97eeb3d`); see flow-bringup.md log.

**Decided (William, 2026-09-25):** no run step in discovery plans. D03 had also planned `docker run
--rm hello-autotools World`; the devops prompt now forbids running what a definition builds, and SAT
stage 8 fails on a `docker`/`podman`/`nerdctl` `run`/`exec`/`start` or `compose up`/`run` entry.
Containers stay static in discovery; the build lane builds the images and never runs them. Running a
built target (fuzzing, dynamic testing) is a later TODO (last section of this file). **Confirmed
live 2026-09-25:** fresh `--dispatch` SAT through `devops-project-discovery`, run `20260925T173117Z-055b25`, Dagster `d0f5fd8d`: stage 8
PASS with the plan `docker build -t hello-autotools .` [network-required] and no run step.

### Phase 5f -- build lane dependency restore: public registries for the POC; local mirror deferred -- TODO

Design: `docs/processes/build-unit-classification.md` (draft, 2026-09-25). Decided by William,
2026-09-25: **for the POC, dependencies are fetched straight from each ecosystem's public registry**,
verifying TLS certificates and content hashes. A local caching proxy is deferred because it reaches
outside this project (a separate service to run, own, update and back up).

POC rules (apply to every ecosystem):

- Restore happens only in the provisioning step, under a `package-restore` grant naming the exact
  public host(s); the trial stays `--network none` and builds offline against what was restored.
- TLS: normal certificate and hostname verification against the system CA store; never disabled,
  never a custom insecure trust setting.
- Hashes: every downloaded artifact is checked against the hash the repository's own lockfile pins
  (`package-lock.json` `integrity`, `Cargo.lock` `checksum`, `go.sum` plus the Go checksum database,
  `packages.lock.json` `contentHash`, Gradle `verification-metadata.xml`). A mismatch fails the
  restore. Where the repository pins no hash (no lockfile; plain Maven), the registry's published
  checksum is used and recorded as a **weaker, registry-vouched** check, plus a coverage gap.
- Record every downloaded artifact (name, version, source URL, hash, which check applied) in the
  attempt, so a result can be audited and replayed.

TODO:

- [ ] Confirm the grant model allows more than one `package-restore` entry per ecosystem: cargo needs
  `index.crates.io` and `static.crates.io`; Go needs `proxy.golang.org` and `sum.golang.org`; Gradle
  may need `plugins.gradle.org` beside `repo.maven.apache.org`. A grant is one exact host.
- [ ] Verify the public host list per ecosystem (npm `registry.npmjs.org`, Maven Central
  `repo.maven.apache.org`, Go, crates.io, NuGet `api.nuget.org`) against current registry docs; hosts
  above are from memory.
- [ ] Per-ecosystem restore/offline-build argv for the resolution loop (`npm ci`, `cargo fetch` then
  `cargo build --locked --offline`, `go mod download` then `GOFLAGS=-mod=readonly GOPROXY=off`,
  `mvn dependency:go-offline` then `mvn -o`, `dotnet restore` then `--no-restore`), and how install
  scripts (npm lifecycle scripts, `build.rs`) are handled: they need `target-execution` too.
- [ ] **Deferred (external dependency):** a local caching proxy (Nexus/Artifactory, or
  Verdaccio/Athens per ecosystem) as the single fixed host per ecosystem. Decide product, host and
  ownership before it is built; it replaces the public hosts in the grants and nothing else changes.

### Phase 6 -- build and compile database (E01, E02)

- E01 `02-build-configure`: B13 + `audit-buildenv-cpp`, replays the lock's configure argv
  (`autoreconf -fi`, `./configure`), common-runtime adoption, provenance (image digest, lock hash,
  source revision).
- E02 `02-native-build`: `bear -- make` and `make check` prerequisites, produces
  `compile_commands.json`, objects, binaries and logs as run-owned artifacts; variant = the lock's
  single variant for now.
- Done when: both accepted on the fixture with `CONFIGURE_OK`, a 3-entry compile database and the
  `hello` binary recorded with hashes.

### Phase 7 -- static evidence off intake (parallel; one batch each)

| Node | Batch | Tool / image | Fixture expectation |
|---|---|---|---|
| `02-source-sast` | D09 | Semgrep in `audit-static` | 3 unconditional hits (VULN-01 `strcpy`, VULN-02 format string, VULN-04 `memcpy` behind macro+template) + VULN-03 (command injection) as a reachability case behind `--report` |
| `02-secrets-inventory` | M03 | gitleaks in `audit-static` | clean; V06 redaction receipt present |
| `02-iac-config-scan` | M03 | `audit-iac` | `SKIPPED(not-applicable-no-matching-inputs)` |
| `02-sbom-inventory` | M05 | syft in `audit-static` | valid SBOM with **one** component: vendored cJSON 1.7.18 (not zero -- updated when the fixture gained a vendored dependency) |
| `02-license-scan` | M05 | `scancode-toolkit` | project licence (MIT) plus vendored cJSON's licence (MIT) -- two components, same licence text |
| `02-dependency-lifecycle` | M05 | `analyze_dependency_lifecycle` + `data/eol-reference.json` | cJSON isn't in a lifecycle/EOL-tracked product family, so still empty/`unknown`-never-inferred-current is the expected outcome even with a real dependency present |
| `02-sca-vulnerability-match` | M05 + V16/V17/V18 | Grype with mirrored DB, OSV snapshot | **one** match, not zero -- vendored cJSON 1.7.18 against **CVE-2025-57052** (published, affects 1.5.0-1.7.18). This is the fixture's actual test of match accuracy, not just of the zero-input skip path (the publishers are still the real work here) |
| `02-container-image-inventory` | M04 (after M02) | `audit-container` | `SKIPPED` zero-input receipt |
| `02-binary-hardening` | M04 | `audit-binary-analysis` | `SKIPPED` (no supplied binaries) |
| `02-mobile-sast` | M04 | mobile SAST in `audit-static` | `SKIPPED` |

- Each worker: own attempt allocation writing only the closed set (owner decision 2026-09-21),
  vendor-prepass contract validation (`validator-vendor-prepass-dispatch.md`), fixtures for
  clean / hit / tool-error / timeout / cancel / reuse / recovery, then the fixture live run.
  Delete the replaced `pipeline/Invoke-VendorAuditPrePass.*` step for each node as it lands
  (V10-V14 in the vendor-prepass task series); no wrapper.

### Phase 8 -- native evidence chain (E03-E10)

- E03 `02-native-sast` (clang-tidy, cppcheck, CSA in `audit-native`; expect the same 3
  unconditional hits as `02-source-sast` -- VULN-01, VULN-02, VULN-04 -- and the same
  `--report`-gated VULN-03 reachability case; VULN-04 (`src/store.h`) is the one worth checking
  per-tool, since it's only visible if the tool expands the `STORE_INTO` macro and instantiates
  the `copy_into_fixed<16>` template rather than analyzing pre-expansion source),
  E04 `02-ir-capture`, E05 `02-ir-link` + `02-ir-facts`, E06 `02-debug-symbol-index`,
  E07 `02-binary-triage` (after the M02 image decision), E08 `02-binary-cfg` +
  `02-binary-intelligence-ingest`, E09 `02-test-execution` (`make check`; the first job to declare
  a `target-execution` capability requirement, so B11 gets its first grant record and its
  qualification), E10 `02-test-result-ingest` + `02-test-coverage-ingest`.
- Done when: each accepted on the fixture; IR facts name `greet` and `main`; test ingest records
  one passing test.

### Phase 9 -- intelligence ingests and the standards gate (D05-D08, S01)

- D05-D08 and `02-api-collection-intelligence-ingest`: on the fixture these are zero-input
  (`README.md` only) and must end accepted-empty or `SKIPPED` with receipts -- the skip paths are
  the test.
- `02-standards-source-ingest` (S01) is blocked on the G02/G03 human gates yet is a required
  input of `02-evidence-assembly`. Decision needed before phase 10: either resolve G02/G03, or
  add `decision-pending` to that edge's `allowed_skip_reasons` for fixture qualification only,
  recorded in the parity manifest as a gap.

### Phase 10 -- assembly rendezvous (F01, F02; first Dagster consumer of C01/C02/B15)

- F01 evidence-index enrichment over the accepted step-4 outputs.
- F02 `02-evidence-assembly`: a wait-all rendezvous (C02) over the `02-*` set expressed as a pool
  specification (C01), running under the B15 pools -- which also closes B15's owed live step 8
  and takes C01/C02 from unit level to qualified.
- Done when: `02-evidence-assembly` accepted on the fixture with a terminal-instances manifest
  listing every node and its state.

### Phase 11 -- close-out

- Parity manifest: every step-4 capability `implemented_and_qualified` or a declared gap;
  regenerate the four views; `docs/design-parity/design-parity-completion-plan.md` D1-D3 checked.
- `docs/processes/evidence-collection.md`: the step-4 runbook (fixture commands, expected states,
  how to read the assembly manifest); update `engagement-start.md` so step 4 is no longer a fork.
- Q02 (real supplied discovery/build chain) then runs the same graph on the first real target.

### Fixture addendum -- polyglot multi-ecosystem fixture (parallel track, not on the hello-autotools critical path)

A second target repository (name TBD, e.g. `hello-polyglot`), following the same rule as
hello-autotools: tracked as its own repo, cloned into `fixtures/targets/`, not committed into
this tree. One hello-world component per ecosystem the catalog claims `auto` support for --
Java, Go, Node/TypeScript, a VC++ `.sln`/`.vcxproj`, Rust -- each with its own small seeded defect
so SAST/SCA nodes get a real hit per ecosystem instead of only exercising zero-input skip paths,
mirroring the vendored-cJSON choice in hello-autotools. It exists to prove two things
hello-autotools's single C++ root cannot: that `02-repository-partition-discovery` correctly
enumerates more than one build root, and that the provisioning loop's detect/hydrate/infer/build
cycle generalizes across ecosystems, including the ambiguous-marker case (`*.sln` currently
matches both the `cpp` and `dotnet` catalog entries). Unity and Unreal are not included here --
they are `supplied`-only and get their own licensed, human-provisioned fixture image if/when
that's prioritized, not a hello-world in this repo. Has its own done-when bar; does not block or
extend hello-autotools's ten-minute target.

## Workstream B Batch 8 checkpoint (2026-09-19)

- [x] Add fully resolved immutable registry handoffs and bounded run-owned input hashes.
- [x] Add the dedicated project-discovery result schema without enabling persona dispatch.
- [x] Adopt the common envelope and separated publication boundary in exactly
  `02-ossf-scorecard` and supplied `02-repository-partition-discovery`.
- [x] Qualify Windows/Linux validation plus live Dagster publication, reuse, newer-failure
  blocking, and recovery. See `docs/continuation-prompts/design-parity-worker-envelope.md` for run IDs.
- [x] Centralize collision-safe allocation, fail-closed `PENDING`/`latest.json` movement,
  interrupted-attempt recovery, and durable `BLOCKED`/`FAILED`/`CANCELED` envelopes for exactly
  the same two adopted workers. Worker execution and process control remain local.
- [x] Centralize immutable reusable-candidate admission and successful terminal persistence for
  those same two workers, including recovery of a validated `CURRENT` envelope left behind a
  `PENDING` pointer. Matching corrupt or stale pointers fail closed.
- [x] Centralize the per-job lock, reuse decision, interrupted-attempt recovery/allocation, and
  exception-to-terminal routing for those same two workers. Preflight failures become `BLOCKED`,
  post-allocation work/validation failures become `FAILED`, and `KeyboardInterrupt` becomes
  `CANCELED` without changing the exception observed by Dagster or writing a second terminal.
- [x] Qualify the Batch 7 lifecycle coordinator on Windows and Linux plus the actual Dagster
  service.
- [x] Add `appsec-review/deterministic-child/1.0` as an argv-only execution boundary with a fixed
  executable/prefix, explicit environment, timeout, bounded concurrent stdout/stderr draining,
  cancellation diagnostics, and complete child-tree cleanup.
- [x] Adopt that child boundary in exactly `02-ossf-scorecard`; supplied repository partition
  discovery has no child and remains unchanged.
- [x] Fault-inject timeout, cancellation, simultaneous stream pressure, retained-log truncation,
  child loss, and log-write failure on Windows and Linux, then exercise a real published Scorecard
  API ingest through Dagster. Exact identities and evidence are in the continuation prompt.

This list is ordered by the current Dagster/run-owned architecture. New work should preserve the
rule that accepted evidence lives under `runs/<run_id>/data/`, with immutable attempts and explicit
publication through `accepted.json`.

The cross-cutting implementation and acceptance backlog for parity with `docs/architecture/design-v3.md` is
[`docs/design-parity/design-parity-completion-plan.md`](../docs/design-parity/design-parity-completion-plan.md). It is the
authoritative checklist for pools, all lifecycle jobs, personas, feedback loops, standards decision
gates, and final end-to-end qualification. Continue the next bounded Workstream B batch with
[`docs/continuation-prompts/design-parity-worker-envelope.md`](../docs/continuation-prompts/design-parity-worker-envelope.md).
The sections below retain
subsystem-specific detail.

## Independent work protocol

Scope: this protocol applies only to changes to the Dagster runtime (`orchestrator/dagster/`,
`dagster_workflow.py`, `launch_job.py`), the job graph (`job-graph.json`,
`design-parity-manifest.json`) and the worker contracts (`worker-result-contract.json`, output
contracts, validators). Changes under `pipeline/`, `scripts/`, `data/`, `images/` and `docs/` are
the fast lane: no batch claim, no shared-surface lock, no qualification, only a normal pull
request (see `AGENTS.md`).

The batch IDs below are the executable backlog. An agent may claim exactly one `READY` batch at a
time. The older subsystem lists later in this file explain context but are not standalone work
orders unless a batch points to them.

For every batch:

- Start from current `origin/main` on a dedicated branch. Do not commit directly to `main` and do
  not merge the branch. Report the branch and commit so the integrator can review it.
- Read `AGENTS.md`, `docs/agent-reader.md`,
  `docs/dagster/run-data-and-job-execution.md`, and the batch's named source documents before editing.
- Preserve unrelated work and ignored run evidence. Never reset, clean, stash, rewrite historical
  attempts, delete locks, or make old evidence look current.
- Treat every path listed under **Shared surfaces** as exclusive. Only one active batch may edit
  those paths. A batch may add its named worker/schema/test paths without claiming unrelated files.
- Do not infer Workstream G decisions. A decision batch records options and an explicit user gate;
  a dependent implementation stays `BLOCKED` until the ADR is approved.
- New or migrated jobs must use run-owned immutable attempts, the common terminal envelope,
  read-only validation, fail-closed publication, newest-failure blocking, explicit recovery, and
  exact permission checks. A registered job or green process exit is not acceptance by itself.
- Minimum local acceptance is focused tests, `python -B -m py_compile` for changed Python,
  `python -B appsec-review-process/validate_design_parity.py`,
  `python -B appsec-review-process/qualify_phase1.py --check-contracts`, and
  `git diff --check`. Run the focused suite in the Linux code-server too.
- If Dagster registration, worker execution identity, lifecycle wiring, sensors, or launcher
  behavior changes, check for active runs first and perform a bounded live service qualification.
  Record run IDs, attempt IDs, report path/hash, image identity, failure injection, and recovery.
- A batch result must state scope included/excluded, files changed, commands and counts, evidence,
  limitations, and the next unblocked batch. Missing prerequisites mean `BLOCKED`, not improvised
  scope expansion.

Shared surfaces are `appsec-review-process/job-graph.json`,
`appsec-review-process/design-parity-manifest.json`, `appsec-review-process/dagster_workflow.py`,
`appsec-review-process/launch_job.py`, `orchestrator/dagster/definitions.py`, common runtime modules,
generated parity views, and this TODO. Batches that name any of them must run sequentially.

Status vocabulary: `READY` means independently executable now; `BLOCKED(<ids>)` names required
predecessors or decisions; `HUMAN_GATE` produces an ADR/options packet but may not choose policy;
`INTEGRATION` combines already-qualified producers and should not invent missing worker behavior.

Implemented baseline job nodes are `00-intake`, `02-ossf-scorecard`, and `02-evidence-index`.
Every one of the 51 graph job IDs appears in this backlog; a later batch may harden an implemented
node without changing the honest current readiness flag. (42 until 2026-09-20; ADR-0010 task V02
declared the nine vendor-prepass nodes named under M03, M04 and M05, all `implemented: false`.)
A closed decision batch is marked `DONE` with the accepted ADR that closed it; `DONE` is not a
worker-readiness claim.

Cross-cutting capability ownership is explicit:

| Manifest capability | Owning batches |
|---|---|
| `common-worker-result-envelope` | B09, B10, B13, B14 |
| `dedicated-resource-pools` | B15 |
| `persona-tool-pool-dispatch` | C01 |
| `wait-all-rendezvous` | C02 |
| `deterministic-pool-merge` | C03 |
| `evidence-qualified-quorum` | C04 |
| `claim-ledger-routing` | L01 |
| `remediation-retest-feedback` | L09 |
| `dynamic-rescope` | L10 |
| `completeness-feedback` | L11 |
| `synthetic-hypothesis-resynthesis` | L11 |
| `threat-model-standard` | G01, S02 |
| `owasp-checklist-model` | G02, S03 |
| `disa-nsa-hardening-model` | G03, S04 |
| `final-publication-gate` | L12 |

## Dependency-ordered implementation batches

### Runtime foundation

#### B09 — Critical-findings SARIF common-runtime adoption — QUALIFIED

- Depends: Batch 8 checkpoint.
- Deliver: migrate standalone `10-critical-findings-sarif` to the common lifecycle, envelope,
  validator/publication boundary, and deterministic-child contract without changing its strict
  fixed-input Markdown-to-SARIF semantics.
- Primary paths: `critical_findings_sarif.py`, its focused test, SARIF output contract/schema,
  `publish_job_output.py` only if a proven generic gap exists, qualification script/docs, and the
  shared registration/parity surfaces only where identity or readiness changes.
- Acceptance: semantic parity fixture; success/reuse/force/tamper; preflight/work/cancellation;
  timeout/stream/child/log faults; pending-publication recovery; interrupted attempt; no fallback
  after newer failure; Windows/Linux tests; one live success/reuse/failure/recovery sequence.
- Excludes: synthesis binding, developer discovery, containers, personas, pools, and standards.
- Status: the migration is implemented on branch `claude/b09-sarif-common-runtime`.
  `critical_findings_sarif.py` now runs through `coordinate_worker_lifecycle`, the v1.0
  worker-result envelope, the read-only validation/publication boundary and
  `appsec-review/deterministic-child/1.0`; the `critical-findings-sarif` contract declares
  `schemas/critical-findings-sarif.schema.json` as its single result schema; conversion semantics
  are pinned by a golden fixture; 13 focused tests plus the generic adoption and child suites pass
  on Linux. Windows host focused tests passed on 2026-09-20, and the bounded live Dagster
  success/reuse/newer-failure/recovery sequence passed in owner run
  `20260920T003602Z-41cea7`; report:
  `appsec-review-process/runs/20260920T003602Z-41cea7/data/qualification/sarif-adoption-e96975cb/report.json`,
  SHA-256 `e1b00bdbbc85fbf324cf9d79edb5117541e9e45009bf484bc12938bbe9860caa`.

#### B10 — Supplied developer-discovery common envelope — BLOCKED(B09)

- Deliver: migrate only the existing supplied `02-dev-project-discovery` gate to the same common
  allocation, terminal, validation, publication, reuse, and recovery boundary. It remains supplied
  human/agent data and performs no automatic analysis.
- Primary paths: `discovery_gate.py`, `project-discovery` contract/schema, focused adoption tests,
  qualification evidence, and parity/docs. Do not touch repository partition behavior except
  shared regression coverage.
- Acceptance: schema/citation/cross-ID/claim-class/secret rejection, immutable reuse, invalid-newer
  blocking, interrupted recovery, Windows/Linux tests, and live supplied-result qualification.

#### B11 — Permission-capability model — IMPLEMENTED_NOT_QUALIFIED (PR #6, merged 2026-09-20; consumed by B13/B14/C01/C02, no job declares a requirement yet)

- Status 2026-09-21: the evaluator, seven schemas and seven registry records exist and are
  imported by `container_execution.py`, `persona_invocation.py`, `pool_specification.py` and
  `pool_rendezvous.py` (fingerprint folding; C01 re-evaluates at expansion). Not wired into any
  lifecycle worker, the launcher, the graph or the handoff builder; no parity capability tracks
  it. Remaining work is the eleven integration follow-ups in
  `docs/adapters/permission-capabilities.md`.

- Deliver: versioned capability records and validation for target execution, fixed network
  destinations, dynamic testing, debugger/ptrace, credentials, package restore, and target
  mutation. Default deny; exact capabilities become part of the input fingerprint.
- Primary paths: new permission schema/registry module/tests and permission documentation. Changes
  to shared manifest/graph/launcher are integration-only and require exclusive ownership.
- Acceptance: unknown, widened, target-controlled, missing, stale, and conflicting permissions all
  fail before work; redaction tests prove credential values never enter tracked or UI-safe records.

#### B12 — Operator status and resume detail — BLOCKED(B09,B10)

- Deliver: `review_cli.py status` reports job, worker kind, attempt, upstream generation,
  permission decision, execution/acceptance status, coverage gaps, evidence pointer, and actionable
  resume prerequisite for common-runtime workers plus existing build/evidence-index jobs.
- Primary paths: `review_cli.py`, focused status tests, operator docs; no worker behavior changes.
- Acceptance: current, pending, failed-newer, canceled, corrupt, stale, and missing-prerequisite
  fixtures on Windows/Linux; status remains read-only.

#### B13 — Pinned-container argv adapter — DONE (PR #29, merged 2026-09-21; no lifecycle worker migrated yet)

- Deliver: one versioned adapter that accepts only registry-resolved image digests and argv arrays,
  uses the maintained wrapper, read-only target mounts, run-owned writable scratch, disabled network
  by default, resource limits, and bounded diagnostics. No shell strings or raw `docker run`.
- Primary paths: `worker_adapters.py`, new container execution module/schema/tests, wrapper identity
  docs, permission integration. Do not migrate a lifecycle worker in this batch.
- Acceptance: hostile argv/mount/image/network/capability cases, timeout/cancel/worker-loss/log
  failure, Windows-host/Linux-worker parity, and a harmless pinned fixture container.
- TODO (owner, 2026-09-21; from the PR #29 review): decide whether `verify_container_result` /
  `load_verified_result` / `to_worker_envelope` should REQUIRE an externally held
  `expected_result_sha256` (the hash `run_container` returned, kept where the attempt cannot reach).
  Today the verifier's checks are consistency checks: an edit to the result or to any one file is
  caught, a consistent rewrite of every file in the log directory is not
  (`docs/adapters/pinned-container-adapter.md`). Decide before C02 or the first migrated worker calls the
  verifier; adding a required argument afterwards touches every caller.

#### B14 — Persona invocation adapter — DONE (PR #32, merged 2026-09-21; dispatch protocol only)

- Deliver: isolated invocation request/result contract pinning outer prompt, selected persona,
  model/tool identity, budget, exact readable inputs, writable output root, and prohibited claims.
  Implement dispatch protocol only; do not enable a lifecycle persona job.
- Primary paths: `worker_adapters.py`, new persona request/result schemas, tests, persona registry
  validation, and docs.
- Acceptance: hostile prompt/evidence cannot widen scope, permissions, claim class, or output path;
  missing model identity, unbounded context, self-verification, and malformed result fail closed.
- Owner decision 2026-09-21 (PR #32 review): B14 checks independence against DIRECT producers only
  and that is accepted -- the adapter sees one request at a time. Independence of a whole chain
  (P1 produces, P2 verifies, P1 judges P2's result) is a requirement of C02 and C04, below.

#### B15 — Dedicated resource pools — IMPLEMENTED_NOT_QUALIFIED (PR #33; live qualification step 8 owed)

- Deliver: named Dagster pools for CPU, memory, Docker, network, persona/LLM, and dynamic-analysis
  work while preserving global and per-engagement outer limits. Record an explicit unassigned state.
- Primary paths: Dagster configuration/definitions, parity manifest/validator, queue tests, operator
  docs. Do not raise concurrency until measured.
- Acceptance: service tests prove per-pool limits, fairness, cancellation, restart behavior, and
  unchanged engagement serialization; record load evidence before any limit increase.
- Status 2026-09-21: six pools, the explicit unassigned state, the guard sensor and the pool-state
  evidence document are implemented; the parity manifest assigns the six jobs that have workers.
  Live service qualification run on the Linux host (`docs/pools/resource-pools.md`, record of
  2026-09-21): per-pool limits, fairness, engagement serialization, cancellation, restart, drift and
  the evidence document PASS. Owed: step 8 (`kill -9` of a run worker and its step child), which
  the coordinator session was not permitted to run. Finding: a terminated run that holds a slot
  frees it only through `free_slots_after_run_end_seconds` (about 150 s), so that setting must stay.

### Pool runtime

#### C01 — Pool specification and deterministic instance expansion — IMPLEMENTED_NOT_QUALIFIED (PR #34 in review; unit level, no consumer yet)

- Deliver: versioned pool schema covering lane, worker kind, persona/tool identity, count, scope,
  inputs, budget, permissions, timeout, pool, and `wait_all`; deterministic unique instance IDs and
  private run-owned roots.
- Primary paths: new pool schema/runtime/tests and parity capability record.
- Acceptance: zero/one/many, duplicates, mixed kinds, invalid counts/scopes, ID collisions, and
  cross-instance path access.
- Status 2026-09-21: `pool_specification.py`, its four schemas and `docs/pools/pool-specification.md`
  deliver the specification, the deterministic expansion and its verifier; the parity capability
  `persona-tool-pool-dispatch` records qualification level `unit` and stays
  `missing_prerequisites` (no launcher; no lifecycle job consumes a pool specification). Portable
  tool mounts (`mount_root_id` + relative path) are the coordinator's recommendation, owner to
  confirm. Next: C02.

#### C02 — Wait-all rendezvous and terminal-instance manifest — IMPLEMENTED_NOT_QUALIFIED (PR #35 in review; unit level, no Dagster op yet)

- Deliver: bounded non-busy waiter that observes every expected instance to a terminal state and
  publishes a manifest without treating missing workers as empty success.
- Acceptance: late finish, failure, timeout, cancel, crash, restart, duplicate terminal, and missing
  instance; publication never occurs early.
- Requirement (owner decision 2026-09-21): C02 builds a reviewer's producers from verified results
  and is the first component that sees a chain. It owns chain independence: consider every ancestor
  of the pinned producer results, not only the direct producers B14 checks.
- TODO: consider how to enforce that (refuse at dispatch, or record and let C04 discount), and
  whether B14 should additionally walk pinned producer results recursively.
- Status 2026-09-21: `pool_rendezvous.py`, its two schemas and `docs/rendezvous/pool-rendezvous.md` deliver the
  launch, the wait, the classification rule (eleven states, closed `state_reason`) and the
  terminal-instance manifest with its verifier and reader; the parity capability
  `wait-all-rendezvous` records qualification level `unit` and stays `missing_prerequisites`.
  NOT done: no Dagster op runs it; producers and chain independence (the requirement above) are not
  implemented (C02b/T10); in-process caps see only their own rendezvous (see the owner
  decision below) until instances are pooled ops.
  `state_reason` is the coordinator's recommendation, owner to confirm. Next: C03 / T10.
- Owner decision 2026-09-21 (PR #35 review, Q2, clarified the same day): **one engagement at a time
  for now** -- the review processes themselves are not concurrent, so there are never two OWASP
  pools at once. INSIDE an engagement concurrency is fine: forked branches may each run their own
  rendezvous (OWASP review in A, red/blue team in B). T10 must put a run-level tag with a tag
  concurrency limit of 1 on the job whose op calls `run_rendezvous`, and does not merge without it;
  until then this is an operating rule (the run queue still admits two engagements).
- TODO (open gap `in_process_caps_do_not_see_other_rendezvous`): pool lanes launch in-process and
  are invisible to B15's pools, and each rendezvous sees only itself, so k concurrent rendezvous of
  one engagement can run k containers (`docker` limit 1) and 3k persona invocations (`persona_llm`
  limit 3), and `persona_slot_request` is taken per pool rather than per run. Closes when instances
  are dynamically mapped pooled ops with C02 as the collector (target design). Decide whether that
  lands before the first engagement forks two pool lanes.

#### C03 — Deterministic typed merges — BLOCKED(C02)

- Deliver: separate stable merges for persona claims, deterministic tool evidence, and coverage
  receipts. Mixed pools retain types and failures instead of flattening them.
- Acceptance: order independence, duplicate IDs, malformed result, partial failure, degraded
  coverage, stable hashes, and immutable reuse.

#### C04 — Evidence-qualified quorum and diversity accounting — BLOCKED(C03)

- Deliver: claim-keyed quorum using evidence and declared persona/model independence; record unmet
  diversity without inferring independence from worker count.
- Acceptance: duplicate personas/models, conflicting claims, missing citations, minority dissent,
  insufficient quorum, and deterministic recomputation.
- Requirement (owner decision 2026-09-21): a persona or model that appears earlier in a claim's
  chain is never counted as independent of it (see C02); add the transitive case to acceptance.

### Decision gates (can run independently; implementation remains blocked on user approval)

#### G01 — Threat-model ADR/options packet — DONE (ADR-0008 accepted 2026-09-20)

- Closed: `docs/decisions/ADR-0008-threat-workbench.md` is `Accepted 2026-09-20` with every
  gate answered by the user. This closes the design gate only; S02 remains blocked below.
- Deliver: decision-ready ADR covering DFD/STRIDE versus composed privacy/abuse/attack-tree/runtime
  overlays; element schema; evidence types; applicability/completeness; rescope; disagreement; and
  approval authority. Do not choose for the user.
- Primary paths: new ADR under `docs/decisions/`, Workstream G cross-reference only.
- Acceptance: options, tradeoffs, recommendation, explicit questions, golden/mutation fixture plan,
  and no worker/readiness claim.

#### G02 — OWASP applicability/evidence ADR/options packet — HUMAN_GATE

- Deliver: options for pinned ASVS profile/level, MASVS/MASTG, API Top 10, LLM guidance,
  applicability overrides, per-control statuses/evidence, crosswalks, and finding-promotion rules.
- Acceptance: version/license storage plan, static/runtime boundary, positive/negative/partial/NA/
  cannot-verify fixtures, explicit user questions, and no inferred selection.

#### G03 — DISA/NSA hardening ADR/options packet — HUMAN_GATE

- Deliver: options for supported STIG/SRG and NSA/CISA sources, platform applicability, host versus
  container/runtime boundaries, precedence, tailoring, licensing, and reference storage.
- Acceptance: precedence conflicts, tailoring evidence, platform fixtures, explicit user questions,
  and no inferred selection.

### Discovery and source intelligence

#### D01 — Repository-partition persona dispatch — DONE (unpooled, 2026-09-24; see Phase 5b above)

- Delivered: automatic persona mode for `02-repository-partition-discovery` (unpooled: one job
  template, one invocation, one result), supplied mode retained as an explicit validated
  alternative. Never fabricates target classification.
- Acceptance met: dispatch, supplied mode, inapplicable/gap, citation freshness, rescope trigger,
  malformed persona result, timeout/cancel, reuse/recovery, and live real-target qualification --
  all confirmed, including a clean live `--dispatch` SAT PASS against a real `claude` CLI call
  (SAT run `20260924T214618Z`, Dagster run `7e2fc40f-9e22-4c03-8cdc-ab488ac2219c`). Pooled D01
  (concurrent fan-out across many partitions on a real target) remains a separate, later piece,
  tracked by C01-C03, not required to close this entry.

#### D02 — Developer project discovery dispatch — BLOCKED(B10,D01) — D01 leg now satisfied; see Phase 5c

- Deliver: automatic `02-dev-project-discovery` worker producing schema-valid project/build plans;
  retain supplied mode. It proposes safe argv arrays but runs no target build.
- Acceptance: monorepo/multi-language/shared-path fixtures, unsafe command rejection, evidence
  citations, supplied/automatic parity, and live full-review dependency-chain proof.
- **Construction started 2026-09-24 (Phase 5c, below): task prompt authored, model pinned, prompt
  assembly structurally verified. Not yet dispatched live -- a real, pre-existing gap in the
  registry (not something this session introduced) blocks the first attempt. Read Phase 5c before
  doing anything else here; do not re-author what it already describes as done.** Whether B10 (the
  supplied-path common-envelope migration this entry also lists as a blocker) is itself done is
  not verified in this entry -- re-derive it from `discovery_gate.py` and this file's B10 section
  rather than trusting this note.

#### D03 — DevOps project discovery — BLOCKED(D01,B14)

- Deliver: `02-devops-project-discovery` worker/contract/schema for CI/CD, IaC, packaging, release, and deployment structure,
  with documented intent separated from observed runtime state.
- Acceptance: applicable/inapplicable, secret redaction, citation freshness, static/runtime claim
  rejection, reuse/recovery, and live registration.

#### D04 — SRE operations topology — BLOCKED(D01,B14)

- Deliver: `02-sre-operations-topology` worker/contract/schema for services, dependencies, deployment zones, observability,
  operational controls, and unknown topology, without claiming observed runtime behavior.
- Acceptance: source/docs-only semantics, missing-doc gaps, secret redaction, cross-ID validation,
  reuse/recovery, and live registration.

#### D05 — Document intelligence ingest — BLOCKED(B09)

- Deliver: `02-doc-intelligence-ingest` bounded static extraction with lineage, redaction, safe summaries, and index-ready records
  for functional/design documents. Documents remain evidence, never instructions.
- Acceptance: supported/unsupported formats, hostile content, oversized input, secrets, duplicate
  identity, malformed extraction, reuse/recovery, and live registration.

#### D06 — API collection intelligence ingest — BLOCKED(B09)

- Deliver: `02-api-collection-intelligence-ingest` bounded Postman/Bruno/Insomnia/OpenAPI extraction with environment/credential redaction,
  endpoint/auth/data-shape lineage, and index-ready records.
- Acceptance: representative formats, external refs, malformed collections, secrets, duplicate
  endpoints, static/runtime separation, reuse/recovery, and live registration.

#### D07 — Test intelligence ingest — BLOCKED(B09)

- Deliver: `02-test-intelligence-ingest` static inventory of unit/integration/acceptance/smoke/load tests, tags, components, and
  documented coverage intent. It does not claim tests ran.
- Acceptance: framework fixtures, generated/vendor exclusions, missing manifests, static/runtime
  separation, lineage, reuse/recovery, and live registration.

#### D08 — Operations-document ingest — BLOCKED(D05)

- Deliver: `02-operations-doc-ingest` runbook/operations evidence producer with lineage, redaction, topology links, and
  explicit documented-intent semantics.
- Acceptance: secrets, stale links, unknown services, unsupported docs, reuse/recovery, and live
  registration.

#### D09 — Source SAST job and legacy-prepass split — READY (B13 done 2026-09-21; settle B13's `expected_result_sha256` question before this worker calls the verifier)

- Status 2026-09-21: M01 is closed (ADR-0010 accepted), the V06 redactor is merged (PR #10,
  #17) and B13 is DONE (PR #29), so nothing precedes this batch; `02-source-sast` is declared in
  `job-graph.json` (`implemented: false`, depends only on `00-intake`). ADR-0010's requirements on this batch are listed
  under `existing_nodes_receiving_legacy_steps` in
  `docs/proposals/vendor-prepass/job-nodes.proposal.json` (task V13).
- Deliver: per-tool source SAST Dagster worker(s) for the declared `02-source-sast` node, pinned
  tool/image identity, normalized evidence, tool-specific exit semantics, and no finding promotion.
- Acceptance: clean/hit/tool-error/timeout/cancel/corrupt/stale/reuse/recovery fixtures and live
  bounded source scan. Delete replaced legacy logic; no compatibility wrapper.

### Build, compiled evidence, tests, and binaries

#### E01 — Build-configure qualification and common-runtime adoption — BLOCKED(B13,D02)

- Deliver: run `qualify_build_execution.py`, repair only demonstrated gaps, migrate configure to the
  common lifecycle/container boundary, and record whether Freeciv21 produces a non-empty compile DB.
- Acceptance: discovery generation match, safe argv/mounts, configure success/no-compile-db/failure,
  cancel/recovery/newer-failure, Windows/Linux tests, and live service evidence.

#### E02 — Native-build variants and provenance — BLOCKED(E01)

- Deliver: distinct `02-native-build` worker with Debug, RelWithDebInfo, and Release manifests;
  compiler/dependency/generated-source/binary/symbol/compile-DB identities; no configure-only
  success claim.
- Acceptance: variant mismatch, stale compile DB, missing symbols, partial build, hostile build,
  timeout/cancel/recovery, and authoritative container qualification.

#### E03 — Native SAST — BLOCKED(E02,B13)

- Deliver: `02-native-sast` worker with pinned tools, compile-DB lineage, separate outputs and
  tool-specific exit handling. Results are evidence leads, not verified findings.
- Acceptance: supported/unsupported TU, stale DB, analyzer error, partial coverage, reuse/recovery,
  and bounded real-target run.

#### E04 — IR capture — BLOCKED(E02,B13)

- Deliver: `02-ir-capture` worker with variant/compiler/source-generation provenance and explicit
  uncovered units.
- Acceptance: zero/partial/full capture, stale variant, malformed bitcode, cancel/recovery, and live
  bounded qualification.

#### E05 — IR link and facts — BLOCKED(E04)

- Deliver: separate `02-ir-link` and `02-ir-facts` accepted attempts with linked-module provenance,
  debug locations, pointer/memory facts, coverage gaps, and no vulnerability verdicts.
- Acceptance: link conflict, missing module, stale capture, malformed facts, deterministic output,
  reuse/recovery, and live qualification.

#### E06 — Debug-symbol index — BLOCKED(E02)

- Deliver: `02-debug-symbol-index` worker binding binaries, symbols, source revision, build variant,
  and supported lookup records.
- Acceptance: mismatched/stripped/partial symbols, duplicate binary IDs, stale build, reuse/recovery,
  and live bounded qualification.

#### E07 — Binary triage — BLOCKED(E02,B13,M02)

- Deliver: `02-binary-triage` worker and finalized inventory/tool-evidence/candidate/follow-up
  schemas, static-only by default, with image/tool lineage and redaction.
- Acceptance: format matrix, stripped/packed/unknown binaries, tool failure, secrets, partial
  coverage, reuse/recovery, and live static qualification.

#### E08 — Binary CFG and intelligence ingest — BLOCKED(E06,E07)

- Deliver: `02-binary-cfg` plus `02-binary-intelligence-ingest`, preserving binary/symbol/build
  lineage and separating decompiler/tool leads from verified claims.
- Acceptance: missing symbols, unsupported architecture, malformed CFG, cross-ID mismatches,
  partial coverage, reuse/recovery, and bounded live qualification.

#### E09 — Test execution — BLOCKED(E02,B11,B13)

- Deliver: authorized `02-test-execution` worker with exact argv, environment, build/source identity,
  timeout, artifacts, and explicit network/credential/target-mutation decisions.
- Acceptance: pass/fail/skip/crash/timeout/cancel, flaky retry prohibition, secret redaction,
  generation mismatch, reuse/recovery, and live fixture execution.

#### E10 — Test-result and coverage ingest — BLOCKED(E09)

- Deliver: separate `02-test-result-ingest` and `02-test-coverage-ingest` producers tied to exact
  execution/binary/source identities; unsupported formats become gaps.
- Acceptance: passing/failing/partial/malformed result sets, stale or mismatched coverage, duplicate
  tests, deterministic merge, reuse/recovery, and live fixture qualification.

### Evidence assembly and characterization

#### F01 — Evidence-index enrichment and partition exposure — BLOCKED(B10,D01,D05,D06,D07,D08,E05,E08,E10)

- Deliver: enrich `02-evidence-index` to safely index accepted derived intelligence and partition maps with producer attempt IDs,
  citations, hashes, redaction, and type labels; never index raw secrets or conflate intent/runtime.
- Acceptance: stale producer, corrupt pointer, duplicate record, secret negative tests, query bounds,
  immutable reuse, and CLI/MCP retrieval qualification.
- Slice done 2026-09-20: ADR-0010 task V15 (G10 = B), the language/size metrics enrichment that
  replaces the legacy `cloc` and `scc` steps, merged in PR #25 and `02-evidence-index` was
  requalified on Linux (`docs/evidence/evidence-index-metrics.md`); Windows verification is outstanding.
  The rest of F01 (derived intelligence and partition maps) is unchanged and still blocked.

#### F02 — Evidence assembly rendezvous — BLOCKED(D02,D03,D04,D05,D06,D07,D08,D09,E03,E05,E08,E10,F01,S01)

- Deliver: `02-evidence-assembly` barrier validating applicability, required/authorized skips,
  schemas, hashes, producer IDs, generations, build lineage, freshness, permissions, and coverage
  before publishing `intel-manifest.json`.
- Acceptance: every required producer success/skip/failure/stale/corrupt/mixed-generation case,
  no early publication, deterministic manifest, reuse/recovery, and parallel live qualification.

#### F03 — Component characterization and tag cloud — BLOCKED(F02)

- Deliver: `01-component-characterization` worker and schema with component purpose, ownership,
  paths, relationships, evidence citations, confidence, unknowns, and tag cloud; rescope events are
  explicit and bounded.
- Acceptance: web/native/mobile/IaC/library/mixed fixtures, overlaps/unassigned paths, citation
  freshness, deterministic IDs, reuse/recovery, and live qualification.

### Standards sources and decision-dependent workers

#### S01 — Standards-source ingest — BLOCKED(G02,G03 user-approved ADRs,B09)

- Deliver: pinned licensed source store and `02-standards-source-ingest` worker with version/hash/
  license lineage and per-control records. A mapping or checklist is not proof.
- Acceptance: changed source/version/license, missing control text, duplicate IDs, crosswalk lineage,
  offline reuse, recovery, and live registration.

#### S02 — Threat model — BLOCKED(G01,F03,B14,M01)

- Predecessors as ADR-0008 records them (Decision 5 added M01). G01 (ADR-0008) and M01 (ADR-0010,
  nodes declared by V02) are now `DONE`; F03 and B14 remain. The threat-workbench producer fill
  (ADR-0010 task V08, ADR-0008 task T03) is unblocked by V02.
- Deliver: `03-threat-model-dfd-stride` according to the approved ADR, with modeled elements,
  trust-boundary flows, cited threats, unknowns, completeness, dissent, and rescope triggers.
- Acceptance: approved golden and mutation fixtures; every threat cites an element/evidence and every
  in-scope crossing is assessed or explicitly unresolved.

#### S03 — OWASP worklist and ASVS/MASVS — BLOCKED(G02 user-approved ADR,S01,F03,S02)

- Deliver: `04-owasp-validation-worklist` and `04-asvs-masvs` per approved applicability/evidence
  rules, preserving per-control status and separating gaps from promoted findings.
- Acceptance: family/version/applicability matrix, positive/negative/partial/NA/cannot-verify,
  runtime-evidence requirements, crosswalk dedupe, reuse/recovery, and live qualification.

#### S04 — STIG/SRG worklist and deployment hardening — BLOCKED(G03 user-approved ADR,S01,F03)

- Deliver: `15-stig-srg-validation-worklist` and `15-deployment-hardening` per approved platform,
  precedence, tailoring, and evidence rules.
- Acceptance: host/container/cloud/platform fixtures, conflicts/tailoring/unknowns, static/runtime
  boundaries, reuse/recovery, and live qualification.

### Analysis, claim lifecycle, and reporting

#### L01 — Append-only claim/decision ledger — BLOCKED(C04,F03)

- Deliver: hash-linked ledger with stable claim IDs, citations, producer/persona/model identity,
  status/confidence/components, proof obligations, dissent, supersession, and causal links; illegal
  transitions fail closed.
- Acceptance: verified/refuted/narrowed/duplicate/conflicting/unresolved/superseded scenarios,
  tamper/cycle/self-verification/stale-evidence rejection, and crash/restart recovery.

#### L02 — Native-memory analysis — BLOCKED(F03,E03,E05,L01)

- Deliver: `05-native-memory` worker using accepted source/native/IR evidence with explicit coverage
  and proof obligations; no host-compiler-only verification.
- Acceptance: seeded positive/negative/unknown fixtures, source-only limits, sanitizer/IR lineage,
  persona independence, reuse/recovery, and authoritative container qualification.

#### L03 — CVE reachability — BLOCKED(F03,F02,L01,M05)

- Deliver: `06-cve-reachability` worker connecting pinned dependency/CVE evidence to component,
  build, import/call/configuration evidence; version match alone is not reachability.
- Acceptance: reachable/unreachable/unknown/dev-only/vendored/generated cases, database staleness,
  cited paths, reuse/recovery, and bounded real-target qualification.

#### L04 — Fuzz-target triage — BLOCKED(S02,L02,L03,L01)

- Deliver: `13-fuzz-target-triage` prioritized targets with harness feasibility, input surfaces,
  sanitizers, dictionaries/corpora, blockers, and evidence; it does not claim fuzz execution.
- Acceptance: native/non-native/inapplicable targets, duplicate surfaces, missing build evidence,
  deterministic ranking, reuse/recovery, and live qualification.

#### L05 — Red-team discovery — BLOCKED(S02,S03,S04,L02,L03,L04,L01,B14,C04)

- Deliver: `07-red-team-adversarial` pool producing cited candidate claims only, with dissent and
  coverage. It cannot self-verify or promote severity.
- Acceptance: hostile evidence, duplicate/conflicting claims, insufficient diversity, partial pool
  failure, timeout/cancel, deterministic merge, ledger routing, and live qualification.

#### L06 — Blue-team refutation — BLOCKED(L05,L01,B14,C04)

- Deliver: `08-blue-team-refutation` independent pool routing each candidate to refuted, narrowed,
  surviving, or unresolved with evidence and dissent.
- Acceptance: no self-refutation, every candidate accounted for, conflicting evidence, partial
  failure, quorum/diversity, ledger transitions, recovery, and live qualification.

#### L07 — Independent verification — BLOCKED(L06,L01,B14,C04)

- Deliver: `09-independent-verification` with proof obligations, same-environment deterministic
  checks where applicable, explicit unresolved status, and independent producer identity.
- Acceptance: verified/refuted/unresolved/blocked, static/runtime boundaries, High/Critical gate,
  no self-verification, ledger transitions, recovery, and live qualification.

#### L08 — Scoring and prioritization — BLOCKED(L07,S02,S04,L01)

- Deliver: `12-scoring-prioritization` from accepted verification, threat, business, exploitability,
  exposure, and control evidence with explainable scoring and no severity inflation.
- Acceptance: missing factors, conflicting evidence, deterministic tie handling, stale inputs,
  reuse/recovery, and live qualification.

#### L09 — Remediation and same-environment retest loop — BLOCKED(L07,E02,E09,L01)

- Deliver: `11-remediation-proposal` plus bounded retest/reverification controller. Patches remain
  proposals until explicitly authorized; `fixed` requires same-environment retest and independent
  re-verification.
- Acceptance: accepted/declined patch, build failure, failed retest, regression, stale source,
  loop limit/no progress, unresolved terminal, recovery, and ledger audit.

#### L10 — Dynamic rescope controller — BLOCKED(F03,L01)

- Deliver: dependency index and bounded rescope for changed component classification, source/build
  generation, applicability, or invalidated evidence; recompute only affected descendants.
- Acceptance: generation advance, unaffected branch preservation, no-progress/iteration bounds,
  crash recovery, and no silent deletion.

#### L11 — Completeness and synthetic-hypothesis feedback — BLOCKED(L07,L08,L10)

- Deliver: completeness auditor, coverage feedback, synthetic hypothesis routing, bounded targeted
  analysis, and resynthesis trigger with `UNRESOLVED_AND_REPORTED` termination.
- Acceptance: missing edge, false gap, duplicate hypothesis, partial evidence, iteration/no-progress
  limits, deterministic routing, ledger preservation, and restart recovery.

#### L12 — Synthesis, SARIF binding, and final publication gate — BLOCKED(L08,L09 optional,L11,B09)

- Deliver: `10-synthesis-report`, bind SARIF generation to accepted synthesis/verification while
  retaining standalone diagnostic mode, completion validator, human signoff ledger, and immutable
  publication package.
- Acceptance: every claim traceable, dissent/gaps/unresolved retained, High/Critical independently
  verified, optional remediation represented honestly, stale/mixed generations rejected, and
  publication blocked without signoff.

### Legacy-script decomposition and tooling qualification

#### M01 — Vendor-prepass graph/contract decision — DONE (ADR-0010 accepted 2026-09-20; nodes declared by V02)

- Closed: `docs/decisions/ADR-0010-vendor-prepass-decomposition.md` answers gates G1-G10 and M1-M5
  and maps all 37 legacy steps; task V02 declared its nine `02-*` nodes in `job-graph.json` as
  `implemented: false`, joined them at `02-evidence-assembly`, and registered the skip reason
  `not-applicable-no-matching-inputs`. Every one of them blocks with `WORKER_NOT_IMPLEMENTED`.
  Remaining work is the task series in `docs/proposals/vendor-prepass/task-series.md`.
- Deliver: explicit graph-node and output-contract decisions for secrets, IaC, SBOM/SCA, container,
  BinSkim/binary-hardening, mobile SAST, and source SAST. Map old steps; do not implement tools yet.
- Primary paths: ADR/plan, job graph/parity proposal fixtures. Do not guess hidden generic nodes.
- Acceptance: each legacy step has one disposition, producer/consumer edge, claim limit, permission,
  image/tool identity requirement, and migration/delete gate.

#### M02 — Binary image pinning/split decision — READY

- Deliver: decide static/firmware/mobile/dynamic image split and pin or lock every external binary
  tool download. Dynamic execution remains separately authorized.
- Acceptance: reproducible image identities, licenses, offline/static default, smoke fixtures, and
  no unpinned download or network-enabled analysis by default.

#### M03 — Secrets and IaC per-tool jobs — READY (B13 done 2026-09-21; settle B13's `expected_result_sha256` question before these workers call the verifier)

- Graph nodes (declared, not implemented): `02-secrets-inventory`, `02-iac-config-scan`.
- Status 2026-09-20: part 1 is merged: contracts and schemas (V04, PR #18 and #21), shared
  tool-instance shapes (V03, PR #9) and the redactor with its receipt (V06, PR #10 and #17).
  Part 2, the workers (V10), is unblocked since B13 merged (PR #29, 2026-09-21); the validator
  policy and dispatch for the new claim classes are a separate integration change.
- Deliver: separate run-owned secrets and IaC jobs/contracts/schemas, safe redaction, pinned images,
  and legacy-step deletion after parity. Scanner hits remain evidence leads.
- Acceptance: clean/hit/secret-output/tool-error/timeout/cancel/reuse/recovery and bounded live runs.
- Owner decision 2026-09-21 (PR #31 review): the validator closes the attempt tree for the nine
  vendor-prepass contracts (`status.json`, `manifest.json`, `result.json`, `outputs/` only) and
  `inputs.json` is never an allowance. These workers therefore get their OWN attempt allocation,
  which keeps the input record outside the attempt and writes only the closed set; they do not
  publish through `allocate_attempt` / `persist_terminal_current` as those stand
  (`docs/contracts/validator-vendor-prepass-dispatch.md`, known limits).

#### M04 — Container, mobile, and binary-hardening jobs — BLOCKED(M02,B13)

- Graph nodes (declared, not implemented): `02-container-image-inventory`, `02-mobile-sast`,
  `02-binary-hardening`. `02-mobile-applicability` is not adopted (ADR-0010 G6 = A).
- Status 2026-09-20: part 1, contracts and schemas (V07), merged in PR #19. Part 2, the workers
  (V12), waits for M02 and B13.
- Deliver: separate jobs selected by applicability with pinned tools and explicit static/dynamic
  semantics; remove replaced legacy steps without wrappers.
- Acceptance: applicable/inapplicable/unsupported artifacts, tool failure, permissions, partial
  coverage, reuse/recovery, and bounded live qualification.
- Owner decision 2026-09-21 (PR #31 review), as under M03: these workers get their own attempt
  allocation that writes only the closed set; `inputs.json` is never an allowance.

#### M05 — SBOM/SCA evidence jobs — BLOCKED(B13,V16,V17,V18)

- Graph nodes (declared, not implemented): `02-sbom-inventory`, `02-sca-vulnerability-match`,
  `02-license-scan`, `02-dependency-lifecycle`.
- Status 2026-09-20: part 1, contracts and schemas (V05), merged in PR #23; the NVD snapshot
  binding (V09) merged in PR #8. Part 2, the workers (V11), waits for B13 and for ADR-0010 tasks
  V16 (Grype DB mirror publisher) and V17 (OSV snapshot publisher), both behind B11, and V18
  (their consumer bindings). `02-dependency-lifecycle` also needs a published, identified
  lifecycle reference table; no publisher for one exists.
- Deliver: separate SBOM, dependency lifecycle, vulnerability database, and license producers with
  component/version/source/database timestamps and hashes; do not claim reachability.
- Acceptance: lockfile/binary/vendor cases, offline/stale DB, unknown version, duplicate component,
  tool failure, reuse/recovery, and bounded live qualification.
- Owner decision 2026-09-21 (PR #31 review), as under M03: the validator closes the attempt tree for the nine
  vendor-prepass contracts (`status.json`, `manifest.json`, `result.json`, `outputs/` only) and
  `inputs.json` is never an allowance. These workers therefore get their OWN attempt allocation,
  which keeps the input record outside the attempt and writes only the closed set; they do not
  publish through `allocate_attempt` / `persist_terminal_current` as those stand
  (`docs/contracts/validator-vendor-prepass-dispatch.md`, known limits).

#### M06 — Semantic-index disposition — READY

- Deliver: compare legacy semantic-index scripts with accepted `evidence_store.py`/MCP capability;
  delete as superseded or port only unique qualified behavior. No compatibility wrapper.
- Acceptance: feature matrix, retrieval parity fixtures, explicit disposition, updated callers/docs,
  and no duplicate mutable index authority.

#### M07 — Remaining script disposition/migration — BLOCKED(M06)

- Status 2026-09-20: M01 is closed. The vendor-prepass deletion slice (ADR-0010 task V14) is
  additionally blocked on V10-V13.
- Deliver: process Tier 2–4 inventory in dependency order; each script gets delete/superseded/port/
  retain-tooling disposition, caller update, focused parity test, and no thin wrapper.
- Acceptance: zero undocumented executable callers and updated migration inventory after each slice.

### Operations, documentation, and release

#### Q01 — Full host/Linux regression baseline — BLOCKED(B09,B10)

- Deliver: run complete supported suites against one pinned commit, record service/image identities,
  failures, quarantines, timing, and hashes; do not edit behavior merely to make tests green.

#### Q02 — Real supplied discovery/build chain — BLOCKED(B10,E01)

- Deliver: create schema-valid partition and developer-discovery results for a real engagement and
  prove `full_review` reaches build configure with exact source/generation lineage.

#### Q03 — LSP semantic-reference qualification — BLOCKED(E01)

- Deliver: qualify supported language servers against accepted compile DB/build variants and record
  semantic coverage separately from initialization smoke success.

#### Q04 — Reusable skill installation documentation — READY

- Deliver: tested Codex and Claude installation/use instructions for tracked process-reader,
  retrieval, and project-discovery skills; no untracked personal-path assumption.

#### Q05 — CI contract/parity/retrieval coverage — BLOCKED(Q01)

- Deliver: CI for registry/contracts, parity/generation freshness, focused runtime tests, evidence
  index bounds, stale/corrupt rejection, and platform-appropriate skips with no fabricated service
  success.

#### R01 — Full-system release qualification — BLOCKED(all applicable batches above)

- Deliver: a clean `full_review` with zero applicable `WORKER_NOT_IMPLEMENTED`, accepted skip/gap
  receipts for inapplicable/unavailable evidence, failure/recovery and cancellation scenarios,
  reproducible qualification manifest, independent review, and documented residual deviations.
- Acceptance: every enabled node has worker, validator, composition, contract/schema, recovery,
  permission, pool, qualification, and traceable evidence; final publication requires human signoff.

## 0. Accepted foundation

- [x] Re-vet and implement Phase 1 intake: A01-A16 PASS on 2026-09-19, run `20260919T104300Z-ba7b4c`.
- [x] Add the persistent Dagster run queue, per-engagement serialization, parallel preparation,
  validated final join and branch recovery: [workflow documentation](../docs/dagster/dagster-workflow.md).
- [x] Enforce run-owned `runs/<run_id>/data/`, immutable attempts, validated reuse and explicit
  legacy imports.
- [x] Register lifecycle/registry jobs in the full Dagster graph with explicit missing-worker gates.
- [x] Add reference-resolution and semantic compatibility checks for composition IDs.
- [x] Validate registry JSON records locally through `qualify_phase1.py`.
- [x] Move agent-facing process guidance into docs/skills:
  [agent reader](../docs/agent-reader.md), Codex/Claude process readers, evidence retrieval
  skills, and root `AGENTS.md`.

## 1. Immediate qualification gates

- [x] Add the v1.0 machine-readable design-parity manifest, strict validator, deterministic report,
  and focused mutation tests. The honest baseline covers 42 lifecycle jobs and 15 cross-cutting
  design capabilities; missing workers, validators, contracts, schemas, pools, qualification, and
  Workstream G decisions remain explicit gaps rather than inferred readiness.
- [x] Generate and freshness-check the lifecycle Mermaid and operator readiness table from the
  parity manifest. Workstream A now also defines the common worker-result envelope, immutable
  terminal/acceptance transitions, and graph integrity checks; runtime adoption is Workstream B.
- [x] Implement the first bounded Workstream B validation runtime: common envelope/state module,
  run-owned artifact path/hash and input-fingerprint checks, registry-required-file validation,
  edge-authorized skips, immutable reuse, and narrow deterministic/supplied-human adapters.
- [ ] Add contract-specific schemas, citations/source freshness, claim-class limits, redaction,
  remaining adapters, and migrate selected workers through live Dagster qualification.

- [ ] Run and record `qualify_build_execution.py` on a host with Docker and the Dagster service.
  This is the current gate for whether `build_execution` actually produces
  `build/discovery/compile_commands.json` for Freeciv21.
- [ ] Run the full host and Linux test suites after the current Dagster/build/evidence-index code
  changes are staged together. Record the tested commit, service image identities and run IDs.
- [ ] Decide whether `build_execution` should remain a standalone launched job or be wired into
  `full_review` as `02-build-configure` after qualification. (Wired in 2026-09-19 as
  `build_configure_work` in `dagster_workflow.py`, ahead of qualification, per direct request;
  its real declared upstream, `02-dev-project-discovery`, was still an unimplemented `blocked_op`
  stub at the time -- see section 4's discovery hand-off gate, added the same day, which resolves
  that chain once real data is supplied. Still not run for real inside `full_review`.)
- [ ] Confirm `review_cli.py status` clearly reports `build_discovery`, `build_execution` and
  `evidence_index` acceptance/failure locations for operators.

## 2. Build and collection graph

- [x] Implement and qualify bounded `build_discovery`: separate streams, immutable reuse,
  full-graph failure and recovery. See [build discovery](../docs/build-discovery/build-discovery-integration.md).
- [ ] Implement successful-build manifests with separate Debug, RelWithDebInfo and Release
  provenance, matching symbols, generated inputs, binary hashes and compile databases. Configure
  success alone is insufficient.
- [ ] Implement the `02-native-build` worker as a distinct run-owned job after configure succeeds.
- [ ] Adapt native SAST, IR capture, IR link and IR facts to bounded Dagster workers with separate
  stdout/stderr, image/version records, tool-specific exit handling and immutable outputs.
- [ ] Add source SAST as a source-only branch that can run in parallel with build-gated work.
- [ ] Implement test execution, test-result ingest and coverage ingest as separate branches.
- [ ] Implement operations-doc ingest and keep it source-only unless it needs explicit tooling.
- [ ] Implement `02-evidence-assembly` as the rendezvous barrier: validate schemas, hashes,
  producer attempt IDs, build lineage, freshness, skip receipts and coverage gaps before publishing
  `intel-manifest.json`.
- [ ] Qualify parallel Freeciv21 collection with at least one branch failure/recovery scenario.

## 3. Evidence retrieval and tooling

- [x] Implement the Dagster source evidence index, immutable snapshots, ssdeep, FTS5 retrieval,
  bounded read-only MCP tools and Codex/Claude retrieval skills:
  [retrieval guide](../docs/evidence/evidence-retrieval.md).
- [x] Add repeatable LSP and MCP filesystem/memory protocol probes with image identities and
  run-owned receipts.
- [ ] Qualify language-server semantic references against accepted compile databases/build variants;
  initialization smoke tests alone do not establish semantic coverage.
- [ ] Publish reusable Codex and Claude skill installation instructions from `skills/agents/`
  once the skills rework (`docs/TODO/09-skills-rework.md`) lands.
- [ ] Add CI coverage for evidence-index CLI/MCP query bounds, stale acceptance and corrupt
  artifact rejection when CI orchestration is introduced.

## 4. Registry, personas and handoff rendering

- [x] Wire `02-repository-partition-discovery` and `02-dev-project-discovery` into `full_review`
  as a validated hand-off gate (`appsec-review-process/discovery_gate.py`, 2026-09-19): each op
  accepts an out-of-band-supplied, schema-valid result from
  `runs/<run_id>/data/jobs/<job>/supplied/result.json` (schema validation covers map IDs, path
  scopes, overlap explanations, citations and persona routes for the partition-map contract), or
  writes an actionable `handoff.md`/`handoff.json` and fails clearly if none is supplied yet. This
  is deliberately not a worker that performs the partition analysis itself -- that requires real
  judgment about the specific target that a script cannot honestly fabricate. See
  [build discovery](../docs/build-discovery/build-discovery-integration.md)'s new hand-off-gate section.
- [ ] Have a human or agent actually produce and supply a schema-valid
  `02-repository-partition-discovery` / `02-dev-project-discovery` result for a real engagement,
  so `02-build-configure`'s dependency chain resolves end to end in `full_review` (currently wired
  but unexercised with real data).
- [ ] Expose the accepted partition map in the engagement evidence index once real data exists.
- [x] Implement `create_job_handoff.py` to render registry job templates into run-scoped handoffs
  with persona, role, domain, tooling profile and output contract sections, including immutable
  composition/input hashes.
- [x] Implement the first `validate_job_output.py` contract slice: common envelope/status/artifact
  checks plus dedicated Scorecard, repository-partition, and project-discovery schema, citation,
  claim-class, cross-record, freshness, and secret-leak checks. Broader contracts remain in the
  owning batches above.
- [x] Add smoke and mutation tests for job-template rendering and immutable handoffs.
- [x] Add negative tests proving the adopted discovery contracts cannot emit findings, severity,
  or observed-runtime claims.
- [ ] Add the registry qualification command to CI when CI orchestration is introduced.

## 5. Intelligence ingestion

- [x] Declare parallel source SAST, doc, API and test consumers; build-gated IR and binary analysis;
  separate test-result/coverage consumers; and an evidence rendezvous:
  [collection plan](../docs/evidence/parallel-intelligence.md).
- [ ] Implement doc intelligence ingestion with run-owned outputs and safe summary/search records.
- [ ] Implement API collection ingestion for Postman, Bruno, Insomnia and OpenAPI artifacts,
  including environment redaction.
- [ ] Implement test intelligence ingestion for unit, integration, acceptance, smoke and load tests.
- [ ] Build reverse indexes from standards controls to tests, components, tags and binary-intel
  leads.
- [ ] Wire component tag-cloud generation into `01-component-characterization`.
- [ ] Connect doc/API/test/binary intelligence manifests into the run-owned evidence assembly and
  downstream `ENGAGEMENT_LLM_INPUT` compatibility surface.

## 6. Binary intelligence

- [ ] Decide whether the large binary analysis image should be split into static, firmware, mobile
  and dynamic variants.
- [ ] Add version-pinning or lock metadata for external binary-tool downloads in
  `images/audit-binary-analysis/Dockerfile`.
- [ ] Implement an automated `02-binary-intelligence-ingest` runner that discovers candidate binary
  artifacts and writes run-owned binary-intel outputs.
- [ ] Define or finalize JSON contracts for `binary-artifact-inventory.json`,
  `tool-evidence-manifest.json`, `candidate-leads.json` and `verification-followups.json`.
- [ ] Add skill guidance for the `reverse-engineer` persona and binary-intelligence job.
- [ ] Add optional YARA rule bundles and document where engagement-specific rules live.
- [ ] Add a safe mechanism for network-enabled Trivy/Grype DB refreshes when explicitly authorized.
- [ ] Add dynamic-analysis job templates for debugger, QEMU and Frida workflows with stronger
  authorization gates.

## 7. Standards and validation hardening

- [ ] Complete and record the threat-model, OWASP, and DISA/NSA decision gates in the
  [design-parity plan](../docs/design-parity/design-parity-completion-plan.md#workstream-g-required-design-discussions-for-standards-work)
  before implementing those workers. Do not infer versions, applicability, evidence thresholds,
  crosswalk semantics, or static/runtime claim rules from the existing prompts.
- [ ] Populate per-control standards source directories with upstream lineage, hashes and license
  metadata.
- [ ] Add checks that High/Critical findings cite independent verification outputs.
- [ ] Document when `DEBUG_CAPS=1`, `ALLOW_NETWORK=1` and dynamic analysis are allowed, including
  required status fields.
- [ ] Add checks that runtime exposure claims cannot be satisfied by static-only evidence.
- [ ] Add regression tests for cancellation, worker loss, stale producer pointers, corrupted
  `accepted.json`, mismatched build symbols and one-branch recovery after failure.

## 8. Script migration (`scripts/` -> `pipeline/` or Dagster workers)

Per the 2026-09-19 script migration rule (`AGENTS.md`, `README.md`, `docs/architecture/migration.md`): no new
review-work logic in `scripts/`; port active review scripts, qualify, update callers, delete the
old script outright (no thin wrapper). Full script-by-script survey and priority tiers:
`docs/continuation-prompts/scripts-to-pipeline-migration.md`.

- [x] Port `scripts/summarize_evidence.py` -> `pipeline/summarize_evidence.py` (2026-09-19,
  verbatim copy -- the script had no dependency on anything else under `scripts/`). Updated both
  callers (`pipeline/engagement_job.sh` line 148, `pipeline/engagement_job.ps1`'s static-summary
  step) and `pipeline/README.md`'s script table. Qualified by running old and new against an
  identical synthetic evidence tree and diffing output (byte-identical apart from the wall-clock
  timestamp line). Old script deleted outright, no wrapper.
- [x] Port `scripts/md_to_sarif.py` to the registered, run-owned
  `critical_findings_sarif` Dagster job (2026-09-19). The replacement uses a complete registry
  composition, fixed run input, bounded child execution, immutable attempts, separate streams,
  strict finding/SARIF validation, freshness and hash checks. Semantic parity against the legacy
  converter passed on a structured fixture; focused host/Linux tests and a live service launch
  qualify the workflow registration. The old script was removed from both static images and
  deleted outright with no wrapper.
- [x] Retire the one-time `scripts/fix-binskim.ps1` Dockerfile patcher (2026-09-19). Both maintained
  static-image Dockerfiles already contain the pinned self-contained BinSkim `4.4.9.11` install,
  the existing toolbox image reports that version, and preserved EASTL evidence records a
  successful BinSkim SARIF-producing step. The patcher had no executable callers and was deleted
  without a wrapper; the future run-owned binary-hardening producer remains separate open work.
- [x] Port `scripts/Get-ComponentLocations.ps1` to
  `pipeline/extract_component_locations.py` (2026-09-19). The replacement retains the deterministic
  CycloneDX/Syft component-location CSV and path/no-location summaries, adds bounded input and
  atomic output handling, and remains explicitly outside accepted Dagster evidence. Focused fixtures
  and a Windows old/new semantic comparison qualified it; the old script had no executable callers
  and was deleted without a wrapper.
- [x] Replace retired `scripts/check_ossf_scorecard.py` with the registered run-owned
  `ossf_scorecard` published-results job (2026-09-19). The replacement requires explicit fixed-host
  network authorization, validates canonical JSON2 identity and structure, preserves raw response
  provenance, exposes missing published results as coverage gaps, and fails newer attempts closed.
  The old helper remains deleted without a wrapper. A live Scorecard CLI scan remains separate work.
- [ ] Break `scripts/Invoke-VendorAuditPrePass.ps1` / `.sh` (the big legacy audit orchestrator) apart
  into separate per-tool Dagster jobs under `appsec-review-process/` -- **corrected 2026-09-19,
  repo owner's direct instruction**: NOT a single `orchestrator/` Python replacement (superseded
  `docs/architecture/migration.md` planned-change #5). Each tool becomes a job that communicates like every
  other job in the graph (`accepted.json`/`attempts/<id>/`), orchestrated by Dagster. Source-SAST
  tools map onto the already-declared `02-source-sast` node; secrets, IaC, SBOM/SCA, BinSkim and
  mobile SAST had no declared `job-graph.json` node and needed a decision on new nodes/contracts
  before implementation. **Decided 2026-09-20 (ADR-0010, batch M01) and declared by task V02**:
  nine `implemented: false` nodes, listed under M03, M04 and M05 above; no worker exists yet. Highest-
  value, highest-risk remaining Tier 1 item -- treat the PowerShell/bash as reference for step
  semantics only, not code to lift verbatim.
- [ ] Resolve `scripts/build_semantic_index.py` / `query_semantic_index.py` -- check for overlap
  with the newer Dagster evidence index (`appsec-review-process/evidence_store.py`,
  `evidence_mcp.py`) before porting; may be substantially superseded rather than needing a straight
  port.
- [ ] Tier 2-4 scripts (11 documented-but-unwired scripts, 2 apparently orphaned, build-image
  tooling, dev/ops utilities): see the continuation prompt doc above for the full breakdown and
  per-script disposition questions. Not started.

## 9. Design-parity release gate

- [ ] Complete Workstreams A-H in the
  [design-parity completion plan](../docs/design-parity/design-parity-completion-plan.md).
- [ ] Generate the machine-readable parity report and prove every enabled graph node has a worker,
  validator, registry composition, output contract, recovery policy, resource-pool assignment, and
  service-level qualification.
- [ ] Qualify persona/tool pools, wait-all rendezvous, deterministic merge, quorum, claim ledger,
  refutation/verification, remediation/retest, rescope, completeness, and resynthesis loops.
- [ ] Run an actual `full_review` with zero applicable `WORKER_NOT_IMPLEMENTED` results; preserve
  explicit accepted skip/gap receipts for inapplicable or unavailable evidence.
- [ ] Obtain independent review of the qualification manifest and residual design deviations before
  claiming parity with `docs/architecture/design-v3.md`.

## 10. Later: running built targets (fuzzing, dynamic testing)

Added 2026-09-25 (William). Today no job runs what it builds: discovery plans only build and inspect
commands, and the build lane builds images and binaries without running them. Eventually we may want
to run them, for example:

- [ ] Fuzzing the built binaries (E-series fuzzing jobs, `13-fuzz-target-triage`): run harnesses
  against what the build lane produced, under the B13 boundary.
- [ ] Dynamic testing of built container images (start the image, exercise declared ports and
  entrypoints) under the `dynamic-testing` permission capability, not `target-execution` alone.
- [ ] Decide where such run steps come from (the build lock, a new plan field, or a dedicated job) and
  how they are granted; discovery prompts stay build/inspect-only until then.
