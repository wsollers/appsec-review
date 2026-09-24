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
- **Persona-dependent discovery nodes use the supplied pattern until D01 lands.** A validated,
  hand-supplied record stands in for `02-dev-project-discovery`, `02-devops-project-discovery` and
  `02-sre-operations-topology` so the build chain is not blocked on pool dispatch. **Correction,
  William 2026-09-24: this was right for getting the gate/schema/chaining plumbing built (SAT
  stages 6-9), but the SAT does not get to call itself done that way. A gate that only checks "does
  the supplied file validate" while a human hand-writes the file it is checking is a test of the
  JSON schema, not of the system. D01 (below, Phase 5b) is now under construction to close this for
  real; SAT stages 6-9 will be re-proven against automatic dispatch, not re-declared passing on the
  fixture alone.**
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

### Phase 5b -- D01: automatic persona dispatch for repository-partition-discovery (unpooled)

**Started 2026-09-24 (William's correction).** The goal: `02-repository-partition-discovery`
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
   literal bytes), concatenates, and (via `assemble_outer_prompt`) writes the result under the
   attempt's own scratch dir via `execution_state.data_path` (run-owned, symlink-checked, atomic),
   returning `{path, sha256, bytes}` ready to drop straight into
   `request["outer_prompt"]`. Verified in the cloud sandbox: full render of D01's 8-section prompt
   (governing_rules, persona, role, domain, tooling_profile, buildenv_catalog, task,
   output_contract) succeeds; the written file round-trips through
   `persona_invocation._read_pinned` with the exact `sha256`/`bytes` this module returns (proves
   the pin persona_invocation.resolve_request will independently verify actually matches); a
   missing job template raises `PromptAssemblyError` before writing anything. `--print` on the
   module (`python3 persona_prompt_assembly.py <job_template_id> --print`) renders without writing,
   for review.
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
3. **Request builder -- new code.** Builds the full `appsec-review/persona-invocation-request/1.0`
   object `persona_invocation.resolve_request` expects: `persona` (the composition ids),
   `model`/`effort` (`model_version_registry.model_identity_for(run_id, alias)` for the pinned
   identity, `alias` and `effort` from the job template's own `model` field via
   `review_cli.resolve_model(job_template_id, budget)` -- called by `job_template_id` directly,
   never through `review_cli`'s own `run`/`model` CLI commands, which resolve at the coarser
   *process* granularity; see the model-routing-redesign note above), `tools`
   (derived from the tooling profile via `persona_invocation.tool_ids`), `allowed_claim_classes` /
   `prohibited_claim_classes` (from `persona_invocation.claim_ceiling(role, tooling_profile)` --
   already exists, just needs calling), `outer_prompt` (from step 2), `readable_inputs` (a per-file
   manifest -- root id, relative path, role, sha256, byte count -- for every file in the fixture
   checkout the tooling profile's boundary allows the persona to read; for `static-repo-project-
   inspector` that is the whole read-only checkout, hidden CI paths included, per the job template's
   required inputs), `permission.decision` (a real B11 `permission_capabilities` evaluation for
   `read-source` at probe/standard budget -- reuse the evaluator, do not hand-roll a decision
   object). Where this code lives is an open call for whoever picks this up: either a new
   `appsec-review-process/persona_dispatch.py`, or as new functions inside `discovery_gate.py`
   alongside the existing supplied-path helpers. Prefer the new module; `discovery_gate.py` already
   carries two execution shapes (common-envelope + legacy) and a third (automatic dispatch) reads
   more clearly as its own file that `discovery_gate.py` calls into.
4. **`PersonaInvoker` -- new code, real model client.** `appsec-review-process/persona_invocation.py`
   is dispatch-protocol-only by design ("no model client and no network here"); B14 explicitly wants
   this supplied by the integrator. `appsec-review-process/review_cli.py` already has a live,
   previously-debugged `claude -p` dispatch path (`build_claude_argv`, `_dispatch_streaming`,
   `resolve_model`) proven against real subscription auth on hal5000 -- reuse it, do not rewrite it.
   New file: `appsec-review-process/claude_cli_invoker.py`, a class implementing B14's
   `PersonaInvoker` protocol (`invoker_id: str`, `invoke(package: InvocationPackage, *, output_root:
   Path, cancel: threading.Event) -> None`): materialize `package.prompt` and every `package.inputs`
   entry's bytes into a private scratch dir the invoker controls (B14 hands bytes, not paths -- the
   invoker, not the adapter, decides how to expose them to the CLI), build a `claude -p` invocation
   adapted from `build_claude_argv`/`_dispatch_streaming` (`--add-dir` scoped to that scratch dir and
   `output_root` only, `--allowedTools` from `package.tool_actions`, model/effort from the request,
   budget from `model-config.json`), run it with `cancel` polled the way `_dispatch_streaming`
   already polls for timeout, parse the result, and write `invoker-output.json` (matching
   `schemas/persona-invoker-output.schema.json`) plus any declared output files under `output_root`
   -- and nothing else; the adapter reads only what is on disk afterward, per B14's contract.
5. **Dagster lifecycle wiring -- extend existing code.** `discovery_gate.py` gets an automatic-
   dispatch execution path for `02-repository-partition-discovery`, selected instead of the
   supplied/hand-off path when automatic mode is requested. It builds a `PersonaRuntime` (invoker =
   step 4's class, `registry_dir=appsec-review-process/registry`, `prompt_root`= the run's own
   scratch root, `readable_roots={"target": <fixture checkout path>}`, `allowed_models` from
   `model-config.json`, `source_snapshot_sha256` = the checkout's pinned revision content hash,
   `registry_ceiling=None`, a real UTC `clock`, a fresh `threading.Event()` for `cancel`,
   `stop_grace_seconds` from budget policy), calls `PersonaInvocationAdapter.execute()`, and
   publishes the result through the *existing* `coordinate_worker_lifecycle` / `record_terminal_
   current` / `validate_published` common-envelope boundary -- the same one `02-repository-
   partition-discovery` already uses today (`ADOPTED_JOB` in `discovery_gate.py`). No new
   publication plumbing; this is a new way to *produce* the value that boundary already accepts.
   Supplied mode stays wired and tested as an explicit, separately-invoked alternative (William:
   "retaining supplied mode as an explicit validated alternative" is D01's own acceptance
   criterion) -- it becomes a regression/comparison fixture, not the SAT's proof path.
6. **SAT script change.** `scripts/system-acceptance-test.sh`'s `stage_partition_discovery()`
   (stage 6) gets a new `dispatch` mode that launches automatic dispatch instead of `gate_supply`'s
   fixture copy. The `accept` step's checks change from "output byte-equals the fixture" to
   "output validates against `repository-partition-map.schema.json`, every citation hash matches
   the live checkout, and the record's own structural rules pass (routing table complete, `docs`
   partition deferred, etc.)" -- comparing against the fixture record becomes an optional
   informational diff, never a pass/fail gate. `--list`/`--through` keep working for a supplied-mode
   run too, for regression.
7. **Docs, same commit as the code (standing rule):** `docs/processes/system-acceptance-test.md`
   stage 6 description, `docs/processes/engagement-start.md` step 2b, `docs/processes/flow-
   bringup.md` log, and this file's Phase 5b status. BPMN/Mermaid diagrams if the dispatch step
   changes the pictured flow meaningfully (a new "automatic dispatch" branch inside the existing
   S2b box, likely -- check before assuming the diagram needs a new node).

**Acceptance for D01 (unpooled), from the batch table, still holds:** dispatch, supplied mode
retained, inapplicable/gap handling, citation freshness, rescope trigger, malformed persona result,
timeout/cancel, reuse/recovery, and live real-target qualification (live = the fixture, run in WSL
by William; a second real target is a separate, later qualification step, not required to close D01
on the fixture).

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

#### D01 — Repository-partition persona dispatch — BLOCKED(B14,C01,C02,C03)

- Deliver: automatic persona mode for `02-repository-partition-discovery` while retaining supplied
  mode as an explicit validated alternative. Never fabricate target classification.
- Acceptance: dispatch, supplied mode, inapplicable/gap, citation freshness, rescope trigger,
  malformed persona result, timeout/cancel, reuse/recovery, and live real-target qualification.

#### D02 — Developer project discovery dispatch — BLOCKED(B10,D01)

- Deliver: automatic `02-dev-project-discovery` worker producing schema-valid project/build plans;
  retain supplied mode. It proposes safe argv arrays but runs no target build.
- Acceptance: monorepo/multi-language/shared-path fixtures, unsafe command rejection, evidence
  citations, supplied/automatic parity, and live full-review dependency-chain proof.

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
