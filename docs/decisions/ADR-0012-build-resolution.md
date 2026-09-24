# ADR-0012: Build Resolution (index, LLM plan, bounded build loop, image catalog)

Status: Proposed 2026-09-24 (design direction from William Sollers, 2026-09-24). Design:
[docs/processes/build-resolution.md](../processes/build-resolution.md).

## Context

The review needs a working build of the target for every native activity: compile database, native
SAST, binaries for fuzzing and binary analysis. The system does not know how to build a target it
has never seen. What exists today does not close that gap:

- `build_discovery.py` is a CMake-only regex collector; the `hello-autotools` fixture has no CMake.
- The build fields of developer discovery (`02-dev-project-discovery`) come from a hand-written
  supplied record. We could write it only because we wrote `hello`.
- `persona_invocation.py` is protocol only; no model is ever called for discovery.
- No build image has been built or locked; Phase 4 in `appsec-review-process/TODO.md` planned a
  hand-supplied lock and an agent skill, without a job, a retry budget or reuse.

The system acceptance test surfaced this as the first real gap after the discovery gates: proceeding
to evidence collection without knowing how to build means native evidence can never be complete.

## Decision

1. **Deterministic indexer first (`02-build-index`).** A Python pass gathers every build signal
   (build systems, toolchain and dependency declarations, CI and Dockerfile recipes, README build
   text) into a bounded, sha256-cited index. It executes nothing.
2. **LLM inference over the index (`02-build-plan`).** The model reads only the index, the buildenv
   catalog and the schema, and returns a structured build plan: base image, apt packages, ordered
   argv commands, feasibility tier, each claim cited. The plan is validated deterministically
   before anything is built. The model is **Haiku**, called through the `claude` CLI with its
   current login (the operator's subscription), never an API key: the invoker strips
   `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` from the child process. Both are set in
   `model-config.json` (`lane_overrides["02-build-plan"]`, `invocation.auth.mode`); switching to an
   API key is `invocation.auth.mode = "api-key"` there and nothing else.
3. **Our code renders the Dockerfile.** The model chooses base and packages; it never writes a
   Dockerfile, adds repositories, downloads or copies target files into an image.
4. **Bounded loop (`02-build-resolution`).** Build the image (network to the distro mirror only,
   under a `package-restore` grant), then configure and build a writable copy of the source through
   B13 with no network, under a `target-execution` grant. On failure, feed a bounded, redacted
   failure excerpt back to the model and retry. `build_resolution_attempts`, default 3, bounds plan
   rejections and trial failures together. Exhausted: `FAILED(BUILD_UNRESOLVED)`; native jobs are
   blocked, non-native lanes continue and the report states the gap.
5. **Catalog on success.** The image is recorded as `image_build_<id>` (id from the image spec
   fingerprint) in a host-local catalog with every validated build; a B16-shaped record lets B13 run
   it; the run gets a build lock that E01/E02 replay from a clean copy.
6. **Reuse by default, overridable.** `build_image_reuse` = `auto` (try a catalogued image first; its
   failure seeds the model), `rebuild` (the build needs different tools: infer from scratch),
   `require` (catalogued image or block). `build_image_id` pins one.
7. **Fixture discovery records become answer keys.** The SAT compares the plan with them; no job may
   read them.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Widen the regex collector until it proposes commands itself | Every build system and project convention becomes code we maintain; cannot reason over README text or CI recipes; still cannot recover from a failed configure. |
| Let the model read the whole checkout (agentic, tool use) | Unbounded cost and input; harder to cite and replay; more exposure to target-controlled text. The index gives the model what it needs, bounded and cited. |
| Model writes the Dockerfile | Gives target-influenced text control over `RUN`, repositories and downloads during a networked build. A structured spec keeps the effect to "these distro packages on this base". |
| Unbounded retry / human after the first failure | Unbounded is a cost and a loop risk; human-first defeats the purpose. A small budget with full attempt records hands the human a precise state when it fails. |
| Tracked, per-project catalog in the repository | Local images are identified by a local image id that means nothing on another host, and customer project identities should not land in the tracked repository. |

## Consequences

- Three new graph nodes and their schemas (`build-index`, `build-plan`, `build-image`), under the
  full job-graph protocol; `build_discovery` / `build_execution` retire when they land.
- B13 must resolve host-local `image_build_*` records in addition to tracked ones.
- The first model call in the pre-evidence process; its prompt hash, model and output are recorded
  per attempt so a result can be audited and replayed.
- Phase 4 and the build part of Phase 5 in `appsec-review-process/TODO.md` are replaced by this
  design.
- The SAT gains `build-index`, `build-plan`, `build-resolution` stages between the discovery gates
  and `build-configure`.

## Non-decisions

- Ecosystems beyond apt (pip, npm, cargo, Maven): each needs its own `package-restore` mirror; until
  then `BLOCKED(UNSUPPORTED_ECOSYSTEM)`.
- Windows and MSVC targets.
- Pruning of catalogued images.
