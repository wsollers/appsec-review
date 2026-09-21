# 07 -- Write the images-and-tools docs (image guidelines, bundled tools, host baseline)

Goal: image guidance lives only in `images/*/README.md` and scattered non-negotiables. Produce a
succinct `docs/images-and-tools/` bucket that states the rules once and inventories what exists.

## Inputs
- `images/*/README.md` (`audit-static`, `audit-native`, `audit-codeql`, `audit-iac`,
  `audit-container`, `audit-static-opengrep`, `audit-report`, `audit-buildenv-*`,
  `audit-binary-analysis`, `mythos-orchestrator`), `images/audit-buildenv-common/run.sh`.
- `README.md` §Non-negotiables; `docs/architecture/design-v3.md` §2.2.1 (isolation profile);
  ADR-0001, ADR-0003, ADR-0006; `orchestrator/dagster/README.md` (native Linux host facts, uid/gid,
  image pins); `docs/adapters/pinned-container-adapter.md` (how images are invoked).

## Steps
1. `docs/images-and-tools/guidelines.md`: pin every tool version at first write; argv arrays never
   shell strings; one tool per container; read-only workspace; hardened run profile; licensed inputs
   mounted never baked; how a new image is qualified (`qualify_tooling`).
2. `docs/images-and-tools/inventory.md`: one table -- image, purpose, bundled tools with pinned
   versions, which job/step invokes it, qualification status. Generate the tool/version column from
   the Dockerfiles rather than typing it, and say how to regenerate.
3. `docs/images-and-tools/host-baseline.md`: the durable host facts from `orchestrator/dagster/README.md`
   (not a dated snapshot -- the disposed `linux-host-baseline-2026-09-20.md` is the anti-pattern).

## Done when
Every image has a row in the inventory and every rule in `guidelines.md` cites the ADR or code that
enforces it.

## Touches
New files under `docs/images-and-tools/`, `docs/README.md`.
