---
title: "Task plan T-177: Rebuild and register container images compile CodeQL packs and refresh Dagster pins"
kind: "task"
subsystem: "images and deployment"
status: "current"
jobs: ["job_codeql_analysis", "job_image_pin_verification", "job_model_connectivity"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Task plan T-177: Rebuild and register container images compile CodeQL packs and refresh Dagster pins

This plan implements **T-177** (`docs/TODO.md`): provisioning and verifying the WSL review host
(`WSOLLERS1`, `/home/wsollers/projects/appsec-review`) so all nine smoke targets, active container
catalog images, compiled CodeQL query packs, the Dagster application image, and operator-signed
host image pins (`deploy/dagster/host-pins.toml`) are ready for a subsequent user-authorized run
against `targets/appsec-review-smoke-cpp`.

## Completed smoke-repository provisioning

- Synced `/home/wsollers/projects/appsec-review` (`main`) on ext4 in WSL via `ssh wsl-ubuntu`.
- Cloned all nine language smoke targets under `targets/appsec-review-smoke-<lang>` at detached tag
  `v1.0.0`:
  - `cpp` (`bededb6`), `java` (`3219d17`), `javascript` (`84e3c01`), `python` (`0821c00`),
    `ruby` (`c82179d`), `go` (`5f83d50`), `csharp` (`887af65`), `rust` (`6a11cc9`), `php` (`ef0c942`).
- Cloned `wsollers/appsec-review-smoke-guide` (`dc69349`) strictly outside the repository at
  `/home/wsollers/projects/appsec-review-smoke-guide` to preserve blind-target isolation
  (`tests/test_blind_target_isolation.py`).

## Technical execution steps in WSL (`ssh wsl-ubuntu`)

1. **Container catalog rebuild & smoke verification (`containers/build.py`):**
   - With `tool-joern` and `tool-svf` marked `manual = true` (`T-168`), build all active base,
     `buildenv-*`, and `tool-*` images (including `tool-report-latex`) using
     `.venv/bin/python containers/build.py` in topological dependency order with BuildKit
     reproducible flags (`--provenance=false --sbom=false`).
   - Run catalog smoke probes (`probe_argv` / `probe_expect`, uid `10001`, read-only rootfs,
     no-network runtime policy) across built images.
2. **Compile custom & graph-export CodeQL packs (`scripts/compile-codeql-queries.sh`):**
   - Recompile custom and graph-export `.ql` packs against the pinned `tool-codeql` release image
     (never warming standard precompiled suites, per `AGENTS.md`).
3. **Rebuild Dagster application image & reload source mount (`scripts/stack-rebuild.sh`):**
   - Rebuild the Dagster tooling image if interpreter/dependency layers changed, re-sign the
     read-only mounted repository source tree (`implementation-release.json`), and verify container
     health without launching an unauthorized review run.
4. **Update and operator-sign `deploy/dagster/host-pins.toml`:**
   - Bind observed `sha256:...` image digests for every configured pin source into
     `deploy/dagster/host-pins.toml` and sign with `/home/wsollers/.config/appsec-review/signing/private/operator.pem`.

## Schema and telemetry specification

```text
Verified operational schemas:
- appsec-review/container-catalog/1
- appsec-review/container-build-summary/2  (step cache ratios, wall/build seconds, critical path, sizes)
- appsec-review/host-image-pins/1          (digest bindings + Ed25519/ECDSA operator signature envelope)

Telemetry & metrics recorded:
- build.images_passed, build.wall_seconds, build.critical_path,
  codeql.packs_compiled, pins.verified_sources_count
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Update [`../operations/run-readiness.md`](../operations/run-readiness.md),
   [`../operations/test-targets.md`](../operations/test-targets.md),
   [`../architecture/images-and-deployment.md`](../architecture/images-and-deployment.md),
   `docs/docs-ledger.json`, and run `scripts/generate-docs.py`.
2. **Full indexing & runtime readiness:** Confirm every tool image producing indexed shards
   (`tool-codeql`, `tool-semgrep`, `tool-opengrep`, `tool-clang-tidy`, `tool-clangd-indexer`,
   `tool-cppcheck`, `tool-infer`, `tool-bandit`, `tool-gosec`, `tool-brakeman`, `tool-trivy`,
   `tool-grype`, `tool-syft`, `tool-blint`, `tool-ghidra`, `tool-dwarfdump`, `tool-pdb-Inspect`,
   `tool-report-latex`) is built, smoked, and digest-pinned on WSL.
3. **Fast, isolated unit tests (`<10s`):** Run `tests/unit/job_image_pin_verification/` and
   `tests/test_blind_target_isolation.py` in `<10s` per test to confirm catalog-to-pin parity and
   zero answer-key leakage under `targets/`.
4. **Common querying & indexing skills doc alignment:** Confirm producer container availability
   matches the shard table in
   [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md).
5. **Frontier prompting, roles & skills alignment:** Verify `lifecycle.py reload` signs the updated
   `pipeline/guidance/` and `pipeline/skills/` bundles into the mounted release manifest.
6. **Metrics & telemetry:** Record `container-build-summary/2` timings, image sizes, and CodeQL
   pack compilation timings in this task record upon completion.
7. **Proper schema versioning & live-run gate:** Verify `host-pins.toml` signature and stop cleanly
   **before** launching a live Dagster review or executing any PoCs, awaiting explicit user command.

## Recorded verification results (2026-11-17)

- **Catalog build & smoke (`runs/container-builds/20261117T204749Z-60611/summary.json`):**
  - Updated `containers/build.py` (`selected_ids`) so `--all` excludes `manual = true` images
    (`tool-svf`, `tool-joern`, `tool-report-latex`) unless `--include-manual` is set, and bounded
    `containers/tools/svf/Dockerfile` CMake parallelism to `-j2` to fit `appsecreview-engine.slice`
    (`CPUQuota=200%`, `MemoryMax=2G`, `MemorySwapMax=0`).
  - Built and startup-smoked all **44** non-manual enabled images (`passed=44`, `wall=1368.4s`,
    `build=1353.6s`, `fetch=12.0s`, `cached_steps=140`, `executed_steps=426`, `size=12110MB`,
    `critical_path=340.5s`: `base-ubuntu -> buildenv-native-toolchain -> audit-buildenv-rust-wasm`),
    plus verified `PASSED tool-report-latex startup`.
- **Host pins & image signatures (`runs/run-readiness/20261117T204749Z/`):**
  - Updated `deploy/dagster/host-pins.toml` (`sha256: e63e36fb0894a82bc8e5a39ca248487e2bd78135e5e786f34eb48e5b6c23253f`,
    `checked=48`, `edits=0`, `failures=0`) and signed all 48 image digests under
    `/var/lib/appsec-review/signing/images/`.
- **CodeQL pack compilation:**
  - Compiled all **8** active `graph-export-*` packs (`cpp` 101s, `java` 7s, `javascript` 7s,
    `python` 6s, `ruby` 7s, `go` 6s, `csharp` 8s, `rust` 7s; `summary=packs=15 failed=0`) into
    `appsec-codeql-compile-68c7e693d38170f016750452`.
- **Dagster stack rebuild & health:**
  - Ran `deploy/dagster/bin/bootstrap.py` and `scripts/stack-rebuild.sh --no-probe --target appsec-review-smoke-cpp`;
    rebuilt and signed the Dagster application image, reloaded the signed mounted source tree, and
    verified `postgres`, `code-location`, `daemon`, `webserver`, and `result-cache` all
    `running (healthy)`. No live review run or PoC execution was launched.
