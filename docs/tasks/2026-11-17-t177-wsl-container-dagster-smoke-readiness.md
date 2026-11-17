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
