# opengrep tool image

`appsec-review/tool-opengrep:1.30.2` is the tool image declared by `tool-opengrep` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM` `appsec-review/base-ubuntu:24.04`,
which must exist locally first. Its single external artifact, the upstream
`opengrep_manylinux_x86` release launcher, is pinned by exact byte size and SHA-256 in
`assets.lock.json` and is fetched into the ignored `downloads/` directory. Upstream publishes a
Sigstore signature that this build does not consume; the lock records it as `not-performed`.

The launcher is a self-extracting payload, so a digest-pinned Ubuntu stage extracts it once at build
time and the image runs the extracted `/opt/tool/opengrep/opengrep.bin` directly. No rules are in the
image.

## Use

`job_evidence_collection` runs it through the `tool-opengrep` adapter with only the portable SEI CERT
rule pack (`rules/sei-cert/`). The pack is mounted read-only at `/rules-sei-cert` only after its files
match `rules/sei-cert/pack.lock.json`; otherwise the adapter does not run and reports the pack as
unavailable. The target is mounted read-only at `/target`, output goes to the writable `/scratch`,
and the run uses `tool.toml` and
[`runtime-policy.toml`](../../runtime-policy.toml): no network, UID/GID 10001, read-only root,
dropped capabilities, `no-new-privileges`, and bounded CPU, memory, PIDs, time, and output.

## Build

Run from the repository root. The launcher builds missing dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-opengrep
containers/build-all.ps1 build tool-opengrep
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false \
  --file containers/tools/opengrep/Dockerfile \
  --build-arg TOOL_VERSION=1.30.2 \
  --tag appsec-review/tool-opengrep:1.30.2 containers/tools/opengrep
```

Run the startup smoke test, and the functional smoke test against the Semgrep fixture:

```text
containers/build-all.sh smoke tool-opengrep
containers/build-all.sh smoke --functional tool-opengrep
```
