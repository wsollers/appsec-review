# Tree-sitter parser image

This image is the only supported runtime for AST production. It performs no grammar download or
compilation. `downloads/` is an ignored acquisition cache; every required byte is checked against
`assets.lock.json` before a build.

Acquire on Linux using the digest-pinned base image, download the exact binary wheels into
`downloads/wheels`, install those exact versions in the acquisition container, and run
`acquire_assets.py` with `/out` bound to `downloads`. Regenerate the lock only after recording each
grammar's upstream repository, release, license, generated library hash, and byte size.

Review execution mounts the accepted target at `/target` read-only and a scope-specific scratch
directory at `/scratch` while the image working directory remains `/work`. It uses `--network none`,
a read-only root filesystem, a non-root user,
dropped capabilities, `no-new-privileges`, and configured CPU, memory, PID, timeout, and output
bounds.

Build with no registry refresh, no build-step network, and no nondeterministic provenance wrapper:

```text
docker build --pull=false --network none --provenance=false \
  --file containers/tools/tree-sitter/Dockerfile \
  --tag appsec-review/tool-tree-sitter:1.0.0 containers/tools/tree-sitter
```
