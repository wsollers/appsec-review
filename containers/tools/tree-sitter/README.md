# Tree-sitter parser image

This image is the only supported runtime for AST production. It performs no grammar download or
compilation. `downloads/` is an ignored acquisition cache; every required byte is checked against
`assets.lock.json` before a build.

Acquire on Linux using the digest-pinned base image, download the exact binary wheels into
`downloads/wheels`, install those exact versions in the acquisition container, and run
`acquire_assets.py` with `/out` bound to `downloads`. Regenerate the lock only after recording each
grammar's upstream repository, release, license, generated library hash, and byte size.

The locked grammar set is C, C++, C#, Go, Java, JavaScript, Kotlin, PHP, PowerShell, Python,
Ruby, Rust, Shell (the upstream `bash` grammar), TSX, and TypeScript. `assets.lock.json` records the
upstream repository revision and license for each generated library; `verify_assets.py` rejects a
missing, additional, or hash-mismatched library. The acquisition helper fetches Kotlin,
PowerShell, and Bash explicitly along with the original grammar set, so the production build does
not depend on a runtime manifest or network access.

Review execution mounts the accepted target at `/target` read-only and a scope-specific scratch
directory at `/scratch`, and runs with working directory `/scratch` (the executor always passes
`--workdir`, overriding the image's `WORKDIR /work`). It uses `--network none`,
a read-only root filesystem, a non-root user,
dropped capabilities, `no-new-privileges`, and configured CPU, memory, PID, timeout, and output
bounds.
The host prepares each scope directory as container-writable and its request as world-readable
before launch. The request stays owner-writable instead of using a host read-only attribute because
Docker Desktop bind mounts can otherwise return an input/output error under concurrent readers.
This is required because the parser runs as uid/gid 10001 rather than the host process that
atomically created the request.

Build with no registry refresh, no build-step network, and no nondeterministic provenance wrapper:

```text
docker build --pull=false --network none --provenance=false \
  --file containers/tools/tree-sitter/Dockerfile \
  --tag appsec-review/tool-tree-sitter:1.0.0 containers/tools/tree-sitter
```
