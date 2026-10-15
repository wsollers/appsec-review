# Container packaging

`catalog.toml` is the inventory for every image built by `build.py`. For the legacy audit it
accounts for all 42 audited legacy image variants. The current enabled inventory contains 44
images: 30 tool images, four narrow shared runtime bases, and ten build environments (the shared
native toolchain plus the C/C++, Go, Python, PHP, Rust/WebAssembly, Node/TypeScript, Android,
Java/Kotlin and .NET
buildenvs). An
entry is always `enabled`, `deferred`, `replaced`, or `retired`; absence is not a decision.

## Moving forward, not reproducing

Images are built to work on the host that runs reviews, then recorded. Byte-identical rebuilds and
cross-host comparison are not goals. Upstream archives move, so an acquisition or rebuild may
produce new bytes; that is expected. When an image breaks or an asset no longer matches, re-acquire
from the current upstream, rebuild, smoke it, and record the result: the new asset size and SHA-256
in its `assets.lock.json` and the new image ID in its pins. A lock or pin records what a working
build used. It is not a target to recreate. Do not chase an old hash or compare image IDs between
machines.

The catalog also enables tools that were not derived from the legacy archive: `tool-actionlint`,
`tool-cppcheck`, `tool-native-cpp`, `tool-tree-sitter`, `tool-sqlite-fts`, `tool-git`, `tool-pmd`,
`tool-opengrep`, `tool-infer`, `tool-clangd-indexer`, `tool-clang-static-analysis`, `tool-joern`, and
`tool-ghidra`. The authoritative catalog currently enables 30 tool images; the other enabled
entries are the four bases and the ten build environments under `containers/buildenv/`.

CodeQL is the exception: its licensed source image is operator-provided and its derived
`appsec-review-codeql:*` analysis images are built by the CodeQL job
(`src/appsec_review/codeql/runtime.py`), so they are packaged outside the catalog as described in
[`tools/codeql/README.md`](tools/codeql/README.md). The catalog keeps the legacy `audit-codeql`
entry `deferred`.

## Build and validation

The Bash and PowerShell launchers call the same engine and therefore have identical selection and
failure behavior:

```text
containers/build-all.sh --list
containers/build-all.sh --validate-only
containers/build-all.sh build tool-gitleaks tool-semgrep tool-infer
containers/build-all.sh build --all --jobs 4 --continue-on-error
containers/build-all.sh smoke --all
containers/build-all.sh security --all

containers/build-all.ps1 --list
containers/build-all.ps1 --validate-only
containers/build-all.ps1 build tool-gitleaks tool-semgrep tool-infer
containers/build-all.ps1 build --all --jobs 4 --continue-on-error
containers/build-all.ps1 smoke --all
containers/build-all.ps1 security --all
```

Running either launcher with no arguments means `build --all`. `list <ids>` restricts the listing
and `list --json` prints machine-readable id, state, tag, and dependencies. `smoke` runs the startup
version check; `smoke --functional` adds the fixture-based functional checks. Set
`APPSEC_DOCKER_BIN` to use a Docker-compatible client other than `docker` for build, smoke, and
security commands; the application runtime always invokes `docker`.

Before each build, external artifacts are downloaded over HTTPS into an ignored `downloads/`
directory and verified against the declared byte size and SHA-256 in `assets.lock.json`. Docker build
steps run with networking disabled. Logs and the machine-readable summary are written under
`runs/container-builds/<run-id>/`; each result records status, duration, image id, tag, digest, and
log paths. Any failed, blocked, or skipped image makes the command fail, including with
`--continue-on-error`.
`--timeout-seconds` bounds each `docker build` (default 1800, 60..14400). A review run rebuilds the
catalog through this builder in `job_tool_image_rebuild` before intake and fails when any image does
not build; see [`../docs/operations/tool-image-rebuild.md`](../docs/operations/tool-image-rebuild.md).

Some locked assets cannot be downloaded by the launcher and must be placed in `downloads/` by hand
before a build: the `tool-native-cpp` `.deb` closure (its lock URL is the archive root; see
[`tools/native-cpp/README.md`](tools/native-cpp/README.md)) and the `tool-tree-sitter` wheels and
parsers produced with `acquire_assets.py` (its lock lists no fetchable artifacts; see
[`tools/tree-sitter/README.md`](tools/tree-sitter/README.md)). `tool-sqlite-fts` has no asset lock.

## Runtime boundary

`runtime-policy.toml` is the packaging acceptance boundary: no network, non-root UID/GID 10001,
read-only root, all capabilities dropped, `no-new-privileges`, bounded CPU/memory/PIDs/time/output,
a read-only target mount, and one writable scratch mount. Image definitions package tools only.
Application jobs own arguments and translate tool output into findings.

A catalog entry may pin `image_id`; the application executor then refuses to run a local image
whose id differs (`src/appsec_review/container_runtime/executor.py`). Image-ID pins are host-local:
a rebuilt image's id is not reproducible across hosts, results are never compared across hosts,
and a changed pin means rerunning, not a defect (asset locks stay exact). `job_tool_image_rebuild`
reports stale pins and `appsec-review update-image-pins` rewrites them; see
[`buildenv/README.md`](buildenv/README.md) and the last bullet of [`TODO.md`](TODO.md). Every enabled tool is
expected to have a static evidence-collection adapter unless its `tool.toml` sets
`static_adapter = false`; tools with that opt-out are run by their own jobs instead. `tool-ghidra`
is the one tool run by a pre-run command, `appsec-review binary-decompile`, which raises memory,
CPU, PID, and time limits from the typed `[binary_decompilation]` configuration and leaves every
isolation setting at this boundary (see
[`tools/ghidra/README.md`](tools/ghidra/README.md)).

## Updating a pin

1. Select a fixed upstream release and supported architecture; never infer another architecture
   from an amd64 artifact.
2. Review the authoritative project license and provenance.
3. Replace every artifact URL, exact byte size, and SHA-256 in `assets.lock.json`. Record signature
   verification when the upstream publishes a usable signature. A checksum over authenticated HTTPS
   is the minimum accepted verification mode.
4. Update `tool.toml`, the catalog version/tag/build argument, and any hash-pinned local rules.
5. Run validation, build the selected image, run startup and functional smoke tests, lint every
   Dockerfile, and record the result in the review artifact.

The build system never accepts secrets as build arguments and never executes downloaded installer
scripts. Cached downloads are disposable; the committed lock files are authoritative.
