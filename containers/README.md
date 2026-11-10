# Container packaging

`catalog.toml` is the inventory for every image built by `build.py`. For the legacy audit it
accounts for all 42 audited legacy image variants. The current enabled inventory contains 46
images: 32 tool images, four narrow shared runtime bases, and ten build environments (the shared
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
`tool-opengrep`, `tool-infer`, `tool-clangd-indexer`, `tool-clang-static-analysis`, `tool-svf`,
`tool-joern`, `tool-ghidra`, and `tool-report-latex` (report PDF rendering, see
[`report/latex/README.md`](report/latex/README.md); it replaces the deferred `audit-report`). The authoritative catalog currently enables 32 tool images; the other enabled
entries are the four bases and the ten build environments under `containers/buildenv/`.

CodeQL is the exception: its licensed source image is operator-provided and its derived
`appsec-review-codeql:*` analysis images are built by the CodeQL job
(`src/appsec_review/codeql/runtime.py`), so they are packaged outside the catalog as described in
[`tools/codeql/README.md`](tools/codeql/README.md). The catalog keeps the legacy `audit-codeql`
entry `deferred`.

[`services/garnet/`](services/garnet/README.md) is also outside the catalog. It holds the Windows Nano
Server build of the Garnet result-cache service, which an operator builds on a Windows-containers
Docker host. The catalog lists only linux/amd64 images that `build.py` builds and the review
launches, and this is neither. On Linux, Compose uses the upstream Garnet image pinned by digest.

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
steps run with networking disabled, and every build passes `--provenance=false --sbom=false`: under
Docker 29's containerd image store BuildKit otherwise wraps each export in a timestamped attestation,
so an image whose layers were all cache hits still gets a new ID, everything `FROM` it rebuilds, and
its pin moves on every run (seen on HAL5000, 2026-11-09: four full 25-minute builds of unchanged recipes). Logs and the machine-readable summary
(`appsec-review/container-build-summary/2`) are written under `runs/container-builds/<run-id>/`.
Each result records status, image id, tag, digest, log paths and the build's telemetry: `duration_seconds`
split into `fetch_seconds` and `build_seconds`, `assets` (`current`/`fetched` counts and bytes),
`size_bytes`, and `steps` parsed from the `--progress=plain` BuildKit log (`steps`, `cached_steps`,
`executed_steps`, `errored_steps`, `unfinished_steps`, `executed_seconds`, `slowest_step`). The summary's
`metrics` object totals these and names the `slowest` images and the dependency **critical path** — the
chain of images whose durations add up to the most, which is the lower bound on wall time at any
`--jobs` and therefore what to shorten first. The same report is printed at the end of every build
and by `containers/build.py report [summary.json] [--json]` (default: the latest summary). Any failed,
blocked, or skipped image makes the command fail, including with `--continue-on-error`. Images that install Python wheels offline with `--require-hashes` take them
from their asset lock, so a requirements bump must update the lock too;
`tests/test_container_requirements_lock.py` checks that every `requirements.txt` pin with a locked
wheel names that wheel's version and SHA-256.
`--timeout-seconds` bounds each `docker build` (default 1800, 60..14400). The review pipeline never
runs this builder: the operator rebuilds and re-pins images on the host, and every review verifies in
`job_image_pin_verification`, before intake, that each enabled image and pin resolves locally to
exactly its pinned image; see
[`../docs/operations/image-pin-verification.md`](../docs/operations/image-pin-verification.md).

Some locked assets are **host-local**: the launcher cannot download them, a helper produces them, and
the lock pins the result. The catalog names the helper as `acquire = "<script>"` and `build.py` runs it
when any locked local file under the image's `downloads/` is missing or does not match the lock —
once per host, the first time the image is built there, and again after a re-lock — removing the
files that no longer match first (the helpers produce what is missing and keep what exists), then
verifies the result; bytes that no
longer match mean the upstream moved, and re-locking is a reviewed edit, not something the launcher
does. Four images have one: `tool-native-cpp`, `tool-report-latex` and `tool-svf` (`.deb` closures
resolved against the Ubuntu **snapshot** service inside a pinned image by their `acquire_assets.sh`,
with the host's CA bundle lent read-only; the lock URL is the archive root, which marks the artifact
as not fetchable) and `tool-tree-sitter` (`acquire_assets.sh` downloads the two
hash-locked wheels and runs `acquire_assets.py` in the pinned base for the grammar libraries; its lock
has no `artifacts` list, the wheels and grammars themselves are the local files). The helpers may use
the network; builds still never do. `tool-sqlite-fts` has no asset lock.

## Rule and query packs

Every analysis rule and query pack is registered in [`../rules/registry.toml`](../rules/registry.toml)
and verified by the builder:

```text
containers/build.py query-packs            # every enabled pack
containers/build.py query-packs <pack-id>
```

CodeQL packs are type-checked with `codeql query compile --check-only` inside their pinned image
with networking disabled; Semgrep and PMD packs are validated the way the review invokes them. Any
pack that does not verify fails the command, and the failure names the pack, the error count and
the first error with its file and line. Logs are written under
`runs/container-builds/<run-id>/logs/<pack-id>.verify.log`.

The registry pins the analysis library each pack is written against (`library`), and verification
asserts that version is installed before compiling. Image smoke tests prove a tool starts; they do
not prove our queries still compile against the library the image ships. See
[`../rules/README.md`](../rules/README.md) for the field reference.

## Runtime boundary

`runtime-policy.toml` is the packaging acceptance boundary: no network, non-root UID/GID 10001,
read-only root, all capabilities dropped, `no-new-privileges`, bounded CPU/memory/PIDs/time/output,
a read-only target mount, and one writable scratch mount. Image definitions package tools only.
Application jobs own arguments and translate tool output into findings.

A catalog entry may pin `image_id`; the application executor then refuses to run a local image
whose id differs (`src/appsec_review/container_runtime/executor.py`). With the opt-in
`[signing] image_enforcement = "required"`, pinned or not, it also refuses
an image whose id has no signature envelope from a trusted operator key; sign images after building
and re-pinning them (see [`../docs/operations/signing.md`](../docs/operations/signing.md)).
Image-ID pins are host-local:
a rebuilt image's id is not reproducible across hosts, results are never compared across hosts,
and a changed pin means rerunning, not a defect (asset locks stay exact). `job_image_pin_verification`
fails a review whose local images do not match their pins, and `appsec-review update-image-pins`
re-pins them on the host; see
[`buildenv/README.md`](buildenv/README.md) and T-051 in [`../docs/TODO.md`](../docs/TODO.md). Every enabled tool is
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
