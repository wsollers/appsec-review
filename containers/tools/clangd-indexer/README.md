# tool-clangd-indexer: pinned clangd static indexer

This directory builds `appsec-review/tool-clangd-indexer:23.1.0`, an offline, non-root image
containing `clangd-indexer` from the clangd 23.1.0 release. The indexer reads a compilation
database and emits a static symbol and reference index (declarations, definitions, references,
relations). It accepts both GCC/Clang-style and **clang-cl (MSVC-style)** compile commands, which
is why it was chosen as the first C++ indexer for MSVC/Unreal-scale codebases.

**Status: the image is available, but it provides no coverage yet.** Normalizing the index into
retrieval shards, per-TU batching, and job integration are later work. A successful build or
smoke run is not index coverage.

## Files

| File | Role |
| --- | --- |
| `assets.lock.json` | Release provenance, plus the exact URL, path, byte size, SHA-256 and SHA-512 of the archive and its signature status. |
| `tool.toml` | Runtime contract (non-root, no network, read-only root and target, limits, version probe) and the `[closure]` allowlist and extraction limits. |
| `Dockerfile` | Two-stage offline build: verify and unpack in `python:3.12-slim` (digest-pinned), then install into `appsec-review/base-ubuntu:24.04`. |
| `../shared/safe_extract.py` | Shared helper, copied in through the `shared` named build context. Validates every archive member, installs only the closure, and writes or compares the inventory. |
| `inventory.json` | Committed, reviewed inventory of the installed closure: 335 files with path, kind, size and SHA-256. |
| `LICENSE.md` | License, provenance and vulnerability review notes, including the open items. |
| `../../fixtures/clangd-indexer/` | Functional fixture: one Clang TU and one clang-cl TU. |
| `downloads/` | Ignored fetch cache. The 160 MB archive is never committed. |

## Build commands

Run everything from the repository root.

```sh
# Validate the catalog, locks, and Dockerfile policy (no network, no Docker).
python3 containers/build.py validate

# Fetch the archive (the only network step) and build the image offline.
# Dependencies such as base-ubuntu are built first.
python3 containers/build.py build tool-clangd-indexer

# Version smoke, plus the functional fixture (indexes a Clang TU and a clang-cl TU).
python3 containers/build.py smoke tool-clangd-indexer --functional

# Runtime boundary: uid, capabilities, NoNewPrivs, read-only root/target, writable scratch.
python3 containers/build.py security tool-clangd-indexer

# Unit tests for this closure and the shared extraction helper (no network, no Docker).
python3 -m pytest tests/test_clangd_indexer_tool.py tests/test_safe_extract.py
```

On Windows, use `containers/build-all.ps1` with the same arguments; `containers/build-all.sh` is the
POSIX equivalent.

### What `build` does

1. **Fetch.** `build.py` reads `assets.lock.json` and streams
   `clangd_indexing_tools-linux-23.1.0.zip` into `downloads/` through a `.partial` file. It accepts
   the file only at exactly 159,888,487 bytes and SHA-256 `48259f33…a763`. On a mismatch or
   transfer error it deletes the partial file and fails. An existing file is reused only after its
   size and SHA-256 are verified again.
2. **Docker build.** `build.py` runs:

   ```sh
   docker build --network=none --pull=false \
     --file containers/tools/clangd-indexer/Dockerfile \
     --tag appsec-review/tool-clangd-indexer:23.1.0 \
     --build-arg CLANGD_SHA512=1c901aca… --build-arg TOOL_VERSION=23.1.0 \
     --build-context shared=containers/tools/shared \
     containers/tools/clangd-indexer
   ```

3. **Unpack stage**, inside the build:
   - checks the archive against the pinned SHA-512 build argument (`sha512sum --check --strict`);
   - runs `safe_extract.py`, which:
     - re-verifies size, SHA-256 and SHA-512 against the lock;
     - validates every member before writing anything;
     - installs only the closure under `/opt/clangd`;
     - fails unless the result equals the committed `inventory.json`.
4. **Runtime stage:**
   - copies `/opt/clangd` (root-owned, not writable by the runtime user);
   - runs `clangd-indexer --version` and requires `LLVM version 23.1.0`;
   - ends with `USER 10001:10001` and `WORKDIR /scratch`. No entrypoint, ports or volumes are
     defined.

### Running the indexer by hand

```sh
docker run --rm --network none --read-only --user 10001:10001 \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 1g --cpus 2 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m \
  --mount type=bind,src="$PWD/containers/fixtures/clangd-indexer",dst=/workspace,readonly \
  appsec-review/tool-clangd-indexer:23.1.0 \
  /opt/clangd/clangd_23.1.0/bin/clangd-indexer --executor=all-TUs --format=yaml \
  /workspace/compile_commands.json
```

- **Paths.** The compilation database must use container paths (`/workspace/...`).
- **Output.** `--format=yaml` writes a readable index to stdout. The default binary RIFF format is
  clangd's internal format, versioned with clangd, and is not a public schema.
- **MSVC builds.** clang-cl commands also need the MSVC and Windows SDK headers mounted read-only.
  Those are licensed inputs and are never committed.

## How the release was selected and reviewed

```sh
# Release tags (the clangd/clangd repository holds only release automation).
git ls-remote --tags https://github.com/clangd/clangd        # 23.1.0 -> 0d73b70d… (lightweight)
git ls-remote https://github.com/llvm/llvm-project refs/tags/llvmorg-23.1.0

# Download and hash. Upstream publishes no checksum or signature.
curl -L -o clangd_indexing_tools-linux-23.1.0.zip \
  https://github.com/clangd/clangd/releases/download/23.1.0/clangd_indexing_tools-linux-23.1.0.zip
stat -c %s clangd_indexing_tools-linux-23.1.0.zip   # 159888487
sha256sum clangd_indexing_tools-linux-23.1.0.zip    # 48259f33…a763
sha512sum clangd_indexing_tools-linux-23.1.0.zip    # 1c901aca…c2b0

# Generate the committed inventory with the same helper and policy as the image build.
python3 -I containers/tools/shared/safe_extract.py clangd_indexing_tools-linux-23.1.0.zip <empty-dir> \
  --policy containers/tools/clangd-indexer/tool.toml \
  --lock containers/tools/clangd-indexer/assets.lock.json \
  --inventory containers/tools/clangd-indexer/inventory.json
```

**What's in the archive.** It has 439 members (287 MB expanded) under a single `clangd_23.1.0/`
root, with no symlinks:

- `bin/`: `clangd-indexer`, `clangd-index-server` and `clangd-index-server-monitor`;
- `lib/clang/23/`: builtin headers, compiler-rt runtime libraries and sanitizer ignore lists;
- `LICENSE.TXT`.

**What's installed.** Only `clangd-indexer`, `LICENSE.TXT` and `lib/clang/23/include`. The
builtin headers are required to parse any TU. The network index server, its monitor, and the
runtime libraries are excluded.

**The binary.** `clangd-indexer` is dynamically linked against glibc only (requires glibc 2.18 or
later). It statically includes zlib 1.2.11; see `LICENSE.md`.

## Updating

Pick a new clangd release and repeat the review. Then update `version`, the closure paths
(`clangd_<version>/…`, `lib/clang/<major>/include`), `assets.lock.json`, the catalog
`TOOL_VERSION` and `CLANGD_SHA512`, the Dockerfile `COPY` path, the functional smoke argv in
`containers/build.py`, and the regenerated `inventory.json`. Re-review `LICENSE.md`, then run the
build commands above.
