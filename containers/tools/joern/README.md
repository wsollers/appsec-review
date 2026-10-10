# tool-joern: pinned Joern/c2cpg runtime closure

This directory builds `appsec-review/tool-joern:4.0.630`: an offline, non-root image that holds the
reviewed Joern 4.0.630 C/C++ closure (the core Joern libraries plus the `c2cpg` frontend) on the
repository's digest-pinned Java 21 base.

**Status: the image is available, but it provides no coverage yet.** The C++ job's Joern branch
still publishes a `BLOCKED` shard. Bounded CPG/PDG export, source mapping, functional fixtures, and
security acceptance belong to later work items (see `docs/operations/cpp-compiled-analysis.md`).
A successful build or version probe is not CPG coverage.

## Files

| File | Role |
| --- | --- |
| `assets.lock.json` | Release provenance and exact URL, path, byte size, and SHA-256 of the archive and its SHA-512 sidecar, plus the upstream SHA-512 and signature status. |
| `tool.toml` | Runtime contract (non-root, no network, read-only root and target, limits, version probe) and the `[closure]` allowlist and extraction limits. |
| `Dockerfile` | Two-stage offline build: verify and unpack in `python:3.12-slim` (digest-pinned), then install into `appsec-review/base-jre:21-noble`. |
| `safe_extract.py` | Validates every archive member, installs only the closure allowlist, writes the deterministic inventory, and records JAR-manifest versions. |
| `inventory.json` | Committed, reviewed inventory of the installed closure: 222 files with path, kind, size, and SHA-256, plus Maven coordinates and embedded native libraries for each JAR. |
| `joern-version` | Version probe: runs the real `c2cpg` JVM entry point offline, then prints the recorded versions. |
| `LICENSE.md` | License, provenance, and vulnerability review notes, including the open items. |
| `downloads/` | Ignored fetch cache (`containers/.gitignore`). The ~1.86 GB archive is never committed. |

## Command flow

The release was selected and reviewed once, by hand. The commands below are the steps used. All
upstream content (release pages, archive, sidecar, install script) was treated as data; nothing
from it was executed during the review.

### 1. Select and pin the release (review time)

```sh
# Immutable tags, without the GitHub API. v4.0.630 (2026-09-17) was chosen over the newest daily
# tag so the release had several weeks of exposure.
git ls-remote --tags https://github.com/joernio/joern
git fetch --depth 1 origin refs/tags/v4.0.630:refs/tags/v4.0.630
git rev-parse v4.0.630              # tag object 1eaf54c2... (unsigned, created by the CI runner)
git rev-parse v4.0.630^{commit}     # commit 567be3ae... (GitHub web-flow signature on the commit only)
sha256sum LICENSE                   # Apache-2.0, recorded as license_sha256

# Asset names come from the release workflow (.github/workflows/release-github.yml at the tag):
# joern-cli-linux-x86_64.zip and joern-cli-linux-x86_64.zip.sha512. No .asc, .sig, sigstore
# bundle, or attestation exists, so signature_verification is "not-published".
curl -L -o joern-cli-linux-x86_64.zip        https://github.com/joernio/joern/releases/download/v4.0.630/joern-cli-linux-x86_64.zip
curl -L -o joern-cli-linux-x86_64.zip.sha512 https://github.com/joernio/joern/releases/download/v4.0.630/joern-cli-linux-x86_64.zip.sha512
stat -c %s joern-cli-linux-x86_64.zip       # 1858333634
sha256sum joern-cli-linux-x86_64.zip*        # recorded in assets.lock.json
sha512sum joern-cli-linux-x86_64.zip         # equals the sidecar value (sidecar names target/joern-cli-linux-x86_64.zip)
```

### 2. Review the archive and generate the inventory (review time)

The archive has 1,396 members, 2.23 GB expanded, a single `joern-cli/` root, and no symlinks,
duplicates, or unsafe names. It bundles **no JRE**: the launchers run `java` from `PATH`, so the
repository's pinned `base-jre` (Temurin 21, which upstream also builds and tests with) supplies it.
Thirteen language frontends are bundled. Six of them carry standalone native ELF AST generators;
these, Ghidra, `schema-extender`, and the sample scripts are excluded. The `[closure].include` list
in `tool.toml` keeps only:

```text
joern-cli/.installation_root  joern-cli/bin  joern-cli/conf  joern-cli/lib
joern-cli/joern  joern-cli/joern-parse  joern-cli/joern-export  joern-cli/joern-slice
joern-cli/c2cpg.sh  joern-cli/frontends/c2cpg
```

The installed closure has 222 files and 254 MB: 193 JARs, 16 launcher scripts, no ELF executables.
The committed inventory came from the verified archive, using the same helper and policy as the
image build:

```sh
python3 -I containers/tools/joern/safe_extract.py joern-cli-linux-x86_64.zip <empty-dir> \
    --policy containers/tools/joern/tool.toml \
    --lock containers/tools/joern/assets.lock.json \
    --inventory containers/tools/joern/inventory.json \
    --version-file <scratch>/VERSION
```

The license and advisory review of that inventory is recorded in `LICENSE.md`.

### 3. Fetch (catalog-driven; the only network step)

```sh
python3 containers/build.py build tool-joern     # fetch phase, then build; dependencies first
```

`build.py` reads `assets.lock.json` and streams each artifact into
`containers/tools/joern/downloads/` through a `.partial` file. It accepts the file only at the exact
byte size and SHA-256. On a mismatch or transfer error it deletes the partial file and fails. An
existing file is reused only after its size and SHA-256 are verified again (`CURRENT` in the fetch
log).

### 4. Offline image build (`docker build --network=none --pull=false`)

`build.py` passes the fixed build arguments from `containers/catalog.toml`: `TOOL_VERSION=4.0.630` and
`JOERN_SHA512=812cfd7b...`. The Dockerfile then runs these steps.

**Unpack stage** (`python:3.12-slim-bookworm@sha256:3923...`):

1. Copies the archive, the sidecar, `safe_extract.py`, `tool.toml`, `assets.lock.json`, and
   `inventory.json` from the local build context. Nothing comes from the network.
2. Checks that the sidecar's digest equals the pinned `JOERN_SHA512` build argument and that the
   sidecar names `joern-cli-linux-x86_64.zip`.
3. Checks the archive with `sha512sum --check --strict`.
4. Runs `python -I safe_extract.py ... --expect-inventory inventory.json`, which:
   - re-verifies the archive's size, SHA-256, and SHA-512 against `assets.lock.json`;
   - validates **all** members before writing anything. It rejects absolute, drive-qualified,
     backslash, `..`, `.`, and empty path components; duplicate or file/directory-conflicting
     names; members beneath a non-directory or symlink; escaping symlinks; all hard links;
     devices, FIFOs, and setuid, setgid, or sticky bits. It enforces the member-count,
     expanded-byte, per-member compression-ratio, and archive expansion-ratio limits;
   - writes only the allowlisted closure under `/opt/joern`, using `O_EXCL|O_NOFOLLOW` and
     enforcing each member's declared size;
   - regenerates the inventory and fails unless it equals the committed `inventory.json`;
   - writes `/opt/joern/VERSION` from the `Implementation-Title` and `Implementation-Version`
     fields in the hash-pinned `io.joern.joern-cli` and `io.joern.c2cpg` JAR manifests.
5. Requires `VERSION` to contain `joern-cli 4.0.630` and `c2cpg 4.0.630`, then deletes the archive
   from the stage.

**Runtime stage** (`appsec-review/base-jre:21-noble`, built from the digest-pinned Temurin image):

6. Copies `/opt/joern` (root-owned, and not writable by the runtime user) and installs
   `joern-version` with mode `0555`.
7. Runs `/opt/joern/bin/joern-version` and requires it to print `c2cpg 4.0.630`.
8. Ends with `USER 10001:10001` and `WORKDIR /scratch`. No entrypoint, ports, or volumes are
   defined.

The build never runs `joern-install.sh`, curl or wget, a package manager, Maven, SBT, or coursier,
and it never executes target code.

### 5. Verify the image

```sh
python3 containers/build.py smoke tool-joern     # runs version_argv under the central runtime policy
python3 containers/build.py security tool-joern  # uid, capabilities, NoNewPrivs, read-only root/target, writable scratch
```

Both commands use `--network none --read-only --user 10001:10001 --cap-drop ALL --security-opt
no-new-privileges`, the PID, memory, and CPU limits, and a `noexec` `/tmp` tmpfs.

## Recorded verification (2026-10-10, Linux x86-64, Docker 29.8.2)

- **Fetch:** archive `FETCHED 1858333634 92ee27a9...`; sidecar `FETCHED 164 a6a6d2d9...`.
- **Build:** `--network=none` build passed. The log shows `/tmp/joern.zip: OK`,
  `EXTRACTED files=222 bytes=254046742`, and `c2cpg 4.0.630`. Local image ID was
  `sha256:be11aaa8...`. It is environment-specific, so the catalog does not pin it.
- **Smoke:** `PASSED tool-joern startup`.
- **Security:** `build.py security` failed for `tool-joern` and for the existing `base-jre`
  alike, because the session ran as host root and the probe's new `root:root 0755` scratch
  directory is not writable by uid 10001. The same probe, rerun by hand with a scratch directory
  owned by 10001, passed:
  - uid and gid `10001:10001`, `CapEff` 0, `NoNewPrivs` 1;
  - target, root filesystem, and `/opt/joern` are read-only, and scratch is writable;
  - only the loopback interface is present;
  - no setuid or setgid files exist.

## Updating

Pick a new immutable tag and repeat steps 1 and 2. Then update `version`, `version_jars`, the asset
paths, `assets.lock.json`, the catalog `TOOL_VERSION` and `JOERN_SHA512`, the Dockerfile `COPY`
paths, and the regenerated `inventory.json`. Re-review `LICENSE.md`, then run `validate`, `build`,
`smoke`, `security`, and `tests/test_joern_tool.py`.
