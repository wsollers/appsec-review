# Per-tool images

Status: **16 registered images** (the original 13 were built 2026-09-26; OSV Scanner, Microsoft
SBOM Tool and sbomasm were added afterward and independently built/smoke-tested inside the B13 boundary). Decided by
William, 2026-09-26: **one Docker image per tool**, so a tool is updated by itself; tools are bundled only
when one needs another package to run (gosec needs the Go toolchain, mobsfscan imports semgrep, Find
Security Bugs is a SpotBugs plugin). Each image is built from our own Dockerfile on a digest-pinned base,
installing the tool's release asset at a pinned version whose hash was verified against the vendor.

These images replace the tool bundles in `images/audit-static` for the scan jobs (TODO.md Phase 7). The
scan jobs themselves (deterministic Python, no persona, configuration passed in) are not built yet;
`audit-static` is unchanged until they are.

## The images

| Image | Tool | Feeds | Verified by | Bundled |
|---|---|---|---|---|
| `tool-checkov` | checkov 3.3.19 | 02-iac-config-scan | pip lock, 96 wheels (PyPI sha256) | - |
| `tool-gitleaks` | gitleaks 8.30.1 | 02-secrets-inventory | vendor-checksums | - |
| `tool-gosec` | gosec 2.29.0 | 02-source-sast | sigstore-key-checksums, vendor-sha256-file | Go 1.27.1 toolchain |
| `tool-grype` | grype 0.119.0 | 02-sca-vulnerability-match | sigstore-cert-checksums | - |
| `tool-hadolint` | hadolint 2.15.1 | 02-iac-config-scan | vendor-checksums | - |
| `tool-microsoft-sbom-tool` | Microsoft SBOM Tool 4.1.5 | 02-sbom-inventory | vendor-spdx | - |
| `tool-mobsfscan` | mobsfscan 1.0.1 | 02-mobile-sast | pip lock, 77 wheels (PyPI sha256) | semgrep (Python library mobsfscan imports) |
| `tool-osv-scanner` | OSV Scanner 1.9.2 | 02-sca-vulnerability-match | vendor-checksums | - |
| `tool-phpcs` | phpcs 4.0.4 | 02-source-sast | pgp | - |
| `tool-phpstan` | phpstan 2.2.16 | 02-source-sast | pgp | - |
| `tool-psalm` | psalm 6.18.1 | 02-source-sast | pgp | - |
| `tool-sbomasm` | sbomasm 2.1.1 | 02-sbom-inventory | vendor-checksums | - |
| `tool-semgrep` | semgrep 1.178.0 | 02-source-sast | pip lock, 66 wheels (PyPI sha256) | - |
| `tool-spotbugs` | spotbugs 4.10.4 | 02-source-sast | pgp | Find Security Bugs 1.14.0; Temurin 21 JRE (base) |
| `tool-syft` | syft 1.52.0 | 02-sbom-inventory | sigstore-cert-checksums | - |
| `tool-trivy` | trivy 0.74.0 | 02-iac-config-scan | sigstore-checksums | - |
| `tool-zizmor` | zizmor 1.30.1 | 02-iac-config-scan (GitHub Actions, D-34) | pip lock, 1 wheel(s) (PyPI sha256) | - |

Bases (pinned by index digest): Docker Official Image `ubuntu:24.04` for the static binaries,
`python:3.12-slim-bookworm` for the pip tools, `php:8.4-cli-bookworm` for the PHP tools,
`eclipse-temurin:21-jre-noble` for SpotBugs, and `mcr.microsoft.com/dotnet/runtime-deps:8.0-noble`
for Microsoft's self-contained SBOM binary. Every base reference is pinned by digest.

## Layout of one tool folder

```
images/tool-<name>/
  tool.json         appsec-review/tool-image/1: tool, version, feeds, executable, version probe,
                    vendor asset URLs ({version} templates) and how each is verified, offline smoke runs
  image.json        appsec-review/image-build/1 (image_build.py). Its download steps and TOOL_VERSION
                    are written by `tool_pins.py pin`, never by hand
  pin-record.json   what pin verified, against what (checksum file, signature, key), and when
  Dockerfile        digest-pinned bases; installs only files from downloads/; no download, no
                    ENTRYPOINT/CMD; ends as USER 10001
  requirements.txt  pip tools only: uv-compiled lock with every sha256
  keys/             committed public keys (PGP by fingerprint, cosign by sha256)
  smoke-config/     only where a smoke run needs a tool config (psalm)
  downloads/        fetched by image_build.py, gitignored
```

Rules `tool_pins.py check` enforces offline (and `images/tests/test_tool_pins.py` runs): the three JSON
files and the Dockerfile agree; every base is `@sha256:`; the Dockerfile has no `curl`/`wget`, no
ENTRYPOINT/CMD, copies only `downloads/` and the pip lock, and ends as uid 10001; every image.json hash is
the verified pin; asset URLs are https; the executable is absolute (B13 runs argv[0] as the entrypoint).

## Verification at pin time

`python -B images/tool_pins.py pin <image_id> [--version V]` downloads each asset and verifies it before
anything is written. It fails closed: a missing entry, a mismatch, a missing verifier or a bad
signature writes nothing.

| Kind | Used by | What is checked |
|---|---|---|
| `vendor-checksums` | gitleaks, hadolint, sbomasm | sha256 listed in the release's own checksums file |
| `sigstore-checksums` | trivy | vendor checksums, and the checksums file verified with `cosign verify-blob --bundle` against the release workflow's identity and GitHub's OIDC issuer |
| `sigstore-cert-checksums` | syft, grype | the same, with the detached `.sig` and `.pem` Anchore publishes |
| `sigstore-key-checksums` | gosec | the same, with gosec's cosign public key (committed, pinned by sha256) |
| `vendor-sha256-file` | Go toolchain | the `.sha256` Google publishes next to the archive |
| `vendor-spdx` | Microsoft SBOM Tool | the exact asset's sha256 in Microsoft's accompanying SPDX release manifest |
| `pgp` | spotbugs, Find Security Bugs, phpstan, psalm, phpcs | detached `.asc` by the pinned key fingerprint (key committed in `keys/`) |
| pip lock | semgrep, checkov, mobsfscan | `uv pip compile --generate-hashes` for Python 3.12 / glibc 2.36; `pip download --require-hashes` fetches the exact wheels; each wheel's sha256 is matched to PyPI's JSON and declared as a checksummed download |

Trust notes: the PGP keys and gosec's cosign key were taken on first use (keyserver.ubuntu.com, the
gosec repository) and are now pinned; a key rotation is a deliberate change. A sigstore signature proves
the vendor's release workflow produced the checksums, not that the release is clean: trivy v0.69.4
(and v0.69.5/v0.69.6 on Docker Hub) were malicious releases signed by the compromised pipeline
(GHSA-69fq-xp46-6x23), which is why versions are chosen deliberately and never "latest".

Pinning needs network, `cosign` (sigstore kinds), `gpg` (pgp) and `uv` (pip tools) on the host. Building
needs only the host download of the pinned files: nothing inside `docker build` reaches the network
except the base-image pull (pip installs with `--no-index` from the verified wheels).

## Build, smoke, update

```bash
python -B images/tool_pins.py list
python -B images/tool_pins.py check                     # offline, all tools
python -B images/image_build.py build tool-gitleaks     # one tool; each build is independent
python -B images/tool_pins.py smoke tool-gitleaks --target fixtures/targets/hello-autotools
```

`smoke` runs the built image with the exact B13 boundary flags (imported from
`container_execution.BOUNDARY_FLAGS`: `--network none`, `--read-only`, `--cap-drop ALL`,
`no-new-privileges`, uid 10001, `HOME=/tmp` on a `noexec` tmpfs), the target mounted read-only at
`/workspace`, one writable `/scratch`, and a tool configuration mounted read-only at `/config` where
needed. Each smoke run asserts the exit code and an output: e.g. semgrep finds the planted `std::strcpy`
in `src/greet.cpp`, trivy reports Dockerfile misconfigurations, hadolint reports DL3008.

To update a tool: change `version` in its `tool.json`, `pin`, `check`, `image_build.py build`, `smoke`,
commit the folder. On hal5000, `image_build.py publish <id>` and commit `images/published.lock.json` so
other hosts pull it ([ADR-0033](../decisions/ADR-0033-shared-images-google-drive.md)).

A Dependabot (or other reviewed) bump of a pip lock changes the lock but not `pin-record.json`, so
`check` fails. Re-record it without re-resolving: `python -B images/tool_pins.py pin <image_id>
--keep-lock` reads the committed lock as-is (fails if there is none), downloads and hash-checks the
wheels it names, and records the lock's hash. Used for `tool-checkov` and `tool-mobsfscan` on
2026-09-29 (`1661f48`).

## Reverse-engineering tools in audit images (Ghidra, x64dbg)

Ghidra and x64dbg live in the two audit images that hold binaries, not in a `tool-*` image:
`audit-binary-analysis` (debian:bookworm-slim) and `audit-native` (ubuntu:24.04). They are installed
by `curl` in the Dockerfile like every other tool there, and each download is checked with
`sha256sum -c` against a pinned hash. Because these images are not `tool-*` images, `tool_pins.py` does
not cover them. `images/tests/test_reverse_tools.py` keeps the pins and the shared Dockerfile blocks
the same in both images.

| Tool | Version | Pin and how the hash was verified | Images |
|---|---|---|---|
| Ghidra | 12.1.3 (`20260817`) | zip sha256 `93a5d11a…`, taken from the GitHub release asset over TLS on 2026-09-29. Ghidra's own published hash was not reachable from the pinning host; compare it with the release notes. | both |
| Temurin JDK | 21.0.12+8 | tarball sha256 `e4446ff0…`, equal to Adoptium's `.sha256.txt` for the asset | both. In `audit-native` it is `/opt/ghidra-jdk`, for Ghidra only (`JAVA_HOME_OVERRIDE` plus the wrappers); Joern keeps the apt `temurin-21-jdk` |
| x64dbg | snapshot `2026.05.27` (`snapshot_2026-05-27_12-11.zip`, commit `9c8ca1ca`) | sha256 `d41966df…`. The GitHub asset and SourceForge's `snapshots/` copy are byte-identical, and SourceForge's published sha1/md5 match | both |
| Wine | 8.0 `8.0~repack-4` (bookworm), 9.0 `9.0~repack-4build3` (noble) | exact apt versions of `wine`, `wine64`, `wine32:i386`. The noble version was read from the archive index; the bookworm one could not be (see OPEN in TODO) | both |
| Xvfb, xauth | distro | not version-pinned, so they take security updates | both |

**Invocation.**
- `ghidra-analyzeHeadless <project-dir> <name> -import <file>` runs Ghidra headless. The `ghidra` and
  `ghidra-analyzeHeadless` commands are small wrappers that set `user.home` from `$HOME`, because the
  boundary runs as the host uid, which has no passwd entry.
- `x64dbg`, `x32dbg` and `x96dbg` wrap `headless.exe`. They take debugger commands on stdin, and `exit`
  ends the session. `x96dbg FILE` picks x64 or x32 from the PE header.
- `--gui` runs the Qt GUI (for `x96dbg`, the launcher) under `xvfb-run`.
- `--prepare` creates the caller's Wine prefix.
- `--version` prints the pin.

**Wine prefix.** The prefix is built at image build time in `/opt/wine-prefix`, with
`WINEDLLOVERRIDES=mscoree,mshtml=` so Mono and Gecko are never fetched. DLLs identical to Wine's own
are symlinked, which cuts the prefix from 1.3 GB to 72 MB. Wine refuses a prefix owned by another uid,
and the image root is read-only. So on first use the wrapper copies the prefix to
`/scratch/.x64dbg-runtime`, or to `$X64DBG_RUNTIME_DIR` or `$TMPDIR` when `/scratch` is not writable.

**MSVC runtime.** The MSVC runtime DLLs that ship in the x64dbg zip load before Wine's builtins
(`msvcp140,vcruntime140,vcruntime140_1=n,b`). Wine 9.0's `msvcp140` lacks `std::_Throw_Cpp_error`,
and without the override x32dbg crashed on exit.

**Limits.**
- x64dbg is a Windows PE debugger run under Wine: use it to inspect PE files. It is not a sandbox.
  **Do not execute malware or other untrusted targets with it**, and never enable the container network
  for it.
- Stepping a live debuggee needs ptrace between Wine processes. The default boundary drops every
  capability, so real debugging is expected to need the `DEBUG_CAPS=1` profile of
  `images/audit-buildenv-common/run.sh`, which is not qualified.
- The GUI under Xvfb starts, but it is not interactive.
- Unpacked sizes of the added layers on noble: JDK 362 MB, Ghidra 924 MB, Wine with i386 multiarch
  1.67 GB, x64dbg 86 MB, prefix 76 MB.

**Smoke.** `scripts/smoke_reverse_tools.sh --docker <image>` runs the image inside its own boundary
wrapper and checks:
- the Ghidra and JDK versions;
- a headless import and analysis of `images/test/binary/hello.c`;
- `wine --version`;
- the prefix, via wineboot;
- the pinned hashes of the x64dbg executables;
- that x64dbg and x32dbg headless start and exit within 60 s;
- that `x96dbg` selects the right arch.

The `audit-native` Ghidra, Wine and x64dbg layers, built alone on `ubuntu:24.04`, passed every check
on 2026-09-29, both as root and as uid 1000 under the `audit-native/run.sh` flags. That run did not
build either full image; see OPEN in TODO.

## Host-local B13 registry (B16)

Docker image ids differ between hosts, so the 16 tool records and seven shared step-4 image records
are not committed. `orchestrator/dagster/code-location.sh start` runs:

```bash
python3 -B images/registry_records.py generate
```

The generator writes ignored `appsec-review-process/pipeline/container-images/<image_id>.json`
records only after all 23 successful build pointers still match the current image inputs and
`docker image inspect`. It never builds, pulls, or repairs an image. `check` is read-only and fails
on a missing record, changed Dockerfile/build fingerprint, changed attempt identity, or Docker image
id drift. Local records use `digest_kind: image-id`; B13 runs the `sha256:...` image id directly.
The tracked `fixture-harmless` registry record remains a portable image-index record.

`audit-buildenv-cpp` is one of the seven shared records. Its 2026-09-26 rebuild extends
`audit-native:local`, fixes the ADR-0012 Revision 3 compiler paths, and adds the autotools/Bear
prerequisites. The generated record is deliberately still ignored: source control carries the
Dockerfile, declaration, contract tests and documentation, while B16 binds the current host image
id, Dockerfile hash, build fingerprint and attempt id at startup.

## Findings from the first build (2026-09-26, cloud workspace, Docker 29.4.3)

- **Semgrep rules are not in any image.** The engine runs offline with mounted rule sets:
  `data/source-sast/rules-v1.yml` (4 repository rules) and, since 2026-09-28, the 16 C rules vendored
  verbatim from `opengrep/opengrep-rules` at `f1d2b562` under `data/source-sast/opengrep-rules/`
  (LGPL-2.1 + Commons Clause; LICENSE and NOTICE alongside, every file hash-locked by
  `data/source-sast/opengrep-rules.lock.json`; decision William 2026-09-27).
- **CodeQL (`audit-codeql`) feeds the `02-codeql-<lang>` nodes and `06-reachability-codeql`** (ADR-0017,
  ADR-0023): one node per language runs `/opt/scripts/codeql-sast-lane.sh ... keep-db` with
  `--build-mode none` and the bundled security-extended suite and retains the database;
  `/opt/scripts/codeql-reachability-lane.sh` runs the `data/codeql-reachability` packs against it.
  `images/audit-codeql/tool.json` is the authenticated metadata (bundle sha256 must match image.json and
  the Dockerfile). The image needs a rebuild (lane script) and a B16 record before the job executes;
  until then every language is a per-language `UNAVAILABLE` gap. The image now carries a .NET SDK
  for C# (branch `lang-servers`). `audit-codeql-native` holds the traced C/C++ lane
  (`codeql-cpp-traced`, graph queries in `queries/appsec-graph-cpp`), run by `02-codeql-cpp` for each
  unit of the accepted `02-native-build` (see [`docs/dependency-reachability.md`](../dependency-reachability.md)).
- **CodeQL reachability packs** for Go, Java, C#, JS/TS and Python live in `data/codeql-reachability/`
  (pinned to the bundle 2.27.0 libraries; advisory symbols arrive as a generated data extension) and
  are run by `06-reachability-codeql` against the databases the `02-codeql-<lang>` nodes retained
  ([`docs/dependency-reachability.md`](../dependency-reachability.md)). They are not compiled yet:
  `scripts/smoke_codeql_per_language.sh` (needs the rebuilt `audit-codeql:local`) is the first check,
  and Go needs a Go toolchain in `audit-codeql`.
- **Language servers and tree-sitter** are pinned on every `audit-buildenv-*` image, with the
  tree-sitter grammars vendored in `audit-lsp-vendor`; `lsp_driver.py` and `treesitter_ast.py` drive
  them and `images/test/run-lsp-smoke.sh` / `scripts/smoke_lang_servers.sh` smoke-test them. None of
  these images has been built yet; details and WSL commands: [`docs/language-servers.md`](../language-servers.md).
- **grype has no database** until the V16 mirror publisher exists; the smoke run only proves it refuses
  to run without one.
- **syft finds no component in hello-autotools**: the vendored cJSON has no manifest. Phase 7 expects one
  component, so `02-sbom-inventory` needs a vendored-code source (ScanCode, or the build index's
  not-units/members) beside syft.
- **Microsoft SBOM Tool is not a general SBOM editor.** It generates and validates SPDX 2.2/3.0,
  redacts SPDX 2.2 file data, and performs config-driven aggregation. Network license enrichment and
  Docker-daemon scanning are not enabled in the offline B13 profile. A transformation worker and
  immutable output contract remain separate full-protocol work.
- **sbomasm is the semantic mutation tool.** Its offline `assemble`, `edit`, and `rm` operations
  cover SPDX/CycloneDX composition and metadata changes. ClearlyDefined enrichment,
  Dependency-Track integration, and SecureSBOM signing/verification remain disabled because they
  require network access or an external service. A live v2.1.1 probe found that component removal
  removed the component object but left its `dependsOn` reference dangling; do not accept component
  removal without a post-transform referential-integrity check. New-root assembly also emits the
  current timestamp and a random serial number, so its raw output is not byte-deterministic.
- **psalm** refuses a root that has `composer.json` but no `vendor/`; run it with `--root` at the config
  folder and `projectFiles` pointing at `/workspace`.
- **SpotBugs reads bytecode**, so its job depends on a build, not on the source alone.
- Sizes: 148 MB (gitleaks) to 815 MB (psalm, the PHP base).
