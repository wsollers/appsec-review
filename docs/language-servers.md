# Language servers, tree-sitter and CodeQL on the compiler images

Owner: brief C (`docs/agent-briefs/C-language-servers.md`, branch `lang-servers`).
Status: Dockerfiles, locks, driver, AST builder, CodeQL traced lane, smoke script and skills are
written; **no image in this document has been built from this branch yet** (the author has no
Docker). Every "checked" note below says what was checked and where; §7 has the WSL commands.

## 1. Inventory (step 1)

Images under `images/` that compile or analyse target source, and the languages they serve.
"Compiler images" in this brief are the `audit-buildenv-*` family plus the two CodeQL images; the
other analysis images are listed so the gap is visible.

| Image | Base (pinned by digest on this branch) | Languages | Role |
|---|---|---|---|
| `audit-buildenv-cpp` | `audit-native:local` (Ubuntu 24.04, LLVM 21.1.0 at `/opt/llvm`) | C, C++ | locked native build replay, clangd |
| `audit-buildenv-cpp-resolute` | `ubuntu:26.04@sha256:da6f…` + `/opt/llvm` from `audit-native` | C, C++ | builds needing Qt 6.6+/KF6 |
| `audit-buildenv-dotnet` | `mcr.microsoft.com/dotnet/sdk:9.0.318` | C# | build, csharp-ls |
| `audit-buildenv-go` | `golang:1.23-bookworm` | Go | build, gopls |
| `audit-buildenv-java` | `ubuntu:24.04` + Temurin 25 | Java | build, jdtls |
| `audit-buildenv-php` | `php:8.3-cli-bookworm` | PHP | Phpactor |
| `audit-buildenv-python` | `python:3.12-bookworm` | Python | pylsp, basedpyright |
| `audit-buildenv-rust` | `rust:1.90.0-bookworm` | Rust | build, rust-analyzer |
| `audit-buildenv-typescript` | `node:22-bookworm` | JS, TS, JSON | typescript-language-server, vscode-json-language-server |
| `audit-codeql` | `ubuntu:24.04` | cpp, csharp, java, javascript, python, ruby (build-mode none) | `02-codeql-sast` |
| `audit-codeql-native` | `audit-native:local` | C, C++ (traced replay) | `02-codeql-sast` tool `codeql-cpp-traced` |
| `audit-lsp-vendor` (new) | `rust:1.90.0-bookworm`, `python:3.12-bookworm` | none | build-only: vendored tree-sitter CLI + wheels |
| `audit-native`, `audit-static`, `audit-static-opengrep`, `audit-binary-analysis`, `audit-iac`, `audit-container`, `audit-report`, `tool-*` | — | various | **not in scope** of this branch: no language server or tree-sitter added (see §7 OPEN) |

B16 records (`appsec-review-process/registry/container-images/*.json`) are generated host-locally by
`images/registry_records.py` from the successful build state and are not tracked. The
`STEP4_IMAGE_IDS` list now includes `audit-codeql` and `audit-codeql-native`, so
`prepare-host.sh` builds and registers them (ADR-0017 consequence 1).

## 2. Matrix: image × language × server × pinned version × install method (step 2)

Versions and licences checked on 2026-09-29 against the upstream registries named in the last column.

| Image | Language | Server / tool | Pinned version | Licence | Install method (integrity) |
|---|---|---|---|---|---|
| buildenv-cpp | C/C++ | clangd | 21.1.0 (matches the 21.1.0 compiler) | Apache-2.0 WITH LLVM-exception | PyPI wheel `clangd==21.1.0`, `pip --require-hashes` from `audit-lsp-vendor` wheels (was apt `clangd-21`, unpinned minor) |
| buildenv-cpp-resolute | C/C++ | clangd | 21.1.0 | same | same (new: the image had no language server) |
| buildenv-dotnet | C# | csharp-ls | 0.20.0 | MIT | `dotnet tool install --version` (NuGet package signature) |
| buildenv-go | Go | gopls | v0.18.1 | BSD-3-Clause | `go install …@v0.18.1` (Go checksum database) |
| buildenv-java | Java | Eclipse JDT LS | 1.61.0-202609031315 | EPL-2.0 | milestone tarball, vendored by `image.json` prebuild download, `sha256sum -c` in the Dockerfile (was `snapshots/…-latest`) |
| buildenv-php | PHP | Phpactor | 2026.07.22.0 | MIT | `composer create-project` at the tag (installs from Phpactor's own `composer.lock`; was `composer global require` with dev stability) |
| buildenv-python | Python | python-lsp-server | 1.15.0 | MIT | `requirements-lsp.txt` with hashes (`pip --require-hashes`); `[all]` extras dropped |
| buildenv-python | Python | basedpyright | 1.40.1 | MIT | same lock (brings `nodejs-wheel-binaries`) |
| buildenv-rust | Rust | rust-analyzer | toolchain 1.90.0 component | MIT OR Apache-2.0 | `rustup component add` on the digest-pinned `rust:1.90.0-bookworm` (was `rust:1-bookworm`) |
| buildenv-typescript | JS/TS | typescript-language-server | 5.3.0 (+ typescript 5.9.3) | Apache-2.0 | `npm ci` from `images/audit-buildenv-typescript/lsp/package-lock.json` (sha512 integrity) |
| buildenv-typescript | JSON/CSS/HTML | vscode-langservers-extracted | 4.10.0 | MIT | same lock |
| every image above + both CodeQL images | all | tree-sitter CLI | 0.26.13 | MIT | `cargo install --locked` in `audit-lsp-vendor` (crates.io checksums + the crate's `Cargo.lock`), copied as one static-ish binary (glibc 2.36+) |
| every image above + both CodeQL images | all | py-tree-sitter + grammars | tree-sitter 0.26.0; bash 0.25.1, c 0.24.2, c-sharp 0.23.5, cpp 0.23.4, go 0.25.0, java 0.23.5, javascript 0.25.0, json 0.24.8, php 0.24.1, python 0.25.0, ruby 0.23.1, rust 0.24.2, typescript 0.23.2 | MIT | wheels downloaded once into `audit-lsp-vendor` with `--require-hashes` for CPython 3.11–3.14; each image installs them offline into `/opt/treesitter` (venv) |
| audit-codeql | cpp, csharp, java, js, python, ruby | CodeQL | bundle v2.27.0 | GitHub CodeQL terms | unchanged host prebuild + `sha256sum -c` |
| audit-codeql | C# | .NET SDK (for build-mode none) | 9.0.318 | MIT | `COPY --from=mcr.microsoft.com/dotnet/sdk:9.0.318-noble@sha256:0f97…` |
| audit-codeql-native | C/C++ | CodeQL traced replay | bundle v2.27.0 | same | unchanged |

All grammars are installed on every image (13 wheels, ~12 MB) instead of "the image's languages":
target checkouts are polyglot and the AST artifact should not depend on which build image ran it.

Base images are now pinned by digest (resolved 2026-09-29 from Docker Hub / MCR):

| Tag | Digest |
|---|---|
| `golang:1.23-bookworm` | `sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` |
| `rust:1.90.0-bookworm` | `sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f` |
| `python:3.12-bookworm` | `sha256:dbbe4ceb97851e2e5fa83798b239811f871cb743b259ba3563737349f6bcfaa0` |
| `node:22-bookworm` | `sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7` |
| `php:8.3-cli-bookworm` | `sha256:4687aec76c4a895b68b91bcd5e48f1ba7a3dea120f6de50bba7e1a93af5372dd` |
| `composer:2.8.12` | `sha256:5248900ab8b5f7f880c2d62180e40960cd87f60149ec9a1abfd62ac72a02577c` |
| `ubuntu:24.04` | `sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3` |
| `mcr.microsoft.com/dotnet/sdk:9.0.318` | `sha256:01fabc4758d1d74e39eda700c8463dae6241a61481f973683692ddcb59a5eeb7` |
| `mcr.microsoft.com/dotnet/sdk:9.0.318-noble` | `sha256:0f97a4002de8050867e7e55e03a0487aea4f4a933158fe1d2cc35f570fc81a0d` |

Still floating (apt repositories, no content pin available offline): Temurin 25 from Adoptium,
Node 22 from NodeSource, and Debian/Ubuntu packages. The MCP servers are pinned to their top-level
npm versions (2026.8.31) only.

## 3. Vendoring model

"Vendored per version" means every language-tool dependency is fetched once, at image build time,
from its official registry, verified against a checksum committed in this repo, and baked into the
image. Nothing is fetched when a server runs (the B13/`run.sh` boundary has `--network none`). Where
a registry lock exists it is used (`npm ci`, `pip --require-hashes`, `composer create-project` with
the project lock, `cargo install --locked`); where it does not, a host-side prebuild download with a
sha256 is used (jdtls, like the CodeQL bundle). An artifact repository replaces the registries later
without changing the pins.

At run time a server that cannot resolve the *target's* dependencies (no network, missing
`node_modules`, no Maven cache, no Go module cache) keeps running with partial results; the driver
records that as a gap (`server-diagnostic`/`unresolved`) and never crashes (§4).

## 4. `lsp_driver.py` (step 4)

`appsec-review-process/lsp_driver.py`, stdlib only. Starts one server over stdio, `initialize`,
`initialized`, opens the requested files (size-capped), and answers
`textDocument/definition|references|documentSymbol`, `callHierarchy/incomingCalls|outgoingCalls`
(via `prepareCallHierarchy`) and `workspace/symbol`, then `shutdown`/`exit`. Hard limits: overall
deadline, per-request timeout, maximum message bytes, maximum results per query, maximum open file
bytes. Output is one JSON document (`appsec-review/lsp-query-result/1`); every failure (server
missing, crash, timeout, oversized message, unsupported capability, path outside the root) becomes a
`gaps[]` record and the process exits 0 with `status: "OK_WITH_GAPS"` or `"FAILED"`. Locations are
reported relative to the root; a location outside the root is dropped and counted. Server-supplied
text (hover, symbol names) is data: names are truncated and control characters removed.

```
python3 appsec-review-process/lsp_driver.py --server gopls --root /workspace/go \
  --query '{"method":"documentSymbol","path":"main.go"}' \
  --query '{"method":"references","path":"main.go","line":5,"character":6}'
```

Server presets (`--server NAME`) carry the argv and init options per image; `--command` overrides
for ad-hoc use. See `SERVERS` in the module for the list.

## 5. `treesitter_ast.py` (step 5)

`appsec-review-process/treesitter_ast.py` batch-parses a checkout with py-tree-sitter in one
process and writes `appsec-review/treesitter-ast/1` (`schemas/treesitter-ast.schema.json`): per
file the language, sha256, byte size, node-kind histogram, function definitions (name, kind,
start/end line), call sites (callee text, line) and imports (text, line). The document is
deterministic (sorted, no timestamps in the hashed body) and carries `content_sha256` over its
canonical body. Files over the size cap, unparseable files and languages without a grammar become
`gaps`. It is an additional AST source; it does not replace Joern/CPG.

The CLI streams: file records are written (and hashed) one at a time in path order, so memory
stays flat however large the tree; `build()` returns the same document in memory for small trees
and tests (`test_streamed_file_equals_the_in_memory_document`). The whole checkout is parsed in one
pass by one process; the per-file work is independent, so sharding by path prefix across
processes is the scaling step if wall time matters.

Run inside any compiler image (the repo mounted read-only at `/workspace`, as in §8):

```
/opt/treesitter/bin/python /workspace/appsec-review-process/treesitter_ast.py \
  --root /workspace/<target> --out /scratch/treesitter-ast.json --stats /scratch/treesitter-ast.stats.json
```

### 5.1 Measurement (2026-09-29)

Measured in the author's Linux container (4 vCPU, CPython 3.11, py-tree-sitter 0.26.0 and the
pinned grammars from `requirements-treesitter.txt`), default limits (2 MiB per file, 5,000 rows
of each kind per file), one process:

| Tree | Files parsed | Bytes parsed | Functions | Calls | Wall | Peak RSS | Output |
|---|---|---|---|---|---|---|---|
| CPython `main` (shallow clone) | 3,569 (2,367 py, 1,131 c) | 79 MB | 105,229 | 643,887 | 26.5 s | 103 MiB | 66 MB |
| Linux kernel `master` (shallow clone) | 67,606 (64,460 c) | 1.12 GB | 793,851 | 5,642,328 | 273.5 s | 114 MiB | 468 MB |

Before streaming, CPython peaked at 515 MiB (the whole document in memory); streaming keeps RSS
roughly constant (the largest single tree plus counters). Gaps on Linux: 238 suffixes without a
grammar, 102 symlinks skipped, 56 files over 2 MiB, 2 files with a row cap hit. `error_nodes`
is high on C (417,240 on Linux; 55,826 on CPython): tree-sitter parses C without the
preprocessor, so macro-heavy code yields ERROR/MISSING nodes. Treat function/call rows in such
files as navigation hints, and prefer the compile-database-driven sources (clangd, CodeQL
traced, Joern) for C/C++ claims.

## 6. CodeQL (step 6)

`02-codeql-sast` (`appsec-review-process/codeql_sast.py`, ADR-0017) keeps its build-mode none lanes
unchanged and gains a second tool id, **`codeql-cpp-traced`** (ADR-0017 decision 4 left this
open):

- **Input.** The caller passes the accepted `02-native-build` publication
  (`run(..., native_build_root=, native_build_fingerprint=)`, same pair `02-native-sast` takes).
  `load_native_units` revalidates it with `native_sast.load_native_build`, so the traced lane
  replays exactly the adapted compile databases `02-native-sast` analyses, after the same screening
  (in-image `/opt/llvm` clang only; no response files, `-Xclang`, plugins, `--config`, `-specs=`).
  Without that input the plan is byte-for-byte the build-mode none plan.
- **Execution.** One B13 container per native unit in `audit-codeql-native` (the CodeQL bundle on
  `audit-native`, same LLVM 21.1.0): `codeql-sast-lane.sh cpp traced <suite> <threads> <ram>
  /inputs/codeql-db/<unit>/compile_commands.json /inputs/codeql-queries`. CodeQL traces
  `replay_compile_commands.py`, which runs only the recorded compiler invocations (objects to
  `/scratch/obj`, dependency files dropped, a second screen refusing `-B`, `--gcc-toolchain` and
  the plugin flags) and writes `{total, ok, failed, refused}` to `/scratch/replay.json`. No target
  build script, configure step or test runs. Network none, `/workspace` read-only.
- **Output.** Leads with `tool_id: codeql-cpp-traced` from the same `cpp-security-extended` suite;
  the tool row carries `unit_id` and the replay counts; a unit with failed or refused TUs adds
  `codeql-traced-replay-incomplete:<key>:ok=..:failed=..:refused=..:total=..`; a unit that fails
  as a whole is the usual per-lane gap. The build-mode none fidelity gap stays on the none row.
- **Other compiled languages.** Java and C# stay build-mode none: a traced Maven/Gradle/MSBuild
  build needs dependency downloads the offline boundary forbids. C# now has the .NET SDK
  (9.0.318) in `audit-codeql`, which removes ADR-0017's "C# fails, no dotnet" gap. Go stays a gap
  (no build-mode none; autobuild needs module downloads).

### 6.1 Queries for brief E (names are the contract)

`queries/appsec-graph-cpp` (pack `appsec/cpp-graph-queries`), mounted read-only at run time (not
copied into the image) and hashed into each traced plan row (`graph_pack_sha256`). The traced lane
runs them on the traced database after the security suite and decodes to
`tools/codeql-cpp-traced-<unit>/scratch/graph/<Query>.csv`; each CSV's sha256 is in the receipt
(`graph_outputs`) and re-verified by `validate`. A failing graph query is logged
(`graph/<Query>.log`) and its CSV is absent (`null` in the receipt); it does not fail the lane.

| Query | Library | Columns |
|---|---|---|
| `CallEdges.ql` | `cpp` (`Call.getTarget()`) | caller_name, caller_file, caller_line, call_file, call_line, callee_name, callee_file, callee_line, callee_defined |
| `EntryPoints.ql` | `cpp` | name, file, line, reason (`main` / `no-internal-caller` / `address-taken`) |
| `FlowSources.ql` | `semmle.code.cpp.security.FlowSources` | source_type, file, line, function |

Brief E owns reachability and any taint path queries built on
`semmle.code.cpp.dataflow.new.TaintTracking` with these sources; this branch does not implement
reachability. The queries are written but **not compiled here** (no CodeQL in the authoring
container); the smoke script compiles them.

## 7. Build and smoke in WSL (the user runs these)

From the repo root, after `git fetch && git checkout lang-servers`:

```
# 1. vendor image first (tree-sitter CLI build ~2 min, wheels download)
python3 -B images/image_build.py build audit-lsp-vendor
# 2. compiler images (audit-native:local must exist; the java build fetches the jdtls tarball
#    and the codeql builds the 553 MB bundle via image.json prebuild, both sha256-checked)
python3 -B images/image_build.py build audit-buildenv-cpp audit-buildenv-cpp-resolute \
  audit-buildenv-dotnet audit-buildenv-go audit-buildenv-java audit-buildenv-php \
  audit-buildenv-python audit-buildenv-rust audit-buildenv-typescript audit-codeql audit-codeql-native
# 3. smoke every image (or pass image ids); one PASS/FAIL line per check, exit 1 on any FAIL
images/test/run-lsp-smoke.sh
scripts/smoke_lang_servers.sh --docker audit-buildenv-java        # one image
# 4. register B16 records (now includes audit-codeql and audit-codeql-native)
python3 -B images/registry_records.py generate && python3 -B images/registry_records.py check
# 5. image sizes for the delta table below
docker image ls --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -E 'audit-(buildenv|codeql|lsp)'
```

`orchestrator/prepare-host.sh` does steps 1, 2 and 4 in its image stage (the vendor image is
built first via `registry_records.BUILD_ONLY_IMAGE_IDS`).

## 8. Smoke script

`scripts/smoke_lang_servers.sh IMAGE_ID` runs inside the image (repo read-only at `/workspace`,
`--docker` wraps `images/audit-buildenv-common/run.sh`). Per server it copies
`images/test/lsp/<lang>` (a `helper` defined and called at known lines) to `/scratch`, asks
`documentSymbol`, `definition`, `references`, `incomingCalls` through `lsp_driver.py`, and
PASSes when `helper` is listed and its call site resolves to its definition line (references and
call counts are printed; `gap` where the server lacks the capability). Then: tree-sitter CLI
version and `treesitter_ast.py` over all fixtures (hash verifies, 8 helpers, no error nodes); on
`audit-codeql` the CodeQL version/languages, the .NET SDK and a C# build-mode none database; on
`audit-codeql-native` a compile check of the three graph queries and a traced lane run on the C++
fixture (replay counts, CSV row counts).

Checked in the authoring container with host installs of the same pinned versions: gopls,
clangd, pylsp, typescript-language-server, vscode-json-language-server and Phpactor PASS, and
tree-sitter + `treesitter_ast.py` PASS. jdtls, basedpyright, rust-analyzer, csharp-ls and every
CodeQL check have **not** run yet.

## 9. Image size deltas (estimates until step 5 above is run)

| Image | Added | Removed | Estimated delta |
|---|---|---|---|
| every image | tree-sitter CLI (12 MB) + `/opt/treesitter` venv (~53 MB) | — | +65 MB |
| buildenv-cpp | clangd 21.1.0 wheel venv (~85 MB) | apt `clangd-21` + deps | about +50 MB net |
| buildenv-cpp-resolute | clangd venv | — | +150 MB |
| buildenv-java | jdtls 1.61.0 milestone | jdtls snapshot (same size class) | +65 MB |
| buildenv-php | Phpactor project install (no dev deps) | global require with dev stability | about +65 MB |
| buildenv-python | locked pylsp/basedpyright | `python-lsp-server[all]` extras (pylint, yapf, rope, ...) | about +40 MB |
| buildenv-rust | `rust-src` component (rust-analyzer needs the sysroot) | — | +110 MB |
| buildenv-typescript | locked servers in `/opt/node-lsp` | global npm installs | about +65 MB |
| audit-codeql | .NET SDK 9.0.318 (~750 MB) | — | about +820 MB |
| audit-codeql-native | tree-sitter | — | +65 MB |

## 10. OPEN

- **Nothing here has been built.** Steps 1–5 of §7 are the user's; the first build may need
  fixes (most likely: basedpyright or csharp-ls behaviour offline, QL compile errors in
  `queries/appsec-graph-cpp`, rust-analyzer without network).
- **`codeql-cpp-traced` is not wired into the graph.** `dagster_workflow.run_codeql_sast` must
  pass the accepted `02-native-build` root and fingerprint (as `native_sast_lifecycle_work` does)
  and the graph needs a `02-native-build → 02-codeql-sast` edge; until then the job runs
  build-mode none only (plan unchanged). This is a graph/catalog change owned by the controller.
- `treesitter_ast.py` is a CLI and module, not yet a graph job; the host venv has no
  py-tree-sitter, so its parsing tests skip there (they run with `/opt/treesitter/bin/python`).
- Other analysis images (`audit-native`, `audit-static*`, `audit-binary-analysis`, `audit-iac`,
  `audit-container`, `audit-report`, `tool-*`) carry no language server or tree-sitter.
- Floating inputs remain: Adoptium Temurin 25 and NodeSource Node 22 apt repositories, distro
  packages, and the NuGet tools `dotnet-dump`/`dotnet-symbol`/`dotnet-trace` (not language servers).
- Artifact repository for the vendored downloads (later, per William's decision).
