# Archived container assets review

Date: 2026-10-07

## Recommendation

Do not restore the archived container tree wholesale. The reusable core is the narrow, offline
`tool-*` pattern: digest-pinned base, host-prefetched and hash-verified asset, offline install,
numeric non-root user, and an application-owned argv/output adapter. Eighteen assets meet that bar
with small refresh work. Four omnibus images should be retired, six assets should be replaced by a
narrower or maintained approach, and fourteen complex/build images need redesign before use.

The inventory covers 42 project-owned image variants: 40 Dockerfiles directly under
`old/images/<name>/`, the project-selected ScanCode source Dockerfile, and the archived Dagster
image. The complete machine-readable selection record is
[`archived-container-assets.json`](archived-container-assets.json).

| Class | Meaning | Count | Port now? |
|---|---|---:|---|
| 1 | Reuse with minimal changes | 18 | Yes, after refreshing immutable pins/licenses and rerunning validation |
| 2 | Revise before use | 14 | No |
| 3 | Replace with a better approach/tool | 6 | No |
| 4 | Retire | 4 | No |
| 5 | Insufficient evidence | 0 | No |

`old/` was read only. No archived script was executed, no target repository was scanned, and no
archived file was changed.

## Verification performed

- Static inspection covered all 42 Dockerfiles, all 41 `image.json` build declarations (CodeQL has
  two variants), all 20 `tool.json` contracts, lock/pin records, image-local scripts, shared runners,
  the central container adapter, and related Dagster/adapter files.
- The 353 `kind: download` prebuild entries in `image.json` all have SHA-256 values. This does **not**
  cover downloads embedded in legacy Dockerfiles. ScanCode instead declares an unpinned depth-one
  clone at [`old/images/scancode-toolkit/image.json`](../../old/images/scancode-toolkit/image.json#L11).
- Hadolint 2.15.1 ran in the cached narrow image against all 42 Dockerfiles mounted read-only. It
  reported 117 items: 61 missing `pipefail` safeguards for piped `RUN` commands, 22 unpinned apt
  package sets, 13 non-numeric users, 10 `cd`/`WORKDIR` issues, and 11 other items. These are lint
  signals, not security findings.
- Forty-one cached images passed a fresh constrained startup or version probe. The only unprobed
  image was `audit-static-opengrep`, which was not cached. Probes used no network, a read-only root,
  dropped capabilities, `no-new-privileges`, uid/gid 10001, and bounded pids/memory/CPU; no target or
  Docker socket was mounted.
- `tool-hadolint` was rebuilt once under a temporary tag. The build and its build-time version check
  succeeded. BuildKit nevertheless contacted Docker Hub for Dockerfile-frontend and base metadata
  despite `--network none`; therefore this is a build-success result, not proof of an offline build.
  The temporary tag was removed.
- Archived `.build-state` records say 22 images had prior successful builds. They are untrusted
  corroboration only, not fresh proof and not security acceptance.

No authoritative upstream/version research, image vulnerability scanning, full SBOM/license policy
evaluation, arm64 build, functional target scan, or workload-scale resource test was performed.
Current support and vulnerability status are explicit porting gates, not assumed facts.

## Cross-cutting findings

### Runtime boundary worth reimplementing

The archived central adapter has useful concepts: immutable image references and argv-only launch,
numeric non-root execution, no pull, no network by default, read-only target mounts, one writable
run-owned scratch mount, dropped capabilities, `no-new-privileges`, pids/memory/CPU/tmpfs limits,
bounded logs, timeouts, cleanup verification, and explicit failure causes. See
[`container_execution.py`](../../old/appsec-review-process/container_execution.py#L84),
[`build_docker_argv`](../../old/appsec-review-process/container_execution.py#L490), and the sensitive
mount checks at [line 610](../../old/appsec-review-process/container_execution.py#L610).

No project-owned runtime path was found mounting a Docker socket or using `--privileged`. The legacy
build-environment wrapper does have opt-in bridge networking and an escape hatch that adds
`SYS_PTRACE` and disables the default seccomp profile
([`run.sh`](../../old/images/audit-buildenv-common/run.sh#L16)); those must become explicit typed
permissions, not environment-variable switches. The central adapter also fails closed when a job
requests fixed destinations because it cannot enforce them
([`container_execution.py`](../../old/appsec-review-process/container_execution.py#L915)).

### Reproducibility is strongest in the narrow images

The narrow images install local assets without network, use digest-pinned bases, and end as uid
10001. The Python variants use hash-locked wheels and `--no-index --require-hashes`; Semgrep is a
representative example ([Dockerfile](../../old/images/tool-semgrep/Dockerfile#L17),
[lock](../../old/images/tool-semgrep/requirements.txt#L1)). Binary assets use recorded checksums,
PGP, Sigstore, or vendor manifests. Before reuse, every base digest, tool version, verification key,
license, and transitive lock still needs an authoritative refresh.

Eight external `FROM` instructions are not digest-pinned: two in `audit-binary-analysis` and one
each in `audit-container`, `audit-iac`, `audit-native`, `audit-static`, `audit-static-opengrep`, and
ScanCode. The legacy omnibus definitions also execute remote installers and use `@latest`; their own
comments say they were not ready for reliable engagement use
([`audit-static`](../../old/images/audit-static/Dockerfile#L74),
[`audit-static-opengrep`](../../old/images/audit-static-opengrep/Dockerfile#L98)).

### Size and update burden favor decomposition

The cached images' reported virtual sizes (which double-count shared layers) were:

| Group | Cached images | Sum of reported sizes |
|---|---:|---:|
| Four heavy analysis variants (`native`, binary, CodeQL, CodeQL-native) | 4 | 43.10 GiB |
| Ten build/LSP environments | 10 | 36.92 GiB |
| Legacy omnibus images (`audit-static`, `audit-iac`, `audit-container`; Opengrep absent) | 3 | 23.51 GiB |
| Twenty narrow `tool-*` images | 20 | 7.89 GiB |

The archive also holds 254 prefetched files totaling about 0.67 GiB. Keeping fetched artifacts in
each build context makes even the small Hadolint rebuild transfer about 56 MB. A content-addressed
prefetch store or tightly generated contexts would reduce checkout size, context transfer, cache
invalidations, and duplicated dependency updates. Actual disk savings will be lower than the sums
because Docker shares layers.

### Platform support is narrower than the host wrappers imply

The runtime adapter and shell/PowerShell wrappers account for Linux and Windows Docker Desktop path
translation, but the images are Linux containers and many assets/wheels explicitly name amd64 or
x86_64. ScanCode hard-codes `--platform=linux/amd64`
([Dockerfile](../../old/images/scancode-toolkit/src/Dockerfile#L10)). Treat non-amd64 hosts as
unsupported until separate assets are authenticated and probed; do not silently depend on emulation.

### Output and failure contracts must remain application code

Useful archived fixes belong in adapters, not images: Checkov's JSON is captured from stdout after
its file-output assumption lost results; Hadolint expands all discovered Dockerfiles instead of only
`/workspace/Dockerfile`; ScanCode exit 1 is accepted only when its documented partial-scan output and
error text both exist; tool timeouts/OOM/nonzero exits become named coverage gaps rather than clean
results. See [`vendor_evidence_b13.py`](../../old/appsec-review-process/vendor_evidence_b13.py#L34)
and [`dependency_b13_adapters.py`](../../old/appsec-review-process/dependency_b13_adapters.py#L59).

## Inventory

Abbreviations used below:

- `B13`: the shared pinned-container adapter above.
- `VE`: [`vendor_evidence_b13.py`](../../old/appsec-review-process/vendor_evidence_b13.py#L25).
- `LS`: [`source_sast_language_adapters.py`](../../old/appsec-review-process/source_sast_language_adapters.py#L10).
- `DEP`: [`dependency_b13_adapters.py`](../../old/appsec-review-process/dependency_b13_adapters.py#L25).
- `BE`: Linux/PowerShell build-environment runners under
  [`old/images/audit-buildenv-common/`](../../old/images/audit-buildenv-common/README.md#L1).
- “Probe” means startup/version only; it does not mean a functional scan or security acceptance.

### Build, native, document, and legacy images

| Image/source | Purpose; associated scripts | Class | Blocking changes / consolidation / destination | Validation |
|---|---|---:|---|---|
| [`audit-binary-analysis`](../../old/images/audit-binary-analysis/Dockerfile#L2) | Binary/reverse toolbox; three image-local analysis scripts, BE, binary adapter, VE, reverse/export smokes | 3 | Split by capability; authenticate all assets; remove duplicate Syft/Grype/Trivy and curl-to-shell installers. `containers/analysis/binary/<tool>/` | Static, lint, probe, historical build record |
| [`audit-buildenv-cpp`](../../old/images/audit-buildenv-cpp/Dockerfile#L9) | C/C++ build/trace/LSP; BE, build execution, LSP service | 2 | Decouple from 12.6 GiB `audit-native`; replace NodeSource script; consolidate with a typed C++ profile. `containers/buildenv/cpp/` | Static, lint, probe, historical build record |
| [`audit-buildenv-cpp-resolute`](../../old/images/audit-buildenv-cpp-resolute/Dockerfile#L9) | Newer-distribution C/C++ resolver; BE/build/LSP adapters | 2 | Prove general need and shared-library compatibility; fold into C++ profile. `containers/buildenv/cpp/profiles/` | Static, lint, probe |
| [`audit-buildenv-dotnet`](../../old/images/audit-buildenv-dotnet/Dockerfile#L3) | .NET/C# build and LSP; BE/LSP | 2 | Replace remote setup, authenticate csharp-ls, share LSP layer. `containers/buildenv/dotnet/` | Static, lint, probe |
| [`audit-buildenv-go`](../../old/images/audit-buildenv-go/Dockerfile#L3) | Go build/debug/LSP; BE/LSP | 2 | Replace remote Node setup; refresh Go/gopls/delve; keep checksum verification. `containers/buildenv/go/` | Static, lint, probe |
| [`audit-buildenv-java`](../../old/images/audit-buildenv-java/Dockerfile#L3) | Java/JDTLS build/LSP; BE/LSP | 2 | Prefetch apt keys/assets, replace remote setup, refresh JDK/JDTLS. `containers/buildenv/java/` | Static, lint, probe |
| [`audit-buildenv-php`](../../old/images/audit-buildenv-php/Dockerfile#L3) | PHP/Composer/PHPactor; BE/LSP | 2 | Replace remote setup, authenticate PHPactor, share LSP layer. `containers/buildenv/php/` | Static, lint, probe |
| [`audit-buildenv-python`](../../old/images/audit-buildenv-python/Dockerfile#L3) | Python build/debug/LSP; BE/LSP | 2 | Replace remote setup; retain hashed LSP lock; share LSP layer. `containers/buildenv/python/` | Static, lint, probe |
| [`audit-buildenv-rust`](../../old/images/audit-buildenv-rust/Dockerfile#L4) | Rust build/debug/LSP; BE/LSP | 2 | Reproduce rustup components, replace remote setup, share LSP layer. `containers/buildenv/rust/` | Static, lint, probe |
| [`audit-buildenv-typescript`](../../old/images/audit-buildenv-typescript/Dockerfile#L4) | Node/TypeScript build/LSP; BE/LSP | 2 | Refresh Node, preserve npm lock, separate target deps from server. `containers/buildenv/typescript/` | Static, lint, probe |
| [`audit-codeql`](../../old/images/audit-codeql/Dockerfile#L19) | Offline CodeQL SAST/reachability; five image scripts plus CodeQL adapters/smokes | 2 | Reconfirm entitlement; refresh bundle/languages; remove unneeded toolchains; validate every lane contract. `containers/tools/codeql/` | Static, lint, CodeQL probe |
| [`audit-codeql-native`](../../old/images/audit-codeql/Dockerfile.native#L14) | Traced C/C++ CodeQL on full native image | 3 | Replace full native inheritance with narrow compiler/tracer base and shared CodeQL bundle. `containers/tools/codeql/traced-cpp.Dockerfile` | Static, lint, CodeQL probe |
| [`audit-container`](../../old/images/audit-container/Dockerfile#L16) | Legacy Hadolint/base inventory plus unwired Trivy; image script + VE | 4 | Replace with `tool-hadolint`, `tool-trivy`, and application base-image parsing. No destination | Static, lint, probe, historical build record |
| [`audit-doc-convert`](../../old/images/audit-doc-convert/Dockerfile#L16) | PDF/DOCX text conversion; document adapter | 1 | Refresh exact pins; add image-level USER; preserve size/time/encryption/OCR gaps. `containers/tools/doc-convert/` | Static, lint clean, pdftotext probe |
| [`audit-iac`](../../old/images/audit-iac/Dockerfile#L18) | Legacy Checkov/tfsec/Trivy/kube-linter omnibus; VE | 4 | Use narrow Checkov/Trivy; add kube-linter only if coverage warrants; retire deprecated tfsec. No destination | Static, lint, probe, historical build record |
| [`audit-lsp-vendor`](../../old/images/audit-lsp-vendor/Dockerfile#L18) | Build-only tree-sitter/grammar/clangd asset bundle | 2 | Authenticated prefetch, per-asset licenses, arm64 decision; prefer content-addressed build artifact over runtime image. `containers/build-assets/lsp-vendor/` | Static, lint, tree-sitter probe |
| [`audit-native`](../../old/images/audit-native/Dockerfile#L61) | C/C++ build, IR, SAST, CPG, reverse analysis; two runners and 12 helper scripts | 2 | Pin/prefetch everything; split build, native-SAST, IR/SVF, CPG, and reverse capabilities; review licenses. `containers/analysis/native/<capability>/` | Static, lint, probe, historical build record |
| [`audit-report`](../../old/images/audit-report/Dockerfile#L37) | LaTeX/Pandoc/PDF renderer; report presentation adapter | 2 | Choose report format; use dated base; pin packages; add USER; measure smaller TeX/Tectonic option. `containers/report/latex/` | Static, lint, latexmk probe |
| [`audit-static`](../../old/images/audit-static/Dockerfile#L74) | Legacy all-in-one static toolbox | 4 | Replace with narrow tool images/adapters; cached image is 18.7 GB. No destination | Static, lint, probe |
| [`audit-static-opengrep`](../../old/images/audit-static-opengrep/Dockerfile#L65) | Unfinished Opengrep fork of omnibus image | 4 | If chosen later, build a narrow authenticated Opengrep image and resolve rule provenance. No destination | Static, lint; no cached image/probe |
| [`scancode-toolkit`](../../old/images/scancode-toolkit/image.json#L5) | License/package inventory; DEP | 3 | Use pinned official release image/archive; eliminate moving develop clone; keep bounded workers and partial-scan gap. `containers/tools/scancode/` only if needed | Static, lint, ScanCode probe, historical build record |

### Narrow security-tool images

| Image/source | Purpose; adapter | Class | Blocking changes / consolidation / destination | Validation |
|---|---|---:|---|---|
| [`tool-blint`](../../old/images/tool-blint/Dockerfile#L20) | Binary hardening; VE | 1 | Refresh pins/licenses; keep remote database disabled; validate output collisions. `containers/tools/blint/` | Static, lint, help probe |
| [`tool-checkov`](../../old/images/tool-checkov/Dockerfile#L17) | IaC policy scan; VE | 1 | Refresh pins/policies; keep downloads disabled and stdout capture. Replaces audit-iac copy. `containers/tools/checkov/` | Static, lint, version probe, historical build |
| [`tool-cve-bin-tool`](../../old/images/tool-cve-bin-tool/Dockerfile#L22) | Offline binary CVE matching; two mounted tool scripts plus DB/scan adapters | 2 | Reconfirm GPL policy; port/test database lineage and network suppression. `containers/tools/cve-bin-tool/` | Static, lint, version probe |
| [`tool-gitleaks`](../../old/images/tool-gitleaks/image.json#L5) | Redacted secret scan; VE | 1 | Refresh pin/license; make history scope explicit. Replaces omnibus copy. `containers/tools/gitleaks/` | Static, lint, version probe, historical build |
| [`tool-gosec`](../../old/images/tool-gosec/Dockerfile#L16) | Go source SAST; LS | 1 | Refresh signed assets; justify bundled Go; validate module/offline gaps. `containers/tools/gosec/` | Static, lint, version probe, historical build |
| [`tool-grype`](../../old/images/tool-grype/Dockerfile#L12) | Offline SBOM CVE match; DEP | 1 | Complete immutable DB publication; forbid implicit update. Replaces binary omnibus copy. `containers/tools/grype/` | Static, lint, version probe, historical build |
| [`tool-hadolint`](../../old/images/tool-hadolint/Dockerfile#L12) | Dockerfile lint; VE | 1 | Refresh pin; enumerate every Dockerfile; keep lint as evidence. Replaces audit-container copy. `containers/tools/hadolint/` | Static, self-lint, version probe, fresh build, historical build |
| [`tool-microsoft-sbom-tool`](../../old/images/tool-microsoft-sbom-tool/Dockerfile#L3) | SPDX generation/redaction/aggregation; no worker | 3 | Define a non-overlapping contract; validate deterministic output and tmpfs. Prefer Syft initially. Conditional destination | Static, lint, version probe with larger tmpfs |
| [`tool-mobsfscan`](../../old/images/tool-mobsfscan/Dockerfile#L19) | Mobile source SAST; VE | 1 | Measure incremental coverage versus Semgrep; validate SARIF. `containers/tools/mobsfscan/` | Static, lint, version probe, historical build |
| [`tool-osv-scanner`](../../old/images/tool-osv-scanner/Dockerfile#L2) | Offline OSV match; DEP | 1 | Port immutable DB binding; normalize finding/partial exits. `containers/tools/osv-scanner/` | Static, lint, version probe, historical build |
| [`tool-phpcs`](../../old/images/tool-phpcs/Dockerfile#L12) | PHP sniffs; LS | 1 | Define security ruleset and prove incremental signal. `containers/tools/phpcs/` | Static, lint, version probe, historical build |
| [`tool-phpstan`](../../old/images/tool-phpstan/Dockerfile#L12) | PHP static analysis; LS | 1 | Fix policy level/config and resource/exit contract. `containers/tools/phpstan/` | Static, lint, version probe, historical build |
| [`tool-psalm`](../../old/images/tool-psalm/Dockerfile#L12) | PHP taint/static analysis; LS | 1 | Hash external config; bound threads/cache; normalize exits. `containers/tools/psalm/` | Static, lint, version probe, historical build |
| [`tool-sbomasm`](../../old/images/tool-sbomasm/tool.json#L28) | SBOM transformations; no worker | 3 | Add contract, referential-integrity validation, deterministic identity/time; prove need beyond Syft. Conditional destination | Static, lint, corrected version probe |
| [`tool-semgrep`](../../old/images/tool-semgrep/Dockerfile#L17) | Primary source SAST; source-SAST adapter | 1 | Resolve/hash rule provenance and license; keep telemetry/update off; gaps on absent rules. `containers/tools/semgrep/` | Static, lint, version probe, historical build |
| [`tool-shellcheck`](../../old/images/tool-shellcheck/Dockerfile#L19) | Shell static analysis; LS | 1 | Keep `--norc`; bound file argv; name generated exclusions. `containers/tools/shellcheck/` | Static, lint, version probe |
| [`tool-spotbugs`](../../old/images/tool-spotbugs/Dockerfile#L16) | JVM bytecode SAST; LS | 1 | Require accepted bytecode; retain hostname mapping; validate class coverage. `containers/tools/spotbugs/` | Static, lint, clean mapped-host version probe, historical build |
| [`tool-syft`](../../old/images/tool-syft/Dockerfile#L12) | Directory/OCI SBOM inventory; DEP + VE | 1 | Fix output schema; disable registry/network catalogers; separate archive/directory coverage. `containers/tools/syft/` | Static, lint, version probe, historical build |
| [`tool-trivy`](../../old/images/tool-trivy/Dockerfile#L12) | Offline IaC/Dockerfile config scan; VE | 1 | Refresh through incident-aware pin policy; keep updates off; separate vulnerability DB scope. `containers/tools/trivy/` | Static, lint, version probe, historical build |
| [`tool-zizmor`](../../old/images/tool-zizmor/Dockerfile#L18) | Offline GitHub Actions security scan; VE | 1 | Keep offline/no-exit-code flags; scope workflow files; validate SARIF. `containers/tools/zizmor/` | Static, lint, version probe |

### Orchestrator image

| Image/source | Purpose; associated files | Class | Blocking changes / destination | Validation |
|---|---|---:|---|---|
| [`mythos-orchestrator-dagster`](../../old/orchestrator/dagster/Dockerfile#L1) | Dagster webserver/daemon; compose, definitions, code-location scripts, setup, host prep | 3 | Another task is rebuilding Dagster from scratch. Do not port this image; retain only reviewed ideas: no Docker socket/target mounts, loopback-only ports, health checks, bounded logs. New build must be non-root, avoid `chmod 1777`, and hash dependencies. `deploy/dagster/` from that task | Static, lint clean, Dagster version probe |

The Dagster compose file keeps target/run data and the Docker socket out of the service containers
([lines 1-29](../../old/orchestrator/dagster/compose.yaml#L1)), passes the database password by runtime
environment rather than image layers, publishes Postgres/UI only on loopback, and defines health
checks/log rotation ([lines 41-85](../../old/orchestrator/dagster/compose.yaml#L41)). The image itself
has no `USER` and makes two directories world-writable
([Dockerfile lines 8-10](../../old/orchestrator/dagster/Dockerfile#L8)); those are not acceptable to
carry forward.

## Recommended future structure

Keep immutable tool packaging, runtime policy, and job-specific semantics separate:

```text
containers/
  bases/                       # few reviewed digest-pinned bases
  tools/<tool>/
    Dockerfile                 # tool only; no job logic
    tool.toml                  # version, license, provenance, platforms, executable
    assets.lock.json           # URLs, hashes/signatures, sizes, upstream identity
  buildenv/<language>/
    Dockerfile
    lock/                      # language/package-manager locks
  analysis/native/<capability>/
  report/latex/

src/appsec_review/
  container_runtime/           # argv-only boundary, mounts, limits, result contract
  jobs/<job>/adapters/<tool>.py # argv, accepted exits, output parser, gaps

tests/
  containers/                  # build/start/version/functional fixture tests
  container_runtime/           # boundary and failure propagation
  jobs/<job>/                  # output-contract and parser tests
```

Prefetch should resolve upstream material into a content-addressed cache, verify signatures/hashes
before the build, emit license/provenance metadata, and generate a minimal build context. Runtime
jobs should use immutable image digests, mount target/source read-only, mount only run-owned scratch
writable, default to no network, apply typed resource/time/output ceilings, and publish explicit
terminal/gap records. Image definitions must not contain application job selection, finding
interpretation, or orchestration logic.

## Prioritized migration order

1. **First end-to-end review:** port and refresh `tool-gitleaks`, `tool-semgrep` plus one reviewed
   hash-pinned rule bundle, `tool-syft`, `tool-osv-scanner` with the existing immutable OSV snapshot,
   `tool-hadolint`, and `tool-checkov`/`tool-trivy` for IaC/config. Port the runtime boundary and each
   job's output/exit adapter before enabling the tool. This gives secrets, source SAST, SBOM/SCA,
   Dockerfile, and IaC coverage without any omnibus image.
2. **Conditional intake/build support:** `audit-doc-convert` when the first target has PDF/DOCX;
   then only the build environment matching that target's languages. Build environments need the
   class-2 redesign first.
3. **Language-specific optional coverage:** ShellCheck, Gosec, SpotBugs, Psalm/PHPStan/PHPCS,
   Mobsfscan, Zizmor, Grype, and Blint, selected by detected source/artifact types and measured
   incremental coverage.
4. **High-cost/deep coverage:** redesigned CodeQL, native C/C++ analysis, IR/SVF/CPG, and narrowly
   split binary-analysis tools. Require licenses, representative functional fixtures, resource
   measurements, and truthful timeout/OOM/partial-result handling before acceptance.
5. **Publication and transformations:** report renderer, Microsoft SBOM Tool, and sbomasm only after
   their new job/output contracts exist. Use the separately rebuilt Dagster deployment; do not port
   the archived orchestrator image.

This order avoids at least the three cached legacy omnibus images' 23.51 GiB of reported virtual
image footprint and defers the 43.10 GiB heavy-analysis set until the basic evidence path is sound.
Those are practical scheduling and transfer estimates, not guaranteed unique-disk savings.

## Follow-up migration

The accepted implementation and its build, startup, functional, security, provenance, and archive
recovery evidence are recorded in [container-migration.md](container-migration.md). The catalog keeps
all 42 audited decisions explicit; enabled images are rebuilt from `containers/`, while deferred,
replaced, and retired entries remain visible with concrete reasons and destinations.
