# Container migration acceptance record

Date: 2026-10-07
Source audit: `docs/reviews/archived-container-assets.md`
Catalog: `containers/catalog.toml`

## Outcome

The new catalog accounts for every one of the 42 audited legacy image variants: 17 narrow Class 1
tools are enabled, one Class 1 document-conversion image is deferred pending a complete hashed `.deb`
closure, all 14 Class 2 images are deferred behind explicit redesign criteria, all six Class 3 images
have named replacements or a bounded future capability, and all four Class 4 images are retired.
Four small runtime bases are also enabled. No legacy image is silently omitted.

Each enabled tool has a Dockerfile, typed tool metadata, and an asset lock. Every locked artifact
records an immutable URL, version, byte size, SHA-256, architecture, provenance, license evidence,
verification method, and explicit detached-signature status. Builds fetch and verify assets before a
network-disabled Docker build. The standard runtime policy is no network, UID/GID 10001, read-only
root and target, one writable scratch mount, all capabilities dropped, `no-new-privileges`, and
bounded CPU, memory, PIDs, time, temporary storage, and captured output.

## Acceptance results

The final accepted build is `runs/container-builds/20261008T021952Z-54472/summary.json` (local,
run-owned evidence): 21/21 enabled entries built successfully, including four bases and 17 tools.
Every result contains status, duration, id, deterministic tag, resolved image digest, and fetch/build
log paths. Earlier failed attempts remain run-owned evidence and were not interpreted as success.

- Catalog validation: passed; 42 audited entries, 21 enabled entries, valid dependency graph.
- Production Dockerfile lint: passed with Hadolint 2.15.1 and zero findings. Intentionally insecure
  Dockerfiles under `containers/fixtures/` are scanner inputs and were excluded from production lint.
- Startup acceptance: 21/21 passed after the final build with the locked-down runtime boundary.
- Functional acceptance: Gitleaks, Semgrep, Syft, OSV Scanner, Hadolint, Checkov, and Trivy passed.
  Semgrep used the committed SHA-256-pinned local rule bundle. OSV Scanner used the current published
  PyPI archive only after its size and SHA-256 matched the immutable feed manifest, then mounted the
  archive read-only in OSV Scanner's local database layout.
- Security acceptance: 21/21 passed. Image configuration has numeric non-root users, no entrypoints,
  no exposed ports, and no implicit volumes. Runtime probes confirmed zero effective capabilities,
  `NoNewPrivs=1`, read-only root and target, and writable scratch under `--network none`.
- Launcher parity: passed. Bash ran inside the new Linux Python base and returned the same selected
  catalog entries as native PowerShell for `tool-gitleaks` and `tool-semgrep`.
- Repository tests: 15 passed, 2 skipped. The only container-test skip on this host is the direct WSL
  Bash invocation; the equivalent Bash launcher path was exercised successfully inside Linux.

Build success, startup acceptance, functional acceptance, and security acceptance are separate
checks. Passing one does not imply another.

## Recovery proof and deletion boundary

The annotated tag `pre-simplification-2026-10-07` resolves to tag object
`38297bb3` and commit `8e2a184daabea94dc359294a2f635cca7c408d15`. It contains all 272 tracked
files formerly rooted at `images/`. Comparison against `old/images` found 269 byte-identical files
and three files with line-ending-only differences (`images/.gitattributes`,
`images/tool-gosec/keys/cosign.pub`, and `images/tool-semgrep/requirements.txt`); all 272 were
line-equivalent.

The ignored material beneath `old/images` was also classified before deletion:

- 254 cached downloads (722,981,029 bytes) were all declared by archived image metadata and each
  matched its declared byte size and SHA-256; 98 other declared downloads were not cached. These are
  reproducible caches, not unique source.
- 65,414 files (221,009,007 bytes) formed a clean ScanCode Toolkit clone at immutable commit
  `5e8448ecf2397c6eb7e7eb50326c8c880d9b598b`, with origin
  `https://github.com/aboutcode-org/scancode-toolkit.git`.
- 230 build-state files and 16 Python bytecode files were generated, disposable local outputs. They
  contain no authoritative definitions and are reproduced by build execution rather than restored.

Recovery commands for the authoritative archive are:

```text
git restore --source=pre-simplification-2026-10-07 -- images
git restore --source=pre-simplification-2026-10-07 -- scripts/<name>
git clone https://github.com/aboutcode-org/scancode-toolkit.git
git -C scancode-toolkit checkout 5e8448ecf2397c6eb7e7eb50326c8c880d9b598b
```

The only archived scripts approved for deletion are the four line-equivalent files whose behavior is
ported or replaced by this migration: `rebuild-images-and-smoke.sh`, `smoke_reverse_tools.sh`,
`smoke_entry_exports.sh`, and `smoke_osv_feed.sh`. Language-server, CodeQL, and cve-bin-tool scripts
remain because those Class 2 capabilities are unresolved.

After all acceptance checks and the recovery verification above passed, `old/images` was physically
removed in full and those four scripts were removed. The deletion command re-resolved each absolute
path beneath `F:\repos\appsec-review\old`, rechecked the annotated tag's commit, and rechecked every
script line-for-line before deletion. The image directory and all four selected scripts were confirmed
absent afterward. No other path under `old/scripts` was removed.
