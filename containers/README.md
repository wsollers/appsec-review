# Container packaging

`catalog.toml` is the sole inventory for container packaging. It accounts for all 42 audited legacy
image variants and four narrow shared runtime bases. An entry is always `enabled`, `deferred`,
`replaced`, or `retired`; absence is not a decision.

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

Before each build, external artifacts are downloaded over HTTPS into an ignored `downloads/`
directory and verified against the declared byte size and SHA-256 in `assets.lock.json`. Docker build
steps run with networking disabled. Logs and the machine-readable summary are written under
`runs/container-builds/<run-id>/`; each result records status, duration, image id, tag, digest, and
log paths. Any failed, blocked, or skipped image makes the command fail, including with
`--continue-on-error`.

## Runtime boundary

`runtime-policy.toml` is the packaging acceptance boundary: no network, non-root UID/GID 10001,
read-only root, all capabilities dropped, `no-new-privileges`, bounded CPU/memory/PIDs/time/output,
a read-only target mount, and one writable scratch mount. Image definitions package tools only.
Application jobs own arguments and translate tool output into findings.

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
