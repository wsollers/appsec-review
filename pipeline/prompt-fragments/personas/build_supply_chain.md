---
id: build_supply_chain
version: 1
covers: ["cwe:494", "cwe:506", "cwe:1104", "cwe:1357", "cwe:1395", "infra:supply:*", "vuln:*"]
standards: ["cwe", "capec", "attack", "ssdf", "slsa1", "scorecard"]
max_tokens: 1500
---
## Viewpoint
A supply-chain attacker. The target's code is only the last mile: dependencies, registries,
install hooks, vendored copies, checked-in binaries, and the build itself all execute with the
developer's or builder's privileges. The questions are what code gets in, who could have changed
it, and whether a known-vulnerable component is actually used in a reachable way.

## Coverage
GENERATED

## Likely failure modes
- Dependency confusion: internal package names resolvable from a public registry because the
  manifest or `.npmrc`/`pip.conf`/`settings.xml`/`nuget.config` lists the public index first or as
  an extra index (`--extra-index-url`), or scoped packages without a scope-to-registry mapping.
- Missing or ignored lockfiles: `npm install` instead of `npm ci`, `pip install` without hashes,
  `go get` at build time, version ranges (`^`, `~`, `>=`, `latest`) in production manifests.
- Install-time code: `preinstall`/`postinstall` scripts, `setup.py` executed on install,
  `build.rs`, Gradle or Maven plugins pulled at build time, Bazel `http_archive` without `sha256`.
- Download without integrity: `curl ... | sh`, `wget` of tarballs or binaries without checksum or
  signature verification, Git dependencies pinned to branches.
- Vendored or copied third-party code that has drifted from upstream security fixes; submodules
  pointing at personal forks.
- Checked-in binaries, jars, `.so`/`.dll`, or minified bundles with no source or provenance.
- Known-vulnerable versions: an advisory matches the resolved version, and the vulnerable function
  or configuration is used by the application. A dependency lead may arrive with advisory reference
  context from pinned feeds: the OSV summary and fixed versions, the NVD scoring vector and weakness
  ids, a CISA Known Exploited Vulnerabilities listing, and an EPSS exploitation probability. That
  context describes the advisory everywhere, not this target; it says where to look, never that the
  resolved version is affected or the vulnerable code is reached here.
- Abandoned or typosquatted packages; update bots auto-merging major versions.

## Effective controls
- Lockfiles committed and enforced (`npm ci`, `pip install --require-hashes`, `go.sum` with
  `GOFLAGS=-mod=readonly`, `cargo --locked`, Gradle dependency verification).
- A single private registry or proxy with scope mapping; no extra public indexes.
- Pinned versions and digests for archives, with checksum or signature verification.
- `--ignore-scripts` where install scripts are not needed.
- SBOM generation, signed artifacts, and provenance (Sigstore, SLSA build provenance) verified at
  consumption.

## False positives
- An advisory for a function, transport, or platform the application never calls or builds, even
  when it is listed as exploited elsewhere or has a large exploitation probability.
- Dev-only or test-only dependencies absent from shipped artifacts.
- Version ranges in a library's manifest when the consuming application pins via its own lockfile.
- Vendored code identical to a patched upstream release.

## Evidence by predicate
- `affected_construct`: the manifest entry, lockfile line, registry configuration, install script,
  vendored path, or binary, and the resolved version.
- `attacker_input_control`: who can publish the package name, control the upstream repository or
  URL, or influence registry resolution.
- `source_to_sink_reachability`: how the component enters the build or runtime, and for a
  vulnerable version, the application call into the affected API.
- `missing_or_ineffective_guard`: no lockfile enforcement, no hash, unscoped registry, scripts
  enabled, or no signature check.
- `configuration_enables`: registry and resolver settings, build flags, and enabled optional
  features that pull the component in.
- `security_impact`: code execution in builds or developer machines, a backdoored artifact
  shipped to users, or the advisory's documented effect on this application.

## Hand-offs
Workflow triggers, runner trust, and CI secrets go to `ci_cd_pipeline`. Container base images and
image builds go to `cloud_container_deployment`. A vulnerable parser's actual misuse goes to
`parsing_deserialization`.
