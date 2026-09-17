# syntax=docker/dockerfile:1
#
# Vendor Code Audit Playbook — Phase 0A tooling pre-pass, in one container.
#
# Everything an evidence-gathering pass needs before an LLM sees any source:
# secrets scanning, SBOM/SCA, SAST per language (including Java —
# SpotBugs+FindSecBugs, build-dependent — and Semgrep's p/java + p/spring
# rulesets, source-only and primary), mobile-source SAST for the Android/iOS
# client (mobsfscan — MobSF's rule engine, runs against source, no build
# required), complexity metrics, structural/semantic code search (ast-grep,
# weggli, Joern), binary hardening checks (BinSkim, for PE/Windows binaries),
# and the tree-sitter symbol/call indexer (build_symbol_index.py) that ships
# alongside this file.
#
# NOT included as of 2026-09-17, and deliberately so: IaC policy scanning
# (Terraform via checkov/tfsec/trivy config, Kubernetes/Helm via kube-linter)
# moved to `images/audit-iac`; Dockerfile linting and base-image inventory
# (Hadolint, docker-base-images) moved to `images/audit-container`. Both were
# split out of this image (MIGRATION.md item 7, image-per-lane per design
# §17) so an engagement without IaC/Docker surface never has to pull the
# tooling for it, and vice versa.
#
# NOT included, and deliberately so:
#   - ScanCode Toolkit (license/provenance/copyright detection). Its own
#     dependency set is heavy and best kept out of this image. NOTE
#     (corrected 2026-09-01): there is NO publishable
#     ghcr.io/aboutcode-org/scancode-toolkit image to `docker run` — an
#     anonymous manifest pull returns "denied", and ScanCode's own docs say
#     to build it yourself. Build it once with Build-ScanCodeImage.ps1 (which
#     produces the local `scancode-toolkit:local` tag); the orchestrator's
#     `scancode` step runs against that local image. The built image's own
#     ENTRYPOINT already runs `scancode`, so that step passes scancode's
#     arguments only (e.g. `-clip --json-pp /evidence/license/scancode.json
#     /workspace`), not the word `scancode` itself.
#   - A baked-in YARA ruleset. The `yara` engine is installed; mount whatever
#     ruleset you're licensed/cleared to use at runtime (e.g. a private copy
#     of Neo23x0/signature-base) rather than have this image bundle one.
#   - CodeQL. Deliberately excluded, for two independent reasons, not just
#     one: (1) the CodeQL CLI's own terms restrict use to open-source/research
#     code without a GitHub Advanced Security license — this is vendor-owned
#     proprietary code, so that license doesn't clearly cover this use.
#     (2) Even ignoring licensing, CodeQL's C/C++ extractor needs the code to
#     actually *build* to produce a database (`--build-mode=none` exists but
#     gives materially weaker results for C/C++ than a real build) — and a
#     vendor-delivered C++ game server building cleanly in a from-scratch
#     environment is not a given. Joern below doesn't have either problem:
#     genuinely open (Apache-2.0) and its fuzzy parser degrades gracefully
#     without a full build.
#   - Language-server-grade semantic call graphs (Roslyn workspace analysis
#     for the Unity project, gopls/pyright semantic resolution). Those need
#     the target repo's actual build environment (Unity's own package cache,
#     `go mod` state, a Python venv with the project's real dependencies) to
#     resolve symbols correctly — a generic container can't fake that
#     credibly. Build those per-repo, separately, and feed their output into
#     the same /evidence tree this image writes to.
#   - The full MobSF web app (dynamic analysis, and static analysis of a
#     *compiled* APK/IPA — embedded SDK detection, permission/entitlement
#     analysis, hardcoded secrets inside the built package). It's its own
#     heavy web app with an Android SDK toolchain bundled in, and it needs a
#     built package as input, which this engagement doesn't have (source
#     tree only) — run it from its official image instead, if a build is
#     ever produced:
#       docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
#     then submit the built APK/IPA via its REST API and pull the JSON
#     report into /evidence/mobsf/.
#     What IS included below is `mobsfscan` — a separate, lightweight,
#     pip-installable CLI from the same MobSF project that runs the same
#     rule engine directly against Java/Kotlin/Swift/Objective-C *source*,
#     no build or package required. That's the right fit here and needs no
#     separate service.
#
# BUILD NOTE: this Dockerfile has not been build-tested in a live Docker
# daemon as part of producing it (the authoring environment had no daemon
# available). Review it, build it, and pin exact tool versions before relying
# on it for a real engagement — treat every remaining "@latest" below as a
# placeholder to replace with a version you've verified, not a promise of
# reproducibility.
#
# VERSION PINNING (2026-09-01 remediation + verification, see priority fix #5
# in the adversarial process review): every `@latest` / floating install is a
# standing reproducibility risk — a rebuild next month can silently pull a
# different tool version with different default rules/behavior than whatever
# this evidence set was actually produced with. Pinned so far (all verified
# against their real registries):
#     gitleaks       GITLEAKS_VERSION   = v8.30.1
#     mobsfscan      MOBSFSCAN_VERSION  = 1.0.0
#     semgrep        SEMGREP_VERSION    = 1.172.0   (see note at the pip block:
#                    this is also FORCED - mobsfscan 1.0.0 hard-requires
#                    semgrep==1.172.0, so leaving semgrep unpinned in the same
#                    environment is a latent pip dependency conflict, not just
#                    a reproducibility gap. semgrep is ALSO now the primary PHP
#                    SAST pass per finding S6-1, which is the other reason it
#                    must be pinned.)
#     BinSkim        BINSKIM_VERSION    = 4.4.9.11
#     SpotBugs       SPOTBUGS_VERSION   = 4.8.6
#     FindSecBugs    FINDSECBUGS_VERSION= 1.13.0
#     Go toolchain   GO_VERSION         = 1.22.5
#     PHP analyzers  PSALM/PHPSTAN/PHPCS pinned at the composer block below
#                    (5.26.1 / 2.2.12 / 4.0.4 - PSALM_VERSION corrected
#                    2026-09-08 from the original 2026-09-01 pin of 6.16.1,
#                    which cannot install on this image at all: every psalm
#                    6.x release requires a PHP patch version (~8.1.31+) newer
#                    than what Ubuntu 22.04's php-cli package ever reports
#                    (frozen at 8.1.2) - see the comment at the composer block
#                    for the full explanation. PHPSTAN/PHPCS needed no change.
#                    These are SECONDARY to semgrep for PHP per S6-1, but
#                    pinning them keeps the ledger reproducible).
# STILL FLOATING (verify with `go list -m -versions <module>` / each project's
# releases page, then pin to an ARG the same way before the next real build,
# and record the exact tag alongside the engagement's evidence):
#     Go installs: gosec, osv-scanner, govulncheck, callgraph, digraph, scc
#     install-script pulls: Syft
#     pip installs: bandit, pip-audit, lizard, code2flow (semgrep and
#                  mobsfscan in this block ARE pinned; the rest are not)
#     (tfsec, kube-linter, checkov, and Trivy moved to images/audit-iac /
#     images/audit-container on 2026-09-17 — still floating there too, see
#     those Dockerfiles' own headers, not tracked here anymore)
#     NOTE: even with the semgrep binary pinned, the `p/*` rule packs the
#     sast-multi-semgrep step pulls are fetched from the Semgrep registry at
#     SCAN time, so they float regardless of this pin - record which rule-pack
#     versions were in effect (semgrep prints them) alongside each run's
#     evidence if you need that run to be reproducible.

FROM ubuntu:22.04

ARG GO_VERSION=1.22.5
ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8 \
    PATH="/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:/root/.composer/vendor/bin:${PATH}"

# --- Base OS packages -------------------------------------------------------
# 2026-09-10 fix (confirmed live against a real `Build-AuditToolbox.ps1` build
# log — not guessed): the Joern install step below (`./joern-install.sh`)
# failed at its own line 215 with `sudo: not found`. Root-caused by fetching
# and reading the actual upstream joern-install.sh from the same URL this
# Dockerfile pulls it from: in non-interactive mode with its default
# JOERN_LINK_DIR set, the script's symlink-creation branch is
# `if [ $INTERACTIVE = false ] && [ "$(whoami)" != "root" ]; then <skip
# symlinks> else <sudo ln -sf ...> fi` — it never checks whether it is
# ALREADY root before falling into the `else` branch, so it unconditionally
# shells out to `sudo` for every one of the ~15 Joern binary symlinks any
# time it runs as root (which this build always does — see `USER_ID`/`FROM
# ubuntu:22.04` above, no non-root user is ever created in this image). This
# base image never installed the `sudo` package (the whole image builds and
# runs as root throughout, so there was previously no reason to), which is
# the actual cause of "sudo: not found" — not a broken PATH or a missing
# Joern binary. Fix: add `sudo` to this package list so the binary exists;
# each `sudo ln -sf ... || true` then succeeds as a normal (if redundant,
# since we're already root) privileged symlink call. This is a one-line
# addition to the existing package list, not a new RUN layer, to avoid
# invalidating any more of the build cache than necessary.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git curl wget unzip jq ca-certificates gnupg lsb-release \
      software-properties-common pkg-config libssl-dev cloc \
      universal-ctags cppcheck clang clang-tidy clang-tools \
      python3 python3-pip python3-venv \
      php-cli php-mbstring php-xml php-curl composer \
      default-mysql-client \
      yara \
      sudo \
    && rm -rf /var/lib/apt/lists/*

# --- Go toolchain + Go-based tools -----------------------------------------
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
# Note: gitleaks now lives at github.com/gitleaks/gitleaks (org moved from the
# original author's github.com/zricethezav), but its go.mod still declares
# `module github.com/zricethezav/gitleaks/v8` - `go install` resolves by the
# declared module path, not the repo's current URL, so it must be installed
# via the zricethezav path below or `go install` fails with a "version
# constraints conflict" / "module declares its path as ... but was required
# as ..." error. Confirmed against the live go.mod as of this build.
#
# GITLEAKS_VERSION pinned per the 2026-09-01 adversarial process review: live
# proxy.golang.org lookup that day resolved @latest to v8.30.1 - pinning it
# here so a future rebuild doesn't silently pick up a newer gitleaks whose
# default rules (generic-api-key in particular, which drove the fsh-infra
# false-positive triage) have drifted. Re-verify and bump deliberately, don't
# just delete the pin.
ARG GITLEAKS_VERSION=v8.30.1
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest \
    && go install github.com/google/osv-scanner/cmd/osv-scanner@latest \
    && go install golang.org/x/vuln/cmd/govulncheck@latest \
    && go install golang.org/x/tools/cmd/callgraph@latest \
    && go install golang.org/x/tools/cmd/digraph@latest \
    && go install github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION} \
    && go install github.com/boyter/scc/v3@latest

# --- Syft (SBOM) -------------------------------------------------------------
# Trivy moved to `images/audit-iac` (config scanning) / `images/audit-container`
# (image/fs scanning) on 2026-09-17 — see MIGRATION.md item 7.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin

# --- Rust + weggli + ast-grep (C/C++ semantic pattern search, multi-lang
#     structural search/lint) ------------------------------------------------
# weggli is optional — comment it out to shrink the image if you don't need
# it; ast-grep is cheap (pure Rust, no extra runtime) and used across every
# language track, not just C++, so keep it.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && /root/.cargo/bin/cargo install weggli \
    && /root/.cargo/bin/cargo install ast-grep --locked

# --- Joern (Code Property Graph analysis — primary C++ semantic/taint tool,
#     genuinely open source, no build-availability requirement like CodeQL) -
# Joern's docs specify JDK 19 as the tested version ("newer might work, not
# properly tested"). JDK 19 is a non-LTS release and unlikely to still be in
# Adoptium's repo by the time you build this — Temurin 21 (LTS) is used here
# as the practical current choice. If Joern misbehaves at runtime, that JDK
# version mismatch is the first thing to check.
RUN curl -fsSL https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /usr/share/keyrings/adoptium.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb $(lsb_release -cs) main" \
       > /etc/apt/sources.list.d/adoptium.list \
    && apt-get update && apt-get install -y --no-install-recommends temurin-21-jdk \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64 \
    PATH="/opt/joern:${PATH}"
RUN mkdir -p /opt/joern && cd /opt/joern \
    && curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh \
    && chmod u+x joern-install.sh \
    && ./joern-install.sh --install-dir=/opt/joern --reinstall

# --- SpotBugs + FindSecBugs (Java SAST — bonus deep pass, NOT the primary
#     Java tool) --------------------------------------------------------------
# SpotBugs analyzes compiled bytecode, not source — it needs each Java
# service to actually `mvn`/`gradle` build first, the same build-availability
# risk already called out for CodeQL/C++ above. Semgrep (already installed
# below, run with --config=p/java --config=p/spring) is the reliable
# source-only primary pass; run SpotBugs+FindSecBugs per service, opportunistically,
# wherever a build actually succeeds — see the playbook's Phase 4 notes.
ARG SPOTBUGS_VERSION=4.8.6
ARG FINDSECBUGS_VERSION=1.13.0
RUN mkdir -p /opt/spotbugs && cd /opt/spotbugs \
    && curl -fsSL "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz" -o spotbugs.tgz \
    && tar -xzf spotbugs.tgz --strip-components=1 && rm spotbugs.tgz \
    && curl -fsSL "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar" \
       -o plugin/findsecbugs-plugin.jar
ENV PATH="/opt/spotbugs/bin:${PATH}"

# --- BinSkim (binary hardening checker — ASLR/DEP/stack canaries/
#     strong-naming; NOT a dependency/CVE scanner, complements the SBOM work
#     below, doesn't replace it) ----------------------------------------------
# Strongest on PE/COFF (Windows) binaries — a good match if the game server's
# Packer-built images are Windows (windows-game-server / windows-build-server
# in fsh-infra suggest they are). For Linux ELF binaries (Android .so, any
# Linux-built native libs), pair with `checksec` instead — add
# `apt-get install -y checksec` above if you need it; omitted here to keep
# this block focused.
#
# `dotnet tool install --global Microsoft.CodeAnalysis.BinSkim` (the
# officially-documented-sounding install path) does NOT actually work: the
# published NuGet package was never packaged as a proper dotnet global tool
# (no DotnetToolSettings.xml) — a PR to add that packaging
# (microsoft/binskim#790) was closed unmerged. Confirmed directly against the
# package for this build: it's a plain NuGet .nupkg (a zip) containing
# self-contained, per-RID published binaries under tools/net9.0/<rid>/ (e.g.
# linux-x64, win-x64, osx-x64, linux-arm64) — each bundles its own .NET
# runtime, so no .NET SDK install is needed at all (the SDK install this
# block used to carry existed only for this failed dotnet-tool step and has
# been dropped). Pull the linux-x64 build directly instead:
ARG BINSKIM_VERSION=4.4.9.11
RUN mkdir -p /opt/binskim && cd /opt/binskim \
    && curl -fsSL "https://www.nuget.org/api/v2/package/Microsoft.CodeAnalysis.BinSkim/${BINSKIM_VERSION}" -o binskim.zip \
    && unzip -q binskim.zip "tools/net9.0/linux-x64/*" -d extracted \
    && mv extracted/tools/net9.0/linux-x64/* . \
    && rm -rf extracted binskim.zip \
    && chmod +x BinSkim \
    && ln -s /opt/binskim/BinSkim /opt/binskim/binskim
ENV PATH="/opt/binskim:${PATH}"

# kube-linter moved to `images/audit-iac` on 2026-09-17 (MIGRATION.md item 7).

# Hadolint moved to `images/audit-container` on 2026-09-17 (MIGRATION.md item 7).

# --- PHP static analyzers (Composer global installs) ------------------------
# Note: this installs Psalm/PHPStan/PHPCS under the container's PHP 8.1 CLI.
# They parse PHP 5-era syntax reasonably well but not perfectly — expect
# some vendor files to fail to parse (e.g. constructs removed since PHP 7),
# and treat parser failures themselves as a finding about the codebase's age,
# not just a tooling gap. See finding S6-1 (2026-09-01 adversarial process
# review): PHPStan in particular fail-opens on a parse error (hard-errors the
# whole file out of its report rather than partially analyzing it), so
# "0 findings" from this block alone is not evidence a file was analyzed —
# cross-check against the sast-php-parse-coverage step's ledger, and treat
# Semgrep's p/php pass (sast-multi-semgrep) as the primary PHP SAST tool,
# not this one.
#
# Versions pinned 2026-09-01 (verification follow-up): these were left
# floating in the first remediation pass. They're now secondary to semgrep
# for PHP, but pinning keeps the parse-coverage ledger and any findings they
# do produce reproducible across rebuilds. Looked up as current stable that
# day; re-verify and bump deliberately.
# 2026-09-08 fix #2 (confirmed via a real build attempt, and against psalm's
# and phpstan's/phpcs's actual composer.json PHP constraints fetched from
# their real tagged releases — not guessed): psalm 6.16.1 (and in fact every
# psalm 6.x release, including 6.0.0) requires
# `php ~8.1.31 || ~8.2.27 || ~8.3.16 || ~8.4.3 || ~8.5.0` — a tight PATCH-level
# floor, not just "PHP 8.1". Ubuntu 22.04's `php-cli` apt package reports
# PHP_VERSION 8.1.2 permanently for the life of the release: Ubuntu backports
# CVE fixes into that package without ever bumping the upstream version string
# composer's platform check reads, so `composer global require` for any
# psalm 6.x version will fail here with "requirements incompatible with your
# PHP version" no matter how recently `apt-get update` was run. phpstan
# (`^7.4|^8.0`) and phpcs (`>=7.2.0`) do NOT have this problem — both accept
# any PHP 8.x, confirmed against their real composer.json — so only psalm's
# pin needs to change. Fix: pin PSALM_VERSION to 5.26.1, the actual last 5.x
# release (confirmed — 5.26.2 and 5.27.0 both 404 on GitHub, i.e. do not
# exist), whose constraint is `^7.4 || ~8.0.0 || ~8.1.0 || ~8.2.0 || ~8.3.0` —
# a full-minor-version match, so PHP 8.1.2 satisfies it. This is a real major
# version step down (Psalm 5, not 6) — acceptable here since psalm is
# documented above (S6-1) as secondary to semgrep's p/php pass for this
# engagement, not the primary PHP SAST tool. The alternative (add a PPA to
# get a newer PHP just to run psalm 6.x) was deliberately not taken: it adds
# a new package source, more network surface, and more that can drift on a
# rebuild, for a tool this pipeline treats as secondary anyway — the pin
# downgrade is the smaller, more contained change.
ARG PSALM_VERSION=5.26.1
ARG PHPSTAN_VERSION=2.2.12
ARG PHPCS_VERSION=4.0.4
RUN composer global require --no-interaction \
      vimeo/psalm:${PSALM_VERSION} \
      phpstan/phpstan:${PHPSTAN_VERSION} \
      squizlabs/php_codesniffer:${PHPCS_VERSION}
# 2026-09-08 fix #1 (confirmed live, real image): the top-of-file PATH above
# assumed Composer's legacy home directory, ~/.composer/vendor/bin. That is
# WRONG for the Composer 2.x shipped by Ubuntu 22.04's `composer` apt package
# actually installed above — its real default COMPOSER_HOME is
# ~/.config/composer, confirmed directly against the built image
# (`composer global config home` -> /root/.config/composer; psalm, phpstan,
# and phpcs were all genuinely installed successfully, just never reachable
# on PATH, which is why `psalm --version` failed with "executable file not
# found in $PATH" despite the composer install step itself succeeding with
# no error). Appending the real path here — right after the install that
# populates it, rather than editing the top-of-file ENV PATH line — keeps
# this fix minimal and avoids invalidating the build cache for every earlier
# layer (Go/Rust/Joern/SpotBugs/BinSkim), which editing that early ENV line
# would do to every layer that follows it.
ENV PATH="/root/.config/composer/vendor/bin:${PATH}"

# --- Python-based tools ------------------------------------------------------
# lancedb + fastembed back the semantic retrieval layer (build_semantic_index.py
# / query_semantic_index.py). fastembed is deliberately used instead of
# sentence-transformers here — it's ONNX-based with no torch dependency, which
# is the difference between this layer building in a couple of minutes and
# timing out pulling in a multi-GB torch install for no benefit in this
# CPU-only, single-machine use case.
#
# SEMGREP_VERSION pinned 2026-09-01 (verification follow-up). Two reasons,
# either sufficient on its own:
#   1. FORCED: mobsfscan==1.0.0 (pinned below) hard-requires semgrep==1.172.0.
#      Leaving `semgrep` unpinned in the same pip environment is a latent
#      dependency conflict waiting to surface on a rebuild, not just a
#      reproducibility gap - pip would have to resolve two different semgrep
#      constraints in one env. Pinning the standalone semgrep to the exact
#      version mobsfscan needs keeps the environment self-consistent.
#   2. Semgrep is now the PRIMARY PHP SAST pass (finding S6-1) - its analyzer
#      and default behavior drifting between builds would silently change the
#      authoritative PHP result. (The `p/*` rule packs still float at scan
#      time regardless - see the version-pinning header note.)
# Verified live against PyPI: semgrep 1.172.0 exists and is exactly what
# mobsfscan 1.0.0 (2026-08-10) requires.
#
# MOBSFSCAN_VERSION pinned per the 2026-09-01 adversarial process review:
# verified live against PyPI that day (1.0.0, 2026-08-10, itself pinning
# semgrep==1.172.0). An unpinned `mobsfscan` install floats the CLI version
# and its bundled rule packs across rebuilds - pin the outer tool too.
ARG SEMGREP_VERSION=1.172.0
ARG MOBSFSCAN_VERSION=1.0.0
RUN pip3 install --no-cache-dir \
      semgrep==${SEMGREP_VERSION} \
      bandit \
      pip-audit \
      lizard \
      code2flow \
      pyyaml \
      tree-sitter \
      tree-sitter-language-pack \
      lancedb \
      fastembed \
      mobsfscan==${MOBSFSCAN_VERSION}

# --- This repo's own evidence-shaping scripts --------------------------------
COPY scripts/build_symbol_index.py scripts/md_to_sarif.py scripts/build_semantic_index.py scripts/query_semantic_index.py \
     scripts/scrub_evidence.py scripts/php_parse_coverage.py scripts/run-sast-php.sh \
     scripts/run-semantic-index-batched.sh \
     /opt/scripts/
RUN chmod +x /opt/scripts/*.py /opt/scripts/*.sh

# 2026-09-08 fix #3 (confirmed live against a real container, via sast-php's
# own real stderr.log — not guessed): psalm hard-requires a config file in
# the project it analyzes and refuses to run at all without one
# ("Could not locate a config XML file in path /workspace. Have you run
# 'psalm init' ?"). /workspace is bind-mounted read-only for every step in
# this pipeline (see Get-BaseDockerArgs in Invoke-VendorAuditPrePass.ps1), so
# psalm could never write a config there even as a first pass. Fixed by
# baking a minimal static psalm.xml into the image and pointing psalm at it
# explicitly with its config flag (see run-sast-php.sh, copied above, and
# the sast-php step's Cmd in the orchestrator, now just
# @("bash", "/opt/scripts/run-sast-php.sh") — two static array elements
# instead of a runtime PowerShell-concatenated compound string, closing off
# the same class of PowerShell/docker.exe argv-marshalling risk that already
# hit joern-parse and ast-grep-scan twice elsewhere in this toolbox).
# psalm.xml's own schema was confirmed against Psalm's documented minimal
# example, not guessed.
COPY images/audit-static/psalm.xml /opt/config/psalm.xml

# dockerfile-lint's fix history (the PowerShell-to-docker.exe argv-marshalling
# bug, and its static-script fix) now lives with the step itself in
# `images/audit-container/Dockerfile` and `scripts/run-dockerfile-lint.sh`.

WORKDIR /workspace
# No ENTRYPOINT/CMD by design — the orchestrator (Invoke-VendorAuditPrePass.ps1)
# runs one tool at a time via `docker run <image> <command...>` so each step's
# exit code and output are handled individually and one tool failing doesn't
# take the rest of the pre-pass down with it.
CMD ["/bin/bash"]
