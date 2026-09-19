# syntax=docker/dockerfile:1
#
# audit-static-opengrep — a PARALLEL, NOT A REPLACEMENT, image for
# images/audit-static's role. Added 2026-09-19 per the repo owner's explicit
# request: evaluate switching the SAST engine from Semgrep to Opengrep
# (github.com/opengrep/opengrep, LGPL 2.1 -- confirmed live against its own
# README, not assumed), partly because Opengrep's language list includes
# Lua and Semgrep CE's does not carry Lua past "Experimental" tier the same
# way.
#
# images/audit-static/Dockerfile IS NOT MODIFIED. This is a brand-new
# sibling directory/image so the existing Semgrep-based `audit-static:local`
# stays exactly as-is and buildable, and rolling back is just "keep using
# the old tag" -- nothing to revert. Build this one as a DIFFERENT tag,
# e.g.:
#     docker build -t audit-static-opengrep:local -f images/audit-static-opengrep/Dockerfile .
# Do not overwrite the `audit-static:local` tag with this image.
#
# ============================================================================
# THREE THINGS THIS FILE DOES NOT YET RESOLVE -- read before relying on it
# ============================================================================
#
# 1. RULE SOURCING -- DECIDED 2026-09-19, NOT AN OPEN BLOCKER ANYMORE.
#    Opengrep ships no rule registry of its own -- confirmed against
#    Semgrep's own published comparison of the two projects: "Opengrep
#    publishes no ruleset of its own, so sourcing rules, keeping them
#    current, and covering new vulnerability classes is the user's
#    responsibility." (https://docs.semgrep.dev/faq/comparisons/opengrep).
#    It cannot resolve the `p/<name>` registry shortcuts
#    Invoke-VendorAuditPrePass.ps1's 7-way sast-multi-semgrep-* split
#    currently uses (`p/owasp-top-ten`, `p/csharp`, `p/golang`, `p/python`,
#    `p/php`, `p/java`, `p/security-audit`); opengrep's own scan syntax
#    takes a local rule file/directory instead (`opengrep scan -f <rules>
#    <target>`, confirmed against its README).
#
#    Cloning github.com/semgrep/semgrep-rules (the community rules repo most
#    `p/*` packs are generated from) into this image was considered and
#    REJECTED, not left undecided: that repo's rules are distributed under
#    the "Semgrep Rules License v1.0"
#    (https://semgrep.dev/legal/rules-license), not a standard OSS license,
#    and Semgrep's own FAQ characterizes it as restricting vendor use
#    ("Vendors may not use them in competing products or SaaS offerings") --
#    the same category of licensing-fit question this project already took
#    seriously once before for CodeQL (see images/audit-static/Dockerfile's
#    own header).
#
#    DECISION (repo owner, 2026-09-19): stay on Semgrep as the production
#    SAST engine (images/audit-static, unchanged) and author this project's
#    OWN Opengrep rules over time to reach parity with the 7 packs above,
#    rather than vendoring semgrep-rules' licensed content -- sidesteps the
#    license question entirely since nothing here is derived from Semgrep's
#    rule content. `/opt/rules/opengrep/` below is COPYed from
#    images/audit-static-opengrep/rules/ in this repo, which holds one
#    directory per target category (owasp-top-ten/csharp/golang/python/php/
#    java/security-audit) plus `parity-status.json`, the source of truth for
#    how far along each category actually is -- see that directory's own
#    README.md for the full convention. Every category starts
#    `not_started`/empty as of this commit; DO NOT point any real
#    orchestrator step at this image for a category until its
#    parity-status.json entry is marked `parity_reached` (see that file's
#    own warning about a thin/empty ruleset still exiting 0 and looking
#    clean).
#
# 2. LUA SUPPORT IS INHERITED, NOT A HEADLINE FEATURE, AND UNCONFIRMED HERE.
#    Opengrep's own OPENGREP.md documents languages it adds BEYOND Semgrep
#    CE (Crystal, Visual Basic, and Apex improvements) -- it does not
#    re-list languages Semgrep CE already had, which is where Lua actually
#    lives: Semgrep's own supported-languages doc lists Lua at
#    "Experimental" tier for Semgrep Code (community-usable, not Pro-only).
#    Since Opengrep forks Semgrep CE, Lua support most likely carries over,
#    but this was NOT verified against a real `opengrep scan` invocation
#    against actual Lua source in this authoring environment (no Docker
#    daemon here -- see BUILD NOTE below). Confirm with a real Lua fixture
#    on hal5000 before treating Lua coverage as real for a target that
#    embeds it (e.g. a future game-engine target, per the L12/Tier-B
#    discussion in the harness doc).
#
# 3. THE ORCHESTRATOR STEPS (Invoke-VendorAuditPrePass.ps1/.sh's
#    sast-multi-semgrep-* steps and scripts/run-sast-php.sh) ARE NOT CHANGED
#    BY THIS COMMIT. This file only builds the image. Pointing any real step
#    at `audit-static-opengrep:local` instead of `audit-static:local`, and
#    rewriting each step's Cmd array to use `-f /opt/rules/opengrep/<pack>`
#    instead of `--config=p/<pack>`, is a separate, deliberate follow-up --
#    do that only after rule sourcing (item 1) is actually resolved and this
#    image has been built and sanity-checked for real on hal5000.
#
# ============================================================================
#
# mobsfscan==1.0.0 (still installed below, unchanged from images/audit-static)
# hard-requires semgrep==1.172.0 as an internal Python dependency -- it is
# NOT just a CLI wrapper that happens to share a name, it imports semgrep's
# own library code. That pip package is therefore KEPT in this image
# exactly as in images/audit-static, even though opengrep is meant to
# replace semgrep as the thing this pipeline actually invokes for SAST
# scanning. Do not remove the `semgrep` pip install below thinking it's
# redundant with opengrep -- mobsfscan will break without it.
#
# BUILD NOTE (same caveat as images/audit-static/Dockerfile's own header):
# this file has not been build-tested in a live Docker daemon -- the
# authoring environment (a Cowork device-bridge sandbox) has no Docker at
# all. Build it, and work through items 1-3 above, on hal5000 directly
# before relying on it.
#
# VERSION PINNING: OPENGREP_VERSION is left floating (the install.sh script
# below installs whatever it resolves as current) -- same "STILL FLOATING"
# category images/audit-static/Dockerfile already tracks for Syft/gosec/
# osv-scanner/etc. Opengrep is new enough (forked from Semgrep in 2025) that
# pinning to a specific tagged release should happen before this image is
# used for anything you need to reproduce later -- check
# github.com/opengrep/opengrep/releases for a version tag and an
# install.sh flag or a direct release-asset URL to pin against, then record
# the exact version here the same way SEMGREP_VERSION/GITLEAKS_VERSION/etc.
# are recorded in images/audit-static/Dockerfile.

FROM ubuntu:22.04

ARG GO_VERSION=1.22.5
ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8 \
    PATH="/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:/root/.composer/vendor/bin:${PATH}"

# --- Base OS packages -------------------------------------------------------
# Identical to images/audit-static/Dockerfile's own package list, including
# its `sudo` fix for the Joern install step below (see that file's header
# for the full root-cause explanation -- unchanged here, not re-derived).
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

# --- Go toolchain + Go-based tools (unchanged from images/audit-static) ----
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
ARG GITLEAKS_VERSION=v8.30.1
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest \
    && go install github.com/google/osv-scanner/cmd/osv-scanner@latest \
    && go install golang.org/x/vuln/cmd/govulncheck@latest \
    && go install golang.org/x/tools/cmd/callgraph@latest \
    && go install golang.org/x/tools/cmd/digraph@latest \
    && go install github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION} \
    && go install github.com/boyter/scc/v3@latest

# --- Syft (SBOM) -------------------------------------------------------------
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin

# --- Rust + weggli + ast-grep (unchanged from images/audit-static) ---------
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && /root/.cargo/bin/cargo install weggli \
    && /root/.cargo/bin/cargo install ast-grep --locked

# --- Joern (unchanged from images/audit-static) -----------------------------
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

# --- SpotBugs + FindSecBugs (unchanged from images/audit-static) ----------
ARG SPOTBUGS_VERSION=4.8.6
ARG FINDSECBUGS_VERSION=1.13.0
RUN mkdir -p /opt/spotbugs && cd /opt/spotbugs \
    && curl -fsSL "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz" -o spotbugs.tgz \
    && tar -xzf spotbugs.tgz --strip-components=1 && rm spotbugs.tgz \
    && curl -fsSL "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar" \
       -o plugin/findsecbugs-plugin.jar
ENV PATH="/opt/spotbugs/bin:${PATH}"

# --- BinSkim (unchanged from images/audit-static) ---------------------------
ARG BINSKIM_VERSION=4.4.9.11
RUN mkdir -p /opt/binskim && cd /opt/binskim \
    && curl -fsSL "https://www.nuget.org/api/v2/package/Microsoft.CodeAnalysis.BinSkim/${BINSKIM_VERSION}" -o binskim.zip \
    && unzip -q binskim.zip "tools/net9.0/linux-x64/*" -d extracted \
    && mv extracted/tools/net9.0/linux-x64/* . \
    && rm -rf extracted binskim.zip \
    && chmod +x BinSkim \
    && ln -s /opt/binskim/BinSkim /opt/binskim/binskim
ENV PATH="/opt/binskim:${PATH}"

# --- PHP static analyzers (unchanged from images/audit-static) ------------
ARG PSALM_VERSION=5.26.1
ARG PHPSTAN_VERSION=2.2.12
ARG PHPCS_VERSION=4.0.4
RUN composer global require --no-interaction \
      vimeo/psalm:${PSALM_VERSION} \
      phpstan/phpstan:${PHPSTAN_VERSION} \
      squizlabs/php_codesniffer:${PHPCS_VERSION}
ENV PATH="/root/.config/composer/vendor/bin:${PATH}"

# --- Python-based tools ------------------------------------------------------
# semgrep is KEPT here, pinned exactly as in images/audit-static, purely as
# mobsfscan's own internal dependency (see the header block above) -- it is
# not invoked directly as a scanner by this image's intended workflow once
# opengrep takes over that role.
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

# --- Opengrep (the actual change this image exists to make) ----------------
# Install command confirmed live against github.com/opengrep/opengrep's own
# README (not guessed): self-contained Nuitka-built binary, installed via
# its own install.sh, resolving to a real `opengrep` binary on PATH.
# Unpinned -- see VERSION PINNING note above.
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
ENV PATH="/root/.opengrep/cli/latest:${PATH}"
# NOTE: the exact install directory opengrep's install.sh uses was not
# confirmed against a real run in this sandbox (no Docker daemon available
# to actually execute the script and observe where it placed the binary --
# the path above is inferred from opengrep's own documented convention,
# not verified). Confirm `which opengrep` / `opengrep --version` on the
# first real build on hal5000 and correct this ENV line if the real
# install path differs.

# Our own authored Opengrep rules, built toward parity with the 7 Semgrep
# p/* packs -- see item 1 in the header block and
# images/audit-static-opengrep/rules/README.md for the full convention.
# Every category is empty/not_started as of this commit (check
# rules/parity-status.json for current state); this COPY will pick up real
# rule content automatically as categories are authored, no Dockerfile
# change needed when that happens.
COPY images/audit-static-opengrep/rules/ /opt/rules/opengrep/

# --- This repo's own evidence-shaping scripts (unchanged from images/audit-static) -----
COPY scripts/build_symbol_index.py scripts/build_semantic_index.py scripts/query_semantic_index.py \
     scripts/scrub_evidence.py scripts/php_parse_coverage.py scripts/run-sast-php.sh \
     scripts/run-semantic-index-batched.sh \
     scripts/analyze_dependency_lifecycle.py scripts/eol-reference.json \
     /opt/scripts/
RUN chmod +x /opt/scripts/*.py /opt/scripts/*.sh

COPY images/audit-static/psalm.xml /opt/config/psalm.xml

WORKDIR /workspace
CMD ["/bin/bash"]
