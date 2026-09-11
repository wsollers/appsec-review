# syntax=docker/dockerfile:1
#
# audit-native — Mythos L3 native C/C++ analysis worker.
#
# Runs ONLY inside the hostile-build isolation boundary (design §2.2, §17).
# It has no network at run time, mounts /workspace read-only, writes only to
# /scratch, and has no write access to canonical evidence or the ledger. The
# orchestrator imports allowlisted artifacts from /scratch after the worker
# is destroyed. See run.sh for the enforced docker run flags.
#
# Contents (all pinned; every URL below was fetched and returned 200 on
# 2026-09-11 before being written here):
#
#   LLVM/Clang 21.1.0   RTTI-enabled prebuilt from SVF-tools' own LLVM mirror.
#                       One toolchain serves clang, clang-cl, CSA (scan-build /
#                       analyze-build), llvm-lib/llvm-rc/llvm-mt, opt, llvm-link,
#                       AND the SVF build. apt.llvm.org packages are built
#                       without RTTI and cannot link SVF, which is why the
#                       tarball is used instead. Verified contents of bin/:
#                       clang, clang++, clang-cl, scan-build, scan-build-py,
#                       analyze-build, intercept-build, clang-check,
#                       clang-extdef-mapping (CTU), llvm-lib, llvm-rc, llvm-mt,
#                       llvm-ml/ml64, opt, llc, llvm-link, llvm-dis.
#                       NOT in the tarball: clang-tidy, lld/lld-link. Those two
#                       come from apt.llvm.org at the same major (21) below.
#   SVF                 tag SVF-3.3 (its build.sh pins MajorLLVMVer=21 and
#                       Z3 4.8.8 — both match what is installed here).
#   Z3 4.8.8            prebuilt, the exact archive SVF-3.3 build.sh downloads.
#   Joern               v4.0.625 (2026-09-10), joern-cli-linux-x86_64.zip.
#                       README states JDK 21 as the tested JDK. Installed by
#                       unzipping the release asset directly, NOT via
#                       joern-install.sh (which shells out to sudo when run
#                       as root — the bug documented in audit-static).
#   CodeChecker 6.29.0  pip. Wraps CSA + clang-tidy with a report store/diff.
#   cppcheck 2.21.1     built from source; Ubuntu 22.04's apt cppcheck is 2.7.
#   xwin 0.10.0         prebuilt musl binary. Fetches MSVC CRT + Windows SDK
#                       from Microsoft's manifests. NOT run during the image
#                       build — the headers are a licensed input and are
#                       mounted at /msvc at run time (ADR-0003). xwin is in the
#                       image so scripts/fetch-msvc-xwin.sh can populate the
#                       mount on a networked host with the same pinned binary.
#   bear 3.1.3          apt (Ubuntu 22.04). compile_commands.json from
#                       Make/Ninja builds where a .vcxproj converter doesn't
#                       apply.
#
# Base is ubuntu:22.04 deliberately: the SVF-LLVM tarball is built on jammy.

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

ARG LLVM_VERSION=21.1.0
ARG LLVM_MAJOR=21
ARG SVF_TAG=SVF-3.3
ARG Z3_VERSION=4.8.8
ARG JOERN_VERSION=v4.0.625
ARG CODECHECKER_VERSION=6.29.0
ARG CPPCHECK_VERSION=2.21.1
ARG XWIN_VERSION=0.10.0

# --- Base packages -----------------------------------------------------------
# libncurses5/libncurses-dev, zlib1g-dev: SVF build.sh's stated dependencies.
# libtinfo5: LLVM 21 prebuilt binaries link against it on jammy.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git xz-utils unzip zip \
      build-essential cmake ninja-build pkg-config \
      libncurses5 libncurses-dev zlib1g-dev libtinfo5 libxml2-dev \
      python3 python3-pip python3-venv \
      bear \
      gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/*

# --- LLVM/Clang 21.1.0 (RTTI build, from SVF-tools' mirror) ------------------
RUN mkdir -p /opt/llvm && cd /tmp \
    && curl -fsSL -o llvm.tgz \
       "https://github.com/bjjwwang/SVF-LLVM/releases/download/${LLVM_VERSION}/llvm-${LLVM_VERSION}-ubuntu22-rtti-x86-64.tar.gz" \
    && tar -xzf llvm.tgz -C /opt/llvm --strip-components=1 \
    && rm llvm.tgz \
    && /opt/llvm/bin/clang --version && /opt/llvm/bin/clang-cl --version
ENV LLVM_DIR=/opt/llvm \
    PATH="/opt/llvm/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/llvm/lib"

# --- clang-tidy + lld from apt.llvm.org, same major --------------------------
# Different build of the same LLVM major. clang-tidy is a standalone binary and
# CodeChecker only needs it on PATH; lld-link is needed only if a link step is
# ever attempted (it isn't for IR/CSA, but harness builds under 16.1 may want it).
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-${LLVM_MAJOR} main" \
       > /etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y --no-install-recommends \
       clang-tidy-${LLVM_MAJOR} lld-${LLVM_MAJOR} \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/bin/clang-tidy-${LLVM_MAJOR} /usr/local/bin/clang-tidy \
    && ln -s /usr/bin/lld-link-${LLVM_MAJOR} /usr/local/bin/lld-link \
    && ln -s /usr/bin/ld.lld-${LLVM_MAJOR} /usr/local/bin/ld.lld

# --- Z3 4.8.8 (exact prebuilt SVF-3.3 build.sh uses) ---------------------------
RUN cd /tmp \
    && curl -fsSL -o z3.zip \
       "https://github.com/Z3Prover/z3/releases/download/z3-${Z3_VERSION}/z3-${Z3_VERSION}-x64-ubuntu-16.04.zip" \
    && unzip -q z3.zip && mv z3-${Z3_VERSION}-x64-ubuntu-16.04 /opt/z3 && rm z3.zip
ENV Z3_DIR=/opt/z3

# --- SVF (tag SVF-3.3) --------------------------------------------------------
# build.sh skips its own LLVM/Z3 downloads when LLVM_DIR / Z3_DIR point at
# existing directories, which they do above. Shared libs + RTTI (its default).
RUN git clone --depth 1 --branch ${SVF_TAG} https://github.com/SVF-tools/SVF.git /opt/svf \
    && cd /opt/svf \
    && sed -i 's/^jobs=8$/jobs=$(nproc)/' build.sh \
    && bash ./build.sh \
    && /opt/svf/Release-build/bin/wpa --version 2>/dev/null || ls /opt/svf/Release-build/bin
ENV SVF_DIR=/opt/svf \
    PATH="/opt/svf/Release-build/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/svf/Release-build/lib:/opt/z3/bin:/opt/llvm/lib"

# --- Joern v4.0.625 (JDK 21) --------------------------------------------------
RUN curl -fsSL https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /usr/share/keyrings/adoptium.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb $(lsb_release -cs) main" \
       > /etc/apt/sources.list.d/adoptium.list \
    && apt-get update && apt-get install -y --no-install-recommends temurin-21-jdk \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
RUN cd /tmp \
    && curl -fsSL -o joern.zip \
       "https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-cli-linux-x86_64.zip" \
    && unzip -q joern.zip -d /opt && rm joern.zip \
    && ls /opt/joern-cli/joern
ENV PATH="/opt/joern-cli:${PATH}"

# --- cppcheck 2.21.1 from source ---------------------------------------------
RUN cd /tmp \
    && curl -fsSL -o cppcheck.tgz "https://github.com/danmar/cppcheck/archive/refs/tags/${CPPCHECK_VERSION}.tar.gz" \
    && tar -xzf cppcheck.tgz && cd cppcheck-${CPPCHECK_VERSION} \
    && cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DHAVE_RULES=ON -DUSE_MATCHCOMPILER=ON \
       -DCMAKE_INSTALL_PREFIX=/usr/local -DFILESDIR=/usr/local/share/cppcheck \
    && cmake --build build -j"$(nproc)" && cmake --install build \
    && cd /tmp && rm -rf cppcheck.tgz cppcheck-${CPPCHECK_VERSION} \
    && cppcheck --version

# --- xwin 0.10.0 (binary only; never executed during image build) ------------
RUN cd /tmp \
    && curl -fsSL -o xwin.tgz \
       "https://github.com/Jake-Shadle/xwin/releases/download/${XWIN_VERSION}/xwin-${XWIN_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
    && tar -xzf xwin.tgz && mv xwin-${XWIN_VERSION}-x86_64-unknown-linux-musl/xwin /usr/local/bin/xwin \
    && rm -rf xwin.tgz xwin-${XWIN_VERSION}-x86_64-unknown-linux-musl && xwin --version

# --- Python: CodeChecker + this image's scripts' deps -------------------------
RUN pip3 install --no-cache-dir \
      codechecker==${CODECHECKER_VERSION} \
      pyyaml==6.0.2 \
      lxml==5.3.0

# --- This image's scripts ------------------------------------------------------
COPY scripts/ /opt/scripts/
RUN chmod +x /opt/scripts/*.py /opt/scripts/*.sh

# --- Non-root worker user, fixed mount points ----------------------------------
# /workspace : vendor source, read-only
# /msvc      : MSVC CRT + Windows SDK (licensed input), read-only  (ADR-0003)
# /scratch   : the only writable path; orchestrator imports from here
RUN useradd -m -u 10001 -s /bin/bash worker \
    && mkdir -p /workspace /msvc /scratch \
    && chown worker:worker /scratch
USER worker
WORKDIR /scratch

# No ENTRYPOINT/CMD by design — the orchestrator runs one script per step as
# a static argv array (ADR-0002). Every runnable step is under /opt/scripts.
CMD ["/bin/bash"]
