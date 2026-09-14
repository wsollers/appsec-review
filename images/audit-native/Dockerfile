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
# Base is ubuntu:24.04: SVF-3.3's CMakeLists requires CMake >= 3.23 (jammy ships
# 3.22 and the build fails before compiling anything — first build, 2026-09-11),
# and SVF's own Dockerfile builds on noble against this same "ubuntu22" tarball.

FROM ubuntu:24.04

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
# Package list mirrors SVF-3.3's Dockerfile (lib_deps/build_deps) plus what this
# image adds: ninja, bear, python, gnupg/lsb-release for the apt repos below.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git xz-utils unzip zip tcl \
      build-essential gcc g++ cmake ninja-build pkg-config \
      zlib1g-dev libncurses5-dev libtinfo6 libssl-dev libpcre2-dev libzstd-dev libxml2-dev \
      python3 python3-dev python3-pip python3-venv \
      bear \
      gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/* \
    && cmake --version | head -1

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
# apt.llvm.org noble repo (Release file verified 200 on 2026-09-11 for jammy;
# noble is the same layout). Different build of the same LLVM major. clang-tidy is a standalone binary and
# CodeChecker only needs it on PATH; lld-link is needed only if a link step is
# ever attempted (it isn't for IR/CSA, but harness builds under 16.1 may want it).
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/noble/ llvm-toolchain-noble-${LLVM_MAJOR} main" \
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
    && unzip -q z3.zip && mv z3-${Z3_VERSION}-x64-ubuntu-16.04 /opt/z3 && rm z3.zip \
    && ln -s /opt/z3/bin/libz3.so /opt/z3/bin/libz3.so.4
# libz3.so.4 symlink: SVF's own Dockerfile does this; the prebuilt Z3 ships only
# the unversioned soname and SVF's binaries look for .so.4 at run time.
ENV Z3_DIR=/opt/z3

# --- SVF (tag SVF-3.3) --------------------------------------------------------
# build.sh skips its own LLVM/Z3 downloads when LLVM_DIR / Z3_DIR point at
# existing directories, which they do above. Shared libs + RTTI (its default).
# patches/: source-level deviations from upstream, each self-documenting. Applied
# between clone and build so they are part of the image, not the run.
COPY patches/ /opt/patches/
RUN git clone --depth 1 --branch ${SVF_TAG} https://github.com/SVF-tools/SVF.git /opt/svf \
    && cd /opt/svf \
    && python3 /opt/patches/svf-3.3-vfg-setdef-diagnostic.py svf/include/Graphs/VFG.h \
    && sed -i 's/^jobs=8$/jobs=$(nproc)/' build.sh \
    && bash ./build.sh \
    && ls /opt/svf/Release-build/bin \
    && test -x /opt/svf/Release-build/bin/wpa
ENV SVF_DIR=/opt/svf \
    PATH="/opt/svf/Release-build/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/svf/Release-build/lib:/opt/z3/bin:/opt/llvm/lib"

# --- in-tree LLVM tools: ir-facts (L7 fact extractor) and svf-taint (SVF client) ---
# Built against the LLVM/SVF above so their ABI matches. Both are small.
COPY ir-facts/ /opt/src/ir-facts/
COPY svf-taint/ /opt/src/svf-taint/
RUN mkdir -p /opt/ir-facts /opt/svf-taint \
    && cmake -S /opt/src/ir-facts -B /tmp/b1 -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR="$LLVM_DIR/lib/cmake/llvm" > /dev/null \
    && cmake --build /tmp/b1 -j"$(nproc)" > /dev/null && cp /tmp/b1/ir-facts /opt/ir-facts/ \
    && cmake -S /opt/src/svf-taint -B /tmp/b2 -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR="$LLVM_DIR/lib/cmake/llvm" -DSVF_DIR="$SVF_DIR" -DZ3_DIR="$Z3_DIR" > /dev/null \
    && cmake --build /tmp/b2 -j"$(nproc)" > /dev/null && cp /tmp/b2/svf-taint /opt/svf-taint/ \
    && rm -rf /tmp/b1 /tmp/b2 && /opt/ir-facts/ir-facts --help 2>&1 | head -1
ENV PATH="/opt/ir-facts:/opt/svf-taint:${PATH}"

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
# HAVE_RULES=OFF: rules support needs legacy libpcre (not pcre2) and is unused
# here; ON failed the 2026-09-11 build with a missing-PCRE cmake error.
RUN cd /tmp \
    && curl -fsSL -o cppcheck.tgz "https://github.com/danmar/cppcheck/archive/refs/tags/${CPPCHECK_VERSION}.tar.gz" \
    && tar -xzf cppcheck.tgz && cd cppcheck-${CPPCHECK_VERSION} \
    && cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DHAVE_RULES=OFF -DUSE_MATCHCOMPILER=ON \
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

# --- Python: CodeChecker in its own venv ---------------------------------------
# A venv, not --break-system-packages: the 2026-09-11 build failed because
# codechecker pulls pyyaml and pip cannot replace the Debian-installed PyYAML
# ("RECORD file not found"). Isolating CodeChecker avoids every such collision.
# lxml pinned to 6.x because codechecker 6.29.0 requires lxml~=6.0 (5.3.0 gave
# ResolutionImpossible); 6.1.3 verified on PyPI 2026-09-11.
# The image's own scripts under /opt/scripts are stdlib-only and run on the
# system /usr/bin/python3; they do not use this venv.
RUN python3 -m venv /opt/codechecker-venv \
    && /opt/codechecker-venv/bin/pip install --no-cache-dir \
         codechecker==${CODECHECKER_VERSION} \
         lxml==6.1.3 \
    && ln -s /opt/codechecker-venv/bin/CodeChecker /usr/local/bin/CodeChecker \
    && CodeChecker version

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
