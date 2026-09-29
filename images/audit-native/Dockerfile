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
#   Ghidra 12.1.3       release zip (sha256 pinned), headless via
#                       ghidra-analyzeHeadless. Runs on its own pinned JDK
#                       (Temurin 21.0.12+8 tarball, sha256 = Adoptium's
#                       .sha256.txt) through JAVA_HOME_OVERRIDE; Joern keeps
#                       the apt temurin-21-jdk. Same pins as audit-binary-analysis.
#   x64dbg              snapshot 2026.05.27 (sha256 pinned), Windows PE
#                       debugger run under Wine 9.0 (Ubuntu 9.0~repack-4build3,
#                       wine32:i386 for x32dbg) and Xvfb. Wrappers x96dbg,
#                       x64dbg, x32dbg default to headless.exe. For inspecting
#                       PE files only: never run malware, never enable the
#                       network. The Wine prefix is built here, not at run time.
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
ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_BUILD=20260817
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54
ARG GHIDRA_JDK_URL=https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12%2B8/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12_8.tar.gz
ARG GHIDRA_JDK_SHA256=e4446ff06a276155697597cc0f1b15da004ff083f4964a35271ecee567177370
ARG WINE_VERSION=9.0~repack-4build3
ARG X64DBG_TAG=2026.05.27
ARG X64DBG_SNAPSHOT=snapshot_2026-05-27_12-11
ARG X64DBG_SHA256=d41966dfc5b435a372798245300ca0ab7bb8e48bdbf48512c6fb20fcca427697

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

# --- Ghidra 12.1.3 on its own pinned JDK (same pins as audit-binary-analysis) ---
# The ghidra wrappers put /opt/ghidra-jdk first (launch.sh needs a java before it reads
# JAVA_HOME_OVERRIDE; Joern's JAVA_HOME above is unchanged) and set user.home from $HOME: the
# boundary runs as the host uid, which has no passwd entry, and Ghidra saves settings under it.
RUN cd /tmp \
    && curl -fsSL -o jdk.tgz "$GHIDRA_JDK_URL" \
    && echo "$GHIDRA_JDK_SHA256  jdk.tgz" | sha256sum -c - \
    && mkdir -p /opt/ghidra-jdk && tar -xzf jdk.tgz -C /opt/ghidra-jdk --strip-components=1 && rm jdk.tgz \
    && /opt/ghidra-jdk/bin/java -version
RUN cd /tmp \
    && curl -fsSL -o ghidra.zip \
       "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip" \
    && echo "$GHIDRA_SHA256  ghidra.zip" | sha256sum -c - \
    && unzip -q ghidra.zip -d /opt && rm ghidra.zip \
    && ln -sfn "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && sed -i 's#^JAVA_HOME_OVERRIDE=$#JAVA_HOME_OVERRIDE=/opt/ghidra-jdk#' /opt/ghidra/support/launch.properties \
    && grep -qx 'JAVA_HOME_OVERRIDE=/opt/ghidra-jdk' /opt/ghidra/support/launch.properties \
    && for pair in ghidra:ghidraRun ghidra-analyzeHeadless:support/analyzeHeadless; do \
         printf '#!/bin/sh\n%s\n%s\nexec /opt/ghidra/%s "$@"\n' \
           'export PATH=/opt/ghidra-jdk/bin:$PATH JAVA_HOME=/opt/ghidra-jdk' \
           'export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Duser.home=${HOME:-/tmp}"' \
           "${pair#*:}" > "/usr/local/bin/${pair%%:*}"; \
         chmod 0755 "/usr/local/bin/${pair%%:*}"; \
       done
ENV GHIDRA_HOME=/opt/ghidra

# --- Wine + Xvfb, then x64dbg (x96dbg launcher, x64dbg, x32dbg) ------------------
# x64dbg is a Windows debugger; it runs here only under Wine. wine32:i386 (multiarch) is required:
# x96dbg.exe and x32dbg.exe are PE32. Mono and Gecko are never installed (WINEDLLOVERRIDES), and the
# MSVC runtime DLLs shipped with x64dbg load before Wine's builtins.
RUN dpkg --add-architecture i386 \
    && apt-get update && apt-get install -y --no-install-recommends \
       "wine=${WINE_VERSION}" "wine64=${WINE_VERSION}" "wine32:i386=${WINE_VERSION}" xvfb xauth \
    && rm -rf /var/lib/apt/lists/* \
    && wine --version
RUN cd /tmp \
    && curl -fsSL -o x64dbg.zip \
       "https://github.com/x64dbg/x64dbg/releases/download/${X64DBG_TAG}/${X64DBG_SNAPSHOT}.zip" \
    && echo "$X64DBG_SHA256  x64dbg.zip" | sha256sum -c - \
    && mkdir -p /opt/x64dbg && unzip -q x64dbg.zip -d /opt/x64dbg && rm x64dbg.zip \
    && printf '%s' 'C:\x64dbg-user\x64' > /opt/x64dbg/release/x64/userdir \
    && printf '%s' 'C:\x64dbg-user\x32' > /opt/x64dbg/release/x32/userdir \
    && printf 'x64dbg %s (%s.zip sha256 %s, commit %s)\n' "$X64DBG_TAG" "$X64DBG_SNAPSHOT" "$X64DBG_SHA256" \
       "$(cat /opt/x64dbg/commithash.txt)" > /opt/x64dbg/VERSION \
    && chmod -R a+rX,go-w /opt/x64dbg
# Wrapper (tool definition, same text in audit-binary-analysis and audit-native). The userdir files
# above point the GUI at C:\x64dbg-user in the prefix; headless.exe gets -userdir.
RUN cat > /usr/local/bin/x64dbg-wine <<'X64DBG_WRAPPER'
#!/bin/bash
# x64dbg under Wine: installed as x96dbg, x64dbg and x32dbg (symlinks to this file).
# A debugger for Windows PE files inspected under Wine inside the no-network audit container.
# Never run malware with it, and never enable the container network for it.
#
#   x64dbg | x32dbg [ARGS]        headless.exe of that arch; debugger commands on stdin, "exit" ends
#   x96dbg [PE-FILE]              headless of the PE file's arch (x64 when no file is given)
#   NAME --gui [ARGS]             the Qt GUI (x96dbg: the launcher) under xvfb-run
#   NAME --which PE-FILE          print x64 or x32 for a PE file and exit
#   NAME --prepare                create this user's Wine prefix, run wineboot, print its path
#   NAME --version                print the pinned snapshot and exit
#
# Wine refuses a prefix owned by another uid and the image root is read-only, so the prefix built
# into the image (/opt/wine-prefix) is copied once per uid to X64DBG_RUNTIME_DIR (default
# /scratch/.x64dbg-runtime when /scratch is writable, else $TMPDIR). The debugger's user directory
# (settings, databases) is C:\x64dbg-user\<arch> inside that prefix.
set -euo pipefail
home=/opt/x64dbg
base=/opt/wine-prefix
# Mono and Gecko are disabled; the MSVC runtime DLLs shipped in the x64dbg zip are used instead of
# Wine's builtins (Wine 9.0's msvcp140 lacks std::_Throw_Cpp_error, which x32dbg calls on exit).
export WINEDEBUG=${WINEDEBUG:--all} WINEDLLOVERRIDES=${WINEDLLOVERRIDES:-"mscoree,mshtml=;msvcp140,vcruntime140,vcruntime140_1=n,b"}

pe_arch() {
  python3 - "$1" <<'PY'
import struct, sys
data = open(sys.argv[1], "rb").read(4096)
if data[:2] != b"MZ":
    sys.exit("not a PE file: " + sys.argv[1])
offset = struct.unpack_from("<I", data, 0x3C)[0]
if data[offset:offset + 4] != b"PE\0\0":
    sys.exit("not a PE file: " + sys.argv[1])
machine = struct.unpack_from("<H", data, offset + 4)[0]
print({0x8664: "x64", 0x14C: "x32"}.get(machine) or sys.exit(f"unsupported PE machine 0x{machine:x}"))
PY
}

prefix() {
  local uid runtime
  uid=$(id -u)
  if [ "$(stat -c %u "$base")" = "$uid" ] && [ -w "$base" ]; then echo "$base"; return; fi
  runtime=${X64DBG_RUNTIME_DIR:-}
  if [ -z "$runtime" ]; then
    if [ -d /scratch ] && [ -w /scratch ]; then runtime=/scratch/.x64dbg-runtime
    else runtime=${TMPDIR:-/tmp}/x64dbg-runtime-$uid; fi
  fi
  if [ ! -f "$runtime/wine-prefix/system.reg" ]; then
    mkdir -p "$runtime"
    rm -rf "$runtime/wine-prefix.part"
    cp -R --preserve=mode,timestamps,links "$base" "$runtime/wine-prefix.part"
    mv "$runtime/wine-prefix.part" "$runtime/wine-prefix"
  fi
  echo "$runtime/wine-prefix"
}

name=$(basename "$0")
case "$name" in
  x64dbg) arch=x64 ;;
  x32dbg) arch=x32 ;;
  *) arch=x96 ;;
esac
mode=headless
case "${1:-}" in
  --version) cat "$home/VERSION"; exit 0 ;;
  --which) pe_arch "${2:?usage: $name --which PE-FILE}"; exit 0 ;;
  --gui) mode=gui; shift ;;
  --prepare) mode=prepare; shift ;;
  -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

WINEPREFIX=$(prefix)
export WINEPREFIX
case "$mode" in
  prepare)
    timeout "${X64DBG_PREPARE_SECONDS:-120}" xvfb-run -a wine wineboot >/dev/null
    wineserver -w
    echo "$WINEPREFIX" ;;
  gui)
    case "$arch" in
      x96) exe=$home/release/x96dbg.exe ;;
      *) exe=$home/release/$arch/${arch}dbg.exe ;;
    esac
    exec xvfb-run -a -s "-screen 0 1280x1024x24" wine "$exe" "$@" ;;
  headless)
    if [ "$arch" = x96 ]; then
      arch=x64
      if [ $# -gt 0 ]; then arch=$(pe_arch "$1"); shift; fi
    fi
    exec wine "$home/release/$arch/headless.exe" -userdir "C:\\x64dbg-user\\$arch" "$@" ;;
esac
X64DBG_WRAPPER
RUN chmod 0755 /usr/local/bin/x64dbg-wine \
    && for name in x96dbg x64dbg x32dbg; do ln -sfn x64dbg-wine "/usr/local/bin/$name"; done
ENV WINEPREFIX=/opt/wine-prefix \
    WINEARCH=win64 \
    WINEDEBUG=-all \
    WINEDLLOVERRIDES="mscoree,mshtml=;msvcp140,vcruntime140,vcruntime140_1=n,b"
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

# --- Non-root worker user, fixed mount points ----------------------------------
# /workspace : vendor source, read-only
# /msvc      : MSVC CRT + Windows SDK (licensed input), read-only  (ADR-0003)
# /scratch   : the only writable path; orchestrator imports from here
RUN useradd -m -u 10001 -s /bin/bash worker \
    && mkdir -p /workspace /msvc /scratch /opt/wine-prefix \
    && chown worker:worker /scratch /opt/wine-prefix

# --- Wine prefix, created at build time by the worker user --------------------------
# Read-only at run time; the wrapper copies it once per uid to a writable directory. wineboot copies
# every builtin DLL into the prefix (~1.2 GB for Wine 9); identical files become symlinks to Wine's
# own copies so neither the layer nor the per-uid copy duplicates them.
USER worker
RUN xvfb-run -a wine wineboot --init \
    && wineserver -w \
    && mkdir -p /opt/wine-prefix/drive_c/x64dbg-user/x64 /opt/wine-prefix/drive_c/x64dbg-user/x32 \
    && test -f /opt/wine-prefix/system.reg \
    && find /opt/wine-prefix/drive_c/windows -type f | while read -r f; do \
         case "$f" in \
           */syswow64/*) libs="/usr/lib/i386-linux-gnu/wine/i386-windows /usr/lib/wine/i386-windows" ;; \
           *) libs="/usr/lib/x86_64-linux-gnu/wine/x86_64-windows /usr/lib/wine/x86_64-windows" ;; \
         esac; \
         for lib in $libs; do \
           if [ -f "$lib/${f##*/}" ] && cmp -s "$f" "$lib/${f##*/}"; then ln -sf "$lib/${f##*/}" "$f"; break; fi; \
         done; \
       done \
    && du -sh /opt/wine-prefix \
    && chmod -R a+rX /opt/wine-prefix
USER root
# --- This image's scripts (edited often: kept LAST so only these layers rebuild) ------------------------------------------------------
COPY scripts/ /opt/scripts/
RUN find /opt/scripts -type f \( -name '*.py' -o -name '*.sh' \) -print0 \
      | xargs -0 sed -i 's/\r$//' \
    && chmod +x /opt/scripts/*.py /opt/scripts/*.sh

USER worker
WORKDIR /scratch

# No ENTRYPOINT/CMD by design — the orchestrator runs one script per step as
# a static argv array (ADR-0002). Every runnable step is under /opt/scripts.
CMD ["/bin/bash"]
