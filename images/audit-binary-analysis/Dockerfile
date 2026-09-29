# syntax=docker/dockerfile:1
FROM fkiecad/cwe_checker:latest AS cwe-checker

FROM debian:bookworm-slim

ARG NODE_MAJOR=22
ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_BUILD=20260817
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54
ARG RETDEC_VERSION=5.0
ARG RETDEC_URL=https://github.com/avast/retdec/releases/download/v${RETDEC_VERSION}/RetDec-v${RETDEC_VERSION}-Linux-Release.tar.xz
ARG FLOSS_VERSION=3.1.1
ARG FLOSS_URL=https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-linux.zip
ARG DIE_VERSION=3.21
ARG DIE_DEB_URL=https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Debian_12_amd64.deb
ARG JADX_VERSION=1.5.6
ARG JADX_URL=https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip
# Temurin 21.0.12+8; sha256 matches Adoptium's published .sha256.txt for this asset.
ARG JAVA_DOWNLOAD_URL=https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12%2B8/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12_8.tar.gz
ARG JAVA_SHA256=e4446ff06a276155697597cc0f1b15da004ff083f4964a35271ecee567177370
# x64dbg under Wine (Debian bookworm wine 8.0; wine32:i386 for the PE32 x96dbg/x32dbg).
ARG WINE_VERSION=8.0~repack-4
ARG WINE_EXTRA_PACKAGES=
ARG X64DBG_TAG=2026.05.27
ARG X64DBG_SNAPSHOT=snapshot_2026-05-27_12-11
ARG X64DBG_SHA256=d41966dfc5b435a372798245300ca0ab7bb8e48bdbf48512c6fb20fcca427697
ENV JAVA_HOME="/opt/java"
ENV GHIDRA_HOME="/opt/ghidra"
ENV RETDEC_HOME="/opt/retdec"
ENV DOTNET_ROOT="/opt/dotnet"
ENV PATH="/opt/binary-analysis-venv/bin:/opt/retdec:/opt/ghidra:/opt/java/bin:/opt/dotnet:/usr/local/bin:/usr/bin:/bin"

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl git jq ripgrep gnupg passwd \
      build-essential cmake ninja-build pkg-config \
      python3 python3-pip python3-venv \
      file binutils elfutils dwarfdump dwarves pax-utils \
      gdb gdbserver lldb llvm clang valgrind rr \
      strace ltrace procps \
      exiftool unzip zip tar \
      binwalk checksec yara ssdeep tlsh-tools qemu-user-static apktool \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ghidra / ghidra-analyzeHeadless are wrappers, not symlinks: they set user.home from $HOME, because
# the boundary runs as the host uid (no passwd entry) and Ghidra saves its settings under user.home.
RUN curl -fsSL "$JAVA_DOWNLOAD_URL" -o /tmp/jdk.tar.gz \
    && echo "$JAVA_SHA256  /tmp/jdk.tar.gz" | sha256sum -c - \
    && mkdir -p "$JAVA_HOME" \
    && tar -xzf /tmp/jdk.tar.gz -C "$JAVA_HOME" --strip-components=1 \
    && rm /tmp/jdk.tar.gz \
    && curl -fsSL "$GHIDRA_URL" -o /tmp/ghidra.zip \
    && echo "$GHIDRA_SHA256  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && ln -sfn "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" "$GHIDRA_HOME" \
    && curl -fsSL "$RETDEC_URL" -o /tmp/retdec.tar.xz \
    && mkdir -p "$RETDEC_HOME" \
    && tar -xJf /tmp/retdec.tar.xz -C "$RETDEC_HOME" --strip-components=1 \
    && rm /tmp/retdec.tar.xz \
    && ln -sfn "$JAVA_HOME/bin/java" /usr/local/bin/java \
    && ln -sfn "$JAVA_HOME/bin/javac" /usr/local/bin/javac \
    && for pair in ghidra:ghidraRun ghidra-analyzeHeadless:support/analyzeHeadless; do \
         printf '#!/bin/sh\n%s\nexec /opt/ghidra/%s "$@"\n' \
           'export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Duser.home=${HOME:-/tmp}"' \
           "${pair#*:}" > "/usr/local/bin/${pair%%:*}"; \
         chmod 0755 "/usr/local/bin/${pair%%:*}"; \
       done \
    && ln -sfn "$RETDEC_HOME/retdec-fileinfo" /usr/local/bin/retdec-fileinfo \
    && ln -sfn "$RETDEC_HOME/retdec-decompiler" /usr/local/bin/retdec-decompiler \
    && curl -fsSL "$FLOSS_URL" -o /tmp/floss.zip \
    && mkdir -p /opt/floss \
    && unzip -q /tmp/floss.zip -d /opt/floss \
    && rm /tmp/floss.zip \
    && find /opt/floss -type f -name floss -exec ln -sfn {} /usr/local/bin/floss \; \
    && curl -fsSL "$DIE_DEB_URL" -o /tmp/die.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends /tmp/die.deb \
    && rm /tmp/die.deb \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "$JADX_URL" -o /tmp/jadx.zip \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && ln -sfn /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && ln -sfn /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui \
    && curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel 10.0 --install-dir "$DOTNET_ROOT" \
    && rm /tmp/dotnet-install.sh \
    && dotnet tool install ilspycmd --tool-path /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# --- Wine + Xvfb, then x64dbg (x96dbg launcher, x64dbg, x32dbg) ------------------
# x64dbg is a Windows debugger; it runs here only under Wine. wine32:i386 (multiarch) is required:
# x96dbg.exe and x32dbg.exe are PE32. Mono and Gecko are never installed (WINEDLLOVERRIDES), and the
# MSVC runtime DLLs shipped with x64dbg load before Wine's builtins.
# WINE_EXTRA_PACKAGES (per image) names the real ALSA library where a provider of the virtual
# libasound2 that conflicts with wine32:i386 may already be installed; java -version proves
# no JDK was removed to make room.
RUN dpkg --add-architecture i386 \
    && apt-get update && apt-get install -y --no-install-recommends \
       "wine=${WINE_VERSION}" "wine64=${WINE_VERSION}" "wine32:i386=${WINE_VERSION}" xvfb xauth \
       ${WINE_EXTRA_PACKAGES} \
    && rm -rf /var/lib/apt/lists/* \
    && wine --version \
    && java -version
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
COPY --from=cwe-checker /home/cwe/cwe_checker /usr/local/bin/cwe_checker
COPY --from=cwe-checker /home/cwe/.config/cwe_checker /opt/cwe_checker_config

RUN python3 -m venv /opt/binary-analysis-venv \
    && /opt/binary-analysis-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/binary-analysis-venv/bin/pip install --no-cache-dir \
      angr \
      capstone \
      flare-capa \
      frida-tools \
      lief \
      networkx \
      pefile \
      pyelftools \
    && npm install -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory \
    && chmod +x /usr/local/bin/cwe_checker \
    && ln -sfn /usr/local/bin/cwe_checker /usr/local/bin/check_cwe \
    && ln -sfn /opt/binary-analysis-venv/bin/frida /usr/local/bin/frida \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-ps /usr/local/bin/frida-ps \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-trace /usr/local/bin/frida-trace \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-discover /usr/local/bin/frida-discover \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-itrace /usr/local/bin/frida-itrace \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-apk /usr/local/bin/frida-apk \
    && /usr/sbin/useradd -m -u 10001 -s /bin/bash worker \
    && mkdir -p /home/worker/.config \
    && cp -R /opt/cwe_checker_config /home/worker/.config/cwe_checker \
    && mkdir -p /workspace /scratch /opt/wine-prefix \
    && chown -R worker:worker /home/worker/.config /scratch /opt/wine-prefix

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

# --- Repo-owned scripts, kept LAST so editing them rebuilds only these layers.
COPY scripts/analyze-binary.sh /usr/local/bin/analyze-binary
COPY scripts/binary-summary.py /usr/local/bin/binary-summary
COPY scripts/angr-summary.py /usr/local/bin/angr-summary
RUN chmod +x /usr/local/bin/analyze-binary /usr/local/bin/binary-summary /usr/local/bin/angr-summary

USER worker
WORKDIR /scratch
CMD ["/bin/bash"]
