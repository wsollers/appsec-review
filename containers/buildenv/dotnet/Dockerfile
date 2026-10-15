# syntax=docker/dockerfile:1
# .NET build and capture environment. It carries only the language toolchain: target NuGet
# dependencies are restored into derived project images, and language servers are not part of
# this image. Both current LTS SDKs come from version-pinned Ubuntu packages. The source-built
# 10.0 SDK resolves the portable linux-x64 apphost pack for net8.0 targets, which Ubuntu does not
# ship, so that pack is installed from its hash-locked NuGet archive. net8.0 and net10.0 console
# projects therefore build without any NuGet download.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
LABEL org.opencontainers.image.title="audit-buildenv-dotnet" \
      org.opencontainers.image.version="sdk8.0.131-sdk10.0.112-apphost8.0.31"
USER 0:0
# python3 runs the build-capture tool wrapper; strace is the ptrace capture backend.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash=5.2.21-2ubuntu4 ca-certificates=20260601~24.04.1 \
      coreutils=9.4-3ubuntu6.3 findutils=4.9.0-5build1 grep=3.11-4build1 \
      dotnet-sdk-8.0=8.0.131-0ubuntu1~24.04.1 dotnet-sdk-10.0=10.0.112-0ubuntu1~24.04.1 \
      python3=3.12.3-0ubuntu2.1 sed=4.9-2ubuntu0.24.04.1 strace=6.8-0ubuntu2 \
      unzip=6.0-28ubuntu4.1 \
 && rm -rf /var/lib/apt/lists/* \
 && test -d /usr/lib/dotnet/packs/Microsoft.NETCore.App.Ref/8.0.31
COPY downloads/ /tmp/dotnet-assets/
RUN printf '%s  %s\n' \
      3061fc6678cce1f645a7ade66cb3699288c8d93ed3be9bcd82fa633867eb4c81 /tmp/dotnet-assets/microsoft.netcore.app.host.linux-x64.8.0.31.nupkg \
    | sha256sum -c - \
 && mkdir -p /usr/lib/dotnet/packs/Microsoft.NETCore.App.Host.linux-x64/8.0.31 \
 && unzip -q /tmp/dotnet-assets/microsoft.netcore.app.host.linux-x64.8.0.31.nupkg \
      'runtimes/*' Microsoft.NETCore.App.versions.txt LICENSE.TXT THIRD-PARTY-NOTICES.TXT \
      -d /usr/lib/dotnet/packs/Microsoft.NETCore.App.Host.linux-x64/8.0.31 \
 && chmod -R a+rX /usr/lib/dotnet/packs/Microsoft.NETCore.App.Host.linux-x64 \
 && rm -rf /tmp/dotnet-assets \
 && groupadd -g 10001 worker \
 && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
 && mkdir -p /workspace /scratch /capture /opt/project-deps \
 && chown -R 10001:10001 /workspace /scratch /capture /opt/project-deps
# NuGet vulnerability auditing fetches advisory data during restore. It is not build provenance
# (dependency intelligence owns advisories), and an unreachable advisory feed must not fail an
# otherwise offline restore, so the image disables it as an MSBuild environment property.
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true \
    NuGetAudit=false \
    HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
