# syntax=docker/dockerfile:1
# JVM (Java/Kotlin) build and capture environment. It carries only the language toolchain:
# target dependencies are restored into derived project images, and language servers are not
# part of this image. The JDK comes from version-pinned Ubuntu packages; Maven, Gradle and the
# Kotlin compiler come from hash-locked official archives. Maven 3.9 is required for the
# read-only dependency tail (maven.repo.local.tail) that exposes image-restored artifacts to the
# writable per-build local repository.
#
# Tool locations are a contract with appsec-review.toml [jobs.job_language_build.settings.jvm]:
# javac, java, jar, javadoc and kotlinc resolve under /usr/bin, and mvn/gradle resolve on the
# configured "java" system path.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
LABEL org.opencontainers.image.title="audit-buildenv-java" \
      org.opencontainers.image.version="jdk21-maven3.9.9-gradle8.9-kotlin2.0.21"
USER 0:0
# python3 runs the build-capture tool wrapper; strace is the ptrace capture backend.
# Bootstrap HTTPS trust before installing the pinned Ubuntu certificate package.
COPY --from=python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN printf 'APT::Snapshot "20261015T070000Z";\n' > /etc/apt/apt.conf.d/50snapshot \
 && apt-get -o APT::Update::Error-Mode=any update \
 && apt-get install -y --no-install-recommends \
      bash=5.2.21-2ubuntu4 ca-certificates=20260601~24.04.1 \
      coreutils=9.4-3ubuntu6.3 findutils=4.9.0-5build1 grep=3.11-4build1 \
      openjdk-21-jdk-headless=21.0.12.1+1-1~24.04.4 \
      python3=3.12.3-0ubuntu2.1 sed=4.9-2ubuntu0.24.04.1 strace=6.8-0ubuntu2 \
      unzip=6.0-28ubuntu4.1 \
 && rm -rf /var/lib/apt/lists/*
COPY downloads/ /tmp/jvm-assets/
RUN printf '%s  %s\n' \
      d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab /tmp/jvm-assets/gradle-8.9-bin.zip \
      0352c0a45bd22f80f6b26e485cd04da8047baa5de54865281fb9f89a4a7bcf2a /tmp/jvm-assets/kotlin-compiler-2.0.21.zip \
      7a9cdf674fc1703d6382f5f330b3d110ea1b512b51f1652846d9e4e8a588d766 /tmp/jvm-assets/apache-maven-3.9.9-bin.tar.gz \
    | sha256sum -c - \
 && mkdir -p /opt/gradle /opt/kotlin /opt/maven \
 && tar -xzf /tmp/jvm-assets/apache-maven-3.9.9-bin.tar.gz -C /opt/maven --strip-components=1 --no-same-owner \
 && ln -s /opt/maven/bin/mvn /usr/local/bin/mvn \
 && unzip -q /tmp/jvm-assets/gradle-8.9-bin.zip -d /opt/gradle \
 && unzip -q /tmp/jvm-assets/kotlin-compiler-2.0.21.zip -d /opt/kotlin \
 && ln -s /opt/gradle/gradle-8.9/bin/gradle /usr/local/bin/gradle \
 && ln -s /opt/kotlin/kotlinc/bin/kotlinc /usr/bin/kotlinc \
 && ln -s /opt/kotlin/kotlinc/bin/kotlin /usr/bin/kotlin \
 && chmod -R a+rX /opt/gradle /opt/kotlin /opt/maven \
 && rm -rf /tmp/jvm-assets \
 && groupadd -g 10001 worker \
 && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
 && mkdir -p /workspace /scratch /capture /opt/project-deps \
 && chown -R 10001:10001 /workspace /scratch /capture /opt/project-deps
# The build boundary mounts /tmp noexec, so Gradle must not extract and load its native
# integration libraries there.
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
    MAVEN_HOME=/opt/maven \
    GRADLE_OPTS=-Dorg.gradle.native=false \
    HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
