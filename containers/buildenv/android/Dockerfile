# syntax=docker/dockerfile:1
FROM eclipse-temurin:17-jdk-noble@sha256:e1c09a9ee23feb81f94016547826c1e694086cd927356fb57fccc312fcc32f85
LABEL org.opencontainers.image.title="audit-buildenv-android" \
      org.opencontainers.image.version="jdk17-gradle8.9-android35"
USER 0:0
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash=5.2.21-2ubuntu4 ca-certificates=20260601~24.04.1 \
      coreutils=9.4-3ubuntu6.3 findutils=4.9.0-5build1 grep=3.11-4build1 \
      libc6=2.39-0ubuntu8.9 libgcc-s1=14.2.0-4ubuntu2~24.04.1 \
      libstdc++6=14.2.0-4ubuntu2~24.04.1 python3=3.12.3-0ubuntu2.1 \
      sed=4.9-2ubuntu0.24.04.1 strace=6.8-0ubuntu2 unzip=6.0-28ubuntu4.1 \
      zip=3.0-13ubuntu0.2 zlib1g=1:1.3.dfsg-3.1ubuntu2.2 \
 && rm -rf /var/lib/apt/lists/*
COPY downloads/ /tmp/android-assets/
RUN printf '%s  %s\n' \
      d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab /tmp/android-assets/gradle-8.9-bin.zip \
      4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583 /tmp/android-assets/commandlinetools-linux-15859902_latest.zip \
      0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0 /tmp/android-assets/platform-35_r02.zip \
      bd3a4966912eb8b30ed0d00b0cda6b6543b949d5ffe00bea54c04c81e1561d88 /tmp/android-assets/build-tools_r35_linux.zip \
      d230f13842f60f782a8645f9c813f8f845bf36089ea7289f28c48f17979313f1 /tmp/android-assets/platform-tools_r37.0.1-linux.zip \
    | sha256sum -c - \
 && mkdir -p /opt/gradle /opt/android-sdk/cmdline-tools /opt/android-sdk/platforms \
      /opt/android-sdk/build-tools /opt/android-sdk/licenses \
 && unzip -q /tmp/android-assets/gradle-8.9-bin.zip -d /opt/gradle \
 && unzip -q /tmp/android-assets/commandlinetools-linux-15859902_latest.zip -d /tmp/cmdline \
 && mv /tmp/cmdline/cmdline-tools /opt/android-sdk/cmdline-tools/15859902 \
 && unzip -q /tmp/android-assets/platform-35_r02.zip -d /opt/android-sdk/platforms \
 && unzip -q /tmp/android-assets/build-tools_r35_linux.zip -d /opt/android-sdk/build-tools \
 && mv /opt/android-sdk/build-tools/android-15 /opt/android-sdk/build-tools/35.0.0 \
 && unzip -q /tmp/android-assets/platform-tools_r37.0.1-linux.zip -d /opt/android-sdk \
 && printf '%s\n' 24333f8a63b6825ea9c5514f83c2829b004d1fee \
      8933bad161af4178b1185d1a37fbf41ea5269c55 d56f5187479451eabf01fb78af6dfcb131a6481e \
      > /opt/android-sdk/licenses/android-sdk-license \
 && rm -rf /tmp/android-assets /tmp/cmdline \
 && groupadd -g 10001 worker \
 && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
 && mkdir -p /workspace /scratch /capture /opt/gradle-user-home /opt/project-deps \
 && chown -R 10001:10001 /workspace /scratch /capture /opt/gradle-user-home /opt/project-deps
ENV JAVA_HOME=/opt/java/openjdk \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    GRADLE_HOME=/opt/gradle/gradle-8.9 \
    GRADLE_USER_HOME=/opt/gradle-user-home \
    HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    PATH=/opt/gradle/gradle-8.9/bin:/opt/android-sdk/cmdline-tools/15859902/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/build-tools/35.0.0:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
