# syntax=docker/dockerfile:1
# SVF-3.3 points-to producer. Every input comes from the hash-locked downloads cache
# (assets.lock.json, acquire_assets.sh); the build installs nothing from the network.
#
# The build stage compiles SVF and the repository-owned driver with the image's clang-18 against the
# RTTI LLVM 21.1.0 distribution SVF-3.3 requires. The runtime stage is tool-native-cpp, so target
# bitcode is still produced by clang-18, the compiler of record; LLVM 21 only links and reads it.
FROM appsec-review/tool-native-cpp:1.0.0 AS build
USER 0
ARG DEBIAN_FRONTEND=noninteractive
COPY downloads/svf-build-debs.tar /tmp/svf-build-debs.tar
RUN mkdir /tmp/debs \
    && tar -xf /tmp/svf-build-debs.tar -C /tmp/debs \
    && dpkg --install /tmp/debs/*.deb \
    && rm -rf /tmp/debs /tmp/svf-build-debs.tar /var/lib/apt/lists/*
COPY downloads/SVF-3.3.tar.gz downloads/llvm-21.1.0-ubuntu22-rtti-x86-64.tar.gz downloads/z3-4.8.8-x64-ubuntu-16.04.zip /tmp/assets/
RUN mkdir -p /opt/llvm21 /opt/z3 /src/svf \
    && tar -xzf /tmp/assets/llvm-21.1.0-ubuntu22-rtti-x86-64.tar.gz -C /opt/llvm21 --strip-components=1 \
    && python3 -c "import zipfile; zipfile.ZipFile('/tmp/assets/z3-4.8.8-x64-ubuntu-16.04.zip').extractall('/tmp/z3')" \
    && cp -a /tmp/z3/z3-4.8.8-x64-ubuntu-16.04/. /opt/z3/ \
    && tar -xzf /tmp/assets/SVF-3.3.tar.gz -C /src/svf --strip-components=1 \
    && mkdir /src/svf/svf-llvm/tools/AppsecAliasExport \
    && echo 'add_subdirectory(AppsecAliasExport)' >> /src/svf/svf-llvm/tools/CMakeLists.txt \
    && rm -rf /tmp/assets /tmp/z3
ENV LLVM_DIR=/opt/llvm21 Z3_DIR=/opt/z3
# The driver directory starts with the build file only, so SVF itself is compiled and cached before
# the driver source is copied in.
COPY driver/CMakeLists.txt /src/svf/svf-llvm/tools/AppsecAliasExport/CMakeLists.txt
RUN touch /src/svf/svf-llvm/tools/AppsecAliasExport/svf-alias-export.cpp \
    && cmake -S /src/svf -B /src/build -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
        -DBUILD_SHARED_LIBS=OFF -DSVF_WARN_AS_ERROR=OFF -DSVF_ENABLE_ASSERTIONS=OFF \
    && cmake --build /src/build --target SvfLLVM gen_extapi_ir -j"$(nproc)"
COPY driver/svf-alias-export.cpp /src/svf/svf-llvm/tools/AppsecAliasExport/svf-alias-export.cpp
RUN cmake --build /src/build --target svf-alias-export -j"$(nproc)" \
    && mkdir -p /opt/svf/bin /opt/svf/lib \
    && cp /src/build/bin/svf-alias-export /opt/svf/bin/ \
    && cp /opt/llvm21/bin/llvm-link /opt/svf/bin/llvm-link-21 \
    && cp "$(find /src/build -name extapi.bc -print -quit)" /opt/svf/lib/extapi.bc \
    && cp -a /opt/llvm21/lib/libLLVM.so* /opt/z3/bin/libz3.so /opt/svf/lib/ \
    && cp /src/svf/LICENSE.TXT /opt/svf/LICENSE-SVF.TXT \
    && cp /opt/z3/LICENSE.txt /opt/svf/LICENSE-Z3.txt

FROM appsec-review/tool-native-cpp:1.0.0 AS runtime
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-svf" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later AND Apache-2.0 WITH LLVM-exception AND MIT"
USER 0
COPY --from=build /opt/svf /opt/svf
COPY svf.py /opt/appsec/svf.py
ENV LD_LIBRARY_PATH=/opt/svf/lib
RUN chmod 0555 /opt/appsec/svf.py /opt/svf/bin/* \
    && ! ldd /opt/svf/bin/svf-alias-export /opt/svf/bin/llvm-link-21 | grep -F 'not found' \
    && /opt/svf/bin/llvm-link-21 --version | grep -F 'LLVM version 21.1.0' \
    && clang-18 --version | grep -F 'clang version 18' \
    && /opt/appsec/svf.py version | grep -F "appsec-svf ${TOOL_VERSION}"
USER 10001:10001
WORKDIR /scratch
