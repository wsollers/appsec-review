# syntax=docker/dockerfile:1
#
# C/C++ build environment on Ubuntu 26.04 LTS (resolute) for targets whose dependencies are newer
# than 24.04 ships (freeciv21: Qt >= 6.6 and KDE Frameworks 6; resolute has Qt 6.10, KF6 6.24).
# The compiler is the same pinned LLVM 21.1.0 as audit-native / audit-buildenv-cpp, copied from
# audit-native:local, so compile databases, IR capture and the native analyzers stay aligned.
# Sealed like every buildenv: builds add packages in disposable copy-on-write layers on top.
# clangd and tree-sitter: docs/language-servers.md (needs audit-lsp-vendor:local).
FROM audit-native:local AS llvm

FROM ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78
ARG DEBIAN_FRONTEND=noninteractive
COPY --from=llvm /opt/llvm /opt/llvm
# clang 21 was linked on 24.04 against libxml2.so.2 (-> ICU 74); 26.04 ships newer sonames. Carry the
# 24.04 libraries under their own sonames (no clash with 26.04's) for the compiler only.
COPY --from=llvm /usr/lib/x86_64-linux-gnu/libxml2.so.2* /usr/lib/x86_64-linux-gnu/libicuuc.so.74* \
     /usr/lib/x86_64-linux-gnu/libicudata.so.74* /usr/local/lib/llvm-compat/
RUN echo /usr/local/lib/llvm-compat > /etc/ld.so.conf.d/llvm-compat.conf && ldconfig
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git file binutils g++ make cmake ninja-build \
      autoconf automake libtool pkg-config bear python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 -s /bin/bash worker \
    && mkdir -p /scratch && chown worker:worker /scratch \
    && /opt/llvm/bin/clang --version | grep -F 'clang version 21.1.0 ' \
    && printf 'int main(){return 0;}\n' > /tmp/t.cc && /opt/llvm/bin/clang++ /tmp/t.cc -o /tmp/t && /tmp/t \
    && command -v cmake ninja autoconf automake libtoolize make bear pkg-config >/dev/null
# --- clangd 21.1.0 (same release as the compiler) and tree-sitter, from audit-lsp-vendor:local.
RUN --mount=type=bind,from=audit-lsp-vendor:local,source=/opt/lsp-vendor,target=/mnt/lsp-vendor \
    python3 -m venv /opt/clangd \
    && /opt/clangd/bin/pip install --no-cache-dir --no-index --find-links /mnt/lsp-vendor/wheels \
         --require-hashes -r /mnt/lsp-vendor/requirements/clangd.txt \
    && ln -s "$(/opt/clangd/bin/python -c 'import clangd, os; print(os.path.join(os.path.dirname(clangd.__file__), "data", "bin", "clangd"))')" /usr/local/bin/clangd \
    && clangd --version | grep -F "clangd version 21.1.0"
# --- tree-sitter CLI + py-tree-sitter/grammars, vendored in audit-lsp-vendor (docs/language-servers.md §3).
RUN --mount=type=bind,from=audit-lsp-vendor:local,source=/opt/lsp-vendor,target=/mnt/lsp-vendor \
    install -m 0755 /mnt/lsp-vendor/bin/tree-sitter /usr/local/bin/tree-sitter \
    && python3 -m venv /opt/treesitter \
    && /opt/treesitter/bin/pip install --no-cache-dir --no-index --find-links /mnt/lsp-vendor/wheels \
         --require-hashes -r /mnt/lsp-vendor/requirements/treesitter.txt \
    && /opt/treesitter/bin/python -c "import tree_sitter, tree_sitter_c, tree_sitter_python, tree_sitter_php" \
    && tree-sitter --version | grep -F "tree-sitter 0.26.13"
ENV LLVM_DIR=/opt/llvm \
    PATH="/opt/llvm/bin:${PATH}" \
    CC=/opt/llvm/bin/clang \
    CXX=/opt/llvm/bin/clang++
USER worker
WORKDIR /scratch
CMD ["/bin/bash"]
