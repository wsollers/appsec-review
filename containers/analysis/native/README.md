---
title: "Native-analysis capabilities"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: ["job_cpp_compiled_analysis"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Native-analysis capabilities

The archived native and CodeQL images are not copied. Compiler tracing, CodeQL database
creation/query and clangd indexing now have separate implementations and contracts.
The catalog retains `audit-native`, `audit-codeql` and `audit-lsp-vendor` as deferred legacy entries;
`audit-codeql-native` is marked replaced. These legacy dispositions do not disable the current
implementations listed in the [generated tool matrix](../../../docs/generated/matrix-tool-bucket.md).

`containers/tools/native-cpp/` now supplies the narrow build, Clang AST, LLVM IR, and ELF/symbol
capability used by `job_cpp_compiled_analysis`. `containers/tools/infer/` separately supplies the
pinned Infer C/C++ analyzer used by that job's `infer` branch; its findings and capture coverage are
published as run-owned evidence. CodeQL, clangd-indexer, and Joern are separate tool images and
separate jobs (`containers/tools/{codeql,clangd-indexer,joern}/`); they are not folded into either
image.
