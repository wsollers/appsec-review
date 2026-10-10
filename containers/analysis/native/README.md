# Native-analysis capabilities

The archived native and CodeQL images are decomposed here conceptually, not copied. Planned bounded
capabilities are: compiler tracing, CodeQL database creation/query, and language-server extraction.
Each capability needs its own output schema, failure contract, immutable tool closure, and fixture.
The catalog keeps `audit-native`, `audit-codeql`, `audit-codeql-native`, and `audit-lsp-vendor`
visible until those criteria are met.

`containers/tools/native-cpp/` now supplies the narrow build, Clang AST, LLVM IR, and ELF/symbol
capability used by `job_cpp_compiled_analysis`. `containers/tools/infer/` separately supplies the
pinned Infer C/C++ analyzer used by that job's `infer` branch; its findings and capture coverage are
published as run-owned evidence. CodeQL, clangd-indexer, and Joern are separate tool images and
separate jobs (`containers/tools/{codeql,clangd-indexer,joern}/`); they are not folded into either
image.
