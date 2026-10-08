# Native-analysis capabilities

The archived native and CodeQL images are decomposed here conceptually, not copied. Planned bounded
capabilities are: compiler tracing, CodeQL database creation/query, and language-server extraction.
Each capability needs its own output schema, failure contract, immutable tool closure, and fixture.
The catalog keeps `audit-native`, `audit-codeql`, `audit-codeql-native`, and `audit-lsp-vendor`
visible until those criteria are met.

`containers/tools/native-cpp/` now supplies the narrow build, Clang AST, LLVM IR, and ELF/symbol
capability used by `job_cpp_compiled_analysis`. CodeQL and Joern remain separate blocked producer
contracts: they are not folded into this image and will not be enabled without independent
license/provenance, offline asset, security, and functional acceptance.
