# Deferred native-analysis capabilities

The archived native and CodeQL images are decomposed here conceptually, not copied. Planned bounded
capabilities are: compiler tracing, CodeQL database creation/query, and language-server extraction.
Each capability needs its own output schema, failure contract, immutable tool closure, and fixture.
The catalog keeps `audit-native`, `audit-codeql`, `audit-codeql-native`, and `audit-lsp-vendor`
visible until those criteria are met.
