# Deferred build environments

The former language images are deliberately not enabled. Each replacement must be a language-only
toolchain with separate, typed profiles for networked dependency resolution and offline analysis.
It must not inherit the archived native-analysis omnibus or duplicate MCP/LSP payloads.

Tracked catalog entries cover C/C++ (including the former resolute variant), .NET, Go, Java, PHP,
Python, Rust, and TypeScript. Enable a language only after its base and package closure are immutable,
all release assets are authenticated, its supported compiler/runtime range is documented, and tests
prove both profiles, non-root startup, and the standard runtime boundary.
