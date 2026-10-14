# Clang static-analysis tool image

This offline image adds hash-locked `clang-tidy-18` packages and the repository-owned bounded
adapter to the pinned LLVM 18 toolchain in `appsec-review/tool-native-cpp:1.0.0`. The catalog
builder verifies every package's exact byte size and SHA-256 before the network-disabled build.
It runs Clang-Tidy and `clang --analyze` only over an
orchestrator-produced compilation database. The target mount is read-only, the scratch mount is
writable, and target binaries are never executed.

The central container catalog owns the image entry. Build, smoke, and security acceptance use the
normal catalog-driven commands after that entry is installed.
