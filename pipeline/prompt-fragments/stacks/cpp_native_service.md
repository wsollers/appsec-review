---
id: cpp_native_service
version: 1
covers: []
standards: ["cwe", "cert-c", "cert-cpp", "asvs5"]
max_tokens: 1500
---
## Runtime and framework model
A C or C++ server, daemon, or library without an IDL-defined RPC layer: raw sockets with
`epoll`/`kqueue`/IOCP, Boost.Asio, libuv, libevent, an embedded HTTP server (cpp-httplib, Crow,
Pistache, civetweb, Drogon), or a library consumed by other programs. Memory is manually or
RAII-managed; there is no runtime bounds checking. Threads, event loops, and callbacks share state.

## Trust and interface layer
- Entry points: `recv`/`read` on accepted sockets, HTTP route handlers, file and config parsers,
  command-line arguments, environment variables, shared memory, and exported library functions
  whose callers may pass hostile data.
- Custom framing (length prefixes, TLV, delimiter scanning) is the first parser and often the first
  defect.
- Privilege: daemons may start as root to bind ports and are expected to drop privileges with
  `setgroups`, `setgid`, `setuid` in that order.

## Idiomatic security mechanisms
- `std::vector`, `std::string`, `std::span` with `.at()` or explicit size checks; `std::unique_ptr`
  and `std::shared_ptr` for ownership; `std::array` instead of C arrays.
- Checked arithmetic (`__builtin_add_overflow`, `SafeInt`, `absl` numeric helpers).
- `snprintf` with return-value handling; `strlcpy` where available.
- Compiler and linker hardening: `-D_FORTIFY_SOURCE=3`, `-fstack-protector-strong`, `-fPIE -pie`,
  `-Wl,-z,relro,-z,now`, `-fstack-clash-protection`, `-fcf-protection`.
- seccomp, `pledge`/`unveil`, capabilities (`CAP_NET_BIND_SERVICE`) instead of root.

## Stack-specific pitfalls
- Asio handlers capturing raw `this` or buffers on the stack while an async operation is pending;
  missing `shared_from_this()`.
- `std::string_view` or `const char*` from a temporary (`get().c_str()`), returned references to
  locals, iterators held across `push_back`.
- Exceptions thrown through C callbacks or across threads; error paths that leak or double-free.
- `signal` handlers calling `malloc`, logging, or locks.
- `setuid` return values unchecked; supplementary groups not cleared.
- `getenv` values copied into fixed buffers; `sprintf` into stack arrays.
- Library APIs that document "caller must ensure len is valid" while being called with network
  lengths.
- Hand-rolled HTTP parsing: header lines scanned with `strchr` past the buffer end, chunked
  lengths parsed with `strtol` without overflow and sign checks, `Content-Length` trusted for
  allocation.

## Build and deployment facts to check
- Release build flags, warnings-as-errors, and whether sanitizers or fuzzing targets exist.
- CMake or Meson options that compile optional protocol handlers or debug listeners.
- Linked library versions (OpenSSL, zlib, libxml2, libcurl) and whether they are vendored copies.
- The user and capabilities the service runs with (systemd unit, container `USER`).
- Listening addresses and whether the service sits behind a proxy that bounds requests.
