---
id: rust_service
version: 1
covers: []
standards: ["cwe", "asvs5"]
max_tokens: 1500
---
## Runtime and framework model
A Rust service or library: axum, actix-web, warp, rocket, tonic (gRPC), hyper, on a tokio or
async-std runtime; or a crate exposing a C ABI. Safe Rust prevents memory corruption and data
races; the remaining risk lives in `unsafe` blocks, FFI, logic errors, panics, and resource use.

## Trust and interface layer
- Entry points: router handlers with extractors (`Json<T>`, `Query<T>`, `Path<T>`, `Form<T>`),
  tonic service methods, message consumers, CLI arguments, and `extern "C"` functions called by
  other languages.
- serde derives define what input is accepted; `#[serde(deny_unknown_fields)]` and custom
  deserializers shape validation.
- Authentication is typically a tower `Layer`/middleware or an extractor that returns the user;
  routes merged without that layer skip it.
- `extern "C"` exports receive raw pointers and lengths from foreign callers that Rust
  cannot check; the safety contract is only as good as the caller.

## Idiomatic security mechanisms
- Type-driven validation (newtypes, `TryFrom`), `validator` crate, explicit length limits via
  `DefaultBodyLimit` or `RequestBodyLimitLayer`, `tower::timeout`.
- sqlx/diesel bound parameters and compile-time checked queries.
- `std::process::Command` with argument vectors (no shell).
- `ring`, `rustls`, RustCrypto crates; `subtle::ConstantTimeEq`; `rand::rngs::OsRng`.
- `#![forbid(unsafe_code)]` in crates that need none.

## Stack-specific pitfalls
- `unsafe` blocks that build slices from raw parts with unchecked lengths, `get_unchecked`,
  `transmute`, `set_len` before initialization, or `Send`/`Sync` impls that are unsound.
- FFI boundaries: `CStr::from_ptr` on non-terminated data, lifetimes of buffers passed to C,
  panics unwinding across `extern "C"` (undefined behaviour before `C-unwind`).
- Panics from `unwrap`, `expect`, slice indexing, integer overflow in debug builds, or
  `RefCell` borrows reachable from requests: each one can abort a worker or the process
  (`panic = "abort"`).
- Release builds wrap integer overflow silently; arithmetic on lengths needs `checked_*`.
- `format!` into SQL strings with `sqlx::query(&s)`; `Command::new("sh").arg("-c")`.
- Blocking calls inside async handlers starving the runtime; unbounded channels.
- `serde` with `#[serde(untagged)]` or `flatten` producing surprising acceptance; recursion
  without depth limits in custom formats.
- `Path::join` with an absolute user path replacing the base.

## Build and deployment facts to check
- `Cargo.lock` committed for binaries; resolved crate versions against RustSec advisories.
- Build profile settings: `overflow-checks`, `panic`, `debug-assertions` in release.
- Enabled cargo features that pull in optional unsafe or network code.
- `build.rs` scripts and proc-macro crates that run at build time.
- Count and location of `unsafe` blocks and FFI crates (`-sys` crates, `bindgen` output).
