---
id: wasm
version: 1
covers: []
standards: ["cwe", "cert-c"]
max_tokens: 1500
---
## Runtime and framework model
Code compiled to WebAssembly from C/C++ (Emscripten, wasi-sdk), Rust (`wasm-bindgen`,
`wasm32-wasi`), Go, AssemblyScript, or others, running in a browser, Node.js, a WASI runtime
(Wasmtime, Wasmer, WasmEdge), a plugin host, a proxy filter (Envoy proxy-wasm), or a smart
contract or edge platform. A module has one linear memory with no guard pages inside it, no ASLR,
and no stack canaries by default; control-flow is structured, so classic code injection is
replaced by data corruption inside the sandbox.

## Trust and interface layer
- Two directions of trust: the host passes untrusted data into the module through exports, and
  the module calls host imports that carry the host's authority (filesystem preopens, network,
  DOM, JavaScript glue).
- In browsers, the JavaScript glue (`*.js` emitted by Emscripten or wasm-bindgen) is part of the
  attack surface: strings and buffers cross by pointer and length.
- In plugin hosts, the module itself may be the untrusted party and the host must bound it.
- Proxy and edge filters see every request and response passing through the host, so a
  module defect affects all traffic, not only its own route.

## Idiomatic security mechanisms
- Source-language safety (safe Rust, bounds-checked containers) carried into the module.
- WASI capability model: only preopened directories and granted sockets are reachable.
- Host-side limits: fuel or epoch interruption (Wasmtime), memory maximums, table limits,
  stack size limits, timeouts on calls.
- Validation of pointer and length pairs at the host-import boundary against current memory size.

## Stack-specific pitfalls
- C/C++ memory bugs still corrupt linear memory: overwritten function-pointer table indices,
  heap metadata, or adjacent objects change program behaviour without a crash, since there is no
  unmapped memory to fault on.
- Stack and heap share linear memory; stack overflow silently overwrites the heap or data section.
- Host imports trusting module-provided offsets (`memory.buffer.slice(ptr, ptr + len)` without
  bounds), or exposing `eval`-like JavaScript functions to the module.
- Overly broad WASI preopens (`/`, home directories) or inherited environment variables.
- Unbounded execution or memory growth in plugin hosts (denial of service).
- Emscripten builds with `-sASSERTIONS=0` and no `SAFE_HEAP`, or exported internal functions.
- Secrets compiled into modules shipped to browsers (fully readable).

## Build and deployment facts to check
- Toolchain and flags: Emscripten settings (`-sALLOW_MEMORY_GROWTH`, `-sMAXIMUM_MEMORY`,
  `-sEXPORTED_FUNCTIONS`), Rust target and `panic` strategy, optimization level.
- Host runtime configuration: preopens, environment, network permissions, resource limits.
- Which exports are reachable by untrusted callers and which imports grant authority.
- Runtime version against advisories for JIT or sandbox escape issues.
