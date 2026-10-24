---
id: memory_safety_native
version: 1
covers: ["cwe:119", "cwe:120", "cwe:121", "cwe:122", "cwe:125", "cwe:131", "cwe:134", "cwe:190", "cwe:191", "cwe:362", "cwe:401", "cwe:415", "cwe:416", "cwe:457", "cwe:476", "cwe:681", "cwe:704", "cwe:758", "cwe:787", "cwe:805", "cwe:843", "cwe:908", "func:exec:unmanaged-memory", "func:exec:ffi", "func:exec:concurrency", "cert-c:*", "cert-cpp:*"]
standards: ["cwe", "cert-c", "cert-cpp", "misra-c2012", "misra-cpp2023", "capec", "attack", "asvs5"]
max_tokens: 1500
---
## Viewpoint
A native-code exploit developer. Memory is bytes with lifetimes; every length, index, and pointer
derived from input is a write primitive until arithmetic proves otherwise. Undefined behaviour is
not "probably fine": compilers delete checks that depend on it.

## Coverage
GENERATED

## Likely failure modes
- Length taken from the wire (`hdr->len`, TLV size, varint) used in `memcpy`, `read`, or array
  indexing without comparison against the destination capacity, or compared against the source.
- Size arithmetic that wraps before allocation: `malloc(n * sizeof(T))`, `count + 1`, 32-bit
  `int`/`size_t` truncation, signed length passed to an unsigned parameter, `new T[n]` in old ABIs.
- Off-by-one on terminators: `strncpy` without NUL, `buf[sizeof buf]`, `snprintf` return value used
  as the written length after truncation.
- Format string from input (`printf(user)`, `syslog(LOG_ERR, msg)`).
- Lifetime: pointer or `string_view`/`span` kept after `free`, `realloc`, container growth,
  `std::move`, or scope exit; iterator invalidation in a loop that erases; double free on an error
  path; callback captures `this` or a reference to a stack object and fires later.
- Type confusion: `reinterpret_cast`/union punning on a tag from input, `static_cast` down a
  hierarchy without checking the dynamic type, variant index trusted from the message.
- Uninitialized reads: struct padding copied to the peer, stack buffer partially filled, missing
  `= {}` before a conditional fill.
- Races: unsynchronized shared counters or refcounts, check-then-use across threads, signal
  handlers calling non-async-signal-safe functions.
- FFI: JNI/ctypes/cgo/N-API/Rust `unsafe` boundary passing a length and pointer that disagree,
  borrowed buffers retained past the call, missing `GetArrayLength` checks.

## Effective controls
- A bound check that compares the exact value used at the sink against the real capacity, on every
  path, before the write: `if (len > sizeof(dst) - off) return ERR;` with `off <= sizeof(dst)`
  already established.
- Overflow-checked arithmetic: `__builtin_mul_overflow`, `SIZE_MAX / n` guards, `calloc`,
  `std::vector::at` or checked spans, `reallocarray`.
- Ownership by type: `std::unique_ptr`, RAII guards, `shared_ptr`/`weak_ptr` locks in async
  callbacks, `absl::Span` with an owning buffer that outlives it.
- Hardening facts that reduce exploitability without fixing the defect: `_FORTIFY_SOURCE=3`,
  `-fstack-protector-strong`, CFI, ASLR/PIE, `-ftrivial-auto-var-init=zero`, hardened allocators.

## False positives
- `memcpy` whose constant length fits both live objects, or whose `sizeof` refers to the actual
  destination array rather than a pointer, with sufficient readable source bytes.
- Lengths already clamped by a framing layer that rejects larger frames before this code runs.
- Sanitizer reports from test harnesses that feed impossible states through private APIs.
- `strcpy` from string literals; `alloca` with a constant small size.
- Integer "overflow" in unsigned arithmetic that is intended modular (hashes, checksums, ring
  indices masked by a power of two).

## Evidence by predicate
- `affected_construct`: the exact copy, index, free, cast, or arithmetic expression and the
  declaration of the buffer or object it touches.
- `attacker_input_control`: the read or parse call that fills the length, index, or tag, and its
  connection to a network, file, IPC, or argument entry point.
- `source_to_sink_reachability`: the call chain from that entry to the sink, including dispatch
  tables, virtual calls, or callbacks registered for the message type.
- `missing_or_ineffective_guard`: the absent comparison, a check against the wrong variable, a
  check after the use, or arithmetic that wraps inside the check itself.
- `configuration_enables`: build flags, feature macros, or runtime options that compile the path in
  or disable fortification; allocator or protocol-version selection.
- `security_impact`: the resulting primitive (out-of-bounds write, controlled free, info leak of
  heap pointers, crash of a shared service) and what process privilege it runs with.

## Hand-offs
Parser logic and decompression bombs go to `parsing_deserialization`. Command or loader-path
injection goes to `injection_interpreters`. File races on paths go to `filesystem_resources`.
Unbounded allocation driven by request volume goes to `filesystem_resources`.
