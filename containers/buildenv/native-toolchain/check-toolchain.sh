#!/bin/sh
# Assert the compiler identity promised by packages.lock. Every consumer image runs this at
# build time, so a family image cannot silently compile C/C++ with a different toolchain.
set -eu
expect() {
  expected=$1
  shift
  output=$("$@" 2>&1 | head -n 1)
  case "$output" in
    *"$expected"*) printf '%s: %s\n' "$1" "$output" ;;
    *) printf 'toolchain identity mismatch for %s: %s (expected %s)\n' "$1" "$output" "$expected" >&2
       exit 1 ;;
  esac
}
expect "13.3.0" gcc --version
expect "13.3.0" g++ --version
expect "13.3.0" cc --version
expect "13.3.0" c++ --version
expect "18.1.3" clang --version
expect "LLD 18.1.3" wasm-ld --version
expect "18.1.3" /usr/bin/llvm-dwarfdump-18 --version
expect "18.1.3" /usr/bin/llvm-pdbutil-18 --version
# clang can link the address and undefined-behaviour sanitizer runtimes (libclang-rt-18-dev); gcc ships its own.
for runtime in libclang_rt.asan-x86_64.a libclang_rt.ubsan_standalone-x86_64.a; do
  path=$(clang -print-file-name="$runtime")
  [ -f "$path" ] || { printf 'clang sanitizer runtime %s is missing\n' "$runtime" >&2; exit 1; }
done
expect "GNU Make 4.3" make --version
expect "1.8.1" pkg-config --version
expect "Python 3.12.3" python3 --version
expect "strace -- version 6.8" strace -V
