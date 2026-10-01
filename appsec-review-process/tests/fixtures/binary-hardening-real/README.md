# Real binary-hardening tool output (2026-10-01)

Recorded, not written by hand, so the `02-binary-hardening` normalizers are built from what the tools
actually print (continuation prompt 2026-10-01, the `01-component-characterization` lesson).

- `checksec-2.6.0.json`: `checksec --dir=. --output=json` (checksec.sh 2.6.0, the version in
  `audit-binary-analysis`), run over the tree below; keys rewritten from `./<path>` to
  `/workspace/<path>`, as the container prints them. checksec lists ELF files only.
- `blint-3.4.0/<binary_id>-metadata.json`: `blint --no-banner -q --no-error --no-reviews
  --no-wasm-strings -i <view> -o <out>` (blint 3.4.0, LIEF 1.0.0) with the network namespace removed,
  over a view whose files are named by `binary_id`. Each report is trimmed to the keys the normalizer
  reads; values are unchanged. `win/broken.exe` (10 bytes, `MZ` magic) produced no report: blint
  skips what LIEF cannot parse, and exits 0.
- `binary-ids.txt`: `binary_id` and path of every input.

Inputs: `case001`, `case030` (appsec-multi-vuln `1ebaac4`, CMake Release, GCC 13); `weak`
(`-fno-stack-protector -no-pie -z execstack -z norelro`); `nowrelro` (`-z norelro -z now`: no
GNU_RELRO segment, BIND_NOW set); `u1/a.out` = `weak`, `u2/a.out` = `case001` (same basename);
`win/t32.exe`, `win/t64.exe` (pip's distlib launchers, PE32/PE32+); `win/nodyn.exe`, `win/heva.exe`
(`t64.exe` with DYNAMIC_BASE cleared / HIGH_ENTROPY_VA set in the optional header); `mac/speedups.so`
(MarkupSafe 3.0.3 macOS arm64 wheel, a Mach-O bundle).

What this output shows (see docs/proposals/vendor-prepass/blint-cve-bin-tool.md): blint reports
`relro: full` for `nowrelro` (no GNU_RELRO segment), `aslr: false` for every PE (its
`DYNAMIC_BASE` name test fails because LIEF 1.0 prints `UNKNOWN(64)`), and `pie: false` for the
Mach-O bundle (MH_PIE exists only for executables).
