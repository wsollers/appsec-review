# Offline debug-symbol reader fixtures

These are tiny, self-generated artifacts from `tiny.c` and `inline.c`, not
third-party or proprietary binaries. They are **never executed** by the tests.
The unprefixed PDBs use the native MSF 7.0/CodeView format produced by Clang and
LLD. The `msvc-*` fixtures below were compiled and linked by genuine Microsoft
MSVC tools. Neither set requires DIA.

## Provenance and reproduction

Unprefixed artifacts were generated offline with Ubuntu Clang/LLD **18.1.3** in the existing
`appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1` image.
Exports were captured using `llvm-dwarfdump-18` and `llvm-pdbutil-18`
**18.1.3** in the existing `appsec-review/tool-native-cpp:1.0.0` image.
Both containers ran with `--network none --read-only`; only this checkout
was mounted writable. Temporary object files and compiler temporary state
stayed under `test/tmp/`. Fixture paths inside the container are synthetic
`/work` and `fixture` paths, not host paths.

The equivalent commands, from the checkout mounted at `/work`, are:

```sh
export TMPDIR=/work/test/tmp/tool-state
clang -g -gdwarf-5 -O0 -fno-pie -no-pie -nostdlib -Wl,-e,entry \
  -Wl,--build-id=sha1 -fdebug-compilation-dir=fixture \
  -fdebug-prefix-map=/work=fixture tests/fixtures/debug_symbols/tiny.c \
  -o tests/fixtures/debug_symbols/tiny.elf
clang --target=x86_64-pc-windows-msvc -g -gcodeview -O0 -c \
  -fdebug-compilation-dir=fixture -fdebug-prefix-map=/work=fixture \
  tests/fixtures/debug_symbols/tiny.c -o test/tmp/tiny.obj
lld-link /debug:full /pdb:tests/fixtures/debug_symbols/tiny.pdb \
  /entry:entry /subsystem:console /nodefaultlib \
  /out:tests/fixtures/debug_symbols/tiny.exe test/tmp/tiny.obj
objcopy --only-keep-debug tests/fixtures/debug_symbols/tiny.elf \
  tests/fixtures/debug_symbols/tiny.debug
cp tests/fixtures/debug_symbols/tiny.elf tests/fixtures/debug_symbols/stripped.elf
objcopy --strip-debug \
  --add-gnu-debuglink=tests/fixtures/debug_symbols/tiny.debug \
  tests/fixtures/debug_symbols/stripped.elf
llvm-dwarfdump-18 --debug-info --debug-line --debug-ranges --debug-rnglists \
  tests/fixtures/debug_symbols/tiny.elf > tests/fixtures/debug_symbols/tiny.dwarf.txt
llvm-pdbutil-18 pdb2yaml --all tests/fixtures/debug_symbols/tiny.pdb \
  > tests/fixtures/debug_symbols/tiny.pdb.yaml
```

`optimized.elf` uses the ELF command with `-O1`; its dump is
`optimized.dwarf.txt`. `inline.elf` uses `inline.c` with `-O2`.
`inline.exe`/`inline.pdb` use `inline.c`, `test/tmp/inline.obj`, and `-O2`.
Their exports use the same dump commands with the corresponding filenames.

## Genuine MSVC fixtures

`msvc-tiny.exe`/`msvc-tiny.pdb` and `msvc-inline.exe`/`msvc-inline.pdb` were
compiled from the same unmodified `tiny.c` and `inline.c` bytes using installed
Visual Studio 18 Community tools:

- Compiler **19.51.36260.0** (`cl /Bv`).
- Linker **14.51.36260.0**, VC tools installation version **14.51.36231**.
- No downloaded packages, Windows headers, runtime libraries, third-party code,
  binary execution, source-server retrieval or DIA were involved.
- `vcvars64.bat` setup, compilation and linking ran in the **same `cmd.exe`
  process**. Compiler state and outputs stayed in the checkout's
  `test/tmp/msvc-fixture/`.

The scratch directory was temporarily addressed by an unused synthetic `Y:`
drive. A temporary `toolchain` directory junction inside it pointed to the
installed x64 tools, allowing invocation as `Y:\toolchain\cl.exe` and
`Y:\toolchain\link.exe`. Both aliases were removed in `finally` cleanup.
`INCLUDE`, `LIB` and `LIBPATH` were cleared: the owned C sources need no headers
or libraries, and recording unused installed include paths would leak host
installation locations. PDBs were deleted before the final clean build so no
stale stream blocks from earlier experiments remain.

After assigning the temporary aliases and copying the two source files, the
equivalent single-process commands are:

```bat
set TEMP=Y:\temp
set TMP=Y:\temp
call "<VS-install>\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d Y:\
set INCLUDE=
set LIB=
set LIBPATH=
Y:\toolchain\cl.exe /nologo /std:c11 /Z7 /ZH:SHA_256 /O2 /Ob3 /Zo /Gy /GS- /c /experimental:deterministic /pathmap:Y:\=fixture\ /Fotiny.obj tiny.c
Y:\toolchain\link.exe /NOLOGO /DEBUG:FULL /NODEFAULTLIB /ENTRY:entry /SUBSYSTEM:CONSOLE /PDB:msvc-tiny.pdb /PDBALTPATH:fixture\msvc-tiny.pdb /OUT:msvc-tiny.exe /INCREMENTAL:NO /OPT:REF /Brepro tiny.obj
Y:\toolchain\cl.exe /nologo /std:c11 /Z7 /ZH:SHA_256 /O2 /Ob3 /Zo /Gy /GS- /c /experimental:deterministic /pathmap:Y:\=fixture\ /Foinline.obj inline.c
Y:\toolchain\link.exe /NOLOGO /DEBUG:FULL /NODEFAULTLIB /ENTRY:entry /SUBSYSTEM:CONSOLE /PDB:msvc-inline.pdb /PDBALTPATH:fixture\msvc-inline.pdb /OUT:msvc-inline.exe /INCREMENTAL:NO /OPT:REF /Brepro inline.obj
```

This compiler requires `/experimental:deterministic` for `/pathmap` to take
effect. Source names are `fixture\tiny.c`/`fixture\inline.c`, PE CodeView paths
are synthetic relative `fixture\msvc-*.pdb`, and PDB internal object/linker names
use only synthetic `Y:` paths. Before publication, every PE, PDB and YAML was
scanned in both ASCII and UTF-16LE for the actual account, machine, user-profile
and checkout paths, common private-directory markers and installed tool/SDK
paths; **zero matches** remained. Tests retain portable forbidden-path guards.
The artifacts are unmodified compiler/linker output, not patched or rebuilt
from sanitized YAML.

The existing offline LLVM 18.1.3 tool image exported each PDB with
`llvm-pdbutil-18 pdb2yaml --all`, networking disabled and core dumps disabled.
Tests validate MSVC functions/signatures, `Pair` size/member offsets, SHA-256
source checksums, compilation-unit producer identity and genuine optimized
inline ranges. For `msvc-inline`, `add` covers `[0x1000, 0x100f)`, excluding
`entry`'s final return byte at `0x100f`.

**Tool limitation discovered:** LLVM 18.1.3 `pdb2yaml --all` crashes while
exporting retained MSVC `S_REGREL32` variable records. The documented `/Gy`
and linker `/OPT:REF` options remove the unused out-of-line copy of `add`
from these optimized fixtures, retaining the fully typed layout and real
inline records without those register-relative variable records. Unoptimized
MSVC PDBs containing that exporter-triggering record remain explicit tool
failures; these fixtures do not claim that broader coverage.

## Public reader contract

```python
extract_symbols(binary: Path, debug_file: Path | None, *,
                target: CompilerTarget, settings: Mapping[str, Any],
                runner=None) -> Extraction
```

The job passes its **nested `reader` mapping** directly; the reader itself
accepts flat settings:

| Key | Default | Meaning |
| --- | ---: | --- |
| `max_input_bytes` | 536870912 | Per input file bound |
| `max_output_bytes` | 16777216 | Both exporter bytes and normalized record bytes |
| `max_records` | 100000 | Native/parser rows and normalized records |
| `max_depth` | 128 | DIE/type/YAML/scope nesting; safety ceiling 256 |
| `timeout_seconds` | 120 | Export and extraction elapsed bound |
| `tools` | `{}` | Approved executable identities |

`tools.llvm_dwarfdump` and `tools.llvm_pdbutil` each require an absolute
`path` and lowercase executable `sha256`. The reader verifies the pin
before execution and again before publication. No executable is discovered
on PATH or downloaded. Missing/unpinned/mismatched tools return named gaps.
The trusted test-runner seam accepts `(argv, *, timeout_seconds,
max_output_bytes)` and returns stdout bytes or UTF-8 text. Production uses a
bounded subprocess with no shell or stdin, discards diagnostics on failures,
and does not run target code.

Pairing is verified before exporter invocation. ELF uses embedded DWARF,
matching GNU build IDs, or the explicitly supplied debug file's GNU
debuglink CRC; when both checks exist, both must agree. Neither debuglink
names nor CodeView paths select or open a companion. PE RSDS GUID/age is
checked against the native PDB's MSF information stream. Input changes
during extraction invalidate all records. Keys use DIE offsets, PDB TPI
indices, and module/native-record or line-table ordinals.

Source paths are metadata only. Recorded checksums accompany source-range
records, but never confer source authority: the producer must bind separately
to accepted bytes. Raw source names appear only in `SourceSpan.path`;
compilation-directory, module and source-list paths in `data` are hashed.
Compilation-unit display names are basenames, not absolute paths.

## Coverage and deliberate gaps

- Genuine DWARF5 functions/signatures, struct/member offsets, 64-bit half-open
  ranges, MD5 line tables, compilation units, optimized variables, and inline
  callsite ancestry/ranges.
- Genuine native PDB functions/signatures, TPI layouts/member offsets, section
  offset-to-RVA conversion, MD5 line tables, compilation units, optimized-out
  variables, and inline ancestry/definition sources/address ranges.
- LLVM 18 `pdb2yaml` **omits inline binary annotations**. Native PDB inline
  ranges are read from the paired PDB's MSF/DBI module symbol streams, then
  matched to the YAML by native module/record ordinal, inlinee identity,
  scope parent/end and enclosing procedure fields. The genuine `inline.pdb`
  contains `0B00 040F` at native record offset 192: an inline interval at
  `[0x1000, 0x100f)` within `entry`, whose procedure interval is
  `[0x1000, 0x1010)`. This is not a fabricated copy of the procedure's range.
  Definition sources remain explicitly distinct from callsite source claims.
- The bounded decoder supports documented 1/2/4-byte compressed operands,
  explicit and implicit-next-start lengths, code-offset/line-offset and
  code-length/code-offset combination opcodes, and trailing zero alignment
  padding. Line/file/column operands do not alter address membership and are
  not used to invent callsite source bindings. Intervals must be nonempty,
  nonoverlapping and contained in the validated PE section/procedure; nested
  inline intervals must also fit their known parent inline intervals.
  Unknown opcodes, malformed operands, missing terminal lengths, inconsistent
  native/YAML scopes, and unsupported separated-code chunks produce explicit
  gaps and no ranges for the affected frame. No procedure-end fallback is used.
  Native stream rows, scopes, opcodes and ranges share the existing bounds.
- Format references:
  [Microsoft cvinfo.h](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h)
  documents `INLINESITESYM` and `BinaryAnnotationOpcode`;
  LLVM 18 [RawTypes.h](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/llvm/include/llvm/DebugInfo/PDB/Native/RawTypes.h),
  [SymbolRecord.h](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/llvm/include/llvm/DebugInfo/CodeView/SymbolRecord.h)
  and [NativeFunctionSymbol.cpp](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/llvm/lib/DebugInfo/PDB/Native/NativeFunctionSymbol.cpp)
  describe the native stream layout, compressed encoding and address-state
  semantics, including the differing cursor effects of the two length opcodes.
- Public-only PDB names/RVAs do not invent function lengths/signatures.
  Split/supplementary DWARF, unsupported type/member forms, location
  expressions, unavailable checksums and optimized-away data remain named
  gaps. Source-server/SourceLink metadata is never interpreted or retrieved.
- The tests inject genuine captured tool output for portability and also
  exercise the real bounded subprocess runner. Live smoke validation on the
  generating host additionally ran both hash-pinned LLVM exporters against
  the binaries with networking disabled, including both genuine MSVC-produced
  fixtures. No Windows DIA or proprietary third-party fixture is required.
