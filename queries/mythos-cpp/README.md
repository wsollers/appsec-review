# mythos/cpp-queries

Custom CodeQL queries for the memory-safety shapes the stock security-extended suite missed
on Notepad++ v8.5.6 (0/4 CVEs in both build-mode-none and traced extraction, 2026-09-12).
Each query encodes one shape and treats a bounds check as a barrier, so guarded code is not
reported. Status: **written, not yet compiled** — expect a round of QL compile errors.

| Query | Shape | Target CVE |
|---|---|---|
| `UncheckedTableIndexFromInput.ql` | input byte → arithmetic → table index, no guard | 40036, 40164 |
| `UndersizedOutputBufferFromInputLength.ql` | `new T[f(len)]`, cursor write in loop, no size check | 40031 |
| `ReadLoopBoundedByConstantNotLength.ql` | buffer read in loop bounded by literal, length param unused | (loop variant; 40166 turned out not to be a loop) |
| `ConstantLengthReadFromBoundedBuffer.ql` | `std::string(buf+i, 40)` / `memcpy(.., buf, K)` with the length parameter unchecked | 40166 |
| `TableSizeExceedsArrayLength.ql` | ctor sets `ptr = TABLE` and `size = K` with K > entries in TABLE; index guarded by `size` | 40036 |

## First run on the traced v8.5.6 database (2026-09-12)

All three initial queries compiled first time. 42 findings: **40031 hit at `Utf8_16.cpp:175`**,
**40164 hit at `nsCodingStateMachine.h:72`** (`charLenTable[state]`; the fix grew
`ISO2022JPCharLenTable` from 8 to 10 entries). 40036 was *correctly not* reported by the
taint query — `HandleOneChar` is guarded — because the bug is the bound itself:
`EUCTW_TABLE_SIZE 8102` vs 5376 entries; hence `TableSizeExceedsArrayLength.ql`. 40166 is a
`std::string(data + i, 40)` call, not a loop; hence `ConstantLengthReadFromBoundedBuffer.ql`.
Noise: ~25 of 34 taint hits were `UTF8BytesOfLead[ch]`-style — unsigned-char index into a
256-entry table, provably safe; now excluded by `typeBounded`.

## Run (traced database, inside audit-codeql-native; repo mounted as /workspace)

```
AUDIT_NATIVE_IMAGE=audit-codeql-native:local MEM_LIMIT=20g \
  images/audit-native/run.sh . - ./scratch-codeql -- bash -c '
  cd /scratch/codeql && codeql database analyze db-cpp /workspace/queries/mythos-cpp \
    --additional-packs=/opt/codeql/qlpacks --format=sarif-latest --output=mythos.sarif --threads=4 --ram=12000'
```

`--additional-packs=/opt/codeql/qlpacks` lets `codeql/cpp-all` resolve from the bundle
offline. Compile errors print per query; a query that fails to compile is skipped, the
others still run.

## Expected on v8.5.6 / v8.5.7

- 40036: `CharDistribution.cpp` `HandleOneChar` — `mCharToFreqOrder[order]` reported in
  both versions? The 8.5.7 fix added a bound check, so 8.5.6 = reported, 8.5.7 = guarded.
- 40164: `nsCodingStateMachine.h` `NextStateImpl` — same expectation.
- 40031: `Utf8_16.cpp` `convert` — reported in 8.5.6; the fix changed the allocation size,
  not the loop, so the query may still report 8.5.7 (the write loop is still unchecked).
  That would be a true "unchecked but correctly sized" report — a refutation-lane case,
  and a known limitation of a syntactic query.
- 40166: `Buffer.cpp` `detectLanguageFromTextBegining` — depends on the exact loop form.

Everything else the queries report on the tree is either a bug or a refutation seed;
record both.
