# Validation target: Notepad++ v8.5.6 → v8.5.7 (CVE rediscovery)

First ground-truth datapoint for design §19. Run 2026-09-12 on Zarathustra with
`audit-native:local` (LLVM 21.1.0, SVF-3.3), Tier A (346/346 TUs after the `.targets` fix below; 320/320 before), xwin MSVC headers.

| Tag | Commit | Role |
|---|---|---|
| v8.5.6 | `e39deab7782a89990ac5d3b35f910a33949ea740` | before — all four CVEs present |
| v8.5.7 | `5008b8a0cccfff255c5f48b5782ef993b6f9b631` | after — all four fixed |

## Ground truth

| CVE | Site | In compile DB? | CSA (default + security + optin.taint + alpha.*) |
|---|---|---|---|
| CVE-2023-40031 | `Utf8_16_Read::convert`, `Utf8_16.cpp:175` (`*pCur++ = c`) — UTF-16→UTF-8 output buffer sized `len + len/2 + 1`, under-allocates worst case | yes | **FOUND** — `security.ArrayBound` "Out of bound access to memory after the end of the heap area"; gone in v8.5.7 |
| CVE-2023-40166 | `FileManager::detectLanguageFromTextBegining`, `Buffer.cpp` | yes | **MISSED** — only `deadcode.DeadStores` at 1086/1082 in both versions |
| CVE-2023-40036 | `CharDistributionAnalysis::HandleOneChar`, `uchardet/CharDistribution.cpp` — table index from character order | yes (after fix) | **MISSED** — no finding in the TU either version |
| CVE-2023-40164 | `nsCodingStateMachine::NextStateImpl`, `uchardet/nsCodingStateMachine.h` — state-table lookup | yes (after fix) | **MISSED** — no finding either version |

Command: `run_csa.py --filter 'Utf8_16|uchardet|Buffer\.cpp' --alpha` on both versions,
`diff_findings.py` between them. Full outputs: `scratch-npp/csa-cve`, `scratch-npp857/csa-cve`,
`scratch-npp857/cve-diff.json` (local, not committed).

**CSA alone: 1 of 4 CVEs rediscovered, with all 4 in scope (0.25 recall).** First run had only 2 in scope (uchardet absent from the compile DB); the converter was fixed the same day and the run repeated at 346 TUs with the same 1/4 result. Before/after
discrimination on the one it found is clean: present in v8.5.6, absent in v8.5.7, no new
findings introduced.

## CodeQL (audit-codeql, bundle v2.27.0, cpp-queries 1.8.3, security-extended, build-mode none) — 2026-09-12

50 findings on v8.5.6; **0 of 4 CVEs**. Top rules: `cpp/incorrect-allocation-error-handling`
(28, incl. 5 in uchardet — "this null check is unnecessary", i.e. the inverse of a
memory-safety issue), `cpp/suspicious-pointer-scaling` (9), `cpp/overrunning-write-with-float`
(4); `Buffer.cpp` only `cpp/potentially-dangerous-function` (localtime).

Three findings inspected, all refutable — recorded as seeds for the refutation and
component-classification lanes:

| Finding | Disposition | Evidence |
|---|---|---|
| `cpp/use-after-free` `tinystrA.cpp:186` | REFUTED | `cstring` deleted at 171, reassigned at 174, written at 186; query lost the kill on a member field |
| `cpp/type-confusion` `tinyxmlA.h:505` | REFUTED (verify guard on all paths) | TinyXml `ToDocument()`-style downcast guarded by node `type` tag |
| `cpp/uncontrolled-process-operation` `CheckLexilla.c:83` | OUT_OF_SCOPE (component) | argv → `dlopen` in `lexilla/examples/`, a test program, not product code — L0A classification case |

Interpretation: build-mode none resolves Linux libc headers (gcc/libc6-dev in the image)
but not `<windows.h>`/UCRT, so `ReadFile` is an unknown call — no taint source, so the
dataflow queries that did fire on the planted-`strcpy` smoke test have nothing to start
from here. This is a Windows-headers result, not an engine result; the fair comparison is
the traced clang-cl extraction against the same `compile_commands.json` and `/msvc` tree
(open; CodeQL documents clang-cl tracing as preliminary).

### Traced clang-cl extraction (audit-codeql-native, same run day)

`compile_commands.json` replayed under CodeQL's tracer with `/msvc` mounted: **346/346
TUs extracted, 1.6 GB database, 61 findings, still 0 of 4 CVEs** — identical output on
the CVE files. So the 0/4 is a property of the security-extended suite on this code, not
of extraction. Getting the traced build to work took three fixes, each a different layer's
opinion of the command line (recorded in `images/audit-codeql/`): the tracer resolves
symlinks before deciding what it mimics (`clang-cl` must be a real file); a traced
compile writes `.obj` into the read-only workspace (`/clang:-o` into scratch); and the
extractor does not understand the `--` separator the converter emits for clang-cl, so the
source must be passed as a relative path.

### Custom CodeQL pack `queries/mythos-cpp` on the traced databases (2026-09-12)

Written after reading the four fixes; each query encodes a *shape*, with bounds checks as
barriers. Result on v8.5.6: **4 of 4, each at the exact line**, with before/after that
matches the fixes:

| CVE | Query | v8.5.6 | v8.5.7 |
|---|---|---|---|
| 40031 | `UndersizedOutputBufferFromInputLength` | `Utf8_16.cpp:175` | still reported — loop unchanged, buffer resized; a *correct-but-unproven* report for the refutation lane |
| 40036 | `TableSizeExceedsArrayLength` | `CharDistribution.cpp:69`: `EUCTWCharToFreqOrder` 5376 entries vs `mTableSize` 8102 | none |
| 40164 | `UncheckedTableIndexFromInput` | `nsCodingStateMachine.h:72` (`charLenTable[state]`) | still reported — taint shape; the fix grew `ISO2022JPCharLenTable` 8→10 |
| 40166 | `ConstantLengthReadFromBoundedBuffer` | `Buffer.cpp:1399`: `std::string(data + i, 40)` vs `dataLen` | none |

Ground-truth corrections found on the way: 40036's fix is a *data table constant*
(`EUCTWFreq.tab`, 8102→5376), not code in `CharDistribution.*`; 40166 is a constructor
call with a constant length, not a loop; 40164 is a state-count/table-length mismatch.
All three are static properties with no taint involved — which is why CSA, SVF-taint and
the stock CodeQL suite are the wrong instruments for them.

**Overfitting caveat.** These queries were derived from the answers. 4/4 on this corpus
says the shapes are expressible, not that they generalize. Noise on the same tree: taint
query 34 → 16 after excluding unsigned-char indices into ≥256-entry tables; loop query 7
(sha-256, lexers — all benign fixed-size reads). §19 needs a holdout target these queries
have never seen before any recall figure is quoted.

Scoreboard on the four CVEs (rediscovery → mechanical verification): CSA per-TU **1/4** · CSA CTU+Win32 taint (listing not yet
reviewed) · CodeQL security-extended, both modes **0/4** · **CodeQL custom pack 4/4 (on
the corpus it was written from), all 4 VERIFIED_PRIMITIVE against IR** · SVF taint (blocked on source-seeding precision).

## Mechanical verification against LLVM IR (`ir-facts` + `verify_candidate.py`, 2026-09-13)

48 candidates (mythos pack + CSA on the CVE TUs) checked against facts extracted from the
three linked product modules (346 TUs, `-O0 -g`):

| Status | n | Evidence |
|---|---|---|
| VERIFIED_PRIMITIVE | 12 | **all four CVE sites**: 40036 — IR global `[5376 x i16]`, ctor stores 8102 (five sibling classes store correct sizes and are not flagged); 40166 — `basic_string(ptr,n)` with n=40 from an argument-derived pointer; 40164 — argument-dependent index into a table reached via `this->model` (needs table_length); 40031 — write via cursor into `new[]` sized from an argument (needs witness). Plus 8 non-CVE candidates for the refutation lane. |
| REFUTED | 21 | `zext i8` index into a ≥256-entry array: range [0,255] by type. The `UTF8BytesOfLead[ch]` class, dismissed without reading source. |
| UNRESOLVED | 15 | loop query has no verifier yet; 8 where index provenance needs another IR rule |

Two `-O0` IR shapes had to be handled: pointers (incl. `this`) are spilled to stack slots,
so bases and ctor stores resolve through load → slot → stored value. Each VERIFIED result
carries `needs:` — the `VERIFICATION_DEPENDENCY_REGISTERED` payload (design §23.1).

VERIFIED_PRIMITIVE is not "exploitable": it is "the local mechanism the query claimed is
present in the compiled program, with these numbers". Promotion to VERIFIED_FINDING still
needs the named dependency resolved (range analysis, pointee-table length, witness).

## Persistent finding (refutation candidate)

`security.ArrayBound` at `Utf8_Iter::get`, `*c = m_out[m_out1st]` (v8.5.6:490 /
v8.5.7:530). Same code both versions. `m_out1st` is advanced modulo `_countof(m_out)`
elsewhere; CSA does not track the member invariant across calls. Expected disposition:
REFUTED (benign) — a good first case for the blue-team-refutation lane, since the evidence
for refutation (the modulo update) is in a different function.

## Gaps this run exposed

1. **uchardet was not in the compilation database — CLOSED.** Notepad++ compiles it
   through `notepadPlus.uchardet.targets`: a private item list (`_ClCompileUchardet`)
   injected by a `<Target>` as `<ClCompile Include="@(_ClCompileUchardet)"/>`. The
   converter now evaluates local `.targets` imports for that idiom, tags each such TU
   `via_targets` for provenance, and reports `targets_evaluated` / `targets_not_evaluated`
   (MSBuild-internal) separately in the audit seed. 26 TUs added; all compile. Lesson for
   the vendor tree: `source-completeness.json` must be checked against *all* `.targets`
   imports, and any `<Target>` condition the converter does not evaluate is a recorded
   assumption ("sources taken as always-built").
2. **CVE-2023-40166, -40036, -40164 are CSA misses.** 40166: heap read overrun in
   text-beginning language detection (length-vs-buffer across a loop). 40036/40164:
   global-table reads indexed by values derived from input bytes; the tables and the
   index derivation are in different TUs/headers and the bound is a property of the
   table's declared size vs. the derived index range — inter-procedural, data-dependent
   reasoning CSA's per-TU path exploration does not reach. This is the target for the SVF value-flow / taint layer (Tier A input is
   already available: the notepadPlus module is linked and Andersen completes). Until
   that lane exists, the design's memory-safety claim is "CSA-level", not "SVF-level".
3. **Path shift breaks line-based matching.** The 40031 fix moved every later line by
   40; `diff_findings.py` matches on (checker, file, message) for that reason, and it
   held. `issue_hash` from the plist is a stronger key for the orchestrator later.

## What this means for §19 pass criteria

Numbers to write into the design, from measurement rather than aspiration:

- CSA-only memory-safety recall on real (non-planted) CVEs: **0.25**, all four in scope.
  Any §19 threshold above that for the native lane is a claim about SVF, not CSA.
- The three misses share a shape — an index or length derived from untrusted bytes
  reaching a memory access whose bound lives elsewhere — which is exactly the query the
  SVF value-flow + taint lane is meant to answer. They are the acceptance test for it.
- Source completeness must be a hard gate: a CVE in code outside the compile DB is not
  a detector miss, it is a scoping failure, and the report must say which.
- Persistent-across-versions findings are the natural false-positive candidate set for
  the refutation lane.

## Next runs prepared (2026-09-12)

1. `run_csa.py --ctu` with `taint-win32.yaml` (ReadFile as source) over the same 28 TUs,
   both versions. Synthetic two-TU test: per-TU + taint = nothing; taint + CTU =
   `security.ArrayBound` "Potential out of bound access ... with tainted index" in the
   callee's TU. Prediction: 40036 and 40164 become findings; 40166 uncertain (loop +
   length, not a table index).
2. `svf-taint` over the linked `notepadPlus` module. Acceptance: all three CSA misses
   appear as candidates. Not compiled yet.
