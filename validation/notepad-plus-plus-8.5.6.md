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
