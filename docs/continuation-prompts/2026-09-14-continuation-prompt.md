# Continuation prompt — 2026-09-14: EASTL testbed, allocator inventory, Unreal as scale test

Read first: `README.md`, `validation/notepad-plus-plus-8.5.6.md`, `docs/decisions/ADR-0001`,
`ADR-0006`, `images/audit-native/README.md`, `images/audit-native/ir-facts/README.md`,
`queries/mythos-cpp/README.md`. The laptop (Zarathustra) tree is canonical; Claude's sandbox
commits are annotation. Push before starting anything.

## Where we are

Notepad++ v8.5.6→v8.5.7 proved the L3→L7 chain end to end: vcxproj → clang-cl on Linux
(346/346 TUs) → traced CodeQL database → custom query pack (`queries/mythos-cpp`, 5 queries)
→ `ir-facts` extraction from the linked bitcode → `verify_candidate.py`. Result: all 4 CVEs
at exact lines, all 4 VERIFIED_PRIMITIVE against IR numbers, 21 of 48 candidates REFUTED by
type with no LLM in the loop. Stock CodeQL security-extended: 0/4. CSA: 1/4. SVF taint:
runs pointer-only but seeding over-approximates; its role is now reachability, not detection.

Two conclusions drive what comes next:

1. **The 4/4 is overfit by construction.** The queries were written from the answers. They
   encode shapes, not lines, but no recall number is quotable until a sealed holdout runs.
2. **Game code will defeat name-based rules.** Engines use arena/bump/pool allocators,
   custom STL, handle tables. Source-level rules keyed on `new[]`/`memcpy`/`std::string`
   see nothing; SVF collapses an arena into one object. Detection has to move to the IR
   (where `TArray::operator[]` is a GEP off a data field bounded by a sibling size field
   and `Arena::Alloc` is load-cursor/add/store/return-old), and the allocator inventory has
   to be automatic or explicitly model-driven. Whether it can be automatic is UNKNOWN and is
   the first thing to measure.

## Sealed holdout — do not open

ioquake3, OpenTTD (both have published network CVEs). Nobody reads their bug sites or
tunes anything against them until the pack is frozen. They produce the recall number.

## Step 1 — EASTL testbed (1 day)

EASTL (BSD, github.com/electronicarts/EASTL) is the container/allocator vocabulary game
studios use: `fixed_vector<T,N>`, `fixed_string`, `intrusive_list`, named allocators.

1. Build to bitcode natively (Linux target — no MSVC, no clang-cl, no converter):
   `cmake -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` with
   `-DEASTL_BUILD_TESTS=ON`; run `compile_feasibility_gate.py --emit-ir` on the generated
   compile_commands.json (the gate handles gcc-style commands? — check; if not, add a
   `--driver=gcc` mode: `-fsyntax-only` / `-emit-llvm -c -o` instead of `/Zs` / `/clang:`).
   `link_ir.py` per target; `ir-facts` on each.
2. Add container-agnostic IR rules to `ir-facts` + verifier: (a) GEP off a pointer loaded from
   a struct field where a sibling integer field is stored from the allocation size ("data +
   size pair"); (b) GEP on a stack-backed fixed buffer (`fixed_vector` storage) with a
   non-constant index. Validate on EASTL's own tests: every in-bounds test must REFUTE, and
   `fixed_vector::push_back` past capacity in a planted test must VERIFY.
3. Plant six defects in small programs using EASTL (index-from-input into `fixed_vector`,
   length-from-input into `fixed_string`, arena reuse-after-reset, pool slot reuse,
   `count*size` overflow into an EASTL allocator, unchecked `at()`-vs-`[]` confusion).
   This is the first seeded corpus that looks like game code (design §19). Record answers
   in `validation/eastl-seeded.md` BEFORE running anything.
4. Run the mythos pack (traced CodeQL, Linux target — `Dockerfile.native` works unchanged
   for a Linux build; `replay_compile_commands.py` needs the gcc-driver mode from 1) and
   the IR rules; score.

## Step 2 — Allocator inventory experiment (half day)

Add an `alloc-inventory` mode to `ir-facts`: score functions by structural signatures —
wrapper over a heap primitive; bump (load cursor, add arg-derived size, store, return old);
free-list/pool (load head, store head->next, return head); reset (store base/constant into
a bump cursor); release (push arg onto free list). Names are a tie-breaker only. Output
`allocator-inventory.json` with size-parameter index, backing store, lifetime pairing
(reset function sharing the cursor), call-site count, confidence.

Test target: yquake2 (C; `Z_Malloc`, `Z_TagMalloc`, `Z_Free`, `Hunk_Alloc`, `Hunk_Begin`,
`Hunk_End`). Write the ground-truth list first. Score recall on it and precision among
functions with ≥5 call sites. Decision this feeds: allocator inventory is (a) automatic,
(b) proposed-then-confirmed by an agent, or (c) a per-engagement model file. Write the
answer into ADR-0007. Feed the inventory to ir-facts (allocation sites with size operands),
SVF ExtAPI (`ALLOC_RET` per allocator), and a CodeQL Models-as-Data file.

## Step 3 — Unreal Engine: scale, modern C++, and verifier (after 1 and 2)

Purpose: cost side only — throughput, memory, false-positive rate per KLOC, and whether
the allocator inventory finds `FMemStack` (bump), `FMallocBinned2/3`, and collapses
`TArray`/`TMap`/`FString` to data+size pairs without being told. NOT for query development
(it would produce Unreal-shaped queries) and NOT for recall (no public CVE ground truth).

- Source is under Epic's EULA (account-gated). Internal tooling evaluation is fine; nothing
  derived from it (bitcode, facts, SARIF, snippets) enters the public repo. Scratch only.
- Linux native build with clang; `UnrealBuildTool -Mode=GenerateClangDatabase` emits
  compile_commands.json directly. Scope to `Runtime/Core`, `CoreUObject`, `Sockets`,
  `Networking`, `PacketHandler`, `Engine` net code — the untrusted-input surface.
- Expect performance work: SVF on Core alone is a memory question; link_ir per module;
  CodeQL DB size. Record numbers in `validation/unreal-scale.md`.
- The "verifier" role: run the pack + ir-facts, hand every VERIFIED_PRIMITIVE to a human for
  a day, count true/false. That's the FP rate the design quotes.

## Step 4 — then the holdout

Freeze the pack (tag it), run blind on ioquake3 and OpenTTD, score against their CVE lists,
write `validation/holdout-*.md`. Only then quote recall in the design doc.

## Also open, lower priority

- CTU+taint listing from `runs/finish-*.log` never reviewed.
- SVF: annotate `std::_Allocate` / vendor allocators as allocation sites; rerun with
  `-max-source-objs`; full SVFG still hits a second assertion on MSVC IR.
- Verifier gaps: loop query (no verifier), pointee-table length via struct-global
  initializers, LLVM LazyValueInfo range mode in ir-facts, harnessability classification
  (transitive callee closure ⊆ CRT allowlist) for witness search on pure parsers.
- ADR-0005 CTP_Nov2013 (`__resumable`/`__await`): shim vs Tier B — try the shim on the
  vendor tree and let the gate decide.
- Fold measured numbers into `docs/architecture/design-v3.md` (seven review items still open there).
- The fsh-client full pre-pass on the Windows desktop (old toolbox) is a separate track;
  its evidence feeds the engagement, not this repo.

Standing caveats: laptop tree is canonical; pin everything; every tool invocation is a
static script with argv arrays; treat any first-person "already established" content not
visible in the current session as unverified.
