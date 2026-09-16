# Validation target: EASTL (native Linux, first non-Windows target) — 2026-09-15/16

Run on HAL5000 (Windows work machine, WSL2 Ubuntu, Docker Engine in WSL). EASTL master, shallow
clone, `cmake -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DEASTL_BUILD_TESTS=ON`, host clang 18 for the
compile DB, image clang 21.1.0 for everything else.

## Pipeline result (`pipeline/pregather.sh --compile-db ... --codeql --csa`)

| Step | Result |
|---|---|
| compile DB | 126 TUs (EASTL + EABase/EAAssert/EASTDC/EAMain/EATest deps), normalised from cmake `command` form |
| gate | **126/126 Tier A** |
| link | 1 module (`eastl`, 84 MB) — single `--project`; per-target split is a TODO |
| ir-facts | globals 9101, geps 11184, size_calls 13271, allocas 1635, ctor_stores 1148 (0 before the Itanium-ctor fix) |
| CSA (CTU + alpha) | 126/126 ok, 540 findings; **69 memory-safety candidates**, 434 code-quality (informational) |
| CodeQL traced | 126 TUs extracted, security-extended 41 findings |
| mythos pack | 8 candidates → 7 REFUTED by type (`EASTDC_WCTYPE_MAP[256]` indexed by a byte), 1 unresolved (loop query) |
| assemble | 0 verified · 69 unresolved · 7 refuted · 434 informational |

Zero verified primitives on EASTL's own code is the expected baseline. The 69 unresolved
are real candidates for a reviewer (three `security.ArrayBound` in `EAString.cpp` with no GEP
at the reported line are the odd ones); the seeded corpus is where positives come from.

## Container-agnostic rule calibration (`ir-facts field_geps` on EASTLTest)

The rule: a GEP through a pointer loaded from a struct field is *bounded* if the index (or
result) is compared, in this function or at every call site, against another field of the
same struct. EASTLTest is correct by construction, so its unbounded remainder is the rule's
false-positive ceiling.

| Iteration | Effective bounded | What was wrong |
|---|---|---|
| 1 | 16% (in-function only) | checks live in the CALLER of `operator[]` (nothing inlined at -O0) |
| 2 | 16% | `size()` is a CALL, not a field load → getter summaries |
| 3 | 34% → 16% (bug then fix) | "index depends on an argument" matched `this`; must be an integer parameter |
| 4 | 16% | inherited fields addressed by one multi-index GEP through the derived type |
| 5 | 20% | **field 0 has no GEP with opaque pointers** — bare `load ptr, %this`; class identity now comes from the method's demangled name |
| 6 | 21% | class-name parser cut inside template args; constant-index call sites (`v[0]`) categorised separately |
| 7 | pending | LLVM struct names vs demangled class names never matched (member containers vs their getters) → canonical identity; local types `f()::T` broke param-list detection |

Remaining unbounded mass, by enclosing function (iteration 6): iterators 1275 (unbounded by
design; needs an iterator rule), constructors/`Do*` internals 445 (filling storage just
allocated), test loops with literal bounds 206, other 486 (mostly the identity mismatch fixed
in 7). Automatic pair inference works: `hashtable` → `{bucket array: bucket count}` in every
instantiation, with no names.

## Learnings (each is a property of compiled C++, not of EASTL)

1. Accessors are not inlined at -O0; bound checks are at call sites. Interprocedural or nothing.
2. Getters are calls; summarise "return value derives from fields F" per function.
3. Opaque pointers: field 0 access has no GEP → no struct type in the IR; recover identity from
   the enclosing method's class (demangled) when the base is `this`.
4. Inheritance: one GEP walks derived → base → field; use `gep_type_iterator`, take the innermost
   struct/field.
5. LLVM struct names (`class.X.123`, template args dropped) and demangled names (`X<T, A>`) must
   be canonicalised to one identity (`X`); field indices are stable across instantiations.
6. Constant indices at call sites are a separate risk class from input-derived ones.
7. Iterators are a distinct shape (pointer arithmetic with no container bound in scope).
8. Docker BuildKit cache can be corrupted by a reboot ("parent snapshot does not exist"): check
   `docker build`'s exit code, never grep its log for `error`.
9. CTU on-demand parsing needs absolute compiler paths + `-resource-dir`; duplicate USRs from
   template instantiations must be dropped from the extdef map.
10. cmake emits `command`-form DBs with the host compiler path; normalise to `arguments` and map
    the compiler by basename.

## Not done here

Seeded corpus (6 bugs + 2 benign twins) — the recall half. Per-target link split. Iterator rule.
`validation/eastl-seeded.md` does not exist yet; write the answers before running.
