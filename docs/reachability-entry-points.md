# Reachability entry points beyond `main` (design note, brief M5)

Status: design note for ADR-0020 open item "Entry points beyond `main` need a source".
Implemented from it: step 1 (always on); steps 2 and 3 behind tunables that default **off**
(brief Q, `appsec-review-process/entry_exports.py`). With both off every result is byte-identical
to the code before brief Q (`tests/test_entry_exports.py` pins a golden hash).

## Why it matters

`reachability.py` answers REACHABLE / UNREACHABLE / UNKNOWN with a bounded multi-source BFS over
resolved CPG call edges, starting from `CallGraph.entry_points()`. UNREACHABLE means "no path from
any *modelled* entry point". A function that only an unmodelled entry calls (a `WinMain`, a library
export, an HTTP route handler) is then reported UNREACHABLE although attacker input reaches it. The
severity cap treats UNREACHABLE and UNKNOWN alike (both cap at High), but the 06 correlator lets the
`ir` engine's `unreachable` stand as a verdict, and the report prints it. So the rule is:

> Never assert `UNREACHABLE` through an unmodelled entry point. Adding a *real* entry point is
> always safe: the reached set can only grow, so an UNREACHABLE can only become REACHABLE or
> UNKNOWN, never the reverse. Adding a *wrong* entry point is not safe: it can manufacture a
> REACHABLE witness (and therefore allow Critical).

## Where entry points come from today

| Source | Used by | Trust |
|---|---|---|
| Method named `main` in the CPG | `reachability.CallGraph.entry_points` (finding enrichment, 06 IR engine) | Deterministic |
| `inputs/reachability-entry-points.json` (run-supplied, hash-bound) | finding enrichment, `06-reachability-*` | Operator assertion; bound by hash, not verified |
| `dep_reachability_engines.ENTRY_POINT_SOURCES[lang]["names"]` (`ServeHTTP`, servlet `do*`, ...; for `cpp` it *is* `reachability.PROGRAM_ENTRY_NAMES`) | dependency engines only | Name match; language-defined |
| CodeQL pack `EntryPoint` classes (routes, controller actions, `RemoteFlowSource`, address-taken, no-internal-caller) | `06-reachability-codeql` (never reports `unreachable`) | QL library model |
| Dynamic export table of a shipped shared library (`binary-summary` `dynamic_exports`, read from the accepted `02-binary-triage` evidence) | finding enrichment, when `reachability_export_entries` is on | Linker output; unique join only |

Finding enrichment (ADR-0020) therefore sees fewer entries than the dependency engines for the same
C/C++ program.

## Candidate sources and how each maps to the CPG

1. **Toolchain/OS program entries (implemented).** `wmain`, `WinMain`, `wWinMain` (the C/C++
   runtime calls them instead of `main`) and `DllMain` (the loader calls it). CPG mapping: a
   `METHOD` record whose `name` equals one of these. Deterministic and language-defined, so it is
   in `reachability.PROGRAM_ENTRY_NAMES` and always on. `LLVMFuzzerTestOneInput` is deliberately
   *not* included: it is a harness entry, and a path from a fuzz harness is not a path from the
   shipped program, so it must not produce a REACHABLE witness that lifts the Critical cap. The dependency engines follow the same rule (decision D-01,
   `docs/decisions/DECISION-LOG-2026-09-29.md`): a dependency reached only from a fuzz harness is not reachable from the shipped program.
2. **Exported symbols of a shared library.** Correct source: the dynamic symbol table of the built
   artifact (`02-native-build` binaries, `02-binary-triage` exports) or linkage facts from
   `02-ir-facts` (external linkage, `visibility("default")`, not `static`, not in an anonymous
   namespace, not hidden by `-fvisibility=hidden` or a version script). CPG mapping: join the
   exported name (demangled) to `METHOD.full_name`/`name`; an ambiguous join is an escape, not an
   entry. **Implemented behind `reachability_export_entries` (default off), brief Q:**
   * *Source.* What the jobs published before brief Q was not enough: `02-debug-symbol-index`
     keeps `nm -an` (since P03, `73b64a7`, `nm -anl`, which adds DWARF `file:line` but no linkage; the static `.symtab`, which lists an executable's globals that are not
     exported and says nothing about visibility), `binary-summary` kept at most 200 `lief`
     export strings with no completeness marker, and `02-ir-facts` carries no linkage. So the
     pinned `binary-summary` tool (`images/audit-binary-analysis/scripts/binary-summary.py`, same
     container, same receipts) now also writes `dynamic_exports`: every defined `STT_FUNC` /
     `STT_GNU_IFUNC` symbol of ELF `.dynsym` with its binding, visibility and version-hidden bit
     (PE: named, non-forwarded export-directory entries in an executable section), demangled by
     binutils `c++filt`, the artifact kind (`shared-library` = `ET_DYN` without `PT_INTERP`, or a
     PE with the DLL flag) and `complete` (false on truncation, an unreadable table, a demangler
     failure or an ordinal-only export). Mach-O has no reader yet: its table is missing. Needs the
     `audit-binary-analysis` image rebuilt; until then every table reads as missing.
   * *Reader.* `entry_exports.tables_from_triage` re-hashes each per-binary `summary.json`
     against the accepted `02-binary-triage` attempt's B13 receipt. An entry is a GLOBAL / WEAK /
     UNIQUE, DEFAULT / PROTECTED, not version-hidden function export. Nothing is inferred from
     source text.
   * *Join.* The demangled name without parameters (`fx::overload(int)` -> `fx.overload`) is
     compared with the qualified part of `METHOD.full_name`. One candidate: a root labelled
     `exported-symbol` with the artifact, binary hash and symbol (the report shows it in
     `entry_point` and the witness's first step). Several candidates: an `ambiguous-export`
     escape, no entry (so C++ overloads are never roots). No candidate, or a file-scoped
     candidate (`dir/a.c:helper`, internal linkage): the coverage gap
     `export-symbol-not-in-cpg`. Operators, templates, thunks, lambdas and MSVC-decorated names
     cannot be expressed in the join: the gap `export-symbol-unjoinable`.
   * *Shipped-library rule.* An executable's exports are not roots. A binary whose table is
     missing, partial, has version-hidden exports or cannot be classified is the gap
     `export-table-incomplete`; no accepted `02-binary-triage` is `export-facts-missing`. Any
     such gap, an ambiguous export or an unmatched symbol keeps an unreached function UNKNOWN,
     never UNREACHABLE; a proven path stays REACHABLE. (With the tunable on and no native build,
     every unreached function is therefore UNKNOWN; that is the conservative reading of "the
     build may ship a library".)
   * *Qualification.* `scripts/smoke_entry_exports.sh` (WSL): builds the fixture in
     `images/test/entry-exports/`, runs `binary-summary` in the image, joins it to the fixture's
     canned CPG. William flips the default after it passes on the rebuilt image.
3. **Framework route / handler registrations.** Correct source: the CodeQL pack `EntryPoint`
   reasons already computed by `06-reachability-codeql` (servlet, request mapping, controller
   action, route handler), exported as function full names with `file:line`. CPG mapping: by
   `(path, start_line)` of the handler's definition, which is exact where both tools saw the same
   source snapshot. **Join implemented, not wired live (`reachability_codeql_entries`, default
   off):** `entry_exports.join_codeql_entries` turns `EntryPoints` rows (`name, file, line,
   reason`) into roots labelled `codeql-entry` by the exact `(path, start_line)` of a CPG method,
   only when the CPG and the CodeQL database share the source snapshot (else the gap
   `codeql-entry-snapshot-mismatch`); two methods at one start is an escape, none is a gap.
   Reasons taken: `servlet`, `request-mapping`, `controller-action`, `route-handler`.
   `remote-flow-source` is **not** taken (a function that reads remote input is not an entry, see
   source 4); `main` is already a program entry; `no-internal-caller` and `address-taken` are
   guesses. `CpgEngine` accepts the roots. Tested with canned tables only: the tables are not
   produced live yet (ADR-0023), the C/C++ traced table (the only one the `ir` engine can see)
   carries none of the taken reasons, and feeding the other languages' tables to finding
   enrichment or the `ir` engine needs a new job edge.
4. **Input-reading sinks from source SAST tags** (argv, socket `recv`/`accept`, file `read`,
   `getenv`). These are not entry points: they show where input *enters* a function that is
   itself reached (or not) from an entry. Use them as sink/source annotations for taint, never as
   BFS roots. Rooting the BFS at them would turn "the function that reads a socket" into a
   reachable root even when nothing calls it.
5. **Run-supplied list** (`inputs/reachability-entry-points.json`). Stays the escape hatch for
   anything the above cannot see (plugin entry tables, callbacks registered through data). It is
   an operator assertion and is labelled as such in the witness.

## What stays UNKNOWN

* A target whose program has no modelled entry (a library with no main and no run-supplied list).
* Anything behind an indirect call, function pointer, virtual dispatch or ambiguous name (escape).
* A graph with a CPG coverage gap that could hide an edge, or a search that hit its bound.
* A library function not reachable from any modelled entry while the build ships the library
  and its export table is missing or partial (source 2, tunable on). With the tunable off this
  is still reported UNREACHABLE, as before brief Q.

## Open

* Rebuild `audit-binary-analysis`, run `scripts/smoke_entry_exports.sh`, then decide the default
  of `reachability_export_entries` (William).
* Exported-symbol roots in `06-reachability-ir` (dependency queries): `CpgEngine` takes them, but
  the job needs `02-binary-triage` as an input first (a graph edge and a fingerprint change).
* Source 3 live: a consumer for the non-native `EntryPoints` tables (finding enrichment reading
  `06-reachability-codeql`, or a new edge), after the CodeQL image rebuild (ADR-0023).
* Mach-O export trie; linkage facts from `02-ir-facts` as a second source for stripped binaries.
* Done: one shared entry-name table (`ENTRY_POINT_SOURCES["cpp"]["names"]` is
  `reachability.PROGRAM_ENTRY_NAMES`); `LLVMFuzzerTestOneInput` is in neither (D-01).
