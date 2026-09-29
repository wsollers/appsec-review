# Reachability entry points beyond `main` (design note, brief M5)

Status: design note for ADR-0020 open item "Entry points beyond `main` need a source".
Implemented from it: step 1 below only. Everything else is open.

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
| `dep_reachability_engines.ENTRY_POINT_SOURCES[lang]["names"]` (`wmain`, `WinMain`, `wWinMain`, `DllMain`, `ServeHTTP`, servlet `do*`, ...) | dependency engines only | Name match; language-defined |
| CodeQL pack `EntryPoint` classes (routes, controller actions, `RemoteFlowSource`, address-taken, no-internal-caller) | `06-reachability-codeql` (never reports `unreachable`) | QL library model |

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
   entry. **Not implemented:** the CPG records carry no linkage or visibility (the Joern exporter
   emits `name`, `full_name`, `signature`, `code`, location only), and guessing from `static` in
   the method's code text is wrong for C++ members, anonymous namespaces and visibility attributes.
   Needs either an exporter field (image rebuild) or a binary/IR export join; behind a tunable,
   default off, until qualified on a real library target.
3. **Framework route / handler registrations.** Correct source: the CodeQL pack `EntryPoint`
   reasons already computed by `06-reachability-codeql` (servlet, request mapping, controller
   action, route handler), exported as function full names with `file:line`. CPG mapping: by
   `(path, start_line)` of the handler's definition, which is exact where both tools saw the same
   source snapshot. **Not implemented:** the CodeQL tables are not yet produced live (image rebuild
   pending, ADR-0023) and C/C++ has no pack.
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
* A library function not reachable from the program's entries when the build also ships the
  library for other consumers: until source 2 exists, this should become UNKNOWN rather than
  UNREACHABLE. Doing that needs the export facts from source 2 (to know that the library is
  shipped); without them no deterministic rule separates it from genuinely dead code, so it is
  left open rather than guessed.

## Open

* Source 2 (exports) and source 3 (CodeQL entry rows into the CPG engine), each behind a tunable,
  default off.
* One shared entry-name table: `dep_reachability_engines.ENTRY_POINT_SOURCES["cpp"]["names"]`
  and `reachability.PROGRAM_ENTRY_NAMES` overlap by design today (the engine table also carries
  the fuzz entry for dependency queries); merge when the engine file's owner next edits it.
