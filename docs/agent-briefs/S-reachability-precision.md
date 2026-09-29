# Brief S: reachability precision for C++ (branch `reach-precision`) - CLOUD agent
William, 2026-09-29. Today `reachability.py` treats virtual calls, function pointers and C++ template instantiations as
escapes, so a real C++ library mostly reads UNKNOWN. The static-name join in `entry_exports.py` (brief Q) assumes a
static function's CPG name carries a file prefix (`dir/a.c:helper`) that has never been compared with real Joern output.
Goal: resolve more calls SOUNDLY (never invent an edge; an edge added in error can manufacture REACHABLE and allow
Critical, ADR-0020), and check the assumptions against real Joern output.

Read first: `docs/agent-briefs/00-common.md`, `reachability.py` (CallGraph, `resolution` values, escape reasons),
`entry_exports.py`, `dep_reachability_engines.py`, `docs/reachability-entry-points.md`, `docs/dependency-reachability.md`,
`code_graph_evidence.py`, `joern_cpg.py` (what the CPG records actually contain) and decision log D-01, D-05, D-24.

## S1. Ground truth first: real Joern output (do this before changing any resolver)
- Add a small fixture corpus of C/C++ sources under `tests/fixtures/reach-precision/`: static functions with the same
  name in two files, an anonymous-namespace function, overloaded functions, class methods, virtual and pure-virtual
  hierarchies, a function-pointer table, a callback registered via `std::function`, a lambda, a function template with two
  instantiations, an operator overload, an extern "C" export and a namespaced export.
- A script `scripts/capture_joern_fixture.sh` runs the pinned Joern image (through `02-code-property-graph`'s own
  container path, not a new one) over the corpus and stores the CPG records under
  `tests/fixtures/reach-precision/joern-output/` with the Joern version and image digest recorded. The cloud agent has no
  Docker: write and unit-test the script, ship the parsing tests against a hand-written sample that follows the
  published record shape, and mark real-capture assertions `skip` until William runs the script in WSL. Give the exact
  WSL command in your report.
- Record findings in `docs/reachability-precision.md`: for each construct, what Joern's `METHOD.full_name`, `name`,
  `signature`, `CALL.methodFullName` and dynamic-dispatch fields actually contain. Correct the file-prefix assumption in
  `entry_exports.py` if the capture disagrees (a mismatch must fail loudly in a test, not silently miss).

## S2. Sound resolution rules, each behind its own tunable, default OFF
Add each rule as a separate resolver stage in `reachability.CallGraph`, recording `resolution` = the rule name so the
witness shows why an edge exists, and keep the existing rules and their order unchanged when the tunable is off (a
golden-hash test proves byte-identical output when everything is off, as brief Q did):
1. **Qualified-name and signature match:** resolve a C++ call to a method by `full_name` + parameter signature before
   falling back to the short name; overloads resolve only when exactly one signature matches the call's argument count
   and available types. Otherwise remain an escape.
2. **Class-hierarchy virtual dispatch (CHA):** a virtual call on a static receiver type T resolves to the overrides in
   T and its known subclasses (from CPG type-decl inheritance). The edge set is the over-approximation CHA gives; a
   type hierarchy that is incomplete (a base class from an unindexed header or a shared library) marks the call an escape,
   never a partial resolution. Reachable-through-CHA witnesses are labelled `cha` and carry the candidate count.
3. **Function-pointer and callback tables:** a call through a variable resolves only when the CPG shows that variable is
   assigned exactly a finite set of known functions in the same translation unit and is not address-taken elsewhere,
   otherwise escape (soundness first). Include registration tables (array of struct with function members) and
   `std::function`/lambda assigned once.
4. **Templates:** treat each instantiation the CPG records as its own method; resolve a call inside a template body to the
   instantiation that matches the recorded instantiation edge; an un-instantiated template is a gap, not a method.
5. **Conservative escape reporting:** each remaining escape carries a stable reason code (`virtual-unresolved`,
   `fnptr-unbounded`, `template-uninstantiated`, `ambiguous-name`, `hierarchy-incomplete`) so the report can say WHY a
   finding is UNKNOWN and what would fix it.

Rules 2 and 3 can only add edges. State in the docs and tests that a REACHABLE verdict derived through `cha` or `fnptr`
is labelled `REACHABLE (over-approximate)` in the witness and NEVER alone allows Critical (ADR-0020 requires REACHABLE;
decide and document whether over-approximate paths count; default: they do not, behind tunable
`reachability_overapprox_allows_critical`, default OFF). UNREACHABLE is issued only when the search completed with no
remaining escape of any kind.

## S3. Measure it
Report a table over the fixture corpus: number of call sites, resolved by each rule, still escaped by reason; and the
verdict change (UNKNOWN -> REACHABLE / UNREACHABLE) for a set of seeded sink functions. Also run the existing
reachability and entry-export tests with all tunables off (must be byte-identical) and on.

## Rules
- No live tools in the cloud; deterministic code only. Every new state, reason and rule name in a schema enum or closed
  vocabulary; regenerate catalogs and tunable docs, never hand-edit.
- ADR-0030 (proposed). List every job fingerprint that moves by job id (06 jobs, 10, 12b at least). Update `TODO.md`
  (section S). Finish with the exact WSL commands: capture script, then the skipped real-capture tests.
