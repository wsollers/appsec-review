# Brief Q: exported-symbol entry points for reachability (branch `entry-exports`) - CLOUD agent
William, 2026-09-29: yes to the extra entry points, starting with exported symbols. Design source:
`docs/reachability-entry-points.md` (brief M5), sources 2 and 3, and ADR-0020's open item. Rule that governs all of it:
adding a REAL entry can only turn UNREACHABLE into REACHABLE or UNKNOWN; adding a WRONG entry can manufacture a
REACHABLE witness and allow Critical. So every entry needs a deterministic, verified source; an ambiguous join is an
escape, never an entry; `LLVMFuzzerTestOneInput` stays out (decision D-01).

## Q1. Exported-symbol entries (source 2)
Give `reachability.CallGraph` a second, tunable entry set: symbols a shipped library exports.
- Source of truth, in order of preference: (a) the dynamic symbol table of each built artifact published by
  `02-native-build` / read by `02-binary-triage` and `02-binary-cfg` (defined, global, default-visibility, not hidden by a
  version script; ELF `.dynsym`, PE export directory, Mach-O export trie); (b) linkage facts from `02-ir-facts` (external
  linkage, default visibility, not `static`, not in an anonymous namespace). Use what the existing jobs already publish
  before adding any exporter field. Do NOT infer linkage from source text (wrong for C++ members, anonymous namespaces
  and visibility attributes).
- Mapping to the CPG: join the exported (demangled) name to `METHOD.full_name` / `name`. A join that is not unique is an
  escape and produces NO entry (record it in the witness as `ambiguous-export`). A symbol with no CPG method is recorded
  as a coverage gap, not dropped silently.
- Tunable `reachability_export_entries` (default OFF in the code; see Q3). When ON, entries carry a witness label
  `exported-symbol` with the artifact and symbol so the report shows why the path exists.
- Shipped libraries: a function reachable only from an export in a library the build ships is REACHABLE from that
  export. A library function NOT reachable from any modelled entry while the build ships the library must become
  UNKNOWN (never UNREACHABLE) when Q1 is ON but the export table is missing or partial. Implement that rule and test it.
- Share the entry-name table: `dep_reachability_engines.ENTRY_POINT_SOURCES["cpp"]["names"]` and
  `reachability.PROGRAM_ENTRY_NAMES` overlap by design today; make one table both import (no behaviour change).

## Q2. CodeQL EntryPoint rows into the CPG engine (source 3, second slice, only after Q1 is green)
Export the `EntryPoint` reasons `06-reachability-codeql` already computes (servlet, request mapping, controller action,
route handler, remote-flow source) as `(path, start_line, reason)` rows and let the `ir` engine consume them as entries
by `(path, start_line)` of the handler definition, exact only where both tools saw the same snapshot. Behind tunable
`reachability_codeql_entries` (default OFF). If the CodeQL tables are not produced yet (image rebuild pending, ADR-0023),
test with canned tables and say so; do not fake a live result.

## Q3. Qualification (needs WSL, you prepare it)
Add `scripts/smoke_entry_exports.sh`: build a tiny shared library fixture (`images/test/`) with one exported function,
one `static` function and one hidden-visibility function, run the reachability path over it, and assert: the exported
function is REACHABLE via `exported-symbol`; the static and hidden ones are NOT roots; an ambiguous overload produces no
entry. William runs it in WSL and then decides whether to flip the tunable default; do not flip it yourself.

## You own
`reachability.py`, the shared entry-name table (small edits in `dep_reachability_engines.py`), an entry-export
reader module, the new tunables (`docs/processes/tunables.md` via the generator), tests, the smoke script and fixture,
`docs/reachability-entry-points.md` (update status; this is the design note you implement).
## Do not touch
Persona files, `execution_state.py`, `dev_restart.py`, `job_executor.py`, report templates.
## Acceptance
Both tunables default OFF and prod behaviour is byte-identical with them off (test); Q1 tests for unique join, ambiguous
join, missing symbol, hidden and static exclusion, and the shipped-library UNKNOWN rule; the fuzz entry is still absent
from both tables; baseline failures in 00-common.md unchanged. Job fingerprints that move (reachability.py is hashed by
finding enrichment and 06) are listed in your report.
