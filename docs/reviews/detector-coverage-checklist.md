# Detector coverage checklist against CodeBadger's detector list

Status: review record, verified against repository files on 2026-10-16 at commit `dc8bc5d3`
(`main`). It accompanies
[`../architecture/graph-alias-slice-layout-modes.md`](../architecture/graph-alias-slice-layout-modes.md).
Remediations named here are **proposed, not implemented**.

## 1. What was compared, and how

CodeBadger (qcri/codebadger, GPL-3.0) ships a C/C++ detector list over a live Joern CPG:
`find_use_after_free`, `find_double_free`, `find_null_pointer_deref`, `find_heap_overflow`,
`find_stack_overflow`, `find_uninitialized_reads`, `find_integer_overflow`,
`find_format_string_vulns`, `find_toctou`, `find_command_injection_sinks`, plus taint sources,
sinks and flows, and bounds checks. Only the list of capabilities was used; no code or text was
taken.

This record maps each detector to what the repository actually registers, pins or configures. A
row is:

- **covered** when a repository-owned file names the exact rule, query, catalog entry or checker
  that establishes the class, and the producer is enabled in the central TOML;
- **partial** when coverage exists only through a tool observation (SAST lane) without a graph
  fact, when the owning rule pack is registered but known broken, or when only a syntactic subset
  is matched;
- **missing** when no repository file establishes the class.

Two verification limits apply to every row and are stated rather than guessed around:

1. **Upstream CodeQL suites are pinned by hash, not by query list.** The C/C++ scope runs
   `codeql/cpp-queries` 1.8.3 with `codeql-suites/cpp-code-scanning.qls`
   (`containers/tools/codeql/assets.lock.json`, `appsec-review.toml` line 1370). The repository
   records the suite's SHA-256 but not the query ids it expands to, and no upstream `cpp/*` query
   id appears anywhere in the tree outside `old/`. A detector that upstream CodeQL is known to
   cover is therefore recorded as "upstream suite, query ids not recorded here", which counts as
   **partial** until the live tier records the expanded suite.
2. **The licensed CERT C++ pack is registered but known broken.** `rules/registry.toml` marks
   `cert-cpp-coding-standards` as unable to resolve its dependencies in the pinned image ("the
   suite has never produced a finding"). `rules/cpp-cert/coverage.json` lists the CERT queries by
   path. A row that relies on that pack is **partial** at best.

Producers consulted, with the file that establishes each:

| Producer | Enabled by | Rule or checker inventory consulted |
|---|---|---|
| CodeQL graph export (`graph` index) | `appsec-review.toml` line 1395 (`graph-export.qls`), `rules/registry.toml` `graph-export-cpp` | `rules/codeql-graph-export/catalog.json` (sinks, sources, sanitizers), `rules/codeql-graph-export/cpp/*.ql` |
| CodeQL upstream C/C++ suite | `appsec-review.toml` line 1370 | not recorded (limit 1) |
| CodeQL CERT C++ pack | `appsec-review.toml` line 1382, `rules/registry.toml` (known broken) | `rules/cpp-cert/coverage.json` |
| Clang Static Analyzer and clang-tidy (`job_clang_static_analysis`) | `appsec-review.toml` lines 1309 to 1310: `clang_analyzer_checkers = ["core", "cplusplus", "deadcode", "security", "unix", "alpha.security.*"]`, `clang_tidy_checks = ["clang-analyzer-*", "bugprone-*", "cert-*", "concurrency-*", "performance-*", "portability-*"]`; clang 18.1.3 (`containers/tools/clang-static-analysis/assets.lock.json`) | `rules/cpp-cert/mappings/codechecker/clangsa.json` and `clang-tidy.json` (CodeChecker label maps; mappings only, per `coverage.json` `known_gaps`) |
| Cppcheck 2.x (`job_evidence_collection`) | `src/appsec_review/jobs/job_evidence_collection/adapters.py` line 286: `--enable=warning,style,performance,portability`; `error`-severity checkers are always on | `rules/cpp-cert/mappings/codechecker/cppcheck.json` |
| Infer 1.3.0 (`job_cpp_compiled_analysis`, `infer` branch) | `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py` line 143: `infer run` with no checker flags (Infer defaults) | none in the repository; `bug_type` is retained verbatim (`job.py` line 718) |
| SEI CERT Semgrep/OpenGrep pack | `rules/registry.toml` is silent on it; the pack is `rules/sei-cert/pack.json` and runs through `job_evidence_collection` per `docs/operations/sei-cert-rule-pack.md` | `rules/sei-cert/rules/{c,cpp}/*.yml`, `rules/sei-cert/mappings/{c,cpp}.json` (status per CERT rule) |
| Repository Semgrep rules | `rules/registry.toml` `semgrep-security` | `rules/semgrep/security.yml`, `review-signals.yml` (no C/C++ rules) |

## 2. Checklist

Graph coverage means a `query_code_graph` family a reviewer can cite; SAST coverage means a
`tool_observation` in the source-SAST lane.

| # | CodeBadger detector | Graph facts today | SAST and rule packs today | Status | Proposed remediation |
|---|---|---|---|---|---|
| 1 | `find_use_after_free` | None. `SINK_CLASSES` has no free or lifetime class; `memory_read` exists in the vocabulary (`graph/contract.py`) but `catalog.json` has **no `memory_read` entry**, so no read sink is exported. The SVF design excludes `saber` by decision. | CSA `unix.Malloc` and `cplusplus.NewDelete` (enabled through the `unix` and `cplusplus` groups; `clangsa.json` labels `unix.Malloc` with `sei-cert-c`); cppcheck `deallocuse` (`cppcheck.json`: `sei-cert-c:mem30-c`, `mem50-cpp`, severity HIGH; error-level, always on); Infer defaults (Pulse reports use-after-free, but no issue type is recorded in the repository); CERT pack `MEM50-CPP/UseAfterFree.ql` (`coverage.json`; pack known broken); SEI CERT `MEM50-CPP` is `REQUIRES_CODEQL` and `MEM30-C` `REQUIRES_DATAFLOW` (`mappings/cpp.json`, `c.json`); upstream suite not recorded. | **partial** (SAST only; no graph fact) | R-UAF: catalog revision adding `memory_free` sink class (`free`, `delete`, `realloc` arg 0, `munmap`) and `memory_read` entries (`ArrayFunction` input buffers, `ArrayExpr` reads); `cfg_context.block_dominated_by_free_of_operand` (design 4.5) and `slice_backward` from the read make the free visible as citable context. Fix the CERT pack image extraction (`registry.toml` note). Record Infer issue types in the live tier. |
| 2 | `find_double_free` | None (as row 1). | CSA `unix.Malloc` / `cplusplus.NewDelete`; cppcheck `doubleFree` (`cppcheck.json`: `sei-cert-c:mem36-c`, HIGH); Infer defaults; CERT pack `MEM51-CPP/ProperlyDeallocateDynamicallyAllocatedResources.ql` (known broken); SEI CERT `mem51-cpp` Semgrep rules match allocator/deallocator *mismatch* only, and `coverage.json` states "double free and cross-function ownership remain CodeQL work". | **partial** (SAST only) | R-UAF plus: with a `memory_free` sink class, two `memory_free` sinks whose operands `may_alias` (`aliases` mode) and where one dominates the other become citable context; no finding rule is proposed. |
| 3 | `find_null_pointer_deref` | None. `guard_fact` reports NULL checks only when a sink's operand is compared (`Guards.ql` `comparesOperand`), and only for catalog sinks. | CSA `core.NullDereference` (`core` group; `clangsa.json`: `cwe-top-25-2024`); cppcheck `nullPointer` and `ctunullpointer` (`sei-cert-c:exp34-c`, HIGH); Infer defaults (Pulse null dereference, not recorded); SEI CERT `EXP34-C` `REQUIRES_DATAFLOW`; upstream suite not recorded. | **partial** (SAST only) | None in the graph beyond `aliases`: a NULL-check guard on an alias of the dereferenced pointer is exactly SVF design 7.2. Record CSA and Infer issue-type counts on the acceptance target in the live tier so the lane's real yield is known. |
| 4 | `find_heap_overflow` | **Sinks:** `memory_write` entries for `strcpy`, `strcat`, `strncpy`, `strncat`, `memcpy`, `memmove`, `memset`, `gets`, the `ArrayFunction.output` model and `ArrayExprWrite` (`catalog.json`); **size:** `allocation_size` via the `AllocationFunction` model; **intervals:** `range_fact` (`Ranges.ql`, `SimpleRangeAnalysis` with conversion chain); **guards:** `guard_fact` (`Guards.ql`); **paths:** `dataflow_path` from catalog sources. **Missing:** destination capacity (nothing exports array or allocation size of the destination), no `memory_read` entries for over-read. | CSA `security.ArrayBound`, `alpha.security.ArrayBoundV2`, `alpha.security.MallocOverflow`, `unix.cstring.BadSizeArg`, `alpha.unix.cstring.OutOfBounds` (all in enabled groups per `clangsa.json`); cppcheck `bufferAccessOutOfBounds`, `arrayIndexOutOfBounds`, `negativeIndex` (HIGH); CERT pack `CTR50-CPP`; SEI CERT `ARR30-C`, `ARR38-C`, `STR31-C` (`REQUIRES_DATAFLOW` / `PARTIAL`); upstream suite not recorded. | **partial** (graph: write sinks, ranges, guards covered; capacity missing) | `buffer_bounds` and `type_layout` modes (design 4.3, 4.4): capacity with basis next to the sink's `range_fact`. R-OOB-R: `memory_read` catalog entries. |
| 5 | `find_stack_overflow` | `ArrayExprWrite` covers writes into local arrays by index; `gets` is a catalog `memory_write` sink; `AllocationFunction` is exported as `allocation_size` (whether cpp-all models `alloca` under it is **not verifiable offline**). No recursion or VLA facts; `call_site` has no recursion flag. | CSA `security.insecureAPI.gets`, `security.insecureAPI.strcpy`, `core.StackAddressEscape`, `alpha.core.StackAddressAsyncEscape` (`clangsa.json`); cppcheck `arrayIndexOutOfBounds` on stack arrays; SEI CERT `str31-c` Semgrep rules match `gets` and unbounded `scanf` `%s` (`rules/sei-cert/rules/c/str31-c.yml`; status `PARTIAL`); upstream suite not recorded. | **partial** | `buffer_bounds` with basis `array_type` for locals (design 4.4) covers the write side. Add `alloca`/VLA size to `allocation_size` if the live tier shows cpp-all does not model it; a recursion flag on `call_site` (`caller == callee` or SCC membership from the closure) is a small `graph-normalize/2` addition, listed as open work, not designed here. |
| 6 | `find_uninitialized_reads` | None. | CSA `core.uninitialized.*` (in the `core` group), `unix.cstring.UninitializedRead`, `alpha.unix.cstring.UninitializedRead`; `alpha.cplusplus.UninitializedObject` and `optin.cplusplus.UninitializedObject` are **not** enabled (neither `alpha.cplusplus` nor `optin` is in the TOML list); cppcheck `uninitvar`, `uninitStructMember` (`sei-cert-c:exp33-c`, HIGH); Infer defaults (Pulse uninitialized value, not recorded); SEI CERT `EXP33-C` `REQUIRES_DATAFLOW`; upstream suite not recorded. | **partial** (SAST only) | `slice_backward` publishes `declaration_without_initializer` nodes (design 4.2) so a reviewer can cite the missing definition; no verdict family is proposed. Consider adding `optin.cplusplus.UninitializedObject` to `clang_analyzer_checkers` (a TOML change with its own acceptance). |
| 7 | `find_integer_overflow` | `range_fact` gives sink-operand intervals, signedness, width and the conversion chain (`sign_change`, `narrowing`, `promotion`) from `Ranges.ql`; `integer_conversion` is in `SINK_CLASSES` but the catalog has **no `integer_conversion` entry**, so overflow at a non-sink arithmetic expression is not exported. | CSA `core.DivideZero`, `alpha.core.TestAfterDivZero`; the taint-to-arithmetic checkers are `optin.taint.*` in the mapping file and the `optin` group is not enabled (whether clang 18.1.3 still names them `alpha.security.taint.*` is **unverified**); cppcheck `integerOverflow`, `signConversion`, `shiftTooManyBits` (`integerOverflow`: `sei-cert-c:int32-c`, HIGH); SEI CERT `INT30-C`, `INT31-C`, `INT32-C` `REQUIRES_DATAFLOW`; upstream suite not recorded. | **partial** (graph: at sinks only) | Catalog entries for `integer_conversion` (e.g. `AllocationFunction` size arguments after a narrowing conversion, array index expressions) so `Ranges.ql` emits them; `buffer_bounds.size_operand` joins the length argument's interval to the destination capacity. Verify the clang 18 taint checker name in the live tier and enable it deliberately. |
| 8 | `find_format_string_vulns` | **Covered:** `format_string` sink class via the `FormattingFunction` model (`catalog.json` `cpp.sink.model.formattingfunction`, CWE-134), `dataflow_path` from catalog sources to it, `guard_fact`/`range_fact` on it. | SEI CERT `fio30-c` Semgrep rules (`nonliteral-format-without-arguments`; status `PARTIAL`); cppcheck `wrongPrintfScanfArgNum`, `invalidPrintfArgType_*`; CSA `security.insecureAPI.*`; upstream suite not recorded. | **covered** (graph) | None required. Live tier to confirm the `FormattingFunction` model fires on the acceptance target. |
| 9 | `find_toctou` | None. `path_access` sinks exist (`fopen`, `open`, `unlink`) but no check-API class (`access`, `stat`, `lstat`, `faccessat`) and no check-then-use pairing. | No CSA checker in the enabled groups targets TOCTOU; cppcheck has none mapped; SEI CERT `FIO45-C` `REQUIRES_DATAFLOW` (`mappings/c.json`); CERT pack has no C rule (C++ pack); upstream suite not recorded. | **missing** | R-TOCTOU: catalog `path_check` sink class for `access`/`stat`/`lstat`/`faccessat` (argument 0), and a normalizer join `toctou_candidate` (`graph-normalize/2`) that relates a `path_check` sink to a `path_access` sink in the same function when the path operands are joined by local flow and the check dominates the use (`control_flow` family, design 4.5). Published as context on both sinks with a `REFERENCES` relation; indirect. |
| 10 | `find_command_injection_sinks` | **Covered:** `command_execution` sink class via `system`, `popen`, `execv`, `execvp` and the `CommandExecutionFunction` model (`catalog.json`, CWE-78); `dataflow_path` to them. | SEI CERT `env33-c` Semgrep rules (`system`/`popen`/`_popen`, `exec*` with shell; status `PARTIAL`); upstream suite not recorded. | **covered** (graph) | Catalog breadth only: `execl*`, `execve`, `posix_spawn*` are not listed and reach the class only through the `CommandExecutionFunction` model when cpp-all models them. |
| 11 | Taint sources | **Covered (C/C++):** `entry_point` family from `SourceSites.ql`: cpp-all `RemoteFlowSource`, `LocalFlowSource`, `FlowSource` (argv, environment) plus catalog APIs `getenv`, `secure_getenv`, `fgets`, `fread`, `read`, `recv`, `recvfrom`, `getchar`, `msgrcv`, `mq_receive`, `sqlite3_column_text`, `mysql_fetch_row` (`catalog.json`). | — | **covered** (C/C++ only; Java/Kotlin, JavaScript/TypeScript and Python packs are not written, code-graph design section 8) | Language packs per the code-graph rollout; nothing new here. |
| 12 | Taint sinks | **Covered (C/C++):** nine of the twelve `SINK_CLASSES` have catalog entries; `memory_read`, `integer_conversion` and `deserialization` have none. | — | **covered** with three empty classes | R-OOB-R, row 7 entries; `deserialization` is unlikely to matter for C/C++ and is a named gap. |
| 13 | Taint flows | **Covered (C/C++):** `dataflow_path` from `Paths.ql` (`TaintTracking::Global`, catalog sources to catalog sinks, sanitizers, bounded shortest-k), `sarif_path` correlation with CodeQL alerts, `flow_summary` per function. | CSA taint checkers not enabled (row 7). | **covered** | None. |
| 14 | Bounds checks | **Covered:** `guard_fact` (`Guards.ql`: dominance, polarity, operator and bound display, `constrains_sink_operand`), `range_fact`. **Weak point:** `constrains_sink_operand = unknown` whenever the compared variable is not locally joined to the sink operand (code-graph design 4.6, risk "guard semantics are shallow"). | cppcheck `arrayIndexOutOfBounds`; CSA `ArrayBound*`. | **covered**, shallow aliasing | `aliases` mode and SVF cross-check 7.2 (SVF design) give the alias answer; `slice_backward` shows guards on other variables as `condition` nodes; `buffer_bounds` gives the capacity the check must respect. |

## 3. Outcome counts

| Status | Rows |
|---|---|
| covered | 6 (format string, command-injection sinks, taint sources, taint sinks, taint flows, bounds checks) |
| partial | 7 (use after free, double free, null dereference, heap overflow, stack overflow, uninitialized reads, integer overflow) |
| missing | 1 (TOCTOU) |

Every `partial` memory-lifetime row (1, 2, 3, 6) has SAST coverage from at least two enabled
producers (CSA and cppcheck, plus Infer defaults) but no citable graph fact; every `covered` row is
C/C++ only. The two cross-cutting verification gaps (upstream CodeQL query list; Infer and CSA issue
types actually produced) are live-tier work, not design work.

## 4. Proposed catalog and configuration follow-ups (not implemented)

| Id | Change | Where | Depends on |
|---|---|---|---|
| R-UAF | `memory_free` sink class; `free`, `delete`/`delete[]` (via `DeallocationFunction` model if cpp-all exposes it, else API names), `realloc` argument 0, `munmap` | `graph/contract.py` `SINK_CLASSES`, `rules/codeql-graph-export/catalog.json` revision 2, catalog pin in TOML | none; scheduled before G3 as design chunk GC |
| R-OOB-R | `memory_read` catalog entries: `ArrayFunction` input buffers (`hasArrayInput`), `ArrayExpr` reads, `memcmp`, `strlen` | catalog revision 2, `GraphExport.qll` `sink` predicate | none; scheduled before G3 as design chunk GC |
| R-INT | `integer_conversion` catalog entries: allocation size arguments and array index expressions after a narrowing or sign-changing conversion | catalog revision 2 | none |
| R-TOCTOU | `path_check` sink class and `toctou_candidate` join | contract, catalog revision 2, `graph-normalize/2`, `control_flow` family (design G3) | design chunk G3 |
| R-CSA | enable `optin.cplusplus.UninitializedObject` and the clang 18 taint checker under its real name | `appsec-review.toml` `clang_analyzer_checkers`, `tests/test_clang_static_analysis.py` | live verification of checker names on clang 18.1.3 |
| R-CERT | extract every member pack of the licensed CERT zip so `cert-cpp-coding-standards` resolves | `containers/tools/codeql/Dockerfile.custom-source`, image rebuild and re-pin by the review-host session (single-owner value) | review host |
| R-LIVE | record the expanded `cpp-code-scanning.qls` query list, Infer `bug_type`s and CSA checker ids observed on the acceptance target | `tests/live/`, `deploy/dagster/verification/` | pinned images on the review host |
