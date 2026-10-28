/**
 * @name Code-graph export: call sites
 * @description Every call in a function defined inside the source root, with its resolved
 *              callee or an explicit unresolved row. One row per (call, candidate callee).
 * @kind table
 * @id appsec-review/graph-export/rust/call-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `call_sites`.
//
// Dispatch: a trait-method call with more than one run-time target is `virtual_resolved` (one
// row per implementation); a call to a closure or function value is `unresolved_indirect`
// (codeql/rust-all keeps closure call resolution internal); a static target defined in the
// source root is `direct`, any other static target `external_undefined`. Rust has no
// `function_pointer_resolved` or `template_instantiation` rows: generic functions are not
// instantiated per call in the Rust database.
import rust
import GraphExport

/** The callee, dispatch and candidate count of a call with a resolved target. */
predicate callee(GraphExport::ExportCall call, Function target, string dispatch, int candidateCount) {
  not GraphExport::dynamicCall(call) and
  (
    target = GraphExport::virtualCandidate(call) and
    dispatch = "virtual_resolved" and
    candidateCount = strictcount(call.getARuntimeTarget())
    or
    not exists(GraphExport::virtualCandidate(call)) and
    target = call.getStaticTarget() and
    (
      if target instanceof GraphExport::SourceFunction
      then dispatch = "direct"
      else dispatch = "external_undefined"
    ) and
    candidateCount = 1
  )
}

string inLoop(GraphExport::ExportCall call) {
  if exists(LoopingExpr loop | loop.getLoopBody() = call.getParentNode+())
  then result = "true"
  else result = "false"
}

/** The display name of an unresolved call: `<indirect:callee>` or the method name. */
string unresolvedName(GraphExport::ExportCall call) {
  result = "<indirect:" + call.(CallExpr).getFunction().toString() + ">"
  or
  result = call.(MethodCallExpr).getIdentifier().getText()
}

query predicate call_sites(
  string caller_name, string caller_path, int caller_start_line, int caller_start_column,
  string call_path, int call_start_line, int call_start_column, int call_end_line,
  int call_end_column, string callee_name, string callee_declared_in, string callee_path,
  int callee_start_line, int callee_start_column, string dispatch, int candidate_count,
  int argument_count, string in_loop
) {
  exists(GraphExport::ExportCall call, GraphExport::SourceFunction caller |
    caller = GraphExport::enclosingFunction(call) and
    GraphExport::inSource(call) and
    GraphExport::exported(caller)
  |
    caller_name = GraphExport::functionName(caller) and
    GraphExport::locationColumns(GraphExport::functionLocation(caller), caller_path,
      caller_start_line, caller_start_column, _, _) and
    GraphExport::locationColumns(call.getLocation(), call_path, call_start_line,
      call_start_column, call_end_line, call_end_column) and
    argument_count = call.getNumberOfPositionalArguments() and
    in_loop = inLoop(call) and
    (
      exists(Function target | callee(call, target, dispatch, candidate_count) |
        callee_name = GraphExport::functionName(target) and
        callee_declared_in = GraphExport::declaredIn(target) and
        GraphExport::locationColumns(GraphExport::functionLocation(target), callee_path,
          callee_start_line, callee_start_column, _, _)
      )
      or
      not callee(call, _, _, _) and
      dispatch = "unresolved_indirect" and
      candidate_count = 0 and
      callee_name = unresolvedName(call) and
      callee_declared_in = "" and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
    )
  )
}
