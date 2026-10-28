/**
 * @name Code-graph export: call sites
 * @description Every call in a function defined inside the source root, with its resolved
 *              callee or an explicit unresolved row. One row per (call, candidate callee).
 * @kind table
 * @id appsec-review/graph-export/swift/call-sites
 */

// LIVE-UNVERIFIED (see GraphExport.qll). Column contract: ../columns.json `call_sites`.
//
// Dispatch vocabulary used by Swift: "direct" (a source-defined static target),
// "external_undefined" (a target without a body in the source root, e.g. Foundation),
// "virtual_resolved" (a protocol requirement or an overridden class method, one row per
// implementation with a body) and "unresolved_indirect" (no static target: a closure value or a
// function-typed variable). Swift generics are not instantiated in the database, so
// "template_instantiation" is never emitted; closure values are not resolved through dataflow,
// so "function_pointer_resolved" is never emitted. Calls to standard-library operators
// (`a < b`, `a + b`) are not call sites.
import swift
import codeql.swift.generated.ParentChild
import GraphExport

/** The dispatch class of a static (non-dynamic) call to `target`. */
string directDispatch(Function target) {
  if target instanceof GraphExport::SourceFunction
  then result = "direct"
  else result = "external_undefined"
}

/** The callee and dispatch of `call`, with the number of candidate callees. */
predicate callee(ApplyExpr call, Function target, string dispatch, int candidateCount) {
  exists(GraphExport::virtualCandidate(call)) and
  target = GraphExport::virtualCandidate(call) and
  dispatch = "virtual_resolved" and
  candidateCount = count(Function f | f = GraphExport::virtualCandidate(call))
  or
  not exists(GraphExport::virtualCandidate(call)) and
  target = call.getStaticTarget() and
  dispatch = directDispatch(target) and
  candidateCount = 1
}

/** A standard-library operator application, which is not a call site. */
predicate builtinOperator(ApplyExpr call) {
  (
    call instanceof BinaryExpr or
    call instanceof PrefixUnaryExpr or
    call instanceof PostfixUnaryExpr
  ) and
  not call.getStaticTarget() instanceof GraphExport::SourceFunction
}

/** The body of a loop statement. */
Stmt loopBody() {
  result = any(ForEachStmt l).getBody() or
  result = any(WhileStmt l).getBody() or
  result = any(RepeatWhileStmt l).getBody()
}

string inLoop(ApplyExpr call) {
  if loopBody() = getImmediateParent*(call) then result = "true" else result = "false"
}

query predicate call_sites(
  string caller_name, string caller_path, int caller_start_line, int caller_start_column,
  string call_path, int call_start_line, int call_start_column, int call_end_line,
  int call_end_column, string callee_name, string callee_declared_in, string callee_path,
  int callee_start_line, int callee_start_column, string dispatch, int candidate_count,
  int argument_count, string in_loop
) {
  exists(ApplyExpr call, GraphExport::SourceFunction caller |
    caller = call.getEnclosingFunction() and
    GraphExport::inSource(call) and
    GraphExport::exported(caller) and
    not builtinOperator(call)
  |
    caller_name = GraphExport::qualifiedName(caller) and
    GraphExport::locationColumns(caller.getLocation(), caller_path, caller_start_line,
      caller_start_column, _, _) and
    GraphExport::locationColumns(call.getLocation(), call_path, call_start_line,
      call_start_column, call_end_line, call_end_column) and
    argument_count = call.getNumberOfArguments() and
    in_loop = inLoop(call) and
    (
      exists(Function target | callee(call, target, dispatch, candidate_count) |
        // A callee without a body is named like a catalog API (base name; the type is in
        // callee_declared_in) so sanitizer and opaque-call summaries can match it.
        (
          if target instanceof GraphExport::SourceFunction
          then callee_name = GraphExport::qualifiedName(target)
          else callee_name = GraphExport::shortName(target)
        ) and
        callee_declared_in = GraphExport::declaredIn(target) and
        GraphExport::locationColumns(target.getLocation(), callee_path, callee_start_line,
          callee_start_column, _, _)
      )
      or
      // A call with no static function target (a closure value, a function-typed variable) is
      // published as unresolved instead of being dropped.
      not callee(call, _, _, _) and
      dispatch = "unresolved_indirect" and
      candidate_count = 0 and
      callee_name = "<indirect:" + call.getFunction().toString() + ">" and
      callee_declared_in = "" and
      callee_path = "" and
      callee_start_line = 0 and
      callee_start_column = 0
    )
  )
}
